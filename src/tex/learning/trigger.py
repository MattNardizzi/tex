"""
Anytime-valid calibration trigger.

This is the missing piece: the thing that lets the learning voice speak
*unprompted*. Before this module, ``FeedbackLoopOrchestrator.propose`` had
exactly one caller — a manual ``POST /v1/learning/proposals`` — so in
production the proposal store stayed empty and Tex never offered a
calibration on its own. The machinery downstream of ``propose`` was complete;
the trigger upstream of it did not exist.

The trigger is deliberately *not* a cron and *not* a count. A cron fires on
the clock; a count fires on volume; both are arbitrary. Tex fires on
*evidence*: it maintains, per tenant and per policy target, an anytime-valid
e-process on the miscalibration signal (the false-permit indicator stream
standardised against the policy's tolerated false-permit rate). When that
e-process crosses its boundary — i.e. the anytime-valid p-value drops below
``alpha`` — the evidence against "this policy is well-calibrated" is
significant with a false-alarm rate bounded by ``alpha`` over the *entire*
horizon, no matter how often the loop peeks (Ville's inequality). That
crossing is the moment, and the crossing certificate is itself sealable
evidence: Tex can prove *why* it spoke, not just *that* it did.

On a crossing the trigger calls the existing ``propose`` (which still runs
every safety gate, the sufficiency gate, replay, OPE, and never auto-applies)
and seals the certificate into the proposal's metadata.

Lapse-on-supersession (the doctrine, made mechanical)
-----------------------------------------------------
A proposal never nags and never expires on an attention timer. It lapses only
when its evidence is *superseded*: a fresh boundary crossing over the same
(tenant, source-policy) target produces a newer proposal, at which point any
older pending proposal for that target is marked EXPIRED and the gate records
"offered, not answered — superseded". A still-valid pending proposal simply
waits to be pulled; the trigger does not re-raise it. After a successful
fire the e-process is reset, so the next regime is certified against a fresh
baseline rather than the one that already crossed.

The trigger is read-mostly and defensive: any failure is swallowed so it can
never break the ingest path it hangs off. It is opt-in — an orchestrator with
no trigger behaves exactly as before.

stdlib + existing tex modules only. No new dependencies.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import UTC, datetime
from threading import RLock
from typing import Any, Callable

from tex.domain.outcome import OutcomeRecord
from tex.domain.outcome_trust import OutcomeTrustLevel
from tex.domain.verdict import Verdict
from tex.drift._anytime_valid import AnytimeValidEProcess

__all__ = [
    "AnytimeValidCalibrationTrigger",
    "TriggerOutcome",
    "DEFAULT_TRIGGER_ALPHA",
    "DEFAULT_TARGET_FALSE_PERMIT_RATE",
]

DEFAULT_TRIGGER_ALPHA = 0.01
# The null hypothesis the e-process tests is "the policy's false-permit rate
# equals its tolerated rate p0". Decisions are standardised against p0; a
# sustained excess of false-permits drives the e-process up. 0.05 is a
# conservative default tolerated rate; configurable per deployment.
DEFAULT_TARGET_FALSE_PERMIT_RATE = 0.05

# Floor on how many standardised observations must accumulate before a
# crossing is allowed to fire. The e-process is anytime-valid from t=1, but a
# governance change off two data points is operationally absurd; this is a
# sanity floor distinct from (and looser than) the sufficiency gate.
_MIN_OBSERVATIONS_BEFORE_FIRE = 5


@dataclass(frozen=True, slots=True)
class TriggerOutcome:
    """What one ``on_outcome`` call did. Returned for tests/observability."""

    observed: bool
    fired: bool
    proposal_id: str | None
    superseded_ids: tuple[str, ...]
    p_anytime_valid: float | None
    sample_size: int
    reason: str


@dataclass(slots=True)
class _TargetState:
    """Per (tenant, source-policy-version) e-process state."""

    eprocess: AnytimeValidEProcess
    pending_proposal_id: str | None = None


class AnytimeValidCalibrationTrigger:
    """Fires ``orchestrator.propose`` when the calibration e-process crosses.

    Wiring: the orchestrator calls ``on_outcome(outcome)`` at the end of every
    successful ingest. The trigger holds a back-reference to the orchestrator
    (set after construction via the orchestrator's ``set_trigger`` to break
    the construction cycle) and to the proposal store (for supersession).
    """

    __slots__ = (
        "_orchestrator",
        "_proposals",
        "_alpha",
        "_target_false_permit_rate",
        "_min_observations",
        "_created_by",
        "_version_namer",
        "_clock",
        "_lock",
        "_targets",
    )

    def __init__(
        self,
        *,
        orchestrator: Any,
        proposals: Any,
        alpha: float = DEFAULT_TRIGGER_ALPHA,
        target_false_permit_rate: float = DEFAULT_TARGET_FALSE_PERMIT_RATE,
        min_observations: int = _MIN_OBSERVATIONS_BEFORE_FIRE,
        created_by: str = "tex:auto",
        version_namer: Callable[[str, str], str] | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not 0.0 < alpha < 1.0:
            raise ValueError("alpha must be in (0, 1)")
        if not 0.0 < target_false_permit_rate < 1.0:
            raise ValueError("target_false_permit_rate must be in (0, 1)")
        self._orchestrator = orchestrator
        self._proposals = proposals
        self._alpha = alpha
        self._target_false_permit_rate = target_false_permit_rate
        self._min_observations = max(1, min_observations)
        self._created_by = created_by
        self._version_namer = version_namer or _default_version_namer
        self._clock = clock or (lambda: datetime.now(UTC))
        self._lock = RLock()
        self._targets: dict[tuple[str, str], _TargetState] = {}

    # ── ingest hook ─────────────────────────────────────────────────────

    def on_outcome(self, outcome: OutcomeRecord) -> TriggerOutcome:
        """Fold one ingested outcome into its target's e-process; maybe fire.

        Only calibration-eligible PERMIT outcomes with a ground-truth safety
        label carry the false-permit signal, so only those advance the
        e-process. Everything else is a no-op observation.
        """
        try:
            return self._on_outcome_inner(outcome)
        except Exception as exc:  # noqa: BLE001 — never break ingest
            return TriggerOutcome(
                observed=False,
                fired=False,
                proposal_id=None,
                superseded_ids=(),
                p_anytime_valid=None,
                sample_size=0,
                reason=f"trigger error swallowed: {type(exc).__name__}",
            )

    def _on_outcome_inner(self, outcome: OutcomeRecord) -> TriggerOutcome:
        if not _carries_signal(outcome):
            return TriggerOutcome(
                observed=False,
                fired=False,
                proposal_id=None,
                superseded_ids=(),
                p_anytime_valid=None,
                sample_size=0,
                reason="outcome carries no false-permit signal",
            )

        tenant = (outcome.tenant_id or "").strip() or "__none__"
        source_version = (outcome.policy_version or "").strip() or "__active__"
        key = (tenant, source_version)

        with self._lock:
            state = self._targets.get(key)
            if state is None:
                state = _TargetState(eprocess=AnytimeValidEProcess())
                self._targets[key] = state

            x = _standardise_false_permit(
                is_false_permit=(outcome.was_safe is False),
                p0=self._target_false_permit_rate,
            )
            cert = state.eprocess.observe(standardised_x=x)

            significant = (
                cert.sample_size >= self._min_observations
                and cert.is_significant_at(self._alpha)
            )
            if not significant:
                return TriggerOutcome(
                    observed=True,
                    fired=False,
                    proposal_id=state.pending_proposal_id,
                    superseded_ids=(),
                    p_anytime_valid=cert.p_anytime_valid,
                    sample_size=cert.sample_size,
                    reason="e-process below boundary; accumulating",
                )

            # Boundary crossed. Draft first; only supersede a prior pending
            # proposal once the replacement actually exists. Expiring the old
            # one before knowing the new one drafts would lapse a good
            # proposal for nothing.
            certificate_meta = {
                "trigger": "anytime_valid_eprocess",
                "p_anytime_valid": cert.p_anytime_valid,
                "log_e_value": cert.log_e_value,
                "dominant_lambda": cert.dominant_lambda,
                "sample_size": cert.sample_size,
                "alpha": self._alpha,
                "target_false_permit_rate": self._target_false_permit_rate,
                "crossed_at": self._clock().isoformat(),
            }

            new_version = self._version_namer(tenant, source_version)
            source_arg = (
                outcome.policy_version
                if outcome.policy_version not in (None, "", "__active__")
                else None
            )

            result = self._orchestrator.propose(
                tenant_id=outcome.tenant_id or tenant,
                proposed_new_version=new_version,
                created_by=self._created_by,
                source_policy_version=source_arg,
                trigger_metadata={"calibration_trigger": certificate_meta},
            )

            if result.proposal is None:
                # propose() refused (sufficiency not ready, safety blocked,
                # freeze, no movement). Do NOT reset and do NOT supersede: the
                # crossing stands, any existing pending proposal stays live,
                # and we keep accumulating until the gate downstream clears.
                return TriggerOutcome(
                    observed=True,
                    fired=False,
                    proposal_id=state.pending_proposal_id,
                    superseded_ids=(),
                    p_anytime_valid=cert.p_anytime_valid,
                    sample_size=cert.sample_size,
                    reason="crossed but propose() declined: "
                    + "; ".join(result.advisories),
                )

            pid = str(result.proposal.proposal_id)
            # The replacement exists — now lapse the prior pending proposal for
            # this target (excluding the one we just created).
            superseded = self._supersede_existing(
                tenant=outcome.tenant_id,
                source_version=source_version,
                exclude_id=pid,
            )
            state.pending_proposal_id = pid
            # Fresh baseline for the next regime: the crossing is consumed.
            state.eprocess.reset()
            return TriggerOutcome(
                observed=True,
                fired=True,
                proposal_id=pid,
                superseded_ids=superseded,
                p_anytime_valid=cert.p_anytime_valid,
                sample_size=cert.sample_size,
                reason="e-process crossed; proposal drafted",
            )

    # ── supersession ────────────────────────────────────────────────────

    def _supersede_existing(
        self, *, tenant: str | None, source_version: str, exclude_id: str | None = None
    ) -> tuple[str, ...]:
        """Expire any pending proposal for the same (tenant, source) target.

        This is lapse-on-supersession: a newer crossing makes an older,
        un-acted proposal stale. We mark it EXPIRED (the gate records
        "offered, not answered — superseded") rather than leaving two live
        proposals competing for the one held-card slot. ``exclude_id`` is the
        freshly-created proposal, which must never expire itself.
        """
        superseded: list[str] = []
        list_pending = getattr(self._proposals, "list_pending", None)
        mark_expired = getattr(self._proposals, "mark_expired", None)
        if not callable(list_pending) or not callable(mark_expired):
            return ()
        try:
            pending = (
                list_pending(tenant_id=tenant)
                if tenant
                else list_pending()
            )
        except TypeError:
            pending = list_pending()
        except Exception:  # noqa: BLE001
            return ()

        for proposal in list(pending or []):
            if proposal.source_policy_version != source_version:
                continue
            if exclude_id is not None and str(proposal.proposal_id) == exclude_id:
                continue
            try:
                mark_expired(proposal_id=proposal.proposal_id)
                superseded.append(str(proposal.proposal_id))
            except Exception:  # noqa: BLE001
                continue
        return tuple(superseded)


# ── helpers ─────────────────────────────────────────────────────────────


def _carries_signal(outcome: OutcomeRecord) -> bool:
    """Only calibration-eligible PERMIT outcomes with a safety label move the
    false-permit e-process."""
    if outcome.trust_level not in (
        OutcomeTrustLevel.VALIDATED,
        OutcomeTrustLevel.VERIFIED,
    ):
        return False
    if outcome.verdict is not Verdict.PERMIT:
        return False
    return outcome.was_safe is not None


def _standardise_false_permit(*, is_false_permit: bool, p0: float) -> float:
    """Standardise a Bernoulli false-permit indicator against the null rate.

    x = (indicator - p0) / sqrt(p0 (1 - p0)). Under H0 (false-permit rate ==
    p0) the indicator has mean p0 and variance p0(1-p0), so x has ~zero mean
    and unit variance — the input the sub-Gaussian e-process expects. A
    sustained run of false-permits pushes the mean positive and drives the
    e-process up; a clean run of correct-permits pulls it down.
    """
    indicator = 1.0 if is_false_permit else 0.0
    denom = math.sqrt(p0 * (1.0 - p0))
    return (indicator - p0) / denom


def _default_version_namer(tenant: str, source_version: str) -> str:
    """Deterministic-ish proposed version name. The operator never types this;
    it exists only so applied policies carry a legible lineage."""
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S")
    base = source_version if source_version != "__active__" else "active"
    return f"{base}+cal-{stamp}"

"""How a profile CORRECTION influences the next decision — and the proof it can
only ever TIGHTEN.

This is the load-bearing constitution piece. A correction is applied as a
POST-GATE MONOTONE FOLD: after the truth-gate has produced its verdicts (from
sealed rows alone — a correction never touches the recompute), each verdict whose
subject has an active correction is capped at the correction's ceiling via
:func:`tex.presence.contract.tighten`. Because the only combinator is ``tighten``
(the more-cautious of two tiers), there is NO code path by which a correction can
raise a tier. "Becomes more yours" therefore can never mean "becomes more confident
than it can prove."

Two honesty rules make every emitted verdict coherent with the contract:

  * **Never fabricate a DERIVED floor.** A ``SEALED`` verdict carries no
    ``correctness_floor``; a ``DERIVED`` ceiling applied to it would imply a
    statistical floor the gate never computed. So a cap that would land on
    ``DERIVED`` without a floor present drops to ``ABSTAIN`` instead. (In practice
    every *effective* correction lands on ABSTAIN — it suppresses the claim, which
    ``compose.py`` then strips — except a ``DERIVED`` claim capped at ``DERIVED``,
    a no-op.)
  * **Evidence empty iff ABSTAIN.** When a cap lands on ``ABSTAIN`` the verdict's
    evidence/floor/coverage are cleared, preserving the contract invariant.

Wiring (the orchestrator's ONE additive line — L2 does not edit ``run_presence``):

    detailed = gate.evaluate_detailed(request=..., tenant=tenant, draft=draft,
                                      claims=claims, facts=facts)
    detailed = apply_profile_corrections(tenant=tenant, evaluations=detailed,
                                         profile=app.state.presence_profile)   # ← here
    envelope = build_envelope(detailed, templated_abstain=...)
"""

from __future__ import annotations

import logging
from dataclasses import replace
from typing import Any

from tex.presence.contract import PresenceTier, PresenceVerdict, tighten
from tex.presence.profile.types import ProfileFacts, ProfileMemory

_logger = logging.getLogger(__name__)

__all__ = [
    "cap_verdict",
    "apply_corrections_to_verdicts",
    "apply_profile_corrections",
]

_CORRECTION_TAG = "profile-correction"


def cap_verdict(
    verdict: PresenceVerdict, ceiling: PresenceTier | None, *, record_id: str | None = None
) -> PresenceVerdict:
    """Return ``verdict`` capped at ``ceiling`` (monotone — only ever lowers).

    ``ceiling=None`` (no correction for this subject) → unchanged. Never raises a
    tier; never fabricates a DERIVED floor; clears evidence/floor/coverage when the
    cap lands on ABSTAIN (contract: evidence empty iff ABSTAIN).
    """
    if ceiling is None:
        return verdict
    capped = tighten(verdict.tier, ceiling)
    if capped is PresenceTier.DERIVED and verdict.correctness_floor is None:
        # Would be a floor-less DERIVED — refuse to fabricate a floor; suppress.
        capped = PresenceTier.ABSTAIN
    if capped is verdict.tier:
        return verdict  # no-op (ceiling no stricter than the gate's tier)

    tag = _CORRECTION_TAG if record_id is None else f"{_CORRECTION_TAG}:{record_id}"
    reason = f"{verdict.reason};{tag}" if verdict.reason else tag
    if capped is PresenceTier.ABSTAIN:
        return replace(
            verdict,
            tier=PresenceTier.ABSTAIN,
            evidence=(),
            correctness_floor=None,
            coverage_mode=None,
            reason=reason,
        )
    # capped is DERIVED with a floor already present (a DERIVED→DERIVED edge that
    # tighten() left unchanged is handled above; this branch is defensive).
    return replace(verdict, tier=capped, reason=reason)


def apply_corrections_to_verdicts(
    *, tenant: str, verdicts: tuple[PresenceVerdict, ...], profile: ProfileMemory | None
) -> tuple[PresenceVerdict, ...]:
    """Cap a tuple of verdicts by this tenant's active corrections. Decoupled from
    the gate (contract types only) so it is unit-testable in isolation. Fail-open
    to the UNCORRECTED verdicts on any profile error — a profile fault must never
    *raise* a tier, and equally must never crash the voice path; the gate's verdict
    already stands on its own."""
    if profile is None or not verdicts:
        return verdicts
    facts = _safe_recall(profile, tenant)
    if facts is None or not facts.facts:
        return verdicts
    out = []
    for v in verdicts:
        ceiling = facts.tier_ceiling(v.claim_id)
        out.append(cap_verdict(v, ceiling, record_id=_first_correction_id(facts, v.claim_id)))
    return tuple(out)


def apply_profile_corrections(
    *, tenant: str | None, evaluations: tuple[Any, ...], profile: ProfileMemory | None
) -> tuple[Any, ...]:
    """The orchestrator seam. Cap each ``ClaimEvaluation``'s verdict by this
    tenant's active corrections, returning a new tuple (the ``recompute``/``routed``
    fields are carried through, so ``compose.build_envelope`` strips a
    correction-suppressed claim exactly as it strips any ABSTAIN).

    Fail-open to the UNCORRECTED evaluations on any error or when ``tenant``/
    ``profile`` is absent — a profile fault may never raise a tier or break voice.
    """
    if profile is None or tenant is None or not evaluations:
        return evaluations
    facts = _safe_recall(profile, tenant)
    if facts is None or not facts.facts:
        return evaluations
    try:
        out = []
        for e in evaluations:
            v = e.verdict
            ceiling = facts.tier_ceiling(v.claim_id)
            if ceiling is None:
                out.append(e)
                continue
            capped = cap_verdict(v, ceiling, record_id=_first_correction_id(facts, v.claim_id))
            out.append(e if capped is v else replace(e, verdict=capped))
        return tuple(out)
    except Exception:  # noqa: BLE001 — never break the voice path; keep gate verdicts
        _logger.warning("apply_profile_corrections failed; using uncorrected verdicts", exc_info=True)
        return evaluations


def _safe_recall(profile: ProfileMemory, tenant: str) -> ProfileFacts | None:
    try:
        return profile.recall_profile(tenant=tenant)
    except Exception:  # noqa: BLE001
        _logger.warning("profile recall failed; no corrections applied", exc_info=True)
        return None


def _first_correction_id(facts: ProfileFacts, claim_id: str) -> str | None:
    """The record_id of the most-cautious active correction for this subject (for
    the audit tag on the lowered verdict's reason)."""
    from tex.presence.profile.types import _norm_subject

    subject = _norm_subject(claim_id)
    best: Any | None = None
    for f in facts.corrections():
        if f.subject_key == subject and f.corrected_tier is not None:
            if best is None or _stricter(f.corrected_tier, best.corrected_tier):
                best = f
    return best.record_id if best is not None else None


def _stricter(a: PresenceTier, b: PresenceTier | None) -> bool:
    if b is None:
        return True
    return tighten(a, b) is a and a is not b

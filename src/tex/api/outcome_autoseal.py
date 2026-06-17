"""
Auto-seal a human resolution into a labeled, ingested OutcomeRecord.

When a human resolves a held (ABSTAIN) decision via ``POST
/decisions/{id}/seal``, the resolution is sealed as a hash-chained,
signed evidence row — but historically that act was never turned into a
labeled calibration/training outcome. The flywheel's fuel (the
accumulating corpus of *human-resolved ABSTAINs*) was generated and then
dropped on the floor: minting an ``OutcomeRecord`` required a separate,
discretionary ``POST /outcomes`` an operator would skip.

This module closes that gap. Every sealed human resolution mints a
labeled ``OutcomeRecord`` **by construction**, in the same request,
parent-linked to the resolution's ``record_hash`` (so the outcome is
provably tied to the sealed act, not free-floating) and routed into the
live feedback loop via the orchestrator's ``ingest_outcome`` — the exact
ingest path ``ReportOutcomeCommand`` itself delegates to (the sanctioned
``/outcomes`` path), reused rather than forked.

Design properties (load-bearing):

  * **Capture is not silently skippable.** The mint+ingest runs in the
    same handler. On any failure it does NOT swallow the error: the seal
    still succeeds (the human's act is never lost), but the response
    carries an explicit ``status="degraded"`` + ``warning`` and the
    failure is logged. Success returns ``status="captured"``.
  * **Never blocks the worker.** The ingest touches the outcome store
    (Postgres-capable, and its ``psycopg.connect`` is NOT
    connect-timeout-bounded — that store is owned by the durable track)
    and the evidence recorder (Postgres-capable mirror). To honour the
    single-worker invariant, the whole capture runs under a bounded
    ``ThreadPoolExecutor`` wait; if it exceeds the timeout the request
    returns ``degraded`` and frees the serving worker while the capture
    finishes (or fails) on a detached pool thread.
  * **Never auto-applies a policy.** ``ingest_outcome`` only validates,
    persists, updates reporter reputation, and folds the outcome into the
    autonomous calibration e-process trigger (which at most DRAFTS a
    PENDING proposal — application always requires an explicit human
    approver elsewhere). Minting an outcome cannot silently change a
    future verdict.
  * **Trust is earned, not forged.** The outcome is constructed at the
    default REPORTED tier with source HUMAN_REVIEWER / verification
    AUDIT_SIGN_OFF; the validator promotes it to VALIDATED (the tier the
    code grants a human reviewer — VERIFIED is reserved for
    external-audit / automated-replay sources). We never pre-stamp a
    higher tier than the validator would grant.

Behind the ``TEX_AUTOSEAL_OUTCOME`` flag, **default ON** — the capture is
the entire point. Operators who want the pre-existing seal-only behaviour
set ``TEX_AUTOSEAL_OUTCOME=0``.
"""

from __future__ import annotations

import logging
import os
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeoutError
from typing import Any

from tex.domain.decision import Decision
from tex.domain.outcome import OutcomeKind, OutcomeRecord
from tex.domain.outcome_trust import OutcomeSourceType, VerificationMethod
from tex.domain.verdict import Verdict


_logger = logging.getLogger(__name__)

#: Env flag — default ON. Any of {0,false,no,off} disables auto-mint.
FLAG_ENV = "TEX_AUTOSEAL_OUTCOME"
#: Env override for the bounded capture wait (seconds).
TIMEOUT_ENV = "TEX_AUTOSEAL_OUTCOME_TIMEOUT"
DEFAULT_TIMEOUT_S = 5.0

# Seals are rare (only human-resolved holds), so a tiny shared pool is
# ample. The pool exists solely to bound the serving worker's wait — see
# ``capture_resolution_outcome``. We deliberately do NOT use a
# ``with``-block executor (its __exit__ joins, which would defeat the
# timeout); a long-lived module pool with ``future.result(timeout=...)``
# is the correct shape.
_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="autoseal-outcome")


def autoseal_enabled() -> bool:
    """True unless ``TEX_AUTOSEAL_OUTCOME`` is explicitly falsey."""
    raw = os.environ.get(FLAG_ENV, "1").strip().lower()
    return raw not in {"0", "false", "no", "off"}


def _capture_timeout_seconds() -> float:
    raw = os.environ.get(TIMEOUT_ENV, "").strip()
    if not raw:
        return DEFAULT_TIMEOUT_S
    try:
        value = float(raw)
    except ValueError:
        return DEFAULT_TIMEOUT_S
    return value if value > 0 else DEFAULT_TIMEOUT_S


def map_resolution_to_outcome(
    *,
    decision_verdict: Verdict,
    human_verdict: str,
) -> tuple[OutcomeKind, bool | None, bool]:
    """
    Map ``(machine verdict, human act)`` → ``(outcome_kind, was_safe, human_override)``.

    The human act on a hold is ``approved`` / ``held`` / ``refused`` (the
    recorder normalises and validates these before we ever see them).

      * ``approved`` — the operator releases the action and thereby deems
        it safe in hindsight (``was_safe=True``).
      * ``refused``  — the operator blocks the action and deems it unsafe
        (``was_safe=False``).
      * ``held``     — the operator keeps it escalated; safety is still
        unknown (``was_safe=None``).

    A resolution is an *override* iff the operator's disposition reverses a
    *terminal* machine verdict: approving a FORBID, or refusing a PERMIT.
    Resolving an ABSTAIN is never an override — ABSTAIN exists precisely to
    delegate the call to a human, so the human deciding fulfils it rather
    than overriding it. Keeping a hold (``held``) is never an override of a
    terminal verdict either. ``human_override`` is derived as
    ``outcome_kind is OVERRIDDEN`` so the domain invariant
    (OVERRIDDEN ⇒ human_override) holds by construction.

    The label is then computed by ``OutcomeRecord.classify`` from
    ``(decision_verdict, outcome_kind, was_safe)``; e.g. a FORBID the human
    approves becomes ``FALSE_FORBID``, a PERMIT the human refuses becomes
    ``FALSE_PERMIT``, and any ABSTAIN becomes ``ABSTAIN_REVIEW``.
    """
    verdict_choice = (human_verdict or "").strip().lower()

    if verdict_choice == "approved":
        was_safe: bool | None = True
        override = decision_verdict is Verdict.FORBID
        kind = OutcomeKind.OVERRIDDEN if override else OutcomeKind.RELEASED
    elif verdict_choice == "refused":
        was_safe = False
        override = decision_verdict is Verdict.PERMIT
        kind = OutcomeKind.OVERRIDDEN if override else OutcomeKind.BLOCKED
    elif verdict_choice == "held":
        was_safe = None
        kind = OutcomeKind.ESCALATED
    else:
        # Defensive: the recorder already rejects anything else, but we
        # never trust an unchecked branch to silently mislabel.
        was_safe = None
        kind = OutcomeKind.UNKNOWN

    human_override = kind is OutcomeKind.OVERRIDDEN
    return kind, was_safe, human_override


def _build_outcome(
    *,
    decision: Decision,
    human_verdict: str,
    resolved_by: str,
    note: str | None,
) -> OutcomeRecord:
    """Construct the labeled, highest-trust-source OutcomeRecord."""
    kind, was_safe, human_override = map_resolution_to_outcome(
        decision_verdict=decision.verdict,
        human_verdict=human_verdict,
    )
    return OutcomeRecord.create(
        decision_id=decision.decision_id,
        request_id=decision.request_id,
        verdict=decision.verdict,
        outcome_kind=kind,
        was_safe=was_safe,
        human_override=human_override,
        summary=note,
        reporter=resolved_by,
        # Highest-trust source/verification available. trust_level is left
        # at the REPORTED default on purpose: the validator promotes it to
        # the tier a human reviewer earns (VALIDATED). Pre-stamping VERIFIED
        # here would forge a tier the sanctioned path does not grant.
        source_type=OutcomeSourceType.HUMAN_REVIEWER,
        verification_method=VerificationMethod.AUDIT_SIGN_OFF,
        confidence_score=1.0,
        # tenant_id intentionally None — the validator backfills it from the
        # linked decision so the stored outcome is tenant-scoped correctly.
        tenant_id=None,
        policy_version=decision.policy_version,
    )


def _do_capture(
    *,
    decision: Decision,
    human_verdict: str,
    resolved_by: str,
    note: str | None,
    parent_record_hash: str | None,
    orchestrator: Any,
    recorder: Any,
) -> dict[str, Any]:
    """
    The capture body run on the bounded pool: construct → ingest → seal a
    parent-linked outcome evidence row. Returns the response fragment.
    Raises on failure (caught by ``capture_resolution_outcome``).
    """
    outcome = _build_outcome(
        decision=decision,
        human_verdict=human_verdict,
        resolved_by=resolved_by,
        note=note,
    )

    # Sanctioned ingest: validate → persist → reputation → e-process
    # trigger. ``stored`` is the validated/promoted record actually in the
    # store (trust tier set, tenant backfilled), so the evidence row we
    # write next reflects the durable truth, not the raw input.
    ingest_result = orchestrator.ingest_outcome(outcome)
    stored = ingest_result.validation.outcome

    # Seal the outcome as its own evidence row, parent-linked by hash to
    # the human-resolution row it was minted from. ``parent_evidence_hash``
    # is a semantic cross-reference (the same idiom as
    # ``record_contract_violation`` / ``record_attribution``), not a chain
    # edge — so the link survives regardless of global chain interleaving.
    evidence = recorder.record_outcome(
        stored,
        policy_version=decision.policy_version,
        parent_evidence_hash=parent_record_hash,
        metadata={
            "auto_sealed": True,
            "human_verdict": (human_verdict or "").strip().lower(),
            "human_resolution_record_hash": parent_record_hash,
            "source_type": stored.source_type.value,
            "trust_level": stored.trust_level.value,
            "verification_method": stored.verification_method.value,
            "tenant_id": stored.tenant_id,
        },
    )

    return {
        "status": "captured",
        "outcome_id": str(stored.outcome_id),
        "outcome_label": stored.label.value,
        "outcome_kind": stored.outcome_kind.value,
        "trust_level": stored.trust_level.value,
        "was_safe": stored.was_safe,
        "human_override": stored.human_override,
        "ingested": bool(ingest_result.persisted),
        "quarantined": bool(ingest_result.quarantined),
        "reputation_updated": bool(ingest_result.reputation_updated),
        "parent_record_hash": parent_record_hash,
        "outcome_evidence_hash": evidence.record_hash,
    }


def _degraded(warning: str, *, error: str | None = None) -> dict[str, Any]:
    fragment: dict[str, Any] = {"status": "degraded", "warning": warning}
    if error is not None:
        fragment["error"] = error
    return fragment


def capture_resolution_outcome(
    *,
    request: Any,
    decision: Decision,
    human_verdict: str,
    resolved_by: str,
    note: str | None,
    parent_record_hash: str | None,
) -> dict[str, Any]:
    """
    Mint + ingest + seal the labeled outcome for a just-sealed resolution.

    Returns a response fragment for the seal handler to attach under
    ``outcome_capture``. Never raises: a capture failure degrades the
    fragment (with a warning, and a log line) but must not lose the human's
    sealed act. ``status`` is one of ``captured`` / ``degraded`` /
    ``disabled``.
    """
    if not autoseal_enabled():
        return {
            "status": "disabled",
            "warning": (
                f"Outcome auto-mint disabled by {FLAG_ENV}; the resolution "
                "is sealed but no labeled outcome was generated."
            ),
        }

    orchestrator = getattr(request.app.state, "learning_orchestrator", None)
    recorder = getattr(request.app.state, "evidence_recorder", None)
    if orchestrator is None or recorder is None:
        warning = (
            "Outcome capture skipped: learning orchestrator or evidence "
            "recorder is not wired on app state; resolution sealed without "
            "minting a labeled outcome."
        )
        _logger.error(
            "autoseal_outcome: %s (decision_id=%s)",
            warning,
            decision.decision_id,
        )
        return _degraded(warning)

    future = _executor.submit(
        _do_capture,
        decision=decision,
        human_verdict=human_verdict,
        resolved_by=resolved_by,
        note=note,
        parent_record_hash=parent_record_hash,
        orchestrator=orchestrator,
        recorder=recorder,
    )
    timeout = _capture_timeout_seconds()
    try:
        return future.result(timeout=timeout)
    except FutureTimeoutError:
        warning = (
            f"Outcome capture exceeded {timeout:.1f}s and did not complete "
            "in-band; the resolution is sealed and capture continues on a "
            "background worker, but the labeled outcome is not confirmed in "
            "this response."
        )
        _logger.error(
            "autoseal_outcome: capture timed out after %.1fs (decision_id=%s)",
            timeout,
            decision.decision_id,
        )
        return _degraded(warning)
    except Exception as exc:  # noqa: BLE001 — capture must never sink the seal
        warning = (
            "Outcome capture failed; the resolution is sealed but no labeled "
            "outcome was ingested. See server logs."
        )
        _logger.exception(
            "autoseal_outcome: capture failed (decision_id=%s): %s",
            decision.decision_id,
            exc,
        )
        return _degraded(warning, error=str(exc))


__all__ = [
    "FLAG_ENV",
    "TIMEOUT_ENV",
    "DEFAULT_TIMEOUT_S",
    "autoseal_enabled",
    "map_resolution_to_outcome",
    "capture_resolution_outcome",
]

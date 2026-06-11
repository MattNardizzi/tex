"""
The Honest-Decline demo — Tex refuses, and names the fact it is missing.

[Architecture: Engine (ABSTAIN/Hold) + Layer 5 (Evidence)]

The competitor's failure mode is a confident answer with nothing under it. Tex's
differentiator is the opposite: when it cannot stand behind a call, it ABSTAINs
*and tells you the single fact whose absence is the reason* — so the hold is
actionable, not a shrug.

This demo asks Tex to stand behind a moderate-stakes approval ("should I approve
this vendor's invoice for $4,200?") taken by an agent Tex has **never sealed any
evidence about**. The request is not content-dangerous on its own — a benign
phrasing would auto-PERMIT — but with no behavioral history to lean on, the
call lands in the hold band: Tex will not rule alone. The runtime returns
ABSTAIN, and the deterministic hold-builder
(``tex.engine.hold.build_hold``) reads the real uncertainty flags the evaluator
raised and surfaces the pivotal one. The named missing fact is engine output,
not a script: for a never-before-seen agent it is the ``cold_start`` flag —
*"how this agent has behaved before — there is no history yet."*

Honesty notes that keep this from being theater:
- The resolving question is whatever the *real* pipeline raised; we do not
  hand-pick a flag. (Historical note: the pivot census used to carry phantom
  keys no evaluator emitted — e.g. ``low_evidence_sufficiency`` — which this
  bench deliberately refused to claim. The census was reconciled with the
  live emitters on 2026-06-10 and is now guarded by a tripwire test, so every
  census question is one the pipeline can genuinely raise.)
- The decline is itself sealed into the evidence chain, so "Tex declined, here is
  why" is a tamper-evident, offline-verifiable fact — not a transient UI string.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

from tex.bench.evidence_bundle import BundleVerification, trusted_public_key_b64, verify_bundle, write_bundle
from tex.domain.evaluation import EvaluationRequest
from tex.domain.verdict import Verdict
from tex.engine.hold import build_hold

# A fixed agent id that a freshly-built runtime has never witnessed — so the run
# is deterministic (same input → same verdict, flags, and named missing fact).
UNKNOWN_AGENT_ID = UUID("00000000-0000-4000-8000-00000000dec1")

# A moderate-stakes question Tex is asked to stand behind with no sealed history.
# Benign phrasings auto-PERMIT; this one carries just enough stake that, absent
# any behavioral evidence about the agent, the call falls into the hold band.
DECLINE_QUESTION = "Should I approve this vendor's invoice for $4,200?"


@dataclass(frozen=True, slots=True)
class HonestDeclineResult:
    verdict: str
    declined: bool  # verdict is ABSTAIN
    pivotal_flag: str | None
    named_missing_fact: str | None  # the resolving question — engine-derived
    sentence: str
    detail: str | None
    uncertainty_flags: tuple[str, ...]
    sealed_record_count: int
    bundle_path: str
    verification: BundleVerification
    notes: tuple[str, ...] = field(default_factory=tuple)

    @property
    def passed(self) -> bool:
        """Passes iff Tex declined AND named a real missing fact AND sealed it."""
        return (
            self.declined
            and self.pivotal_flag is not None
            and bool(self.named_missing_fact)
            and self.verification.valid
        )


def run_honest_decline(
    runtime,
    *,
    bundle_path: str | Path,
    question: str = DECLINE_QUESTION,
    agent_id: UUID = UNKNOWN_AGENT_ID,
) -> HonestDeclineResult:
    """Drive the runtime to an honest decline and seal it.

    ``runtime`` must be built with a clean ``evidence_path`` so the sealed chain
    holds only this decline.
    """
    request = EvaluationRequest(
        request_id=UUID("00000000-0000-4000-8000-00000000d0c2"),
        action_type="answer",
        content=question,
        recipient=None,
        channel="api",
        environment="production",
        metadata={},
        policy_id=None,
        agent_id=agent_id,
        requested_at=datetime.now(UTC),
    )
    result = runtime.evaluate_action_command.execute(request)
    response = result.response

    declined = response.verdict is Verdict.ABSTAIN

    # Build the hold from the REAL uncertainty flags the pipeline raised. The
    # certificate is None here (no live calibration band) — band_certified will
    # be False, which is the honest posture; the named fact does not depend on it.
    hold = build_hold(
        verdict=response.verdict,
        final_score=response.final_score,
        uncertainty_flags=tuple(response.uncertainty_flags),
        certificate=None,
        confidence=response.confidence,
        agent_id="new-vendor-bot",
        action_type="approve_invoice",
    )

    notes: list[str] = []
    if hold is None:
        notes.append(
            f"verdict was {response.verdict.value}, not ABSTAIN — no hold to surface. "
            f"(Only an ABSTAIN may raise a user-facing hold; PERMIT/FORBID stay silent.)"
        )

    # The decline was sealed by the runtime; verify it offline, pinned to Tex's key.
    sealed = runtime.evidence_recorder.read_all()
    out = write_bundle(sealed, bundle_path)
    pin = trusted_public_key_b64(runtime.evidence_recorder._chain_signer)
    verification = verify_bundle(sealed, pinned_public_key_b64=pin)

    return HonestDeclineResult(
        verdict=response.verdict.value,
        declined=declined,
        pivotal_flag=hold.pivotal_flag if hold else None,
        named_missing_fact=hold.resolving_question if hold else None,
        sentence=hold.sentence if hold else "",
        detail=hold.detail if hold else None,
        uncertainty_flags=tuple(response.uncertainty_flags),
        sealed_record_count=len(sealed),
        bundle_path=str(out),
        verification=verification,
        notes=tuple(notes),
    )


__all__ = [
    "DECLINE_QUESTION",
    "UNKNOWN_AGENT_ID",
    "HonestDeclineResult",
    "run_honest_decline",
]

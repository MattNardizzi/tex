"""Compose the spoken presence answer from the gate's verdicts — and raise a
held decision when nothing could be grounded.

The composition rule is what makes "cannot lie" airtight at the speech layer:

  * A SEALED/DERIVED claim contributes the GATE's canonical phrasing of the
    recomputed value (``Recompute.canonical_phrase``) — never the brain's raw
    span. Injected/hostile text in the draft is therefore discarded by
    construction; the user only ever hears the gate's phrasing of a recomputed
    truth.
  * An ABSTAIN claim is STRIPPED — it contributes nothing to the spoken text and
    is dropped from the envelope's claims/verdicts (it survives in
    ``surface_object`` for the UI and telemetry).
  * If NOTHING is supported, the spoken text is the existing deterministic
    templated ABSTAIN answer, and ONE held decision (``dimension="presence"``) is
    raised into the existing ``HeldDecisionSink`` — no new route.

Prosody is bound as the pure function of the spoken answer's overall tier
(:meth:`AnswerEnvelope.with_bound_prosody`), so the voice's confidence is the
gate's verdict, not the model's vibe.
"""

from __future__ import annotations

import logging
from typing import Any
from uuid import UUID

from tex.presence.contract import (
    AnswerEnvelope,
    PresenceClaim,
    PresenceTier,
    ProsodyPlan,
)
from tex.presence.gate.gate import ClaimEvaluation, PresenceTruthGate
from tex.presence.gate.telemetry import PresenceTelemetry

_logger = logging.getLogger(__name__)

__all__ = ["build_envelope", "raise_presence_hold", "run_presence", "PRESENCE_HOLD_AGENT_ID"]

# A stable sentinel agent_id for a presence-origin hold that is not tied to any
# single agent (the answer-level abstain). HeldDecision requires a UUID; this one
# is reserved and documented rather than faked from a real agent.
PRESENCE_HOLD_AGENT_ID = UUID(int=0)


def _surface_object(detailed: tuple[ClaimEvaluation, ...]) -> dict[str, Any]:
    """The hold-to-see structured object: every claim, supported or not, with its
    tier, recomputed value, evidence anchors and reason. Honest and complete."""
    rows = []
    for e in detailed:
        v = e.verdict
        rows.append({
            "claim_id": v.claim_id,
            "tier": v.tier.value,
            "kind": e.claim.kind.value,
            "recomputed_value": v.recomputed_value,
            "correctness_floor": v.correctness_floor,
            "coverage_mode": v.coverage_mode,
            "evidence": [
                {"record_id": r.record_id, "record_hash": r.record_hash,
                 "store": r.store, "field": r.field}
                for r in v.evidence
            ],
            "reason": v.reason,
        })
    return {"claims": rows}


def build_envelope(
    detailed: tuple[ClaimEvaluation, ...],
    *,
    templated_abstain: str,
    attestor: Any = None,
) -> AnswerEnvelope:
    """Assemble the envelope spoken to the user. Supported claims contribute the
    gate's canonical phrasing; ABSTAIN claims are stripped. Prosody is bound to
    the spoken answer's overall tier."""
    supported = [
        e for e in detailed
        if e.verdict.tier is not PresenceTier.ABSTAIN
        and e.recompute is not None
        and e.recompute.canonical_phrase
    ]
    surface = _surface_object(detailed)

    if not supported:
        # Nothing grounded — speak the existing deterministic ABSTAIN answer.
        return AnswerEnvelope(
            spoken_text=templated_abstain,
            claims=(),
            verdicts=(),
            prosody_plan=ProsodyPlan.from_tier(PresenceTier.ABSTAIN),
            surface_object=surface,
        )

    spoken = " ".join(e.recompute.canonical_phrase for e in supported)  # type: ignore[union-attr]
    # Rewrite each supported claim's span to the gate-authored phrasing so the
    # envelope's claims are consistent with what is actually spoken.
    claims = tuple(
        PresenceClaim(
            claim_id=e.claim.claim_id,
            text_span=e.recompute.canonical_phrase,  # type: ignore[union-attr]
            kind=e.claim.kind,
        )
        for e in supported
    )
    verdicts = tuple(e.verdict for e in supported)
    envelope = AnswerEnvelope(
        spoken_text=spoken,
        claims=claims,
        verdicts=verdicts,
        surface_object=surface,
    ).with_bound_prosody()

    # Defensive: the structural invariant (claim↔verdict pairing, prosody bound)
    # must hold before speaking. If it ever doesn't, fall back to ABSTAIN.
    try:
        envelope.assert_supported()
    except ValueError:
        _logger.warning("presence envelope failed assert_supported; falling back to ABSTAIN")
        return AnswerEnvelope(
            spoken_text=templated_abstain,
            prosody_plan=ProsodyPlan.from_tier(PresenceTier.ABSTAIN),
            surface_object=surface,
        )

    # Post-gate proof step (Session 3): sign the (claim → evidence → tier) binding
    # so the proof glass can show a verifiable attestation. No-op when no attestor
    # is wired or sealing is OFF (TEX_SEAL_DECISIONS unset) → attestation stays
    # None (contract-allowed). Only ever SETS .attestation on the verdicts; never
    # touches tier/claims/prosody, so the invariant asserted above still holds.
    if attestor is not None:
        from tex.presence.attest import apply_attestation  # local import: keep the gate decoupled

        envelope = apply_attestation(envelope, attestor)
    return envelope


def raise_presence_hold(
    held_sink: Any,
    detailed: tuple[ClaimEvaluation, ...],
    *,
    transcript: str | None = None,
) -> Any | None:
    """Raise ONE ``dimension="presence"`` held decision for an answer that could
    not be grounded (the consequential, surfaceable event). Best-effort: never
    raises into the voice path. Returns the HeldDecision appended, or None."""
    if held_sink is None or not hasattr(held_sink, "append"):
        return None
    try:
        from tex.provenance.feed import HeldDecision  # local import: keep gate decoupled

        abstained = [e for e in detailed if e.verdict.tier is PresenceTier.ABSTAIN]
        reasons = [{"claim_id": e.verdict.claim_id, "reason": e.verdict.reason,
                    "text_span": e.claim.text_span} for e in abstained]
        hold = HeldDecision(
            agent_id=PRESENCE_HOLD_AGENT_ID,
            kind="presence_abstain",
            confidence=0.0,
            note="presence could not ground the spoken answer; held for review",
            detail={
                "dimension": "presence",  # the vigil provider reads dimension from here
                "transcript": transcript,
                "abstained_claims": reasons,
            },
        )
        held_sink.append(hold)
        return hold
    except Exception:  # noqa: BLE001 — a hold must never break the voice
        _logger.debug("presence hold append swallowed an error", exc_info=True)
        return None


def run_presence(
    *,
    gate: PresenceTruthGate,
    request: Any,
    tenant: str | None,
    brain: Any,
    transcript: str,
    facts: Any,
    templated_abstain: str,
    telemetry: PresenceTelemetry | None = None,
    held_sink: Any = None,
    attestor: Any = None,
) -> AnswerEnvelope | None:
    """Run the presence channel in PARALLEL to the deterministic voice path.

    Returns the presence :class:`AnswerEnvelope`, or ``None`` when presence is
    not engaged (no brain configured / brain proposed no claims) — in which case
    the caller keeps its legacy deterministic answer untouched. Never raises into
    the voice path: any internal failure yields ``None`` (fail-closed to legacy).
    """
    try:
        draft, claims = brain.propose(
            question=transcript, tenant=tenant, facts=facts, tools=(),
        )
    except Exception:  # noqa: BLE001
        _logger.debug("presence brain.propose swallowed an error", exc_info=True)
        return None

    if not claims:
        return None  # presence not engaged → caller uses the legacy path

    try:
        detailed = gate.evaluate_detailed(
            request=request, tenant=tenant, draft=draft, claims=tuple(claims), facts=facts,
        )
    except Exception:  # noqa: BLE001 — the gate is built not to raise, but belt-and-braces
        _logger.warning("presence gate raised; abstaining", exc_info=True)
        return AnswerEnvelope(spoken_text=templated_abstain, surface_object=None)

    if telemetry is not None:
        telemetry.observe_answer([e.verdict for e in detailed])

    envelope = build_envelope(detailed, templated_abstain=templated_abstain, attestor=attestor)

    if not envelope.verdicts:  # answer-level ABSTAIN → surface one hold
        raise_presence_hold(held_sink, detailed, transcript=transcript)

    return envelope

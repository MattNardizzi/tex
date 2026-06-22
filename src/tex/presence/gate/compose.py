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
    tier, recomputed value, evidence anchors and reason. Honest and complete.

    Each row also carries ``subject_key`` — the STABLE subject an operator
    correction is scoped to (the gate's routing identity, not the volatile
    claim_id). The confirm/correct UI echoes this back to ``/v1/presence/profile/
    correct`` so a correction caps the SAME thing when the question is asked again.
    """
    from tex.presence.profile.influence import stable_subject_key  # local: keep gate decoupled

    rows = []
    for e in detailed:
        v = e.verdict
        rows.append({
            "claim_id": v.claim_id,
            "subject_key": stable_subject_key(e),
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


def _resolve_decision_store(request: Any) -> Any | None:
    """The app's decision store from ``request.app.state`` on the live path, else
    ``None`` (a bare test double, or an unwired app). When ``None`` the producer
    degrades to appending a hold with ``decision_id=None`` — exactly the pre-producer
    behaviour — so the gate never depends on the store being wired."""
    state = getattr(getattr(request, "app", None), "state", None)
    return getattr(state, "decision_store", None) if state is not None else None


def _build_presence_abstain_decision(
    transcript: str | None, reasons: list[dict[str, Any]]
) -> Any | None:
    """Build the durable ``Decision`` that makes an answer-level presence ABSTAIN a
    SEALABLE /held card — WITHOUT fabricating a risk score.

    A presence ABSTAIN is a claim-GROUNDING credibility event, not a governed action
    with a fused risk: there is no decisive-step ``final_score`` to record (the
    conformal floor's calibration point is the score of a human-confirmed true
    decisive-error step in an action trace — ``tex.causal.conformal_attribution`` —
    which an answer-level abstain has none of). So we persist an HONEST ABSTAIN record:

      * ``final_score=0.0`` / ``confidence=0.0`` mean *no fused risk was computed*, not
        "zero risk" — stated out loud in ``reasons`` and ``uncertainty_flags`` because
        the field is non-nullable, never as a real score.
      * ``metadata["dimension"]="presence"`` is the honest provenance marker (mirrors
        the HeldDecision's ``detail["dimension"]``).
      * ``metadata["presence_calibration_eligible"]=False`` EXPLICITLY tells the
        conformal feed this Decision carries no decisive-step score, so its placeholder
        ``final_score`` is never read as a calibration point
        (``tex.presence.memory.calibration.record_resolution`` is fail-closed: a
        presence-origin Decision feeds only when this is ``True``).

    Returns the Decision, or ``None`` if construction fails (the caller then appends a
    hold with ``decision_id=None`` — the card is simply not sealable, voice unaffected).
    """
    try:
        import hashlib
        from uuid import uuid4

        from tex.domain.decision import Decision
        from tex.domain.verdict import Verdict

        text = (transcript or "").strip()
        excerpt = text[:2000] if text else "(presence answer: no transcript)"
        content_sha = hashlib.sha256(text.encode("utf-8")).hexdigest()
        claim_ids = [r["claim_id"] for r in reasons if r.get("claim_id")]
        return Decision(
            request_id=uuid4(),
            verdict=Verdict.ABSTAIN,
            confidence=0.0,
            final_score=0.0,  # NO fused risk — a grounding ABSTAIN is not a scored action
            action_type="presence_answer",
            channel="voice",
            environment="presence",
            content_excerpt=excerpt,
            content_sha256=content_sha,
            policy_version="presence-gate",
            reasons=["presence could not ground the spoken answer"],
            uncertainty_flags=["presence_ungrounded_no_fused_risk"],
            metadata={
                "dimension": "presence",
                "presence_kind": "answer_abstain",
                # No decisive-step score exists → never feed the conformal floor.
                "presence_calibration_eligible": False,
                "abstained_claim_ids": claim_ids,
            },
        )
    except Exception:  # noqa: BLE001 — a producer hiccup must never break the voice
        _logger.debug("presence decision construction swallowed an error", exc_info=True)
        return None


def raise_presence_hold(
    held_sink: Any,
    detailed: tuple[ClaimEvaluation, ...],
    *,
    transcript: str | None = None,
    decision_store: Any = None,
) -> Any | None:
    """Raise ONE ``dimension="presence"`` held decision for an answer that could
    not be grounded (the consequential, surfaceable event). Best-effort: never
    raises into the voice path. Returns the HeldDecision appended, or None.

    When ``decision_store`` is wired, ALSO persist an honest presence-origin ABSTAIN
    ``Decision`` (no fabricated risk score; see :func:`_build_presence_abstain_decision`)
    and stamp its ``decision_id`` onto the hold, so the /held card is SEALABLE
    end-to-end (``POST /decisions/{id}/seal`` can resolve it). Without a store
    (legacy/tests) the hold is appended with ``decision_id=None`` exactly as before."""
    if held_sink is None or not hasattr(held_sink, "append"):
        return None
    try:
        from tex.provenance.feed import HeldDecision  # local import: keep gate decoupled

        abstained = [e for e in detailed if e.verdict.tier is PresenceTier.ABSTAIN]
        reasons = [{"claim_id": e.verdict.claim_id, "reason": e.verdict.reason,
                    "text_span": e.claim.text_span} for e in abstained]

        # Producer: make the /held card a SEALABLE Decision when a store is wired.
        decision_id: str | None = None
        if decision_store is not None and hasattr(decision_store, "save"):
            decision = _build_presence_abstain_decision(transcript, reasons)
            if decision is not None:
                try:
                    decision_store.save(decision)
                    decision_id = str(decision.decision_id)
                except Exception:  # noqa: BLE001 — persistence is best-effort
                    _logger.debug("presence decision save swallowed an error", exc_info=True)
                    decision_id = None

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
            decision_id=decision_id,  # stamped → /held card is sealable (None if no store)
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
    profile: Any = None,
) -> AnswerEnvelope | None:
    """Run the presence channel in PARALLEL to the deterministic voice path.

    Returns the presence :class:`AnswerEnvelope`, or ``None`` when presence is
    not engaged (no brain configured / brain proposed no claims) — in which case
    the caller keeps its legacy deterministic answer untouched. Never raises into
    the voice path: any internal failure yields ``None`` (fail-closed to legacy).

    ``profile`` (optional :class:`~tex.presence.profile.types.ProfileMemory`): the
    per-tenant correction store. When present, an operator's prior corrections cap
    the matching claims AFTER the gate and BEFORE composition — monotone, so a
    correction can only tighten (lower) a tier, never raise one. Fail-open: with
    ``profile``/``tenant`` absent or on any profile fault the gate's verdicts stand
    unchanged, so this can never break the voice.
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

    # Apply the operator's per-tenant CORRECTIONS between the gate and composition.
    # Monotone (tighten-only) and fail-open — see apply_profile_corrections. Snapshot
    # the gate's tiers first so we can measure over-suppression (corrections can only
    # lower, so any tier change here is a suppression — the metric to watch).
    from tex.presence.profile.influence import apply_profile_corrections  # local: keep gate decoupled

    pre_tiers = [e.verdict.tier for e in detailed]
    detailed = apply_profile_corrections(tenant=tenant, evaluations=detailed, profile=profile)

    if telemetry is not None:
        try:
            lowered = sum(1 for pre, e in zip(pre_tiers, detailed) if e.verdict.tier is not pre)
            telemetry.observe_answer([e.verdict for e in detailed], claims_lowered=lowered)
        except Exception:  # noqa: BLE001 — telemetry must never break the voice
            _logger.debug("presence telemetry observe swallowed an error", exc_info=True)

    try:
        envelope = build_envelope(detailed, templated_abstain=templated_abstain, attestor=attestor)
    except Exception:  # noqa: BLE001 — composition/attestation must never break the voice
        _logger.warning("presence build_envelope raised; abstaining", exc_info=True)
        return AnswerEnvelope(spoken_text=templated_abstain, surface_object=None)

    if not envelope.verdicts:  # answer-level ABSTAIN → surface one hold
        raise_presence_hold(
            held_sink,
            detailed,
            transcript=transcript,
            decision_store=_resolve_decision_store(request),
        )

    return envelope

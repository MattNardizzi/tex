"""
[Architecture: Voice cognition] — the ``/v1/ask`` grounding pipeline.

This is THE integrity boundary. A transcript comes in; an answer Tex can prove
goes out, or an honest abstention. The pipeline is a fixed sequence, every step
deterministic and zero-LLM on the load-bearing path:

    route_intent → fetch SEALED facts → fill an AUTHORED template → the GATE →
    verdict → seal a voice-attestation record.

Zero-LLM is enforced structurally, not by hope: facts are fetched through a
``provider=None`` ``Explainer`` (``tex.vigil``) — the app may have an LLM
explainer configured for the *prose* surface (``/v1/vigil/explain``), but the
voice answer reads ONLY the deterministic ``.facts`` and never the provider
narration, so no model is ever on this path.

Verdict → spoken surface (the doctrine):
  * PERMIT  → the grounded sentence + (for a record) the one handle object +
              the sealed proof_ref.
  * ABSTAIN → an authored honest-decline sentence, no object. ``/v1/ask`` is a
              direct spoken answer, NOT a held card — it never raises a vigil
              hold (only an ABSTAIN on the /v1/vigil channel does that). So the
              "only ABSTAIN surfaces a hold" invariant is satisfied trivially:
              /v1/ask surfaces no hold at all, it speaks.
  * FORBID  → a refusal sentence (the question asserted something the sealed
              record contradicts), no object. Delivered as a refusal, never as
              a hold.

Every outcome — PERMIT, ABSTAIN, FORBID — is sealed into the voice-attestation
chain, so even a decline is provable.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any
from uuid import UUID

from tex.domain.verdict import Verdict
from tex.presence.contract import NULL_BRAIN, AnswerEnvelope
from tex.presence.gate import PresenceTelemetry, PresenceTruthGate, run_presence
from tex.vigil import Explainer
from tex.voice import answer_forms
from tex.voice.attestation import VoiceAttestor
from tex.voice.intent import HandleKind, Intent, IntentKind, route_intent
from tex.voice.voice_gate import VoiceGate

__all__ = ["AskOutcome", "answer_question", "get_attestor", "get_presence_telemetry"]


# A deterministic, provider-free explainer: it builds the sealed EvidenceFacts
# from app.state stores and NEVER calls a model. Stateless and safe to share.
_FACTS_EXPLAINER = Explainer(provider=None)
_GATE = VoiceGate()

# The presence truth-gate runs in PARALLEL to VoiceGate (it never replaces the
# deterministic sealed-fact floor). It is INERT by default: with no brain on
# app.state the NULL_BRAIN proposes no claims, so presence stays None and the
# live answer is byte-identical to before this wiring.
_PRESENCE_GATE = PresenceTruthGate()
_PRESENCE_TELEMETRY = PresenceTelemetry()

_ATTESTOR_LOCK = threading.Lock()


def get_presence_telemetry() -> PresenceTelemetry:
    """The process-wide presence telemetry (abstain / grounding / mismatch)."""
    return _PRESENCE_TELEMETRY


def _run_presence(
    request: Any, *, transcript: str, tenant: str | None, facts: Any, templated_abstain: str
) -> AnswerEnvelope | None:
    """Run the presence channel for a dimension question. Best-effort and inert
    unless a GroundedBrain is configured on ``app.state.presence_brain``."""
    state = getattr(getattr(request, "app", None), "state", None)
    brain = getattr(state, "presence_brain", None) or NULL_BRAIN
    held_sink = getattr(state, "held_decision_sink", None)
    attestor = getattr(state, "presence_attestor", None)
    profile = getattr(state, "presence_profile", None)
    def _go() -> AnswerEnvelope | None:
        return run_presence(
            gate=_PRESENCE_GATE,
            request=request,
            tenant=tenant,
            brain=brain,
            transcript=transcript,
            facts=facts,
            templated_abstain=templated_abstain,
            telemetry=_PRESENCE_TELEMETRY,
            held_sink=held_sink,
            attestor=attestor,
            profile=profile,
        )

    # L1 flywheel: when a per-tenant calibration feed exists, let the conformal
    # gate read THIS tenant's calibration so it tightens as holds resolve. Inert
    # (plain transductive) when no feed or no tenant — never changes behavior then.
    feed = getattr(state, "presence_calibration", None)
    if feed is not None and tenant:
        try:
            from tex.presence.memory import tenant_calibration_env

            with tenant_calibration_env(feed, tenant):
                return _go()
        except Exception:  # calibration must never break the voice path
            return _go()
    return _go()


@dataclass(frozen=True, slots=True)
class AskOutcome:
    verdict: Verdict
    answer: str
    object: dict[str, Any] | None = None
    proof_ref: dict[str, Any] | None = None
    routed_dimension: str | None = None
    attestation_anchor: str | None = None
    attestation_algorithm: str | None = None
    gate: dict[str, Any] = field(default_factory=dict)
    # The presence channel's bound answer (words + per-claim verdicts + prosody),
    # produced by the truth-gate running in parallel to VoiceGate. None unless a
    # GroundedBrain is engaged; the legacy fields above are untouched either way.
    presence: AnswerEnvelope | None = None


def get_attestor(request: Any) -> VoiceAttestor:
    """Lazily attach a single ``VoiceAttestor`` to ``app.state`` (mirrors the
    lazy ``vigil_engine``/``vigil_explainer`` pattern in vigil_routes). One per
    process so the chain is continuous across requests."""
    state = getattr(request.app, "state", None)
    attestor = getattr(state, "voice_attestor", None)
    if attestor is not None:
        return attestor
    with _ATTESTOR_LOCK:
        attestor = getattr(state, "voice_attestor", None)
        if attestor is None:
            attestor = VoiceAttestor()
            if state is not None:
                state.voice_attestor = attestor
        return attestor


def _gate_summary(gate_result: Any) -> dict[str, Any]:
    return {
        "scorer": gate_result.scorer,
        "verdict": gate_result.verdict.value,
        "threshold_label": gate_result.threshold_label,
        "reason": gate_result.reason,
        "claims": [
            {
                "token": c.token,
                "kind": c.kind,
                "source_field": c.source_field,
                "outcome": c.outcome,
            }
            for c in gate_result.claims
        ],
    }


def _lookup_decision(request: Any, intent: Intent) -> Any | None:
    """Resolve the sealed Decision the operator named. UUID → direct id lookup;
    a bare SHA-256 → scan recent decisions for a matching content/evidence hash
    (we key records by id, so a hash is resolved by search, not by index)."""
    store = getattr(getattr(request.app, "state", None), "decision_store", None)
    if store is None:
        return None
    handle = intent.handle or ""
    if intent.handle_kind is HandleKind.NAME:
        try:
            return store.get(UUID(handle))
        except (ValueError, AttributeError):
            return None
    # HASH handle: search recent decisions by content/evidence hash.
    target = handle.casefold()
    try:
        recent = store.list_recent(limit=500)
    except AttributeError:
        return None
    for d in recent:
        for attr in ("content_sha256", "evidence_hash"):
            val = getattr(d, attr, None)
            if val and str(val).casefold() == target:
                return d
    return None


def answer_question(
    request: Any,
    *,
    transcript: str,
    tenant: str | None,
) -> AskOutcome:
    """Answer a spoken question ONLY from sealed facts, or abstain. Never raises
    on a bad transcript — an unanswerable question is an ABSTAIN, not a 500."""
    intent = route_intent(transcript)
    attestor = get_attestor(request)

    def _seal(
        outcome_verdict: Verdict, answer: str, obj, proof, dim, gate_dict,
        presence: AnswerEnvelope | None = None,
    ) -> AskOutcome:
        rec = attestor.seal(
            transcript=transcript,
            routed_dimension=dim,
            verdict=outcome_verdict.value,
            answer=answer,
            object_=obj,
            proof_ref=proof,
            gate=gate_dict,
            tenant=tenant,
        )
        return AskOutcome(
            verdict=outcome_verdict,
            answer=answer,
            object=obj,
            proof_ref=proof,
            routed_dimension=dim,
            attestation_anchor=rec.record_hash,
            attestation_algorithm=attestor.algorithm,
            gate=gate_dict,
            presence=presence,
        )

    # ── No sealed source could be resolved ──────────────────────────────────
    if intent.kind is IntentKind.ABSTAIN:
        return _seal(
            Verdict.ABSTAIN,
            answer_forms.ABSTAIN_NO_ROUTE,
            None, None, None,
            {"reason": intent.reason, "scorer": "router", "route": "abstain"},
        )

    # ── A record: the operator named one exact sealed object ────────────────
    if intent.kind is IntentKind.RECORD:
        decision = _lookup_decision(request, intent)
        if decision is None:
            return _seal(
                Verdict.ABSTAIN, answer_forms.ABSTAIN_NO_RECORD, None, None, "record",
                {"reason": "record-not-found", "scorer": "router", "handle": intent.handle},
            )
        build = answer_forms.build_record_answer(decision)
        if build is None:
            return _seal(
                Verdict.ABSTAIN, answer_forms.ABSTAIN_NO_RECORD, None, None, "record",
                {"reason": "record-not-verbalizable", "scorer": "router"},
            )
        sealed_verdict = getattr(getattr(decision, "verdict", None), "value", None)
        gate = _GATE.evaluate(
            answer=build.answer, template=build.template, slots=build.slots,
            asserted_verdict=intent.asserted_verdict, sealed_verdict=sealed_verdict,
        )
        gate_dict = _gate_summary(gate)
        if gate.verdict is Verdict.FORBID:
            return _seal(Verdict.FORBID, answer_forms.FORBID_CONTRADICTION, None, None, "record", gate_dict)
        if gate.verdict is Verdict.PERMIT:
            return _seal(Verdict.PERMIT, build.answer, build.object, build.proof_ref, "record", gate_dict)
        return _seal(Verdict.ABSTAIN, answer_forms.ABSTAIN_NO_RECORD, None, None, "record", gate_dict)

    # ── A dimension question ────────────────────────────────────────────────
    dimension = intent.dimension or ""
    explanation = _FACTS_EXPLAINER.explain(request, dimension=dimension, tenant=tenant, claim_text=None)
    facts = explanation.facts
    if facts.is_empty():
        return _seal(
            Verdict.ABSTAIN, answer_forms.ABSTAIN_NO_FACT, None, None, dimension,
            {"reason": "no-sealed-fact", "scorer": "router"},
        )
    # Presence runs in PARALLEL to VoiceGate, off the SAME sealed facts. It never
    # replaces the deterministic floor below; it only attaches an optional bound
    # answer. Inert (None) unless a GroundedBrain is configured.
    presence_env = _run_presence(
        request, transcript=transcript, tenant=tenant, facts=facts,
        templated_abstain=answer_forms.ABSTAIN_NO_FACT,
    )

    build = answer_forms.build_dimension_answer(dimension, facts)
    if build is None:
        return _seal(
            Verdict.ABSTAIN, answer_forms.ABSTAIN_NO_FACT, None, None, dimension,
            {"reason": "no-fillable-form", "scorer": "router"}, presence_env,
        )
    # A dimension question has no single sealed verdict to contradict, so the
    # structural FORBID (Rule B) cannot fire here — sealed_verdict stays None.
    gate = _GATE.evaluate(
        answer=build.answer, template=build.template, slots=build.slots,
        asserted_verdict=None, sealed_verdict=None,
    )
    gate_dict = _gate_summary(gate)
    if gate.verdict is Verdict.PERMIT:
        return _seal(Verdict.PERMIT, build.answer, build.object, build.proof_ref, dimension, gate_dict, presence_env)
    return _seal(Verdict.ABSTAIN, answer_forms.ABSTAIN_NO_FACT, None, None, dimension, gate_dict, presence_env)

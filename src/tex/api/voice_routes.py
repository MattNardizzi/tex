"""
The voice surface — ``/v1/voice/token``, ``/v1/ask``, ``/v1/speak``.

These three endpoints are the server side of the grounded cascade the client
(``tex-systems``) already drives: hold-to-talk streams 16 kHz PCM to the
self-hosted gateway (``tex.gateway``) for STT, the final transcript hits
``POST /v1/ask`` — THE INTEGRITY BOUNDARY, answered only from sealed facts —
and the grounded line is synthesized back by ``GET /v1/speak``. There is never
a free-running model in the speaking seat; this is a deliberate cascade, never
end-to-end speech-to-speech.

Auth posture (resolved against ``tex.api.auth``, not assumed):
  * ``/v1/voice/token`` mints a short-lived recognizer grant → ``decision:read``
    (it is part of the authenticated voice surface). Returns 503 when a
    production env has no gateway secret configured (fail closed).
  * ``/v1/ask`` returns sealed ``evidence_hash`` anchors in its proof_ref, the
    same exposure the ``/v1/vigil/explain`` route gates — so it requires BOTH
    ``decision:read`` AND ``evidence:read``. (The client contract names only
    ``decision:read``; following it literally would under-scope in production.
    The stricter gate is correct and is invisible in keyless dev, where the
    anonymous principal carries every scope.)
  * ``/v1/speak`` synthesizes a line of text into Tex's one voice → ``decision:read``.

Against a keyless backend the principal is anonymous (every scope) so a keyless
frontend works in dev; against a keyed backend a caller missing a scope is
correctly 401/403'd.
"""

from __future__ import annotations

import os
from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse, Response, StreamingResponse
from pydantic import BaseModel, ConfigDict, Field

from tex.api.auth import RequireScope, TexPrincipal, authenticate_request
from tex.api.vigil_routes import _resolve_effective_tenant
from tex.gateway import grant
from tex.gateway.backends import ElevenLabsTTS, synthesize_tts, synthesize_tts_stream
from tex.presence.contract import DEFAULT_PROSODY
from tex.presence.prosody import plan_from_token, prosody_param_for_envelope
from tex.voice import voice_ask

__all__ = ["build_voice_router"]

# Where the browser opens the recognizer WebSocket. Tex's OWN gateway, inside
# the same trust domain — never a third party. Overridable per deploy.
_GATEWAY_URL = os.environ.get("TEX_VOICE_GATEWAY_URL", "ws://localhost:8765")
_SPEAK_SAMPLE_RATE = 24000


# --------------------------------------------------------------------------- DTOs


class VoiceTokenResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ws_url: str
    token: str
    expires_at: int  # epoch seconds


class AskRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    transcript: str = Field(default="", max_length=4000)
    tenant_id: str | None = Field(default=None, max_length=200)


class ObjectDTO(BaseModel):
    model_config = ConfigDict(extra="forbid")
    value: str
    kind: str  # "hash" | "name"


class ProofRefDTO(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: str | None = None
    id: str | None = None
    sha256: str | None = None
    seq: int | None = None


class AttestationDTO(BaseModel):
    model_config = ConfigDict(extra="forbid")
    anchor_sha256: str | None = None
    algorithm: str | None = None
    verdict: str
    routed_dimension: str | None = None


class AskResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    answer: str
    object: ObjectDTO | None = None
    proof_ref: ProofRefDTO | None = None
    attestation: AttestationDTO | None = None
    # The presence channel (Session 1 grounded brain + Session 2 truth-gate): the
    # full AnswerEnvelope — spoken_text + per-claim verdicts + evidence anchors +
    # prosody_plan + overall_tier — that the tex-systems glass renders as a real
    # credibility tier and reachable evidence. None whenever no GroundedBrain is
    # engaged, so the legacy response is unchanged (mirrors object/proof_ref, which
    # are likewise null when absent). Serialized WHOLE, including prosody_plan.
    presence: dict | None = None
    # Convenience mirror of presence["overall_tier"] (Session 4): the verdict's TIER
    # token ("sealed"/"derived"/"abstain"), or None when presence isn't engaged. The
    # MONOTONE fold of the answer's per-claim verdicts — not the draft, not a "vibe".
    # The client echoes it verbatim to GET /v1/speak?prosody=<token> so the spoken
    # line's perceived confidence equals the gate's verdict.
    prosody: str | None = None


# --------------------------------------------------------------- presence serialization
#
# Map the frozen ``tex.presence.contract.AnswerEnvelope`` onto the exact wire shape
# tex-systems' ``presence.js`` (derivePresence / normClaims / normEvidence) reads.
# The contract is the source of truth; we add two UI-compat aliases the renderer
# needs and the contract does not name:
#   * each claim carries ``text``   — presence.js reads ``claim.text`` (not text_span)
#   * each evidence ref carries ``sha256`` — normEvidence reads ``sha256`` (not record_hash)
# Both aliases mirror a real contract field (text_span / record_hash) byte-for-byte —
# no fabricated data — and the faithful contract fields are emitted alongside them.


def _evidence_ref_dict(ref: Any) -> dict:
    return {
        "record_id": ref.record_id,
        "record_hash": ref.record_hash,
        "sha256": ref.record_hash,  # UI-compat: presence.js normEvidence reads .sha256
        "store": ref.store,
        "field": ref.field,
        "prior_link_witness": ref.prior_link_witness,
    }


def _attestation_dict(att: Any) -> dict | None:
    if att is None:
        return None
    return {
        "algorithm": att.algorithm,
        "signed_digest_sha256": att.signed_digest_sha256,
        "signature_b64": att.signature_b64,
        "is_post_quantum": att.is_post_quantum,
        "key_id": att.key_id,
        "public_key_b64": att.public_key_b64,
        "signed_at": att.signed_at,
    }


def _serialize_presence(env: Any) -> dict | None:
    """Serialize ``AskOutcome.presence`` (an ``AnswerEnvelope``) for the wire, or
    ``None`` when presence did not engage — so the legacy response is preserved."""
    if env is None:
        return None
    verdict_by_claim = {v.claim_id: v for v in env.verdicts}
    claims = []
    for c in env.claims:
        v = verdict_by_claim.get(c.claim_id)
        first_ref = v.evidence[0] if (v is not None and v.evidence) else None
        claims.append({
            "claim_id": c.claim_id,
            "text": c.text_span,        # UI-compat alias: presence.js reads claim.text
            "text_span": c.text_span,   # faithful contract field
            "kind": c.kind.value,
            "tier": v.tier.value if v is not None else None,
            "evidence": (
                {
                    "value": first_ref.record_hash, "kind": "hash",
                    "record_id": first_ref.record_id, "store": first_ref.store,
                    "field": first_ref.field,
                }
                if first_ref is not None else None
            ),
        })
    verdicts = [
        {
            "claim_id": v.claim_id,
            "tier": v.tier.value,
            "evidence": [_evidence_ref_dict(r) for r in v.evidence],
            "recomputed_value": v.recomputed_value,
            "correctness_floor": v.correctness_floor,
            "coverage_mode": v.coverage_mode,
            "governance_verdict": (
                v.governance_verdict.value if v.governance_verdict is not None else None
            ),
            "reason": v.reason,
            "attestation": _attestation_dict(v.attestation),
        }
        for v in env.verdicts
    ]
    return {
        "spoken_text": env.spoken_text,
        "overall_tier": env.overall_tier.value,
        "reason": None,  # optional ABSTAIN gloss override; the spoken line already says why
        "prosody_plan": {
            "tier": env.prosody_plan.tier.value,
            "style_label": env.prosody_plan.style_label,
            "rate": env.prosody_plan.rate,
            "terminal_pitch": env.prosody_plan.terminal_pitch,
            "lead_pause_ms": env.prosody_plan.lead_pause_ms,
        },
        "surface_object": env.surface_object,
        "claims": claims,
        "verdicts": verdicts,
    }


# --------------------------------------------------------------------------- router


def build_voice_router() -> APIRouter:
    router = APIRouter(prefix="/v1", tags=["voice"])

    @router.get(
        "/voice/token",
        response_model=VoiceTokenResponse,
        summary="Mint a short-lived grant for the self-hosted recognizer socket",
    )
    def voice_token(
        request: Request,
        principal: TexPrincipal = Depends(RequireScope("decision:read")),
    ) -> VoiceTokenResponse:
        tenant = None if principal.is_anonymous or principal.tenant == "default" else principal.tenant
        minted = grant.make_token(tenant)
        if minted is None:
            # Production-like env with no gateway secret configured: the voice
            # loop is OFF rather than protected by a guessable default.
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="voice gateway secret not configured",
            )
        token, expires_at = minted
        return VoiceTokenResponse(ws_url=_GATEWAY_URL, token=token, expires_at=expires_at)

    @router.post(
        "/ask",
        response_model=AskResponse,
        summary="Answer a spoken question, grounded ONLY in sealed facts",
    )
    def ask(
        request: Request,
        body: AskRequest = Body(...),
        # Returns sealed evidence_hash anchors → BOTH read scopes, matching the
        # /v1/vigil/explain precedent (vigil_routes.py).
        principal: TexPrincipal = Depends(authenticate_request),
    ) -> AskResponse:
        for scope in ("decision:read", "evidence:read"):
            if not principal.has_scope(scope):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"missing required scope: {scope}",
                )
        effective_tenant = _resolve_effective_tenant(principal, body.tenant_id)
        outcome = voice_ask.answer_question(
            request, transcript=body.transcript, tenant=effective_tenant
        )
        return AskResponse(
            answer=outcome.answer,
            object=(ObjectDTO(**outcome.object) if outcome.object else None),
            proof_ref=(ProofRefDTO(**outcome.proof_ref) if outcome.proof_ref else None),
            attestation=AttestationDTO(
                anchor_sha256=outcome.attestation_anchor,
                algorithm=outcome.attestation_algorithm,
                verdict=outcome.verdict.value,
                routed_dimension=outcome.routed_dimension,
            ),
            presence=_serialize_presence(outcome.presence),
            # Session 4: read-only hand-off of the presence TIER token (pure function
            # of the gate's monotone verdict; a convenience mirror of
            # presence["overall_tier"]) for the client to echo to /v1/speak.
            prosody=prosody_param_for_envelope(getattr(outcome, "presence", None)),
        )

    @router.get(
        "/speak",
        summary="Synthesize a grounded line in Tex's one voice (epistemic prosody)",
    )
    def speak(
        request: Request,
        text: str = Query(default="", max_length=4000),
        prosody: str | None = Query(
            default=None,
            max_length=32,
            description="Verdict TIER token ('sealed'/'derived'/'abstain') from "
            "/v1/ask's `prosody` field. Carries the gate's monotone verdict so the "
            "voice's perceived confidence equals it. Omit for today's neutral voice.",
        ),
        principal: TexPrincipal = Depends(RequireScope("decision:read")),
    ) -> Response:
        # The grounding already happened in /v1/ask; this is pure synthesis of a
        # line Tex already sealed. The backend is pluggable (tex.gateway.backends):
        # the ElevenLabs cloud voice when ELEVENLABS_API_KEY is set, else local
        # Kokoro, else the honest offline tone — and a RUNTIME vendor failure falls
        # through too, so Tex is never muted. The header names whoever ACTUALLY
        # spoke, so a cloud vendor in the audio path is labeled on every byte.
        #
        # EPISTEMIC PROSODY (Session 4). The `prosody` token is the gate's verdict
        # TIER; the plan is re-derived SERVER-SIDE from it (pure function
        # ProsodyPlan.from_tier) so a caller can never hand-set assured-sounding
        # knobs on an uncertain answer. Routing:
        #   * prosody ABSENT (None) → today's low-latency MP3 stream, UNCHANGED
        #     (purely additive; no presence verdict ⇒ no epistemic prosody).
        #   * prosody PRESENT → the full WAV post-process path so EVERY tier's
        #     cues are really delivered (lead pause + terminal-pitch glide cannot
        #     be spliced into a live MP3 stream — see synthesize_tts_stream). A
        #     PRESENT-but-unparseable token FAILS CLOSED to the most cautious plan
        #     (ABSTAIN), never to a confident default. Trades a little streaming
        #     latency for an honest, fully-delivered epistemic cue.
        #
        # HONEST TRUST BOUNDARY (no overclaim): like the `text` it voices, the
        # `prosody` tier here is exactly as trustworthy as the caller. In the
        # integrated path the client echoes /v1/ask's `prosody`
        # (= prosody_param_for_envelope, the MONOTONE overall_tier), so the voice
        # cannot sound more confident than the verdict FOR A FAITHFUL CLIENT. A
        # hostile/buggy client passing a higher token can over-state confidence —
        # the same trust surface as the text. Closing that fully needs a signed
        # (text,tier) binding minted at /v1/ask (gateway secret + a 1-line mint in
        # the orchestrator), which is a future hardening out of this track.
        if prosody is None:
            iterator, backend_name, media_type = synthesize_tts_stream(
                text, sample_rate=_SPEAK_SAMPLE_RATE
            )
            return StreamingResponse(
                iterator,
                media_type=media_type,
                headers={
                    "Cache-Control": "no-store",
                    "X-Tex-Voice-Backend": backend_name,
                    "X-Tex-Voice-Prosody": "neutral",
                },
            )

        plan = plan_from_token(prosody) or DEFAULT_PROSODY  # garbage ⇒ ABSTAIN floor
        audio, backend_name = synthesize_tts(
            text, sample_rate=_SPEAK_SAMPLE_RATE, prosody=plan
        )
        return Response(
            content=audio,
            media_type="audio/wav",
            headers={
                "Cache-Control": "no-store",
                "X-Tex-Voice-Backend": backend_name,
                "X-Tex-Voice-Prosody": plan.style_label,
                "X-Tex-Voice-Prosody-Tier": plan.tier.value,
            },
        )

    @router.get(
        "/speak/timed",
        summary="Synthesize a sealed line WITH per-word timing for in-sync highlighting",
    )
    def speak_timed(
        request: Request,
        text: str = Query(default="", max_length=4000),
        prosody: str | None = Query(
            default=None,
            max_length=32,
            description="Verdict TIER token, as for /v1/speak. On the word-timed "
            "path the rate + lead pause are applied (word times shifted to stay in "
            "sync); the terminal-pitch glide degrades (it would desync per-word "
            "timing).",
        ),
        principal: TexPrincipal = Depends(RequireScope("decision:read")),
    ) -> Response:
        # Word-timed audio is an ElevenLabs-only capability (it returns the
        # per-character alignment for the EXACT sealed line). The grounding still
        # happened in /v1/ask; this only adds timing so the on-screen text can
        # light up in step with Tex's voice. When ElevenLabs isn't configured we
        # 503 and the client falls back to plain /v1/speak — a real voice, just
        # without the highlight — so this is purely additive, never a regression.
        #
        # Prosody (same token semantics as /v1/speak; PRESENT-but-garbage fails
        # closed to the ABSTAIN plan) applies the rate + a real lead pause with
        # the word times shifted to match. The terminal glide is intentionally not
        # applied here — it would desync the highlight — so this path is monotone
        # via the pause+rate cues; for the full contour the client uses /v1/speak.
        el = ElevenLabsTTS()
        if not el.available():
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="word-timed voice not configured (no ElevenLabs key)",
            )
        plan = None if prosody is None else (plan_from_token(prosody) or DEFAULT_PROSODY)
        payload = el.synthesize_timed(text, sample_rate=_SPEAK_SAMPLE_RATE, prosody=plan)
        headers = {"Cache-Control": "no-store", "X-Tex-Voice-Backend": el.name}
        if plan is not None:
            headers["X-Tex-Voice-Prosody"] = plan.style_label
            headers["X-Tex-Voice-Prosody-Tier"] = plan.tier.value
        return JSONResponse(content=payload, headers=headers)

    return router

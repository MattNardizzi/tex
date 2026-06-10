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

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request, status
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict, Field

from tex.api.auth import RequireScope, TexPrincipal, authenticate_request
from tex.api.vigil_routes import _resolve_effective_tenant
from tex.gateway import grant
from tex.gateway.backends import select_tts
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
        )

    @router.get(
        "/speak",
        summary="Synthesize a grounded line in Tex's one voice (streamed audio)",
    )
    def speak(
        request: Request,
        text: str = Query(default="", max_length=4000),
        principal: TexPrincipal = Depends(RequireScope("decision:read")),
    ) -> Response:
        # The grounding already happened in /v1/ask; this is pure synthesis of a
        # line Tex chose. The backend is pluggable (tex.gateway.backends); only
        # the offline tone runs in this environment — a placeholder, not a voice.
        tts = select_tts()
        audio = tts.synthesize(text, sample_rate=_SPEAK_SAMPLE_RATE)
        return Response(
            content=audio,
            media_type="audio/wav",
            headers={"Cache-Control": "no-store", "X-Tex-Voice-Backend": tts.name},
        )

    return router

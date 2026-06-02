"""
GET /v1/vigil — Tex choosing what to say.

This is the voice's wire: the frontend never computes sentences, it renders
what this endpoint chose. The endpoint reads across all six dimensions,
holds a model of normal for the tenant (warmed from ledger history),
computes Bayesian surprise, and returns the chosen utterances in surprise
order, the standing word (Absolute / Open), the human-decision line when a
person is required, and a proof reference on any line that has one.

Auth posture (resolved against tex.api.auth, not assumed):

  * The endpoint speaks real findings — the sentences are filled from
    sealed data. So it is tenant-scoped and authenticated exactly like the
    proof endpoints: it requires ``decision:read``.
  * Against a keyless backend (no TEX_API_KEYS) the principal is anonymous,
    which has every scope — so a keyless frontend works in dev.
  * Against a keyed backend the caller must present a key carrying
    ``decision:read`` (and ``evidence:read`` to later resolve proofs), or
    it is correctly 401/403'd rather than silently leaking findings.

This is a strict read. No side effects.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, ConfigDict, Field

from tex.api.auth import RequireScope, TexPrincipal, authenticate_request
from tex.vigil import Explainer, VigilEngine, build_default_explainer

__all__ = ["build_vigil_router"]


# --------------------------------------------------------------------------- DTOs
# This shape is the contract the interface will render. Keep it stable.


class ProofRefDTO(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: str
    id: str | None = None
    sha256: str | None = None
    seq: int | None = None


class VigilUtteranceDTO(BaseModel):
    model_config = ConfigDict(extra="forbid")
    text: str
    dimension: str
    surprise: float = Field(ge=0.0)
    proof_ref: ProofRefDTO | None = None
    requires_human: bool = False


class VigilMetaDTO(BaseModel):
    model_config = ConfigDict(extra="forbid")
    warm: bool
    observed_dimensions: int
    spoken: int
    suppressed: int
    selector_version: str


class VigilResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tenant_id: str | None = None
    generated_at: str
    standing: str  # "Absolute" | "Open"
    utterances: list[VigilUtteranceDTO] = Field(default_factory=list)
    human_decision: VigilUtteranceDTO | None = None
    meta: VigilMetaDTO


# --------------------------------------------------------------------------- mapping


def _proof_dto(proof: Any) -> ProofRefDTO | None:
    if proof is None or proof.is_empty():
        return None
    return ProofRefDTO(kind=proof.kind, id=proof.id, sha256=proof.sha256, seq=proof.seq)


def _utterance_dto(u: Any) -> VigilUtteranceDTO:
    return VigilUtteranceDTO(
        text=u.text,
        dimension=u.dimension,
        surprise=round(float(u.surprise), 6),
        proof_ref=_proof_dto(u.proof),
        requires_human=u.requires_human,
    )


def _resolve_effective_tenant(principal: TexPrincipal, tenant_id: str | None) -> str | None:
    """
    Same rule as system_state and /v1/vigil: a keyed, non-default principal
    is scoped to its own tenant; a cross-tenant query by a scoped key is
    403'd; anonymous (keyless dev) is honored as-is.
    """
    if tenant_id is None and not principal.is_anonymous and principal.tenant != "default":
        return principal.tenant
    if (
        tenant_id is not None
        and not principal.is_anonymous
        and principal.tenant != "default"
        and principal.tenant.casefold() != tenant_id.strip().casefold()
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="API key tenant does not match query tenant_id",
        )
    return tenant_id


# --------------------------------------------------------------------------- explain DTOs
# The proof layer: click a spoken line, ask what happened. The response
# always carries the structured sealed facts and proof anchors alongside the
# prose, so nothing is taken on the model's word.


class ExplainRequestDTO(BaseModel):
    model_config = ConfigDict(extra="forbid")
    dimension: str = Field(min_length=1, max_length=64)
    tenant_id: str | None = Field(default=None, max_length=200)
    claim_text: str | None = Field(default=None, max_length=2000)


class EvidenceFactsDTO(BaseModel):
    model_config = ConfigDict(extra="forbid")
    dimension: str
    headline: str
    details: list[dict[str, Any]] = Field(default_factory=list)
    anchors: list[ProofRefDTO] = Field(default_factory=list)


class ExplanationResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    dimension: str
    claim_text: str | None = None
    explanation: str          # prose: generated OR deterministic
    facts: EvidenceFactsDTO   # the sealed evidence the prose must rest on
    mode: str                 # primary_provider | default_fallback | failure_fallback
    generator: str            # provider name, or "deterministic"
    grounded: bool            # facts + anchors travel with the prose


def _facts_dto(facts: Any) -> EvidenceFactsDTO:
    return EvidenceFactsDTO(
        dimension=facts.dimension,
        headline=facts.headline,
        details=list(facts.details),
        anchors=[
            ProofRefDTO(kind=a.kind, id=a.id, sha256=a.sha256, seq=a.seq)
            for a in facts.anchors
        ],
    )


# --------------------------------------------------------------------------- router


def build_vigil_router() -> APIRouter:
    router = APIRouter(prefix="/v1", tags=["vigil"])

    @router.get(
        "/vigil",
        response_model=VigilResponse,
        summary="What Tex chose to say this cycle (surprise-selected, sealed-filled)",
    )
    def vigil(
        request: Request,
        tenant_id: str | None = Query(default=None, max_length=200),
        # Speaks real findings -> authed like the proof endpoints.
        principal: TexPrincipal = Depends(RequireScope("decision:read")),
    ) -> VigilResponse:
        # Resolve effective tenant the same way system_state does.
        effective_tenant = _resolve_effective_tenant(principal, tenant_id)

        from datetime import UTC, datetime

        engine = getattr(request.app.state, "vigil_engine", None)
        if engine is None:
            engine = VigilEngine()  # safe default; no warm cache attached
        selection = engine.run(request, effective_tenant)

        return VigilResponse(
            tenant_id=effective_tenant,
            generated_at=datetime.now(UTC).isoformat(),
            standing=selection.standing,
            utterances=[_utterance_dto(u) for u in selection.utterances],
            human_decision=(
                _utterance_dto(selection.human_decision)
                if selection.human_decision is not None
                else None
            ),
            meta=VigilMetaDTO(
                warm=selection.warm,
                observed_dimensions=selection.observed_dimensions,
                spoken=len(selection.utterances),
                suppressed=selection.suppressed,
                selector_version=selection.selector_version,
            ),
        )

    @router.post(
        "/vigil/explain",
        response_model=ExplanationResponse,
        summary="Finish the story behind a spoken line, grounded in sealed facts",
    )
    def explain(
        request: Request,
        body: ExplainRequestDTO = Body(...),
        # The explainer exposes sealed evidence detail (decision records,
        # chain state, coverage roots), so it requires BOTH read scopes.
        principal: TexPrincipal = Depends(authenticate_request),
    ) -> ExplanationResponse:
        for scope in ("decision:read", "evidence:read"):
            if not principal.has_scope(scope):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"missing required scope: {scope}",
                )

        effective_tenant = _resolve_effective_tenant(principal, body.tenant_id)

        explainer: Explainer | None = getattr(request.app.state, "vigil_explainer", None)
        if explainer is None:
            explainer = build_default_explainer()

        result = explainer.explain(
            request,
            dimension=body.dimension,
            tenant=effective_tenant,
            claim_text=body.claim_text,
        )

        return ExplanationResponse(
            dimension=result.dimension,
            claim_text=result.claim_text,
            explanation=result.explanation,
            facts=_facts_dto(result.facts),
            mode=result.mode.value,
            generator=result.generator,
            grounded=result.grounded,
        )

    return router

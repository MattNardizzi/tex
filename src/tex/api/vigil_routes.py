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


class HoldDTO(BaseModel):
    """The first-class abstention the operator hears (engine/hold.py).

    Carries the two-sided certificate band, the epistemic/aleatoric type, and
    the single pivotal fact that would resolve it. The voice speaks the
    meaning; the surface renders the type and the question — never the file.
    """

    model_config = ConfigDict(extra="forbid")
    hold_type: str                       # EPISTEMIC | ALEATORIC | MIXED
    resolution_mode: str                 # SELF_HEAL | HUMAN_FACT | HUMAN_JUDGMENT
    resolving_question: str | None = None
    epistemic_score: float = Field(ge=0.0, le=1.0)
    aleatoric_score: float = Field(ge=0.0, le=1.0)
    band_certified: bool = False
    band_lower: float = 0.0
    band_upper: float = 1.0
    final_score: float = Field(ge=0.0, le=1.0, default=0.0)
    # ── calibration-hold extension (additive; default keeps decision holds
    # identical on the wire). A calibration hold sets kind="calibration" and
    # carries the proposal handle + proposed change + anytime-valid safety
    # bound, which the surface raises only on reach.
    kind: str = "decision"               # decision | calibration
    proposal_id: str | None = None
    proposed_change: dict[str, Any] | None = None
    safety_bound: dict[str, Any] | None = None


class HumanDecisionDTO(BaseModel):
    """What the held card renders. A superset of an utterance: it adds the
    durable decision id, the spoken sentence + grounding detail, the agent,
    and the structured Hold. Backward-compatible with the older shape (the
    surface read ``sentence``/``detail`` already)."""

    model_config = ConfigDict(extra="forbid")
    id: str | None = None
    sentence: str
    detail: str | None = None
    dimension: str = "execution"
    surprise: float = Field(ge=0.0, default=0.0)
    agent: str | None = None
    proof_ref: ProofRefDTO | None = None
    requires_human: bool = True
    anchor_sha256: str | None = None
    hold: HoldDTO | None = None


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
    human_decision: HumanDecisionDTO | None = None
    meta: VigilMetaDTO


# --------------------------------------------------------------------------- mapping


def _hold_dto(hold: Any) -> HoldDTO | None:
    """Map a Hold (engine/hold.py) or its dict form to the wire DTO."""
    if hold is None:
        return None
    g = hold.get if isinstance(hold, dict) else (lambda k, d=None: getattr(hold, k, d))
    return HoldDTO(
        hold_type=str(g("hold_type", "MIXED")),
        resolution_mode=str(g("resolution_mode", "HUMAN_JUDGMENT")),
        resolving_question=g("resolving_question", None),
        epistemic_score=float(g("epistemic_score", 0.5)),
        aleatoric_score=float(g("aleatoric_score", 0.5)),
        band_certified=bool(g("band_certified", False)),
        band_lower=float(g("band_lower", 0.0)),
        band_upper=float(g("band_upper", 1.0)),
        final_score=float(g("final_score", 0.0)),
        kind=str(g("kind", "decision")),
        proposal_id=g("proposal_id", None),
        proposed_change=g("proposed_change", None),
        safety_bound=g("safety_bound", None),
    )


def _human_decision_from_held(held: Any) -> HumanDecisionDTO:
    """Build the held-card DTO from a held-decision payload supplied by the
    provider seam (a real PDP ABSTAIN with its Hold)."""
    g = held.get if isinstance(held, dict) else (lambda k, d=None: getattr(held, k, d))
    hold = g("hold", None)
    proof = g("proof_ref", None)
    return HumanDecisionDTO(
        id=g("id", None),
        sentence=g("sentence", "I'm holding this one. It's yours to decide."),
        detail=g("detail", None),
        dimension=g("dimension", "execution"),
        surprise=float(g("surprise", 0.0) or 0.0),
        agent=g("agent", None),
        proof_ref=(ProofRefDTO(**proof) if isinstance(proof, dict) else _proof_dto(proof)),
        requires_human=True,
        anchor_sha256=g("anchor_sha256", None),
        hold=_hold_dto(hold),
    )


def _human_decision_from_utterance(u: Any) -> HumanDecisionDTO:
    """Posture-true fallback: map the selector's dimension-derived
    human_decision utterance into the held-card DTO (no structured Hold yet —
    the honest shape until a real held decision is wired through the provider)."""
    proof = _proof_dto(getattr(u, "proof", None))
    return HumanDecisionDTO(
        id=None,
        sentence=u.text,
        detail=None,
        dimension=u.dimension,
        surprise=round(float(u.surprise), 6),
        agent=None,
        proof_ref=proof,
        requires_human=True,
        anchor_sha256=(proof.sha256 if proof is not None else None),
        hold=None,
    )


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


def _build_vigil_response(request: Request, effective_tenant: str | None) -> VigilResponse:
    """Run one vigil cycle and assemble the wire contract. Shared by the
    polling GET and the SSE stream so both speak the identical truth."""
    from datetime import UTC, datetime

    engine = getattr(request.app.state, "vigil_engine", None)
    if engine is None:
        engine = VigilEngine()  # safe default; no warm cache attached
    selection = engine.run(request, effective_tenant)

    # Held-decision provider seam (mirrors the vigil v2–v5 collaborator
    # pattern): when the runtime wires a provider, it yields the freshest
    # unresolved ABSTAIN — a real PDP decision carrying its two-sided Hold —
    # which becomes the held card. When absent, fall back to the selector's
    # dimension-derived human_decision (posture-true, no structured Hold).
    human_decision: HumanDecisionDTO | None = None
    provider = getattr(request.app.state, "held_decision_provider", None)
    if provider is not None:
        try:
            current = getattr(provider, "current", None)
            held = current(effective_tenant) if callable(current) else provider(effective_tenant)
        except Exception:  # noqa: BLE001 — the provider never breaks the cycle
            held = None
        if held is not None:
            human_decision = _human_decision_from_held(held)
    if human_decision is None and selection.human_decision is not None:
        human_decision = _human_decision_from_utterance(selection.human_decision)

    return VigilResponse(
        tenant_id=effective_tenant,
        generated_at=datetime.now(UTC).isoformat(),
        standing=selection.standing,
        utterances=[_utterance_dto(u) for u in selection.utterances],
        human_decision=human_decision,
        meta=VigilMetaDTO(
            warm=selection.warm,
            observed_dimensions=selection.observed_dimensions,
            spoken=len(selection.utterances),
            suppressed=selection.suppressed,
            selector_version=selection.selector_version,
        ),
    )


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
        effective_tenant = _resolve_effective_tenant(principal, tenant_id)
        return _build_vigil_response(request, effective_tenant)

    @router.get(
        "/vigil/stream",
        summary="The live voice as a Server-Sent Events stream (push, not poll)",
    )
    def vigil_stream(
        request: Request,
        tenant_id: str | None = Query(default=None, max_length=200),
        principal: TexPrincipal = Depends(RequireScope("decision:read")),
    ):
        """SSE is the 2026 SOTA for one-way server→client push (native
        EventSource auto-reconnect + Last-Event-ID resume, rides the existing
        same-origin proxy untouched; the WebSocket stays only for the truly
        bidirectional recognizer). The stream emits the same VigilResponse the
        poll returns, as ``event: vigil`` frames with a monotonic ``id:`` for
        resume, plus periodic ``event: pulse`` frames that keep intermediaries
        warm AND give the client a visible proof-of-life. The frontend renders
        on change; between frames the pulse says "alive, unchanged" — so the
        client can go honestly silent when the pulse stops, instead of
        repeating stale truth."""
        import asyncio
        import json

        from fastapi.responses import StreamingResponse
        from starlette.concurrency import run_in_threadpool

        effective_tenant = _resolve_effective_tenant(principal, tenant_id)
        # Cadence: a calm push every PERIOD_S, a keepalive every HEARTBEAT_S.
        PERIOD_S = 10.0
        HEARTBEAT_S = 15.0

        async def event_source():
            seq = 0
            last_truth: str | None = None
            # Emit immediately so a fresh subscriber gets the current truth.
            while True:
                if await request.is_disconnected():
                    break
                try:
                    # Offload the synchronous vigil cycle to the threadpool so a
                    # per-stream recompute never blocks the single worker's event
                    # loop. Running it inline here froze the one loop for the whole
                    # duration of engine.run() on EVERY open stream, every PERIOD_S
                    # — starving /health, /speak/timed and every other route until
                    # it returned (the multi-minute wedge). The polling /vigil route
                    # already runs this in the threadpool; this makes the stream
                    # path match it so concurrent streams can no longer wedge Tex.
                    resp = await run_in_threadpool(
                        _build_vigil_response, request, effective_tenant
                    )
                    payload = resp.model_dump_json()
                    # Change-detection must ignore generated_at: the stamp is
                    # new every cycle, so comparing raw payloads re-emitted an
                    # unchanged vigil as a "new" frame every PERIOD_S (and the
                    # pulse branch below was dead code). Truth is what the
                    # frame SAYS, not when it was stamped.
                    truth = resp.model_dump()
                    truth.pop("generated_at", None)
                    truth_key = json.dumps(truth, sort_keys=True, default=str)
                except Exception:  # noqa: BLE001 — never crash the stream
                    payload = None
                    truth_key = None

                if payload is not None and truth_key != last_truth:
                    seq += 1
                    last_truth = truth_key
                    yield f"id: {seq}\nevent: vigil\ndata: {payload}\n\n"
                elif payload is not None:
                    # Pulse frame: the backend just RECOMPUTED the vigil and
                    # affirms it is unchanged. Visible to the EventSource
                    # consumer (a `: comment` would be swallowed), it is the
                    # client's proof-of-life — the license to keep rendering
                    # the truth already on the glass.
                    yield "event: pulse\ndata: {}\n\n"
                else:
                    # Compute FAILED. Keep the socket warm for intermediaries,
                    # but with an invisible comment — no pulse. A backend that
                    # cannot stand behind the truth does not renew the client's
                    # license to keep speaking it; if this persists past the
                    # client's staleness bound, the surface goes honestly
                    # silent instead of narrating an estate nobody can see.
                    yield ": alive, truth unavailable\n\n"

                # Sleep in heartbeat-sized slices up to one push period.
                slept = 0.0
                while slept < PERIOD_S:
                    if await request.is_disconnected():
                        return
                    await asyncio.sleep(min(HEARTBEAT_S, PERIOD_S - slept))
                    slept += HEARTBEAT_S
                    if slept < PERIOD_S:
                        # Mid-sleep keepalive: socket warmth only. It carries
                        # no fresh affirmation of the truth (no recompute has
                        # run), so it must not be a pulse — only the cycle
                        # above may renew the client's license to speak.
                        yield ": keepalive\n\n"

        return StreamingResponse(
            event_source(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-store",
                "X-Accel-Buffering": "no",   # disable nginx buffering of the stream
                "Connection": "keep-alive",
            },
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

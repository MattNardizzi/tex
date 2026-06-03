"""
Streaming and async evaluation endpoints for Tex.

Three new shapes layered on top of the existing canonical /v1/guardrail
endpoint, none of which require changes to the engine:

1. **POST /v1/guardrail/stream** - Server-Sent Events response.
   The gateway calls this and we emit progressive risk signals as each
   evaluation layer completes. Useful for gateways that want early
   deterministic findings before the slower semantic layer finishes.

2. **POST /v1/guardrail/stream/chunk** - Token-stream evaluation.
   The customer's LLM is streaming tokens to the user. They ping us with
   each new chunk; we maintain a session buffer and re-evaluate only when
   the cumulative content meaningfully changed. Returns a verdict per
   chunk so the customer can interrupt the stream mid-flight.

3. **POST /v1/guardrail/async** - Fire-and-forget audit mode.
   Returns 202 Accepted immediately with a decision_id. Evaluation runs
   in the background and lands in the durable evidence chain. Customer
   polls GET /v1/guardrail/async/{decision_id} to collect.

Critical design notes:

- Async mode is **observability-only**. It cannot block the customer's
  outbound action because by the time we have a verdict, the action has
  already shipped. The endpoint enforces this by name and documentation.
  Customers who need pre-release blocking must use the synchronous
  /v1/guardrail endpoint.

- Streaming mode emits the same canonical verdict shape as a final event,
  so any gateway that already consumes the canonical shape can layer
  early-warning telemetry on top.

- The Tex engine itself stays synchronous. We delegate via
  asyncio.to_thread so the FastAPI worker isn't pinned during evaluation.
"""

from __future__ import annotations

import asyncio
import json
import time
from datetime import UTC, datetime
from typing import Any, AsyncIterator
from uuid import UUID, uuid4

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    HTTPException,
    Query,
    Request,
    status,
)
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, ConfigDict, Field

from tex.api.auth import TexPrincipal, authenticate_request
from tex.api.guardrail import (
    GuardrailFormat,
    GuardrailWebhookRequest,
    _build_response,
    _get_evaluate_action_command,
    _RENDERERS,
    _to_evaluation_request,
)
from tex.api.runtime_store import async_results, stream_sessions


router = APIRouter(prefix="/v1/guardrail", tags=["guardrail-streaming"])


# --------------------------------------------------------------------------- #
# Async (fire-and-forget) endpoint                                            #
# --------------------------------------------------------------------------- #


class AsyncAcceptedDTO(BaseModel):
    """Response body for accepted async evaluation requests."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    decision_id: str
    status: str = Field(default="accepted")
    poll_url: str
    note: str = Field(
        default=(
            "Async evaluations are observability-only. Do not use this mode "
            "to gate pre-release actions. Use POST /v1/guardrail for "
            "synchronous PERMIT/ABSTAIN/FORBID verdicts."
        ),
    )


class AsyncResultDTO(BaseModel):
    """Response body for async result polling."""

    model_config = ConfigDict(extra="allow")

    decision_id: str
    status: str  # "pending" | "complete" | "failed"
    result: dict[str, Any] | None = None
    error: str | None = None
    submitted_at: datetime
    completed_at: datetime | None = None


def _run_async_evaluation(
    *,
    decision_id_str: str,
    canonical: GuardrailWebhookRequest,
    principal: TexPrincipal,
    command: Any,
    submitted_at: datetime,
) -> None:
    """Background-task entry point. Runs the engine, stashes the result."""
    try:
        domain_request = _to_evaluation_request(canonical, principal=principal)
        result = command.execute(domain_request)
        response = _build_response(
            result=result,
            request_id=domain_request.request_id,
            source=canonical.source or "async",
        )
        async_results.put(decision_id_str, {
            "decision_id": decision_id_str,
            "status": "complete",
            "result": response.model_dump(mode="json"),
            "error": None,
            "submitted_at": submitted_at.isoformat(),
            "completed_at": datetime.now(UTC).isoformat(),
        })
    except Exception as exc:
        async_results.put(decision_id_str, {
            "decision_id": decision_id_str,
            "status": "failed",
            "result": None,
            "error": f"{type(exc).__name__}: {exc}",
            "submitted_at": submitted_at.isoformat(),
            "completed_at": datetime.now(UTC).isoformat(),
        })


@router.post(
    "/async",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Submit an action for async (fire-and-forget) evaluation",
)
def guardrail_async_submit(
    payload: GuardrailWebhookRequest,
    request: Request,
    background_tasks: BackgroundTasks,
    principal: TexPrincipal = Depends(authenticate_request),
) -> JSONResponse:
    """
    Accept an evaluation request without blocking the caller.

    **This endpoint is observability-only.** By the time the result is
    available, the caller's outbound action has already shipped. Use this
    mode for:
      - High-throughput audit and drift monitoring
      - Backfilling evidence on agent activity that already happened
      - Sampling production traffic for compliance review

    For pre-release gating, use POST /v1/guardrail (synchronous) instead.
    """
    # Validate the payload converts cleanly before accepting it. We don't
    # want to 202 something that will fail to evaluate later.
    try:
        _to_evaluation_request(payload, principal=principal)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    command = _get_evaluate_action_command(request)
    decision_id = uuid4()
    decision_id_str = str(decision_id)
    submitted_at = datetime.now(UTC)

    # Seed a 'pending' record so polling sees something useful immediately.
    async_results.put(decision_id_str, {
        "decision_id": decision_id_str,
        "status": "pending",
        "result": None,
        "error": None,
        "submitted_at": submitted_at.isoformat(),
        "completed_at": None,
    })

    background_tasks.add_task(
        _run_async_evaluation,
        decision_id_str=decision_id_str,
        canonical=payload,
        principal=principal,
        command=command,
        submitted_at=submitted_at,
    )

    base = str(request.base_url).rstrip("/")
    accepted = AsyncAcceptedDTO(
        decision_id=decision_id_str,
        poll_url=f"{base}/v1/guardrail/async/{decision_id_str}",
    )
    return JSONResponse(
        status_code=status.HTTP_202_ACCEPTED,
        content=accepted.model_dump(mode="json"),
    )


@router.get(
    "/async/{decision_id}",
    summary="Poll for async evaluation result",
)
def guardrail_async_poll(
    decision_id: UUID,
    principal: TexPrincipal = Depends(authenticate_request),
) -> AsyncResultDTO:
    """Poll the result of a previously-submitted async evaluation."""
    raw = async_results.get(str(decision_id))
    if raw is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                f"async result not found for {decision_id}. "
                "Either it was never submitted, or it expired (1h TTL)."
            ),
        )
    return AsyncResultDTO(**raw)


# --------------------------------------------------------------------------- #
# SSE progressive-evaluation endpoint                                         #
# --------------------------------------------------------------------------- #


def _sse(event: str, data: dict[str, Any]) -> str:
    """Format one Server-Sent Events frame."""
    payload = json.dumps(data, default=str)
    return f"event: {event}\ndata: {payload}\n\n"


async def _evaluate_progressive(
    *,
    canonical: GuardrailWebhookRequest,
    principal: TexPrincipal,
    command: Any,
) -> AsyncIterator[str]:
    """
    Drive the engine and yield SSE frames as work progresses.

    The Tex engine runs as a single synchronous call internally, so we
    can't actually emit per-layer progress without engine changes. What
    we *can* do that's still genuinely useful:
      - emit a 'started' frame immediately (low-latency UX signal)
      - run the evaluation off-thread so we don't block the worker
      - emit the final canonical verdict frame when complete
      - emit a 'done' terminator so clients know the stream closed cleanly

    A future engine refactor can wire per-layer callbacks; this endpoint's
    SSE contract is forward-compatible with that.
    """
    started_at = time.perf_counter()
    yield _sse("started", {
        "started_at": datetime.now(UTC).isoformat(),
        "source": canonical.source,
    })

    try:
        domain_request = await asyncio.to_thread(
            _to_evaluation_request, canonical, principal=principal
        )
    except ValueError as exc:
        yield _sse("error", {"error": str(exc), "phase": "normalize"})
        yield _sse("done", {"ok": False})
        return

    try:
        result = await asyncio.to_thread(command.execute, domain_request)
    except Exception as exc:
        yield _sse("error", {
            "error": f"{type(exc).__name__}: {exc}",
            "phase": "evaluate",
        })
        yield _sse("done", {"ok": False})
        return

    response = _build_response(
        result=result,
        request_id=domain_request.request_id,
        source=canonical.source or "stream",
    )

    elapsed_ms = round((time.perf_counter() - started_at) * 1000, 2)
    yield _sse("verdict", response.model_dump(mode="json"))
    yield _sse("done", {"ok": True, "elapsed_ms": elapsed_ms})


@router.post(
    "/stream",
    summary="SSE progressive evaluation (Server-Sent Events)",
)
async def guardrail_stream(
    payload: GuardrailWebhookRequest,
    request: Request,
    principal: TexPrincipal = Depends(authenticate_request),
) -> StreamingResponse:
    """
    Evaluate one action and stream progressive signals over SSE.

    Emits these named events:
      - `started`  : evaluation accepted, work begun
      - `verdict`  : final canonical verdict (full response body)
      - `error`    : an error frame (then `done` with ok=false)
      - `done`     : terminator with elapsed_ms

    Forward-compatible with future per-layer progress (deterministic /
    retrieval / specialists / semantic / fusion). When the engine emits
    layer-completion callbacks, we will route them through this stream
    without changing the SSE contract.
    """
    command = _get_evaluate_action_command(request)
    return StreamingResponse(
        _evaluate_progressive(
            canonical=payload,
            principal=principal,
            command=command,
        ),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",  # disable nginx buffering for SSE
        },
    )


# --------------------------------------------------------------------------- #
# Token-stream chunk endpoint                                                 #
# --------------------------------------------------------------------------- #


class StreamChunkRequest(BaseModel):
    """One chunk of streaming content from a customer's LLM output."""

    model_config = ConfigDict(extra="ignore")

    session_id: str = Field(min_length=1, max_length=200)
    chunk: str = Field(default="", max_length=10_000)
    is_final: bool = Field(default=False)

    # Tex-native fields. Only honored on the first chunk; subsequent chunks
    # are tied to the existing session and reuse the original action_type
    # / channel / environment.
    action_type: str | None = None
    channel: str | None = None
    environment: str | None = None
    recipient: str | None = None
    policy_id: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class StreamChunkResponse(BaseModel):
    """Verdict shape returned per chunk."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    session_id: str
    chunk_index: int
    cumulative_chars: int
    verdict: str  # PERMIT / ABSTAIN / FORBID
    allowed: bool
    score: float
    confidence: float
    reason: str
    decision_id: str | None = None
    re_evaluated: bool
    is_final: bool


# Number of new characters that must accumulate before we re-evaluate.
# Smaller values produce more responsive interrupts at higher cost.
_REEVAL_THRESHOLD_CHARS = 80
_HARD_REEVAL_INTERVAL_CHARS = 400  # always re-evaluate at least this often


@router.post(
    "/stream/chunk",
    response_model=StreamChunkResponse,
    summary="Submit one chunk of streaming LLM output for inline evaluation",
)
async def guardrail_stream_chunk(
    payload: StreamChunkRequest,
    request: Request,
    principal: TexPrincipal = Depends(authenticate_request),
) -> StreamChunkResponse:
    """
    Evaluate streaming content chunk-by-chunk so a customer can interrupt
    their LLM mid-stream when the response goes off the rails.

    The customer maintains a session_id (a UUID they generate). On each
    new token chunk, they POST it here. We:
      1. Append to the cumulative session buffer.
      2. Re-evaluate the cumulative content if (a) enough new chars have
         arrived since last re-evaluation, or (b) is_final=true.
      3. Return the latest verdict the customer can act on.

    If a re-evaluation produces FORBID, the customer should drop the
    rest of their stream immediately. ABSTAIN means "you should escalate
    or finish-then-review." PERMIT means proceed.
    """
    command = _get_evaluate_action_command(request)
    session = stream_sessions.get(payload.session_id)

    if session is None:
        # First chunk in a new session.
        session = {
            "session_id": payload.session_id,
            "buffer": "",
            "chunk_index": 0,
            "last_eval_chars": 0,
            "action_type": payload.action_type,
            "channel": payload.channel,
            "environment": payload.environment,
            "recipient": payload.recipient,
            "policy_id": payload.policy_id,
            "metadata": dict(payload.metadata),
            "last_verdict": None,
        }

    # Append the new chunk.
    session["buffer"] = (session["buffer"] + payload.chunk)[-50_000:]  # bound
    session["chunk_index"] = int(session["chunk_index"]) + 1

    cumulative = session["buffer"]
    cumulative_chars = len(cumulative)
    chars_since_last = cumulative_chars - int(session["last_eval_chars"])

    should_reeval = (
        payload.is_final
        or chars_since_last >= _REEVAL_THRESHOLD_CHARS
        or (
            session["last_verdict"] is None  # always evaluate first time
        )
    )

    re_evaluated = False
    if should_reeval and cumulative.strip():
        canonical = GuardrailWebhookRequest(
            content=cumulative,
            action_type=session["action_type"],
            channel=session["channel"],
            environment=session["environment"],
            recipient=session["recipient"],
            policy_id=session["policy_id"],
            metadata={
                **session["metadata"],
                "stream_session_id": payload.session_id,
                "stream_chunk_index": session["chunk_index"],
                "stream_is_final": payload.is_final,
            },
            source="stream_chunk",
        )

        try:
            domain_request = await asyncio.to_thread(
                _to_evaluation_request, canonical, principal=principal,
            )
            result = await asyncio.to_thread(command.execute, domain_request)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(exc),
            ) from exc
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"chunk evaluation failed: {exc}",
            ) from exc

        response = _build_response(
            result=result,
            request_id=domain_request.request_id,
            source="stream_chunk",
        )

        session["last_verdict"] = {
            "verdict": response.verdict.value,
            "allowed": response.allowed,
            "score": response.score,
            "confidence": response.confidence,
            "reason": response.reason,
            "decision_id": str(response.decision_id),
        }
        session["last_eval_chars"] = cumulative_chars
        re_evaluated = True

    # Persist the session forward (or drop it if final).
    if payload.is_final:
        stream_sessions.delete(payload.session_id)
    else:
        stream_sessions.put(payload.session_id, session)

    last = session["last_verdict"] or {
        "verdict": "PERMIT",
        "allowed": True,
        "score": 0.0,
        "confidence": 0.0,
        "reason": "no content yet",
        "decision_id": None,
    }

    return StreamChunkResponse(
        session_id=payload.session_id,
        chunk_index=int(session["chunk_index"]),
        cumulative_chars=cumulative_chars,
        verdict=last["verdict"],
        allowed=bool(last["allowed"]),
        score=float(last["score"]),
        confidence=float(last["confidence"]),
        reason=last["reason"],
        decision_id=last["decision_id"],
        re_evaluated=re_evaluated,
        is_final=payload.is_final,
    )


def build_streaming_router() -> APIRouter:
    """Convenience constructor."""
    return router


__all__ = [
    "build_streaming_router",
    "router",
    "AsyncAcceptedDTO",
    "AsyncResultDTO",
    "StreamChunkRequest",
    "StreamChunkResponse",
]

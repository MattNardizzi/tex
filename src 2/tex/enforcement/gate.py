"""
TexGate — the core enforcement primitive.

A `TexGate` wraps a Python callable so that the callable cannot
execute unless Tex returns PERMIT (or, with explicit configuration,
ABSTAIN). The gate is the smallest possible piece of code that turns
"Tex returned a verdict" into "the action did or did not happen."

Five guarantees the gate makes:

1. **FORBID always blocks.** No flag overrides this. The wrapped
   callable does not run. The gate raises TexForbiddenError so the
   surrounding code knows enforcement happened.

2. **PERMIT always passes through transparently.** The wrapped
   callable runs with its original arguments, its return value is
   returned to the caller unchanged.

3. **ABSTAIN behavior is configurable.** Default is BLOCK (fail
   closed). Other options: ALLOW (pass through with a warning), or
   REVIEW (raise TexAbstainError so the caller can route to a human).

4. **Failure modes are fail-closed by default.** If the transport
   errors, times out, or returns an unparseable response, the gate
   does NOT execute the wrapped action. Operators can opt into
   fail-open with `fail_closed=False` but the library never does
   this implicitly.

5. **Every gated execution emits exactly one GateEvent.** Observers
   are called from within the gate; observer failures are suppressed.

The gate has both sync (`TexGate`) and async (`TexGateAsync`)
flavors. Use the matching one for your codebase. The async flavor
runs the synchronous transport on a thread to avoid blocking the
event loop; users with an async-native transport can wrap it in a
CallableTransport that awaits internally.
"""

from __future__ import annotations

import asyncio
import functools
import time
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Awaitable, Callable, TypeVar
from uuid import UUID, uuid4

from tex.domain.evaluation import EvaluationRequest, EvaluationResponse
from tex.domain.verdict import Verdict
from tex.enforcement.errors import (
    TexAbstainError,
    TexForbiddenError,
    TexUnavailableError,
)
from tex.enforcement.events import (
    GateEvent,
    GateEventObserver,
    NullObserver,
)
from tex.enforcement.transport import (
    TexEvaluationTransport,
    TransportResult,
)


T = TypeVar("T")


class AbstainPolicy(StrEnum):
    """
    What the gate does when Tex returns ABSTAIN.

    - BLOCK: do not execute the wrapped action. Raise
      TexAbstainError. This is the default and the safest.

    - ALLOW: execute the wrapped action anyway. Emit an event with
      outcome="executed" and a flag in `details` indicating that
      ABSTAIN was overridden. Use only when the upstream caller has
      already done its own review.

    - REVIEW: raise TexAbstainError without executing. Identical to
      BLOCK from the wrapped action's perspective; the difference
      is purely for operator clarity — REVIEW signals "route this
      to a human", BLOCK signals "fail closed".
    """

    BLOCK = "BLOCK"
    ALLOW = "ALLOW"
    REVIEW = "REVIEW"


@dataclass(frozen=True, slots=True)
class GateConfig:
    """
    Immutable configuration for one TexGate.

    Construct once, reuse across many gated executions. The gate
    itself is stateless aside from holding a reference to the
    transport and the config.
    """

    transport: TexEvaluationTransport
    abstain_policy: AbstainPolicy = AbstainPolicy.BLOCK
    fail_closed: bool = True
    observer: GateEventObserver = field(default_factory=NullObserver)

    # Default values used to fill in EvaluationRequest fields the
    # caller does not supply. The wrapped callable usually does not
    # know about Tex taxonomy, so the gate fills these from config.
    default_action_type: str = "agent_action"
    default_channel: str = "api"
    default_environment: str = "production"


# --------------------------------------------------------------------------- #
# Core gate (synchronous)                                                     #
# --------------------------------------------------------------------------- #


class TexGate:
    """
    Synchronous in-process enforcement gate.

    Two ways to use it:

        # 1) Imperative: call .check() before running the action
        gate = TexGate(config)
        gate.check(content="hello", recipient="x@y.com")
        send_email(...)

        # 2) Wrap: hand the gate a callable, get back a gated callable
        send_email_gated = gate.wrap(send_email,
                                     content_arg="body",
                                     recipient_arg="to")
        send_email_gated(to="x@y.com", body="hello")  # blocks if FORBID

    The first form is more flexible. The second is more ergonomic
    once you've decided which arguments contain the content and
    recipient. Both honor the same five guarantees described in the
    module docstring.
    """

    __slots__ = ("_config",)

    def __init__(self, config: GateConfig) -> None:
        self._config = config

    # -- Imperative interface -----------------------------------------

    def check(
        self,
        *,
        content: str,
        action_type: str | None = None,
        channel: str | None = None,
        environment: str | None = None,
        recipient: str | None = None,
        agent_id: UUID | None = None,
        session_id: str | None = None,
        request_id: UUID | None = None,
        policy_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> EvaluationResponse:
        """
        Synchronously evaluate the action and return the response.

        Raises:
            TexForbiddenError    when verdict is FORBID
            TexAbstainError      when verdict is ABSTAIN and policy
                                 is BLOCK or REVIEW
            TexUnavailableError  when the transport fails AND
                                 fail_closed=True

        On PERMIT, returns the EvaluationResponse so the caller can
        attach the decision_id, fingerprint, etc. to its own audit.
        """
        gate_start = time.perf_counter()
        rid = request_id or uuid4()
        request = EvaluationRequest(
            request_id=rid,
            action_type=action_type or self._config.default_action_type,
            content=content,
            channel=channel or self._config.default_channel,
            environment=environment or self._config.default_environment,
            recipient=recipient,
            agent_id=agent_id,
            session_id=session_id,
            policy_id=policy_id,
            metadata=metadata or {},
        )

        result = self._config.transport.evaluate(request)
        gate_latency_ms = round((time.perf_counter() - gate_start) * 1000.0, 2)

        # Transport failure path.
        if result.response is None:
            self._handle_transport_failure(
                request=request,
                result=result,
                gate_latency_ms=gate_latency_ms,
            )
            # If fail_closed=False, _handle_transport_failure does not
            # raise. We return a synthetic UNAVAILABLE response so
            # callers using `gate.check()` still see something useful.
            return _synthetic_unavailable_response(request)

        response = result.response

        # Decide what to do based on verdict.
        if response.verdict is Verdict.PERMIT:
            self._emit(
                request=request,
                response=response,
                outcome="executed",
                gate_latency_ms=gate_latency_ms,
                extra={"transport_latency_ms": result.transport_latency_ms},
            )
            return response

        if response.verdict is Verdict.FORBID:
            self._emit(
                request=request,
                response=response,
                outcome="blocked",
                gate_latency_ms=gate_latency_ms,
                extra={"transport_latency_ms": result.transport_latency_ms},
            )
            raise TexForbiddenError(
                f"Tex FORBID for action_type={request.action_type!r}: "
                f"final_score={response.final_score:.3f}",
                response=response,
                details={
                    "request_id": str(request.request_id),
                    "decision_id": str(response.decision_id),
                    "fingerprint": response.determinism_fingerprint,
                },
            )

        # ABSTAIN
        if self._config.abstain_policy is AbstainPolicy.ALLOW:
            self._emit(
                request=request,
                response=response,
                outcome="executed",
                gate_latency_ms=gate_latency_ms,
                extra={
                    "transport_latency_ms": result.transport_latency_ms,
                    "abstain_overridden": True,
                },
            )
            return response

        outcome = "reviewed" if self._config.abstain_policy is AbstainPolicy.REVIEW else "blocked"
        self._emit(
            request=request,
            response=response,
            outcome=outcome,
            gate_latency_ms=gate_latency_ms,
            extra={"transport_latency_ms": result.transport_latency_ms},
        )
        raise TexAbstainError(
            f"Tex ABSTAIN for action_type={request.action_type!r}: "
            f"final_score={response.final_score:.3f}",
            response=response,
            details={
                "request_id": str(request.request_id),
                "decision_id": str(response.decision_id),
                "fingerprint": response.determinism_fingerprint,
                "abstain_policy": self._config.abstain_policy.value,
            },
        )

    # -- Decorator / wrap interface -----------------------------------

    def wrap(
        self,
        fn: Callable[..., T],
        *,
        content_arg: str,
        recipient_arg: str | None = None,
        action_type: str | None = None,
        channel: str | None = None,
        environment: str | None = None,
        agent_id: UUID | None = None,
    ) -> Callable[..., T]:
        """
        Return a gated version of `fn`.

        The gated callable extracts `content` (and optionally
        `recipient`) from its keyword arguments, calls Tex, and only
        invokes `fn` on PERMIT (or ABSTAIN with policy=ALLOW). If the
        gate raises, the original `fn` is never called.
        """

        @functools.wraps(fn)
        def gated(*args: Any, **kwargs: Any) -> T:
            if content_arg not in kwargs:
                raise TypeError(
                    f"gated callable {fn.__name__!r} requires keyword "
                    f"argument {content_arg!r} containing the action's "
                    "content for Tex evaluation"
                )
            content = kwargs[content_arg]
            recipient = (
                kwargs.get(recipient_arg) if recipient_arg is not None else None
            )
            self.check(
                content=content,
                action_type=action_type,
                channel=channel,
                environment=environment,
                recipient=recipient,
                agent_id=agent_id,
            )
            return fn(*args, **kwargs)

        return gated

    # -- Internals ----------------------------------------------------

    def _handle_transport_failure(
        self,
        *,
        request: EvaluationRequest,
        result: TransportResult,
        gate_latency_ms: float,
    ) -> None:
        outcome = "blocked" if self._config.fail_closed else "executed"
        self._emit(
            request=request,
            response=None,
            outcome=outcome,
            gate_latency_ms=gate_latency_ms,
            extra={
                "transport_error": result.error,
                "transport_latency_ms": result.transport_latency_ms,
                **result.details,
            },
            verdict_override="UNAVAILABLE",
        )
        if self._config.fail_closed:
            raise TexUnavailableError(
                f"Tex transport failed: {result.error}",
                details={
                    "request_id": str(request.request_id),
                    "transport_error": result.error,
                    **result.details,
                },
            )

    def _emit(
        self,
        *,
        request: EvaluationRequest,
        response: EvaluationResponse | None,
        outcome: str,
        gate_latency_ms: float,
        extra: dict[str, Any] | None = None,
        verdict_override: str | None = None,
    ) -> None:
        verdict = (
            verdict_override
            if verdict_override is not None
            else (response.verdict.value if response is not None else "UNAVAILABLE")
        )
        event = GateEvent(
            request_id=request.request_id,
            action_type=request.action_type,
            channel=request.channel,
            environment=request.environment,
            recipient=request.recipient,
            agent_id=request.agent_id,
            verdict=verdict,
            decision_id=response.decision_id if response is not None else None,
            determinism_fingerprint=(
                response.determinism_fingerprint if response is not None else None
            ),
            final_score=response.final_score if response is not None else None,
            confidence=response.confidence if response is not None else None,
            outcome=outcome,
            abstain_policy=self._config.abstain_policy.value,
            fail_closed=self._config.fail_closed,
            gate_latency_ms=gate_latency_ms,
            details=dict(extra) if extra else {},
        )
        try:
            self._config.observer(event)
        except Exception:  # noqa: BLE001 — never let a buggy observer break the gate
            pass


# --------------------------------------------------------------------------- #
# Async gate                                                                  #
# --------------------------------------------------------------------------- #


class TexGateAsync:
    """
    Async wrapper around TexGate.

    Runs the synchronous transport on a thread via
    asyncio.to_thread so the event loop is not blocked.

    For async-native transports, wrap them in a CallableTransport
    that awaits internally — TexGateAsync will pick that up because
    asyncio.to_thread is happy to await a coroutine inside the
    thread-pool worker.
    """

    __slots__ = ("_inner",)

    def __init__(self, config: GateConfig) -> None:
        self._inner = TexGate(config)

    async def check(
        self,
        *,
        content: str,
        action_type: str | None = None,
        channel: str | None = None,
        environment: str | None = None,
        recipient: str | None = None,
        agent_id: UUID | None = None,
        session_id: str | None = None,
        request_id: UUID | None = None,
        policy_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> EvaluationResponse:
        return await asyncio.to_thread(
            self._inner.check,
            content=content,
            action_type=action_type,
            channel=channel,
            environment=environment,
            recipient=recipient,
            agent_id=agent_id,
            session_id=session_id,
            request_id=request_id,
            policy_id=policy_id,
            metadata=metadata,
        )

    def wrap(
        self,
        fn: Callable[..., Awaitable[T]],
        *,
        content_arg: str,
        recipient_arg: str | None = None,
        action_type: str | None = None,
        channel: str | None = None,
        environment: str | None = None,
        agent_id: UUID | None = None,
    ) -> Callable[..., Awaitable[T]]:
        """
        Return an async gated version of `fn`. The gate runs first;
        on PERMIT (or ALLOW-policy ABSTAIN) the wrapped coroutine is
        awaited. On block, the wrapped coroutine is never created.
        """

        @functools.wraps(fn)
        async def gated(*args: Any, **kwargs: Any) -> T:
            if content_arg not in kwargs:
                raise TypeError(
                    f"async gated callable {fn.__name__!r} requires keyword "
                    f"argument {content_arg!r} containing the action's "
                    "content for Tex evaluation"
                )
            content = kwargs[content_arg]
            recipient = (
                kwargs.get(recipient_arg) if recipient_arg is not None else None
            )
            await self.check(
                content=content,
                action_type=action_type,
                channel=channel,
                environment=environment,
                recipient=recipient,
                agent_id=agent_id,
            )
            return await fn(*args, **kwargs)

        return gated


# --------------------------------------------------------------------------- #
# Decorator helpers                                                           #
# --------------------------------------------------------------------------- #


def tex_gated(
    gate: TexGate,
    *,
    content_arg: str,
    recipient_arg: str | None = None,
    action_type: str | None = None,
    channel: str | None = None,
    environment: str | None = None,
    agent_id: UUID | None = None,
) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """
    Decorator form of TexGate.wrap.

    Usage:

        @tex_gated(gate, content_arg="body", recipient_arg="to")
        def send_email(*, to: str, body: str) -> None: ...
    """

    def decorator(fn: Callable[..., T]) -> Callable[..., T]:
        return gate.wrap(
            fn,
            content_arg=content_arg,
            recipient_arg=recipient_arg,
            action_type=action_type,
            channel=channel,
            environment=environment,
            agent_id=agent_id,
        )

    return decorator


def tex_gated_async(
    gate: TexGateAsync,
    *,
    content_arg: str,
    recipient_arg: str | None = None,
    action_type: str | None = None,
    channel: str | None = None,
    environment: str | None = None,
    agent_id: UUID | None = None,
) -> Callable[[Callable[..., Awaitable[T]]], Callable[..., Awaitable[T]]]:
    """Decorator form of TexGateAsync.wrap."""

    def decorator(fn: Callable[..., Awaitable[T]]) -> Callable[..., Awaitable[T]]:
        return gate.wrap(
            fn,
            content_arg=content_arg,
            recipient_arg=recipient_arg,
            action_type=action_type,
            channel=channel,
            environment=environment,
            agent_id=agent_id,
        )

    return decorator


# --------------------------------------------------------------------------- #
# Internal helpers                                                            #
# --------------------------------------------------------------------------- #


def _synthetic_unavailable_response(request: EvaluationRequest) -> EvaluationResponse:
    """
    Build a placeholder response for the fail-open path.

    Only used when the operator explicitly disables fail_closed. The
    response carries verdict=ABSTAIN to signal "we don't actually
    know what Tex would have said" — fail-open does not mean PERMIT.
    """
    from datetime import UTC, datetime

    return EvaluationResponse(
        decision_id=uuid4(),
        verdict=Verdict.ABSTAIN,
        confidence=0.0,
        final_score=0.0,
        reasons=["Tex transport unavailable; gate operating in fail-open mode."],
        findings=[],
        scores={},
        uncertainty_flags=["tex_unavailable", "fail_open"],
        asi_findings=[],
        determinism_fingerprint=None,
        latency=None,
        replay_url=None,
        evidence_bundle_url=None,
        policy_version="unavailable",
        evidence_hash=None,
        evaluated_at=datetime.now(UTC),
    )

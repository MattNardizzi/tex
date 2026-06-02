"""
Transports the gate uses to reach Tex.

Three implementations ship in the box:

1. DirectCommandTransport — calls the in-process EvaluateActionCommand
   directly. Lowest latency. Use when Tex is embedded in the same
   process as the agent.

2. HttpClientTransport — calls a remote /evaluate endpoint over HTTP.
   Use when Tex runs as a separate service. Uses httpx if available;
   the gate raises an actionable ImportError if httpx is missing.

3. CallableTransport — a thin shim around any callable that takes an
   EvaluationRequest and returns an EvaluationResponse. Trivially
   useful for testing and for users who want to plug in a custom
   transport (gRPC, queue-based, etc.).

Every transport returns a TransportResult: the Tex response, plus
diagnostic metadata about how the call went. The gate uses the result
to decide what to do; transports never make policy decisions.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Protocol, runtime_checkable

from tex.commands.evaluate_action import EvaluateActionCommand
from tex.domain.evaluation import EvaluationRequest, EvaluationResponse


@dataclass(frozen=True, slots=True)
class TransportResult:
    """
    Result of one Tex evaluation call.

    `response` is the public EvaluationResponse when the call
    succeeded. When the call failed (network error, timeout, etc.),
    `response` is None and `error` carries a human-readable reason.
    `transport_latency_ms` is wall-clock for the transport call only,
    not the gate as a whole.
    """

    response: EvaluationResponse | None
    error: str | None
    transport_latency_ms: float
    details: dict[str, Any]


@runtime_checkable
class TexEvaluationTransport(Protocol):
    """
    Protocol every transport implements.

    Transports are synchronous from the gate's perspective. Async
    callers go through TexGateAsync, which wraps a transport whose
    `evaluate` is async-friendly via thread-pool dispatch.
    """

    def evaluate(self, request: EvaluationRequest) -> TransportResult: ...


# --------------------------------------------------------------------------- #
# Direct in-process transport                                                 #
# --------------------------------------------------------------------------- #


class DirectCommandTransport:
    """
    Calls the EvaluateActionCommand directly, in-process.

    Lowest possible latency. Use when the agent and Tex live in the
    same Python process — typical for embedded deployments and for
    testing.
    """

    __slots__ = ("_command",)

    def __init__(self, command: EvaluateActionCommand) -> None:
        self._command = command

    def evaluate(self, request: EvaluationRequest) -> TransportResult:
        import time

        start = time.perf_counter()
        try:
            result = self._command.execute(request)
        except Exception as exc:  # noqa: BLE001 — any failure is "unavailable"
            elapsed = (time.perf_counter() - start) * 1000.0
            return TransportResult(
                response=None,
                error=f"{type(exc).__name__}: {exc}",
                transport_latency_ms=round(elapsed, 2),
                details={"transport": "direct"},
            )
        elapsed = (time.perf_counter() - start) * 1000.0
        return TransportResult(
            response=result.response,
            error=None,
            transport_latency_ms=round(elapsed, 2),
            details={"transport": "direct"},
        )


# --------------------------------------------------------------------------- #
# HTTP transport                                                              #
# --------------------------------------------------------------------------- #


class HttpClientTransport:
    """
    Calls a remote Tex /evaluate endpoint over HTTP.

    The transport accepts any object with a `.post(url, json=...,
    timeout=...)` method that returns something with `.status_code`,
    `.json()`, and `.text`. In practice this is `httpx.Client` or
    `requests.Session`. The library does not import httpx itself —
    the caller passes the client they already have.

    On non-2xx responses the transport returns a TransportResult with
    `response=None` and `error` populated; the gate then decides
    whether to fail closed (default) or open.
    """

    __slots__ = ("_client", "_url", "_timeout", "_headers")

    def __init__(
        self,
        *,
        client: Any,
        url: str,
        timeout: float = 5.0,
        headers: dict[str, str] | None = None,
    ) -> None:
        if not hasattr(client, "post"):
            raise TypeError(
                "client must be an httpx.Client / requests.Session-like "
                "object exposing .post(url, json=, timeout=, headers=)"
            )
        self._client = client
        self._url = url
        self._timeout = timeout
        self._headers = dict(headers) if headers else {}

    def evaluate(self, request: EvaluationRequest) -> TransportResult:
        import time

        start = time.perf_counter()
        try:
            payload = request.model_dump(mode="json")
            http_response = self._client.post(
                self._url,
                json=payload,
                timeout=self._timeout,
                headers=self._headers,
            )
            elapsed = (time.perf_counter() - start) * 1000.0
        except Exception as exc:  # noqa: BLE001
            elapsed = (time.perf_counter() - start) * 1000.0
            return TransportResult(
                response=None,
                error=f"{type(exc).__name__}: {exc}",
                transport_latency_ms=round(elapsed, 2),
                details={"transport": "http", "url": self._url},
            )

        status_code = getattr(http_response, "status_code", None)
        if status_code is None or status_code >= 400:
            text = ""
            try:
                text = http_response.text  # type: ignore[assignment]
            except Exception:  # noqa: BLE001
                text = ""
            return TransportResult(
                response=None,
                error=f"HTTP {status_code}: {text[:500]}",
                transport_latency_ms=round(elapsed, 2),
                details={
                    "transport": "http",
                    "url": self._url,
                    "status_code": status_code,
                },
            )

        try:
            body = http_response.json()
            response = EvaluationResponse.model_validate(body)
        except Exception as exc:  # noqa: BLE001
            return TransportResult(
                response=None,
                error=f"response parse failed: {type(exc).__name__}: {exc}",
                transport_latency_ms=round(elapsed, 2),
                details={
                    "transport": "http",
                    "url": self._url,
                    "status_code": status_code,
                },
            )

        return TransportResult(
            response=response,
            error=None,
            transport_latency_ms=round(elapsed, 2),
            details={
                "transport": "http",
                "url": self._url,
                "status_code": status_code,
            },
        )


# --------------------------------------------------------------------------- #
# Callable transport — for testing and custom shims                           #
# --------------------------------------------------------------------------- #


class CallableTransport:
    """
    Thin shim around a callable.

    Lets users plug in any function with the right shape, including
    test doubles, gRPC clients, and queue-based transports.
    """

    __slots__ = ("_fn", "_label")

    def __init__(
        self,
        fn: Callable[[EvaluationRequest], EvaluationResponse],
        *,
        label: str = "callable",
    ) -> None:
        self._fn = fn
        self._label = label

    def evaluate(self, request: EvaluationRequest) -> TransportResult:
        import time

        start = time.perf_counter()
        try:
            response = self._fn(request)
        except Exception as exc:  # noqa: BLE001
            elapsed = (time.perf_counter() - start) * 1000.0
            return TransportResult(
                response=None,
                error=f"{type(exc).__name__}: {exc}",
                transport_latency_ms=round(elapsed, 2),
                details={"transport": "callable", "label": self._label},
            )
        elapsed = (time.perf_counter() - start) * 1000.0
        return TransportResult(
            response=response,
            error=None,
            transport_latency_ms=round(elapsed, 2),
            details={"transport": "callable", "label": self._label},
        )

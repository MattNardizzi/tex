"""
Tex Enforcement HTTP Proxy.

A small ASGI app that sits in front of any HTTP-based agent action,
calls Tex with the request body as the content under evaluation,
and either forwards the request to the upstream URL or refuses based
on the verdict.

Deployment shape:

    [agent] -> [tex.enforcement.proxy] -> [agent's real action endpoint]

Example: an agent that POSTs emails to /send-email gets pointed at
the proxy instead. The proxy reads the request body, asks Tex if the
content is OK, and either forwards to the original /send-email or
returns 403 with the Tex evidence attached.

This is the simplest possible production-grade enforcement deployment
for teams that already have an HTTP boundary in their agent system.
For deeper integration, use the in-process gate or framework adapters.

Design properties:

- Stateless. Every request is independent.
- Forwards the upstream response transparently on PERMIT.
- Returns 403 with Tex evidence on FORBID.
- Returns 409 with Tex evidence on ABSTAIN (BLOCK or REVIEW).
- Returns 502 when Tex is unavailable AND fail_closed=True.
- Pluggable upstream client. The proxy itself does not import httpx;
  the caller injects the HTTP client they want to use for the
  upstream forward.
"""

from __future__ import annotations

import json
from typing import Any, Callable
from uuid import UUID

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse

from tex.enforcement.errors import (
    TexAbstainError,
    TexForbiddenError,
    TexUnavailableError,
)
from tex.enforcement.gate import TexGate


# --------------------------------------------------------------------------- #
# Upstream forwarder protocol                                                 #
# --------------------------------------------------------------------------- #


class UpstreamForwarder:
    """
    Forwards a permitted request to its real destination.

    The default implementation expects an httpx-style client. Users
    who want a different client (requests, aiohttp, raw sockets) can
    subclass and override `forward`.
    """

    __slots__ = ("_client", "_upstream_url", "_timeout", "_extra_headers")

    def __init__(
        self,
        *,
        client: Any,
        upstream_url: str,
        timeout: float = 30.0,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        if not hasattr(client, "request"):
            raise TypeError(
                "UpstreamForwarder client must expose a "
                ".request(method, url, ...) method"
            )
        self._client = client
        self._upstream_url = upstream_url
        self._timeout = timeout
        self._extra_headers = dict(extra_headers) if extra_headers else {}

    def forward(
        self,
        *,
        method: str,
        body: bytes,
        headers: dict[str, str],
    ) -> Response:
        merged_headers = dict(headers)
        merged_headers.update(self._extra_headers)
        # Strip hop-by-hop headers; client/server set these themselves.
        for hop in ("host", "content-length", "transfer-encoding", "connection"):
            merged_headers.pop(hop, None)
        upstream_response = self._client.request(
            method,
            self._upstream_url,
            content=body,
            headers=merged_headers,
            timeout=self._timeout,
        )
        return Response(
            content=upstream_response.content,
            status_code=upstream_response.status_code,
            headers=dict(upstream_response.headers),
        )


# --------------------------------------------------------------------------- #
# Content extraction                                                          #
# --------------------------------------------------------------------------- #


# Default content extractor. Looks for common fields used by agent
# action APIs and falls back to the whole body as a string. Users
# with non-standard payloads can plug in their own.
DEFAULT_CONTENT_FIELDS: tuple[str, ...] = (
    "content",
    "body",
    "text",
    "message",
    "input",
    "prompt",
)
DEFAULT_RECIPIENT_FIELDS: tuple[str, ...] = (
    "to",
    "recipient",
    "destination",
    "target",
)


def default_content_extractor(body: bytes) -> tuple[str, str | None]:
    """
    Best-effort extraction of (content, recipient) from a JSON body.

    Returns (content, recipient_or_None). If the body is not JSON or
    no known field is present, the entire body is treated as the
    content and the recipient is None. This is a conservative default
    — the proxy still forwards the *original* body upstream, so
    nothing is lost; the extractor only affects what Tex sees.
    """
    try:
        parsed = json.loads(body)
    except Exception:  # noqa: BLE001
        return body.decode("utf-8", errors="replace"), None

    if not isinstance(parsed, dict):
        return json.dumps(parsed), None

    content = None
    for field in DEFAULT_CONTENT_FIELDS:
        if field in parsed and isinstance(parsed[field], str) and parsed[field].strip():
            content = parsed[field]
            break
    if content is None:
        content = json.dumps(parsed)

    recipient = None
    for field in DEFAULT_RECIPIENT_FIELDS:
        if field in parsed and isinstance(parsed[field], str) and parsed[field].strip():
            recipient = parsed[field]
            break

    return content, recipient


# --------------------------------------------------------------------------- #
# Proxy app                                                                   #
# --------------------------------------------------------------------------- #


def build_enforcement_proxy(
    *,
    gate: TexGate,
    forwarder: UpstreamForwarder,
    content_extractor: Callable[[bytes], tuple[str, str | None]] = default_content_extractor,
    action_type: str = "agent_http_action",
    channel: str = "http",
    environment: str = "production",
    agent_id: UUID | None = None,
    path: str = "/{full_path:path}",
) -> FastAPI:
    """
    Build a FastAPI app that proxies HTTP requests through Tex.

    Mount this in front of any HTTP-based agent action. Every
    request to the proxy is checked by Tex; on PERMIT the request is
    forwarded to `forwarder.upstream_url` and the upstream's response
    is returned to the caller. On FORBID/ABSTAIN/UNAVAILABLE the
    request is refused with structured Tex evidence in the response
    body.

    The proxy honors all five gate guarantees: FORBID always blocks,
    PERMIT always passes through, ABSTAIN is configurable via the
    gate's policy, transport failures fail closed by default, and
    every gated execution emits a GateEvent.
    """

    app = FastAPI(title="Tex Enforcement Proxy")

    @app.api_route(path, methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
    async def proxy(request: Request, full_path: str = "") -> Response:
        body = await request.body()
        content, recipient = content_extractor(body)

        try:
            gate.check(
                content=content,
                action_type=action_type,
                channel=channel,
                environment=environment,
                recipient=recipient,
                agent_id=agent_id,
            )
        except TexForbiddenError as exc:
            return _refusal_response(403, "FORBID", exc)
        except TexAbstainError as exc:
            return _refusal_response(409, "ABSTAIN", exc)
        except TexUnavailableError as exc:
            return _refusal_response(502, "UNAVAILABLE", exc)

        # PERMIT — forward upstream.
        try:
            return forwarder.forward(
                method=request.method,
                body=body,
                headers={k.lower(): v for k, v in request.headers.items()},
            )
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(
                status_code=502,
                detail=f"upstream forward failed: {type(exc).__name__}: {exc}",
            ) from exc

    return app


def _refusal_response(
    status_code: int,
    verdict: str,
    exc: Any,
) -> JSONResponse:
    response = getattr(exc, "response", None)
    payload = {
        "verdict": verdict,
        "message": str(exc),
        "details": getattr(exc, "details", {}) or {},
    }
    if response is not None:
        payload["evidence"] = {
            "decision_id": str(response.decision_id),
            "determinism_fingerprint": response.determinism_fingerprint,
            "final_score": response.final_score,
            "confidence": response.confidence,
            "policy_version": response.policy_version,
            "evidence_hash": response.evidence_hash,
            "reasons": list(response.reasons),
            "uncertainty_flags": list(response.uncertainty_flags),
        }
    return JSONResponse(status_code=status_code, content=payload)

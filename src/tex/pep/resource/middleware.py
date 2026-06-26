"""B3 — a thin, pure-ASGI demand-middleware + an nginx auth_request reference.

Both are THIN WRAPPERS over ``verify.verify_tgpcc``. They add the in-path
plumbing (read the header, short-circuit a 401/403) and ZERO new verification
logic. Like ``verify.py`` they import ONLY the standard library — no fastapi, no
starlette — so a downstream resource can mount the middleware on any ASGI server
without dragging in the Tex app/PDP (see the import-purity contract in
``verify.py``'s docstring).

HONESTY: mounting this middleware makes the resource DEMAND a TG-PCC on the
protected routes that traverse it. It is NOT un-bypassable — a route that does
not pass through this middleware (a raw API key, an alternate port) is not
covered. The non-bypassable property is POSITIONAL-ONLY. See the package README.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable
from typing import Any

from tex.pep.resource.verify import (
    PresentedRequest,
    ResourceCheck,
    verify_tgpcc,
)

__all__ = [
    "TexDemandMiddleware",
    "verify_request_headers",
    "asgi_auth_request_app",
]

# The header the resource demands the TG-PCC on. Mirrors the credential-presenting
# convention (a DPoP-style sender-constrained token + its proof).
_CRED_HEADER = b"x-tex-credential"
_DPOP_HEADER = b"x-tex-dpop"


def _header(headers: Iterable[tuple[bytes, bytes]], name: bytes) -> str | None:
    """First value of a header (ASGI headers are list[(bytes, bytes)])."""
    lname = name.lower()
    for k, v in headers:
        if k.lower() == lname:
            try:
                return v.decode("latin-1")
            except Exception:  # noqa: BLE001
                return None
    return None


def verify_request_headers(
    scope: dict[str, Any],
    jwks: dict[str, Any],
    *,
    pinned_epoch: int | None = None,
    expected_issuer: str | None = None,
    require_prov_commit: bool = True,
    now: float | None = None,
) -> ResourceCheck:
    """DEMAND + verify a TG-PCC from an ASGI ``http`` scope, default-DENY.

    Builds the PRESENTED request from ``scope['method']`` + ``scope['path']`` (so
    the intent-bind is recomputed from the call the resource actually received)
    and reads the token + DPoP proof from the demand headers. A missing header is
    a DENY ("no artifact") — never a bypass.
    """
    headers = scope.get("headers") or []
    token = _header(headers, _CRED_HEADER)
    dpop = _header(headers, _DPOP_HEADER)
    request = PresentedRequest(
        method=str(scope.get("method", "")),
        resource=str(scope.get("path", "")),
        params=_query_params(scope),
    )
    return verify_tgpcc(
        token,
        request,
        dpop,
        jwks,
        pinned_epoch,
        expected_issuer=expected_issuer,
        now=now,
        require_prov_commit=require_prov_commit,
    )


def _query_params(scope: dict[str, Any]) -> dict[str, str]:
    """Parse the ASGI query string into a flat dict (params for the intent-bind).

    NOTE: the intent commitment is order-insensitive in keys, so the resource and
    the minter must agree on the params SHAPE. A resource that commits a richer
    params structure should build ``PresentedRequest`` itself rather than rely on
    this default query parse.
    """
    raw = scope.get("query_string") or b""
    if not raw:
        return {}
    from urllib.parse import parse_qsl

    try:
        return dict(parse_qsl(raw.decode("latin-1")))
    except Exception:  # noqa: BLE001
        return {}


class TexDemandMiddleware:
    """A pure-ASGI middleware that DEMANDS a TG-PCC on protected routes.

    Mirrors the project's own ``_WarmupGateMiddleware`` shape (main.py): wrap a
    plain ASGI app, guard on ``scope['type'] == 'http'``, verify, and on failure
    emit a JSON 401/403 WITHOUT calling the wrapped app. It never buffers the body
    (streaming/SSE responses are unaffected) because it only ever short-circuits
    BEFORE the app runs.

    ``protected`` is an optional predicate ``(path: str) -> bool`` selecting which
    routes to demand on; when omitted, EVERY http route is protected (fail-closed
    default). Non-http scopes (lifespan, websocket) pass straight through.

    Usage (any ASGI server, not only FastAPI)::

        app = TexDemandMiddleware(app, jwks=pinned_jwks, expected_issuer="tex-authority")
    """

    def __init__(
        self,
        app: Callable,
        *,
        jwks: dict[str, Any],
        pinned_epoch: int | None = None,
        expected_issuer: str | None = None,
        require_prov_commit: bool = True,
        protected: Callable[[str], bool] | None = None,
    ) -> None:
        self.app = app
        self._jwks = jwks
        self._pinned_epoch = pinned_epoch
        self._expected_issuer = expected_issuer
        self._require_prov_commit = require_prov_commit
        self._protected = protected

    async def __call__(self, scope: dict[str, Any], receive: Callable, send: Callable) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        path = str(scope.get("path", ""))
        if self._protected is not None and not self._protected(path):
            await self.app(scope, receive, send)
            return

        chk = verify_request_headers(
            scope,
            self._jwks,
            pinned_epoch=self._pinned_epoch,
            expected_issuer=self._expected_issuer,
            require_prov_commit=self._require_prov_commit,
        )
        if chk.ok:
            await self.app(scope, receive, send)
            return

        # DENY — 401 when nothing was presented, 403 when a token was presented
        # but failed a leg. Either way: short-circuit, never call the app.
        status = 401 if chk.reason == "no artifact" else 403
        await _send_json(
            send,
            status,
            {"released": False, "reason": chk.reason, "detail": "tex credential required"},
        )


async def _send_json(send: Callable, status: int, payload: dict[str, Any]) -> None:
    body = json.dumps(payload).encode("utf-8")
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"cache-control", b"no-store"),
                (b"content-length", str(len(body)).encode("ascii")),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


def asgi_auth_request_app(
    jwks: dict[str, Any],
    *,
    pinned_epoch: int | None = None,
    expected_issuer: str | None = None,
    require_prov_commit: bool = True,
) -> Callable:
    """A tiny ASGI app for nginx ``auth_request`` — returns 204 (PERMIT) or
    401/403 (DENY), with NO body.

    nginx's ``auth_request`` issues an internal subrequest to this endpoint and
    gates the real upstream on its status. The original request's method/path and
    the demand headers must be forwarded to the subrequest (see the reference
    config in ``nginx_auth_request.conf``). This app reuses the SAME
    ``verify_request_headers`` the in-process middleware uses — there is exactly
    one verification path.
    """

    async def _app(scope: dict[str, Any], receive: Callable, send: Callable) -> None:
        if scope.get("type") != "http":
            await send({"type": "http.response.start", "status": 404, "headers": []})
            await send({"type": "http.response.body", "body": b""})
            return
        chk = verify_request_headers(
            scope,
            jwks,
            pinned_epoch=pinned_epoch,
            expected_issuer=expected_issuer,
            require_prov_commit=require_prov_commit,
        )
        if chk.ok:
            status = 204
        else:
            status = 401 if chk.reason == "no artifact" else 403
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [
                    (b"cache-control", b"no-store"),
                    (b"x-tex-deny-reason", chk.reason.encode("latin-1", "replace")),
                ],
            }
        )
        await send({"type": "http.response.body", "body": b""})

    return _app

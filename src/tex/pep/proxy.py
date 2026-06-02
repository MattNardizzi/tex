"""
The transparent enforcement proxy — the userspace data-plane PEP.

This is the thing the eBPF kernel-floor redirects agent egress into, and it
also runs standalone as an MCP/HTTP sidecar gateway. For every action that
arrives it: resolves the agent identity and the real upstream, maps the
request to a decision, asks the PDP, and obeys ``released`` — forwarding the
call upstream on PERMIT, refusing with 403 otherwise. A refused ABSTAIN is
already queued to the one voice by the PDP; the proxy just blocks.

It is MCP-aware. A JSON-RPC ``tools/call`` is ruled on by tool name (the
action) and arguments (the content). A ``tools/list`` is *filtered discovery*:
when the proxy can see the governor in-process, the response is stripped to the
tools the agent's sealed capability surface allows — the agent never learns a
tool it may not call exists.

What this layer does NOT do: terminate TLS to read encrypted intent. That is
the eBPF uprobe layer's job (TLS interception at the userspace SSL boundary).
This proxy enforces on the HTTP/MCP request it is handed — plaintext egress
redirected by the kernel, an explicit sidecar hop, or an MCP client pointed at
it.

Identity & routing are taken from request headers the redirector/sidecar sets:
    X-Tex-Agent-Id     stable agent UUID (preferred)
    X-Tex-Agent        external id / name (fallback resolution)
    X-Tex-Tenant       tenant (else the proxy's configured default)
    X-Tex-Upstream     real upstream base URL (the SO_ORIGINAL_DST the eBPF
                       redirector recovered); else reconstructed from Host
    X-Tex-Session      logical session id (optional)
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Protocol
from uuid import UUID

from tex.pep.decision_client import Decision, DecisionClient, DecisionResult

__all__ = [
    "ProxyConfig",
    "Forwarder",
    "HttpxForwarder",
    "TexEnforcementProxy",
    "build_proxy_app",
]


@dataclass(frozen=True, slots=True)
class ProxyConfig:
    environment: str = "production"
    default_tenant: str = "default"
    # Cap the body bytes folded into a decision's content.
    max_content_bytes: int = 16_000
    # When the governor is reachable in-process, filter tools/list responses.
    filter_tool_discovery: bool = True
    # Sidecar mode: when the proxy lives in the agent's own pod, every request
    # it sees is that one agent's. The injector sets these from the pod's
    # downward API so traffic with no per-request identity header is still
    # attributed to the right sealed agent.
    default_agent_id: str | None = None
    default_agent_external_id: str | None = None


@dataclass(frozen=True, slots=True)
class UpstreamResponse:
    status: int
    headers: dict[str, str]
    body: bytes


class Forwarder(Protocol):
    """Sends the permitted request to the real upstream."""

    def send(
        self, method: str, url: str, headers: dict[str, str], body: bytes
    ) -> UpstreamResponse: ...


class HttpxForwarder:
    """Default upstream forwarder. Lazily imports httpx."""

    __slots__ = ("_timeout",)

    def __init__(self, timeout: float = 30.0) -> None:
        self._timeout = timeout

    def send(
        self, method: str, url: str, headers: dict[str, str], body: bytes
    ) -> UpstreamResponse:
        import httpx

        with httpx.Client(timeout=self._timeout) as client:
            resp = client.request(method, url, headers=headers, content=body)
            return UpstreamResponse(
                status=resp.status_code,
                headers=dict(resp.headers),
                body=resp.content,
            )


# Hop-by-hop and routing headers stripped before forwarding upstream.
_STRIP_HEADERS = {
    "host",
    "content-length",
    "connection",
    "keep-alive",
    "proxy-authorization",
    "proxy-connection",
    "transfer-encoding",
    "upgrade",
    "x-tex-agent-id",
    "x-tex-agent",
    "x-tex-tenant",
    "x-tex-upstream",
    "x-tex-session",
}


class TexEnforcementProxy:
    """The PEP. Frame-agnostic core; ``build_proxy_app`` wraps it in Starlette."""

    def __init__(
        self,
        *,
        decision_client: DecisionClient,
        forwarder: Forwarder | None = None,
        config: ProxyConfig | None = None,
        governance: Any | None = None,
    ) -> None:
        self._decide = decision_client
        self._forward = forwarder or HttpxForwarder()
        self._config = config or ProxyConfig()
        # Optional in-process governor, only for filtered tool discovery.
        self._governance = governance

    # ------------------------------------------------------------------ core

    def handle(
        self,
        *,
        method: str,
        path: str,
        headers: dict[str, str],
        body: bytes,
    ) -> UpstreamResponse:
        """Rule on one request and either forward it or refuse it."""
        h = {k.lower(): v for k, v in headers.items()}
        upstream_base = h.get("x-tex-upstream") or _reconstruct_upstream(h)
        if not upstream_base:
            return _refuse(
                "No upstream resolved; refusing to forward blind.", verdict="FORBID"
            )

        agent_id = _as_uuid(h.get("x-tex-agent-id")) or _as_uuid(
            self._config.default_agent_id
        )
        agent_external_id = h.get("x-tex-agent") or self._config.default_agent_external_id
        tenant = (h.get("x-tex-tenant") or self._config.default_tenant).strip().casefold()
        session_id = h.get("x-tex-session")

        decision, mcp = self._to_decision(
            method=method,
            path=path,
            body=body,
            tenant=tenant,
            recipient=_host_of(upstream_base),
            agent_id=agent_id,
            agent_external_id=agent_external_id,
            session_id=session_id,
        )

        result = self._decide.decide(decision)
        if not result.released:
            return _refuse(result.reason or "Forbidden by Tex.", verdict=result.verdict)

        # PERMIT — forward upstream.
        fwd_headers = {k: v for k, v in headers.items() if k.lower() not in _STRIP_HEADERS}
        url = upstream_base.rstrip("/") + path
        upstream = self._forward.send(method, url, fwd_headers, body)

        # Filtered discovery: strip tools the agent may not call.
        if (
            mcp == "tools/list"
            and self._config.filter_tool_discovery
            and self._governance is not None
        ):
            upstream = self._filter_tools_list(
                upstream, tenant=tenant, agent_id=agent_id,
                agent_external_id=agent_external_id,
            )
        return upstream

    # ------------------------------------------------------------------ mapping

    def _to_decision(
        self,
        *,
        method: str,
        path: str,
        body: bytes,
        tenant: str,
        recipient: str | None,
        agent_id: UUID | None,
        agent_external_id: str | None,
        session_id: str | None,
    ) -> tuple[Decision, str | None]:
        cap = self._config.max_content_bytes
        mcp_kind: str | None = None
        action_type = f"http_{method.lower()}"
        content = f"{method} {path}"
        channel = "network"

        parsed = _try_json(body)
        if isinstance(parsed, dict) and parsed.get("jsonrpc") == "2.0":
            mcp_method = parsed.get("method")
            channel = "mcp"
            if mcp_method == "tools/call":
                params = parsed.get("params") or {}
                tool = params.get("name") or "unknown_tool"
                mcp_kind = "tools/call"
                action_type = str(tool)
                content = json.dumps(params.get("arguments", {}))[:cap] or "{}"
            elif mcp_method == "tools/list":
                mcp_kind = "tools/list"
                action_type = "mcp_tools_list"
                content = "list available tools"
            else:
                action_type = f"mcp_{mcp_method or 'unknown'}"
                content = json.dumps(parsed.get("params", {}))[:cap] or "{}"
        else:
            # Plain HTTP egress: fold a bounded slice of the body in as content.
            text = body[:cap].decode("utf-8", errors="replace") if body else ""
            content = (f"{method} {path}\n{text}").strip()[:cap] or f"{method} {path}"

        decision = Decision(
            tenant=tenant,
            action_type=action_type,
            content=content or f"{method} {path}",
            channel=channel,
            environment=self._config.environment,
            recipient=recipient,
            agent_id=agent_id,
            agent_external_id=agent_external_id,
            session_id=session_id,
        )
        return decision, mcp_kind

    # ------------------------------------------------------------------ filtered discovery

    def _filter_tools_list(
        self,
        upstream: UpstreamResponse,
        *,
        tenant: str,
        agent_id: UUID | None,
        agent_external_id: str | None,
    ) -> UpstreamResponse:
        surface = self._resolve_surface(tenant, agent_id, agent_external_id)
        if surface is None:
            return upstream
        body = _try_json(upstream.body)
        if not isinstance(body, dict):
            return upstream
        result = body.get("result")
        if not isinstance(result, dict) or not isinstance(result.get("tools"), list):
            return upstream
        permits = getattr(surface, "permits_action_type", None)
        if not callable(permits):
            return upstream
        kept = [
            t
            for t in result["tools"]
            if isinstance(t, dict) and permits(str(t.get("name", "")))
        ]
        result["tools"] = kept
        new_body = json.dumps(body).encode("utf-8")
        headers = dict(upstream.headers)
        headers["content-length"] = str(len(new_body))
        return UpstreamResponse(status=upstream.status, headers=headers, body=new_body)

    def _resolve_surface(
        self, tenant: str, agent_id: UUID | None, agent_external_id: str | None
    ) -> Any | None:
        gov = self._governance
        if gov is None:
            return None
        try:
            agent = gov._resolve_agent(tenant, agent_id, agent_external_id)  # noqa: SLF001
        except Exception:  # noqa: BLE001
            return None
        return getattr(agent, "capability_surface", None) if agent is not None else None


# --------------------------------------------------------------------------- #
# Helpers                                                                      #
# --------------------------------------------------------------------------- #


def _refuse(reason: str, *, verdict: str) -> UpstreamResponse:
    payload = json.dumps(
        {"forbidden": True, "verdict": verdict, "spoken": reason}
    ).encode("utf-8")
    return UpstreamResponse(
        status=403,
        headers={"content-type": "application/json", "x-tex-verdict": verdict},
        body=payload,
    )


def _reconstruct_upstream(headers: dict[str, str]) -> str | None:
    host = headers.get("host")
    if not host:
        return None
    scheme = headers.get("x-forwarded-proto", "https")
    return f"{scheme}://{host}"


def _host_of(base_url: str) -> str | None:
    try:
        from urllib.parse import urlparse

        return urlparse(base_url).hostname
    except Exception:  # noqa: BLE001
        return None


def _try_json(body: bytes) -> Any:
    if not body:
        return None
    try:
        return json.loads(body.decode("utf-8", errors="replace"))
    except Exception:  # noqa: BLE001
        return None


def _as_uuid(value: str | None) -> UUID | None:
    if not value:
        return None
    try:
        return UUID(value)
    except (ValueError, TypeError):
        return None


# --------------------------------------------------------------------------- #
# Starlette wrapper                                                            #
# --------------------------------------------------------------------------- #


def build_proxy_app(proxy: TexEnforcementProxy):
    """Wrap the PEP core in a Starlette app with a catch-all route.

    Every method/path is intercepted, ruled on, and forwarded or refused.
    """
    from starlette.applications import Starlette
    from starlette.requests import Request
    from starlette.responses import Response
    from starlette.routing import Route

    async def _endpoint(request: Request) -> Response:
        body = await request.body()
        result = proxy.handle(
            method=request.method,
            path=request.url.path
            + (("?" + request.url.query) if request.url.query else ""),
            headers=dict(request.headers),
            body=body,
        )
        return Response(
            content=result.body,
            status_code=result.status,
            headers=result.headers,
        )

    return Starlette(
        routes=[
            Route(
                "/{path:path}",
                _endpoint,
                methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"],
            )
        ]
    )

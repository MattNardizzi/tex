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

Reference-monitor posture (this module's job):
  * Destination is the **kernel-captured** dst recovered from Thread T1's
    orig_dst loader over a UDS, keyed by the accepted connection's source
    ``ip:port`` — NOT the spoofable ``Host`` / ``X-Tex-Upstream`` header. We
    rule on, and forward to, the destination the kernel actually saw; the
    headers are display/vhost-only once a verified dst exists (closes G7).
  * Identity is an **attested** credential (``verify_agent_credential``),
    cross-checked against the ruled-on agent id — not ``X-Tex-Agent-Id`` taken
    on faith (closes G6).
  * Every released action mints a single-use, **content-bound permit** that is
    verified against a fresh digest of the exact bytes about to egress and
    consumed exactly once — the egress proof (closes G10).
  * The decision client can be wrapped to **seal** an offline-verifiable
    receipt per decision (closes G4; wired, gated, in ``__main__``).

Identity & routing headers the redirector/sidecar sets (display-only once a
kernel-verified dst exists):
    X-Tex-Agent-Id        stable agent UUID (preferred)
    X-Tex-Agent           external id / name (fallback resolution)
    X-Tex-Tenant          tenant (else the proxy's configured default)
    X-Tex-Upstream        upstream base URL — UNTRUSTED fallback only; used to
                          route ONLY when no kernel-verified dst is available
    X-Tex-Session         logical session id (optional)
    X-Tex-Agent-Credential base64 (or raw) JSON signed identity card (G6)
"""

from __future__ import annotations

import json
import logging
import zlib
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Protocol
from uuid import UUID, uuid4

from tex.emission import (
    APPROACH_PROVIDER_TRUSTED,
    compile_constraint,
    detect_provider,
    rewrite_provider_request,
    seal_constraint,
)
from tex.identity.agent_credential import (
    AttestedIdentity,
    CredentialVerification,
    verify_agent_credential,
)
from tex.pep.decision_client import Decision, DecisionClient, DecisionResult

__all__ = [
    "ProxyConfig",
    "Forwarder",
    "HttpxForwarder",
    "ResolvedDst",
    "OrigDstResolver",
    "SurfaceResolver",
    "TexEnforcementProxy",
    "build_proxy_app",
]

_logger = logging.getLogger(__name__)


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
    # G7 — when True, a request with NO kernel-verified dst is FORBIDden rather
    # than falling back to the spoofable Host/X-Tex-Upstream header. Deployments
    # behind the eBPF redirector (where every connection HAS an orig_dst) should
    # set this; a standalone sidecar without the loader leaves it False.
    require_verified_dst: bool = False
    # G6 — issuer id -> base64 raw-32-byte Ed25519 public key. When empty, no
    # credential can verify; with require_identity False that degrades to the
    # documented header-trust gap (see _verify_identity).
    trusted_issuers: dict[str, str] = field(default_factory=dict)
    # G6 — when True, a request without a verified credential matching the
    # ruled-on agent id is FORBIDden. Default False: we still FORBID a *bad*
    # presented credential, but we do not require one (and never claim an
    # unattested header is attested).
    require_identity: bool = False
    # Cross-tenant binding (wave-1 medium d) — when True, a presented credential
    # must carry ``aud == "tex://<request-tenant>"`` (the reused audience
    # primitive); a card scoped to a different tenant (or with no aud) is
    # FORBIDden EVEN when require_identity is False, so a credential minted for
    # tenant A cannot be replayed against tenant B. Default False: degrade-open
    # for issuers not yet minting ``aud=tex://<tenant>`` (honest — flagged, not
    # claimed as enforced until issuers populate the claim and operators set it).
    require_tenant_binding: bool = False
    # G10 — TTL of a minted egress permit (seconds).
    permit_ttl_seconds: int = 30
    # G6 — credential freshness (anti-replay). When ``pep_audience`` is set a
    # presented credential must carry that ``aud``; an ``exp`` on the card is
    # always honoured, and ``require_credential_expiry`` additionally rejects a
    # card with no ``exp`` at all. Together these stop a captured credential from
    # being a non-expiring, anywhere-valid bearer token.
    pep_audience: str | None = None
    require_credential_expiry: bool = False
    # G7 (vhost binding) — when True (default), a kernel-pinned connection that
    # carries a Host header rules policy on the HOSTNAME and requires that host to
    # resolve to the kernel-pinned IP. This catches a forbidden vhost co-located
    # on an allowed IP (CDN / shared host) and refuses a Host naming an unrelated
    # IP. False falls back to ruling on the IP alone (the coarser prior behaviour).
    require_host_dst_match: bool = True


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


class SurfaceResolver(Protocol):
    """Resolves an agent's sealed ``CapabilitySurface`` WITHOUT an in-process
    governor — the http-mode path to the emission gate / filtered discovery.

    Returns the surface to confine egress against, or ``None`` (no restriction /
    unresolved -> the gate leaves the body unchanged, fail-safe). The PRIMARY
    implementation piggybacks the surface that already drove the PDP decision (no
    extra round-trip); a SECONDARY one may fetch it from the PDP (opt-in)."""

    def __call__(
        self,
        tenant: str,
        agent_id: "UUID | None",
        agent_external_id: str | None,
    ) -> "Any | None": ...


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


# --------------------------------------------------------------------------- #
# Kernel-captured destination (G7)                                             #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class ResolvedDst:
    """The true destination the kernel saw for the accepted connection.

    ``tls`` is the transport hint when a layer KNOWS it (the tls_front terminator,
    or a future uprobe): ``True`` => speak TLS upstream, ``False`` => plaintext,
    ``None`` => unknown (the kernel orig_dst loader only sees ip:port, so it
    leaves this None and the scheme is guessed from the port — see
    ``_base_from_dst``)."""

    ip: str
    port: int
    tls: bool | None = None


class OrigDstResolver:
    """UDS client to Thread T1's orig_dst loader.

    Recovers the SO_ORIGINAL_DST the eBPF redirector captured for the accepted
    connection, keyed by the agent's source ``ip:port`` (``getpeername`` on the
    accepted socket, surfaced by ASGI as ``scope['client']``). Contract, fixed
    with Thread T1:

        request   {"src_ip": str, "src_port": int, "family": 4|6}
        response  {"ip": str, "port": int}  | {"error": "not_found"}

    Fail-soft: any socket/timeout/parse error or a ``not_found`` response
    returns ``None`` so the caller degrades to the (untrusted) header path —
    EXCEPT when ``ProxyConfig.require_verified_dst`` makes a miss fail closed.
    """

    __slots__ = ("_path", "_timeout")

    def __init__(self, path: str, *, timeout: float = 0.5) -> None:
        self._path = path
        self._timeout = timeout

    def resolve(self, src_ip: str, src_port: int) -> ResolvedDst | None:
        import socket

        family = 6 if ":" in src_ip else 4
        req = json.dumps(
            {"src_ip": src_ip, "src_port": int(src_port), "family": family}
        ).encode("utf-8")
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(self._timeout)
                sock.connect(self._path)
                sock.sendall(req)
                try:
                    sock.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                chunks: list[bytes] = []
                while True:
                    buf = sock.recv(4096)
                    if not buf:
                        break
                    chunks.append(buf)
        except OSError as exc:
            _logger.warning("orig_dst UDS %s unreachable: %s", self._path, exc)
            return None
        raw = b"".join(chunks)
        if not raw:
            return None
        try:
            resp = json.loads(raw.decode("utf-8", errors="replace"))
        except (ValueError, json.JSONDecodeError):
            _logger.warning("orig_dst UDS returned unparseable response")
            return None
        if not isinstance(resp, dict) or "ip" not in resp or "port" not in resp:
            return None  # {"error": "not_found"} or malformed -> no verified dst
        try:
            return ResolvedDst(ip=str(resp["ip"]), port=int(resp["port"]))
        except (TypeError, ValueError):
            return None


def _base_from_dst(dst: ResolvedDst) -> str:
    """Reconstruct an upstream base URL from a kernel-verified ip:port.

    The kernel gives an ip:port, not a scheme. Resolution order:

      1. ``dst.tls`` when a layer KNOWS the transport (tls_front terminator /
         uprobe) — authoritative.
      2. port 80 — the one unambiguous well-known plaintext port → ``http``.
      3. anything else (443, 8443, and every unknown port) → ``https``.

    Rationale (the fix for the old ``443 -> https else http`` rule): an opaque
    TLS service on a non-standard port (8443, a private MCP-over-TLS endpoint)
    must NOT be silently downgraded to ``http`` — that would make the forwarder
    speak plaintext to a TLS upstream (a broken/foot-gun egress, and a
    visibility gap dressed as "it worked"). Defaulting unknown ports to ``https``
    fails safe; a layer that truly knows it is plaintext pins ``dst.tls=False``.

    The TCP destination is pinned to ``dst.ip``; a downstream ``Host`` header can
    at most select a vhost on that already-authorized server, never redirect
    egress elsewhere.
    """
    if dst.tls is True:
        scheme = "https"
    elif dst.tls is False:
        scheme = "http"
    elif dst.port == 80:
        scheme = "http"
    else:
        scheme = "https"
    return f"{scheme}://{dst.ip}:{dst.port}"


# Hop-by-hop and routing headers stripped before forwarding upstream. The
# inbound x-tex-* control headers are stripped so an agent cannot smuggle a
# pre-set permit / credential / routing hint upstream or past a later hop.
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
    "x-tex-permit",
    "x-tex-agent-credential",
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
        origdst: OrigDstResolver | None = None,
        permit_memory: Any | None = None,
        seal_ledger: Any | None = None,
        host_resolver: "Callable[[str], set[str]] | None" = None,
        surface_resolver: "SurfaceResolver | None" = None,
    ) -> None:
        self._decide = decision_client
        self._forward = forwarder or HttpxForwarder()
        self._config = config or ProxyConfig()
        # Optional in-process governor, only for filtered tool discovery.
        self._governance = governance
        # Capability-surface resolver for HTTP sidecar mode (no in-process
        # governor). When set, the emission gate + filtered discovery activate
        # without an in-process governor: the resolver supplies the agent's
        # surface (piggybacked from the PDP decision, or fetched). None => the
        # gate stays inert in http mode unless a per-request piggyback surface is
        # present (today's behaviour for a bare sidecar).
        self._surface_resolver = surface_resolver
        # G7 — kernel-captured destination recovery (None => header fallback).
        self._origdst = origdst
        # G4 — when set, seal ONE ENFORCEMENT receipt per request for the TERMINAL
        # outcome (after the PDP verdict AND the permit gate), so a receipt can
        # never claim "executed" for an action the permit gate later 403'd. None
        # => seal nothing (gated off by default in __main__, as before).
        self._seal_ledger = seal_ledger
        self.seal_records: list[Any] = []
        # G7 vhost binding — host -> resolved IP set (default: system DNS).
        # Injectable for tests and to swap in a pinned/cached resolver.
        self._host_resolver = host_resolver or _default_host_ips
        # G10 — durable permit subsystem (a MemorySystem-like object exposing
        # issue_permit / verify_permit / .permits). None => no egress permits
        # (today's behaviour, documented). When present, every released action
        # mints+verifies+consumes a single-use content-bound permit.
        self._permit_memory = permit_memory

    # ------------------------------------------------------------------ core

    def handle(
        self,
        *,
        method: str,
        path: str,
        headers: dict[str, str],
        body: bytes,
        peer: tuple[str, int] | None = None,
    ) -> UpstreamResponse:
        """Rule on one request and either forward it or refuse it.

        ``peer`` is the accepted connection's source ``(ip, port)`` — the key
        the orig_dst loader maps to the kernel-captured destination (G7).
        """
        h = {k.lower(): v for k, v in headers.items()}

        # ---- G7: destination is the kernel-captured dst, not a spoofable header
        verified_dst = self._resolve_verified_dst(peer)
        if verified_dst is not None:
            upstream_base: str | None = _base_from_dst(verified_dst)
            dst_trusted = True
        else:
            if self._config.require_verified_dst:
                return _refuse(
                    "No kernel-verified destination for this connection; "
                    "refusing to trust request headers.",
                    verdict="FORBID",
                )
            upstream_base = h.get("x-tex-upstream") or _reconstruct_upstream(h)
            dst_trusted = False
            if upstream_base:
                _logger.warning(
                    "PEP: no verified dst for peer=%s — routing on UNTRUSTED "
                    "header upstream %s (standalone-sidecar fallback)",
                    peer,
                    upstream_base,
                )
        if not upstream_base:
            return _refuse(
                "No upstream resolved; refusing to forward blind.", verdict="FORBID"
            )
        recipient = _host_of(upstream_base)

        # ---- G7 (vhost binding): the kernel pins the TCP destination to an IP,
        # but the agent's Host header still selects which vhost on that IP the
        # bytes reach. Ruling on the IP alone misses a FORBIDDEN hostname
        # co-located on an ALLOWED IP (CDN / shared host). So when the dst is
        # kernel-verified and a Host is present, require the host to resolve to
        # the pinned IP and rule policy on the NAME the bytes actually reach.
        if (
            dst_trusted
            and verified_dst is not None
            and self._config.require_host_dst_match
        ):
            vhost = _hostname_only(h.get("host"))
            if vhost and vhost != verified_dst.ip:
                if verified_dst.ip not in self._host_ips(vhost):
                    return _refuse(
                        f"Host {vhost!r} does not resolve to the kernel-verified "
                        f"destination {verified_dst.ip}; refusing vhost/IP mismatch.",
                        verdict="FORBID",
                    )
                recipient = vhost  # rule policy on the hostname the bytes reach

        agent_id = _as_uuid(h.get("x-tex-agent-id")) or _as_uuid(
            self._config.default_agent_id
        )
        agent_external_id = h.get("x-tex-agent") or self._config.default_agent_external_id
        tenant = (h.get("x-tex-tenant") or self._config.default_tenant).strip().casefold()
        session_id = h.get("x-tex-session")

        # ---- G6: authenticate identity instead of trusting X-Tex-Agent-Id
        ident = self._verify_identity(
            h, agent_id=agent_id, agent_external_id=agent_external_id, tenant=tenant
        )
        if ident.refuse is not None:
            return ident.refuse
        # When the header carried no principal but a verified credential did,
        # rule on the attested id rather than an anonymous request.
        if agent_id is None and agent_external_id is None and ident.effective_external_id:
            agent_external_id = ident.effective_external_id

        decision, mcp = self._to_decision(
            method=method,
            path=path,
            body=body,
            tenant=tenant,
            recipient=recipient,
            agent_id=agent_id,
            agent_external_id=agent_external_id,
            session_id=session_id,
            attested_identity=ident.attested,
            content_encoding=h.get("content-encoding"),
        )

        result = self._decide.decide(decision)
        if not result.released:
            self._seal_outcome(
                decision, result, executed=False,
                reason=result.reason, attested=ident.attested,
            )
            return _refuse(result.reason or "Forbidden by Tex.", verdict=result.verdict)

        # ---- PERMIT path. The PDP may have piggybacked the agent's permitted
        # tool subset on the decision (http mode, race-free: the surface that
        # confined the ruling). Reconstruct it once and feed both gates below, so
        # the emission gate + filtered discovery fire WITHOUT an in-process
        # governor. None => fall through to the governor / injected resolver.
        piggyback_surface = self._surface_from_decision(result)

        # ---- PERMIT path. Build the forward headers first.
        fwd_headers = {k: v for k, v in headers.items() if k.lower() not in _STRIP_HEADERS}
        # Preserve the agent's intended vhost ONLY when the TCP dst is pinned to a
        # kernel-verified IP: the Host can then select a vhost on the authorized
        # server but can never move the connection (G7). On the untrusted-header
        # fallback we let the forwarder set Host from the URL.
        if dst_trusted:
            orig_host = h.get("host")
            if orig_host:
                fwd_headers["Host"] = orig_host

        # ---- Emission gate (Approach B, provider-trusted): when the outbound
        # body is a known LLM-provider chat request, re-assert the agent's
        # permitted tool subset BEFORE it egresses. Placed BEFORE the permit gate
        # so the content-bound egress permit (G10) binds to the bytes that
        # ACTUALLY egress — the rewrite only ever TIGHTENS, so the released
        # request stays within what the PDP already PERMITted.
        body = self._apply_emission_gate(
            body=body,
            fwd_headers=fwd_headers,
            tenant=tenant,
            agent_id=agent_id,
            agent_external_id=agent_external_id,
            decision_id=result.decision_id,
            content_encoding=h.get("content-encoding"),
            surface=piggyback_surface,
        )

        # ---- G10: mint -> persist -> verify(fresh digest, audience) -> consume
        permit_outcome = self._mint_check_consume_permit(
            result=result, decision=decision, recipient=recipient, body=body
        )
        if isinstance(permit_outcome, UpstreamResponse):
            # A released action the permit gate REFUSED: the receipt must record
            # the true terminal outcome (blocked), never a premature "executed".
            self._seal_outcome(
                decision, result, executed=False,
                reason="permit gate refused released action",
                attested=ident.attested,
            )
            return permit_outcome  # permit verification failed -> FORBID
        if permit_outcome is not None:
            fwd_headers["X-Tex-Permit"] = permit_outcome

        # The full gate ALLOWED the action: seal the executed outcome before
        # dispatch (the action is now committed to forward).
        self._seal_outcome(
            decision, result, executed=True,
            reason=result.reason, attested=ident.attested,
        )
        url = upstream_base.rstrip("/") + path
        upstream = self._forward.send(method, url, fwd_headers, body)

        # Filtered discovery: strip tools the agent may not call. Activates when a
        # surface is reachable — an in-process governor OR an http-mode resolver
        # (piggyback / fetch) — not only inprocess (closes the http-mode gap).
        if (
            mcp == "tools/list"
            and self._config.filter_tool_discovery
            and (
                self._governance is not None
                or self._surface_resolver is not None
                or piggyback_surface is not None
            )
        ):
            upstream = self._filter_tools_list(
                upstream, tenant=tenant, agent_id=agent_id,
                agent_external_id=agent_external_id, surface=piggyback_surface,
            )
        return upstream

    # ------------------------------------------------------------------ opaque L4

    def rule_opaque(self, *, recipient: str | None) -> DecisionResult:
        """Rule on TLS-opaque HTTPS egress whose content the proxy could NOT read.

        The companion to :meth:`handle` for the ``tls_front`` terminator: it is
        called for every connection NOT MITM-terminated (destination off the
        terminate-allowlist, the agent refused our leaf under termination, or
        ECH/SNI that could not be pinned to the kernel orig_dst). There is no
        plaintext HTTP request and no readable ``X-Tex-*`` identity header — both
        are inside the encrypted stream — so we rule on what IS known: the
        SNI-pinned-to-orig_dst ``recipient`` and the sidecar's configured agent
        identity, with ``action_type='https_opaque'`` (see :meth:`_to_decision`).

        Returns the ``DecisionResult``. The caller (``tls_front``) splices the TCP
        through to the verified orig_dst on ``released`` and refuses otherwise — so
        un-inspectable HTTPS becomes an EXPLICIT verdict the PDP can ABSTAIN on,
        never a silent bypass. A seal ledger (when wired) records ONE terminal
        outcome whose channel/recipient say "opaque egress ruled", never "content
        observed" — the honest scope (CLAUDE.md: name must deliver its property).

        ``executed`` is sealed as ``released`` at the verdict point, mirroring
        :meth:`handle`'s "committed to forward" seal: a PERMIT here means the front
        is committed to splicing; a later TCP-level splice failure is an upstream
        error, not a policy bypass.
        """
        tenant = self._config.default_tenant.strip().casefold()
        agent_id = _as_uuid(self._config.default_agent_id)
        agent_external_id = self._config.default_agent_external_id

        decision, _ = self._to_decision(
            method="CONNECT",
            path="",
            body=b"",
            tenant=tenant,
            recipient=recipient,
            agent_id=agent_id,
            agent_external_id=agent_external_id,
            session_id=None,
            opaque=True,
        )
        result = self._decide.decide(decision)
        self._seal_outcome(
            decision,
            result,
            executed=result.released,
            reason=result.reason,
            attested=None,
        )
        return result

    # ------------------------------------------------------------------ G7 dst

    def _resolve_verified_dst(
        self, peer: tuple[str, int] | None
    ) -> ResolvedDst | None:
        resolver = self._origdst
        if resolver is None or peer is None:
            return None
        src_ip, src_port = peer
        if not src_ip or not src_port:
            return None
        try:
            return resolver.resolve(str(src_ip), int(src_port))
        except Exception:  # noqa: BLE001 — a resolver fault degrades to fallback
            _logger.warning("PEP: orig_dst resolve raised for peer=%s", peer, exc_info=True)
            return None

    def _host_ips(self, host: str) -> set[str]:
        """Resolved IPs for a vhost. Fail-closed: a resolver error returns an
        empty set, which makes the kernel-IP pin check refuse the request."""
        try:
            return set(self._host_resolver(host))
        except Exception:  # noqa: BLE001 — a resolver fault must not fail open
            _logger.warning("PEP: host resolve raised for %r", host, exc_info=True)
            return set()

    # ------------------------------------------------------------------ G6 identity

    def _verify_identity(
        self,
        h: dict[str, str],
        *,
        agent_id: UUID | None,
        agent_external_id: str | None,
        tenant: str,
    ) -> "_IdentityCheck":
        """Authenticate a presented identity credential (fail-closed).

        Honest scope: ``verify_agent_credential`` attests *who* the agent is; it
        does NOT lower risk. A presented credential that is unsigned / tampered /
        from an untrusted issuer / oversize, or whose attested id disagrees with
        the ruled-on principal, is FORBIDden — an agent cannot mint an identity
        by setting a header. When NO credential is presented and
        ``require_identity`` is False, we proceed on the (unverified) header but
        never seal it as attested: that is the documented header-trust gap for
        deployments without an identity issuer wired, not a solved property.

        Cross-tenant binding: when ``require_tenant_binding`` is set the presented
        credential must carry ``aud == "tex://<tenant>"`` (the reused audience
        primitive), so a card minted for another tenant cannot be replayed here.
        A mismatch is FORBIDden EVEN when ``require_identity`` is False (a *bad*
        presented credential always loses). With the flag off, ``aud`` is left to
        ``pep_audience`` (None by default) — the documented degrade-open for
        issuers not yet minting a tenant ``aud``.
        """
        cfg = self._config
        principal = str(agent_id) if agent_id is not None else (agent_external_id or None)
        raw = h.get("x-tex-agent-credential")

        if not raw:
            # Fail-closed for tenant binding too: a MISSING card is strictly
            # weaker evidence than a card with a wrong/absent aud (already
            # FORBIDden below), so it must not pass where that card fails. When
            # require_tenant_binding is on, a no-credential request cannot be
            # bound to this tenant -> FORBID, even if require_identity is False.
            if cfg.require_identity or cfg.require_tenant_binding:
                return _IdentityCheck(
                    refuse=_refuse(
                        "No agent credential presented (cannot bind to tenant)."
                        if cfg.require_tenant_binding
                        else "No agent credential presented (identity required).",
                        verdict="FORBID",
                    )
                )
            return _IdentityCheck()  # documented gap: proceed, attested=None

        card = _decode_credential(raw)
        if card is None:
            return _IdentityCheck(
                refuse=_refuse("Malformed agent credential.", verdict="FORBID")
            )

        # When tenant binding is required, the credential's audience MUST be this
        # request's tenant URI; otherwise fall back to the per-PEP-instance
        # ``pep_audience`` (the existing scoping concept). Both reuse the same
        # signed ``aud`` claim and the same offline check in agent_credential.
        expected_audience = (
            f"tex://{tenant}" if cfg.require_tenant_binding else cfg.pep_audience
        )

        att = verify_agent_credential(
            card,
            trusted_issuers=cfg.trusted_issuers or {},
            expected_audience=expected_audience,
            require_expiry=cfg.require_credential_expiry,
        )
        # Cross-tenant binding: an aud that does not name this tenant fails the
        # audience check above (status == audience_mismatch). Refuse it with an
        # explicit, tenant-scoped reason BEFORE the generic not-verified branch,
        # so the verdict says WHY — and so the requirement is enforced even when
        # require_identity is False (a presented-but-wrongly-scoped card loses).
        if (
            cfg.require_tenant_binding
            and not att.verified
            and att.status == CredentialVerification.AUDIENCE_MISMATCH.value
        ):
            return _IdentityCheck(
                refuse=_refuse(
                    f"Agent credential not scoped to this tenant "
                    f"(expected aud=tex://{tenant}).",
                    verdict="FORBID",
                )
            )
        if not att.verified:
            return _IdentityCheck(
                refuse=_refuse(
                    f"Agent credential not verified: {att.status}.", verdict="FORBID"
                )
            )
        # Bind the attested identity to the ruled-on principal.
        if principal is not None and att.claimed_agent_id != principal:
            return _IdentityCheck(
                refuse=_refuse(
                    "Agent identity mismatch (attested id != declared id).",
                    verdict="FORBID",
                )
            )
        return _IdentityCheck(
            attested=att,
            effective_external_id=(
                att.claimed_agent_id if principal is None else None
            ),
        )

    # ------------------------------------------------------------------ G10 permit

    def _mint_check_consume_permit(
        self,
        *,
        result: DecisionResult,
        decision: Decision,
        recipient: str | None,
        body: bytes,
    ) -> UpstreamResponse | str | None:
        """Mint a single-use, content-bound egress permit for a released action.

        Returns the permit token to attach (success), an ``UpstreamResponse``
        refusal (FORBID — fail closed on any defect), or ``None`` when the permit
        subsystem is not configured (today's behaviour).

        Honest scope: this is a **Tex-to-Tex self-check**. A third-party API
        ignores ``X-Tex-Permit`` — the permit is *our* proof that the PDP
        released exactly these bytes to exactly this audience, not the upstream's
        admission control. The cryptographic defence against replay-to-different-
        content is the content digest re-derived here from the bytes about to
        egress; the durable consume makes the permit single-use for any
        Tex-aware verifier.
        """
        from tex.enforcement import permit

        mem = self._permit_memory
        if mem is None:
            return None  # permit enforcement not configured

        # The permit binds to the PDP decision; if that ruling carried no id we
        # synthesize one so the egress proof (content+audience) still mints, and
        # note the weakened linkage in the claim.
        did = _as_uuid(result.decision_id) or uuid4()

        minted = permit.mint(
            decision_id=did,
            tenant=decision.tenant,
            action_type=decision.action_type,
            agent_id=(
                str(decision.agent_id)
                if decision.agent_id is not None
                else decision.agent_external_id
            ),
            recipient=recipient,
            content=body,  # bind the EXACT bytes that will egress
            ttl_seconds=self._config.permit_ttl_seconds,
        )
        if minted is None:
            # Production requires TEX_PERMIT_SIGNING_SECRET; none set -> we cannot
            # produce an egress proof, so fail closed rather than forward blind.
            return _refuse(
                "Permit unavailable: no signing secret (fail-closed).",
                verdict="FORBID",
            )

        try:
            stored = mem.issue_permit(
                decision_id=did,
                nonce=minted.nonce,
                signature=minted.signature,
                expiry=minted.expiry,
                metadata=minted.metadata,
            )
        except Exception as exc:  # noqa: BLE001 — persist failure is fail-closed
            _logger.warning("PEP: permit persist failed: %s", exc)
            return _refuse(
                f"Permit persist failed: {type(exc).__name__}.", verdict="FORBID"
            )

        # Verify the just-minted permit against a FRESH digest of the bytes we are
        # about to send (closes the check-vs-commit / TOCTOU gap) and the pinned
        # audience.
        fresh_digest = permit.content_digest(body)
        principal = (
            str(decision.agent_id)
            if decision.agent_id is not None
            else decision.agent_external_id
        )
        verification = permit.verify(
            minted.token,
            expected_content_digest=fresh_digest,
            expected_audience=recipient,
            expected_action_type=decision.action_type,
            expected_tenant=decision.tenant,
            expected_agent_id=principal,
        )
        if not verification.ok:
            self._record_verification(
                mem, stored.permit_id, minted.nonce, verification.reason, ok=False
            )
            return _refuse(
                f"Permit verify failed: {verification.reason}.", verdict="FORBID"
            )

        # Single-use: consume exactly once. A replay of this token finds the
        # permit already consumed (or, for a foreign token, absent) -> rejected.
        current = mem.permits.get_by_nonce(minted.nonce)
        if current is None or not current.is_active:
            self._record_verification(
                mem, stored.permit_id, minted.nonce, "reused/inactive",
                ok=False, reused=True,
            )
            return _refuse("Permit not active (single-use).", verdict="FORBID")
        mem.permits.consume(stored.permit_id)
        self._record_verification(mem, stored.permit_id, minted.nonce, "ok", ok=True)
        return minted.token

    @staticmethod
    def _record_verification(
        mem: Any,
        permit_id: UUID,
        nonce: str,
        reason: str,
        *,
        ok: bool,
        reused: bool = False,
    ) -> None:
        """Append to the durable verification log; never break the request."""
        from tex.memory import VerificationResult

        if ok:
            outcome = VerificationResult.VALID
        elif reused:
            outcome = VerificationResult.REUSED
        else:
            outcome = VerificationResult.INVALID_SIG
        try:
            mem.verify_permit(
                permit_id=permit_id,
                consumed_nonce=nonce,
                result=outcome,
                reason=reason,
            )
        except Exception as exc:  # noqa: BLE001 — audit-log write is best-effort
            _logger.warning("PEP: verification record failed: %s", exc)

    # ------------------------------------------------------------------ G4 seal

    def _seal_outcome(
        self,
        decision: Decision,
        result: DecisionResult,
        *,
        executed: bool,
        reason: str | None,
        attested: AttestedIdentity | None,
    ) -> None:
        """Seal ONE ENFORCEMENT receipt for the TERMINAL outcome of this request.

        Called once, AFTER the full gate (PDP verdict + permit gate) resolves, so
        ``executed`` is what ACTUALLY happened — not the raw PDP ``released`` bit.
        This is the fix for the receipt-inversion defect: a permit-gate refusal of
        a released action now seals ``outcome=blocked``, never ``executed``. The
        PDP ``verdict`` is still recorded verbatim, so a "verdict PERMIT, outcome
        blocked" receipt truthfully shows the PDP released it but the PEP stopped
        it at the permit gate. Fail-soft: a seal failure never changes the
        response (mirrors ``seal_enforcement_decision``'s own contract)."""
        ledger = self._seal_ledger
        if ledger is None:
            return
        from tex.provenance.enforcement_seal import seal_enforcement_decision

        record = seal_enforcement_decision(
            ledger,
            action_type=decision.action_type,
            channel=decision.channel,
            environment=decision.environment,
            recipient=decision.recipient,
            agent_id=(
                str(decision.agent_id)
                if decision.agent_id is not None
                else (decision.agent_external_id or None)
            ),
            verdict=result.verdict,
            released=executed,  # the TRUE terminal outcome, not the PDP bit
            decision_id=result.decision_id,
            reason=reason,
            tier=result.tier,
            held=result.held,
            attested_identity=attested,
        )
        if record is not None:
            self.seal_records.append(record)

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
        attested_identity: AttestedIdentity | None = None,
        opaque: bool = False,
        content_encoding: str | None = None,
    ) -> tuple[Decision, str | None]:
        cap = self._config.max_content_bytes
        mcp_kind: str | None = None
        action_type = f"http_{method.lower()}"
        content = f"{method} {path}"
        channel = "network"

        if opaque:
            # TLS-opaque egress: the body is ciphertext we could NOT terminate or
            # read (the destination is not on the MITM terminate-allowlist, the
            # agent refused our leaf under termination, or ECH/SNI could not be
            # pinned). We know only WHERE it is going (``recipient`` = SNI pinned
            # to the kernel orig_dst, else the orig_dst IP), never WHAT. Mark it
            # ``https_opaque`` so the action is LABELLED honestly instead of
            # slipping through as a silent PERMIT-shaped ``http_<method>`` no-op.
            # WIRING STATUS: the PDP now CONSUMES this label — StandingGovernance
            # maps ``https_opaque`` -> ABSTAIN/held (governance/standing.py,
            # ``_UNINSPECTABLE_ACTION_TYPES`` -> ``_abstain_uninspectable``), so an
            # opaque request is HELD, never a content-blind PERMIT (CLAUDE.md rule
            # 2). The remaining gap is the PRODUCER: this opaque branch is reached
            # only via ``rule_opaque()`` -> ``TlsFront``, which is still test-only /
            # off the live deploy path (see pep/tls_front.py). So the DECISION half
            # of G9 is live; the live-path producer is the deploy follow-up.
            decision = Decision(
                tenant=tenant,
                action_type="https_opaque",
                content=(
                    f"TLS-opaque HTTPS egress to "
                    f"{recipient or 'unknown destination'}; content not "
                    "inspectable (not MITM-terminated)"
                ),
                channel=channel,
                environment=self._config.environment,
                recipient=recipient,
                agent_id=agent_id,
                agent_external_id=agent_external_id,
                session_id=session_id,
                attested_identity=attested_identity,
            )
            return decision, None

        # Decode the body per its Content-Encoding so the PDP rules on what the
        # agent is ACTUALLY sending — not the compressed bytes. A body Tex cannot
        # decode (br/zstd/unknown/bomb) is UN-inspectable: label it
        # ``http_opaque_body`` so the PDP holds it (ABSTAIN) rather than scoring
        # garbage as a benign ``http_<method>`` and content-blind PERMITting a
        # forbidden payload (the gzip-smuggle bypass). Mirrors the https_opaque
        # honesty for the TLS-opaque case.
        inspect_body, undecodable = _decode_for_inspection(body, content_encoding)
        if undecodable:
            decision = Decision(
                tenant=tenant,
                action_type="http_opaque_body",
                content=(
                    f"{method} {path}; request body uses Content-Encoding "
                    f"{(content_encoding or '').strip() or 'unknown'!r} that Tex "
                    "cannot decode — content not inspectable"
                ),
                channel=channel,
                environment=self._config.environment,
                recipient=recipient,
                agent_id=agent_id,
                agent_external_id=agent_external_id,
                session_id=session_id,
                attested_identity=attested_identity,
            )
            return decision, None

        parsed = _try_json(inspect_body)
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
            # Plain HTTP egress: fold a bounded slice of the (decoded) body in.
            text = inspect_body[:cap].decode("utf-8", errors="replace") if inspect_body else ""
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
            attested_identity=attested_identity,
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
        surface: Any | None = None,
    ) -> UpstreamResponse:
        surface = self._resolve_surface(
            tenant, agent_id, agent_external_id, surface
        )
        if surface is None:
            return upstream
        body = _try_json(upstream.body)
        if not isinstance(body, dict):
            return upstream
        result = body.get("result")
        if not isinstance(result, dict) or not isinstance(result.get("tools"), list):
            return upstream
        # Gate discovery on the TOOL-NAME allowlist (the dimension a piggyback
        # surface carries), via the SAME compile the emission gate + sealed H use
        # — so discovery, emission, and the seal all agree on one allowlist.
        # (permits_action_type reads allowed_action_types, which the piggyback
        # surface leaves empty -> it would keep every tool, leaking a forbidden
        # tool's existence on the primary http path.) is_tool_allowed returns True
        # when no name allowlist is declared, so an unrestricted surface is a no-op.
        constraint = compile_constraint(surface)
        kept = [
            t
            for t in result["tools"]
            if isinstance(t, dict) and constraint.is_tool_allowed(str(t.get("name", "")))
        ]
        result["tools"] = kept
        new_body = json.dumps(body).encode("utf-8")
        headers = dict(upstream.headers)
        headers["content-length"] = str(len(new_body))
        return UpstreamResponse(status=upstream.status, headers=headers, body=new_body)

    def _resolve_surface(
        self,
        tenant: str,
        agent_id: UUID | None,
        agent_external_id: str | None,
        surface: Any | None = None,
    ) -> Any | None:
        """Resolve the capability surface to confine egress against.

        Precedence: an explicit per-request ``surface`` (piggybacked from the PDP
        decision — race-free, no round-trip) > the in-process governor fast-path >
        an injected ``SurfaceResolver`` (http mode). Returns ``None`` when none can
        supply one, which leaves the gate inert (body unchanged) — exactly today's
        behaviour for a bare http sidecar."""
        if surface is not None:
            return surface
        gov = self._governance
        if gov is not None:
            try:
                agent = gov._resolve_agent(tenant, agent_id, agent_external_id)  # noqa: SLF001
            except Exception:  # noqa: BLE001
                return None
            return (
                getattr(agent, "capability_surface", None)
                if agent is not None
                else None
            )
        resolver = self._surface_resolver
        if resolver is None:
            return None
        try:
            return resolver(tenant, agent_id, agent_external_id)
        except Exception:  # noqa: BLE001 — a resolver fault leaves the gate inert
            _logger.warning("PEP: surface resolver raised", exc_info=True)
            return None

    def _surface_from_decision(self, result: DecisionResult) -> Any | None:
        """Reconstruct a ``CapabilitySurface`` from a decision's piggybacked tool
        subset, or ``None`` when none was carried. The piggyback round-trips the
        TOOL-NAME allowlist ONLY — NOT the full surface (e.g. recipient-domain
        dims are not carried). That is exactly what the emission gate and filtered
        discovery consume here (both read tool names via ``compile_constraint``;
        the actuator never reads recipient regexes), so on the egressed bytes the
        piggyback path is identical to in-process — but it is NOT a full-surface
        equivalent, and a future gate dimension would need to be piggybacked too.
        Race-free: the tool allowlist that confined the PDP ruling is the one that
        tightens egress. Fail-safe: a malformed payload yields None (gate inert)."""
        allowed = getattr(result, "allowed_tools", None)
        if not allowed:
            return None
        try:
            from tex.domain.agent import CapabilitySurface

            return CapabilitySurface(allowed_tools=tuple(allowed))
        except Exception:  # noqa: BLE001 — never let a bad piggyback break the request
            _logger.warning("PEP: piggyback surface reconstruct failed", exc_info=True)
            return None

    # ------------------------------------------------------------------ emission gate

    def _apply_emission_gate(
        self,
        *,
        body: bytes,
        fwd_headers: dict[str, str],
        tenant: str,
        agent_id: UUID | None,
        agent_external_id: str | None,
        decision_id: str | None,
        content_encoding: str | None = None,
        surface: Any | None = None,
    ) -> bytes:
        """Approach B (provider-trusted) emission gate on the outbound request.

        When the body is a recognizable LLM-provider chat request, rewrite it to
        the agent's permitted tool subset off the SAME sealed ``CapabilitySurface``
        :meth:`_filter_tools_list` reads (discovery → **emission** → adjudication),
        reset ``content-length`` to the rewritten size, and optionally seal WHICH
        allowlist ``H`` the turn decoded under. Returns the (possibly rewritten)
        body; on any non-applicable case it returns the body byte-identical.

        The surface is resolved by :meth:`_resolve_surface` (precedence: a
        per-request ``surface`` piggybacked on the PDP decision > an in-process
        governor > an injected ``SurfaceResolver``), so the gate now also fires in
        the http sidecar mode — not only when an in-process governor is wired.

        A ``Content-Encoding``-compressed provider body is DECODED before the
        rewrite and re-egressed UN-compressed (the ``content-encoding`` header is
        dropped so the provider reads the plaintext JSON we tightened), so a
        forbidden tool cannot ride out inside a gzip body. A body Tex cannot
        decode never reaches here as a PERMIT — :meth:`_to_decision` already
        labels it ``http_opaque_body`` and the PDP holds it (ABSTAIN).

        Behaviour on the non-rewrite branches (returns the body byte-identical):
          * Unresolved surface — no governor, no injected resolver, and no
            piggyback on the decision (a bare ``http`` sidecar with the flag off,
            see ``pep/__main__``). Fail-safe: no surface => body unchanged.
          * A body Tex cannot decode (defence-in-depth — should have ABSTAINed
            upstream; we never silently rewrite or forward-blind it here).
          * Body is not a JSON object, or ``detect_provider`` does not recognize
            the dialect -> body unchanged (no silent mis-rewrite). The
            ``isinstance(parsed, dict)`` guard is load-bearing: ``detect_provider``
            and ``rewrite_provider_request`` index the body, so a non-dict
            (``None``/list/scalar) must never reach them. These bodies were
            already ruled on (decoded) by the PDP; the gate only declines to
            REWRITE them, it is not the gate that PERMITted them.
          * ``rewrite_provider_request`` is pure (never mutates ``body``) and only
            ever TIGHTENS — strips a forbidden tool, narrows ``tool_choice`` — so
            the egressed request is always a subset of what the PDP PERMITted.
          * ``seal_constraint`` is fail-closed / observation-only: a ``None``
            ledger is a no-op and a seal failure never changes what egresses.
        """
        surface = self._resolve_surface(
            tenant, agent_id, agent_external_id, surface
        )
        if surface is None:
            return body
        inspect_body, undecodable = _decode_for_inspection(body, content_encoding)
        if undecodable:
            return body
        parsed = _try_json(inspect_body)
        if not isinstance(parsed, dict) or detect_provider(parsed) is None:
            return body
        constraint = compile_constraint(surface)
        new_body = json.dumps(
            rewrite_provider_request(parsed, constraint)
        ).encode("utf-8")
        # content-length was stripped building fwd_headers; set it to the new size
        # (mirrors _filter_tools_list, which resets it on the response side).
        fwd_headers["content-length"] = str(len(new_body))
        # We egress the rewritten body UNCOMPRESSED — drop any content-encoding
        # the agent set (else the provider would try to gunzip plaintext JSON,
        # and a stale gzip header beside un-gzipped bytes is a smuggling seam).
        for key in [k for k in fwd_headers if k.lower() == "content-encoding"]:
            del fwd_headers[key]
        seal_constraint(
            self._seal_ledger,
            constraint,
            subject_id=decision_id or str(uuid4()),
            approach=APPROACH_PROVIDER_TRUSTED,
            agent_id=(str(agent_id) if agent_id is not None else agent_external_id),
        )
        return new_body


# --------------------------------------------------------------------------- #
# Helpers                                                                      #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class _IdentityCheck:
    """Outcome of ``_verify_identity``.

    ``refuse`` set => FORBID immediately. ``attested`` is the verified identity
    (or None on the documented no-credential gap). ``effective_external_id`` is
    a verified id to rule on when the request header carried no principal.
    """

    refuse: UpstreamResponse | None = None
    attested: AttestedIdentity | None = None
    effective_external_id: str | None = None


def _decode_credential(raw: str) -> dict[str, Any] | None:
    """Decode an X-Tex-Agent-Credential header into a signed-card dict.

    Accepts base64url/base64 JSON (the wire-friendly form) or raw JSON. Any
    decode/parse failure returns None (caller FORBIDs)."""
    text = raw.strip()
    # Try the header-safe base64 forms first, then fall back to raw JSON.
    for candidate in (_b64_to_text(text), text):
        if candidate is None:
            continue
        try:
            obj = json.loads(candidate)
        except (ValueError, json.JSONDecodeError):
            continue
        if isinstance(obj, dict):
            return obj
    return None


def _b64_to_text(text: str) -> str | None:
    import base64
    import binascii

    pad = "=" * (-len(text) % 4)
    for decode in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            return decode((text + pad).encode("ascii")).decode("utf-8")
        except (binascii.Error, ValueError, UnicodeDecodeError):
            continue
    return None


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


def _default_host_ips(host: str) -> set[str]:
    """System-DNS resolution of a hostname to its IP set (A + AAAA)."""
    import socket

    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return set()
    return {info[4][0] for info in infos}


def _hostname_only(value: str | None) -> str | None:
    """The bare hostname from a Host header, dropping any ``:port`` and brackets."""
    if not value:
        return None
    host = value.strip()
    if host.startswith("["):  # [::1]:443 -> ::1
        end = host.find("]")
        return (host[1:end] if end != -1 else host[1:]) or None
    if host.count(":") == 1:  # example.com:443 / 10.0.0.5:443 -> drop port
        host = host.split(":", 1)[0]
    return host or None


def _try_json(body: bytes) -> Any:
    if not body:
        return None
    try:
        return json.loads(body.decode("utf-8", errors="replace"))
    except Exception:  # noqa: BLE001
        return None


# Hard ceiling on a decompressed body (decompression-bomb guard). A body that
# inflates past this is treated as UN-decodable rather than expanded in memory.
_DECODE_MAX_BYTES = 64 * 1024 * 1024


def _inflate(data: bytes, wbits: int) -> bytes | None:
    """Bounded zlib/gzip inflate. Returns the decoded bytes, or ``None`` if the
    stream is malformed OR would exceed ``_DECODE_MAX_BYTES`` (bomb guard)."""
    try:
        d = zlib.decompressobj(wbits)
        out = d.decompress(data, _DECODE_MAX_BYTES)
        if d.unconsumed_tail:  # more than the cap would inflate -> treat as bomb
            return None
        out += d.flush()
    except (zlib.error, OSError, ValueError):
        return None
    return out


def _decode_for_inspection(
    body: bytes, content_encoding: str | None
) -> tuple[bytes, bool]:
    """Decode ``body`` per its ``Content-Encoding`` so Tex can inspect what an
    agent is actually sending — the bytes that egress are NOT what Tex can read
    until this runs.

    Returns ``(decoded_bytes, undecodable)``:
      * no encoding / ``identity`` -> ``(body, False)`` (the common case; byte
        for byte unchanged, so plaintext traffic behaves exactly as before).
      * ``gzip``/``x-gzip``/``deflate`` -> the inflated bytes + ``False`` when it
        decodes within the bomb ceiling.
      * an encoding Tex cannot decode (``br``, ``zstd``, ``compress``, unknown),
        a malformed stream, or one that exceeds the ceiling -> ``(b"", True)``.
        An ``undecodable`` body is an UN-inspectable action: the caller must
        treat it like opaque TLS (ABSTAIN / fail-closed), never content-blind
        PERMIT it. Multiple stacked encodings are also undecodable here.
    """
    if not body:
        return body, False
    enc = (content_encoding or "").strip().lower()
    if enc in ("", "identity"):
        return body, False
    if "," in enc:  # stacked encodings (e.g. "gzip, br") — not handled here
        return b"", True
    if enc in ("gzip", "x-gzip"):
        out = _inflate(body, zlib.MAX_WBITS | 16)
        return (out, False) if out is not None else (b"", True)
    if enc == "deflate":
        # "deflate" is ambiguous in the wild: try zlib-wrapped, then raw.
        out = _inflate(body, zlib.MAX_WBITS)
        if out is None:
            out = _inflate(body, -zlib.MAX_WBITS)
        return (out, False) if out is not None else (b"", True)
    return b"", True  # br / zstd / compress / unknown -> uninspectable


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
        # The accepted connection's source ip:port — the key the orig_dst loader
        # maps to the kernel-captured destination (G7). ASGI surfaces it as
        # scope['client']; absent behind some test transports.
        client = request.client
        peer = (client.host, client.port) if client is not None else None
        result = proxy.handle(
            method=request.method,
            path=request.url.path
            + (("?" + request.url.query) if request.url.query else ""),
            headers=dict(request.headers),
            body=body,
            peer=peer,
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

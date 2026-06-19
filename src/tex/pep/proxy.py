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
from dataclasses import dataclass, field
from typing import Any, Protocol
from uuid import UUID, uuid4

from tex.identity.agent_credential import AttestedIdentity, verify_agent_credential
from tex.pep.decision_client import Decision, DecisionClient, DecisionResult

__all__ = [
    "ProxyConfig",
    "Forwarder",
    "HttpxForwarder",
    "ResolvedDst",
    "OrigDstResolver",
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
    # G10 — TTL of a minted egress permit (seconds).
    permit_ttl_seconds: int = 30


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


# --------------------------------------------------------------------------- #
# Kernel-captured destination (G7)                                             #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class ResolvedDst:
    """The true destination the kernel saw for the accepted connection."""

    ip: str
    port: int


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

    The kernel gives an ip:port, not a scheme — derive it from the port (443 ->
    https, else http). The TCP destination is pinned to ``dst.ip``; a downstream
    ``Host`` header can at most select a vhost on that already-authorized server,
    never redirect egress elsewhere.
    """
    scheme = "https" if dst.port == 443 else "http"
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
    ) -> None:
        self._decide = decision_client
        self._forward = forwarder or HttpxForwarder()
        self._config = config or ProxyConfig()
        # Optional in-process governor, only for filtered tool discovery.
        self._governance = governance
        # G7 — kernel-captured destination recovery (None => header fallback).
        self._origdst = origdst
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

        agent_id = _as_uuid(h.get("x-tex-agent-id")) or _as_uuid(
            self._config.default_agent_id
        )
        agent_external_id = h.get("x-tex-agent") or self._config.default_agent_external_id
        tenant = (h.get("x-tex-tenant") or self._config.default_tenant).strip().casefold()
        session_id = h.get("x-tex-session")

        # ---- G6: authenticate identity instead of trusting X-Tex-Agent-Id
        ident = self._verify_identity(
            h, agent_id=agent_id, agent_external_id=agent_external_id
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
        )

        result = self._decide.decide(decision)
        if not result.released:
            return _refuse(result.reason or "Forbidden by Tex.", verdict=result.verdict)

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

        # ---- G10: mint -> persist -> verify(fresh digest, audience) -> consume
        permit_outcome = self._mint_check_consume_permit(
            result=result, decision=decision, recipient=recipient, body=body
        )
        if isinstance(permit_outcome, UpstreamResponse):
            return permit_outcome  # permit verification failed -> FORBID
        if permit_outcome is not None:
            fwd_headers["X-Tex-Permit"] = permit_outcome

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

    # ------------------------------------------------------------------ G6 identity

    def _verify_identity(
        self,
        h: dict[str, str],
        *,
        agent_id: UUID | None,
        agent_external_id: str | None,
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
        """
        cfg = self._config
        principal = str(agent_id) if agent_id is not None else (agent_external_id or None)
        raw = h.get("x-tex-agent-credential")

        if not raw:
            if cfg.require_identity:
                return _IdentityCheck(
                    refuse=_refuse(
                        "No agent credential presented (identity required).",
                        verdict="FORBID",
                    )
                )
            return _IdentityCheck()  # documented gap: proceed, attested=None

        card = _decode_credential(raw)
        if card is None:
            return _IdentityCheck(
                refuse=_refuse("Malformed agent credential.", verdict="FORBID")
            )

        att = verify_agent_credential(card, trusted_issuers=cfg.trusted_issuers or {})
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
        verification = permit.verify(
            minted.token,
            expected_content_digest=fresh_digest,
            expected_audience=recipient,
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

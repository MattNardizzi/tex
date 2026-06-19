"""
The PEP's client to the PDP.

Two modes, one interface (``Decision`` in, ``DecisionResult`` out):

  * InProcessDecisionClient — Tex runs in the same process as the proxy
    (sidecar embedding the runtime). Calls StandingGovernance directly:
    lowest latency, no network hop.

  * HttpDecisionClient — Tex runs as a separate service. POSTs to
    ``/v1/govern/decide``. Fail-closed: any transport/HTTP/parse error is
    treated as "not released."

Both return a normalized ``DecisionResult`` the proxy acts on. The single
field that matters is ``released``. Everything else is provenance.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any
from uuid import UUID

if TYPE_CHECKING:
    from tex.identity.agent_credential import AttestedIdentity

__all__ = [
    "Decision",
    "DecisionResult",
    "DecisionClient",
    "InProcessDecisionClient",
    "HttpDecisionClient",
    "HttpSurfaceClient",
]


@dataclass(frozen=True, slots=True)
class Decision:
    """One action the PEP wants ruled on."""

    tenant: str
    action_type: str
    content: str
    channel: str
    environment: str
    recipient: str | None = None
    agent_id: UUID | None = None
    agent_external_id: str | None = None
    session_id: str | None = None
    # Per-request cryptographically attested identity (G6), when the PEP verified
    # one. Used by SealingDecisionClient to bind THIS decision's receipt to the
    # attested principal; the two decision clients ignore it (the PDP rules on
    # agent_id / agent_external_id). None => no credential verified this request.
    attested_identity: "AttestedIdentity | None" = None


@dataclass(frozen=True, slots=True)
class DecisionResult:
    released: bool
    verdict: str
    reason: str
    tier: str = "unknown"
    held: bool = False
    decision_id: str | None = None
    evidence_hash: str | None = None
    # The agent's permitted tool subset, piggybacked from the PDP decision so a
    # remote PEP can drive its emission gate off the SAME decision (no extra
    # round-trip). None => no tool restriction to apply (the gate leaves the body
    # unchanged). Only ever populated on a released outcome.
    allowed_tools: tuple[str, ...] | None = None
    # Digest of the surface tool allowlist the tightening commits to.
    surface_seal_hash: str | None = None

    @classmethod
    def fail_closed(cls, reason: str) -> "DecisionResult":
        return cls(released=False, verdict="FORBID", reason=reason, tier="fail-closed")


def _as_tool_tuple(value: Any) -> tuple[str, ...] | None:
    """Normalize a piggybacked ``allowed_tools`` field (a JSON list or None) into
    a tuple of strings, or None when absent. Fail-safe: a malformed value (not a
    list) returns None so the emission gate simply leaves the body unchanged."""
    if not isinstance(value, (list, tuple)):
        return None
    return tuple(str(v) for v in value)


class DecisionClient:
    """Interface every decision client satisfies."""

    def decide(self, decision: Decision) -> DecisionResult:  # pragma: no cover
        raise NotImplementedError


class InProcessDecisionClient(DecisionClient):
    """Calls the in-process StandingGovernance PDP."""

    __slots__ = ("_governance",)

    def __init__(self, governance: Any) -> None:
        self._governance = governance

    def decide(self, decision: Decision) -> DecisionResult:
        try:
            outcome = self._governance.decide(
                tenant=decision.tenant,
                action_type=decision.action_type,
                content=decision.content,
                channel=decision.channel,
                environment=decision.environment,
                recipient=decision.recipient,
                agent_id=decision.agent_id,
                agent_external_id=decision.agent_external_id,
                session_id=decision.session_id,
            )
        except Exception as exc:  # noqa: BLE001 — fail closed on any error
            return DecisionResult.fail_closed(f"PDP raised: {type(exc).__name__}")
        return DecisionResult(
            released=bool(getattr(outcome, "released", False)),
            verdict=str(getattr(outcome, "verdict", "FORBID")),
            reason=str(getattr(outcome, "reason", "")),
            tier=str(getattr(outcome, "tier", "unknown")),
            held=bool(getattr(outcome, "held", False)),
            decision_id=(
                str(outcome.decision_id)
                if getattr(outcome, "decision_id", None)
                else None
            ),
            evidence_hash=getattr(outcome, "evidence_hash", None),
            allowed_tools=_as_tool_tuple(getattr(outcome, "allowed_tools", None)),
            surface_seal_hash=getattr(outcome, "surface_seal_hash", None),
        )


class HttpDecisionClient(DecisionClient):
    """POSTs to a remote Tex /v1/govern/decide.

    ``client`` is any object exposing ``.post(url, json=, timeout=, headers=)``
    returning an object with ``.status_code`` and ``.json()`` — httpx.Client or
    requests.Session. The PEP does not import httpx itself.
    """

    __slots__ = ("_client", "_url", "_timeout", "_headers")

    def __init__(
        self,
        *,
        client: Any,
        base_url: str,
        timeout: float = 5.0,
        api_key: str | None = None,
    ) -> None:
        if not hasattr(client, "post"):
            raise TypeError("client must expose .post(url, json=, timeout=, headers=)")
        self._client = client
        self._url = base_url.rstrip("/") + "/v1/govern/decide"
        self._timeout = timeout
        self._headers = {"Content-Type": "application/json"}
        if api_key:
            self._headers["Authorization"] = f"Bearer {api_key}"

    def decide(self, decision: Decision) -> DecisionResult:
        payload = {
            "tenant_id": decision.tenant,
            "action_type": decision.action_type,
            "content": decision.content,
            "channel": decision.channel,
            "environment": decision.environment,
            "recipient": decision.recipient,
            "agent_id": str(decision.agent_id) if decision.agent_id else None,
            "agent_external_id": decision.agent_external_id,
            "session_id": decision.session_id,
        }
        try:
            resp = self._client.post(
                self._url, json=payload, timeout=self._timeout, headers=self._headers
            )
        except Exception as exc:  # noqa: BLE001
            return DecisionResult.fail_closed(f"PDP unreachable: {type(exc).__name__}")
        status = getattr(resp, "status_code", None)
        if status is None or status >= 400:
            return DecisionResult.fail_closed(f"PDP HTTP {status}")
        try:
            body = resp.json()
        except Exception as exc:  # noqa: BLE001
            return DecisionResult.fail_closed(f"PDP parse error: {type(exc).__name__}")
        return DecisionResult(
            released=bool(body.get("released", False)),
            verdict=str(body.get("verdict", "FORBID")),
            reason=str(body.get("reason", "")),
            tier=str(body.get("tier", "unknown")),
            held=bool(body.get("held", False)),
            decision_id=body.get("decision_id"),
            evidence_hash=body.get("evidence_hash"),
            allowed_tools=_as_tool_tuple(body.get("allowed_tools")),
            surface_seal_hash=body.get("surface_seal_hash"),
        )


class HttpSurfaceClient:
    """SECONDARY (opt-in) http-mode surface resolver: fetch an agent's sealed
    ``CapabilitySurface`` from the PDP's ``GET /v1/agents/{agent_id}`` and run
    ``CapabilitySurfaceDTO.to_domain()``.

    This is the fallback to the PRIMARY race-free piggyback (the surface carried
    on the decision the PEP already made). It is OFF by default — wired only when
    a deployment opts in (see ``pep/__main__``) — because it costs an extra
    round-trip and only helps when the decision did not piggyback a surface (e.g.
    a ``tools/list`` filtered-discovery hop, where there is no per-request
    permitted-tool subset to carry).

    Satisfies the ``SurfaceResolver`` protocol: ``(tenant, agent_id,
    agent_external_id) -> CapabilitySurface | None``. Resolves ONLY by stable
    UUID (the surface endpoint is keyed by ``agent_id``); a request with only an
    external id returns ``None`` (the gate then stays inert — fail-safe). A short
    TTL cache bounds the round-trips. Fail-safe throughout: any transport / HTTP /
    parse error returns ``None`` so the emission gate leaves the body unchanged,
    never forwards blind on a fetch failure.
    """

    __slots__ = ("_client", "_base", "_timeout", "_headers", "_ttl", "_cache")

    def __init__(
        self,
        *,
        client: Any,
        base_url: str,
        timeout: float = 5.0,
        api_key: str | None = None,
        ttl_seconds: float = 30.0,
    ) -> None:
        if not hasattr(client, "get"):
            raise TypeError("client must expose .get(url, timeout=, headers=)")
        self._client = client
        self._base = base_url.rstrip("/")
        self._timeout = timeout
        self._headers = {}
        if api_key:
            self._headers["Authorization"] = f"Bearer {api_key}"
        self._ttl = ttl_seconds
        # agent_id (str) -> (expiry_monotonic, surface | None)
        self._cache: dict[str, tuple[float, Any]] = {}

    def __call__(
        self,
        tenant: str,
        agent_id: UUID | None,
        agent_external_id: str | None,
    ) -> Any | None:
        if agent_id is None:
            return None  # endpoint is keyed by UUID; nothing to fetch
        import time as _time

        key = str(agent_id)
        now = _time.monotonic()
        cached = self._cache.get(key)
        if cached is not None and cached[0] > now:
            return cached[1]

        surface = self._fetch(key)
        self._cache[key] = (now + self._ttl, surface)
        return surface

    def _fetch(self, agent_id: str) -> Any | None:
        url = f"{self._base}/v1/agents/{agent_id}"
        try:
            resp = self._client.get(url, timeout=self._timeout, headers=self._headers)
        except Exception:  # noqa: BLE001 — fetch failure leaves the gate inert
            return None
        status = getattr(resp, "status_code", None)
        if status is None or status >= 400:
            return None
        try:
            body = resp.json()
        except Exception:  # noqa: BLE001
            return None
        raw = body.get("capability_surface") if isinstance(body, dict) else None
        if not isinstance(raw, dict):
            return None
        try:
            from tex.api.agent_routes import CapabilitySurfaceDTO

            return CapabilitySurfaceDTO(**raw).to_domain()
        except Exception:  # noqa: BLE001 — a malformed surface leaves the gate inert
            return None

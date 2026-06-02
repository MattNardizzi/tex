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
from typing import Any
from uuid import UUID

__all__ = [
    "Decision",
    "DecisionResult",
    "DecisionClient",
    "InProcessDecisionClient",
    "HttpDecisionClient",
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


@dataclass(frozen=True, slots=True)
class DecisionResult:
    released: bool
    verdict: str
    reason: str
    tier: str = "unknown"
    held: bool = False
    decision_id: str | None = None
    evidence_hash: str | None = None

    @classmethod
    def fail_closed(cls, reason: str) -> "DecisionResult":
        return cls(released=False, verdict="FORBID", reason=reason, tier="fail-closed")


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
        )

"""
Cloud-audit connector — agentless, tamper-resistant discovery.

This is the highest admissibility-per-effort plane: a control-plane audit
log fires *outside the workload's reachability surface*, so the workload
cannot suppress or forge that it acted, and Tex needs no in-process agent
to read it. That combination — tamper-resistant *and* agentless — is the
sweet spot (§4), which is why it is built first.

Modelled on the real AWS CloudTrail shape for Amazon Bedrock AgentCore
(verified June 2026). A Bedrock AgentCore data event looks like:

    {
      "eventSource": "bedrock-agentcore.amazonaws.com",
      "eventName": "InvokeAgentRuntime" | "InvokeGateway" | "InvokeMcp" | ...,
      "eventTime": "2026-...Z",
      "userIdentity": {"type": "...", "principalId": "...", "accountId": "..."},
      "sourceIPAddress": "...",
      "requestParameters": {"runtimeUserId": "...", "sessionId": "..."},
      "resources": [{"type": "AWS::BedrockAgentCore::Runtime", "ARN": "arn:..."}],
      "eventCategory": "Data",
      "tlsDetails": {"tlsVersion": "...", "clientProvidedHostHeader": "..."}
    }

The same connector shape generalizes to Azure Monitor + Entra audit logs
and GCP audit logs: a record with an actor identity, a resource ARN/URI,
a timestamp, and the operation, fired by the platform's own audit plane.
The external_id is the agent runtime/gateway ARN — the platform's stable
identifier for the agent, which the agent itself cannot rewrite in the
audit trail.

Real connector replacement: implement ``_run_scan`` against a CloudTrail
Lake query (or an S3 trail read, or Azure Monitor / GCP Logging), grouping
audit records by ``resources[].ARN`` to one CandidateAgent per agent
runtime. The fields below map directly.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import UTC, datetime
from typing import Any, Iterable

from tex.discovery.connectors.base import BaseConnector, ConnectorContext
from tex.domain.agent import AgentEnvironment
from tex.domain.discovery import (
    CandidateAgent,
    DiscoveredCapabilityHints,
    DiscoveryRiskBand,
    DiscoverySource,
)

# Operations that mean "an agent ran," not just "an agent was configured."
# Data events (an agent acting) are stronger discovery signals than
# management events (someone created a resource).
_INVOCATION_EVENTS = {
    "invokeagentruntime",
    "invokegateway",
    "invokemcp",
    "invokeagent",
    "invokemodel",
    "converse",
}


class CloudAuditConnector(BaseConnector):
    """
    Mock cloud-audit connector.

    Accepts a list of audit records shaped like CloudTrail AgentCore
    events and folds them, per agent ARN, into one CandidateAgent each
    with ``AUDIT_LOG`` admissibility (resolved from the source string by
    ``tex.domain.signal_trust.tier_for_source``).
    """

    def __init__(self, *, records: list[dict[str, Any]] | None = None) -> None:
        super().__init__(source=DiscoverySource.CLOUD_AUDIT, name="cloud_audit_mock")
        self._records = list(records or [])

    def replace_records(self, records: list[dict[str, Any]]) -> None:
        self._records = list(records)

    def _run_scan(self, context: ConnectorContext) -> Iterable[CandidateAgent]:
        # Group raw audit events by the agent resource ARN — the stable
        # platform identifier the workload cannot rewrite in the trail.
        by_arn: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for event in self._records:
            arn = _resource_arn(event)
            if arn is None:
                continue
            by_arn[arn].append(event)

        for arn, events in by_arn.items():
            yield self._build_candidate(arn, events, context)

    def _build_candidate(
        self,
        arn: str,
        events: list[dict[str, Any]],
        context: ConnectorContext,
    ) -> CandidateAgent:
        op_names = [str(e.get("eventName", "")).casefold() for e in events]
        invocations = [n for n in op_names if n in _INVOCATION_EVENTS]
        latest = max(
            (_parse_iso(e.get("eventTime")) for e in events if e.get("eventTime")),
            default=None,
        )
        # Identity touched: principalId across the events (the actor the
        # platform attributes the call to).
        principals = sorted(
            {
                str((e.get("userIdentity") or {}).get("principalId") or "").strip()
                for e in events
            }
            - {""}
        )
        host_headers = sorted(
            {
                str((e.get("tlsDetails") or {}).get("clientProvidedHostHeader") or "")
                for e in events
            }
            - {""}
        )
        tools = sorted(
            {
                _tool_from_event(e)
                for e in events
                if _tool_from_event(e) is not None
            }
        )

        # An agent the audit log proves *acted* is high-confidence; one we
        # only saw configured (management events) is lower.
        acted = bool(invocations)
        confidence = 0.97 if acted else 0.7

        # Risk rises with the breadth of operations and any privileged op.
        distinct_ops = len(set(op_names))
        if distinct_ops >= 4:
            risk = DiscoveryRiskBand.HIGH
        elif distinct_ops >= 2:
            risk = DiscoveryRiskBand.MEDIUM
        else:
            risk = DiscoveryRiskBand.LOW

        capability_hints = DiscoveredCapabilityHints(
            inferred_action_types=tuple(sorted(set(op_names) - {""})),
            inferred_tools=tuple(t for t in tools if t),
            inferred_data_scopes=tuple(),
        )

        evidence = {
            "resource_arn": arn,
            "event_count": len(events),
            "invocation_count": len(invocations),
            "operations": sorted(set(op_names) - {""}),
            "principals": principals,
            "client_host_headers": host_headers,
            "signal": "control_plane_audit_log",
            "tamper_resistant": True,
            "agentless": True,
        }

        return CandidateAgent(
            source=DiscoverySource.CLOUD_AUDIT,
            tenant_id=context.tenant_id,
            external_id=arn,
            name=_name_from_arn(arn),
            owner_hint=principals[0] if principals else None,
            framework_hint=_framework_from_arn(arn),
            environment_hint=AgentEnvironment.PRODUCTION,
            risk_band=risk,
            confidence=confidence,
            capability_hints=capability_hints,
            last_seen_active_at=latest,
            evidence=evidence,
            tags=("cloud_audit", "tamper_resistant", "agentless"),
        )


# --------------------------------------------------------------------------- helpers
def _resource_arn(event: dict[str, Any]) -> str | None:
    resources = event.get("resources")
    if isinstance(resources, list):
        for r in resources:
            if isinstance(r, dict) and r.get("ARN"):
                return str(r["ARN"])
    # Azure/GCP shapes carry the resource id under different keys.
    for key in ("resourceId", "resourceUri", "targetResource"):
        if event.get(key):
            return str(event[key])
    return None


def _tool_from_event(event: dict[str, Any]) -> str | None:
    params = event.get("requestParameters") or {}
    body = params.get("body") if isinstance(params, dict) else None
    if isinstance(body, dict):
        inner = body.get("params")
        if isinstance(inner, dict) and inner.get("name"):
            return str(inner["name"]).casefold()
    return None


def _name_from_arn(arn: str) -> str:
    tail = arn.rsplit("/", 1)[-1] if "/" in arn else arn.rsplit(":", 1)[-1]
    return tail or arn


def _framework_from_arn(arn: str) -> str | None:
    low = arn.casefold()
    if "bedrock-agentcore" in low:
        return "bedrock_agentcore"
    if "bedrock" in low:
        return "bedrock"
    if "azure" in low or "microsoft" in low:
        return "azure"
    if "googleapis" in low or "gcp" in low:
        return "vertex"
    return None


def _parse_iso(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.astimezone(UTC) if value.tzinfo else value.replace(tzinfo=UTC)
    if not isinstance(value, str):
        return None
    try:
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        return datetime.fromisoformat(value).astimezone(UTC)
    except ValueError:
        return None

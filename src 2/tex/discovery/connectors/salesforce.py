"""
Mock connector for Salesforce Agentforce / Einstein AI agents.

Translates the shape of the Salesforce REST API's `/services/data/
v59.0/sobjects/AgentforceAgent` response (and the equivalent for
Einstein bots) into CandidateAgents.

Real connector replacement: implement `_run_scan` against the
Salesforce REST API with a connected app and an OAuth bearer token.
The fields below map directly to the Salesforce object schema.
"""

from __future__ import annotations

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


_HIGH_RISK_SF_PERMS: frozenset[str] = frozenset(
    {
        "modifyalldata",
        "viewalldata",
        "managelusers",
        "apidisable",
        "deleteopportunities",
    }
)


class SalesforceConnector(BaseConnector):
    """
    Mock Salesforce connector.

    Records are dicts shaped like Salesforce's tooling API output:

    - Id: 18-character Salesforce id (becomes external_id)
    - Name
    - OwnerId / OwnerEmail
    - Description
    - Type: 'Agentforce' or 'EinsteinBot'
    - IsActive: bool
    - Permissions: list of profile-permission strings (lowercased)
    - LastModifiedDate: ISO-8601
    - SandboxName: optional; if present we mark environment_hint=SANDBOX
    """

    def __init__(self, *, records: list[dict[str, Any]] | None = None) -> None:
        super().__init__(
            source=DiscoverySource.SALESFORCE,
            name="salesforce_mock",
        )
        self._records = list(records or [])

    def replace_records(self, records: list[dict[str, Any]]) -> None:
        self._records = list(records)

    def _run_scan(self, context: ConnectorContext) -> Iterable[CandidateAgent]:
        for record in self._records:
            yield self._build_candidate(record, context)

    def _build_candidate(
        self,
        record: dict[str, Any],
        context: ConnectorContext,
    ) -> CandidateAgent:
        perms = [
            str(p).casefold() for p in record.get("Permissions", []) if isinstance(p, str)
        ]
        type_value = str(record.get("Type", "agentforce")).casefold()
        is_active = bool(record.get("IsActive", True))
        sandbox_name = record.get("SandboxName")
        last_modified = _parse_iso(record.get("LastModifiedDate"))

        environment = (
            AgentEnvironment.SANDBOX if sandbox_name else AgentEnvironment.PRODUCTION
        )

        # Risk: presence of "modifyalldata" or "viewalldata" is a
        # tenant-wide blast radius. Treat it as critical.
        critical = any(p in {"modifyalldata", "managelusers"} for p in perms)
        high_count = sum(1 for p in perms if p in _HIGH_RISK_SF_PERMS)
        if critical:
            risk_band = DiscoveryRiskBand.CRITICAL
        elif high_count >= 2:
            risk_band = DiscoveryRiskBand.HIGH
        elif high_count == 1:
            risk_band = DiscoveryRiskBand.MEDIUM
        else:
            risk_band = DiscoveryRiskBand.LOW

        # Inferred surface
        inferred_action_types: list[str] = []
        if "send_email" in perms or "sendemail" in perms:
            inferred_action_types.append("send_email")
        if "sendmessage" in perms:
            inferred_action_types.append("send_message")
        if "deleteopportunities" in perms:
            inferred_action_types.append("delete_record")

        capability_hints = DiscoveredCapabilityHints(
            inferred_action_types=tuple(inferred_action_types),
            inferred_channels=tuple(),
            inferred_recipient_domains=tuple(),
            inferred_tools=tuple(perms),
            inferred_mcp_servers=tuple(),
            inferred_data_scopes=tuple(
                p for p in perms if p.startswith("view") or p.startswith("modify")
            ),
            surface_unbounded=critical,
        )

        confidence = 0.92 if is_active else 0.55

        evidence = {
            "type": type_value,
            "permissions": perms,
            "is_active": is_active,
            "sandbox_name": sandbox_name,
            "raw_id": record.get("Id"),
        }

        return CandidateAgent(
            source=DiscoverySource.SALESFORCE,
            tenant_id=context.tenant_id,
            external_id=str(record["Id"]),
            name=str(record.get("Name") or record["Id"]),
            owner_hint=record.get("OwnerEmail") or record.get("OwnerId"),
            description=record.get("Description"),
            model_provider_hint="salesforce",
            framework_hint=type_value,
            environment_hint=environment,
            risk_band=risk_band,
            confidence=confidence,
            capability_hints=capability_hints,
            last_seen_active_at=last_modified,
            evidence=evidence,
            tags=("salesforce", type_value),
        )


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

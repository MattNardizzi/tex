"""
Mock connector for Microsoft 365 / Copilot Studio agents.

This connector models the shape of Microsoft Graph's response for
Copilot Studio agents and OAuth-permissioned applications. It does
not call Microsoft Graph. The real connector is a drop-in
replacement: implement `_run_scan` to call Graph's
`/copilot/declarativeAgents` and `/applications` endpoints, map the
fields below, return the same CandidateAgent shape.

The mock is configured at construction time with a list of
"platform records" (dicts shaped like Graph responses). This is the
testing surface — drop in fixtures, the connector translates them.

What this connector knows how to detect:

- Copilot Studio agents (declarative agents)
- Apps with high-risk Microsoft Graph permission scopes
  (Mail.Send, Files.ReadWrite.All, Sites.FullControl.All)
- Whether the agent has been granted tenant-wide or user-scope access

The risk-band scoring captures the scope: tenant-wide writes go to
HIGH; user-scope reads stay LOW. This is information Tex's
evaluation layer cannot recover at runtime — by the time an action
fires, the OAuth scope has already been granted. Discovery is the
only place to catch it.
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


# OAuth scopes considered high-risk because they grant write access at
# tenant scope. The list is conservative; operators can extend it.
_HIGH_RISK_SCOPES: frozenset[str] = frozenset(
    {
        "mail.send",
        "mail.readwrite",
        "files.readwrite.all",
        "sites.fullcontrol.all",
        "user.readwrite.all",
        "directory.readwrite.all",
        "application.readwrite.all",
    }
)

_CRITICAL_SCOPES: frozenset[str] = frozenset(
    {
        "directory.readwrite.all",
        "application.readwrite.all",
        "rolemanagement.readwrite.directory",
    }
)


class MicrosoftGraphConnector(BaseConnector):
    """
    Mock connector for Microsoft 365 Copilot Studio + permissioned apps.

    Constructor takes a list of platform records that look like the
    JSON Microsoft Graph would return. The connector translates each
    record into one CandidateAgent.

    Each record is a dict with keys:

    - id: the Microsoft object id (becomes external_id)
    - displayName: human-readable name
    - owner: UPN of the owner (becomes owner_hint)
    - description: optional
    - kind: 'declarativeAgent' or 'application'
    - scopes: list of OAuth scopes (lowercased)
    - tenantId: the Microsoft tenant id (engine still gates on
                ConnectorContext.tenant_id)
    - lastSignInDateTime: optional ISO-8601 string
    - resourcePermissions: optional list of dicts representing
                           granted Mail/Files permissions
    """

    def __init__(self, *, records: list[dict[str, Any]] | None = None) -> None:
        super().__init__(
            source=DiscoverySource.MICROSOFT_GRAPH,
            name="microsoft_graph_mock",
        )
        self._records = list(records or [])

    def replace_records(self, records: list[dict[str, Any]]) -> None:
        """Hot-swap the underlying fixture list. Useful for tests."""
        self._records = list(records)

    def _run_scan(self, context: ConnectorContext) -> Iterable[CandidateAgent]:
        for record in self._records:
            yield self._build_candidate(record, context)

    def _build_candidate(
        self,
        record: dict[str, Any],
        context: ConnectorContext,
    ) -> CandidateAgent:
        scopes = [s.casefold() for s in record.get("scopes", []) if isinstance(s, str)]
        kind = str(record.get("kind", "application")).casefold()
        last_seen = _parse_iso_datetime(record.get("lastSignInDateTime"))

        # Risk band: anything with a critical scope is CRITICAL,
        # otherwise count high-risk scopes; a declarativeAgent (Copilot
        # Studio bot) without explicit scope info is MEDIUM by default.
        critical_hits = sum(1 for s in scopes if s in _CRITICAL_SCOPES)
        high_hits = sum(1 for s in scopes if s in _HIGH_RISK_SCOPES)
        if critical_hits > 0:
            risk_band = DiscoveryRiskBand.CRITICAL
        elif high_hits >= 2:
            risk_band = DiscoveryRiskBand.HIGH
        elif high_hits == 1:
            risk_band = DiscoveryRiskBand.MEDIUM
        else:
            risk_band = DiscoveryRiskBand.LOW

        # Inferred surface from scopes
        inferred_action_types: list[str] = []
        inferred_channels: list[str] = []
        if any(s.startswith("mail.") for s in scopes):
            inferred_channels.append("email")
            if "mail.send" in scopes or "mail.readwrite" in scopes:
                inferred_action_types.append("send_email")
        if any(s.startswith("files.") for s in scopes):
            inferred_channels.append("files")
            inferred_action_types.append("upload_file")
        if any(s.startswith("chatmessage.") for s in scopes):
            inferred_channels.append("teams")
            inferred_action_types.append("send_message")

        surface_unbounded = any(
            s in {"directory.readwrite.all", "application.readwrite.all"}
            for s in scopes
        )

        capability_hints = DiscoveredCapabilityHints(
            inferred_action_types=tuple(inferred_action_types),
            inferred_channels=tuple(inferred_channels),
            inferred_recipient_domains=tuple(),
            inferred_tools=tuple(scopes),
            inferred_mcp_servers=tuple(),
            inferred_data_scopes=tuple(),
            surface_unbounded=surface_unbounded,
        )

        confidence = 0.95 if kind == "declarativeagent" else 0.85

        evidence = {
            "kind": kind,
            "scopes": scopes,
            "tenant_record_id": record.get("tenantId"),
            "raw_id": record.get("id"),
        }

        return CandidateAgent(
            source=DiscoverySource.MICROSOFT_GRAPH,
            tenant_id=context.tenant_id,
            external_id=str(record["id"]),
            name=str(record.get("displayName") or record["id"]),
            owner_hint=record.get("owner"),
            description=record.get("description"),
            model_provider_hint="microsoft",
            framework_hint="copilot_studio" if kind == "declarativeagent" else "azure_app",
            environment_hint=AgentEnvironment.PRODUCTION,
            risk_band=risk_band,
            confidence=confidence,
            capability_hints=capability_hints,
            last_seen_active_at=last_seen,
            evidence=evidence,
            tags=("microsoft", "copilot") if kind == "declarativeagent" else ("microsoft",),
        )


def _parse_iso_datetime(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)
    if not isinstance(value, str):
        return None
    try:
        # Python 3.11+ accepts trailing 'Z'
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        return datetime.fromisoformat(value).astimezone(UTC)
    except ValueError:
        return None

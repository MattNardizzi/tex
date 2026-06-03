"""
Mock connector for MCP servers and the agents that connect to them.

The Model Context Protocol is the connective tissue between agents
and tools. A live MCP server discovery probe would speak the MCP
discovery handshake (`initialize` / `tools/list` / `resources/list`)
and translate the result into one CandidateAgent per registered
client identity. This mock encodes the shape of that handshake
output so the rest of the discovery pipeline can be exercised.

Why MCP discovery matters: an MCP-aware coding agent (Cursor, Claude
Desktop, Cline) shows up here as a candidate even if it never
appears in any of the SaaS-platform connectors. Endpoint coding
agents are the most common shadow AI in modern engineering orgs and
the discovery story has to cover them.
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


class MCPServerConnector(BaseConnector):
    """
    Mock MCP discovery connector.

    Records shaped like the output of a tenant-wide MCP server
    inventory (one per server, each with a `clients` list of
    connected agent identities):

    - server_name: e.g. 'tex-mcp', 'github-mcp'
    - server_url: where the server lives
    - environment: 'production' / 'staging' / 'sandbox'
    - clients: list of dicts, each:
        - client_id
        - client_name
        - client_version
        - tool_names: list of tools the client has called
        - resource_uris: list of resource URIs the client has read
        - last_seen_at: ISO-8601
        - host_kind: 'cursor' / 'claude_desktop' / 'cline' / 'custom'
    """

    def __init__(self, *, records: list[dict[str, Any]] | None = None) -> None:
        super().__init__(
            source=DiscoverySource.MCP_SERVER,
            name="mcp_server_mock",
        )
        self._records = list(records or [])

    def replace_records(self, records: list[dict[str, Any]]) -> None:
        self._records = list(records)

    def _run_scan(self, context: ConnectorContext) -> Iterable[CandidateAgent]:
        for record in self._records:
            yield from self._expand(record, context)

    def _expand(
        self,
        server_record: dict[str, Any],
        context: ConnectorContext,
    ) -> Iterable[CandidateAgent]:
        server_name = str(server_record.get("server_name", "unknown_mcp_server"))
        server_url = str(server_record.get("server_url", ""))
        env_tag = str(server_record.get("environment", "production")).casefold()
        environment = {
            "production": AgentEnvironment.PRODUCTION,
            "prod": AgentEnvironment.PRODUCTION,
            "staging": AgentEnvironment.STAGING,
            "stage": AgentEnvironment.STAGING,
            "sandbox": AgentEnvironment.SANDBOX,
            "dev": AgentEnvironment.SANDBOX,
        }.get(env_tag, AgentEnvironment.PRODUCTION)

        clients = list(server_record.get("clients", []) or [])
        for client in clients:
            yield self._build_candidate(
                server_name=server_name,
                server_url=server_url,
                environment=environment,
                client=client,
                context=context,
            )

    def _build_candidate(
        self,
        *,
        server_name: str,
        server_url: str,
        environment: AgentEnvironment,
        client: dict[str, Any],
        context: ConnectorContext,
    ) -> CandidateAgent:
        client_id = str(client.get("client_id") or client.get("client_name") or "unknown")
        client_name = str(client.get("client_name") or client_id)
        host_kind = str(client.get("host_kind", "custom")).casefold()
        tool_names = [
            str(t).casefold() for t in client.get("tool_names", []) or [] if isinstance(t, str)
        ]
        resource_uris = [
            str(r) for r in client.get("resource_uris", []) or [] if isinstance(r, str)
        ]
        last_seen = _parse_iso(client.get("last_seen_at"))

        # Risk: many tool-name calls + resource access on a non-prod
        # host means an aggressive coding agent. Specifically a
        # 'cursor' or 'claude_desktop' host calling write-shaped tools
        # is HIGH; CRITICAL if the tool surface is arbitrary.
        write_calls = sum(
            1
            for t in tool_names
            if any(h in t for h in ("write", "send", "deploy", "exec"))
        )
        if write_calls >= 3:
            risk_band = DiscoveryRiskBand.CRITICAL
        elif write_calls >= 1:
            risk_band = DiscoveryRiskBand.HIGH
        elif len(tool_names) >= 5:
            risk_band = DiscoveryRiskBand.MEDIUM
        else:
            risk_band = DiscoveryRiskBand.LOW

        capability_hints = DiscoveredCapabilityHints(
            inferred_action_types=tuple(),
            inferred_channels=tuple(),
            inferred_recipient_domains=tuple(),
            inferred_tools=tuple(sorted(set(tool_names))),
            inferred_mcp_servers=(server_name,),
            inferred_data_scopes=tuple(sorted(set(resource_uris))),
            surface_unbounded=False,
        )

        evidence = {
            "server_name": server_name,
            "server_url": server_url,
            "host_kind": host_kind,
            "client_version": client.get("client_version"),
            "tool_names": tool_names,
            "resource_uris": resource_uris,
            "raw_client_id": client.get("client_id"),
        }

        return CandidateAgent(
            source=DiscoverySource.MCP_SERVER,
            tenant_id=context.tenant_id,
            external_id=f"{server_name}:{client_id}",
            name=f"{client_name} via {server_name}",
            owner_hint=client.get("owner"),
            description=f"MCP client {client_name} ({host_kind}) on server {server_name}",
            model_provider_hint=None,
            framework_hint=host_kind,
            environment_hint=environment,
            risk_band=risk_band,
            confidence=0.88,
            capability_hints=capability_hints,
            last_seen_active_at=last_seen,
            evidence=evidence,
            tags=("mcp", host_kind),
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

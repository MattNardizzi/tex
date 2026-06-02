"""
Mock connector for OpenAI Assistants / Custom GPTs / Agents.

Models the shape of OpenAI's `/v1/assistants` API output (and the
parallel ChatGPT Enterprise admin API for custom GPTs). Real
connector replacement: implement `_run_scan` against
`client.beta.assistants.list()` plus the admin API for tenant-scoped
discovery.
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


_DANGEROUS_TOOL_TYPES: frozenset[str] = frozenset(
    {"code_interpreter", "function", "retrieval", "file_search", "web_search"}
)


class OpenAIConnector(BaseConnector):
    """
    Mock OpenAI assistants connector.

    Records shaped like assistant objects:

    - id: 'asst_...'
    - name
    - description
    - model: 'gpt-4o', etc.
    - tools: list of dicts; each has 'type' and optional 'function.name'
    - file_ids: list of attached file ids
    - created_at: epoch seconds
    - metadata: dict
    - org_id / project_id: scope
    """

    def __init__(self, *, records: list[dict[str, Any]] | None = None) -> None:
        super().__init__(
            source=DiscoverySource.OPENAI,
            name="openai_mock",
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
        tools: list[dict[str, Any]] = list(record.get("tools", []) or [])
        tool_types: list[str] = []
        function_names: list[str] = []
        for tool in tools:
            t_type = str(tool.get("type", "")).casefold()
            if t_type:
                tool_types.append(t_type)
            if t_type == "function":
                fn = tool.get("function", {}) or {}
                fn_name = fn.get("name")
                if isinstance(fn_name, str):
                    function_names.append(fn_name.casefold())

        file_ids = [
            str(f) for f in record.get("file_ids", []) or [] if isinstance(f, str)
        ]

        # Risk: function-calling assistants can call arbitrary tools;
        # presence of a `code_interpreter` tool means it can execute
        # code; combine both → CRITICAL. A read-only file_search-only
        # assistant is LOW.
        has_code_interp = "code_interpreter" in tool_types
        has_functions = "function" in tool_types
        unique_dangerous = {t for t in tool_types if t in _DANGEROUS_TOOL_TYPES}

        if has_code_interp and has_functions:
            risk_band = DiscoveryRiskBand.CRITICAL
        elif has_code_interp:
            risk_band = DiscoveryRiskBand.HIGH
        elif len(unique_dangerous) >= 2:
            risk_band = DiscoveryRiskBand.MEDIUM
        else:
            risk_band = DiscoveryRiskBand.LOW

        capability_hints = DiscoveredCapabilityHints(
            inferred_action_types=tuple(function_names),
            inferred_channels=tuple(),
            inferred_recipient_domains=tuple(),
            inferred_tools=tuple(sorted(set(tool_types) | set(function_names))),
            inferred_mcp_servers=tuple(),
            inferred_data_scopes=tuple(file_ids),
            surface_unbounded=has_code_interp and has_functions,
        )

        created_dt = _epoch_to_dt(record.get("created_at"))

        evidence = {
            "model": record.get("model"),
            "tool_types": tool_types,
            "function_names": function_names,
            "file_ids": file_ids,
            "metadata": record.get("metadata", {}),
            "raw_id": record.get("id"),
        }

        confidence = 0.93
        owner_hint = (record.get("metadata") or {}).get("owner")

        return CandidateAgent(
            source=DiscoverySource.OPENAI,
            tenant_id=context.tenant_id,
            external_id=str(record["id"]),
            name=str(record.get("name") or record["id"]),
            owner_hint=owner_hint,
            description=record.get("description"),
            model_provider_hint="openai",
            model_name_hint=record.get("model"),
            framework_hint="openai_assistants",
            environment_hint=AgentEnvironment.PRODUCTION,
            risk_band=risk_band,
            confidence=confidence,
            capability_hints=capability_hints,
            last_seen_active_at=created_dt,
            evidence=evidence,
            tags=("openai", "assistants"),
        )


def _epoch_to_dt(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.astimezone(UTC) if value.tzinfo else value.replace(tzinfo=UTC)
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(value, tz=UTC)
        except (OSError, ValueError):
            return None
    return None

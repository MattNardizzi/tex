"""
Mock connector for AWS Bedrock agents and knowledge bases.

Models the shape of Bedrock's `ListAgents` + `GetAgent` API output.
Real connector replacement: implement `_run_scan` against
`bedrock-agent` boto3 client. The fields below map directly.
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


class AwsBedrockConnector(BaseConnector):
    """
    Mock AWS Bedrock connector.

    Records shaped like Bedrock agent metadata:

    - agentId
    - agentName
    - foundationModel: e.g. 'anthropic.claude-3-7-sonnet-20250219-v1:0'
    - actionGroups: list of action group names (each represents a tool)
    - knowledgeBases: list of KB ids
    - status: 'PREPARED' / 'NOT_PREPARED' / 'CREATING' / 'FAILED'
    - createdAt / updatedAt
    - environmentTag: optional tag string ('prod', 'staging', 'dev')
    - iamRoleArn: arn of the execution role
    - hasOpenScopedRole: bool — operator-supplied; if True, the role
      is overprovisioned (e.g. * on s3:*). The connector cannot
      compute this from boto3 alone in a real deployment, but a
      well-instrumented one will because IAM analysis is critical.
    """

    def __init__(self, *, records: list[dict[str, Any]] | None = None) -> None:
        super().__init__(
            source=DiscoverySource.AWS_BEDROCK,
            name="aws_bedrock_mock",
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
        action_groups = [
            str(g).casefold() for g in record.get("actionGroups", []) if isinstance(g, str)
        ]
        knowledge_bases = [
            str(k) for k in record.get("knowledgeBases", []) if isinstance(k, str)
        ]
        status = str(record.get("status", "PREPARED")).upper()
        env_tag = str(record.get("environmentTag", "prod")).casefold()
        has_open_role = bool(record.get("hasOpenScopedRole", False))
        created = _parse_iso(record.get("createdAt"))
        updated = _parse_iso(record.get("updatedAt")) or created

        environment = {
            "prod": AgentEnvironment.PRODUCTION,
            "production": AgentEnvironment.PRODUCTION,
            "staging": AgentEnvironment.STAGING,
            "stage": AgentEnvironment.STAGING,
            "dev": AgentEnvironment.SANDBOX,
            "sandbox": AgentEnvironment.SANDBOX,
        }.get(env_tag, AgentEnvironment.PRODUCTION)

        if has_open_role:
            risk_band = DiscoveryRiskBand.CRITICAL
        elif len(action_groups) >= 4:
            risk_band = DiscoveryRiskBand.HIGH
        elif len(action_groups) >= 2:
            risk_band = DiscoveryRiskBand.MEDIUM
        else:
            risk_band = DiscoveryRiskBand.LOW

        capability_hints = DiscoveredCapabilityHints(
            inferred_action_types=tuple(action_groups),
            inferred_channels=tuple(),
            inferred_recipient_domains=tuple(),
            inferred_tools=tuple(action_groups),
            inferred_mcp_servers=tuple(),
            inferred_data_scopes=tuple(knowledge_bases),
            surface_unbounded=has_open_role,
        )

        confidence = 0.95 if status == "PREPARED" else 0.55

        evidence = {
            "foundation_model": record.get("foundationModel"),
            "action_groups": action_groups,
            "knowledge_bases": knowledge_bases,
            "status": status,
            "iam_role_arn": record.get("iamRoleArn"),
            "has_open_scoped_role": has_open_role,
            "raw_id": record.get("agentId"),
        }

        return CandidateAgent(
            source=DiscoverySource.AWS_BEDROCK,
            tenant_id=context.tenant_id,
            external_id=str(record["agentId"]),
            name=str(record.get("agentName") or record["agentId"]),
            owner_hint=record.get("owner"),
            description=record.get("description"),
            model_provider_hint=_provider_from_foundation_model(
                record.get("foundationModel")
            ),
            model_name_hint=record.get("foundationModel"),
            framework_hint="bedrock_agent",
            environment_hint=environment,
            risk_band=risk_band,
            confidence=confidence,
            capability_hints=capability_hints,
            last_seen_active_at=updated,
            evidence=evidence,
            tags=("aws", "bedrock"),
        )


def _provider_from_foundation_model(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    head = value.split(".", 1)[0].casefold()
    return head or None


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

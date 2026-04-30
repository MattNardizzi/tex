"""
Mock connector for Slack workspaces.

Models the shape of Slack's Web API output (`apps.list`, `users.list`
filtered to bots, `bots.info`). Real connector replacement: implement
``_run_scan`` against
``https://slack.com/api/users.list`` (then ``bots.info`` for each
``is_bot=true`` user) plus ``apps.list`` for installed apps with bot
scopes.

This is the *mock* surface — record dictionaries shaped like the Slack
API response are passed in via ``records=`` for tests and fixtures. A
live connector that calls the real Slack API ships separately as
``SlackLiveConnector`` in ``tex.discovery.connectors.slack_live`` so
the test suite never accidentally reaches the network.

Slack discovery is the highest-signal cheap win for buyer-side
visibility: every business-line AI agent that anyone has wired into
Slack shows up in this list, including agents the security team
didn't know about. That includes Workflow Builder bots, vendor apps
(Notion, ChatGPT, Gemini, Asana AI), and homegrown bots authored on
the Bolt SDK.
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


# Slack OAuth scopes that grant the bot the ability to write or send
# data outward. Presence of any of these elevates the risk band — they
# correspond to the "external communication / data write" branches of
# the V1 hardcoded risk rules.
_WRITE_SCOPES: frozenset[str] = frozenset(
    {
        "chat:write",
        "chat:write.public",
        "chat:write.customize",
        "files:write",
        "im:write",
        "mpim:write",
        "groups:write",
        "channels:manage",
        "users:write",
        "admin",
        "admin.users:write",
        "admin.conversations:write",
    }
)

# Scopes that grant the bot read access to sensitive content. Combined
# with a write scope, this gives a bot enough authority to exfiltrate
# data, which is the risk pattern Tex's discovery layer is designed to
# surface.
_SENSITIVE_READ_SCOPES: frozenset[str] = frozenset(
    {
        "channels:history",
        "groups:history",
        "im:history",
        "mpim:history",
        "files:read",
        "users:read.email",
        "admin.users:read",
        "search:read",
    }
)


class SlackConnector(BaseConnector):
    """
    Mock Slack workspace connector.

    Records shaped like Slack ``users.list`` + ``bots.info`` responses.
    The connector consumes a list of records and produces one
    ``CandidateAgent`` per record:

    - id: ``B...`` for bots, ``U...`` for users (only ``is_bot=true``
      users yield a candidate)
    - name / real_name
    - app_id: the Slack app this bot belongs to (if any)
    - scopes: list of OAuth scopes the bot has been granted
    - team_id: the Slack workspace ID, used as the tenant
    - is_workflow_bot: True for Workflow Builder bots
    - updated: epoch seconds, last config change
    - metadata: dict, free-form

    A real connector would normalize the same shape from the Slack
    Web API; the rest of the discovery pipeline does not change.
    """

    def __init__(self, *, records: list[dict[str, Any]] | None = None) -> None:
        super().__init__(
            source=DiscoverySource.SLACK,
            name="slack_mock",
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
        scopes_raw = record.get("scopes", []) or []
        scopes = tuple(
            sorted(
                {str(s).strip().casefold() for s in scopes_raw if isinstance(s, str)}
            )
        )

        write_scopes = {s for s in scopes if s in _WRITE_SCOPES}
        sensitive_read_scopes = {s for s in scopes if s in _SENSITIVE_READ_SCOPES}
        admin_scopes = {s for s in scopes if s.startswith("admin")}

        # Risk model:
        # CRITICAL — admin scope (workspace-wide write authority)
        # HIGH     — write + sensitive read (exfiltration capability)
        # MEDIUM   — write only (can post but not read history)
        # LOW      — read-only or no scopes recorded
        if admin_scopes:
            risk_band = DiscoveryRiskBand.CRITICAL
        elif write_scopes and sensitive_read_scopes:
            risk_band = DiscoveryRiskBand.HIGH
        elif write_scopes:
            risk_band = DiscoveryRiskBand.MEDIUM
        else:
            risk_band = DiscoveryRiskBand.LOW

        # Workflow Builder bots are agents in the V1 sense: they fire
        # on a trigger and execute a workflow without a human in the
        # loop. Even with no scopes they count as agents.
        is_workflow_bot = bool(record.get("is_workflow_bot", False))

        capability_hints = DiscoveredCapabilityHints(
            inferred_action_types=("send_message",) if write_scopes else tuple(),
            inferred_channels=("slack",),
            inferred_recipient_domains=tuple(),
            inferred_tools=scopes,
            inferred_mcp_servers=tuple(),
            inferred_data_scopes=tuple(sorted(sensitive_read_scopes)),
            # An admin-scoped Slack bot can do anything in the workspace;
            # treat that as an unbounded surface and let the
            # reconciliation engine hold it for operator review.
            surface_unbounded=bool(admin_scopes),
        )

        updated_dt = _epoch_to_dt(record.get("updated"))

        evidence = {
            "scopes": list(scopes),
            "app_id": record.get("app_id"),
            "team_id": record.get("team_id"),
            "is_workflow_bot": is_workflow_bot,
            "metadata": record.get("metadata", {}),
            "raw_id": record.get("id"),
        }

        # Confidence: workflow bots and apps with declared scopes are
        # high-confidence; bots with no scope info (legacy bot users)
        # are slightly lower because we don't know what they can do.
        confidence = 0.92 if scopes or is_workflow_bot else 0.78

        owner_hint = (record.get("metadata") or {}).get("owner")
        framework = "slack_workflow_builder" if is_workflow_bot else "slack_bot"

        tags: tuple[str, ...] = ("slack", framework)
        if admin_scopes:
            tags = tags + ("admin_scope",)

        return CandidateAgent(
            source=DiscoverySource.SLACK,
            tenant_id=context.tenant_id,
            external_id=str(record["id"]),
            name=str(
                record.get("real_name")
                or record.get("name")
                or record["id"]
            ),
            owner_hint=owner_hint,
            description=record.get("description"),
            model_provider_hint=None,
            model_name_hint=None,
            framework_hint=framework,
            environment_hint=AgentEnvironment.PRODUCTION,
            risk_band=risk_band,
            confidence=confidence,
            capability_hints=capability_hints,
            last_seen_active_at=updated_dt,
            evidence=evidence,
            tags=tags,
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

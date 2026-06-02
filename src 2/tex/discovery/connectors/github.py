"""
Mock connector for GitHub Copilot installations and AI-bot apps.

Models the shape of the GitHub `/orgs/{org}/copilot/billing/seats`
and `/orgs/{org}/installations` API outputs. Real connector
replacement: implement `_run_scan` against the GitHub REST API with
a GitHub App or a fine-grained PAT scoped to the org.
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


class GitHubConnector(BaseConnector):
    """
    Mock GitHub connector.

    Two record kinds, distinguished by the `kind` field:

    `copilot_seat`:
        - id: numeric seat id
        - assignee_login: username
        - assignee_email: optional
        - org: org slug
        - last_activity_at: ISO-8601
        - plan: 'business' / 'enterprise' / 'individual'

    `app_installation`:
        - id: numeric installation id
        - app_slug: e.g. 'copilot-chat' or a third-party AI bot
        - target: 'organization' / 'repository'
        - permissions: dict of permission -> 'read' / 'write' / 'admin'
        - events: list of subscribed webhook events
        - suspended_at: optional ISO-8601 (None if active)
    """

    _DANGEROUS_PERMISSIONS: frozenset[str] = frozenset(
        {"contents", "pull_requests", "secrets", "actions", "administration"}
    )

    def __init__(self, *, records: list[dict[str, Any]] | None = None) -> None:
        super().__init__(
            source=DiscoverySource.GITHUB,
            name="github_mock",
        )
        self._records = list(records or [])

    def replace_records(self, records: list[dict[str, Any]]) -> None:
        self._records = list(records)

    def _run_scan(self, context: ConnectorContext) -> Iterable[CandidateAgent]:
        for record in self._records:
            yield self._dispatch(record, context)

    def _dispatch(
        self,
        record: dict[str, Any],
        context: ConnectorContext,
    ) -> CandidateAgent:
        kind = str(record.get("kind", "app_installation")).casefold()
        if kind == "copilot_seat":
            return self._copilot_seat(record, context)
        return self._app_installation(record, context)

    def _copilot_seat(
        self,
        record: dict[str, Any],
        context: ConnectorContext,
    ) -> CandidateAgent:
        assignee_login = str(record.get("assignee_login", "unknown"))
        seat_id = str(record.get("id", assignee_login))
        plan = str(record.get("plan", "business")).casefold()
        last_activity = _parse_iso(record.get("last_activity_at"))

        # A Copilot seat is a coding agent — a developer using AI
        # assistance. It is low-risk by default but the seat itself
        # represents an AI agent acting on a real human's behalf.
        capability_hints = DiscoveredCapabilityHints(
            inferred_action_types=("code_suggestion", "code_completion"),
            inferred_channels=("ide",),
            inferred_recipient_domains=tuple(),
            inferred_tools=("github_copilot",),
            inferred_mcp_servers=tuple(),
            inferred_data_scopes=tuple(),
            surface_unbounded=False,
        )

        evidence = {
            "kind": "copilot_seat",
            "plan": plan,
            "assignee_login": assignee_login,
            "assignee_email": record.get("assignee_email"),
            "org": record.get("org"),
        }

        return CandidateAgent(
            source=DiscoverySource.GITHUB,
            tenant_id=context.tenant_id,
            external_id=f"copilot-seat-{seat_id}",
            name=f"GitHub Copilot ({assignee_login})",
            owner_hint=record.get("assignee_email") or assignee_login,
            description=f"Copilot {plan} seat assigned to {assignee_login}",
            model_provider_hint="github",
            model_name_hint=None,
            framework_hint="github_copilot",
            environment_hint=AgentEnvironment.PRODUCTION,
            risk_band=DiscoveryRiskBand.LOW,
            confidence=0.92,
            capability_hints=capability_hints,
            last_seen_active_at=last_activity,
            evidence=evidence,
            tags=("github", "copilot", "coding_agent"),
        )

    def _app_installation(
        self,
        record: dict[str, Any],
        context: ConnectorContext,
    ) -> CandidateAgent:
        app_slug = str(record.get("app_slug", "unknown-app"))
        permissions: dict[str, str] = record.get("permissions", {}) or {}
        events: list[str] = list(record.get("events", []) or [])
        target = str(record.get("target", "organization")).casefold()
        suspended_at = record.get("suspended_at")

        # Risk: any "write" or "admin" on a dangerous permission key
        # is High; "admin" on administration or secrets is Critical.
        critical = False
        high = 0
        for perm, level in permissions.items():
            level_norm = str(level).casefold()
            perm_norm = str(perm).casefold()
            if perm_norm in {"administration", "secrets"} and level_norm == "admin":
                critical = True
            elif (
                perm_norm in self._DANGEROUS_PERMISSIONS
                and level_norm in {"write", "admin"}
            ):
                high += 1

        if critical:
            risk_band = DiscoveryRiskBand.CRITICAL
        elif high >= 2:
            risk_band = DiscoveryRiskBand.HIGH
        elif high == 1:
            risk_band = DiscoveryRiskBand.MEDIUM
        else:
            risk_band = DiscoveryRiskBand.LOW

        capability_hints = DiscoveredCapabilityHints(
            inferred_action_types=tuple(),
            inferred_channels=tuple(),
            inferred_recipient_domains=tuple(),
            inferred_tools=tuple(sorted(permissions.keys())),
            inferred_mcp_servers=tuple(),
            inferred_data_scopes=tuple(sorted(events)),
            surface_unbounded=critical,
        )

        evidence = {
            "kind": "app_installation",
            "app_slug": app_slug,
            "target": target,
            "permissions": permissions,
            "events": events,
            "suspended_at": suspended_at,
            "raw_id": record.get("id"),
        }

        confidence = 0.55 if suspended_at else 0.9

        return CandidateAgent(
            source=DiscoverySource.GITHUB,
            tenant_id=context.tenant_id,
            external_id=f"app-installation-{record.get('id', app_slug)}",
            name=f"GitHub App: {app_slug}",
            owner_hint=record.get("installer_login"),
            description=f"GitHub App {app_slug} installed on {target}",
            model_provider_hint="github",
            framework_hint="github_app",
            environment_hint=AgentEnvironment.PRODUCTION,
            risk_band=risk_band,
            confidence=confidence,
            capability_hints=capability_hints,
            last_seen_active_at=_parse_iso(record.get("updated_at")),
            evidence=evidence,
            tags=("github", "app"),
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

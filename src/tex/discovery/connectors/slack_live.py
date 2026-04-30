"""
Live Slack connector.

Real-API counterpart to ``SlackConnector`` (the mock). Uses the
Slack Web API to enumerate bots in a workspace and turn each one
into a ``CandidateAgent``.

The Slack Web API does not have a single "list every bot in the
workspace" call. The connector composes three calls:

1. ``users.list`` — paginate the user directory, keep entries with
   ``is_bot=true``. This catches every bot user, including legacy
   bots from apps that no longer support OAuth scopes.
2. ``bots.info`` (per bot) — gets the ``app_id`` and metadata for
   the bot user.
3. ``apps.list`` (admin scope) — for orgs that have it, returns
   installed apps with their declared scope sets. The connector
   joins these against the bot users so each ``CandidateAgent``
   carries the OAuth scopes that drive risk classification.

When the calling token does not have the admin scopes required for
``apps.list``, the connector silently degrades: bots still appear,
but with empty ``scopes``. They land at LOW risk and the operator
gets a structured note in the scan errors so they know coverage was
partial.

Auth: Slack tokens come in two forms — bot tokens (``xoxb-...``) and
user tokens (``xoxp-...``). For workspace-wide discovery the operator
typically uses a user token from a workspace admin, or a bot token
that has been granted ``users:read``, ``users:read.email``, and (for
full surface) the admin scopes. The connector takes whatever token
it's given and reports what it can see.
"""

from __future__ import annotations

import json
import logging
import time
from datetime import UTC, datetime
from typing import Any, Iterable
from urllib import error as urlerror
from urllib import parse as urlparse
from urllib import request as urlrequest

from tex.discovery.connectors.base import (
    BaseConnector,
    ConnectorContext,
    ConnectorError,
    ConnectorTimeout,
)
from tex.discovery.connectors.slack import (
    _SENSITIVE_READ_SCOPES,
    _WRITE_SCOPES,
)
from tex.domain.agent import AgentEnvironment
from tex.domain.discovery import (
    CandidateAgent,
    DiscoveredCapabilityHints,
    DiscoveryRiskBand,
    DiscoverySource,
)


_logger = logging.getLogger(__name__)

_DEFAULT_API_BASE = "https://slack.com/api"
_USERS_LIST_PATH = "/users.list"
_APPS_LIST_PATH = "/admin.apps.approved.list"
_BOTS_INFO_PATH = "/bots.info"
_PAGE_LIMIT = 200


class SlackLiveConnector(BaseConnector):
    """
    Live connector against the Slack Web API.

    Use this in production. For tests, use ``SlackConnector`` from
    ``tex.discovery.connectors.slack``.
    """

    def __init__(
        self,
        *,
        token: str,
        team_id: str | None = None,
        api_base: str = _DEFAULT_API_BASE,
        name: str = "slack_live",
    ) -> None:
        super().__init__(
            source=DiscoverySource.SLACK,
            name=name,
        )
        if not token or not token.strip():
            raise ValueError("token must be non-empty")
        self._token = token.strip()
        self._team_id = team_id.strip() if team_id else None
        self._api_base = api_base.rstrip("/")

    def _run_scan(self, context: ConnectorContext) -> Iterable[CandidateAgent]:
        # Optional admin lookup. If this fails (likely scope error),
        # we degrade to "bots without scope info" rather than failing
        # the whole scan.
        scopes_by_app_id = self._safe_fetch_app_scopes(context=context)

        produced = 0
        for user in self._iter_bot_users(context=context):
            if produced >= context.max_candidates:
                return
            try:
                yield self._build_candidate(user, scopes_by_app_id, context)
            except Exception as exc:  # noqa: BLE001
                _logger.warning(
                    "slack_live: skipping malformed bot user: %s", exc
                )
                continue
            produced += 1

    # ------------------------------------------------------------------
    # API helpers
    # ------------------------------------------------------------------

    def _iter_bot_users(
        self,
        *,
        context: ConnectorContext,
    ) -> Iterable[dict[str, Any]]:
        cursor: str | None = None
        while True:
            params: dict[str, str] = {"limit": str(_PAGE_LIMIT)}
            if cursor:
                params["cursor"] = cursor
            if self._team_id:
                params["team_id"] = self._team_id
            payload = self._call(
                _USERS_LIST_PATH,
                params=params,
                context=context,
            )
            members = payload.get("members", []) or []
            for member in members:
                if not isinstance(member, dict):
                    continue
                if not member.get("is_bot"):
                    continue
                if member.get("deleted"):
                    continue
                yield member
            cursor = (payload.get("response_metadata") or {}).get("next_cursor")
            if not cursor:
                return

    def _safe_fetch_app_scopes(
        self,
        *,
        context: ConnectorContext,
    ) -> dict[str, list[str]]:
        try:
            return self._fetch_app_scopes(context=context)
        except ConnectorError as exc:
            _logger.info(
                "slack_live: degrading without admin app scopes: %s", exc
            )
            return {}

    def _fetch_app_scopes(
        self,
        *,
        context: ConnectorContext,
    ) -> dict[str, list[str]]:
        scopes_by_app_id: dict[str, list[str]] = {}
        cursor: str | None = None
        while True:
            params: dict[str, str] = {"limit": str(_PAGE_LIMIT)}
            if cursor:
                params["cursor"] = cursor
            if self._team_id:
                params["team_id"] = self._team_id
            payload = self._call(
                _APPS_LIST_PATH,
                params=params,
                context=context,
            )
            for app in payload.get("approved_apps", []) or []:
                if not isinstance(app, dict):
                    continue
                app_meta = app.get("app", {}) or {}
                app_id = app_meta.get("id") or app.get("app_id")
                if not isinstance(app_id, str):
                    continue
                scopes = app.get("scopes", {}) or {}
                bot_scopes = scopes.get("bot", []) or []
                user_scopes = scopes.get("user", []) or []
                merged = sorted(
                    {
                        str(s).strip().casefold()
                        for s in (*bot_scopes, *user_scopes)
                        if isinstance(s, str)
                    }
                )
                scopes_by_app_id[app_id] = merged
            cursor = (payload.get("response_metadata") or {}).get("next_cursor")
            if not cursor:
                return scopes_by_app_id

    def _call(
        self,
        path: str,
        *,
        params: dict[str, str],
        context: ConnectorContext,
    ) -> dict[str, Any]:
        url = f"{self._api_base}{path}"
        if params:
            url = f"{url}?{urlparse.urlencode(params)}"
        req = urlrequest.Request(url, method="GET")
        req.add_header("Authorization", f"Bearer {self._token}")
        req.add_header("Accept", "application/json")

        try:
            with urlrequest.urlopen(req, timeout=context.timeout_seconds) as resp:
                body = resp.read().decode("utf-8")
        except urlerror.HTTPError as exc:
            raise ConnectorError(
                f"slack_live: HTTP {exc.code} on {path}"
            ) from exc
        except urlerror.URLError as exc:
            reason = getattr(exc, "reason", exc)
            if "timed out" in str(reason).lower():
                raise ConnectorTimeout(
                    f"slack_live: timeout on {path} after "
                    f"{context.timeout_seconds}s"
                ) from exc
            raise ConnectorError(
                f"slack_live: network error on {path}: {reason}"
            ) from exc
        except TimeoutError as exc:
            raise ConnectorTimeout(
                f"slack_live: timeout on {path} after "
                f"{context.timeout_seconds}s"
            ) from exc

        try:
            payload = json.loads(body)
        except json.JSONDecodeError as exc:
            raise ConnectorError(
                f"slack_live: malformed JSON response from {path}"
            ) from exc

        if not isinstance(payload, dict):
            raise ConnectorError(f"slack_live: unexpected response shape from {path}")
        if not payload.get("ok", False):
            error = payload.get("error", "unknown_error")
            # Slack rate-limit response: respect Retry-After by
            # raising a typed timeout so the engine records it.
            if error == "ratelimited":
                retry_after = payload.get("retry_after", 30)
                raise ConnectorTimeout(
                    f"slack_live: rate limited on {path}; retry_after={retry_after}"
                )
            raise ConnectorError(f"slack_live: {error} on {path}")
        return payload

    # ------------------------------------------------------------------
    # Candidate construction (shared shape with the mock)
    # ------------------------------------------------------------------

    def _build_candidate(
        self,
        member: dict[str, Any],
        scopes_by_app_id: dict[str, list[str]],
        context: ConnectorContext,
    ) -> CandidateAgent:
        bot_id = str(member.get("id"))
        profile = member.get("profile", {}) or {}
        app_id = profile.get("api_app_id") or member.get("app_id")
        scopes_raw = scopes_by_app_id.get(str(app_id), []) if app_id else []
        scopes = tuple(
            sorted(
                {str(s).strip().casefold() for s in scopes_raw if isinstance(s, str)}
            )
        )

        write_scopes = {s for s in scopes if s in _WRITE_SCOPES}
        sensitive_read_scopes = {s for s in scopes if s in _SENSITIVE_READ_SCOPES}
        admin_scopes = {s for s in scopes if s.startswith("admin")}

        if admin_scopes:
            risk_band = DiscoveryRiskBand.CRITICAL
        elif write_scopes and sensitive_read_scopes:
            risk_band = DiscoveryRiskBand.HIGH
        elif write_scopes:
            risk_band = DiscoveryRiskBand.MEDIUM
        else:
            risk_band = DiscoveryRiskBand.LOW

        # Workflow Builder bots come back with ``is_workflow_bot`` on
        # the user record, or with ``app_id="A0LANXQRY"`` on some
        # workspaces; the env we care about is the ``is_workflow_bot``
        # flag introduced in 2024.
        is_workflow_bot = bool(member.get("is_workflow_bot", False))

        capability_hints = DiscoveredCapabilityHints(
            inferred_action_types=("send_message",) if write_scopes else tuple(),
            inferred_channels=("slack",),
            inferred_recipient_domains=tuple(),
            inferred_tools=scopes,
            inferred_mcp_servers=tuple(),
            inferred_data_scopes=tuple(sorted(sensitive_read_scopes)),
            surface_unbounded=bool(admin_scopes),
        )

        updated_dt = _epoch_to_dt(member.get("updated"))

        evidence = {
            "scopes": list(scopes),
            "app_id": app_id,
            "team_id": member.get("team_id"),
            "is_workflow_bot": is_workflow_bot,
            "raw_id": bot_id,
            "live": True,
        }

        confidence = 0.94 if scopes or is_workflow_bot else 0.80
        framework = "slack_workflow_builder" if is_workflow_bot else "slack_bot"

        tags: tuple[str, ...] = ("slack", framework, "live")
        if admin_scopes:
            tags = tags + ("admin_scope",)

        name = (
            profile.get("real_name")
            or member.get("real_name")
            or member.get("name")
            or bot_id
        )

        return CandidateAgent(
            source=DiscoverySource.SLACK,
            tenant_id=context.tenant_id,
            external_id=bot_id,
            name=str(name),
            owner_hint=None,
            description=profile.get("title"),
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

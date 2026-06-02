"""
Real-time alert engine.

Subscribes to drift events and governance snapshot transitions.
When a configured threshold rule fires, emits to one or more sinks:

  - LOG sink (always on; structured logger)
  - WEBHOOK sink (when ``TEX_ALERT_WEBHOOK_URL`` is set; POSTs JSON)
  - SLACK sink (when ``TEX_ALERT_SLACK_WEBHOOK_URL`` is set; posts a
    Slack-formatted message via the same HTTP path)

The alert engine is intentionally simple:

    drift_event   →  threshold rule  →  alert payload  →  sinks

Rules ship with sensible defaults and can be replaced wholesale at
construction. The alert engine never blocks the scheduler — sinks
fire in a fire-and-forget thread so a slow webhook does not stall
the next scan cycle.

Design note: this is a **detection** engine, not a **response**
engine. It tells you what changed. It does not auto-quarantine, auto-
revoke, or auto-mitigate. Those decisions belong to operators (or to
the policy layer, which already has its own gates). Conflating
detection with response is what turns a useful tool into one that
nobody trusts to enable in production.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any
from urllib import error as urlerror
from urllib import request as urlrequest

from tex.stores.drift_events import DriftEvent, DriftEventKind

_logger = logging.getLogger(__name__)


WEBHOOK_URL_ENV = "TEX_ALERT_WEBHOOK_URL"
SLACK_WEBHOOK_URL_ENV = "TEX_ALERT_SLACK_WEBHOOK_URL"
DISABLE_ENV = "TEX_ALERTS_DISABLED"


# ---------------------------------------------------------------------------
# Sinks
# ---------------------------------------------------------------------------


class AlertSink:
    """Implementor contract: take a payload dict, deliver it somewhere."""

    name: str

    def deliver(self, payload: dict[str, Any]) -> None:  # pragma: no cover
        raise NotImplementedError


class LogSink(AlertSink):
    """Always-on sink that just logs alerts at WARNING."""

    name = "log"

    def deliver(self, payload: dict[str, Any]) -> None:
        _logger.warning("[ALERT] %s", json.dumps(payload, default=str))


class WebhookSink(AlertSink):
    """
    POSTs the alert payload as JSON to a configured URL.

    Uses urllib so there's no extra dependency. 5-second timeout —
    if the receiver is slow we'd rather drop the alert than stall
    the alert loop.
    """

    name = "webhook"

    def __init__(self, url: str, *, timeout_seconds: float = 5.0) -> None:
        self._url = url
        self._timeout = timeout_seconds

    def deliver(self, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, default=str).encode("utf-8")
        req = urlrequest.Request(
            self._url,
            data=body,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            with urlrequest.urlopen(req, timeout=self._timeout) as resp:
                resp.read()
        except (urlerror.URLError, TimeoutError) as exc:
            _logger.error(
                "WebhookSink: delivery to %s failed: %s",
                self._url, exc,
            )


class SlackSink(AlertSink):
    """
    Posts to a Slack incoming webhook URL using Slack's expected
    payload shape ({"text": "..."}).
    """

    name = "slack"

    def __init__(self, webhook_url: str, *, timeout_seconds: float = 5.0) -> None:
        self._url = webhook_url
        self._timeout = timeout_seconds

    def deliver(self, payload: dict[str, Any]) -> None:
        # Slack incoming webhooks accept either a plain {"text": "..."}
        # or a richer block-kit payload. Plain text is more
        # compatible across slash-command bots, custom apps, and
        # legacy webhooks, so we use that.
        text = self._format(payload)
        body = json.dumps({"text": text}).encode("utf-8")
        req = urlrequest.Request(
            self._url,
            data=body,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            with urlrequest.urlopen(req, timeout=self._timeout) as resp:
                resp.read()
        except (urlerror.URLError, TimeoutError) as exc:
            _logger.error(
                "SlackSink: delivery to %s failed: %s", self._url, exc,
            )

    @staticmethod
    def _format(payload: dict[str, Any]) -> str:
        rule = payload.get("rule", "alert")
        severity = payload.get("severity", "INFO")
        summary = payload.get("summary", "")
        details = payload.get("details", {})
        lines = [f":rotating_light: *Tex {severity} — {rule}*", summary]
        if details:
            for k, v in details.items():
                lines.append(f"  • *{k}*: `{v}`")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AlertRule:
    """
    Rule: given a DriftEvent, return an alert payload (or None).

    A payload includes:
      rule       — short rule name (used in logs and the Slack header)
      severity   — INFO | WARN | CRITICAL
      summary    — human-readable line
      details    — structured key/value pairs

    Rules are pure functions; they don't fire side effects, the
    engine does.
    """

    name: str
    severity: str
    matches: Callable[[DriftEvent], bool]
    summarize: Callable[[DriftEvent], str]
    details: Callable[[DriftEvent], dict] = field(
        default=lambda _e: {}
    )


def default_rules() -> list[AlertRule]:
    """The rules that ship out of the box."""
    return [
        AlertRule(
            name="ungoverned_high_risk_appeared",
            severity="CRITICAL",
            matches=lambda e: (
                e.kind is DriftEventKind.NEW_AGENT
                and (e.details.get("risk_band") or "").upper() in {"HIGH", "CRITICAL"}
                and not e.details.get("auto_registered", False)
            ),
            summarize=lambda e: (
                f"New high-risk ungoverned agent detected: "
                f"{e.details.get('name') or e.reconciliation_key}"
            ),
            details=lambda e: {
                "tenant_id": e.tenant_id,
                "discovery_source": e.discovery_source,
                "risk_band": e.details.get("risk_band"),
                "reconciliation_key": e.reconciliation_key,
            },
        ),
        AlertRule(
            name="agent_disappeared",
            severity="WARN",
            matches=lambda e: e.kind is DriftEventKind.AGENT_DISAPPEARED,
            summarize=lambda e: (
                f"Agent disappeared from {e.discovery_source}: "
                f"{e.details.get('name') or e.reconciliation_key}"
            ),
            details=lambda e: {
                "tenant_id": e.tenant_id,
                "discovery_source": e.discovery_source,
                "reconciliation_key": e.reconciliation_key,
                "last_seen_revision": e.details.get("last_seen_revision"),
            },
        ),
        AlertRule(
            name="capability_surface_widened",
            severity="WARN",
            matches=lambda e: (
                e.kind is DriftEventKind.AGENT_CHANGED
                and e.details.get("change_kind") == "capability_widened"
            ),
            summarize=lambda e: (
                f"Capability surface widened on agent: "
                f"{e.details.get('name') or e.reconciliation_key}"
            ),
            details=lambda e: {
                "tenant_id": e.tenant_id,
                "discovery_source": e.discovery_source,
                "added": e.details.get("added", []),
            },
        ),
    ]


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class AlertEngine:
    """
    Subscribes to drift events and dispatches alerts.

    Usage:
        engine = AlertEngine.from_environment()
        engine.handle_drift_event(event)

    Sinks fire in a worker thread so slow webhooks never block.
    """

    __slots__ = ("_rules", "_sinks", "_disabled", "_lock")

    def __init__(
        self,
        *,
        rules: Iterable[AlertRule] | None = None,
        sinks: Iterable[AlertSink] | None = None,
        disabled: bool = False,
    ) -> None:
        self._rules = list(rules) if rules is not None else default_rules()
        self._sinks = list(sinks) if sinks is not None else [LogSink()]
        self._disabled = disabled
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ public

    @classmethod
    def from_environment(cls) -> AlertEngine:
        """
        Build an engine from env vars:

          TEX_ALERTS_DISABLED=1            — alerts off entirely
          TEX_ALERT_WEBHOOK_URL=...        — generic webhook sink
          TEX_ALERT_SLACK_WEBHOOK_URL=...  — Slack sink
        """
        disabled = bool(os.environ.get(DISABLE_ENV, "").strip())
        sinks: list[AlertSink] = [LogSink()]
        webhook = os.environ.get(WEBHOOK_URL_ENV, "").strip()
        if webhook:
            sinks.append(WebhookSink(webhook))
        slack = os.environ.get(SLACK_WEBHOOK_URL_ENV, "").strip()
        if slack:
            sinks.append(SlackSink(slack))
        return cls(sinks=sinks, disabled=disabled)

    @property
    def is_enabled(self) -> bool:
        return not self._disabled

    @property
    def sink_names(self) -> list[str]:
        return [s.name for s in self._sinks]

    def handle_drift_event(self, event: DriftEvent) -> list[dict[str, Any]]:
        """
        Run all rules against one event and dispatch any matches.

        Returns the list of dispatched alert payloads (mostly for
        introspection / testing — production code does not need to
        consume the return value).
        """
        if self._disabled:
            return []

        dispatched: list[dict[str, Any]] = []
        for rule in self._rules:
            try:
                if not rule.matches(event):
                    continue
            except Exception as exc:  # noqa: BLE001
                _logger.error("AlertEngine: rule %s.matches failed: %s", rule.name, exc)
                continue
            payload = self._build_payload(event, rule)
            self._dispatch(payload)
            dispatched.append(payload)
        return dispatched

    # ------------------------------------------------------------------ internals

    def _build_payload(self, event: DriftEvent, rule: AlertRule) -> dict[str, Any]:
        try:
            summary = rule.summarize(event)
        except Exception as exc:  # noqa: BLE001
            summary = f"<rule {rule.name} summarize failed: {exc}>"
        try:
            details = rule.details(event)
        except Exception as exc:  # noqa: BLE001
            _logger.error("AlertEngine: rule %s.details failed: %s", rule.name, exc)
            details = {}
        return {
            "rule": rule.name,
            "severity": rule.severity,
            "summary": summary,
            "details": details,
            "event": event.to_dict(),
        }

    def _dispatch(self, payload: dict[str, Any]) -> None:
        # Fire all sinks on a worker thread so a slow webhook doesn't
        # block the alert loop. The thread is daemon so it doesn't
        # delay shutdown.
        def _worker() -> None:
            for sink in self._sinks:
                try:
                    sink.deliver(payload)
                except Exception as exc:  # noqa: BLE001
                    _logger.error(
                        "AlertEngine: sink=%s delivery raised: %s",
                        sink.name, exc,
                    )

        t = threading.Thread(target=_worker, daemon=True, name="tex-alert-dispatch")
        t.start()


__all__ = [
    "AlertEngine",
    "AlertRule",
    "AlertSink",
    "LogSink",
    "WebhookSink",
    "SlackSink",
    "default_rules",
    "WEBHOOK_URL_ENV",
    "SLACK_WEBHOOK_URL_ENV",
    "DISABLE_ENV",
]

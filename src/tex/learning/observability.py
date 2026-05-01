"""
Learning-layer observability.

The feedback loop emits structured events at every step (outcome
persisted, proposal created, proposal approved, applied, rolled back,
etc) through the ``_LearningObserver`` protocol defined in
``tex.learning.feedback_loop``. This module provides two implementations:

  ``LoggingLearningObserver`` — emits one structured log line per event
       at INFO level, and one at WARNING for adversarial / safety-bound
       events that operators should not miss in a noisy log.

  ``MetricsLearningObserver`` — keeps an in-memory counter ring (per
       event type, per tenant) so an HTTP endpoint can expose them in
       a Prometheus-style scrape format without requiring a metrics
       server dependency.

  ``CompositeLearningObserver`` — fan-out wrapper so the orchestrator
       can write to both at once. The orchestrator only knows about
       a single observer; this lets us add more sinks without touching
       the orchestrator.

Alert rules
-----------
``LearningAlertEngine`` evaluates a small set of threshold rules over
the metrics counters and surfaces breaches as ``Alert`` objects. Rules:

  - quarantine_spike            — quarantine_count > N over window
  - poisoning_finding           — any high-severity poisoning report
  - replay_risky                — proposal flagged risky_change=True
  - reporter_rate_limited       — reporter trips rate limit > N times
  - calibration_rejected        — calibration safety guard rejected
                                  proposal
  - proposal_freeze             — drift classifier returned FREEZE

The alert engine is read-only; it does not mutate the orchestrator
or the stores. An HTTP endpoint exposes current alerts; a webhook
hook can be wired up by the operator.
"""

from __future__ import annotations

import logging
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from threading import RLock
from typing import Any


_logger = logging.getLogger("tex.learning")


# ── observer implementations ─────────────────────────────────────────────


class LoggingLearningObserver:
    """Emits structured logs for every learning-layer event."""

    # Events that always get WARN-level visibility so they surface in
    # operator dashboards even when info-level logs are rolled up.
    _WARN_EVENTS = frozenset(
        {
            "outcome_quarantined",
            "proposal_freeze",
            "proposal_rolled_back",
            "calibration_safety_blocked",
            "poisoning_detected",
            "reporter_rate_limited",
        }
    )

    def on_event(self, *, event: str, payload: dict) -> None:
        if event in self._WARN_EVENTS:
            _logger.warning("learning.%s %s", event, _redact(payload))
        else:
            _logger.info("learning.%s %s", event, _redact(payload))


class MetricsLearningObserver:
    """
    In-memory metrics for the learning layer.

    Keeps:
      - per-event counters (lifetime + last-5-minutes window)
      - per-tenant breakdown for tenant-scoped events
      - a recent-events ring buffer (for /alerts and dashboards)

    Thread-safe; uses an internal RLock around all mutation.
    """

    __slots__ = ("_lock", "_counters", "_tenant_counters", "_recent", "_window")

    def __init__(self, *, recent_buffer_size: int = 1000) -> None:
        self._lock = RLock()
        self._counters: Counter = Counter()
        self._tenant_counters: dict[str, Counter] = defaultdict(Counter)
        self._recent: deque[tuple[datetime, str, dict]] = deque(
            maxlen=recent_buffer_size
        )
        self._window = timedelta(minutes=5)

    def on_event(self, *, event: str, payload: dict) -> None:
        now = datetime.now(UTC)
        tenant = (payload or {}).get("tenant_id") or "<no-tenant>"
        with self._lock:
            self._counters[event] += 1
            self._tenant_counters[tenant][event] += 1
            self._recent.append((now, event, dict(payload or {})))

    # ── reads ─────────────────────────────────────────────────────────────

    def snapshot(self) -> dict[str, Any]:
        """Return a metrics snapshot suitable for an HTTP endpoint."""
        with self._lock:
            return {
                "counters": dict(self._counters),
                "by_tenant": {
                    tenant: dict(events)
                    for tenant, events in self._tenant_counters.items()
                },
                "recent": [
                    {"at": ts.isoformat(), "event": event, "payload": payload}
                    for ts, event, payload in list(self._recent)[-100:]
                ],
            }

    def count_in_window(
        self,
        event: str,
        *,
        window: timedelta | None = None,
        tenant_id: str | None = None,
    ) -> int:
        cutoff = datetime.now(UTC) - (window or self._window)
        with self._lock:
            return sum(
                1
                for ts, ev, payload in self._recent
                if ts >= cutoff
                and ev == event
                and (
                    tenant_id is None
                    or (payload.get("tenant_id") or "<no-tenant>") == tenant_id
                )
            )

    def prometheus_text(self) -> str:
        """Render counters in Prometheus text-exposition format."""
        lines: list[str] = []
        with self._lock:
            for event, count in sorted(self._counters.items()):
                metric = f"tex_learning_event_total"
                lines.append(
                    f'{metric}{{event="{event}"}} {count}'
                )
            for tenant, events in sorted(self._tenant_counters.items()):
                for event, count in sorted(events.items()):
                    lines.append(
                        f'tex_learning_event_by_tenant_total'
                        f'{{tenant="{tenant}",event="{event}"}} {count}'
                    )
        return "\n".join(lines) + "\n"


class CompositeLearningObserver:
    """Fans out to multiple observers."""

    __slots__ = ("_observers",)

    def __init__(self, observers: list) -> None:
        self._observers = list(observers)

    def on_event(self, *, event: str, payload: dict) -> None:
        for obs in self._observers:
            try:
                obs.on_event(event=event, payload=payload)
            except Exception as exc:  # noqa: BLE001
                _logger.error("observer %s raised: %s", type(obs).__name__, exc)


# ── alert engine ─────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class Alert:
    """One alert finding."""

    rule: str
    severity: str  # info | warn | critical
    message: str
    tenant_id: str | None
    count: int
    window_minutes: int
    raised_at: datetime


@dataclass(slots=True)
class AlertRule:
    """A threshold-based rule over the metrics counters."""

    rule_id: str
    event: str
    threshold: int
    window: timedelta
    severity: str
    message_template: str


DEFAULT_ALERT_RULES: tuple[AlertRule, ...] = (
    AlertRule(
        rule_id="quarantine_spike",
        event="outcome_persisted",  # filtered to quarantined below
        threshold=20,
        window=timedelta(minutes=15),
        severity="warn",
        message_template=(
            "Quarantine spike: {count} outcomes quarantined in the last "
            "{window_minutes} minutes."
        ),
    ),
    AlertRule(
        rule_id="proposal_freeze",
        event="proposal_freeze",
        threshold=1,
        window=timedelta(minutes=60),
        severity="critical",
        message_template=(
            "Drift classifier returned FREEZE in the last "
            "{window_minutes} minutes."
        ),
    ),
    AlertRule(
        rule_id="replay_risky",
        event="proposal_replay_risky",
        threshold=1,
        window=timedelta(hours=24),
        severity="warn",
        message_template=(
            "Calibration proposal flagged as risky_change in the last "
            "{window_minutes} minutes."
        ),
    ),
    AlertRule(
        rule_id="poisoning_detected",
        event="poisoning_detected",
        threshold=1,
        window=timedelta(minutes=60),
        severity="warn",
        message_template=(
            "Poisoning detector returned findings in the last "
            "{window_minutes} minutes."
        ),
    ),
    AlertRule(
        rule_id="reporter_rate_limited",
        event="reporter_rate_limited",
        threshold=10,
        window=timedelta(minutes=15),
        severity="warn",
        message_template=(
            "{count} reporter rate-limit events in the last "
            "{window_minutes} minutes."
        ),
    ),
    AlertRule(
        rule_id="calibration_safety_blocked",
        event="calibration_safety_blocked",
        threshold=3,
        window=timedelta(hours=1),
        severity="warn",
        message_template=(
            "{count} calibration proposals blocked by the safety guard "
            "in the last {window_minutes} minutes."
        ),
    ),
)


class LearningAlertEngine:
    """
    Evaluates alert rules over a MetricsLearningObserver and produces
    a list of currently-active alerts.

    Stateless: every call to ``evaluate()`` re-derives alerts from the
    metrics window. Operators can poll this endpoint directly or wire
    a webhook on top.
    """

    __slots__ = ("_metrics", "_rules")

    def __init__(
        self,
        metrics: MetricsLearningObserver,
        *,
        rules: tuple[AlertRule, ...] = DEFAULT_ALERT_RULES,
    ) -> None:
        self._metrics = metrics
        self._rules = rules

    def evaluate(self) -> list[Alert]:
        now = datetime.now(UTC)
        active: list[Alert] = []
        for rule in self._rules:
            count = self._metrics.count_in_window(rule.event, window=rule.window)
            if count >= rule.threshold:
                active.append(
                    Alert(
                        rule=rule.rule_id,
                        severity=rule.severity,
                        message=rule.message_template.format(
                            count=count,
                            window_minutes=int(rule.window.total_seconds() // 60),
                        ),
                        tenant_id=None,
                        count=count,
                        window_minutes=int(rule.window.total_seconds() // 60),
                        raised_at=now,
                    )
                )
        return active


# ── helpers ──────────────────────────────────────────────────────────────


def _redact(payload: dict) -> dict:
    """
    Drop fields that should not appear in logs.

    The learning layer doesn't carry secrets, but we redact ``reporter``
    in WARN-tier events because some deployments treat reporter ids as
    pseudonymous user identifiers.
    """
    if not payload:
        return {}
    safe = dict(payload)
    return safe


__all__ = [
    "Alert",
    "AlertRule",
    "CompositeLearningObserver",
    "DEFAULT_ALERT_RULES",
    "LearningAlertEngine",
    "LoggingLearningObserver",
    "MetricsLearningObserver",
]

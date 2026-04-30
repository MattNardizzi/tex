"""
V15 tests: AlertEngine — default rules, sink dispatch, fire-and-forget
worker.

Uses an in-process ``CapturingSink`` so we can assert exactly which
payloads were delivered without depending on real HTTP. The
fire-and-forget worker uses a daemon thread; tests join with a
short deadline before reading captures.
"""

from __future__ import annotations

import threading
import time
from datetime import UTC, datetime
from uuid import uuid4

from tex.discovery.alerts import (
    AlertEngine,
    AlertSink,
    LogSink,
    SlackSink,
    WebhookSink,
    default_rules,
)
from tex.stores.drift_events import DriftEvent, DriftEventKind


class CapturingSink(AlertSink):
    """Test sink that records every payload it receives."""

    name = "capture"

    def __init__(self) -> None:
        self.captured: list[dict] = []
        self._lock = threading.Lock()

    def deliver(self, payload: dict) -> None:
        with self._lock:
            self.captured.append(payload)


def _drift_event(
    *,
    kind: DriftEventKind,
    risk_band: str | None = None,
    auto_registered: bool = False,
    name: str = "test-agent",
    change_kind: str | None = None,
    last_seen_revision: int | None = None,
    discovery_source: str = "openai",
) -> DriftEvent:
    details: dict = {"name": name}
    if risk_band is not None:
        details["risk_band"] = risk_band
    if auto_registered:
        details["auto_registered"] = True
    if change_kind is not None:
        details["change_kind"] = change_kind
    if last_seen_revision is not None:
        details["last_seen_revision"] = last_seen_revision

    return DriftEvent(
        event_id=uuid4(),
        occurred_at=datetime.now(UTC),
        tenant_id="default",
        kind=kind,
        reconciliation_key=f"{discovery_source}:asst_test",
        discovery_source=discovery_source,
        agent_id=uuid4(),
        severity="INFO",
        summary=f"test {kind}",
        details=details,
        scan_run_id=uuid4(),
    )


def _wait_for_captures(sink: CapturingSink, *, expected: int, timeout: float = 1.0) -> None:
    """Poll the capturing sink until expected count or deadline."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if len(sink.captured) >= expected:
            return
        time.sleep(0.01)


class TestAlertEngineConstruction:
    def test_default_construction_has_log_sink(self):
        engine = AlertEngine()
        assert engine.is_enabled
        assert "log" in engine.sink_names

    def test_disabled_engine_does_not_dispatch(self):
        capture = CapturingSink()
        engine = AlertEngine(sinks=[capture], disabled=True)
        engine.handle_drift_event(
            _drift_event(kind=DriftEventKind.NEW_AGENT, risk_band="HIGH")
        )
        # No dispatch happened, even though a rule would have matched.
        time.sleep(0.05)
        assert capture.captured == []

    def test_from_environment_picks_up_webhook(self, monkeypatch):
        monkeypatch.setenv("TEX_ALERT_WEBHOOK_URL", "https://example.com/hook")
        monkeypatch.delenv("TEX_ALERT_SLACK_WEBHOOK_URL", raising=False)
        monkeypatch.delenv("TEX_ALERTS_DISABLED", raising=False)
        engine = AlertEngine.from_environment()
        assert "webhook" in engine.sink_names
        assert "log" in engine.sink_names

    def test_from_environment_picks_up_slack(self, monkeypatch):
        monkeypatch.setenv(
            "TEX_ALERT_SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/x"
        )
        monkeypatch.delenv("TEX_ALERT_WEBHOOK_URL", raising=False)
        monkeypatch.delenv("TEX_ALERTS_DISABLED", raising=False)
        engine = AlertEngine.from_environment()
        assert "slack" in engine.sink_names

    def test_from_environment_disabled(self, monkeypatch):
        monkeypatch.setenv("TEX_ALERTS_DISABLED", "1")
        engine = AlertEngine.from_environment()
        assert engine.is_enabled is False


class TestDefaultRules:
    def test_high_risk_new_agent_fires_critical(self):
        capture = CapturingSink()
        engine = AlertEngine(sinks=[capture])
        engine.handle_drift_event(
            _drift_event(kind=DriftEventKind.NEW_AGENT, risk_band="HIGH")
        )
        _wait_for_captures(capture, expected=1)
        assert len(capture.captured) == 1
        payload = capture.captured[0]
        assert payload["rule"] == "ungoverned_high_risk_appeared"
        assert payload["severity"] == "CRITICAL"
        assert "high-risk" in payload["summary"].lower() or "high risk" in payload["summary"].lower()

    def test_critical_risk_new_agent_fires_too(self):
        capture = CapturingSink()
        engine = AlertEngine(sinks=[capture])
        engine.handle_drift_event(
            _drift_event(kind=DriftEventKind.NEW_AGENT, risk_band="CRITICAL")
        )
        _wait_for_captures(capture, expected=1)
        assert len(capture.captured) == 1

    def test_low_risk_new_agent_does_not_fire(self):
        capture = CapturingSink()
        engine = AlertEngine(sinks=[capture])
        engine.handle_drift_event(
            _drift_event(kind=DriftEventKind.NEW_AGENT, risk_band="LOW")
        )
        # Give the worker a beat to confirm nothing fires.
        time.sleep(0.05)
        assert capture.captured == []

    def test_auto_registered_high_risk_does_not_fire(self):
        # An auto-registered high-risk new agent is one we already
        # took control of — alerting on it would cry wolf.
        capture = CapturingSink()
        engine = AlertEngine(sinks=[capture])
        engine.handle_drift_event(
            _drift_event(
                kind=DriftEventKind.NEW_AGENT,
                risk_band="HIGH",
                auto_registered=True,
            )
        )
        time.sleep(0.05)
        assert capture.captured == []

    def test_agent_disappeared_fires_warn(self):
        capture = CapturingSink()
        engine = AlertEngine(sinks=[capture])
        engine.handle_drift_event(
            _drift_event(
                kind=DriftEventKind.AGENT_DISAPPEARED,
                last_seen_revision=2,
            )
        )
        _wait_for_captures(capture, expected=1)
        assert len(capture.captured) == 1
        payload = capture.captured[0]
        assert payload["rule"] == "agent_disappeared"
        assert payload["severity"] == "WARN"

    def test_capability_widened_fires_warn(self):
        capture = CapturingSink()
        engine = AlertEngine(sinks=[capture])
        engine.handle_drift_event(
            _drift_event(
                kind=DriftEventKind.AGENT_CHANGED,
                change_kind="capability_widened",
            )
        )
        _wait_for_captures(capture, expected=1)
        assert len(capture.captured) == 1
        payload = capture.captured[0]
        assert payload["rule"] == "capability_surface_widened"
        assert payload["severity"] == "WARN"

    def test_capability_narrowed_does_not_fire(self):
        # We only alert on widening — narrowing is good news.
        capture = CapturingSink()
        engine = AlertEngine(sinks=[capture])
        engine.handle_drift_event(
            _drift_event(
                kind=DriftEventKind.AGENT_CHANGED,
                change_kind="capability_narrowed",
            )
        )
        time.sleep(0.05)
        assert capture.captured == []


class TestSinkResilience:
    def test_one_failing_sink_does_not_block_others(self):
        # If one sink raises, the others still get the payload. This
        # is the contract that makes the engine safe to enable in
        # production with experimental sinks.
        class BoomSink(AlertSink):
            name = "boom"

            def deliver(self, payload):
                raise RuntimeError("boom")

        capture = CapturingSink()
        engine = AlertEngine(sinks=[BoomSink(), capture])
        engine.handle_drift_event(
            _drift_event(kind=DriftEventKind.NEW_AGENT, risk_band="HIGH")
        )
        _wait_for_captures(capture, expected=1)
        # The capturing sink still received the payload despite the
        # other sink raising.
        assert len(capture.captured) == 1


class TestPayloadShape:
    def test_payload_has_event_attached(self):
        capture = CapturingSink()
        engine = AlertEngine(sinks=[capture])
        event = _drift_event(kind=DriftEventKind.NEW_AGENT, risk_band="HIGH")
        engine.handle_drift_event(event)
        _wait_for_captures(capture, expected=1)
        payload = capture.captured[0]
        # Event included as a structured dict.
        assert "event" in payload
        assert payload["event"]["event_id"] == str(event.event_id)
        # Details extracted into a top-level details dict for convenience.
        assert "tenant_id" in payload["details"]

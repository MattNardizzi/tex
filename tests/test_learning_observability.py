"""Tests for the learning observability layer and alert engine."""

from __future__ import annotations

from datetime import timedelta

from tex.learning.observability import (
    AlertRule,
    CompositeLearningObserver,
    LearningAlertEngine,
    LoggingLearningObserver,
    MetricsLearningObserver,
)


def test_metrics_observer_increments_counters() -> None:
    metrics = MetricsLearningObserver()
    metrics.on_event(event="outcome_persisted", payload={"tenant_id": "acme"})
    metrics.on_event(event="outcome_persisted", payload={"tenant_id": "acme"})
    metrics.on_event(event="outcome_quarantined", payload={"tenant_id": "evil"})

    snap = metrics.snapshot()
    assert snap["counters"]["outcome_persisted"] == 2
    assert snap["counters"]["outcome_quarantined"] == 1
    assert snap["by_tenant"]["acme"]["outcome_persisted"] == 2
    assert snap["by_tenant"]["evil"]["outcome_quarantined"] == 1


def test_metrics_observer_recent_buffer() -> None:
    metrics = MetricsLearningObserver(recent_buffer_size=3)
    for i in range(5):
        metrics.on_event(event="outcome_persisted", payload={"i": i})
    snap = metrics.snapshot()
    # Buffer is bounded.
    assert len(snap["recent"]) <= 5
    # The most recent ones should be there.
    assert any(r["payload"].get("i") == 4 for r in snap["recent"])


def test_count_in_window_filters_by_tenant() -> None:
    metrics = MetricsLearningObserver()
    metrics.on_event(event="outcome_quarantined", payload={"tenant_id": "acme"})
    metrics.on_event(event="outcome_quarantined", payload={"tenant_id": "acme"})
    metrics.on_event(event="outcome_quarantined", payload={"tenant_id": "other"})

    assert metrics.count_in_window("outcome_quarantined", tenant_id="acme") == 2
    assert metrics.count_in_window("outcome_quarantined", tenant_id="other") == 1
    assert metrics.count_in_window("outcome_quarantined") == 3


def test_prometheus_output_includes_counters() -> None:
    metrics = MetricsLearningObserver()
    metrics.on_event(event="outcome_persisted", payload={"tenant_id": "acme"})
    text = metrics.prometheus_text()
    assert "tex_learning_event_total" in text
    assert "outcome_persisted" in text
    assert "tex_learning_event_by_tenant_total" in text


def test_composite_fans_out() -> None:
    seen_a: list[str] = []
    seen_b: list[str] = []

    class _Sink:
        def __init__(self, sink_list):
            self._sink = sink_list

        def on_event(self, *, event: str, payload: dict) -> None:
            self._sink.append(event)

    composite = CompositeLearningObserver([_Sink(seen_a), _Sink(seen_b)])
    composite.on_event(event="x", payload={})
    assert seen_a == ["x"]
    assert seen_b == ["x"]


def test_composite_isolates_observer_failures() -> None:
    seen: list[str] = []

    class _Boom:
        def on_event(self, **kwargs) -> None:
            raise RuntimeError("boom")

    class _Sink:
        def on_event(self, *, event: str, payload: dict) -> None:
            seen.append(event)

    composite = CompositeLearningObserver([_Boom(), _Sink()])
    # A raising observer must not stop the others.
    composite.on_event(event="x", payload={})
    assert seen == ["x"]


def test_logging_observer_runs_without_errors() -> None:
    obs = LoggingLearningObserver()
    obs.on_event(event="outcome_persisted", payload={"tenant_id": "acme"})
    obs.on_event(event="proposal_freeze", payload={"tenant_id": "evil"})


def test_alert_engine_fires_on_threshold() -> None:
    metrics = MetricsLearningObserver()
    rule = AlertRule(
        rule_id="poison_test",
        event="poisoning_detected",
        threshold=2,
        window=timedelta(minutes=5),
        severity="warn",
        message_template="{count} poisoning findings in {window_minutes}m",
    )
    engine = LearningAlertEngine(metrics=metrics, rules=(rule,))

    # Below threshold.
    metrics.on_event(event="poisoning_detected", payload={})
    assert engine.evaluate() == []

    # At threshold.
    metrics.on_event(event="poisoning_detected", payload={})
    alerts = engine.evaluate()
    assert len(alerts) == 1
    assert alerts[0].rule == "poison_test"
    assert alerts[0].severity == "warn"
    assert alerts[0].count >= 2


def test_alert_engine_does_not_fire_below_threshold() -> None:
    metrics = MetricsLearningObserver()
    rule = AlertRule(
        rule_id="never",
        event="never_emitted",
        threshold=1,
        window=timedelta(minutes=5),
        severity="info",
        message_template="x",
    )
    engine = LearningAlertEngine(metrics=metrics, rules=(rule,))
    assert engine.evaluate() == []

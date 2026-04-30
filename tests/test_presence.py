"""
V16 tests: PresenceTracker — soft-disappearance state machine.

The tracker turns "missing this scan" into a graduated state:
PRESENT → MISSING_ONCE → MISSING_TWICE → CONFIRMED_DISAPPEARED.
Only the transition INTO confirmed-disappeared produces an event the
scheduler should alert on. Tests pin every transition.
"""

from __future__ import annotations

from tex.discovery.presence import (
    PresenceState,
    PresenceTracker,
    TransitionEvent,
)


class TestStateProgression:
    def test_first_seen_is_present(self) -> None:
        t = PresenceTracker()
        rec, event = t.observe_seen(
            tenant_id="acme", reconciliation_key="openai:default:bot1",
        )
        assert rec.state is PresenceState.PRESENT
        assert event is TransitionEvent.NO_EVENT
        assert rec.consecutive_misses == 0

    def test_first_miss_advances_to_missing_once(self) -> None:
        t = PresenceTracker(missing_threshold=3)
        # Establish presence first.
        t.observe_seen(tenant_id="acme", reconciliation_key="k")
        rec, event = t.observe_missing(tenant_id="acme", reconciliation_key="k")
        assert rec.state is PresenceState.MISSING_ONCE
        assert event is TransitionEvent.SILENT_MISS
        assert rec.consecutive_misses == 1

    def test_second_miss_advances_to_missing_twice(self) -> None:
        t = PresenceTracker(missing_threshold=3)
        t.observe_seen(tenant_id="acme", reconciliation_key="k")
        t.observe_missing(tenant_id="acme", reconciliation_key="k")
        rec, event = t.observe_missing(tenant_id="acme", reconciliation_key="k")
        assert rec.state is PresenceState.MISSING_TWICE
        assert event is TransitionEvent.SILENT_MISS
        assert rec.consecutive_misses == 2

    def test_third_miss_confirms_disappearance(self) -> None:
        t = PresenceTracker(missing_threshold=3)
        t.observe_seen(tenant_id="acme", reconciliation_key="k")
        t.observe_missing(tenant_id="acme", reconciliation_key="k")
        t.observe_missing(tenant_id="acme", reconciliation_key="k")
        rec, event = t.observe_missing(tenant_id="acme", reconciliation_key="k")
        assert rec.state is PresenceState.CONFIRMED_DISAPPEARED
        assert event is TransitionEvent.CONFIRMED_DISAPPEARED
        assert rec.confirmed_at is not None

    def test_confirmation_emitted_only_once(self) -> None:
        t = PresenceTracker(missing_threshold=2)
        t.observe_seen(tenant_id="acme", reconciliation_key="k")
        t.observe_missing(tenant_id="acme", reconciliation_key="k")
        rec, ev = t.observe_missing(tenant_id="acme", reconciliation_key="k")
        assert ev is TransitionEvent.CONFIRMED_DISAPPEARED
        # Subsequent miss after confirmation: no new event.
        rec, ev = t.observe_missing(tenant_id="acme", reconciliation_key="k")
        assert ev is TransitionEvent.NO_EVENT
        assert rec.state is PresenceState.CONFIRMED_DISAPPEARED


class TestRecoveryAndReappearance:
    def test_seen_after_missing_once_recovers_silently(self) -> None:
        t = PresenceTracker(missing_threshold=3)
        t.observe_seen(tenant_id="acme", reconciliation_key="k")
        t.observe_missing(tenant_id="acme", reconciliation_key="k")
        rec, event = t.observe_seen(tenant_id="acme", reconciliation_key="k")
        assert rec.state is PresenceState.PRESENT
        assert event is TransitionEvent.RECOVERED
        assert rec.consecutive_misses == 0

    def test_seen_after_missing_twice_also_recovers(self) -> None:
        t = PresenceTracker(missing_threshold=3)
        t.observe_seen(tenant_id="acme", reconciliation_key="k")
        t.observe_missing(tenant_id="acme", reconciliation_key="k")
        t.observe_missing(tenant_id="acme", reconciliation_key="k")
        rec, event = t.observe_seen(tenant_id="acme", reconciliation_key="k")
        assert rec.state is PresenceState.PRESENT
        assert event is TransitionEvent.RECOVERED

    def test_seen_after_confirmed_emits_reappeared(self) -> None:
        t = PresenceTracker(missing_threshold=2)
        t.observe_seen(tenant_id="acme", reconciliation_key="k")
        t.observe_missing(tenant_id="acme", reconciliation_key="k")
        t.observe_missing(tenant_id="acme", reconciliation_key="k")
        rec, event = t.observe_seen(tenant_id="acme", reconciliation_key="k")
        assert rec.state is PresenceState.PRESENT
        assert event is TransitionEvent.REAPPEARED


class TestThresholdTuning:
    def test_threshold_one_emits_immediately(self) -> None:
        t = PresenceTracker(missing_threshold=1)
        t.observe_seen(tenant_id="acme", reconciliation_key="k")
        rec, event = t.observe_missing(tenant_id="acme", reconciliation_key="k")
        assert rec.state is PresenceState.CONFIRMED_DISAPPEARED
        assert event is TransitionEvent.CONFIRMED_DISAPPEARED

    def test_threshold_floor_is_one(self) -> None:
        # Even passing 0, the implementation clamps to 1 so we never
        # silently never-emit.
        t = PresenceTracker(missing_threshold=0)
        assert t.threshold == 1


class TestIsolation:
    def test_tenant_isolation(self) -> None:
        t = PresenceTracker()
        t.observe_seen(tenant_id="acme", reconciliation_key="k")
        t.observe_missing(tenant_id="acme", reconciliation_key="k")
        # Another tenant with the same key shouldn't be impacted.
        rec, _ = t.observe_seen(tenant_id="globex", reconciliation_key="k")
        assert rec.state is PresenceState.PRESENT
        assert rec.consecutive_misses == 0

    def test_key_isolation(self) -> None:
        t = PresenceTracker()
        t.observe_seen(tenant_id="acme", reconciliation_key="k1")
        t.observe_missing(tenant_id="acme", reconciliation_key="k1")
        rec, _ = t.observe_missing(tenant_id="acme", reconciliation_key="k2")
        # k2 is a fresh key — first miss only.
        assert rec.consecutive_misses == 1
        assert rec.state is PresenceState.MISSING_ONCE

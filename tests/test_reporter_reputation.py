"""Tests for the reporter reputation system with time decay."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from tex.learning.reporter_reputation import (
    DEFAULT_NEUTRAL_WEIGHT,
    ReporterReputationStore,
)


def test_unknown_reporter_gets_neutral_weight() -> None:
    store = ReporterReputationStore()
    assert store.weight_for("never-seen") == DEFAULT_NEUTRAL_WEIGHT
    assert store.weight_for(None) == DEFAULT_NEUTRAL_WEIGHT
    assert store.weight_for("") == DEFAULT_NEUTRAL_WEIGHT


def test_consistent_agreer_climbs_above_neutral() -> None:
    store = ReporterReputationStore(min_observations_before_decay=2)
    base = datetime(2026, 1, 1, tzinfo=UTC)
    for i in range(20):
        store.record_observation(
            reporter="reliable",
            agreed_with_consensus=True,
            observed_at=base + timedelta(minutes=i),
        )
    weight = store.weight_for("reliable")
    assert weight > DEFAULT_NEUTRAL_WEIGHT
    assert weight <= 1.5  # ceiling


def test_consistent_disagreer_falls_below_neutral() -> None:
    store = ReporterReputationStore(min_observations_before_decay=2)
    base = datetime(2026, 1, 1, tzinfo=UTC)
    for i in range(20):
        store.record_observation(
            reporter="bad-reporter",
            agreed_with_consensus=False,
            observed_at=base + timedelta(minutes=i),
        )
    weight = store.weight_for("bad-reporter")
    assert weight < DEFAULT_NEUTRAL_WEIGHT
    assert weight >= 0.05  # floor


def test_old_disagreements_decay_via_half_life() -> None:
    fixed_clock_value = [datetime(2026, 1, 1, tzinfo=UTC)]
    store = ReporterReputationStore(
        half_life=timedelta(days=7),
        min_observations_before_decay=2,
        clock=lambda: fixed_clock_value[0],
    )
    # Record 10 disagreements at t=0
    for _ in range(10):
        store.record_observation(
            reporter="erratic",
            agreed_with_consensus=False,
            observed_at=fixed_clock_value[0],
        )
    weight_immediately = store.weight_for("erratic")

    # Now jump the clock forward 60 days (≈8.5 half-lives) and add fresh agreements.
    fixed_clock_value[0] = datetime(2026, 3, 1, tzinfo=UTC)
    for _ in range(10):
        store.record_observation(
            reporter="erratic",
            agreed_with_consensus=True,
            observed_at=fixed_clock_value[0],
        )
    weight_after_redemption = store.weight_for("erratic")

    # Old disagreements decayed; recent agreements lift the weight.
    assert weight_after_redemption > weight_immediately


def test_reset_clears_history() -> None:
    store = ReporterReputationStore(min_observations_before_decay=2)
    base = datetime(2026, 1, 1, tzinfo=UTC)
    for _ in range(10):
        store.record_observation(
            reporter="x", agreed_with_consensus=False, observed_at=base
        )
    assert store.weight_for("x") < DEFAULT_NEUTRAL_WEIGHT
    store.reset("x")
    assert store.weight_for("x") == DEFAULT_NEUTRAL_WEIGHT


def test_blank_reporter_rejected() -> None:
    store = ReporterReputationStore()
    with pytest.raises(ValueError):
        store.record_observation(reporter="", agreed_with_consensus=True)
    with pytest.raises(ValueError):
        store.get("")


def test_get_returns_full_snapshot() -> None:
    store = ReporterReputationStore(min_observations_before_decay=2)
    base = datetime(2026, 1, 1, tzinfo=UTC)
    for i in range(5):
        store.record_observation(
            reporter="alice",
            agreed_with_consensus=True,
            observed_at=base + timedelta(minutes=i),
        )
    snapshot = store.get("alice")
    assert snapshot.reporter == "alice"
    assert snapshot.observations == 5
    assert snapshot.agreements == 5
    assert snapshot.disagreements == 0
    assert snapshot.accuracy == 1.0
    assert snapshot.disagreement_rate == 0.0

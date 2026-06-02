"""Tests for tex.drift.signal_registry."""

from __future__ import annotations

import pytest

from tex.drift.signal_registry import (
    DEFAULT_SIGNAL_IDS,
    SIGNAL_AVERAGE_COMPROMISE_SCORE,
    SIGNAL_AVERAGE_PATH_DEPTH,
    SIGNAL_CAPABILITY_GRANT_RATE,
    SIGNAL_CROSS_AGENT_MESSAGE_RATE,
    SIGNAL_DENIAL_RATE_PER_AGENT,
    SIGNAL_OUTBOUND_CONTENT_VOLUME_PER_TENANT,
    SIGNAL_TOOL_CALL_RATE_PER_AGENT,
    DriftSignal,
    DriftSignalRegistry,
)


class TestDefaultSeed:
    def test_seven_default_signals_present(self) -> None:
        registry = DriftSignalRegistry()
        assert len(registry) == 7

    def test_default_ids_match_constants(self) -> None:
        # The seven signals from the package scaffolding docstring.
        expected = {
            SIGNAL_TOOL_CALL_RATE_PER_AGENT,
            SIGNAL_CROSS_AGENT_MESSAGE_RATE,
            SIGNAL_CAPABILITY_GRANT_RATE,
            SIGNAL_DENIAL_RATE_PER_AGENT,
            SIGNAL_OUTBOUND_CONTENT_VOLUME_PER_TENANT,
            SIGNAL_AVERAGE_PATH_DEPTH,
            SIGNAL_AVERAGE_COMPROMISE_SCORE,
        }
        registry = DriftSignalRegistry()
        assert set(registry.signal_ids()) == expected
        assert set(DEFAULT_SIGNAL_IDS) == expected

    def test_can_disable_default_seed(self) -> None:
        registry = DriftSignalRegistry(seed_defaults=False)
        assert len(registry) == 0
        assert registry.signal_ids() == ()

    def test_default_signals_have_descriptions_and_baselines(self) -> None:
        registry = DriftSignalRegistry()
        for signal in registry:
            assert signal.description
            assert signal.aggregation_window_seconds > 0
            assert signal.baseline_stddev > 0.0


class TestRegistration:
    def test_register_custom_signal(self) -> None:
        registry = DriftSignalRegistry(seed_defaults=False)
        custom = DriftSignal(
            signal_id="custom_signal",
            description="custom",
            aggregation_window_seconds=30,
            baseline_mean=1.0,
            baseline_stddev=0.5,
        )
        registry.register(custom)
        assert "custom_signal" in registry
        assert registry.get("custom_signal") is custom

    def test_register_rejects_duplicate(self) -> None:
        registry = DriftSignalRegistry()
        dup = DriftSignal(
            signal_id=SIGNAL_TOOL_CALL_RATE_PER_AGENT,
            description="duplicate",
            aggregation_window_seconds=60,
            baseline_mean=0.0,
            baseline_stddev=1.0,
        )
        with pytest.raises(ValueError, match="already registered"):
            registry.register(dup)

    def test_register_rejects_non_drift_signal(self) -> None:
        registry = DriftSignalRegistry()
        with pytest.raises(TypeError, match="DriftSignal"):
            registry.register("not a signal")  # type: ignore[arg-type]

    def test_register_rejects_empty_id(self) -> None:
        registry = DriftSignalRegistry(seed_defaults=False)
        with pytest.raises(ValueError, match="non-empty"):
            registry.register(
                DriftSignal(
                    signal_id="",
                    description="x",
                    aggregation_window_seconds=60,
                    baseline_mean=0.0,
                    baseline_stddev=1.0,
                )
            )

    def test_register_rejects_zero_window(self) -> None:
        registry = DriftSignalRegistry(seed_defaults=False)
        with pytest.raises(ValueError, match="aggregation_window_seconds"):
            registry.register(
                DriftSignal(
                    signal_id="x",
                    description="x",
                    aggregation_window_seconds=0,
                    baseline_mean=0.0,
                    baseline_stddev=1.0,
                )
            )

    def test_register_rejects_negative_stddev(self) -> None:
        registry = DriftSignalRegistry(seed_defaults=False)
        with pytest.raises(ValueError, match="baseline_stddev"):
            registry.register(
                DriftSignal(
                    signal_id="x",
                    description="x",
                    aggregation_window_seconds=60,
                    baseline_mean=0.0,
                    baseline_stddev=-1.0,
                )
            )


class TestLookup:
    def test_get_known_signal(self) -> None:
        registry = DriftSignalRegistry()
        signal = registry.get(SIGNAL_DENIAL_RATE_PER_AGENT)
        assert signal.signal_id == SIGNAL_DENIAL_RATE_PER_AGENT

    def test_get_missing_raises_keyerror(self) -> None:
        registry = DriftSignalRegistry()
        with pytest.raises(KeyError, match="not registered"):
            registry.get("nonexistent_signal")

    def test_contains_returns_false_for_non_string(self) -> None:
        registry = DriftSignalRegistry()
        assert 123 not in registry  # type: ignore[operator]
        assert None not in registry  # type: ignore[operator]


class TestUpdateBaseline:
    def test_update_baseline_replaces_in_place(self) -> None:
        registry = DriftSignalRegistry()
        original = registry.get(SIGNAL_AVERAGE_COMPROMISE_SCORE)
        replacement = registry.update_baseline(
            signal_id=SIGNAL_AVERAGE_COMPROMISE_SCORE,
            baseline_mean=0.05,
            baseline_stddev=0.02,
        )
        assert replacement.baseline_mean == 0.05
        assert replacement.baseline_stddev == 0.02
        # Description and window preserved.
        assert replacement.description == original.description
        assert (
            replacement.aggregation_window_seconds
            == original.aggregation_window_seconds
        )
        # New signal is in the registry.
        assert (
            registry.get(SIGNAL_AVERAGE_COMPROMISE_SCORE).baseline_mean == 0.05
        )

    def test_update_baseline_rejects_zero_stddev(self) -> None:
        registry = DriftSignalRegistry()
        with pytest.raises(ValueError, match="positive"):
            registry.update_baseline(
                signal_id=SIGNAL_AVERAGE_COMPROMISE_SCORE,
                baseline_mean=0.0,
                baseline_stddev=0.0,
            )

    def test_update_baseline_unknown_signal_raises(self) -> None:
        registry = DriftSignalRegistry()
        with pytest.raises(KeyError):
            registry.update_baseline(
                signal_id="unknown",
                baseline_mean=0.0,
                baseline_stddev=1.0,
            )


class TestIteration:
    def test_iteration_yields_all_signals(self) -> None:
        registry = DriftSignalRegistry()
        seen = list(registry)
        assert len(seen) == 7
        assert all(isinstance(s, DriftSignal) for s in seen)

    def test_iteration_is_sorted(self) -> None:
        registry = DriftSignalRegistry()
        ids = [s.signal_id for s in registry]
        assert ids == sorted(ids)


class TestSerialization:
    def test_to_dict_shape(self) -> None:
        registry = DriftSignalRegistry()
        d = registry.to_dict()
        assert len(d) == 7
        for sid, payload in d.items():
            assert payload["signal_id"] == sid
            assert "description" in payload
            assert "baseline_mean" in payload
            assert "baseline_stddev" in payload

    def test_to_dict_is_sorted(self) -> None:
        registry = DriftSignalRegistry()
        d = registry.to_dict()
        keys = list(d)
        assert keys == sorted(keys)

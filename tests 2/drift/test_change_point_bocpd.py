"""
Tests for tex.drift.change_point — BOCPD path.

Acceptance: median detection delay ≤ 100 steps on synthetic
distribution-shift fixtures (loose bound on AAF's 71-step claim,
arXiv:2512.18561).
"""

from __future__ import annotations

import logging
import random
import statistics
from datetime import UTC, datetime

import pytest

from tex.drift import ChangePointDetector, ChangePointEvent
from tex.drift._bocpd import (
    BOCPDStep,
    _NormalGammaSufficient,
    _logsumexp,
    bocpd_step,
    make_default_state,
)


# Suppress JSON telemetry log spam during tests.
@pytest.fixture(autouse=True)
def _silence_telemetry():
    logging.getLogger("tex").setLevel(logging.CRITICAL)


# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------

CHANGE_AT = 200
LIMIT = 600
N_SEEDS = 30


def _gaussian_shift_stream(
    seed: int, *, change_at: int = CHANGE_AT, limit: int = LIMIT
) -> list[float]:
    """N(0,1) for t < change_at, N(3,1) for t ≥ change_at."""
    rng = random.Random(seed)
    return [
        rng.gauss(0.0, 1.0) if t < change_at else rng.gauss(3.0, 1.0)
        for t in range(limit)
    ]


def _stationary_stream(seed: int, *, limit: int = LIMIT) -> list[float]:
    rng = random.Random(seed)
    return [rng.gauss(0.0, 1.0) for _ in range(limit)]


# ---------------------------------------------------------------------
# Construction / parameter validation
# ---------------------------------------------------------------------


class TestConstruction:
    def test_default_construction_is_bocpd(self) -> None:
        det = ChangePointDetector()
        assert det.detector_kind == "bocpd"

    def test_rejects_invalid_baseline_window(self) -> None:
        with pytest.raises(ValueError):
            ChangePointDetector(baseline_window_steps=0)

    def test_rejects_out_of_range_threshold(self) -> None:
        with pytest.raises(ValueError):
            ChangePointDetector(detection_threshold=0.0)
        with pytest.raises(ValueError):
            ChangePointDetector(detection_threshold=20.0)

    def test_rejects_invalid_warmup(self) -> None:
        with pytest.raises(ValueError):
            ChangePointDetector(warmup_steps=0)

    def test_rejects_unknown_detector_kind(self) -> None:
        with pytest.raises(ValueError, match="bocpd.*cusum"):
            ChangePointDetector(detector_kind="ewma")  # type: ignore[arg-type]

    def test_ledger_and_provenance_must_be_paired(self) -> None:
        # Both required together.
        with pytest.raises(ValueError, match="together"):
            ChangePointDetector(ledger=object())
        with pytest.raises(ValueError, match="together"):
            ChangePointDetector(provenance=object())


# ---------------------------------------------------------------------
# Detection delay — ACCEPTANCE CRITERION
# ---------------------------------------------------------------------


class TestDetectionDelay:
    """The ≤ 100-step median detection delay acceptance criterion."""

    def test_median_delay_within_loose_aaf_bound(self) -> None:
        delays: list[int] = []
        for seed in range(N_SEEDS):
            stream = _gaussian_shift_stream(seed)
            det = ChangePointDetector()
            detected_at: int | None = None
            for t, x in enumerate(stream):
                fired = det.update(
                    signal_name="s", signal_value=x, at=datetime.now(UTC)
                )
                if fired and t >= CHANGE_AT and detected_at is None:
                    detected_at = t
                    break
            if detected_at is not None:
                delays.append(detected_at - CHANGE_AT)
        # Acceptance: median delay ≤ 100 (loose bound on AAF's 71-step claim).
        assert len(delays) == N_SEEDS, (
            f"expected detection on every seed; got {len(delays)}/{N_SEEDS}"
        )
        median = statistics.median(delays)
        assert median <= 100, (
            f"median detection delay {median} exceeds 100-step acceptance bound"
        )

    def test_detection_score_above_threshold(self) -> None:
        """Each fire must have score ≥ the configured threshold."""
        det = ChangePointDetector()
        stream = _gaussian_shift_stream(0)
        for t, x in enumerate(stream):
            det.update(signal_name="s", signal_value=x, at=datetime.now(UTC))
        for cp_event in det.detections:
            assert cp_event.change_point_score >= det.detection_threshold


# ---------------------------------------------------------------------
# False alarm rate
# ---------------------------------------------------------------------


class TestFalseAlarmRate:
    def test_low_false_alarm_rate_on_stationary_data(self) -> None:
        """Mean false alarms over 1000 steps of N(0,1) should stay small."""
        false_alarms: list[int] = []
        for seed in range(10):
            det = ChangePointDetector()
            stream = _stationary_stream(seed + 1000, limit=1000)
            count = 0
            for x in stream:
                if det.update(
                    signal_name="s", signal_value=x, at=datetime.now(UTC)
                ):
                    count += 1
            false_alarms.append(count)
        mean_fa = statistics.mean(false_alarms)
        # Tolerate a small handful of false positives; mean should be < 3.
        assert mean_fa < 3.0, (
            f"mean false-alarm count {mean_fa} too high on stationary data"
        )


# ---------------------------------------------------------------------
# Anti-flutter / restart behavior
# ---------------------------------------------------------------------


class TestAntiFlutter:
    def test_no_double_fire_within_warmup_window(self) -> None:
        """After firing, the detector should not re-fire within `warmup_steps`."""
        det = ChangePointDetector(warmup_steps=30)
        stream = _gaussian_shift_stream(0)
        fire_steps: list[int] = []
        for t, x in enumerate(stream):
            if det.update(signal_name="s", signal_value=x, at=datetime.now(UTC)):
                fire_steps.append(t)
        # Successive fires on the same signal must be at least warmup_steps apart.
        for prev, cur in zip(fire_steps, fire_steps[1:]):
            assert cur - prev >= 30, (
                f"Fires too close: {prev} → {cur} "
                f"(< warmup window of 30 steps)"
            )


# ---------------------------------------------------------------------
# Per-signal isolation
# ---------------------------------------------------------------------


class TestPerSignalIsolation:
    def test_signals_have_independent_state(self) -> None:
        det = ChangePointDetector()
        stream_a = _gaussian_shift_stream(0)
        stream_b = _stationary_stream(99, limit=LIMIT)
        for t in range(LIMIT):
            det.update(
                signal_name="signal_a",
                signal_value=stream_a[t],
                at=datetime.now(UTC),
            )
            det.update(
                signal_name="signal_b",
                signal_value=stream_b[t],
                at=datetime.now(UTC),
            )
        # signal_a should fire (real change point); signal_b should not (stationary).
        a_fires = [d for d in det.detections if d.signal_name == "signal_a"]
        b_fires = [d for d in det.detections if d.signal_name == "signal_b"]
        assert len(a_fires) >= 1
        assert len(b_fires) <= 2  # tolerate occasional false alarm
        # State counters separate.
        assert det.signal_step_count("signal_a") == LIMIT
        assert det.signal_step_count("signal_b") == LIMIT


# ---------------------------------------------------------------------
# Detection event payload
# ---------------------------------------------------------------------


class TestDetectionEvent:
    def test_detection_event_is_frozen(self) -> None:
        det = ChangePointDetector()
        for x in _gaussian_shift_stream(0):
            det.update(signal_name="s", signal_value=x, at=datetime.now(UTC))
        assert det.detections, "expected at least one detection"
        event = det.detections[0]
        assert isinstance(event, ChangePointEvent)
        with pytest.raises((ValueError, TypeError)):
            # pydantic frozen models reject attribute assignment.
            event.signal_name = "tampered"  # type: ignore[misc]

    def test_detection_event_carries_detector_kind(self) -> None:
        det = ChangePointDetector()
        for x in _gaussian_shift_stream(0):
            det.update(signal_name="s", signal_value=x, at=datetime.now(UTC))
        for d in det.detections:
            assert d.detector_kind == "bocpd"

    def test_warmup_suppresses_pre_warmup_fires(self) -> None:
        # All fires should occur after the warmup window.
        det = ChangePointDetector(warmup_steps=30)
        for x in _gaussian_shift_stream(0):
            det.update(signal_name="s", signal_value=x, at=datetime.now(UTC))
        for d in det.detections:
            assert d.step_index > 30


# ---------------------------------------------------------------------
# BOCPD numerical core — directly
# ---------------------------------------------------------------------


class TestBOCPDCore:
    def test_logsumexp_handles_empty(self) -> None:
        import math
        assert _logsumexp([]) == -math.inf

    def test_logsumexp_handles_single(self) -> None:
        assert abs(_logsumexp([1.5]) - 1.5) < 1e-12

    def test_logsumexp_against_naive(self) -> None:
        import math
        values = [-2.0, -1.0, 0.5, 1.0]
        naive = math.log(sum(math.exp(v) for v in values))
        assert abs(_logsumexp(values) - naive) < 1e-10

    def test_logsumexp_handles_minus_inf(self) -> None:
        import math
        # All -inf → -inf; mixed -inf → drops out.
        assert _logsumexp([-math.inf, -math.inf]) == -math.inf
        assert abs(_logsumexp([-math.inf, 0.0]) - 0.0) < 1e-10

    def test_normal_gamma_predictive_is_finite(self) -> None:
        ng = _NormalGammaSufficient(mu=0.0, kappa=0.01, alpha=1.0, beta=1.0)
        log_p = ng.log_predictive(0.5)
        assert log_p == pytest.approx(log_p)  # not NaN
        assert log_p > -1e6

    def test_normal_gamma_update_increments_kappa(self) -> None:
        ng = _NormalGammaSufficient(mu=0.0, kappa=0.01, alpha=1.0, beta=1.0)
        ng2 = ng.updated_with(2.0)
        assert ng2.kappa == 0.01 + 1.0
        assert ng2.alpha == 1.0 + 0.5
        # Posterior mean shifts toward the observation.
        assert ng2.mu > ng.mu

    def test_make_state_rejects_invalid_hazard(self) -> None:
        with pytest.raises(ValueError, match="hazard_lambda"):
            make_default_state(hazard_lambda=0.5)

    def test_make_state_rejects_invalid_top_k(self) -> None:
        with pytest.raises(ValueError, match="top_k"):
            make_default_state(top_k=1)

    def test_make_state_rejects_invalid_prior(self) -> None:
        with pytest.raises(ValueError, match="positive"):
            make_default_state(prior_kappa=-1.0)

    def test_step_returns_frozen_report(self) -> None:
        state = make_default_state()
        result = bocpd_step(state, 1.0)
        assert isinstance(result, BOCPDStep)
        assert result.step_index == 1
        # Frozen — mutation rejected.
        with pytest.raises((ValueError, AttributeError)):
            result.step_index = 2  # type: ignore[misc]

    def test_step_keeps_support_under_top_k(self) -> None:
        state = make_default_state(top_k=10)
        for x in _stationary_stream(0, limit=100):
            result = bocpd_step(state, x)
        assert result.n_active_run_lengths <= 10

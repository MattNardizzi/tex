"""
Tests for the adaptive-CUSUM detector path.

CUSUM is the actual detector used by AAF (arXiv:2512.18561 §5.3) to
achieve its 71-step empirical median delay; we ship it as an alternative
detector_kind alongside the primary BOCPD.
"""

from __future__ import annotations

import logging
import random
import statistics
from datetime import UTC, datetime

import pytest

from tex.drift import ChangePointDetector
from tex.drift._cusum import (
    CUSUMState,
    CUSUMStep,
    cusum_step,
    make_default_cusum_state,
)


@pytest.fixture(autouse=True)
def _silence_telemetry():
    logging.getLogger("tex").setLevel(logging.CRITICAL)


# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------


def _gaussian_shift_stream(seed: int, change_at: int = 200, limit: int = 600):
    rng = random.Random(seed)
    return [
        rng.gauss(0.0, 1.0) if t < change_at else rng.gauss(3.0, 1.0)
        for t in range(limit)
    ]


# ---------------------------------------------------------------------
# Detection delay
# ---------------------------------------------------------------------


class TestCUSUMDetectionDelay:
    def test_cusum_median_delay_within_bound(self) -> None:
        N_SEEDS = 30
        CHANGE_AT = 200
        delays: list[int] = []
        for seed in range(N_SEEDS):
            stream = _gaussian_shift_stream(seed)
            det = ChangePointDetector(
                detector_kind="cusum", detection_threshold=1.0
            )
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
        assert len(delays) >= int(0.9 * N_SEEDS), (
            f"CUSUM detected only {len(delays)}/{N_SEEDS}"
        )
        median = statistics.median(delays)
        # Same loose 100-step bound. CUSUM tuned with k=0.5/h=5 typically
        # detects faster than BOCPD on shift-in-mean.
        assert median <= 100


class TestCUSUMState:
    def test_state_construction_validates(self) -> None:
        with pytest.raises(ValueError, match="k"):
            make_default_cusum_state(k=0.0)
        with pytest.raises(ValueError, match="h"):
            make_default_cusum_state(h=-1.0)
        with pytest.raises(ValueError, match="ewma_alpha"):
            make_default_cusum_state(ewma_alpha=1.5)
        with pytest.raises(ValueError, match="warmup"):
            make_default_cusum_state(warmup_steps=0)

    def test_warmup_suppresses_alarms(self) -> None:
        state = make_default_cusum_state(warmup_steps=30)
        # Pump in 10 large positive values during warmup — must not fire.
        for _ in range(10):
            result = cusum_step(state, 10.0)
            assert not result.fired

    def test_alarm_resets_statistics(self) -> None:
        state = make_default_cusum_state(warmup_steps=10, h=2.0, k=0.5)
        rng = random.Random(0)
        # Burn in
        for _ in range(15):
            cusum_step(state, rng.gauss(0.0, 1.0))
        # Now feed a sustained shift
        last: CUSUMStep | None = None
        fired = False
        for _ in range(50):
            last = cusum_step(state, 5.0)
            if last.fired:
                fired = True
                # Statistics reset on alarm — both sides drop to 0.
                assert last.s_pos == 0.0
                assert last.s_neg == 0.0
                break
        assert fired
        assert isinstance(last, CUSUMStep)


class TestCUSUMNumerics:
    def test_no_alarms_on_pure_noise(self) -> None:
        # Stationary N(0,1) for 500 steps should produce few alarms with
        # default tuning (k=0.5, h=5).
        rng = random.Random(0)
        state = make_default_cusum_state()
        alarms = 0
        for _ in range(500):
            r = cusum_step(state, rng.gauss(0.0, 1.0))
            if r.fired:
                alarms += 1
        assert alarms <= 2  # comfortable bound

    def test_z_score_zero_during_warmup(self) -> None:
        state = make_default_cusum_state(warmup_steps=10)
        result = cusum_step(state, 1.0)
        assert result.z_score == 0.0
        assert result.change_point_score == 0.0

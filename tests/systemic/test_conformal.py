"""Tests for Thread 9 anytime-valid conformal calibration."""

from __future__ import annotations

import math

import pytest

from tex.systemic._conformal import CalibrationBuffer, band_for_prediction


def test_buffer_starts_empty() -> None:
    buf = CalibrationBuffer()
    assert buf.n == 0


def test_buffer_min_size_enforced() -> None:
    with pytest.raises(ValueError, match="max_size must be"):
        CalibrationBuffer(max_size=4)


def test_buffer_drops_oldest_at_capacity() -> None:
    buf = CalibrationBuffer(max_size=16)
    for i in range(20):
        buf.add(float(i))
    assert buf.n == 16
    # Oldest dropped — newest scores are 4..19.
    snap = buf.snapshot()
    assert min(snap) == 4.0
    assert max(snap) == 19.0


def test_quantile_cold_start_is_conservative() -> None:
    buf = CalibrationBuffer()
    # No data → wide band.
    q = buf.anytime_valid_quantile(alpha=0.1)
    assert q >= 1.0


def test_quantile_shrinks_with_more_data() -> None:
    buf = CalibrationBuffer(max_size=1000)
    for _ in range(50):
        buf.add(0.1)
    q1 = buf.anytime_valid_quantile(alpha=0.1)
    for _ in range(500):
        buf.add(0.1)
    q2 = buf.anytime_valid_quantile(alpha=0.1)
    # Epsilon term shrinks as 1/sqrt(n) → q2 < q1.
    assert q2 < q1


def test_quantile_rejects_invalid_alpha() -> None:
    buf = CalibrationBuffer()
    with pytest.raises(ValueError, match="alpha must be"):
        buf.anytime_valid_quantile(alpha=0.0)
    with pytest.raises(ValueError, match="alpha must be"):
        buf.anytime_valid_quantile(alpha=1.5)


def test_band_is_clamped_to_unit_interval() -> None:
    buf = CalibrationBuffer()
    band = band_for_prediction(point=0.9, buffer=buf, alpha=0.1)
    assert 0.0 <= band.lower <= band.point <= band.upper <= 1.0


def test_band_point_clamped() -> None:
    buf = CalibrationBuffer()
    high = band_for_prediction(point=1.5, buffer=buf, alpha=0.1)
    assert high.point == 1.0
    low = band_for_prediction(point=-0.5, buffer=buf, alpha=0.1)
    assert low.point == 0.0


def test_nan_or_inf_silently_dropped() -> None:
    buf = CalibrationBuffer()
    buf.add(float("nan"))
    buf.add(float("inf"))
    buf.add(float("-inf"))
    assert buf.n == 0


def test_band_width_is_decreasing_in_n() -> None:
    buf_small = CalibrationBuffer()
    buf_big = CalibrationBuffer()
    for _ in range(20):
        buf_small.add(0.15)
    for _ in range(500):
        buf_big.add(0.15)
    b_small = band_for_prediction(point=0.5, buffer=buf_small, alpha=0.1)
    b_big = band_for_prediction(point=0.5, buffer=buf_big, alpha=0.1)
    assert b_big.width < b_small.width


def test_negative_scores_clamped_to_zero() -> None:
    buf = CalibrationBuffer()
    buf.add(-0.5)
    assert buf.snapshot() == (0.0,)

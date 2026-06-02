"""Tests for the calibration safety guard: bounds, deltas, rate limits."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from dataclasses import replace

import pytest

from tex.learning.calibration_safety import (
    CalibrationSafetyGuard,
    HARD_FORBID_CEILING,
    HARD_PERMIT_FLOOR,
    HARD_MIN_ABSTAIN_BAND,
)
from tex.learning.calibrator import CalibrationRecommendation
from tex.learning.outcomes import OutcomeSummary
from tex.policies.defaults import build_default_policy


def _summary() -> OutcomeSummary:
    return OutcomeSummary(
        total=100,
        correct_permits=80,
        false_permits=2,
        correct_forbids=10,
        false_forbids=2,
        abstain_reviews=5,
        unknown=1,
    )


def _recommendation(
    *,
    permit_delta: float = 0.0,
    forbid_delta: float = 0.0,
    confidence_delta: float = 0.0,
    current_permit: float = 0.30,
    current_forbid: float = 0.65,
    current_min_conf: float = 0.65,
) -> CalibrationRecommendation:
    return CalibrationRecommendation(
        current_permit_threshold=current_permit,
        recommended_permit_threshold=current_permit + permit_delta,
        current_forbid_threshold=current_forbid,
        recommended_forbid_threshold=current_forbid + forbid_delta,
        current_minimum_confidence=current_min_conf,
        recommended_minimum_confidence=current_min_conf + confidence_delta,
        summary=_summary(),
        reasons=("test",),
        false_permit_rate=0.02,
        false_forbid_rate=0.02,
        abstain_review_rate=0.05,
        unknown_rate=0.01,
        sample_weight=0.8,
        permit_threshold_delta=permit_delta,
        forbid_threshold_delta=forbid_delta,
        minimum_confidence_delta=confidence_delta,
    )


# ── per-cycle deltas ──────────────────────────────────────────────────────


def test_permit_delta_clipped_to_max() -> None:
    guard = CalibrationSafetyGuard(max_permit_delta=0.04)
    rec = _recommendation(permit_delta=0.10)
    decision = guard.evaluate(policy=build_default_policy(), recommendation=rec)
    moved = (
        decision.clipped_recommendation.recommended_permit_threshold
        - decision.clipped_recommendation.current_permit_threshold
    )
    assert abs(moved) <= 0.041
    assert decision.bounds_violated


def test_no_clip_when_delta_inside_cap() -> None:
    guard = CalibrationSafetyGuard(max_permit_delta=0.04)
    rec = _recommendation(permit_delta=0.02)
    decision = guard.evaluate(policy=build_default_policy(), recommendation=rec)
    moved = (
        decision.clipped_recommendation.recommended_permit_threshold
        - decision.clipped_recommendation.current_permit_threshold
    )
    assert abs(moved) == pytest.approx(0.02, abs=1e-4)


# ── hard bounds ───────────────────────────────────────────────────────────


def test_recommendation_below_permit_floor_clamps_to_floor() -> None:
    guard = CalibrationSafetyGuard()
    # Try to push permit threshold to 0.02 — well below HARD_PERMIT_FLOOR=0.10
    rec = _recommendation(current_permit=0.12, permit_delta=-0.10)
    decision = guard.evaluate(policy=build_default_policy(), recommendation=rec)
    assert (
        decision.clipped_recommendation.recommended_permit_threshold
        >= HARD_PERMIT_FLOOR
    )


def test_abstain_band_preserved_when_thresholds_collide() -> None:
    guard = CalibrationSafetyGuard()
    # Push permit up and forbid down so they collapse the band.
    rec = _recommendation(
        current_permit=0.40, permit_delta=0.04,  # → 0.44
        current_forbid=0.50, forbid_delta=-0.04,  # → 0.46
    )
    decision = guard.evaluate(policy=build_default_policy(), recommendation=rec)
    spread = (
        decision.clipped_recommendation.recommended_forbid_threshold
        - decision.clipped_recommendation.recommended_permit_threshold
    )
    assert spread >= HARD_MIN_ABSTAIN_BAND


# ── rate limit ────────────────────────────────────────────────────────────


def test_rate_limit_blocks_back_to_back_calibrations() -> None:
    clock_value = [datetime(2026, 1, 1, tzinfo=UTC)]
    guard = CalibrationSafetyGuard(
        min_interval=timedelta(hours=1),
        clock=lambda: clock_value[0],
    )
    rec = _recommendation(permit_delta=0.02)
    policy = build_default_policy()

    first = guard.evaluate(policy=policy, recommendation=rec)
    assert first.allowed
    guard.commit(
        policy_id=policy.policy_id,
        applied_recommendation=first.clipped_recommendation,
    )

    # Try again 30 min later — should rate-limit.
    clock_value[0] = clock_value[0] + timedelta(minutes=30)
    second = guard.evaluate(policy=policy, recommendation=rec)
    assert not second.allowed
    assert second.rate_limited


# ── cumulative budget ─────────────────────────────────────────────────────


def test_cumulative_budget_exhausted_after_repeated_movement() -> None:
    clock_value = [datetime(2026, 1, 1, tzinfo=UTC)]
    guard = CalibrationSafetyGuard(
        cumulative_budget=0.10,
        cumulative_window=timedelta(hours=24),
        min_interval=timedelta(minutes=1),
        clock=lambda: clock_value[0],
    )
    policy = build_default_policy()

    # Apply 0.04, 0.04, then try 0.04 — total 0.12 exceeds the 0.10 budget.
    for delta in (0.04, 0.04):
        rec = _recommendation(permit_delta=delta)
        decision = guard.evaluate(policy=policy, recommendation=rec)
        assert decision.allowed
        guard.commit(
            policy_id=policy.policy_id,
            applied_recommendation=decision.clipped_recommendation,
        )
        clock_value[0] = clock_value[0] + timedelta(minutes=2)

    rec = _recommendation(permit_delta=0.04)
    final = guard.evaluate(policy=policy, recommendation=rec)
    assert not final.allowed
    assert final.cumulative_budget_exhausted

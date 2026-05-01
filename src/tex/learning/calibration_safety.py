"""
Calibration safety bounds and rate limiting.

Two layers of protection sit between a calibration recommendation and a
policy update:

  1. Rate limiting (item 5). Calibration of a given policy_id is only
     allowed once per ``min_interval``. A flood of feedback cannot
     produce a flood of policy updates.

  2. Hard bounds (item 6). Recommendations that would push the policy
     outside the absolute safe zone are clipped or rejected outright.
     This is independent of the calibrator's own internal clamps —
     those are about reasonable behavior, these are about catastrophic
     prevention.

The bounds are deliberately stricter than the calibrator's own caps. The
calibrator might happily move permit_threshold by 0.05 in one pass, but
across three back-to-back proposals could drift 0.15. The safety layer
caps cumulative movement per day.

Result of every safety check is a ``SafetyDecision`` carrying:
  - allowed: whether the proposal may proceed
  - clipped_recommendation: the bounded version (or the original when
    no clipping was needed)
  - reasons: human-readable explanations for any change

Note: this module does NOT make policy decisions on its own. It evaluates
proposals. The proposal store + approval workflow consumes the decision.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from threading import RLock

from tex.domain.policy import PolicySnapshot
from tex.learning.calibrator import CalibrationRecommendation


# Hard floors and ceilings — the policy must never leave these even if
# the calibrator + reputation system + replay all agree.
HARD_PERMIT_FLOOR = 0.10
HARD_PERMIT_CEILING = 0.55
HARD_FORBID_FLOOR = 0.45
HARD_FORBID_CEILING = 0.92
HARD_MIN_CONFIDENCE_FLOOR = 0.45
HARD_MIN_CONFIDENCE_CEILING = 0.92
HARD_MIN_ABSTAIN_BAND = 0.10

# Per-cycle deltas — how much a single proposal can move thresholds.
DEFAULT_MAX_PERMIT_DELTA = 0.04
DEFAULT_MAX_FORBID_DELTA = 0.04
DEFAULT_MAX_CONFIDENCE_DELTA = 0.03

# Cumulative-movement budget over a sliding window. Default: a policy
# cannot drift more than 0.10 in any threshold over 24h, regardless of
# how many proposals approve.
DEFAULT_CUMULATIVE_BUDGET = 0.10
DEFAULT_CUMULATIVE_WINDOW = timedelta(hours=24)

# Minimum interval between successful calibrations of the same policy_id.
DEFAULT_MIN_INTERVAL = timedelta(hours=1)


@dataclass(frozen=True, slots=True)
class SafetyDecision:
    """Result of a safety evaluation."""

    allowed: bool
    clipped_recommendation: CalibrationRecommendation
    reasons: tuple[str, ...]
    rate_limited: bool = False
    bounds_violated: bool = False
    cumulative_budget_exhausted: bool = False


@dataclass(slots=True)
class _PolicyMovementHistory:
    """Tracks per-policy_id cumulative movement for the rolling window."""

    events: list[tuple[datetime, float, float, float]] = field(default_factory=list)
    last_calibrated_at: datetime | None = None


class CalibrationSafetyGuard:
    """
    Enforces hard bounds, per-cycle deltas, cumulative-movement budgets,
    and rate-limits on calibration.

    Thread-safe; uses an internal RLock around the per-policy history.
    """

    __slots__ = (
        "_lock",
        "_history",
        "_max_permit_delta",
        "_max_forbid_delta",
        "_max_confidence_delta",
        "_cumulative_budget",
        "_cumulative_window",
        "_min_interval",
        "_clock",
    )

    def __init__(
        self,
        *,
        max_permit_delta: float = DEFAULT_MAX_PERMIT_DELTA,
        max_forbid_delta: float = DEFAULT_MAX_FORBID_DELTA,
        max_confidence_delta: float = DEFAULT_MAX_CONFIDENCE_DELTA,
        cumulative_budget: float = DEFAULT_CUMULATIVE_BUDGET,
        cumulative_window: timedelta = DEFAULT_CUMULATIVE_WINDOW,
        min_interval: timedelta = DEFAULT_MIN_INTERVAL,
        clock: callable | None = None,
    ) -> None:
        if not 0.0 < max_permit_delta <= 0.20:
            raise ValueError("max_permit_delta must be in (0.0, 0.20]")
        if not 0.0 < max_forbid_delta <= 0.20:
            raise ValueError("max_forbid_delta must be in (0.0, 0.20]")
        if not 0.0 < max_confidence_delta <= 0.10:
            raise ValueError("max_confidence_delta must be in (0.0, 0.10]")
        if not 0.0 < cumulative_budget <= 0.30:
            raise ValueError("cumulative_budget must be in (0.0, 0.30]")
        if cumulative_window.total_seconds() <= 0:
            raise ValueError("cumulative_window must be positive")
        if min_interval.total_seconds() < 0:
            raise ValueError("min_interval must be >= 0")

        self._lock = RLock()
        self._history: dict[str, _PolicyMovementHistory] = {}
        self._max_permit_delta = max_permit_delta
        self._max_forbid_delta = max_forbid_delta
        self._max_confidence_delta = max_confidence_delta
        self._cumulative_budget = cumulative_budget
        self._cumulative_window = cumulative_window
        self._min_interval = min_interval
        self._clock = clock or (lambda: datetime.now(UTC))

    def evaluate(
        self,
        *,
        policy: PolicySnapshot,
        recommendation: CalibrationRecommendation,
    ) -> SafetyDecision:
        """
        Evaluate a recommendation against the safety bounds and rate-limits.

        Returns a ``SafetyDecision`` with a clipped recommendation. The
        clipped form is never less safe than the original — it can only
        reduce movement, never enlarge it.
        """
        reasons: list[str] = []
        rate_limited = False
        bounds_violated = False
        budget_exhausted = False

        now = self._clock()
        with self._lock:
            history = self._history.setdefault(
                policy.policy_id, _PolicyMovementHistory()
            )
            history.events = [
                event
                for event in history.events
                if event[0] >= now - self._cumulative_window
            ]

            # Rate limit: refuse calibrations of the same policy_id that
            # fire too close together.
            if (
                history.last_calibrated_at is not None
                and now - history.last_calibrated_at < self._min_interval
            ):
                rate_limited = True
                reasons.append(
                    f"Policy '{policy.policy_id}' was calibrated "
                    f"{(now - history.last_calibrated_at).total_seconds() / 60:.1f} "
                    "minutes ago; minimum interval not yet elapsed."
                )

            # Per-cycle deltas: clip any movement that exceeds the cap.
            permit_delta = (
                recommendation.recommended_permit_threshold
                - recommendation.current_permit_threshold
            )
            forbid_delta = (
                recommendation.recommended_forbid_threshold
                - recommendation.current_forbid_threshold
            )
            confidence_delta = (
                recommendation.recommended_minimum_confidence
                - recommendation.current_minimum_confidence
            )

            permit_delta = _clip_delta(permit_delta, self._max_permit_delta)
            forbid_delta = _clip_delta(forbid_delta, self._max_forbid_delta)
            confidence_delta = _clip_delta(
                confidence_delta, self._max_confidence_delta
            )

            if permit_delta != (
                recommendation.recommended_permit_threshold
                - recommendation.current_permit_threshold
            ):
                reasons.append(
                    f"Permit-threshold delta clipped to ±{self._max_permit_delta}."
                )
                bounds_violated = True
            if forbid_delta != (
                recommendation.recommended_forbid_threshold
                - recommendation.current_forbid_threshold
            ):
                reasons.append(
                    f"Forbid-threshold delta clipped to ±{self._max_forbid_delta}."
                )
                bounds_violated = True
            if confidence_delta != (
                recommendation.recommended_minimum_confidence
                - recommendation.current_minimum_confidence
            ):
                reasons.append(
                    "Minimum-confidence delta clipped to "
                    f"±{self._max_confidence_delta}."
                )
                bounds_violated = True

            # Cumulative-movement budget over the sliding window.
            sum_abs_permit = (
                sum(abs(e[1]) for e in history.events) + abs(permit_delta)
            )
            sum_abs_forbid = (
                sum(abs(e[2]) for e in history.events) + abs(forbid_delta)
            )
            sum_abs_conf = (
                sum(abs(e[3]) for e in history.events) + abs(confidence_delta)
            )
            if (
                sum_abs_permit > self._cumulative_budget
                or sum_abs_forbid > self._cumulative_budget
                or sum_abs_conf > self._cumulative_budget
            ):
                budget_exhausted = True
                reasons.append(
                    "Cumulative threshold movement over the rolling window "
                    f"would exceed the {self._cumulative_budget} budget; "
                    "recommendation rejected."
                )

            # Hard bounds — clip into the absolute safe zone.
            permit_after = _clamp(
                recommendation.current_permit_threshold + permit_delta,
                HARD_PERMIT_FLOOR,
                HARD_PERMIT_CEILING,
            )
            forbid_after = _clamp(
                recommendation.current_forbid_threshold + forbid_delta,
                HARD_FORBID_FLOOR,
                HARD_FORBID_CEILING,
            )
            confidence_after = _clamp(
                recommendation.current_minimum_confidence + confidence_delta,
                HARD_MIN_CONFIDENCE_FLOOR,
                HARD_MIN_CONFIDENCE_CEILING,
            )

            # Preserve the abstain band even after clipping.
            if forbid_after - permit_after < HARD_MIN_ABSTAIN_BAND:
                forbid_after = min(
                    HARD_FORBID_CEILING,
                    permit_after + HARD_MIN_ABSTAIN_BAND,
                )
                if forbid_after - permit_after < HARD_MIN_ABSTAIN_BAND:
                    permit_after = max(
                        HARD_PERMIT_FLOOR,
                        forbid_after - HARD_MIN_ABSTAIN_BAND,
                    )
                reasons.append(
                    "Adjusted thresholds to preserve the minimum abstain "
                    f"band of {HARD_MIN_ABSTAIN_BAND}."
                )

            if permit_after != (
                recommendation.current_permit_threshold + permit_delta
            ):
                reasons.append(
                    f"Permit threshold clamped to hard bounds "
                    f"[{HARD_PERMIT_FLOOR}, {HARD_PERMIT_CEILING}]."
                )
                bounds_violated = True
            if forbid_after != (
                recommendation.current_forbid_threshold + forbid_delta
            ):
                reasons.append(
                    f"Forbid threshold clamped to hard bounds "
                    f"[{HARD_FORBID_FLOOR}, {HARD_FORBID_CEILING}]."
                )
                bounds_violated = True
            if confidence_after != (
                recommendation.current_minimum_confidence + confidence_delta
            ):
                reasons.append(
                    "Minimum confidence clamped to hard bounds "
                    f"[{HARD_MIN_CONFIDENCE_FLOOR}, {HARD_MIN_CONFIDENCE_CEILING}]."
                )
                bounds_violated = True

            allowed = not (rate_limited or budget_exhausted)

            clipped = recommendation.__class__(
                **{
                    **{
                        f.name: getattr(recommendation, f.name)
                        for f in recommendation.__dataclass_fields__.values()
                    },
                    "recommended_permit_threshold": round(permit_after, 4),
                    "recommended_forbid_threshold": round(forbid_after, 4),
                    "recommended_minimum_confidence": round(confidence_after, 4),
                    "permit_threshold_delta": round(
                        permit_after - recommendation.current_permit_threshold, 4
                    ),
                    "forbid_threshold_delta": round(
                        forbid_after - recommendation.current_forbid_threshold, 4
                    ),
                    "minimum_confidence_delta": round(
                        confidence_after - recommendation.current_minimum_confidence,
                        4,
                    ),
                    "reasons": tuple(list(recommendation.reasons) + reasons),
                }
            )

            return SafetyDecision(
                allowed=allowed,
                clipped_recommendation=clipped,
                reasons=tuple(reasons),
                rate_limited=rate_limited,
                bounds_violated=bounds_violated,
                cumulative_budget_exhausted=budget_exhausted,
            )

    def commit(
        self,
        *,
        policy_id: str,
        applied_recommendation: CalibrationRecommendation,
    ) -> None:
        """
        Record that a calibration was applied.

        Call after a proposal is approved AND the new policy is saved, so
        future safety checks see the cumulative movement.
        """
        now = self._clock()
        with self._lock:
            history = self._history.setdefault(policy_id, _PolicyMovementHistory())
            history.events.append(
                (
                    now,
                    applied_recommendation.permit_threshold_delta,
                    applied_recommendation.forbid_threshold_delta,
                    applied_recommendation.minimum_confidence_delta,
                )
            )
            history.last_calibrated_at = now


def _clip_delta(delta: float, cap: float) -> float:
    if delta > cap:
        return cap
    if delta < -cap:
        return -cap
    return delta


def _clamp(value: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, value))


__all__ = [
    "CalibrationSafetyGuard",
    "DEFAULT_CUMULATIVE_BUDGET",
    "DEFAULT_CUMULATIVE_WINDOW",
    "DEFAULT_MAX_CONFIDENCE_DELTA",
    "DEFAULT_MAX_FORBID_DELTA",
    "DEFAULT_MAX_PERMIT_DELTA",
    "DEFAULT_MIN_INTERVAL",
    "HARD_FORBID_CEILING",
    "HARD_FORBID_FLOOR",
    "HARD_MIN_ABSTAIN_BAND",
    "HARD_MIN_CONFIDENCE_CEILING",
    "HARD_MIN_CONFIDENCE_FLOOR",
    "HARD_PERMIT_CEILING",
    "HARD_PERMIT_FLOOR",
    "SafetyDecision",
]

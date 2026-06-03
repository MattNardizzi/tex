"""
Calibration health score.

Combines all the diagnostic signals from the learning layer into a single
GREEN / YELLOW / RED indicator with the supporting subscores. Dashboards
consume this; the feedback-loop orchestrator uses it as a guard before
proposing calibration.

Subscores (each in [0.0, 1.0], higher = healthier):

  false_permit_score     — 1.0 when false_permit_rate is at/below target
  false_forbid_score     — 1.0 when false_forbid_rate is at/below target
  abstain_score          — 1.0 when abstain rate is in the comfortable band
  sample_score           — 1.0 when there are enough trusted outcomes
  reporter_diversity     — 1.0 when no single reporter dominates
  quarantine_score       — 1.0 when quarantine rate is low
  drift_volatility_score — 1.0 when verdict-rate movement is small

The composite score is the (weighted) minimum-style aggregate: a single
RED-zone subscore drags the overall to RED. We deliberately don't average
- we want operators to see "your sample size is too small" even when
everything else is fine.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum

from tex.domain.outcome import OutcomeRecord
from tex.domain.outcome_trust import OutcomeTrustLevel
from tex.learning.drift import PolicyDriftReport
from tex.learning.outcomes import OutcomeSummary


class HealthBand(StrEnum):
    GREEN = "GREEN"
    YELLOW = "YELLOW"
    RED = "RED"


@dataclass(frozen=True, slots=True)
class HealthSubscore:
    name: str
    value: float
    band: HealthBand
    reason: str


@dataclass(frozen=True, slots=True)
class CalibrationHealth:
    overall: HealthBand
    composite_score: float
    subscores: tuple[HealthSubscore, ...]
    sample_size: int
    quarantine_rate: float
    reporter_diversity: float
    advisories: tuple[str, ...]


# Thresholds. RED < red_below; YELLOW between; GREEN >= green_above.
_RED_BELOW = 0.55
_GREEN_ABOVE = 0.80


def _band(value: float) -> HealthBand:
    if value < _RED_BELOW:
        return HealthBand.RED
    if value < _GREEN_ABOVE:
        return HealthBand.YELLOW
    return HealthBand.GREEN


def _ramp_down(value: float, *, target: float, ceiling: float) -> float:
    """
    Subscore generator for "low is good" metrics like false_permit_rate.

    value <= target            -> 1.0
    value >= ceiling           -> 0.0
    linear interpolation in between.
    """
    if value <= target:
        return 1.0
    if value >= ceiling:
        return 0.0
    span = ceiling - target
    return max(0.0, 1.0 - (value - target) / span)


def _band_window(value: float, *, comfort_min: float, comfort_max: float) -> float:
    """
    Subscore generator for "stay inside this comfort band" metrics like
    abstain rate.
    """
    if comfort_min <= value <= comfort_max:
        return 1.0
    if value < comfort_min:
        return max(0.0, value / max(comfort_min, 1e-9))
    overshoot = value - comfort_max
    span = max(comfort_max, 1e-9)
    return max(0.0, 1.0 - overshoot / span)


def compute_health(
    *,
    outcome_summary: OutcomeSummary,
    trusted_outcomes: Iterable[OutcomeRecord],
    quarantined_count: int,
    drift_report: PolicyDriftReport | None,
    target_false_permit_rate: float = 0.04,
    target_false_forbid_rate: float = 0.08,
    abstain_comfort_min: float = 0.05,
    abstain_comfort_max: float = 0.30,
    minimum_healthy_sample: int = 30,
) -> CalibrationHealth:
    """
    Compute a calibration health snapshot.

    ``outcome_summary`` is over trusted outcomes only — the same set the
    calibrator uses. ``quarantined_count`` is the count of quarantined
    outcomes in the same window. ``drift_report`` may be None when there's
    not enough data; we mark that as YELLOW rather than RED.
    """
    trusted_tuple = tuple(trusted_outcomes)
    sample_total = outcome_summary.total
    advisories: list[str] = []

    # ── false_permit / false_forbid ──────────────────────────────────────
    fp_rate = (
        outcome_summary.false_permits / sample_total if sample_total > 0 else 0.0
    )
    ff_rate = (
        outcome_summary.false_forbids / sample_total if sample_total > 0 else 0.0
    )

    fp_score = _ramp_down(fp_rate, target=target_false_permit_rate, ceiling=0.20)
    ff_score = _ramp_down(ff_rate, target=target_false_forbid_rate, ceiling=0.30)

    # ── abstain rate ─────────────────────────────────────────────────────
    abstain_rate = (
        outcome_summary.abstain_reviews / sample_total if sample_total > 0 else 0.0
    )
    abstain_score = _band_window(
        abstain_rate, comfort_min=abstain_comfort_min, comfort_max=abstain_comfort_max
    )

    # ── sample size ──────────────────────────────────────────────────────
    if sample_total >= minimum_healthy_sample:
        sample_score = 1.0
    elif sample_total >= minimum_healthy_sample // 2:
        sample_score = 0.65
        advisories.append(
            f"Sample size {sample_total} is below the healthy minimum "
            f"({minimum_healthy_sample}); calibration confidence is reduced."
        )
    else:
        sample_score = 0.25 if sample_total > 0 else 0.0
        advisories.append(
            f"Sample size {sample_total} is too small to calibrate "
            "responsibly. Hold proposals until more trusted outcomes arrive."
        )

    # ── reporter diversity ───────────────────────────────────────────────
    reporter_counts = Counter(o.reporter for o in trusted_tuple if o.reporter)
    reporter_diversity = _diversity_score(reporter_counts)
    if reporter_diversity < 0.5 and reporter_counts:
        top = reporter_counts.most_common(1)[0]
        advisories.append(
            f"Reporter '{top[0]}' contributed {top[1]} of {sum(reporter_counts.values())} "
            "trusted outcomes; consider broadening reporter coverage."
        )

    # ── quarantine rate ──────────────────────────────────────────────────
    total_with_quarantined = sample_total + quarantined_count
    quarantine_rate = (
        quarantined_count / total_with_quarantined
        if total_with_quarantined > 0
        else 0.0
    )
    quarantine_score = _ramp_down(quarantine_rate, target=0.05, ceiling=0.30)
    if quarantine_rate >= 0.20:
        advisories.append(
            f"Quarantine rate is {quarantine_rate:.0%}; investigate which "
            "validation checks are failing most often."
        )

    # ── drift volatility ─────────────────────────────────────────────────
    if drift_report is None or not drift_report.sufficient_data:
        drift_volatility_score = 0.65
        advisories.append(
            "Drift report unavailable or has insufficient data; surface "
            "treated as cautiously YELLOW."
        )
    else:
        worst = max(
            abs(drift_report.permit_rate_delta),
            abs(drift_report.forbid_rate_delta),
            abs(drift_report.abstain_rate_delta),
        )
        drift_volatility_score = _ramp_down(worst, target=0.05, ceiling=0.30)

    subscores = (
        HealthSubscore(
            name="false_permit_rate",
            value=round(fp_score, 4),
            band=_band(fp_score),
            reason=f"observed false_permit_rate={fp_rate:.4f}",
        ),
        HealthSubscore(
            name="false_forbid_rate",
            value=round(ff_score, 4),
            band=_band(ff_score),
            reason=f"observed false_forbid_rate={ff_rate:.4f}",
        ),
        HealthSubscore(
            name="abstain_rate",
            value=round(abstain_score, 4),
            band=_band(abstain_score),
            reason=f"observed abstain_rate={abstain_rate:.4f}",
        ),
        HealthSubscore(
            name="sample_size",
            value=round(sample_score, 4),
            band=_band(sample_score),
            reason=f"observed sample_size={sample_total}",
        ),
        HealthSubscore(
            name="reporter_diversity",
            value=round(reporter_diversity, 4),
            band=_band(reporter_diversity),
            reason=f"observed reporters={len(reporter_counts)}",
        ),
        HealthSubscore(
            name="quarantine_rate",
            value=round(quarantine_score, 4),
            band=_band(quarantine_score),
            reason=f"observed quarantine_rate={quarantine_rate:.4f}",
        ),
        HealthSubscore(
            name="drift_volatility",
            value=round(drift_volatility_score, 4),
            band=_band(drift_volatility_score),
            reason="observed verdict-rate movement",
        ),
    )

    # Composite uses the minimum (any RED subscore -> overall RED).
    composite = min(s.value for s in subscores)
    overall = _band(composite)

    return CalibrationHealth(
        overall=overall,
        composite_score=round(composite, 4),
        subscores=subscores,
        sample_size=sample_total,
        quarantine_rate=round(quarantine_rate, 4),
        reporter_diversity=round(reporter_diversity, 4),
        advisories=tuple(advisories),
    )


def _diversity_score(reporter_counts: Counter) -> float:
    """
    Map a reporter histogram onto [0, 1].

    1.0  = perfectly even contribution across many reporters
    0.0  = one reporter contributed everything
    """
    total = sum(reporter_counts.values())
    if total == 0:
        return 0.0
    distinct = len(reporter_counts)
    if distinct <= 1:
        return 0.0
    # Normalised entropy.
    import math

    entropy = 0.0
    for count in reporter_counts.values():
        p = count / total
        if p > 0:
            entropy -= p * math.log(p)
    max_entropy = math.log(distinct)
    return entropy / max_entropy if max_entropy > 0 else 0.0


__all__ = [
    "CalibrationHealth",
    "HealthBand",
    "HealthSubscore",
    "compute_health",
]

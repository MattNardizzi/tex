"""
Evidence-sufficiency / decision-readiness gate for calibration.

The crude cold-start rule ("hold until N outcomes exist") answers the wrong
question. Under *delayed ground truth* — outcome labels arrive days to months
after the decision they evaluate — a calibration window can be large yet
still unfit to justify a policy change: the labels may be stale, thin, or
unrepresentative of the decisions the policy actually makes. Acting on
insufficient evidence is exactly how a feedback loop poisons itself.

This module formalises evidence sufficiency along four dimensions and gates
proposal generation on a readiness score, so Tex stays silent *honestly*
during the label-blind period and can say precisely why it is holding.

  completeness       enough calibration-eligible outcomes to estimate a rate
  freshness          the outcomes are recent relative to the decision stream
  reliability        the labels are trustworthy (VERIFIED > VALIDATED) and
                     not sourced from a single reporter
  representativeness  the window contains both safe and unsafe outcomes, so a
                     threshold move is informed by both error modes

The overall score is the geometric mean of the four — any single dimension
near zero collapses readiness, which is the intended behaviour of a gate (a
window that is complete and fresh but contains only safe outcomes cannot
justify *loosening* a threshold, and the representativeness term says so).

Reference
---------
- "Evidence Sufficiency Under Delayed Ground Truth: Proxy Monitoring for Risk
  Decision Systems" (2025): the four-dimension sufficiency model + decision-
  readiness gate this module operationalises.

stdlib-only (math + dataclasses + datetime). No new dependencies.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Callable

from tex.domain.outcome import OutcomeRecord
from tex.domain.outcome_trust import OutcomeTrustLevel

__all__ = [
    "EvidenceSufficiency",
    "SufficiencyReport",
    "DEFAULT_FRESHNESS_HORIZON",
    "DEFAULT_READINESS_THRESHOLD",
]


DEFAULT_FRESHNESS_HORIZON = timedelta(days=14)
DEFAULT_READINESS_THRESHOLD = 0.55
# Below this many eligible outcomes the window is unconditionally not ready,
# regardless of how the other dimensions score. A hard floor under the
# geometric mean so a tiny-but-balanced window can't sneak through.
DEFAULT_HARD_FLOOR = 8


@dataclass(frozen=True, slots=True)
class SufficiencyReport:
    """One readiness assessment of a calibration window.

    Every score is a finite float in [0, 1]. ``ready`` is the gate the
    orchestrator consults; ``reason`` is the single human sentence naming the
    weakest dimension — the honest thing Tex says when it stays silent.
    """

    ready: bool
    overall: float
    completeness: float
    freshness: float
    reliability: float
    representativeness: float
    sample_size: int
    reason: str

    def as_dict(self) -> dict[str, object]:
        return {
            "ready": self.ready,
            "overall": round(self.overall, 6),
            "completeness": round(self.completeness, 6),
            "freshness": round(self.freshness, 6),
            "reliability": round(self.reliability, 6),
            "representativeness": round(self.representativeness, 6),
            "sample_size": self.sample_size,
            "reason": self.reason,
        }


class EvidenceSufficiency:
    """Scores a calibration window's fitness to justify a threshold change."""

    __slots__ = (
        "_target_count",
        "_freshness_horizon",
        "_readiness_threshold",
        "_hard_floor",
        "_clock",
    )

    def __init__(
        self,
        *,
        target_count: int = 30,
        freshness_horizon: timedelta = DEFAULT_FRESHNESS_HORIZON,
        readiness_threshold: float = DEFAULT_READINESS_THRESHOLD,
        hard_floor: int = DEFAULT_HARD_FLOOR,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if target_count <= 0:
            raise ValueError("target_count must be positive")
        if not 0.0 < readiness_threshold < 1.0:
            raise ValueError("readiness_threshold must be in (0, 1)")
        if hard_floor < 0:
            raise ValueError("hard_floor must be non-negative")
        self._target_count = target_count
        self._freshness_horizon = freshness_horizon
        self._readiness_threshold = readiness_threshold
        self._hard_floor = hard_floor
        self._clock = clock or (lambda: datetime.now(UTC))

    def assess(self, outcomes: tuple[OutcomeRecord, ...]) -> SufficiencyReport:
        n = len(outcomes)
        if n == 0:
            return SufficiencyReport(
                ready=False,
                overall=0.0,
                completeness=0.0,
                freshness=0.0,
                reliability=0.0,
                representativeness=0.0,
                sample_size=0,
                reason="No calibration-eligible outcomes yet.",
            )

        completeness = min(1.0, n / float(self._target_count))
        freshness = self._freshness(outcomes)
        reliability = self._reliability(outcomes)
        representativeness = self._representativeness(outcomes)

        overall = _geometric_mean(
            (completeness, freshness, reliability, representativeness)
        )

        # Representativeness is a hard sub-gate, not merely a factor: a window
        # that has seen only one error mode (representativeness at the 0.1
        # one-sided score) can never be ready, regardless of how complete,
        # fresh, and reliable it is. You cannot move a threshold responsibly
        # having seen only one side of the trade.
        ready = (
            n >= self._hard_floor
            and representativeness >= 0.15
            and overall >= self._readiness_threshold
        )
        reason = self._reason(
            ready=ready,
            sample_size=n,
            completeness=completeness,
            freshness=freshness,
            reliability=reliability,
            representativeness=representativeness,
        )
        return SufficiencyReport(
            ready=ready,
            overall=overall,
            completeness=completeness,
            freshness=freshness,
            reliability=reliability,
            representativeness=representativeness,
            sample_size=n,
            reason=reason,
        )

    # ── dimensions ──────────────────────────────────────────────────────

    def _freshness(self, outcomes: tuple[OutcomeRecord, ...]) -> float:
        """Fraction of the window recorded within the freshness horizon.

        Stale labels describe a regime that may no longer hold. A window
        entirely older than the horizon scores 0; entirely within scores 1.
        """
        now = self._clock()
        cutoff = now - self._freshness_horizon
        fresh = 0
        for o in outcomes:
            recorded = o.recorded_at
            if recorded.tzinfo is None:
                recorded = recorded.replace(tzinfo=UTC)
            if recorded >= cutoff:
                fresh += 1
        return fresh / float(len(outcomes))

    @staticmethod
    def _reliability(outcomes: tuple[OutcomeRecord, ...]) -> float:
        """Label trust × reporter diversity.

        VERIFIED labels carry full weight, VALIDATED two-thirds (they passed
        validation but lack independent ground-truth confirmation). The mean
        label weight is then attenuated by reporter diversity: a window whose
        labels all came from one reporter is one collusion away from poison,
        so single-source windows are capped well below a diverse one.
        """
        if not outcomes:
            return 0.0
        weight_sum = 0.0
        reporters: set[str] = set()
        for o in outcomes:
            if o.trust_level is OutcomeTrustLevel.VERIFIED:
                weight_sum += 1.0
            elif o.trust_level is OutcomeTrustLevel.VALIDATED:
                weight_sum += 0.667
            # quarantined/raw shouldn't reach here (eligible-only), score 0.
            if o.reporter:
                reporters.add(o.reporter)
        label_quality = weight_sum / float(len(outcomes))

        distinct = len(reporters)
        # Diversity factor: 1 reporter -> 0.5, 2 -> 0.75, 3+ -> 1.0.
        if distinct <= 0:
            diversity = 0.5
        elif distinct == 1:
            diversity = 0.5
        elif distinct == 2:
            diversity = 0.75
        else:
            diversity = 1.0
        return max(0.0, min(1.0, label_quality * diversity))

    @staticmethod
    def _representativeness(outcomes: tuple[OutcomeRecord, ...]) -> float:
        """Balance of safe vs. unsafe labelled outcomes.

        A threshold move trades false-permits against false-forbids; a window
        that contains only one error mode can argue for moving in one
        direction but is blind to the cost. Representativeness peaks when both
        classes are present and balanced, via 4·p·(1−p) on the unsafe
        fraction (1.0 at a 50/50 split, →0 as the window collapses to one
        class). Windows with no usable labels score 0.
        """
        safe = 0
        unsafe = 0
        for o in outcomes:
            if o.was_safe is True:
                safe += 1
            elif o.was_safe is False:
                unsafe += 1
        labelled = safe + unsafe
        if labelled == 0:
            return 0.0
        # A window that has seen only one error mode cannot inform the
        # trade-off a threshold move makes (you can't claim loosening is safe
        # having seen zero unsafe outcomes). Score it near zero so the gate's
        # representativeness floor below can block it outright.
        if safe == 0 or unsafe == 0:
            return 0.1
        p_unsafe = unsafe / float(labelled)
        balance = 4.0 * p_unsafe * (1.0 - p_unsafe)
        # Both classes present: even a strongly imbalanced window carries some
        # information; floor at 0.2 so it's treated as weak, not worthless.
        return max(0.2, balance)

    @staticmethod
    def _reason(
        *,
        ready: bool,
        sample_size: int,
        completeness: float,
        freshness: float,
        reliability: float,
        representativeness: float,
    ) -> str:
        if ready:
            return "Evidence is sufficient to justify a calibration."
        # Name the weakest dimension — the honest reason for silence.
        dims = {
            "completeness": completeness,
            "freshness": freshness,
            "reliability": reliability,
            "representativeness": representativeness,
        }
        weakest = min(dims, key=lambda k: dims[k])
        phrasing = {
            "completeness": (
                f"I've only seen {sample_size} confirmed outcomes — not enough "
                "to justify a change yet."
            ),
            "freshness": (
                "The outcomes I have are too old to trust for a change right now."
            ),
            "reliability": (
                "The outcomes I have aren't confirmed independently enough to act on."
            ),
            "representativeness": (
                "I've only seen one side of this — not enough to know which way to move."
            ),
        }
        return phrasing[weakest]


def _geometric_mean(values: tuple[float, ...]) -> float:
    """Geometric mean with a zero-collapse property.

    Any zero (or negative, defensively floored) factor drives the mean to 0 —
    the gate behaviour we want: one failed dimension fails readiness.
    """
    if not values:
        return 0.0
    acc = 0.0
    for v in values:
        clamped = max(0.0, min(1.0, v))
        if clamped <= 0.0:
            return 0.0
        acc += math.log(clamped)
    return math.exp(acc / float(len(values)))

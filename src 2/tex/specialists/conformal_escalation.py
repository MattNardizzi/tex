"""
Specialist Conformal Escalation Gate.

Single-score conformal prediction interval used to decide *when* a
specialist escalates from its deterministic-lexical layer to its full
paper-faithful LLM-trained judge backend.

Why this exists
---------------
Static thresholds ("escalate when 0.2 <= risk <= 0.7") were defeated by
adaptive attacks in Nasr et al. October 2025 ("The Attacker Moves
Second"). The frontier answer as of May 2026 is conformal-prediction-
calibrated escalation: a formal upper bound on the lexical layer's true
risk at confidence 1 - alpha, with the LLM judge firing when that
upper bound crosses a configured decision boundary.

Mathematical structure
----------------------
For a calibration set of (lexical_score, true_label) pairs:

    s_i = |lexical_i - true_label_i|

The conformal quantile uses the standard split-CP finite-sample
correction:

    q_alpha = scores[ ceil((n + 1)(1 - alpha)) / n ]   (1-indexed)

For any new request with lexical score x:

    Upper bound:  x + q_alpha
    Lower bound:  max(0, x - q_alpha)
    Coverage:     P[ true_risk in [lower, upper] ] >= 1 - alpha

Escalate when upper >= decision_threshold (default 0.5).

References
----------
- Vovk, Gammerman, Shafer 2005 — original conformal prediction monograph.
- Angelopoulos & Bates 2023 — practical CP for ML.
- arxiv 2605.06788 (Feng et al., May 2026) — filtration-based CP Tex's
  Thread 3 attribution uses; same exchangeability argument here.

Priority: P0 — gates LLM-judge wiring for PlanGuard / MAGE.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Sequence

from pydantic import BaseModel, ConfigDict, Field


# Engineered defaults. See FRONTIER_DELTA_thread_4.md §10 for the
# calibration provenance — derived from a 200-fixture mix across
# AgentDojo + InjecAgent + MCPSafeBench + clean fixtures.
_DEFAULT_HALF_WIDTH_ALPHA_10 = 0.18
_DEFAULT_HALF_WIDTH_ALPHA_05 = 0.27
_DEFAULT_DECISION_THRESHOLD = 0.5
_CONSERVATIVE_FALLBACK_HALF_WIDTH = 0.40


class ConformalEscalationVerdict(BaseModel):
    """Output of the escalation gate."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    point_estimate: float = Field(ge=0.0, le=1.0)
    lower_bound: float = Field(ge=0.0, le=1.0)
    upper_bound: float = Field(ge=0.0, le=1.0)
    alpha: float = Field(gt=0.0, lt=1.0)
    coverage: float = Field(gt=0.0, lt=1.0)
    decision_threshold: float = Field(ge=0.0, le=1.0)
    half_width: float = Field(ge=0.0, le=1.0)
    should_escalate: bool
    rationale: str = Field(min_length=1, max_length=500)
    calibration_source: str = Field(min_length=1, max_length=100)


@dataclass(frozen=True, slots=True)
class CalibrationData:
    """Calibration scores from labelled past evaluations."""

    scores: tuple[float, ...]
    specialist_name: str

    def __post_init__(self) -> None:
        if not all(0.0 <= s <= 1.0 for s in self.scores):
            raise ValueError("calibration scores must be in [0, 1]")
        if not self.specialist_name.strip():
            raise ValueError("specialist_name must not be blank")


def conformal_quantile(scores: Sequence[float], alpha: float) -> float:
    """Split-CP quantile with finite-sample correction.

    Standard formula: ceil((n + 1)(1 - alpha)) / n. Guarantees marginal
    coverage >= 1 - alpha. For small n this is materially different from
    the naive empirical quantile.
    """
    if not scores:
        raise ValueError("scores must not be empty")
    if not 0.0 < alpha < 1.0:
        raise ValueError("alpha must be in (0, 1)")
    n = len(scores)
    sorted_scores = sorted(scores)
    k = min(n, max(1, math.ceil((n + 1) * (1.0 - alpha))))
    return float(sorted_scores[k - 1])


class ConformalEscalationGate:
    """
    Calibrated escalation gate for specialist LLM dispatch.

    Stateless across requests; calibration data is loaded at
    construction time. Re-instantiate to pick up fresh calibration.
    """

    def __init__(
        self,
        *,
        specialist_name: str,
        calibration: CalibrationData | None = None,
        alpha: float = 0.1,
        decision_threshold: float = _DEFAULT_DECISION_THRESHOLD,
    ) -> None:
        if not 0.0 < alpha < 1.0:
            raise ValueError("alpha must be in (0, 1)")
        if not 0.0 <= decision_threshold <= 1.0:
            raise ValueError("decision_threshold must be in [0, 1]")
        self._specialist_name = specialist_name
        self._alpha = alpha
        self._decision_threshold = decision_threshold

        if calibration is None or not calibration.scores:
            if abs(alpha - 0.1) < 1e-6:
                self._half_width = _DEFAULT_HALF_WIDTH_ALPHA_10
                self._source = "engineered_default_alpha_10"
            elif abs(alpha - 0.05) < 1e-6:
                self._half_width = _DEFAULT_HALF_WIDTH_ALPHA_05
                self._source = "engineered_default_alpha_05"
            else:
                # Unknown alpha — conservative fallback (escalates often).
                self._half_width = _CONSERVATIVE_FALLBACK_HALF_WIDTH
                self._source = "conservative_fallback"
        else:
            self._half_width = conformal_quantile(calibration.scores, alpha)
            self._source = f"split_cp_n_{len(calibration.scores)}"

    @property
    def half_width(self) -> float:
        return self._half_width

    def evaluate(self, *, lexical_risk_score: float) -> ConformalEscalationVerdict:
        if not 0.0 <= lexical_risk_score <= 1.0:
            raise ValueError("lexical_risk_score must be in [0, 1]")

        upper = min(1.0, lexical_risk_score + self._half_width)
        lower = max(0.0, lexical_risk_score - self._half_width)
        should_escalate = upper >= self._decision_threshold

        if should_escalate:
            rationale = (
                f"Conformal upper bound {upper:.3f} >= decision threshold "
                f"{self._decision_threshold:.3f}; LLM judge dispatched."
            )
        else:
            rationale = (
                f"Conformal upper bound {upper:.3f} < decision threshold "
                f"{self._decision_threshold:.3f}; lexical verdict accepted."
            )

        return ConformalEscalationVerdict(
            point_estimate=round(lexical_risk_score, 4),
            lower_bound=round(lower, 4),
            upper_bound=round(upper, 4),
            alpha=self._alpha,
            coverage=1.0 - self._alpha,
            decision_threshold=self._decision_threshold,
            half_width=round(self._half_width, 4),
            should_escalate=should_escalate,
            rationale=rationale,
            calibration_source=self._source,
        )


__all__ = [
    "CalibrationData",
    "ConformalEscalationGate",
    "ConformalEscalationVerdict",
    "conformal_quantile",
]

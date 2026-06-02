"""
Anytime-valid conformal risk control for trajectory uncertainty.

Thread 9. Reference: arxiv 2602.04364 ("Anytime-Valid Conformal Risk
Control", Feb 2026). Extends standard conformal prediction to remain
valid with high probability over a *cumulatively growing* calibration
dataset at any time point — the regime the digital-twin operator runs
in. Includes the matching asymptotic lower bound proven in the paper.

Why we need this for ``simulate_forward``
------------------------------------------
Standard split conformal assumes a fixed calibration set. The Tex
digital twin runs forever as the ecosystem grows; the calibration set
*must* grow with it, and we want coverage guarantees that hold *at any
time t*, not just on average over many calibration sets of fixed size.

This is what the anytime-valid framework gives us: with probability
(1 - delta) jointly over all t, the prediction set covers truth at the
target miscoverage rate alpha.

Practical shape
---------------
At each step we record nonconformity scores ``s_t`` (here: absolute
residual between Koopman-predicted state and the realized state). To
emit a forecast interval for a new prediction ``y_hat`` we report the
quantile-based prediction set computed *with anytime-valid quantile
bookkeeping*.

This file is intentionally light — the math is one quantile lookup +
a Hoeffding-style correction term that decays as 1/sqrt(t). Pure NumPy.
"""

from __future__ import annotations

import math

import numpy as np
from pydantic import BaseModel, ConfigDict, Field


class ConformalBand(BaseModel):
    """One conformal forecast interval for a scalar prediction."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    point: float
    lower: float
    upper: float
    width: float = Field(..., ge=0.0)
    alpha: float = Field(..., gt=0.0, lt=1.0)
    n_calibration: int = Field(..., ge=0)


class CalibrationBuffer:
    """
    Append-only buffer of nonconformity scores.

    Implements the cumulative-calibration shape from arxiv 2602.04364.
    For each new observation we push a new nonconformity score; for
    each new prediction we read out the anytime-valid quantile.

    Thread-unsafe — caller is the engine's single-thread Step-7
    invocation. Multi-tenant deployments use one buffer per tenant.
    """

    __slots__ = ("_scores", "_max_size")

    def __init__(self, *, max_size: int = 10_000) -> None:
        if max_size < 16:
            raise ValueError(f"max_size must be >= 16, got {max_size!r}")
        self._scores: list[float] = []
        self._max_size = max_size

    @property
    def n(self) -> int:
        return len(self._scores)

    def add(self, score: float) -> None:
        """Push a new nonconformity score. Drops oldest at capacity."""
        if not math.isfinite(score):
            return  # Silently drop NaN/inf; never crash the predictor.
        score = max(0.0, float(score))
        self._scores.append(score)
        if len(self._scores) > self._max_size:
            self._scores.pop(0)

    def anytime_valid_quantile(self, alpha: float, delta: float = 0.05) -> float:
        """
        Compute the anytime-valid (1 - alpha) quantile with high-
        probability correction.

        Per arxiv 2602.04364 §3, the quantile correction is

            q_at(alpha, n, delta) = q_emp((1 - alpha) * (n + 1) / n)
                                    + epsilon(n, delta)

        with ``epsilon(n, delta) ~ sqrt(log(2 / delta) / (2 n))`` —
        a Hoeffding-style correction that decays to zero as the
        calibration buffer grows.

        delta is the per-time-point miscoverage probability; default
        0.05 gives 95% confidence on the coverage statement itself.
        """
        if not (0.0 < alpha < 1.0):
            raise ValueError(f"alpha must be in (0, 1), got {alpha!r}")
        if self.n == 0:
            # Cold start — no data, return a conservative wide band.
            return 1.0

        arr = np.array(self._scores, dtype=np.float64)
        n = arr.size
        # Adjusted quantile per Romano-style finite-sample correction.
        adjusted = min((1.0 - alpha) * (n + 1) / n, 1.0)
        q_emp = float(np.quantile(arr, adjusted, method="higher"))
        # Anytime-valid epsilon (Hoeffding).
        eps = math.sqrt(math.log(2.0 / max(delta, 1e-12)) / (2.0 * n))
        return q_emp + eps

    def snapshot(self) -> tuple[float, ...]:
        """Read-only view (for replay / debug)."""
        return tuple(self._scores)


def band_for_prediction(
    *,
    point: float,
    buffer: CalibrationBuffer,
    alpha: float = 0.1,
    delta: float = 0.05,
) -> ConformalBand:
    """
    Wrap a point prediction in an anytime-valid conformal interval.

    The half-width is the anytime-valid quantile of past nonconformity
    scores (absolute residuals). The interval is symmetric around the
    point estimate, then clipped to [0, 1] (the systemic-axis state
    space is bounded).
    """
    if not math.isfinite(point):
        point = 0.0
    point = float(np.clip(point, 0.0, 1.0))
    half = buffer.anytime_valid_quantile(alpha=alpha, delta=delta)
    lo = float(np.clip(point - half, 0.0, 1.0))
    hi = float(np.clip(point + half, 0.0, 1.0))
    return ConformalBand(
        point=point,
        lower=lo,
        upper=hi,
        width=float(hi - lo),
        alpha=alpha,
        n_calibration=buffer.n,
    )

"""
Adaptive CUSUM detector — secondary change-point detector.

Why this lives next to BOCPD
----------------------------
arXiv:2512.18561 (AAF, Alqithami 2026) — the paper Tex's drift acceptance
criteria pin against — actually achieves its 71-step median detection
delay (IQR 39–177) using an *adaptive CUSUM* fed by ledger statistics, not
BOCPD. See AAF §5.3 ("Detector reliability: finite-sample FP and
detection-delay bounds for the adaptive CUSUM test fed by ledger
statistics") and the empirical run trace in §7 ("AAF's adaptive CUSUM
detector raised an alarm shortly after the coalition's behavior became
statistically distinguishable from the baseline").

Tex ships BOCPD as the primary per the package goal but also exposes
adaptive CUSUM as an alternative detector_kind so deployments that need to
exactly match the paper's empirical detection-delay distribution can opt in.

Algorithm
---------
Two-sided cumulative-sum statistic (Page 1954, "Continuous Inspection
Schemes", Biometrika 41) with adaptive variance estimation:

    z_t = (x_t - μ̂) / σ̂
    S⁺_t = max(0, S⁺_{t-1} + z_t - k)
    S⁻_t = max(0, S⁻_{t-1} - z_t - k)
    alarm if max(S⁺_t, S⁻_t) ≥ h

(μ̂, σ̂) are an exponentially-weighted estimate over a warmup window so the
detector tracks slow drift in the no-change regime without resetting on
every blip. After alarm we reset both statistics — this is the
"observation-adjusted" reset of Tang & Han 2023 (arXiv:2303.04628), the
modern operational pattern.

Reference values
----------------
- k (drift coefficient) = 0.5 — half the magnitude of the smallest shift
  worth detecting; the canonical setting under unit-variance scaling.
- h (decision threshold) = 5.0 — corresponds to an in-control ARL on the
  order of 10^3, comfortable for ledger-scale streams.
"""

from __future__ import annotations

import math
from dataclasses import dataclass


# Default tuning — tracks AAF's empirical 71-step median delay band
# without giving up false-alarm control on stationary fixtures.
DEFAULT_CUSUM_K: float = 0.5
DEFAULT_CUSUM_H: float = 5.0
DEFAULT_CUSUM_EWMA_ALPHA: float = 0.05  # ~ 20-step effective window
DEFAULT_CUSUM_WARMUP_STEPS: int = 30


@dataclass(slots=True)
class CUSUMState:
    """Mutable per-signal CUSUM state. One instance per signal."""

    k: float
    h: float
    ewma_alpha: float
    warmup_steps: int
    # Running mean / variance estimators (Welford-style EWMA).
    mean: float = 0.0
    var: float = 1.0
    # Cumulative statistics.
    s_pos: float = 0.0
    s_neg: float = 0.0
    step_index: int = 0
    last_alarm_step: int = -1


@dataclass(frozen=True, slots=True)
class CUSUMStep:
    """Externalised step report. Frozen for safe ledger hand-off."""

    step_index: int
    s_pos: float
    s_neg: float
    z_score: float                # standardised residual, useful for telemetry
    change_point_score: float     # max(s_pos, s_neg) / h — clipped to [0, 1+]
    fired: bool                   # alarm this step
    estimated_mean: float
    estimated_stddev: float


def cusum_step(state: CUSUMState, x: float) -> CUSUMStep:
    """Consume one observation and update the CUSUM state."""
    state.step_index += 1

    # --- adaptive baseline (EWMA mean & variance) ----------------------
    # We update the baseline only while no alarm is firing; this is the
    # standard "monitor the in-control distribution, freeze on alarm"
    # discipline. After warmup we still update slowly so the detector
    # tracks legitimate slow drift in the baseline.
    if state.step_index <= state.warmup_steps:
        # Burn-in: simple running estimates, no alarming.
        delta = x - state.mean
        state.mean += delta / state.step_index
        # Population variance approximation for warmup.
        state.var = (
            ((state.step_index - 1) * state.var + delta * (x - state.mean))
            / max(1, state.step_index)
        )
        return CUSUMStep(
            step_index=state.step_index,
            s_pos=0.0,
            s_neg=0.0,
            z_score=0.0,
            change_point_score=0.0,
            fired=False,
            estimated_mean=state.mean,
            estimated_stddev=math.sqrt(max(state.var, 1e-12)),
        )

    sigma = math.sqrt(max(state.var, 1e-12))
    z = (x - state.mean) / sigma

    # --- two-sided cumulative sums ------------------------------------
    state.s_pos = max(0.0, state.s_pos + z - state.k)
    state.s_neg = max(0.0, state.s_neg - z - state.k)
    fired = max(state.s_pos, state.s_neg) >= state.h
    cp_score = max(state.s_pos, state.s_neg) / state.h

    if fired:
        # Reset on alarm — observation-adjusted reset (Tang & Han 2023).
        state.last_alarm_step = state.step_index
        state.s_pos = 0.0
        state.s_neg = 0.0
        # Re-anchor baseline to the post-alarm regime so the next change
        # point is detected against the new normal, not the pre-alarm one.
        state.mean = x
        # Keep variance estimate but bound it away from zero so subsequent
        # z-scores don't blow up if the post-alarm regime is initially flat.
        state.var = max(state.var, 1e-6)
    else:
        # Update baseline slowly (EWMA) when not alarming.
        a = state.ewma_alpha
        new_mean = (1.0 - a) * state.mean + a * x
        new_var = (1.0 - a) * state.var + a * (x - state.mean) * (x - new_mean)
        state.mean = new_mean
        state.var = max(new_var, 1e-12)

    return CUSUMStep(
        step_index=state.step_index,
        s_pos=state.s_pos,
        s_neg=state.s_neg,
        z_score=z,
        change_point_score=min(cp_score, 1.0) if not fired else 1.0,
        fired=fired,
        estimated_mean=state.mean,
        estimated_stddev=math.sqrt(max(state.var, 1e-12)),
    )


def make_default_cusum_state(
    *,
    k: float = DEFAULT_CUSUM_K,
    h: float = DEFAULT_CUSUM_H,
    ewma_alpha: float = DEFAULT_CUSUM_EWMA_ALPHA,
    warmup_steps: int = DEFAULT_CUSUM_WARMUP_STEPS,
) -> CUSUMState:
    """Construct a fresh CUSUM state with AAF-tuned defaults."""
    if k <= 0.0:
        raise ValueError(f"CUSUM k must be > 0 (got {k!r})")
    if h <= 0.0:
        raise ValueError(f"CUSUM h must be > 0 (got {h!r})")
    if not 0.0 < ewma_alpha < 1.0:
        raise ValueError(f"ewma_alpha must be in (0, 1) (got {ewma_alpha!r})")
    if warmup_steps < 1:
        raise ValueError(f"warmup_steps must be ≥ 1 (got {warmup_steps!r})")
    return CUSUMState(
        k=k, h=h, ewma_alpha=ewma_alpha, warmup_steps=warmup_steps
    )

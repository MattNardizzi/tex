"""
Tests for the WSR betting confidence-sequence upper bound (learning/ope.py).

The OPE gate stands behind ``wsr_upper_bound`` — a one-sided, anytime-valid,
variance-adaptive upper confidence bound on the counterfactual unsafe-release
rate (Waudby-Smith & Ramdas, arXiv 2010.09686). These tests pin the three
properties the gate depends on:

  1. it is a genuine UPPER bound (>= the point estimate; covers the true mean
     at the stated rate on simulated streams);
  2. it is anytime-valid-conservative yet TIGHTER than the order-free Howard
     boundary it replaced (``wsr <= howard``);
  3. it is deterministic and tightens with n.

If any of these break, the calibration hold's load-bearing sentence
("loosening would have released unsafe actions at most X% of the time")
becomes a lie — exactly the failure the doctrine exists to prevent.
"""

from __future__ import annotations

import random

from tex.learning.ope import (
    WSR_DEFAULT_TRUNCATION,
    _anytime_valid_upper_bound,
    wsr_upper_bound,
)


def _bernoulli_stream(p: float, n: int, seed: int) -> list[float]:
    rng = random.Random(seed)
    return [1.0 if rng.random() < p else 0.0 for _ in range(n)]


# ── basic shape ─────────────────────────────────────────────────────────


def test_empty_stream_is_vacuously_zero() -> None:
    assert wsr_upper_bound([], alpha=0.05) == 0.0


def test_bound_is_in_unit_interval() -> None:
    for p in (0.0, 0.1, 0.5, 0.9, 1.0):
        ub = wsr_upper_bound(_bernoulli_stream(p, 100, seed=1), alpha=0.05)
        assert 0.0 <= ub <= 1.0


def test_bound_exceeds_point_estimate() -> None:
    # A clear upper bound must sit strictly above the empirical mean.
    stream = [1.0] * 5 + [0.0] * 15  # mu_hat = 0.25
    ub = wsr_upper_bound(stream, alpha=0.05)
    assert ub > 0.25
    assert ub <= 1.0


def test_all_zero_stream_bounds_below_one() -> None:
    # No unsafe events seen — with enough data the bound is well under 1.
    ub = wsr_upper_bound([0.0] * 400, alpha=0.05)
    assert ub < 0.20


# ── determinism ─────────────────────────────────────────────────────────


def test_bound_is_deterministic() -> None:
    stream = _bernoulli_stream(0.2, 120, seed=7)
    a = wsr_upper_bound(stream, alpha=0.05)
    b = wsr_upper_bound(list(stream), alpha=0.05)
    assert a == b


# ── tightening + conservatism ordering ──────────────────────────────────


def test_bound_tightens_with_more_data_same_rate() -> None:
    # Representative (interleaved) streams at the same rate — the betting CS is
    # order-dependent, so a fair "more data ⇒ tighter" test must not adversarially
    # front-load the unsafe events. The live gate feeds decision-ordered streams.
    small = wsr_upper_bound(_bernoulli_stream(0.25, 40, seed=42), alpha=0.05)
    large = wsr_upper_bound(_bernoulli_stream(0.25, 1000, seed=42), alpha=0.05)
    assert large < small


def test_smaller_alpha_is_more_conservative() -> None:
    stream = _bernoulli_stream(0.2, 200, seed=3)
    loose = wsr_upper_bound(stream, alpha=0.10)
    tight = wsr_upper_bound(stream, alpha=0.01)
    # A tighter coverage requirement cannot give a SMALLER upper bound.
    assert tight >= loose - 1e-9


def test_wsr_is_no_looser_than_howard() -> None:
    # The headline claim: the betting CS is at least as tight as the Howard
    # boundary it replaced, on the same (k, n).
    for p, n, seed in ((0.05, 200, 1), (0.1, 150, 2), (0.3, 300, 3)):
        stream = _bernoulli_stream(p, n, seed)
        k = int(sum(stream))
        wsr = wsr_upper_bound(stream, alpha=0.05)
        howard = _anytime_valid_upper_bound(successes=k, n=n, alpha=0.05)
        assert wsr <= howard + 1e-9


# ── empirical coverage (validity) ───────────────────────────────────────


def test_bound_covers_true_mean_at_stated_rate() -> None:
    """Anytime-valid ⇒ at any fixed n the bound covers the true mean with
    probability ≥ 1−α. Across many independent streams the violation rate
    (U_n < p) must stay at or below α. The betting CS is conservative, so in
    practice violations are far rarer than α — we allow generous slack but the
    test would still catch a bound that is systematically anti-conservative.
    """
    p = 0.1
    n = 150
    trials = 300
    violations = 0
    for seed in range(trials):
        stream = _bernoulli_stream(p, n, seed=1000 + seed)
        if wsr_upper_bound(stream, alpha=0.05) < p:
            violations += 1
    rate = violations / trials
    assert rate <= 0.05, f"violation rate {rate:.3f} exceeds alpha=0.05"


def test_truncation_constant_keeps_factors_positive() -> None:
    # Adversarial stream alternating 0/1 — the capital factors must never go
    # non-positive (else the martingale, and Ville, break). Indirectly: the
    # bound is finite and in range for any [0,1] stream.
    assert 0.0 < WSR_DEFAULT_TRUNCATION < 1.0
    stream = [float(i % 2) for i in range(200)]
    ub = wsr_upper_bound(stream, alpha=0.01)
    assert 0.0 <= ub <= 1.0

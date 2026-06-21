"""The statistics that gate every "I've noticed…". If these are wrong, L3 either
asserts noise or never speaks — both are failures."""

from __future__ import annotations

import math
from statistics import NormalDist

import pytest

from tex.presence.habits.confidence import (
    bonferroni_alpha,
    score_pattern,
    wilson_lower_bound,
)


def test_wilson_endpoint_satisfies_the_score_equation():
    """Non-circular correctness check: the Wilson lower endpoint p_L is BY DEFINITION
    the p where the score statistic (phat - p)/sqrt(p(1-p)/n) equals z. Validate
    against that definition, not against our own formula."""
    for k, n, alpha in [(8, 10, 0.05), (45, 50, 0.10), (30, 40, 0.025), (7, 12, 0.05)]:
        z = NormalDist().inv_cdf(1.0 - alpha)
        p_l = wilson_lower_bound(k, n, alpha=alpha)
        phat = k / n
        assert 0.0 < p_l < phat  # a lower bound below the point estimate
        score = (phat - p_l) / math.sqrt(p_l * (1 - p_l) / n)
        assert score == pytest.approx(z, abs=1e-6)


def test_wilson_bounds_and_degenerate_inputs():
    assert wilson_lower_bound(0, 0, alpha=0.05) == 0.0       # no evidence → no confidence
    assert wilson_lower_bound(0, 10, alpha=0.05) == 0.0      # zero successes
    full = wilson_lower_bound(10, 10, alpha=0.05)
    assert 0.0 < full < 1.0                                  # certainty is never manufactured
    # k clamped into [0, n] defensively (a miscount can't escape [0,1]).
    assert 0.0 <= wilson_lower_bound(99, 10, alpha=0.05) <= 1.0


def test_wilson_is_monotone_in_n_and_alpha():
    # More consistent evidence at the same rate → a higher (tighter) lower bound.
    assert wilson_lower_bound(10, 10, alpha=0.05) < wilson_lower_bound(20, 20, alpha=0.05)
    # A larger alpha (less confidence demanded) → a higher lower bound.
    assert wilson_lower_bound(8, 10, alpha=0.01) < wilson_lower_bound(8, 10, alpha=0.20)


def test_bonferroni_splits_and_clamps():
    assert bonferroni_alpha(0.10, 1) == pytest.approx(0.10)
    assert bonferroni_alpha(0.10, 20) == pytest.approx(0.005)
    assert bonferroni_alpha(0.10, 0) == pytest.approx(0.10)   # family clamped to >= 1
    assert 0.0 < bonferroni_alpha(2.0, 5) <= 1.0              # alpha clamped into (0,1)


def test_multiplicity_strictly_lowers_the_bound():
    """The crown-jewel guard: testing the SAME clean pattern among more candidates
    must shrink its confidence (so a noisy subject can't look clean by luck)."""
    solo = wilson_lower_bound(5, 5, alpha=bonferroni_alpha(0.10, 1))
    crowd = wilson_lower_bound(5, 5, alpha=bonferroni_alpha(0.10, 20))
    assert crowd < solo
    assert solo > 0.7 and crowd < 0.5


def test_score_pattern_gating_boundaries():
    common = dict(alpha_family=0.10, min_support=5, min_point_rate=0.8, min_confidence=0.55)
    # 5/5 alone → surfaces.
    assert score_pattern(k=5, n=5, family_size=1, **common).surfaced
    # 4/5 alone → blocked by the Wilson floor (rate passes 0.8, bound ~0.51).
    assert not score_pattern(k=4, n=5, family_size=1, **common).surfaced
    # 3/5 → blocked by the observed-rate floor (0.6 < 0.8).
    assert not score_pattern(k=3, n=5, family_size=1, **common).surfaced
    # n=4 → blocked by min_support regardless of consistency.
    assert not score_pattern(k=4, n=4, family_size=1, **common).surfaced
    # 5/5 among a family of 20 → multiplicity blocks it.
    assert not score_pattern(k=5, n=5, family_size=20, **common).surfaced
    # but enough support (10/10) clears even at family=20 — the bar scales with evidence.
    assert score_pattern(k=10, n=10, family_size=20, **common).surfaced


def test_score_pattern_is_pure():
    a = score_pattern(k=6, n=7, family_size=3, alpha_family=0.10, min_support=5,
                      min_point_rate=0.8, min_confidence=0.55)
    b = score_pattern(k=6, n=7, family_size=3, alpha_family=0.10, min_support=5,
                      min_point_rate=0.8, min_confidence=0.55)
    assert a == b
    assert a.label and "NOT calibrated" in a.label

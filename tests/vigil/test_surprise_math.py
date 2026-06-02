"""
Surprise math: the closed-form Bayesian surprise must be correct, because
everything the vigil chooses rests on it.

Properties verified:
  * digamma matches known constants,
  * KL(p || p) == 0 (an observation that matches normal is not surprising),
  * KL >= 0 always,
  * KL is monotonically increasing as the observation departs from normal.
"""

from __future__ import annotations

import math

import pytest

from tex.vigil.conjugate import (
    BetaBelief,
    GammaBelief,
    beta_surprise,
    digamma,
    gamma_surprise,
)


def test_digamma_known_values() -> None:
    # psi(1) = -gamma (Euler-Mascheroni); psi(x+1) = psi(x) + 1/x
    assert digamma(1.0) == pytest.approx(-0.5772156649, abs=1e-6)
    assert digamma(2.0) == pytest.approx(-0.5772156649 + 1.0, abs=1e-6)
    assert digamma(10.0) == pytest.approx(2.2517525890, abs=1e-6)


def test_digamma_rejects_nonpositive() -> None:
    with pytest.raises(ValueError):
        digamma(0.0)


def test_gamma_self_kl_is_zero() -> None:
    g = GammaBelief(5.0, 2.0)
    assert gamma_surprise(g, g) == 0.0


def test_beta_self_kl_is_zero() -> None:
    b = BetaBelief(50.0, 1.0)
    assert beta_surprise(b, b) == 0.0


def test_gamma_surprise_monotonic_in_divergence() -> None:
    prior = GammaBelief(15.0, 7.0)  # mean ~2.14
    s = [gamma_surprise(prior, prior.update(obs, 1.0)) for obs in (2, 5, 10, 40)]
    assert all(x >= 0 for x in s)
    assert s[0] < s[1] < s[2] < s[3]
    # An on-mean observation is essentially unsurprising.
    assert s[0] < 0.05


def test_beta_break_is_far_more_surprising_than_intact() -> None:
    prior = BetaBelief(50.0, 1.0)  # strongly expects integrity
    intact = beta_surprise(prior, prior.update(1.0, 0.0))
    broken = beta_surprise(prior, prior.update(0.0, 1.0))
    assert intact < 0.05  # confirming the chain is whole is not news
    assert broken > 0.2  # a break is real surprise
    assert broken > intact * 100


def test_identity_safety_prior_surprised_by_any_ungoverned() -> None:
    # Safety dimensions expect the safe state; even one departure registers.
    prior = GammaBelief(1.0, 4.0)  # mean 0.25
    zero = gamma_surprise(prior, prior.update(0.0, 1.0))
    one = gamma_surprise(prior, prior.update(1.0, 1.0))
    assert zero < 0.05
    assert one > 0.05

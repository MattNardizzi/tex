"""
[Architecture: Cross-cutting (Vigil cognition)] — closed-form Bayesian surprise.

See ARCHITECTURE.md for the full six-layer model. This module is the
mathematical core of the vigil's selection layer: it computes *Bayesian
surprise* — the KL divergence between a posterior belief (after observing
this cycle) and the prior belief (the model of normal).

    surprise = D_KL( posterior || prior )

This is the realized form of the epistemic-value term in expected free
energy. v1 computes it after the fact; v4 will compute it in expectation.
The functional is identical.

Two conjugate families cover every dimension Tex reads:

  * Beta–Bernoulli  — for rates / fractions / binary events
                      (e.g. "fraction of agents ungoverned", "chain intact?").
  * Gamma–Poisson   — for counts / event rates
                      (e.g. "new agents discovered this cycle",
                       "FORBID verdicts tonight").

Both KLs are closed form. There is no sampling and no inference engine —
that is the whole point of v1's "dumbest correct form". The same conjugate
counts that compute surprise here are the ones v2 will unfreeze into a live
learner (see vigil/learning.py).

No SciPy dependency: digamma is implemented directly (recurrence +
asymptotic expansion) so the vigil has no numerical-stack requirement
beyond the standard library.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

__all__ = [
    "digamma",
    "BetaBelief",
    "GammaBelief",
    "beta_surprise",
    "gamma_surprise",
]


# --------------------------------------------------------------------------- digamma


# Asymptotic-expansion coefficients for ln-derivative of Gamma.
_DIGAMMA_LARGE = 6.0


def digamma(x: float) -> float:
    """
    Digamma function psi(x) for x > 0, stdlib-only.

    Strategy: use the recurrence psi(x) = psi(x + 1) - 1/x to push the
    argument above ``_DIGAMMA_LARGE``, then apply the standard asymptotic
    expansion. Accurate to well within the precision the surprise ranking
    needs (errors are far below the gaps between dimensions' KLs).
    """
    if x <= 0.0:
        # Belief parameters are always strictly positive by construction
        # (priors start at >= 1). Guard anyway rather than NaN-propagate.
        raise ValueError(f"digamma requires x > 0, got {x!r}")

    result = 0.0
    # Recurrence up to the asymptotic regime.
    while x < _DIGAMMA_LARGE:
        result -= 1.0 / x
        x += 1.0

    # Asymptotic expansion:
    #   psi(x) ~ ln(x) - 1/(2x) - 1/(12x^2) + 1/(120x^4) - 1/(252x^6)
    inv = 1.0 / x
    inv2 = inv * inv
    result += (
        math.log(x)
        - 0.5 * inv
        - inv2 * (1.0 / 12.0 - inv2 * (1.0 / 120.0 - inv2 * (1.0 / 252.0)))
    )
    return result


def _lnbeta(a: float, b: float) -> float:
    """ln of the Beta function B(a, b) = Gamma(a)Gamma(b)/Gamma(a+b)."""
    return math.lgamma(a) + math.lgamma(b) - math.lgamma(a + b)


# --------------------------------------------------------------------------- beliefs


@dataclass(frozen=True, slots=True)
class BetaBelief:
    """A Beta(alpha, beta) belief over a probability / rate in [0, 1]."""

    alpha: float
    beta: float

    def __post_init__(self) -> None:
        if self.alpha <= 0.0 or self.beta <= 0.0:
            raise ValueError("Beta parameters must be > 0")

    @property
    def mean(self) -> float:
        return self.alpha / (self.alpha + self.beta)

    def update(self, successes: float, failures: float) -> "BetaBelief":
        """Conjugate update: observe ``successes``/``failures`` Bernoulli trials."""
        if successes < 0 or failures < 0:
            raise ValueError("counts must be non-negative")
        return BetaBelief(self.alpha + successes, self.beta + failures)


@dataclass(frozen=True, slots=True)
class GammaBelief:
    """A Gamma(shape, rate) belief over a non-negative count / rate."""

    shape: float
    rate: float

    def __post_init__(self) -> None:
        if self.shape <= 0.0 or self.rate <= 0.0:
            raise ValueError("Gamma parameters must be > 0")

    @property
    def mean(self) -> float:
        return self.shape / self.rate

    def update(self, count: float, exposure: float = 1.0) -> "GammaBelief":
        """Conjugate update: observe ``count`` events over ``exposure`` units."""
        if count < 0 or exposure < 0:
            raise ValueError("count and exposure must be non-negative")
        return GammaBelief(self.shape + count, self.rate + exposure)


# --------------------------------------------------------------------------- surprise


def beta_surprise(prior: BetaBelief, posterior: BetaBelief) -> float:
    """
    Bayesian surprise for a Beta–Bernoulli dimension:

        D_KL( posterior || prior )

    Closed form for two Beta distributions. Returns nats. Zero iff the
    observation did not move the belief; grows with belief-shift.
    """
    a, b = posterior.alpha, posterior.beta
    c, d = prior.alpha, prior.beta
    kl = (
        _lnbeta(c, d)
        - _lnbeta(a, b)
        + (a - c) * digamma(a)
        + (b - d) * digamma(b)
        + (c - a + d - b) * digamma(a + b)
    )
    # KL is non-negative analytically; clamp tiny negative round-off to 0.
    return kl if kl > 0.0 else 0.0


def gamma_surprise(prior: GammaBelief, posterior: GammaBelief) -> float:
    """
    Bayesian surprise for a Gamma–Poisson dimension:

        D_KL( posterior || prior )

    Closed form for two Gamma distributions (shape/rate parameterization).
    Returns nats. Zero iff the observation did not move the belief.
    """
    ap, bp = posterior.shape, posterior.rate
    aq, bq = prior.shape, prior.rate
    kl = (
        (ap - aq) * digamma(ap)
        - math.lgamma(ap)
        + math.lgamma(aq)
        + aq * (math.log(bp) - math.log(bq))
        + ap * (bq - bp) / bp
    )
    return kl if kl > 0.0 else 0.0

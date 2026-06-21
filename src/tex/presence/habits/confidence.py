"""The statistics that decide whether a noticed pattern is real enough to OFFER.

This is the load-bearing honesty piece of L3: a "noticed pattern" is exactly where
a system starts asserting things it cannot prove. So a pattern is surfaced only
when a DETERMINISTIC, conservative statistic clears a floor — never on a vibe.

THE TWO GUARDS
--------------
1. **Wilson score lower bound** on the dominant-outcome proportion. For ``k`` of
   ``n`` observations sharing the dominant outcome, the Wilson interval's lower
   endpoint is a well-behaved one-sided lower confidence bound on the true rate
   (Wilson, J. Am. Stat. Assoc. 22:209, 1927; recommended over the Wald interval
   for small ``n`` by Brown, Cai & DasGupta, Statist. Sci. 16(2):101, 2001). We
   take the ONE-SIDED lower bound at ``1 - alpha`` because we only ever care that
   the rate is HIGH (a strong, consistent habit), never that it is low. At ``k==n``
   it stays strictly below 1.0 — small ``n`` cannot manufacture certainty.

2. **Bonferroni multiplicity correction.** A miner scans many subjects at once;
   testing ``m`` of them and surfacing any that crosses a fixed bar is the textbook
   multiple-comparisons trap — with enough noisy subjects, one will look like a
   clean pattern by chance (e.g. among 20 subjects with 5 coin-flip outcomes each,
   ~1 is "5/5" by luck). Dividing the family error budget across the ``m`` tested
   subjects (``alpha_eff = alpha_family / m``) widens ``z``, shrinks every lower
   bound, and kills the spurious crossing. This is conservative on purpose: a
   suggestion Tex offers a human must not be a coincidence dressed as a rule.

HONEST EDGE (disclosed, not hidden)
-----------------------------------
The Wilson bound assumes the ``n`` observations are exchangeable Bernoulli trials
of "did the dominant outcome occur." A tenant's sealed records are NOT a clean
i.i.d. draw — they are the population the tenant's own prior decisions produced
(selection bias; cf. the selection-conditional-coverage caveat the calibration
feed already carries, arXiv:2403.03868). So the number this returns is a
**heuristic consistency lower bound that screens out noise**, NOT a calibrated
coverage guarantee. It governs *whether to ask a human*, never what Tex asserts.
A further limitation: re-mining across sessions is SEQUENTIAL (optional stopping),
so the per-call Bonferroni-Wilson bound is a fixed-sample statistic, not an
anytime-valid one; an e-value / betting bound is the documented upgrade path.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from statistics import NormalDist

__all__ = [
    "CONSISTENCY_LABEL",
    "bonferroni_alpha",
    "wilson_lower_bound",
    "PatternConfidence",
    "score_pattern",
]

# The honest label stamped onto every confidence object so a downstream surface
# can never present this as a formal coverage guarantee.
CONSISTENCY_LABEL = (
    "heuristic consistency lower bound (one-sided Wilson, Bonferroni-corrected "
    "over the subjects tested); NOT calibrated coverage — the sample is "
    "selection-biased (the tenant's own prior decisions) and re-mining is "
    "sequential (fixed-sample bound, not anytime-valid)"
)

_NORMAL = NormalDist()


def bonferroni_alpha(alpha_family: float, family_size: int) -> float:
    """Split the family error budget across the ``family_size`` subjects tested.

    ``family_size`` is clamped to ``>= 1`` so a single-subject mine is uncorrected
    (``alpha_eff == alpha_family``) and a larger family is strictly more
    conservative. ``alpha_family`` is clamped into ``(0, 1)``.
    """
    a = min(max(alpha_family, 1e-9), 1.0 - 1e-9)
    return a / max(1, int(family_size))


def wilson_lower_bound(k: int, n: int, *, alpha: float) -> float:
    """One-sided lower endpoint of the Wilson score interval at confidence
    ``1 - alpha`` for ``k`` successes in ``n`` trials.

    Returns ``0.0`` for ``n <= 0`` (no evidence → no confidence). Never raises;
    clamps the result into ``[0, 1]``. ``k`` is clamped into ``[0, n]`` defensively
    so a miscounted input can never push the bound out of range.
    """
    if n <= 0:
        return 0.0
    k = min(max(int(k), 0), int(n))
    a = min(max(alpha, 1e-9), 1.0 - 1e-9)
    # One-sided: put the whole error budget in the lower tail.
    z = _NORMAL.inv_cdf(1.0 - a)
    phat = k / n
    z2 = z * z
    denom = 1.0 + z2 / n
    centre = phat + z2 / (2.0 * n)
    margin = z * math.sqrt(phat * (1.0 - phat) / n + z2 / (4.0 * n * n))
    lower = (centre - margin) / denom
    return min(1.0, max(0.0, lower))


@dataclass(frozen=True, slots=True)
class PatternConfidence:
    """A computed (never vibed) verdict on whether one pattern is real enough to
    offer. ``surfaced`` is the single boolean the miner gates on; every other field
    is the audit trail behind it."""

    n: int
    """Distinct supporting observations (deduped — idempotent re-seals don't count
    twice)."""
    k: int
    """How many of the ``n`` carried the dominant outcome."""
    point_rate: float
    """``k / n`` — the observed dominant-outcome rate (NOT a guarantee)."""
    wilson_lower: float
    """Bonferroni-corrected one-sided Wilson lower bound on the true rate."""
    alpha_family: float
    alpha_effective: float
    """``alpha_family / family_size`` — the per-subject budget after correction."""
    family_size: int
    """``m`` = how many subjects were in contention this mine (the multiplicity)."""
    min_support: int
    min_point_rate: float
    min_confidence: float
    surfaced: bool
    """True iff ``n >= min_support`` AND ``point_rate >= min_point_rate`` AND
    ``wilson_lower >= min_confidence``. The ONLY gate the miner consults."""
    label: str = CONSISTENCY_LABEL


def score_pattern(
    *,
    k: int,
    n: int,
    family_size: int,
    alpha_family: float,
    min_support: int,
    min_point_rate: float,
    min_confidence: float,
) -> PatternConfidence:
    """Score one candidate pattern and decide whether it clears every floor.

    Pure + deterministic: identical inputs always give an identical verdict (the
    miner relies on this for content-addressed, reproducible hypotheses).
    """
    alpha_eff = bonferroni_alpha(alpha_family, family_size)
    point_rate = (k / n) if n > 0 else 0.0
    wilson = wilson_lower_bound(k, n, alpha=alpha_eff)
    surfaced = (
        n >= min_support
        and point_rate >= min_point_rate
        and wilson >= min_confidence
    )
    return PatternConfidence(
        n=n,
        k=k,
        point_rate=point_rate,
        wilson_lower=wilson,
        alpha_family=alpha_family,
        alpha_effective=alpha_eff,
        family_size=max(1, int(family_size)),
        min_support=min_support,
        min_point_rate=min_point_rate,
        min_confidence=min_confidence,
        surfaced=surfaced,
    )

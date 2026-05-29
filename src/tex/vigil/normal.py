"""
[Architecture: Cross-cutting (Vigil cognition)] — the model of normal.

This is Tex's sense of what is ordinary *for this shop*. It is built by
warming a per-dimension conjugate prior from the sealed ledger history,
then accumulating — never sliding. Accumulation matters: a slow drift over
a week still reads as a departure, because the baseline remembers last week
instead of forgetting it. A sliding window can be lied to by patience; an
accumulating prior cannot.

Two postures:

  * **Warm** — history exists, so the prior is the shop's own past. Tex
    boots already knowing this shop. (Chosen posture for v1.)
  * **Neutral fallback** — a brand-new tenant has an empty ledger, so the
    prior is a deliberately skeptical base. For *safety* dimensions
    (ungoverned high-risk agents, failing connectors, chain integrity) the
    base expects the safe state, so any departure registers. The vigil is
    quiet-but-uncertain on a new shop, never a night-one flood.

The base priors below are the v1 seed. In v2 these exact conjugate counts
unfreeze into a live learner (vigil/learning.py): warm-up and learning are
the same machinery at two speeds.

Because the prior is built from sealed ledger entries, *why Tex believed
something was normal* traces back to hashed history like everything else —
the sense of normal is itself auditable.
"""

from __future__ import annotations

from dataclasses import dataclass

from tex.vigil.conjugate import BetaBelief, GammaBelief
from tex.vigil.dimensions import DimensionReading

__all__ = ["ModelOfNormal", "NormalPrior"]


# Per-dimension base priors. The "safe state" dimensions expect near-zero
# events, so departures surprise. The volume dimensions expect a modest
# baseline. Evidence expects integrity strongly.
_GAMMA_BASE: dict[str, tuple[float, float]] = {
    # key:        (shape, rate)   mean = shape / rate ; rate ~ pseudo-strength
    # Volume dimensions carry pseudo-strength (rate=4) so a brand-new shop
    # observing its own expected volume is quiet, not a night-one flood —
    # while a real incident (an order of magnitude off) still blows past.
    "discovery": (8.0, 4.0),       # mean 2: a few new agents per scan is ordinary
    "execution": (8.0, 4.0),       # mean 2: some FORBIDs are ordinary
    # Safety dimensions expect the safe state (~0), so any departure
    # registers — even one ungoverned high-risk agent is news.
    "identity": (1.0, 4.0),        # mean 0.25: ungoverned high-risk SHOULD be ~0
    "monitoring": (1.0, 4.0),      # mean 0.25: failing connectors SHOULD be ~0
    "human_decision": (1.0, 1.0),  # gate; prior is nominal (never ranked)
    "learning": (3.0, 3.0),        # mean 1: a proposal or two is ordinary
}
_GAMMA_DEFAULT: tuple[float, float] = (3.0, 3.0)

# Beta base priors. Evidence integrity is expected strongly.
_BETA_BASE: dict[str, tuple[float, float]] = {
    "evidence": (50.0, 1.0),  # chain is intact; a break is maximal surprise
}
_BETA_DEFAULT: tuple[float, float] = (1.0, 1.0)


@dataclass(frozen=True, slots=True)
class NormalPrior:
    """The warmed prior for one dimension, plus whether it was warm."""

    beta: BetaBelief | None
    gamma: GammaBelief | None
    warm: bool


class ModelOfNormal:
    """
    Builds the warmed prior for a dimension reading.

    Stateless in v1 (recomputed from the reading's history each cycle); v2
    will make it stateful by persisting the accumulated counts instead of
    rebuilding them. The interface does not change between the two.
    """

    def prior_for(self, reading: DimensionReading) -> NormalPrior:
        if reading.kind == "beta":
            return self._beta_prior(reading)
        return self._gamma_prior(reading)

    # ---- gamma ----------------------------------------------------------

    def _gamma_prior(self, reading: DimensionReading) -> NormalPrior:
        base_shape, base_rate = _GAMMA_BASE.get(reading.key, _GAMMA_DEFAULT)
        counts = [float(c) for c in reading.history if _is_number(c)]
        if counts:
            # Accumulate: every past observation adds to the prior. Strength
            # (rate) grows with the number of observations, so the prior
            # tightens around the shop's real average as history grows.
            shape = base_shape + sum(counts)
            rate = base_rate + float(len(counts))
            return NormalPrior(beta=None, gamma=GammaBelief(shape, rate), warm=True)
        return NormalPrior(
            beta=None, gamma=GammaBelief(base_shape, base_rate), warm=False
        )

    # ---- beta -----------------------------------------------------------

    def _beta_prior(self, reading: DimensionReading) -> NormalPrior:
        base_a, base_b = _BETA_BASE.get(reading.key, _BETA_DEFAULT)
        succ = 0.0
        fail = 0.0
        for item in reading.history:
            # history entries shaped as (successes, failures) accumulate.
            if isinstance(item, tuple) and len(item) == 2 and _is_number(item[0]) and _is_number(item[1]):
                succ += float(item[0])
                fail += float(item[1])
        if succ or fail:
            return NormalPrior(
                beta=BetaBelief(base_a + succ, base_b + fail), gamma=None, warm=True
            )
        return NormalPrior(beta=BetaBelief(base_a, base_b), gamma=None, warm=False)


def _is_number(x: object) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool)

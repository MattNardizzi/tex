"""
[Architecture: Cross-cutting (Vigil cognition)] — v2 LIVE LEARNER.

Learn the shop. v1 warms the model of normal from ledger history and
rebuilds it each cycle. v2 makes it *live*: the same per-dimension
conjugate counts stop being recomputed and start accumulating in place, so
Tex's sense of normal earns itself from this shop's ongoing history rather
than being re-derived. Warm-up (v1) and learning (v2) are the same
machinery at two speeds — this class is the second speed.

Temporal order (proper online Bayesian updating, not sliding):

    predict on the accumulated model  ->  THEN fold this cycle in.

So a cycle's surprise is computed against the model as it stood *before*
this cycle, and only afterward does the observation update the model for
the next cycle. Accumulation, never a window: a slow drift over a week
still reads as a departure because the baseline remembers last week.

THE SAFETY FLOOR (load-bearing):

    Descriptive *volume* normals learn. Safety dimensions do not.

The volume dimensions (discovery, execution, learning) accumulate, so Tex
calibrates to what this shop actually does. The safety dimensions
(identity, monitoring, evidence) are *pinned to their fixed safe-state
base* and never learn upward — a flood of "5 ungoverned high-risk agents
every cycle" can never become the new normal that silences the alarm. This
is exactly v1's behavior for those dimensions (their v1 history is empty /
non-numeric, so v1 already returns the base), made explicit and permanent.

Iron-rule note: learning sharpens *selection* (what counts as normal, what
is surprising). It never touches *generation* — the authored forms in
vigil/utterances.py stay fixed. A wiser witness still does not improvise.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from threading import RLock
from typing import Any

from tex.vigil.conjugate import GammaBelief
from tex.vigil.dimensions import DimensionReading
from tex.vigil.normal import (
    _GAMMA_BASE,
    _GAMMA_DEFAULT,
    ModelOfNormal,
    NormalPrior,
)

__all__ = ["DirichletNormalLearner", "LEARNABLE_GAMMA"]


# The only dimensions whose *volume normal* is allowed to learn. Everything
# else is a safety dimension whose prior is pinned to its safe-state base
# (identity / monitoring expect ~0; evidence expects integrity) so an
# accumulating "normal" can never erase the floor. ``human_decision`` is a
# gate, never surprise-ranked, so its model is irrelevant — left un-learned.
LEARNABLE_GAMMA: frozenset[str] = frozenset({"discovery", "execution", "learning"})


def _is_number(x: object) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool)


@dataclass(slots=True)
class _GammaAccum:
    """Accumulated Gamma-Poisson sufficient statistics for one dimension.

    ``total`` is the running sum of observed counts; ``n`` is the number of
    observations folded in. The learned prior is ``Gamma(base_shape + total,
    base_rate + n)`` — identical in form to v1 warming from history, only
    sourced from stored state instead of recomputed every cycle.
    """

    total: float = 0.0
    n: int = 0


class _LearnedModelOfNormal(ModelOfNormal):
    """A ``ModelOfNormal`` backed by a learner's accumulated counts.

    Overrides the gamma prior to source from accumulated state for learnable
    dimensions, and pins every safety dimension to its fixed base. Beta
    dimensions (evidence) defer to the v1 path, which already returns the
    strong integrity base — evidence is a safety floor and does not learn.
    For a learnable dimension with no accumulated state yet (cold boot), it
    falls back to v1's history-warmed prior, so the first cycle equals v1
    and subsequent cycles run live. Same machinery, two speeds.
    """

    __slots__ = ("_learner", "_tenant")

    def __init__(self, learner: "DirichletNormalLearner", tenant: str | None) -> None:
        self._learner = learner
        self._tenant = tenant

    def _gamma_prior(self, reading: DimensionReading) -> NormalPrior:
        key = reading.key
        if key not in LEARNABLE_GAMMA:
            # Safety / non-learnable dimension: pinned to the fixed base.
            base_shape, base_rate = _GAMMA_BASE.get(key, _GAMMA_DEFAULT)
            return NormalPrior(
                beta=None, gamma=GammaBelief(base_shape, base_rate), warm=False
            )

        accum = self._learner._peek_gamma(self._tenant, key)
        if accum is None or accum.n == 0:
            # Cold for this dimension: warm from sealed history exactly as v1.
            return super()._gamma_prior(reading)

        base_shape, base_rate = _GAMMA_BASE.get(key, _GAMMA_DEFAULT)
        return NormalPrior(
            beta=None,
            gamma=GammaBelief(base_shape + accum.total, base_rate + float(accum.n)),
            warm=True,
        )

    # Beta (evidence) deliberately inherits v1 behavior: it is a safety
    # floor, not a learned volume normal. ``_beta_prior`` from the base class
    # returns the strong integrity prior; we do not override it.


class DirichletNormalLearner:
    """v2: accumulating conjugate counts as a live model of normal.

        observe(reading, tenant)  — fold one cycle's observation into the
                                     accumulated counts for its dimension.
        as_model(tenant)          — expose the accumulated counts as a
                                     ``ModelOfNormal`` the selector can use.
        snapshot()                — sealable view of the learned parameters,
                                     so the model's evolution is auditable.

    Thread-safe; per-tenant, per-dimension state. The accumulation is
    conjugate (Gamma-Poisson), identical in form to the priors v1 warms from
    history — the unfreeze is a no-op in math, a state change in storage.
    """

    __slots__ = ("_lock", "_gamma")

    def __init__(self) -> None:
        self._lock = RLock()
        # tenant -> dimension key -> accumulated gamma sufficient statistics.
        self._gamma: dict[str | None, dict[str, _GammaAccum]] = {}

    # ------------------------------------------------------------------ learn

    def observe(self, reading: DimensionReading, *, tenant: str | None = None) -> None:
        """Fold one cycle's observation into the accumulated counts.

        No-op for safety / non-learnable dimensions and for beta readings —
        those are pinned floors, not learned volume normals. On the first
        observation of a learnable dimension for a tenant, the reading's
        sealed history is warm-started in (so the learner boots already
        knowing the shop), then this cycle is folded on top.
        """
        if reading.kind != "gamma":
            return  # evidence (beta) is a safety floor; it does not learn.
        key = reading.key
        if key not in LEARNABLE_GAMMA:
            return

        with self._lock:
            by_dim = self._gamma.setdefault(tenant, {})
            accum = by_dim.get(key)
            if accum is None:
                accum = _GammaAccum()
                by_dim[key] = accum
                # First sight: warm-start from sealed history so boot == v1.
                for item in reading.history:
                    if _is_number(item):
                        accum.total += float(item)
                        accum.n += 1

            # Fold this cycle's observed count (exposure normalized to one
            # observation, matching v1's per-entry history accumulation).
            count = float(reading.observation[0]) if reading.observation else 0.0
            accum.total += count
            accum.n += 1

    # ------------------------------------------------------------------ expose

    def as_model(self, tenant: str | None = None) -> ModelOfNormal:
        """Expose the accumulated counts as a ``ModelOfNormal`` for ``tenant``."""
        return _LearnedModelOfNormal(self, tenant)

    def _peek_gamma(self, tenant: str | None, key: str) -> _GammaAccum | None:
        with self._lock:
            by_dim = self._gamma.get(tenant)
            if by_dim is None:
                return None
            accum = by_dim.get(key)
            if accum is None:
                return None
            # Return a copy so the model never mutates learner state.
            return _GammaAccum(total=accum.total, n=accum.n)

    # ------------------------------------------------------------------ seal

    def snapshot(self) -> dict[str, Any]:
        """A stable, sealable view of every learned parameter.

        Deterministically ordered so the same learned state always hashes to
        the same bytes — the evolution of "normal" is itself auditable
        evidence. Safety dimensions never appear here because they never
        learn; only the descriptive volume normals do.
        """
        with self._lock:
            tenants: dict[str, Any] = {}
            for tenant in sorted(self._gamma, key=lambda t: ("" if t is None else t)):
                by_dim = self._gamma[tenant]
                dims = {
                    key: {
                        "total": round(float(by_dim[key].total), 6),
                        "n": int(by_dim[key].n),
                        "learned_mean": (
                            round(float(by_dim[key].total) / by_dim[key].n, 6)
                            if by_dim[key].n
                            else 0.0
                        ),
                    }
                    for key in sorted(by_dim)
                }
                tenants["__none__" if tenant is None else tenant] = dims
            return {"family": "gamma_poisson", "tenants": tenants}

    def snapshot_sha256(self) -> str:
        """SHA-256 over the canonical snapshot — the seal of learned normal."""
        canonical = json.dumps(
            self.snapshot(), sort_keys=True, separators=(",", ":")
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

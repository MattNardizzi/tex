"""
Systemic risk evaluator.

Thread 7.1: backed by ProbGuard-style PCTL reachability over a DTMC
abstraction of the ecosystem state. Replaces the prior
``NotImplementedError`` stub.

Reference: ProbGuard / Pro2Guard (arxiv 2508.00500 v3, Mar 27 2026).

The score answers the PCTL property

    P_{<θ}[F^{≤k} unsafe_state | current_state]

i.e. the probability that an unsafe state (per AAF §3.1.4 bounded-
compromise threshold) is reachable within ``horizon_k`` DTMC steps
from the current ecosystem abstraction. Score is in [0, 1]; higher
means more forward-looking systemic risk.

Operators flip ``TEX_ECOSYSTEM_SYSTEMIC=1`` to engage the call site
in the engine. Without the flag the engine reports the axis as 0.0
and does not call this evaluator (default-off latency budget).
"""

from __future__ import annotations

from tex.ecosystem.state import EcosystemState
from tex.systemic.probguard import (
    DTMCModel,
    abstract_state,
    default_model,
    reachability_probability,
)
from tex.systemic.trajectory import SimulationTrajectory, SystemicWeights


# Default horizon — 10 steps matches the AAF §6 baseline window. The
# horizon trades freshness (smaller k catches imminent risk) against
# coverage (larger k catches cascading risk). 10 is empirically a
# sweet spot per AAF Table 4.
_DEFAULT_HORIZON_K: int = 10


class SystemicRiskEvaluator:
    """
    Computes systemic risk as PCTL bounded-reachability probability.

    Wire one per engine via ``EcosystemEngine(systemic=...)``. The
    evaluator carries its own ``DTMCModel`` (or shares a module-level
    default) — operators wanting per-tenant model isolation construct
    a custom model and pass it.

    Operators *teach* the model by calling ``score`` as ecosystem
    states evolve; successive calls record (previous, current)
    transitions automatically. Without observations the model uses
    Laplace add-α smoothing (default α=1.0) giving a near-uniform
    transition prior — score under this prior is the cold-start
    expected reachability per the AAF §6 baseline.
    """

    def __init__(
        self,
        *,
        model: DTMCModel | None = None,
        horizon_k: int = _DEFAULT_HORIZON_K,
    ) -> None:
        if horizon_k < 1:
            raise ValueError(f"horizon_k must be ≥ 1, got {horizon_k!r}")
        self._model = model if model is not None else default_model()
        self._horizon_k = horizon_k
        # Track last observed abstraction so successive score() calls
        # can incrementally feed the model. None until the first call.
        self._last_abstraction: str | None = None

    def score(self, *, state: EcosystemState) -> float:
        """
        Compute ``P[F^{≤k} unsafe | current_state]`` via the ProbGuard
        DTMC abstraction.

        Pure read on ``state``; updates the internal DTMC by
        observing the (last, current) transition. The transition is
        recorded *before* the reachability computation so the model
        grows monotonically across calls.

        Returns a float in [0, 1]. 0.0 means no unsafe state is
        reachable within ``horizon_k`` steps under the current model;
        1.0 means an unsafe state is certain to be reached.
        """
        current = abstract_state(state)
        if self._last_abstraction is not None:
            self._model.observe_transition(
                from_state=self._last_abstraction, to_state=current,
            )
        self._last_abstraction = current

        return reachability_probability(
            model=self._model,
            initial_state=current,
            horizon_k=self._horizon_k,
        )

    @property
    def model(self) -> DTMCModel:
        """Read-only access to the underlying DTMC model."""
        return self._model

    @property
    def horizon_k(self) -> int:
        return self._horizon_k

    # ----------------------------------------------------- Thread 9 fusion

    def score_fused(
        self,
        *,
        state: EcosystemState,
        twin_trajectory: SimulationTrajectory | None = None,
        sccal_score: float | None = None,
        cascade_reachability: float | None = None,
        weights: SystemicWeights | None = None,
    ) -> float:
        """
        Thread 9: compose PCTL (this evaluator) with SCCAL (semantic-
        geometric co-evolution from arxiv 2603.13325) and cascade
        reachability (from ``CascadePredictor``).

        Convex combination per ``SystemicWeights``. Backward-compatible:
        when no SCCAL signal and no cascade probability are passed, the
        result equals the pure-PCTL ``score(state=...)``.

        When a ``twin_trajectory`` is supplied, the SCCAL score and
        cascade reachability default to the trajectory's *worst* values
        (most adversarial step) — this is the right thing for a
        governance gate that must FORBID on the upper-bound risk.

        Parameters
        ----------
        state : EcosystemState
            Current ecosystem state (also feeds the DTMC update).
        twin_trajectory : SimulationTrajectory, optional
            If passed, defaults for SCCAL + cascade are pulled from
            the worst step in the trajectory.
        sccal_score : float, optional
            Direct SCCAL signal override.
        cascade_reachability : float, optional
            Direct cascade-reachability override.
        weights : SystemicWeights, optional
            Per-tenant weight overrides. Defaults to the calibrated
            ``SystemicWeights()`` defaults.

        Returns
        -------
        Float in [0, 1]. Higher = more systemic risk.
        """
        pctl = float(self.score(state=state))
        w = weights if weights is not None else SystemicWeights()

        # Pull defaults from the trajectory if supplied.
        if twin_trajectory is not None and twin_trajectory.steps:
            worst = max(
                twin_trajectory.steps,
                key=lambda s: s.fused_systemic_score,
            )
            if sccal_score is None:
                sccal_score = float(worst.sccal_score)
            if cascade_reachability is None:
                # Use the worst step's drift-max as a cascade proxy when
                # the caller did not supply a cascade probability.
                cascade_reachability = float(
                    worst.drift_signals.get("drift_max", 0.0)
                )

        sccal_score = float(sccal_score) if sccal_score is not None else 0.0
        cascade_reachability = (
            float(cascade_reachability) if cascade_reachability is not None else 0.0
        )

        # Clamp inputs defensively.
        sccal_score = max(0.0, min(1.0, sccal_score))
        cascade_reachability = max(0.0, min(1.0, cascade_reachability))

        fused = (
            w.w_pctl * pctl
            + w.w_sccal * sccal_score
            + w.w_cascade * cascade_reachability
        )
        return max(0.0, min(1.0, fused))

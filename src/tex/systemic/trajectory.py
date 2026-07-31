"""
Frozen Pydantic v2 models for digital-twin trajectories and cascade
paths.

Thread 9. All models are ``frozen=True, extra="forbid"`` per the Tex
constitution.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class TrajectoryStep(BaseModel):
    """One step of a digital-twin simulation trajectory."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    step_index: int = Field(..., ge=0)
    state_hash: str = Field(..., min_length=8, description="SHA-256 of canonicalized abstracted state.")
    probguard_pctl_score: float = Field(..., ge=0.0, le=1.0)
    sccal_score: float = Field(..., ge=0.0, le=1.0)
    fused_systemic_score: float = Field(..., ge=0.0, le=1.0)
    drift_signals: dict[str, float] = Field(default_factory=dict)
    conformal_lower: float = Field(..., ge=0.0, le=1.0)
    conformal_upper: float = Field(..., ge=0.0, le=1.0)


class CascadePath(BaseModel):
    """A predicted cascade path from a seed violation event."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    event_ids: tuple[str, ...] = Field(..., min_length=1)
    aggregate_probability: float = Field(..., ge=0.0, le=1.0)
    depth: int = Field(..., ge=1)
    # STPA Unsafe-Control-Action class tag, per arxiv 2512.17600.
    # One of: "NOT_PROVIDED", "PROVIDED_WHEN_NOT_NEEDED",
    # "WRONG_TIMING", "WRONG_DURATION", or "UNSPECIFIED".
    stpa_uca_class: str = Field(default="UNSPECIFIED", min_length=1, max_length=64)
    # Per arxiv 2603.04474 vulnerability classes: cascade_amplification,
    # topological_sensitivity, consensus_inertia.
    spark_to_fire_class: str = Field(default="UNCLASSIFIED", min_length=1, max_length=64)


class SimulationTrajectory(BaseModel):
    """
    Full output of ``EcosystemDigitalTwin.simulate_forward``.

    Records every step's fused systemic score with conformal coverage,
    the most-likely and worst-case predicted cascade paths, the
    seed perturbation, and the deterministic generation counter so
    replay is straightforward.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    fork_timestamp_iso: str
    perturbation_summary: dict[str, str] = Field(default_factory=dict)
    horizon: int = Field(..., ge=1)
    steps: tuple[TrajectoryStep, ...] = Field(..., min_length=1)
    most_likely_cascade_path: CascadePath | None = None
    worst_case_cascade_path: CascadePath | None = None
    # Indexed by the SHA-256 chain — pairs with evidence chain.
    twin_run_id: str = Field(..., min_length=8)


class SystemicWeights(BaseModel):
    """
    Per-tenant weights for the fused systemic-risk score.

    The fused score is a convex combination:

        fused = w_pctl  * probguard_pctl
              + w_sccal * sccal
              + w_casc  * cascade_reachability

    Weights must sum to <= 1.0; remaining mass is the implicit
    "unknown / safe" prior. Defaults are calibrated against the
    Concordia governance-corruption substrate
    (arxiv 2603.18894 / Thread 4 institutional evals) and the
    From-Spark-to-Fire benchmark (arxiv 2603.04474).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    w_pctl: float = Field(default=0.35, ge=0.0, le=1.0)
    w_sccal: float = Field(default=0.45, ge=0.0, le=1.0)
    w_cascade: float = Field(default=0.20, ge=0.0, le=1.0)

    def __init__(self, **data) -> None:  # type: ignore[no-untyped-def]
        super().__init__(**data)
        total = self.w_pctl + self.w_sccal + self.w_cascade
        if total > 1.0 + 1e-9:
            raise ValueError(
                f"systemic weights must sum to <= 1.0, got {total:.4f}"
            )

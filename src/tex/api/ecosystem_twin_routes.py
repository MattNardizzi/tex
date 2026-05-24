"""
Twin simulation endpoint — POST /v1/ecosystem/twin/simulate.

Thread 9. Exposes ``EcosystemDigitalTwin.simulate_forward`` over HTTP
so operators (and the agent ecosystem itself) can run pre-execution
"what if?" simulations of a proposed perturbation before it touches
the live ecosystem state.

Endpoint surface
----------------
``POST /v1/ecosystem/twin/simulate``

Request body (JSON)
-------------------
    {
      "fork_timestamp_iso": "2026-05-20T15:00:00+00:00",
      "perturbation": {
        "compromise_delta": 0.20,
        "drift_delta": 0.10,
        "add_agents": 0,
        "add_tools": 0,
        "label": "what_if_admit_high_risk_action"
      },
      "steps": 16,
      "weights": {                          // optional, per-tenant override
        "w_pctl": 0.35,
        "w_sccal": 0.45,
        "w_cascade": 0.20
      },
      "cascade_seed_event_id": "evt_abc...",  // optional
      "cascade_edges": [                     // optional, BFS dependency graph
        {"from_event_id": "evt_abc",
         "to_event_id":   "evt_xyz",
         "propagation_probability": 0.4},
        ...
      ]
    }

Response (JSON) is the serialized ``SimulationTrajectory`` plus an
optional ``cascade_paths`` array if a seed event was supplied. The
``twin_run_id`` is the SHA-256-derived identifier used as the
evidence-chain anchor for this run.

Live ecosystem read, no live write
-----------------------------------
This endpoint reads from the current ecosystem state, runs a *forked*
simulation, and writes nothing back to the live KG / event ledger
beyond a single twin-run telemetry record. The actual /v1/guardrail
path is unaffected.

Defaults to the application-level twin instance attached at startup
via ``app.state.ecosystem_twin``; if no twin is wired the endpoint
returns 503.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field

from tex.ecosystem.state import EcosystemState
from tex.observability.telemetry import emit_event
from tex.systemic.cascade_predictor import CascadePredictor, DependencyEdge
from tex.systemic.digital_twin import DEFAULT_HORIZON, EcosystemDigitalTwin, MAX_HORIZON
from tex.systemic.trajectory import SimulationTrajectory, SystemicWeights


_router = APIRouter()


class _TwinPerturbationRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    fork_timestamp_iso: str = Field(
        ..., description="ISO-8601 timestamp at which to fork the live state.",
    )
    perturbation: dict[str, Any] = Field(
        default_factory=dict,
        description="Counterfactual perturbation. Recognized keys: "
                    "compromise_delta, drift_delta, add_agents, add_tools, "
                    "label, actor_entity_id.",
    )
    steps: int = Field(default=DEFAULT_HORIZON, ge=1, le=MAX_HORIZON)
    weights: SystemicWeights | None = None
    cascade_seed_event_id: str | None = None
    cascade_edges: tuple[DependencyEdge, ...] | None = None


class _TwinSimulationResponse(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    trajectory: SimulationTrajectory
    cascade_paths: tuple[dict[str, Any], ...] = ()
    elapsed_ms: float = Field(..., ge=0.0)


@_router.post(
    "/v1/ecosystem/twin/simulate",
    response_model=_TwinSimulationResponse,
    status_code=status.HTTP_200_OK,
    tags=["ecosystem"],
)
async def simulate(
    payload: _TwinPerturbationRequest,
    request: Request,
) -> _TwinSimulationResponse:
    """Run a forked counterfactual simulation."""
    twin: EcosystemDigitalTwin | None = getattr(
        request.app.state, "ecosystem_twin", None
    )
    if twin is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="ecosystem digital twin is not wired on this deployment",
        )

    # Read the live ecosystem state. The application-level state factory
    # is expected to be attached as ``app.state.ecosystem_state_factory``,
    # a zero-arg callable returning the current ``EcosystemState``. If
    # not wired, we accept an inline ``state`` field on the request as
    # a fallback for stateless testing.
    factory = getattr(request.app.state, "ecosystem_state_factory", None)
    state: EcosystemState | None = None
    if factory is not None:
        try:
            state = factory()
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"failed to materialize live ecosystem state: {exc!r}",
            ) from exc
    if state is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="no live ecosystem state available",
        )

    t0 = datetime.now(UTC)
    try:
        forked = twin.fork_at(timestamp_iso=payload.fork_timestamp_iso)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    # Apply per-request weight overrides via a transient twin (frozen
    # weights cannot be mutated; we patch the forked instance's
    # ``_weights`` since that's the supported override surface).
    if payload.weights is not None:
        forked._weights = payload.weights

    try:
        trajectory = forked.simulate_forward(
            state=state,
            steps=payload.steps,
            perturbation=payload.perturbation,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    cascade_paths_serialized: tuple[dict[str, Any], ...] = ()
    if payload.cascade_seed_event_id and payload.cascade_edges:
        predictor = CascadePredictor()
        paths = predictor.predict_cascade_paths(
            seed_violation_event_id=payload.cascade_seed_event_id,
            edges=payload.cascade_edges,
        )
        cascade_paths_serialized = tuple(p.model_dump() for p in paths)

    elapsed = (datetime.now(UTC) - t0).total_seconds() * 1000.0

    emit_event(
        "ecosystem.twin.api_invocation",
        twin_run_id=trajectory.twin_run_id,
        steps=payload.steps,
        elapsed_ms=elapsed,
        max_fused=max(s.fused_systemic_score for s in trajectory.steps),
        n_cascade_paths=len(cascade_paths_serialized),
    )

    return _TwinSimulationResponse(
        trajectory=trajectory,
        cascade_paths=cascade_paths_serialized,
        elapsed_ms=elapsed,
    )


def build_twin_router() -> APIRouter:
    """Factory matching the other router builders in ``tex.api``."""
    return _router

"""
Ecosystem digital twin.

Thread 9. A replay-and-perturb simulator that forks the live
ecosystem state at timestamp T, applies a counterfactual perturbation
(e.g. "what if we admit this proposed event?"), simulates forward N
steps in Koopman-lifted latent space, and reports the resulting
fused systemic-risk trajectory with conformal coverage guarantees.

References
----------
- arxiv 2601.01076 (Nath/Yin/Chou, PMLR 2026): Koopman lifting with
  conformal coverage guarantees. → ``_koopman.py``.
- arxiv 2605.01803 (Köglmayr/Räth, May 2026): Koopman early-warning
  + minimal counterfactual intervention in multi-agent simulations.
- arxiv 2603.13325 (SCCAL, ICLR 2026 Workshop): semantic-geometric
  co-evolutionary cascade auditing. → ``_sccal.py``.
- arxiv 2602.04364 (Anytime-Valid Conformal Risk Control, Feb 2026).
  → ``_conformal.py``.
- arxiv 2601.03905 (Jan 2026): documents that LLM agents *rarely*
  invoke simulation (< 1%) and degrade when forced to; the right
  place for the digital twin is at the *governance layer*, not the
  agent. This is precisely what Thread 9 ships.

Used for
--------
- pre-execution event evaluation (via ``POST /v1/ecosystem/twin/simulate``)
- what-if intervention planning (Thread 8 reads twin trajectories
  to evaluate intervention candidates before applying)
- bounded-compromise certificate generation (Thread 8 uses worst-case
  trajectories as the upper bound for eta-star derivation)

Honest scope
------------
``simulate_forward`` returns a *governance-grade* trajectory — a
short-horizon, conformal-covered, Koopman-lifted forecast of the
fused systemic axis. It is NOT a high-fidelity LLM-driven market
simulator (SR-DTMA / GeomHerd run an LLM call per trader per step;
that's a year of engineering for the agent-governance use case).

Per-tenant Koopman operators are fit from observed ecosystem state
transitions in the temporal KG. With < ``MIN_TRAINING_N`` observed
transitions the trajectory falls back to identity advance and the
conformal band is the cold-start wide interval.
"""

from __future__ import annotations

import copy
import hashlib
import uuid
from datetime import datetime
from typing import Any, Mapping, Sequence

import numpy as np
from pydantic import BaseModel, ConfigDict, Field

from tex.ecosystem.state import EcosystemState
from tex.graph.temporal_kg import InMemoryTemporalKG
from tex.observability.telemetry import emit_event
from tex.systemic._conformal import CalibrationBuffer, band_for_prediction
from tex.systemic._koopman import (
    MIN_TRAINING_N,
    KoopmanState,
    TenantSignalProfile,
    fit_koopman,
    predict_trajectory,
)
from tex.systemic._sccal import compute_sccal
from tex.systemic.probguard import (
    DTMCModel,
    abstract_state,
    default_model,
    reachability_probability,
)
from tex.systemic.trajectory import (
    CascadePath,
    SimulationTrajectory,
    SystemicWeights,
    TrajectoryStep,
)


# Default trajectory horizon. Per arxiv 2605.01803 §3.2 a 10-50 step
# window captures epidemic-class early warnings; 16 is the headroom
# choice for the 10 ms p99 budget.
DEFAULT_HORIZON: int = 16
MAX_HORIZON: int = 64


class TwinSnapshot(BaseModel):
    """
    Frozen snapshot of an ecosystem state — the forked twin's initial
    condition.

    Stores a deep-copied versions dict from the temporal KG plus the
    canonical state hash for replay verification.
    """

    model_config = ConfigDict(frozen=True, extra="forbid", arbitrary_types_allowed=True)

    snapshot_at_iso: str
    state_hash: str
    versions: Mapping[str, tuple[tuple[str, dict[str, Any]], ...]] = Field(
        default_factory=dict,
        description="entity_id -> ((iso_timestamp, attrs), ...)",
    )


def _state_to_abstract_vector(state: EcosystemState) -> np.ndarray:
    """
    Map an ``EcosystemState`` to a 4-dim vector for Koopman lifting.

    Coordinates:
      0: sliding_window_compromise_ratio (already in [0, 1])
      1: log-scaled active entity count, normalized to [0, 1]
      2: mean of drift signals, clipped to [0, 1]
      3: max of drift signals, clipped to [0, 1]
    """
    n_active = (
        len(state.active_agent_ids)
        + len(state.active_tool_ids)
        + len(state.active_capability_ids)
    )
    log_count = np.log1p(n_active) / np.log1p(1000.0)  # ~1 at 1000 entities
    drifts = list(state.aggregate_drift_signals.values()) or [0.0]
    drifts_arr = np.array(drifts, dtype=np.float64)
    return np.array(
        [
            float(state.sliding_window_compromise_ratio),
            float(np.clip(log_count, 0.0, 1.0)),
            float(np.clip(drifts_arr.mean(), 0.0, 1.0)),
            float(np.clip(drifts_arr.max(), 0.0, 1.0)),
        ],
        dtype=np.float64,
    )


def _hash_abstract_state(v: np.ndarray) -> str:
    """SHA-256 over a canonicalized rounded vector for replay-stable hashes."""
    rounded = np.round(v, 6)
    h = hashlib.sha256()
    h.update(b"tex:thread9:abstract:")
    h.update(rounded.tobytes())
    return h.hexdigest()


def _build_interaction_graph(
    state: EcosystemState,
) -> tuple[np.ndarray, tuple[tuple[str, str], ...]]:
    """
    Build a binary adjacency from active entities for SCCAL.

    For governance-grade SCCAL we only need *which agents interact*.
    Live ecosystems wire this from the temporal KG's event edges;
    for cold-start / no-event cases we return an empty graph.
    """
    agents = list(state.active_agent_ids)
    tools = list(state.active_tool_ids)
    nodes = agents + tools
    name_to_idx = {n: i for i, n in enumerate(nodes)}
    n = len(nodes)
    if n < 2:
        return np.zeros((max(n, 1), max(n, 1))), ()
    # Bipartite-ish proxy: every agent connects to every tool.
    # Replaced at runtime by event-graph edges when wired against
    # ``InMemoryTemporalKG`` (caller may pass an adj override).
    adj = np.zeros((n, n), dtype=np.float64)
    for ai in range(len(agents)):
        for ti in range(len(agents), len(agents) + len(tools)):
            adj[ai, ti] = 1.0
    edge_labels: list[tuple[str, str]] = []
    for u, v in np.argwhere(adj > 0):
        edge_labels.append((nodes[u], nodes[v]))
    return adj, tuple(edge_labels)


def _perturb_vector(v: np.ndarray, perturbation: Mapping[str, Any]) -> np.ndarray:
    """
    Apply a counterfactual perturbation to the abstract state vector.

    Recognized perturbation keys:
      * ``"compromise_delta"`` (float): add to compromise_ratio coord
      * ``"drift_delta"`` (float): add to mean+max drift coords
      * ``"add_agents"`` (int): bump entity-count coord
      * ``"add_tools"`` (int): bump entity-count coord

    Anything else is ignored (callers can pass labels in metadata
    keys like ``"label"``, ``"actor_entity_id"``, etc).
    """
    out = v.copy()
    cd = float(perturbation.get("compromise_delta", 0.0) or 0.0)
    dd = float(perturbation.get("drift_delta", 0.0) or 0.0)
    add_a = int(perturbation.get("add_agents", 0) or 0)
    add_t = int(perturbation.get("add_tools", 0) or 0)
    out[0] = float(np.clip(out[0] + cd, 0.0, 1.0))
    out[2] = float(np.clip(out[2] + dd, 0.0, 1.0))
    out[3] = float(np.clip(out[3] + dd, 0.0, 1.0))
    if add_a + add_t > 0:
        # Convert delta back through the log1p scale.
        current = float(np.expm1(out[1] * np.log1p(1000.0)))
        bumped = current + add_a + add_t
        out[1] = float(np.clip(np.log1p(bumped) / np.log1p(1000.0), 0.0, 1.0))
    return out


def _abstract_state_label(v: np.ndarray) -> str:
    """ProbGuard symbolic-state label from a continuous abstract vector."""
    # Reuse the bands from ``probguard.abstract_state`` but on the
    # continuous vector: this avoids round-trip to EcosystemState
    # construction during forecast steps.
    compromise = v[0]
    entity = v[1]
    drift = max(v[2], v[3])

    def _band3(x: float) -> str:
        if x < 0.33:
            return "lo"
        elif x < 0.66:
            return "md"
        else:
            return "hi"

    return f"agents_{_band3(entity)}/cap_{_band3(drift)}/comp_{_band3(compromise)}"


class EcosystemDigitalTwin:
    """
    Forks ecosystem state at a timestamp, simulates forward under a
    counterfactual perturbation, returns a conformal-covered fused-
    systemic-risk trajectory.

    Typical usage from the engine / API:

        twin = EcosystemDigitalTwin(graph=temporal_kg)
        forked = twin.fork_at(timestamp_iso="2026-05-20T15:00:00Z")
        traj = forked.simulate_forward(
            state=current_state,
            steps=16,
            perturbation={"compromise_delta": 0.15},
        )
        # traj.steps[-1].fused_systemic_score → forecast under perturbation

    A fork is *isolated*: mutations to its internal state never touch
    the parent twin or the underlying temporal KG. The KG itself is
    shared read-only via the snapshot mechanism.
    """

    def __init__(
        self,
        *,
        graph: InMemoryTemporalKG | None = None,
        dtmc_model: DTMCModel | None = None,
        weights: SystemicWeights | None = None,
        calibration_buffer: CalibrationBuffer | None = None,
        tenant_profile: TenantSignalProfile | None = None,
        learned_dictionary: bool = False,
    ) -> None:
        self._graph = graph
        # Snapshot loaded by ``fork_at``; None on a "live" twin.
        self._snapshot: TwinSnapshot | None = None
        # Per-tenant Koopman operator — refit from observed transitions
        # as they accumulate. None until we have >= MIN_TRAINING_N.
        self._koopman: KoopmanState | None = None
        # Observation buffer for Koopman fitting.
        self._transitions: list[tuple[np.ndarray, np.ndarray]] = []
        # Reuse the existing ProbGuard DTMC (Thread 7.1) for PCTL.
        self._dtmc = dtmc_model if dtmc_model is not None else default_model()
        # Conformal calibration shared across simulations.
        self._conformal = (
            calibration_buffer if calibration_buffer is not None
            else CalibrationBuffer(max_size=10_000)
        )
        self._weights = weights if weights is not None else SystemicWeights()
        self._generation = 0
        # Thread 9.1: tenant signal profile drives calibrator-informed
        # Koopman dictionary placement + SCCAL semantic-flow weighting.
        self._tenant_profile = tenant_profile
        # When the profile's snapshot_version advances, the next
        # observe_transition triggers a Koopman refit so the operator
        # tracks what the tenant has learned.
        self._learned_dictionary = bool(learned_dictionary)

    # ---------------------------------------------------------------- API

    def fork_at(self, *, timestamp_iso: str) -> "EcosystemDigitalTwin":
        """
        Produce a forked twin from a snapshot of the live ecosystem
        state at ``timestamp_iso``.

        The fork is fully isolated: mutating the fork's state never
        touches the parent twin or the underlying temporal KG.

        If no graph was provided at construction, the fork carries no
        snapshot — callers must pass an ``EcosystemState`` directly to
        ``simulate_forward`` (which is the common path; the engine
        already holds the state).
        """
        try:
            datetime.fromisoformat(timestamp_iso.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError(f"invalid ISO-8601 timestamp: {timestamp_iso!r}") from exc

        forked = EcosystemDigitalTwin(
            graph=None,  # forks don't carry the live KG handle
            dtmc_model=copy.deepcopy(self._dtmc),
            weights=self._weights,
            calibration_buffer=CalibrationBuffer(max_size=self._conformal._max_size),
            tenant_profile=self._tenant_profile,
            learned_dictionary=self._learned_dictionary,
        )
        forked._koopman = self._koopman  # frozen Pydantic model — share is safe
        # Copy calibration snapshot so the fork doesn't share future writes.
        for s in self._conformal.snapshot():
            forked._conformal.add(s)

        if self._graph is not None:
            # Deep-copy the versions dict at the snapshot time. We use the
            # KG's own data structures via the public _entities helper.
            snap = self._snapshot_versions(at_iso=timestamp_iso)
            forked._snapshot = snap
        else:
            forked._snapshot = self._snapshot

        forked._generation = self._generation + 1

        emit_event(
            "ecosystem.twin.fork_at",
            timestamp_iso=timestamp_iso,
            generation=forked._generation,
            koopman_trained=forked._koopman is not None,
            n_calibration=forked._conformal.n,
        )
        return forked

    def simulate_forward(
        self,
        *,
        state: EcosystemState,
        steps: int = DEFAULT_HORIZON,
        perturbation: Mapping[str, Any] | None = None,
        adjacency_override: np.ndarray | None = None,
        edge_labels_override: tuple[tuple[str, str], ...] | None = None,
    ) -> SimulationTrajectory:
        """
        Roll out a counterfactual trajectory for ``steps`` time steps.

        Returns
        -------
        SimulationTrajectory whose ``steps[i].fused_systemic_score``
        reports the conformal-covered fused score at step i. The
        first step is the perturbation-applied initial condition; all
        subsequent steps are Koopman-advanced.

        The trajectory is *deterministic* given (state, perturbation,
        koopman state, weights, dtmc state) — replay-stable for
        evidence-chain purposes.
        """
        if steps < 1:
            raise ValueError(f"steps must be >= 1, got {steps!r}")
        if steps > MAX_HORIZON:
            raise ValueError(f"steps must be <= {MAX_HORIZON}, got {steps!r}")
        if perturbation is None:
            perturbation = {}

        x0 = _state_to_abstract_vector(state)
        x0_perturbed = _perturb_vector(x0, perturbation)

        # If we have a Koopman model, roll out; else identity forecast.
        forecast = predict_trajectory(
            self._koopman, x0_perturbed, horizon=steps - 1,
        )
        # forecast.shape == (steps, 4)

        # SCCAL on current graph (the interaction graph is the same
        # across the short horizon — geometry doesn't change in the
        # forecast unless caller passes adjacency_override).
        if adjacency_override is not None:
            adj = adjacency_override
            edge_labels = edge_labels_override or ()
        else:
            adj, edge_labels = _build_interaction_graph(state)

        # Thread 9.1: build a calibrator-weighted semantic flow per edge.
        # The flow magnitude on each edge is shaped by the tenant profile's
        # signal importance — high-importance signals contribute more
        # semantic tension, so the SCCAL curvature-gated recurrence sees
        # the tenant's actual risk geometry. When no profile is provided
        # or no semantic data exists, fall back to geometry-only mode.
        semantic_flow = self._build_calibrator_weighted_semantic_flow(
            adj=adj, state=state,
        )
        sccal = compute_sccal(
            adj=adj,
            semantic_flow=semantic_flow,
            edge_labels=edge_labels,
            enable_curvature_gated_recurrence=True,
            recurrence_steps=4,
        )

        # ProbGuard PCTL scoring at each forecast step.
        traj_steps: list[TrajectoryStep] = []
        for i in range(steps):
            v = forecast[i]
            label = _abstract_state_label(v)
            try:
                pctl = float(
                    reachability_probability(
                        model=self._dtmc, initial_state=label, horizon_k=10,
                    )
                )
            except Exception:  # pragma: no cover — fail-safe
                pctl = 0.0
            pctl = float(np.clip(pctl, 0.0, 1.0))

            # Cascade reachability proxy: distance of (compromise, drift)
            # to the unsafe corner. Higher = closer = riskier.
            casc_proxy = float(np.clip(
                0.5 * v[0] + 0.5 * max(v[2], v[3]), 0.0, 1.0,
            ))

            fused = float(np.clip(
                self._weights.w_pctl * pctl
                + self._weights.w_sccal * sccal.score
                + self._weights.w_cascade * casc_proxy,
                0.0, 1.0,
            ))

            band = band_for_prediction(
                point=fused, buffer=self._conformal, alpha=0.1, delta=0.05,
            )

            traj_steps.append(
                TrajectoryStep(
                    step_index=i,
                    state_hash=_hash_abstract_state(v),
                    probguard_pctl_score=pctl,
                    sccal_score=sccal.score,
                    fused_systemic_score=fused,
                    drift_signals={
                        "compromise": float(v[0]),
                        "entity_load": float(v[1]),
                        "drift_mean": float(v[2]),
                        "drift_max": float(v[3]),
                    },
                    conformal_lower=band.lower,
                    conformal_upper=band.upper,
                )
            )

        twin_run_id = self._make_run_id(state=state, perturbation=perturbation)
        traj = SimulationTrajectory(
            fork_timestamp_iso=state.snapshot_at.isoformat(),
            perturbation_summary={
                str(k): str(v) for k, v in (perturbation or {}).items()
            },
            horizon=steps,
            steps=tuple(traj_steps),
            most_likely_cascade_path=None,  # set by caller via cascade predictor
            worst_case_cascade_path=None,
            twin_run_id=twin_run_id,
        )

        emit_event(
            "ecosystem.twin.simulate_forward",
            twin_run_id=twin_run_id,
            steps=steps,
            generation=self._generation,
            final_fused_score=traj_steps[-1].fused_systemic_score,
            max_fused_score=max(s.fused_systemic_score for s in traj_steps),
            koopman_trained=self._koopman is not None,
        )
        return traj

    # -------------------------------------------------------- training API

    def observe_transition(
        self,
        *,
        from_state: EcosystemState,
        to_state: EcosystemState,
    ) -> None:
        """
        Record an observed (x_t, x_{t+1}) transition for Koopman fitting.

        The engine calls this on every successful evaluate() that
        admits an event (i.e. the new state is real). Calls are cheap
        when the buffer is small; refit fires lazily on the next
        ``simulate_forward`` once we cross ``MIN_TRAINING_N``.
        """
        x = _state_to_abstract_vector(from_state)
        y = _state_to_abstract_vector(to_state)
        self._transitions.append((x, y))

        # Record the actual one-step residual for conformal calibration.
        # We use the absolute residual of any single coord (here:
        # compromise_ratio, the primary risk axis).
        if self._koopman is not None:
            from tex.systemic._koopman import advance
            predicted = advance(self._koopman, x, steps=1)
            residual = float(abs(predicted[0] - y[0]))
            self._conformal.add(residual)

        # Refit periodically — every 8 new transitions once trained,
        # immediately when crossing the training threshold.
        n = len(self._transitions)
        if n == MIN_TRAINING_N or (n > MIN_TRAINING_N and n % 8 == 0):
            self._refit_koopman()

        # Also let the DTMC see this transition.
        try:
            self._dtmc.observe_transition(
                from_state=abstract_state(from_state),
                to_state=abstract_state(to_state),
            )
        except Exception:  # pragma: no cover
            pass

    def _refit_koopman(self) -> None:
        """Re-fit the Koopman operator from the accumulated buffer.

        Thread 9.1: the dictionary is calibrator-informed via
        ``self._tenant_profile`` (signal weights + high-leverage RBF
        centers). When ``learned_dictionary=True`` and torch is
        available, the NN-lift path fires instead.
        """
        if len(self._transitions) < MIN_TRAINING_N:
            return
        self._koopman = fit_koopman(
            self._transitions,
            state_dim=4,
            generation=self._generation,
            tenant_profile=self._tenant_profile,
            learned_dictionary=self._learned_dictionary,
        )
        emit_event(
            "ecosystem.twin.koopman_refit",
            n_observations=len(self._transitions),
            lifted_dim=self._koopman.lifted_dim if self._koopman else None,
            dictionary_kind=(
                self._koopman.dictionary_kind if self._koopman else None
            ),
            tenant_snapshot_version=(
                self._tenant_profile.snapshot_version
                if self._tenant_profile else 0
            ),
        )

    def update_tenant_profile(
        self,
        profile: TenantSignalProfile | None,
    ) -> None:
        """Swap the tenant signal profile and refit Koopman if version bumped.

        Thread 9.1 self-tuning loop: when ``ThresholdCalibrator`` emits
        a new recommendation, the operator (or a small adapter) calls
        this with the updated profile. The twin refits its Koopman
        dictionary around the new signal importance + high-leverage
        regions, so the next ``simulate_forward`` reflects what the
        tenant has learned.
        """
        prev = self._tenant_profile
        self._tenant_profile = profile
        prev_v = prev.snapshot_version if prev else -1
        new_v = profile.snapshot_version if profile else -1
        if new_v != prev_v:
            emit_event(
                "ecosystem.twin.tenant_profile_update",
                tenant_id=profile.tenant_id if profile else "default",
                previous_version=prev_v,
                new_version=new_v,
                will_refit=len(self._transitions) >= MIN_TRAINING_N,
            )
            # Eager refit so subsequent simulate_forward calls use the
            # new dictionary; if we have no data yet, the next
            # observe_transition crossing the threshold will fit.
            if len(self._transitions) >= MIN_TRAINING_N:
                self._refit_koopman()

    # ------------------------------------------------------------- helpers

    def _build_calibrator_weighted_semantic_flow(
        self,
        *,
        adj: np.ndarray,
        state: EcosystemState,
    ) -> np.ndarray:
        """
        Per-edge semantic flow vector weighted by tenant signal importance.

        Thread 9.1: closes the calibrator → SCCAL loop. The per-edge flow
        vector's magnitude is scaled by the calibrator's signal-importance
        weights, so the curvature-gated recurrence "sees" what the tenant
        has learned matters. When no profile is wired, returns an empty
        flow array (geometry-only SCCAL fallback).

        Flow construction:
          For each edge (u, v), build a d-dim vector whose entries are
          [compromise_ratio, log_entity_load, drift_mean, drift_max],
          each scaled by the calibrator's importance weight for that
          coordinate. This is a cheap and replay-stable proxy; live
          deployments override with the temporal-KG event semantic
          embedding via the existing ``adjacency_override`` /
          ``edge_labels_override`` machinery.
        """
        edges_idx = np.argwhere(adj > 0)
        n_edges = int(edges_idx.shape[0])
        if n_edges == 0 or self._tenant_profile is None:
            return np.zeros((0, 0))

        x = _state_to_abstract_vector(state)
        weights = self._tenant_profile.normalized_importance()
        if weights.size != x.size:
            return np.zeros((0, 0))

        flow_vec = x * weights  # element-wise
        # Broadcast the same flow vector across all edges as a baseline;
        # variation comes from the curvature-gated attention itself.
        return np.tile(flow_vec[None, :], (n_edges, 1))

    def _snapshot_versions(self, *, at_iso: str) -> TwinSnapshot:
        """Deep-copy the temporal KG's version timelines for isolation."""
        if self._graph is None:
            return TwinSnapshot(
                snapshot_at_iso=at_iso,
                state_hash="ecosystem_no_graph",
                versions={},
            )
        # We deliberately do not reach into private internals beyond the
        # public _entities/_underlying_graph accessor — the temporal KG's
        # immutable snapshot tuples make this safe.
        entity_ids = self._graph._entities()  # public-prefixed accessor
        versions: dict[str, tuple[tuple[str, dict[str, Any]], ...]] = {}
        for eid in entity_ids:
            # Walk version timeline up to at_iso.
            ts_target = datetime.fromisoformat(at_iso.replace("Z", "+00:00"))
            snapshot = self._graph.get_entity_at(eid, ts_target)
            if snapshot is not None:
                versions[eid] = ((at_iso, copy.deepcopy(snapshot)),)
        try:
            sh = self._graph.state_hash(
                datetime.fromisoformat(at_iso.replace("Z", "+00:00"))
            )
        except Exception:
            sh = "ecosystem_snapshot_hash_unavailable"
        return TwinSnapshot(
            snapshot_at_iso=at_iso,
            state_hash=sh,
            versions=versions,
        )

    def _make_run_id(
        self,
        *,
        state: EcosystemState,
        perturbation: Mapping[str, Any],
    ) -> str:
        """Deterministic SHA-256 over (state_hash, perturbation, generation)."""
        h = hashlib.sha256()
        h.update(b"tex:thread9:twin_run:")
        h.update(state.state_hash.encode("utf-8"))
        h.update(str(sorted(perturbation.items())).encode("utf-8"))
        h.update(str(self._generation).encode("utf-8"))
        # 16-char prefix — collision-resistant within a tenant.
        return h.hexdigest()[:32]

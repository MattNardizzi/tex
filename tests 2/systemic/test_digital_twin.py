"""Tests for Thread 9 EcosystemDigitalTwin."""

from __future__ import annotations

from datetime import UTC, datetime

import numpy as np
import pytest

from tex.ecosystem.state import EcosystemState
from tex.systemic.digital_twin import (
    DEFAULT_HORIZON,
    MAX_HORIZON,
    EcosystemDigitalTwin,
)
from tex.systemic.trajectory import SimulationTrajectory, SystemicWeights


@pytest.fixture
def state() -> EcosystemState:
    return EcosystemState(
        snapshot_at=datetime(2026, 5, 20, 12, 0, 0, tzinfo=UTC),
        state_hash="a" * 64,
        active_agent_ids=("agent_1", "agent_2"),
        active_tool_ids=("tool_a", "tool_b"),
        active_capability_ids=("cap_1",),
        active_governance_graph_id="gov_v1",
        aggregate_drift_signals={"sig1": 0.2, "sig2": 0.3},
        sliding_window_compromise_ratio=0.1,
    )


@pytest.fixture
def state_high(state: EcosystemState) -> EcosystemState:
    return state.model_copy(
        update={
            "sliding_window_compromise_ratio": 0.6,
            "aggregate_drift_signals": {"sig1": 0.7, "sig2": 0.6},
        }
    )


def test_fork_at_returns_independent_twin(state: EcosystemState) -> None:
    parent = EcosystemDigitalTwin()
    forked = parent.fork_at(timestamp_iso="2026-05-20T12:00:00+00:00")
    assert forked is not parent
    # Generation counter advances on fork.
    assert forked._generation == parent._generation + 1


def test_fork_at_rejects_bad_iso() -> None:
    twin = EcosystemDigitalTwin()
    with pytest.raises(ValueError, match="invalid ISO-8601"):
        twin.fork_at(timestamp_iso="not-a-timestamp")


def test_simulate_forward_returns_trajectory_with_correct_length(
    state: EcosystemState,
) -> None:
    twin = EcosystemDigitalTwin().fork_at(timestamp_iso="2026-05-20T12:00:00+00:00")
    traj = twin.simulate_forward(state=state, steps=12, perturbation={})
    assert isinstance(traj, SimulationTrajectory)
    assert traj.horizon == 12
    assert len(traj.steps) == 12
    # Step indices are sequential.
    for i, s in enumerate(traj.steps):
        assert s.step_index == i


def test_simulate_forward_default_horizon(state: EcosystemState) -> None:
    twin = EcosystemDigitalTwin().fork_at(timestamp_iso="2026-05-20T12:00:00+00:00")
    traj = twin.simulate_forward(state=state)
    assert traj.horizon == DEFAULT_HORIZON


def test_simulate_forward_rejects_zero_horizon(state: EcosystemState) -> None:
    twin = EcosystemDigitalTwin().fork_at(timestamp_iso="2026-05-20T12:00:00+00:00")
    with pytest.raises(ValueError, match="steps must be"):
        twin.simulate_forward(state=state, steps=0)


def test_simulate_forward_rejects_oversize_horizon(state: EcosystemState) -> None:
    twin = EcosystemDigitalTwin().fork_at(timestamp_iso="2026-05-20T12:00:00+00:00")
    with pytest.raises(ValueError, match="steps must be"):
        twin.simulate_forward(state=state, steps=MAX_HORIZON + 1)


def test_perturbation_increases_fused_score(state: EcosystemState) -> None:
    """A high-compromise perturbation must yield a higher max fused score
    than a no-op perturbation."""
    twin = EcosystemDigitalTwin().fork_at(timestamp_iso="2026-05-20T12:00:00+00:00")
    base = twin.simulate_forward(state=state, steps=8, perturbation={})
    pert = twin.simulate_forward(
        state=state, steps=8,
        perturbation={"compromise_delta": 0.6, "drift_delta": 0.5},
    )
    base_max = max(s.fused_systemic_score for s in base.steps)
    pert_max = max(s.fused_systemic_score for s in pert.steps)
    assert pert_max > base_max


def test_observe_transition_trains_koopman(
    state: EcosystemState, state_high: EcosystemState,
) -> None:
    twin = EcosystemDigitalTwin()
    assert twin._koopman is None
    for _ in range(10):
        twin.observe_transition(from_state=state, to_state=state_high)
    assert twin._koopman is not None
    assert twin._koopman.state_dim == 4
    assert twin._koopman.lifted_dim > 4


def test_trained_twin_forecast_differs_from_identity(
    state: EcosystemState, state_high: EcosystemState,
) -> None:
    twin = EcosystemDigitalTwin()
    # Build up a clean trend toward unsafe.
    for _ in range(20):
        twin.observe_transition(from_state=state, to_state=state_high)
    traj = twin.simulate_forward(state=state, steps=6, perturbation={})
    # The trained model should not produce purely-constant trajectories.
    first = traj.steps[0].fused_systemic_score
    later = [s.fused_systemic_score for s in traj.steps[1:]]
    assert any(abs(v - first) > 0 for v in later)


def test_trajectory_steps_have_conformal_band(state: EcosystemState) -> None:
    twin = EcosystemDigitalTwin().fork_at(timestamp_iso="2026-05-20T12:00:00+00:00")
    traj = twin.simulate_forward(state=state, steps=4, perturbation={})
    for s in traj.steps:
        assert 0.0 <= s.conformal_lower <= s.fused_systemic_score <= s.conformal_upper <= 1.0


def test_twin_run_id_is_deterministic(state: EcosystemState) -> None:
    """Same (state, perturbation, generation) → same run id."""
    twin = EcosystemDigitalTwin()
    a = twin.simulate_forward(state=state, steps=4, perturbation={"x": 1})
    b = twin.simulate_forward(state=state, steps=4, perturbation={"x": 1})
    assert a.twin_run_id == b.twin_run_id


def test_twin_run_id_changes_on_perturbation(state: EcosystemState) -> None:
    twin = EcosystemDigitalTwin()
    a = twin.simulate_forward(state=state, steps=4, perturbation={"x": 1})
    b = twin.simulate_forward(state=state, steps=4, perturbation={"x": 2})
    assert a.twin_run_id != b.twin_run_id


def test_custom_weights_change_fused_score(state: EcosystemState) -> None:
    twin_default = EcosystemDigitalTwin()
    twin_sccal_heavy = EcosystemDigitalTwin(
        weights=SystemicWeights(w_pctl=0.1, w_sccal=0.8, w_cascade=0.1),
    )
    p = {"compromise_delta": 0.4, "drift_delta": 0.3}
    a = twin_default.simulate_forward(state=state, steps=4, perturbation=p)
    b = twin_sccal_heavy.simulate_forward(state=state, steps=4, perturbation=p)
    # Scores must differ when weights are materially different — except
    # in the degenerate case where SCCAL is 0 (empty interaction graph).
    if any(s.sccal_score > 0 for s in a.steps):
        assert a.steps[-1].fused_systemic_score != b.steps[-1].fused_systemic_score


def test_perturbation_summary_serializes(state: EcosystemState) -> None:
    twin = EcosystemDigitalTwin()
    traj = twin.simulate_forward(
        state=state, steps=2,
        perturbation={"label": "test", "compromise_delta": 0.1},
    )
    assert traj.perturbation_summary == {
        "label": "test",
        "compromise_delta": "0.1",
    }


def test_fork_isolates_calibration_buffer(state: EcosystemState) -> None:
    parent = EcosystemDigitalTwin()
    # Seed parent's buffer.
    parent._conformal.add(0.5)
    parent._conformal.add(0.3)
    forked = parent.fork_at(timestamp_iso="2026-05-20T12:00:00+00:00")
    # Snapshot of parent visible to fork at fork time.
    assert forked._conformal.n == parent._conformal.n
    # Subsequent writes don't cross over.
    parent._conformal.add(0.9)
    assert forked._conformal.n < parent._conformal.n


def test_state_hash_in_step_is_64_char_hex(state: EcosystemState) -> None:
    twin = EcosystemDigitalTwin().fork_at(timestamp_iso="2026-05-20T12:00:00+00:00")
    traj = twin.simulate_forward(state=state, steps=2)
    for s in traj.steps:
        assert len(s.state_hash) == 64
        int(s.state_hash, 16)  # parses as hex


def test_systemic_weights_reject_oversize_sum() -> None:
    with pytest.raises(ValueError, match="must sum to <= 1.0"):
        SystemicWeights(w_pctl=0.5, w_sccal=0.5, w_cascade=0.5)

"""Tests for Thread 9 SystemicRiskEvaluator.score_fused()."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from tex.ecosystem.state import EcosystemState
from tex.systemic.digital_twin import EcosystemDigitalTwin
from tex.systemic.risk_evaluator import SystemicRiskEvaluator
from tex.systemic.trajectory import SystemicWeights


@pytest.fixture
def state() -> EcosystemState:
    return EcosystemState(
        snapshot_at=datetime(2026, 5, 20, 12, 0, 0, tzinfo=UTC),
        state_hash="b" * 64,
        active_agent_ids=("a1", "a2"),
        active_tool_ids=("t1",),
        active_capability_ids=("c1",),
        active_governance_graph_id="g_v1",
        aggregate_drift_signals={"sig": 0.4},
        sliding_window_compromise_ratio=0.25,
    )


def test_pure_pctl_unchanged_by_extension(state: EcosystemState) -> None:
    """score() still returns pure PCTL — backward-compat preserved."""
    ev = SystemicRiskEvaluator()
    pure = ev.score(state=state)
    assert 0.0 <= pure <= 1.0


def test_fused_equals_pctl_when_other_signals_zero(state: EcosystemState) -> None:
    """With sccal=0 and cascade=0, fused == w_pctl * pctl."""
    ev = SystemicRiskEvaluator()
    pure = ev.score(state=state)
    ev2 = SystemicRiskEvaluator()  # fresh DTMC so model state matches
    fused = ev2.score_fused(state=state, sccal_score=0.0, cascade_reachability=0.0)
    w = SystemicWeights()
    assert fused == pytest.approx(w.w_pctl * pure, abs=1e-6)


def test_fused_dominated_by_sccal_when_pctl_zero(state: EcosystemState) -> None:
    """High SCCAL must lift the fused score."""
    ev = SystemicRiskEvaluator()
    low = ev.score_fused(state=state, sccal_score=0.0, cascade_reachability=0.0)
    ev2 = SystemicRiskEvaluator()
    high = ev2.score_fused(state=state, sccal_score=0.9, cascade_reachability=0.0)
    assert high > low


def test_fused_clamped_to_unit(state: EcosystemState) -> None:
    """Even with all signals maxed, output is in [0, 1]."""
    ev = SystemicRiskEvaluator()
    fused = ev.score_fused(state=state, sccal_score=1.0, cascade_reachability=1.0)
    assert 0.0 <= fused <= 1.0


def test_custom_weights_change_output(state: EcosystemState) -> None:
    ev = SystemicRiskEvaluator()
    default = ev.score_fused(state=state, sccal_score=0.5, cascade_reachability=0.5)
    ev2 = SystemicRiskEvaluator()
    custom = ev2.score_fused(
        state=state, sccal_score=0.5, cascade_reachability=0.5,
        weights=SystemicWeights(w_pctl=0.1, w_sccal=0.1, w_cascade=0.1),
    )
    # Custom weights sum to 0.3 — lower than the default 1.0 sum.
    assert custom < default


def test_fused_with_trajectory(state: EcosystemState) -> None:
    """Trajectory worst-step propagates into fused as SCCAL + cascade
    defaults."""
    twin = EcosystemDigitalTwin().fork_at(timestamp_iso="2026-05-20T12:00:00+00:00")
    traj = twin.simulate_forward(
        state=state, steps=6,
        perturbation={"compromise_delta": 0.4, "drift_delta": 0.3},
    )
    ev = SystemicRiskEvaluator()
    fused = ev.score_fused(state=state, twin_trajectory=traj)
    assert 0.0 <= fused <= 1.0


def test_fused_inputs_clamped_defensively(state: EcosystemState) -> None:
    """Out-of-range SCCAL/cascade are clamped to [0, 1] silently."""
    ev = SystemicRiskEvaluator()
    fused = ev.score_fused(state=state, sccal_score=2.0, cascade_reachability=-0.5)
    assert 0.0 <= fused <= 1.0

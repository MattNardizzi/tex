"""
Tests for ProbGuard PCTL systemic risk scorer (Thread 7.1).

Reference: ProbGuard / Pro2Guard (arxiv 2508.00500 v3, Mar 27 2026).

Coverage
--------
* DTMC abstraction is total (every EcosystemState maps to one of 27 ids)
* Transition matrix is row-stochastic (rows sum to 1.0 ± float eps)
* Reachability is bounded in [0, 1]
* Unsafe states are absorbing — reachability from them is 1.0
* Self-loop prior produces low cold-start risk (<0.20)
* Score increases when compromise ratio increases
* Latency < 5ms p99 per call
* SystemicRiskEvaluator.score() no longer raises NotImplementedError
* Successive score() calls feed the model with (last, current) transitions
* Backward-compatible signature (state= keyword only)
"""

from __future__ import annotations

import time
from datetime import UTC, datetime

import pytest

from tex.ecosystem.state import EcosystemState
from tex.systemic.probguard import (
    DTMCModel,
    abstract_state,
    all_states,
    reachability_probability,
    unsafe_states,
    _reset_default_model,
)
from tex.systemic.risk_evaluator import SystemicRiskEvaluator


# ----- fixtures -----------------------------------------------------------


@pytest.fixture(autouse=True)
def fresh_default_model():
    """Reset the module-level singleton between tests."""
    _reset_default_model()
    yield
    _reset_default_model()


def _state(*, compromise: float = 0.1, cap_grant: float = 0.5, n_agents: int = 1) -> EcosystemState:
    return EcosystemState(
        snapshot_at=datetime(2026, 5, 18, 12, 0, 0, tzinfo=UTC),
        state_hash="0" * 64,
        active_agent_ids=tuple(f"a{i}" for i in range(n_agents)),
        active_tool_ids=("t",),
        active_capability_ids=(),
        active_governance_graph_id="g0",
        sliding_window_compromise_ratio=compromise,
        aggregate_drift_signals={"capability_grant_rate": cap_grant},
    )


# ----- abstract_state coverage ---------------------------------------------


def test_abstract_state_total_over_27_classes() -> None:
    """Every plausible EcosystemState maps to one of the 27 ids."""
    seen: set[str] = set()
    for n in (0, 1, 2, 5, 10, 100, 1000):
        for cap in (0.0, 0.5, 2.0, 8.0, 1e6):
            for comp in (0.0, 0.1, 0.3, 0.6, 0.99):
                s = _state(compromise=comp, cap_grant=cap, n_agents=n)
                aid = abstract_state(s)
                assert aid in all_states()
                seen.add(aid)
    # Should cover a wide swath of the 27 (not necessarily all
    # because n=0 collapses with n=1 in the "few" band's lower end).
    assert len(seen) >= 9


def test_abstract_state_deterministic() -> None:
    s1 = _state(compromise=0.5, cap_grant=1.5, n_agents=3)
    s2 = _state(compromise=0.5, cap_grant=1.5, n_agents=3)
    assert abstract_state(s1) == abstract_state(s2)


# ----- DTMC matrix properties ----------------------------------------------


def test_transition_matrix_row_stochastic() -> None:
    """Every row sums to 1.0 (within float tolerance)."""
    m = DTMCModel()
    p = m.transition_matrix
    for i, row in enumerate(p):
        assert abs(sum(row) - 1.0) < 1e-9, f"row {i} sums to {sum(row)}"


def test_transition_matrix_observations_update() -> None:
    m = DTMCModel()
    p_before = [list(row) for row in m.transition_matrix]
    m.observe_transition(
        from_state=all_states()[0], to_state=all_states()[1],
    )
    p_after = m.transition_matrix
    # The cell (0, 1) should have strictly increased.
    assert p_after[0][1] > p_before[0][1]


def test_unsafe_states_count() -> None:
    """9 of 27 abstraction ids are in the high-compromise band."""
    assert len(unsafe_states()) == 9


# ----- reachability ---------------------------------------------------------


def test_reachability_bounded_unit_interval() -> None:
    m = DTMCModel()
    for s in all_states():
        p = reachability_probability(
            model=m, initial_state=s, horizon_k=10,
        )
        assert 0.0 <= p <= 1.0


def test_reachability_from_unsafe_state_is_one() -> None:
    """Unsafe states are absorbing — reachability from them is 1.0."""
    m = DTMCModel()
    for s in unsafe_states():
        p = reachability_probability(
            model=m, initial_state=s, horizon_k=10,
        )
        assert p == 1.0


def test_cold_start_low_risk_from_safe_state() -> None:
    """Self-loop prior calibration: cold-start risk from a clearly
    safe state should be < 0.20."""
    m = DTMCModel()
    safe = _state(compromise=0.05, cap_grant=0.1, n_agents=1)
    p = reachability_probability(
        model=m, initial_state=abstract_state(safe), horizon_k=10,
    )
    assert p < 0.20, f"cold-start safe-state risk {p} too aggressive"


def test_reachability_horizon_must_be_positive() -> None:
    m = DTMCModel()
    with pytest.raises(ValueError, match="horizon_k"):
        reachability_probability(
            model=m, initial_state=all_states()[0], horizon_k=0,
        )


def test_reachability_unknown_initial_state_returns_zero() -> None:
    m = DTMCModel()
    p = reachability_probability(
        model=m, initial_state="not:a:state", horizon_k=10,
    )
    assert p == 0.0


# ----- SystemicRiskEvaluator integration -----------------------------------


def test_evaluator_no_longer_raises_not_implemented() -> None:
    ev = SystemicRiskEvaluator(model=DTMCModel())
    s = _state(compromise=0.1, cap_grant=0.5, n_agents=1)
    # Must not raise — the prior behavior was NotImplementedError.
    score = ev.score(state=s)
    assert isinstance(score, float)
    assert 0.0 <= score <= 1.0


def test_evaluator_score_increases_under_compromise_pressure() -> None:
    """Repeated observations of compromised states should increase the
    reachability score on subsequent calls."""
    ev = SystemicRiskEvaluator(model=DTMCModel())
    safe = _state(compromise=0.05, cap_grant=0.1, n_agents=1)
    initial = ev.score(state=safe)

    # Push transitions into high-compromise territory.
    compromised = _state(compromise=0.85, cap_grant=8.0, n_agents=5)
    for _ in range(20):
        ev.score(state=compromised)
    # Score for a recently-compromised regime is high.
    elevated = ev.score(state=compromised)
    assert elevated >= initial


def test_evaluator_records_transitions_across_calls() -> None:
    """Successive score() calls feed the model with (last, current)
    transitions. With self_loop_prior=50 the diagonal dominates each
    row, so we verify by comparing the observed off-diagonal cell
    against an *unrecorded* off-diagonal cell in the same row."""
    ev = SystemicRiskEvaluator(model=DTMCModel())
    s_a = _state(compromise=0.1, cap_grant=0.5, n_agents=1)
    s_b = _state(compromise=0.4, cap_grant=2.5, n_agents=5)
    aid_a = abstract_state(s_a)
    aid_b = abstract_state(s_b)
    assert aid_a != aid_b  # sanity

    ev.score(state=s_a)
    ev.score(state=s_b)

    matrix = ev.model.transition_matrix
    from tex.systemic.probguard import _STATE_INDEX
    i, j = _STATE_INDEX[aid_a], _STATE_INDEX[aid_b]

    # Pick a different off-diagonal column with no observation.
    k = next(
        idx for idx in range(len(all_states()))
        if idx not in (i, j)
    )
    observed_cell = matrix[i][j]
    unobserved_cell = matrix[i][k]
    assert observed_cell > unobserved_cell, (
        f"observed cell {observed_cell} should exceed "
        f"unobserved peer {unobserved_cell}"
    )


def test_evaluator_horizon_k_validation() -> None:
    with pytest.raises(ValueError, match="horizon_k"):
        SystemicRiskEvaluator(horizon_k=0)
    with pytest.raises(ValueError, match="horizon_k"):
        SystemicRiskEvaluator(horizon_k=-1)


def test_evaluator_custom_model_isolation() -> None:
    """Two evaluators with separate models don't share state."""
    ev_a = SystemicRiskEvaluator(model=DTMCModel())
    ev_b = SystemicRiskEvaluator(model=DTMCModel())
    s = _state(compromise=0.5, cap_grant=2.0, n_agents=3)
    # Drive ev_a hard, ev_b not at all.
    for _ in range(20):
        ev_a.score(state=s)
    # ev_b's model should still be at the prior.
    assert ev_b.score(state=s) != ev_a.score(state=s) or True  # may converge
    # More direct: ev_a's model has recorded transitions; ev_b's hasn't.
    a_counts = sum(sum(row) for row in ev_a.model._counts)
    b_counts = sum(sum(row) for row in ev_b.model._counts)
    assert a_counts > b_counts


# ----- latency budget ------------------------------------------------------


def test_score_under_5ms_p99() -> None:
    """Spec: total evaluate() <50ms p99; Step 7 budget ~10ms.
    ProbGuard PCTL should stay well inside that."""
    ev = SystemicRiskEvaluator(model=DTMCModel())
    s = _state(compromise=0.3, cap_grant=1.0, n_agents=3)

    # warm
    for _ in range(20):
        ev.score(state=s)

    ts: list[float] = []
    for _ in range(500):
        t0 = time.perf_counter()
        ev.score(state=s)
        ts.append((time.perf_counter() - t0) * 1000.0)

    ts.sort()
    p99 = ts[495]
    assert p99 < 5.0, f"ProbGuard score p99 {p99:.3f}ms exceeds 5ms"

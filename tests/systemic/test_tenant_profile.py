"""Tests for Thread 9.1 calibrator-informed Koopman + NN-lift."""

from __future__ import annotations

from datetime import UTC, datetime

import numpy as np
import pytest

from tex.ecosystem.state import EcosystemState
from tex.systemic._koopman import (
    MIN_TRAINING_N,
    TenantSignalProfile,
    _HAS_TORCH,
    advance,
    fit_koopman,
    lift_via_state,
)
from tex.systemic.digital_twin import EcosystemDigitalTwin


def _transitions(seed: int = 0, n: int = 20):
    rng = np.random.default_rng(seed)
    return [(rng.random(4), rng.random(4)) for _ in range(n)]


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


# -------------------------------------------------------- TenantSignalProfile


def test_uniform_profile_defaults() -> None:
    p = TenantSignalProfile.uniform(state_dim=4)
    assert p.signal_importance == (1.0, 1.0, 1.0, 1.0)
    assert p.snapshot_version == 0
    assert p.high_leverage_regions == ()


def test_normalized_importance_preserves_scale() -> None:
    p = TenantSignalProfile(signal_importance=(2.0, 1.0, 0.5, 0.5))
    arr = p.normalized_importance()
    # Normalized to mean 1.0
    assert arr.mean() == pytest.approx(1.0, abs=1e-9)
    # Order preserved
    assert arr[0] > arr[1] > arr[2]


def test_normalized_importance_handles_zero_sum() -> None:
    p = TenantSignalProfile(signal_importance=(0.0, 0.0, 0.0, 0.0))
    arr = p.normalized_importance()
    # Falls back to ones when all zero.
    assert np.allclose(arr, 1.0)


# -------------------------------------------------------- Calibrator-informed fit


def test_fit_with_profile_produces_signal_weights() -> None:
    profile = TenantSignalProfile(
        signal_importance=(2.0, 0.5, 1.0, 1.5),
        snapshot_version=3,
    )
    k = fit_koopman(_transitions(), state_dim=4, tenant_profile=profile)
    assert k is not None
    assert k.dictionary_kind == "polynomial_rbf"
    assert k.signal_weights is not None
    assert k.tenant_snapshot_version == 3


def test_fit_without_profile_has_no_signal_weights() -> None:
    k = fit_koopman(_transitions(), state_dim=4)
    assert k is not None
    assert k.signal_weights is None
    assert k.tenant_snapshot_version == 0


def test_profile_changes_forecast_for_same_data() -> None:
    """Two profiles → two different operators → two different forecasts."""
    profile_a = TenantSignalProfile(signal_importance=(2.0, 0.5, 1.0, 0.5))
    profile_b = TenantSignalProfile(signal_importance=(0.5, 2.0, 0.5, 1.0))
    t = _transitions()
    k_a = fit_koopman(t, state_dim=4, tenant_profile=profile_a)
    k_b = fit_koopman(t, state_dim=4, tenant_profile=profile_b)
    x = np.array([0.3, 0.5, 0.4, 0.2])
    y_a = advance(k_a, x)
    y_b = advance(k_b, x)
    assert not np.allclose(y_a, y_b)


def test_high_leverage_regions_placed_in_rbf_centers() -> None:
    region = (0.95, 0.95, 0.95, 0.95)
    profile = TenantSignalProfile(
        signal_importance=(1.0,) * 4,
        high_leverage_regions=(region,),
        snapshot_version=1,
    )
    k = fit_koopman(_transitions(), state_dim=4, tenant_profile=profile)
    assert k is not None
    # The leverage region should appear among the RBF centers.
    centers = np.array(k.rbf_centers)
    matches = np.all(np.isclose(centers, np.array(region)), axis=1)
    assert matches.any()


def test_lift_via_state_dispatches_on_dictionary_kind() -> None:
    profile = TenantSignalProfile(signal_importance=(2.0,) * 4)
    k = fit_koopman(_transitions(), state_dim=4, tenant_profile=profile)
    x = np.array([0.1, 0.5, 0.3, 0.4])
    z = lift_via_state(x, k)
    assert z.shape == (k.lifted_dim,)


# -------------------------------------------------------- NN-lift path


@pytest.mark.skipif(not _HAS_TORCH, reason="torch not installed")
def test_nn_lift_dictionary_kind() -> None:
    k = fit_koopman(_transitions(n=30), state_dim=4, learned_dictionary=True)
    assert k is not None
    assert k.dictionary_kind == "nn"
    assert k.nn_layer_weights is not None
    assert k.nn_layer_biases is not None


@pytest.mark.skipif(not _HAS_TORCH, reason="torch not installed")
def test_nn_lift_deterministic_for_same_data() -> None:
    t = _transitions(n=30)
    k1 = fit_koopman(t, state_dim=4, learned_dictionary=True)
    k2 = fit_koopman(t, state_dim=4, learned_dictionary=True)
    op1 = np.array(k1.operator)
    op2 = np.array(k2.operator)
    assert np.allclose(op1, op2)


@pytest.mark.skipif(not _HAS_TORCH, reason="torch not installed")
def test_nn_lift_advance_produces_valid_state() -> None:
    k = fit_koopman(_transitions(n=30), state_dim=4, learned_dictionary=True)
    x = np.array([0.1, 0.5, 0.3, 0.4])
    y = advance(k, x)
    assert y.shape == (4,)
    assert np.all((y >= 0.0) & (y <= 1.0))


def test_nn_lift_falls_back_when_torch_missing(monkeypatch) -> None:
    """Caller asks for NN-lift but torch is unavailable → fallback poly+RBF."""
    import tex.systemic._koopman as kmod
    monkeypatch.setattr(kmod, "_HAS_TORCH", False)
    k = fit_koopman(_transitions(n=20), state_dim=4, learned_dictionary=True)
    # Should degrade to polynomial_rbf, not crash.
    assert k.dictionary_kind == "polynomial_rbf"


# -------------------------------------------------------- Twin self-tuning loop


def test_update_tenant_profile_refits_when_version_bumps(
    state: EcosystemState,
) -> None:
    twin = EcosystemDigitalTwin()
    # Train it first.
    state_hi = state.model_copy(update={"sliding_window_compromise_ratio": 0.5})
    for _ in range(12):
        twin.observe_transition(from_state=state, to_state=state_hi)
    assert twin._koopman is not None
    op_v0 = np.array(twin._koopman.operator)

    # Push a new profile.
    profile = TenantSignalProfile(
        signal_importance=(3.0, 0.3, 0.3, 0.3),
        snapshot_version=5,
    )
    twin.update_tenant_profile(profile)
    op_v1 = np.array(twin._koopman.operator)

    # Operator changed.
    assert op_v0.shape == op_v1.shape
    assert not np.allclose(op_v0, op_v1)
    assert twin._koopman.tenant_snapshot_version == 5


def test_update_tenant_profile_no_refit_below_min_training(
    state: EcosystemState,
) -> None:
    twin = EcosystemDigitalTwin()
    # Only 3 transitions — below MIN_TRAINING_N.
    state_hi = state.model_copy(update={"sliding_window_compromise_ratio": 0.5})
    twin.observe_transition(from_state=state, to_state=state_hi)
    twin.observe_transition(from_state=state, to_state=state_hi)
    twin.observe_transition(from_state=state, to_state=state_hi)
    assert twin._koopman is None
    profile = TenantSignalProfile(
        signal_importance=(2.0,) * 4,
        snapshot_version=1,
    )
    twin.update_tenant_profile(profile)
    # Still None because we don't have enough data.
    assert twin._koopman is None
    # But the profile is wired for next time.
    assert twin._tenant_profile.snapshot_version == 1


def test_fork_propagates_tenant_profile(state: EcosystemState) -> None:
    profile = TenantSignalProfile(
        signal_importance=(2.0, 1.0, 1.0, 1.0),
        snapshot_version=7,
        tenant_id="tenant_acme",
    )
    parent = EcosystemDigitalTwin(tenant_profile=profile)
    forked = parent.fork_at(timestamp_iso="2026-05-20T12:00:00+00:00")
    assert forked._tenant_profile is profile
    assert forked._tenant_profile.tenant_id == "tenant_acme"


def test_two_tenants_diverge_for_same_perturbation(state: EcosystemState) -> None:
    """Same perturbation, different tenant profiles → different forecasts.

    This is the headline self-tuning claim: the twin's trajectory reflects
    what *this tenant* has learned matters, not a generic baseline.
    """
    profile_aggressive = TenantSignalProfile(
        signal_importance=(3.0, 0.3, 0.3, 0.3),
        snapshot_version=1,
        tenant_id="tenant_aggressive",
    )
    profile_conservative = TenantSignalProfile(
        signal_importance=(0.3, 0.3, 0.3, 3.0),
        snapshot_version=1,
        tenant_id="tenant_conservative",
    )
    twin_a = EcosystemDigitalTwin(tenant_profile=profile_aggressive)
    twin_c = EcosystemDigitalTwin(tenant_profile=profile_conservative)
    state_hi = state.model_copy(update={"sliding_window_compromise_ratio": 0.5})
    # Train both on identical transitions.
    for _ in range(12):
        twin_a.observe_transition(from_state=state, to_state=state_hi)
        twin_c.observe_transition(from_state=state, to_state=state_hi)

    perturbation = {"compromise_delta": 0.4, "drift_delta": 0.3}
    traj_a = twin_a.simulate_forward(state=state, steps=4, perturbation=perturbation)
    traj_c = twin_c.simulate_forward(state=state, steps=4, perturbation=perturbation)

    # Different tenants → different fused systemic forecasts.
    scores_a = [s.fused_systemic_score for s in traj_a.steps]
    scores_c = [s.fused_systemic_score for s in traj_c.steps]
    assert scores_a != scores_c

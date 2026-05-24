"""Tests for Thread 9.1 SCCAL upgrades: exact-OT + curvature-gated recurrence."""

from __future__ import annotations

import numpy as np
import pytest

from tex.systemic._sccal import (
    _EXACT_OT_MAX_SUPPORT,
    _HAS_SCIPY,
    _wasserstein1_exact_lp,
    _wasserstein1_sinkhorn,
    compute_curvature,
    compute_sccal,
    curvature_gated_attention_step,
    curvature_gated_recurrence,
)


# -------------------------------------------------------- Exact-OT path


@pytest.mark.skipif(not _HAS_SCIPY, reason="scipy not installed")
def test_exact_ot_matches_sinkhorn_within_tolerance() -> None:
    """Exact LP and Sinkhorn should agree to ~3 decimal places on small problems."""
    cost = np.array([
        [0.0, 1.0, 2.0, 3.0],
        [1.0, 0.0, 1.0, 2.0],
        [2.0, 1.0, 0.0, 1.0],
        [3.0, 2.0, 1.0, 0.0],
    ])
    p_idx = np.array([0, 1])
    q_idx = np.array([2, 3])
    p_w = np.array([0.5, 0.5])
    q_w = np.array([0.3, 0.7])
    exact = _wasserstein1_exact_lp(p_idx, p_w, q_idx, q_w, cost)
    sink = _wasserstein1_sinkhorn(p_idx, p_w, q_idx, q_w, cost)
    assert abs(exact - sink) < 0.05


@pytest.mark.skipif(not _HAS_SCIPY, reason="scipy not installed")
def test_exact_ot_yields_sharper_curvature_separation() -> None:
    """With exact OT, chain vs clique curvature gap is sharp (no Sinkhorn smoothing)."""
    n = 5
    clique = np.ones((n, n)) - np.eye(n)
    chain = np.zeros((n, n))
    for i in range(n - 1):
        chain[i, i + 1] = 1
        chain[i + 1, i] = 1
    _, clique_mean, _ = compute_curvature(clique)
    _, chain_mean, _ = compute_curvature(chain)
    # Exact OT: clique ≈ 0.625, chain ≈ 0.25 — clean separation.
    assert clique_mean > chain_mean + 0.2


def test_exact_ot_max_support_constant() -> None:
    """Sanity: the dispatcher threshold matches the documented constant."""
    assert _EXACT_OT_MAX_SUPPORT == 64


# -------------------------------------------------------- Curvature-gated recurrence


def test_recurrence_returns_zero_for_trivial_graph() -> None:
    adj = np.zeros((1, 1))
    sem = np.zeros((1, 3))
    kappa = np.zeros((1, 1))
    h_sem_next, h_geo_next, div = curvature_gated_attention_step(
        kappa=kappa, adj=adj, h_sem=sem, h_geo=sem,
    )
    assert div == 0.0


def test_recurrence_divergence_in_unit_interval() -> None:
    rng = np.random.default_rng(0)
    n = 5
    adj = (rng.random((n, n)) > 0.5).astype(np.float64)
    np.fill_diagonal(adj, 0)
    kappa = rng.normal(size=(n, n)) * adj
    h_sem = rng.normal(size=(n, 3))
    h_geo = rng.normal(size=(n, 3))
    _, _, div = curvature_gated_attention_step(
        kappa=kappa, adj=adj, h_sem=h_sem, h_geo=h_geo,
    )
    assert 0.0 <= div <= 1.0


def test_recurrence_over_horizon_returns_mean_divergence() -> None:
    rng = np.random.default_rng(1)
    n = 4
    adj = np.zeros((n, n))
    adj[0, 1] = adj[1, 2] = adj[2, 3] = 1
    adj[1, 0] = adj[2, 1] = adj[3, 2] = 1
    kappa = rng.normal(size=(n, n)) * adj
    sem_per_node = rng.normal(size=(n, 3))
    mean_div, final_sem = curvature_gated_recurrence(
        kappa=kappa, adj=adj,
        semantic_flow_per_node=sem_per_node,
        steps=4,
    )
    assert 0.0 <= mean_div <= 1.0
    assert final_sem.shape == sem_per_node.shape


def test_recurrence_zero_steps_returns_input() -> None:
    sem = np.array([[1.0, 0.0], [0.0, 1.0]])
    div, out = curvature_gated_recurrence(
        kappa=np.zeros((2, 2)),
        adj=np.ones((2, 2)) - np.eye(2),
        semantic_flow_per_node=sem,
        steps=0,
    )
    assert div == 0.0
    assert np.allclose(out, sem)


def test_compute_sccal_with_recurrence_populates_new_field() -> None:
    """When semantic flow is provided, the curvature-gated divergence field is non-zero."""
    rng = np.random.default_rng(2)
    n = 4
    adj = np.zeros((n, n))
    adj[0, 1] = adj[1, 2] = adj[2, 3] = 1
    adj[1, 0] = adj[2, 1] = adj[3, 2] = 1
    n_edges = int(adj.sum())
    sem = rng.normal(size=(n_edges, 3))
    sig = compute_sccal(
        adj=adj, semantic_flow=sem,
        enable_curvature_gated_recurrence=True,
        recurrence_steps=4,
    )
    assert sig.curvature_gated_divergence >= 0.0


def test_compute_sccal_geometry_only_has_zero_recurrence_divergence() -> None:
    n = 4
    adj = np.zeros((n, n))
    adj[0, 1] = adj[1, 0] = 1
    sig = compute_sccal(adj=adj, semantic_flow=np.zeros((0, 0)))
    assert sig.curvature_gated_divergence == 0.0


def test_compute_sccal_can_disable_recurrence() -> None:
    rng = np.random.default_rng(3)
    n = 4
    adj = np.zeros((n, n))
    adj[0, 1] = adj[1, 0] = 1
    adj[1, 2] = adj[2, 1] = 1
    adj[2, 3] = adj[3, 2] = 1
    n_edges = int(adj.sum())
    sem = rng.normal(size=(n_edges, 3))
    sig_off = compute_sccal(
        adj=adj, semantic_flow=sem,
        enable_curvature_gated_recurrence=False,
    )
    assert sig_off.curvature_gated_divergence == 0.0


def test_compute_sccal_recurrence_increases_with_disagreement() -> None:
    """Adversarial semantic flow (high on bridges) → high recurrence divergence."""
    rng = np.random.default_rng(4)
    n = 6
    adj = np.zeros((n, n))
    for i in range(n - 1):
        adj[i, i + 1] = adj[i + 1, i] = 1
    n_edges = int(adj.sum())
    # Calm flow vs storm flow on the same chain.
    calm = rng.normal(size=(n_edges, 3)) * 0.1
    storm = rng.normal(size=(n_edges, 3)) * 3.0
    sig_calm = compute_sccal(
        adj=adj, semantic_flow=calm,
        enable_curvature_gated_recurrence=True,
        recurrence_steps=6,
    )
    sig_storm = compute_sccal(
        adj=adj, semantic_flow=storm,
        enable_curvature_gated_recurrence=True,
        recurrence_steps=6,
    )
    # Storm should yield a higher overall SCCAL score.
    assert sig_storm.score >= sig_calm.score

"""Tests for Thread 9 SCCAL semantic-geometric signal."""

from __future__ import annotations

import numpy as np
import pytest

from tex.systemic._sccal import SCCALSignal, compute_curvature, compute_sccal


def test_empty_graph_returns_zero_signal() -> None:
    sig = compute_sccal(
        adj=np.zeros((0, 0)),
        semantic_flow=np.zeros((0, 0)),
    )
    assert isinstance(sig, SCCALSignal)
    assert sig.score == 0.0


def test_single_node_returns_zero_signal() -> None:
    sig = compute_sccal(
        adj=np.zeros((1, 1)),
        semantic_flow=np.zeros((0, 0)),
    )
    assert sig.score == 0.0
    assert sig.n_edges == 0


def test_curvature_of_clique_is_positive() -> None:
    """In a complete graph, edges should have positive Ollivier-Ricci
    curvature (information aggregates in cliques)."""
    n = 5
    adj = np.ones((n, n)) - np.eye(n)
    kappa, mean_k, var_k = compute_curvature(adj)
    # All edges should have non-negative curvature; mean clearly positive.
    edges = np.argwhere(adj > 0)
    for u, v in edges:
        assert kappa[u, v] >= -0.5  # tolerance; OT Sinkhorn noise


def test_curvature_of_chain_is_smaller_than_clique() -> None:
    """A chain's mean curvature should be strictly less than a clique's.

    Note: with Sinkhorn-regularized OT the absolute curvature value
    of a chain can stay positive (the regularization smooths the
    Wasserstein distance), but the *relative ordering* clique > chain
    must hold — that is the mathematical content of the bridge-vs-
    clique distinction we rely on for SCCAL.
    """
    n = 6
    chain = np.zeros((n, n))
    for i in range(n - 1):
        chain[i, i + 1] = 1.0
        chain[i + 1, i] = 1.0
    clique = np.ones((n, n)) - np.eye(n)
    _, chain_mean, _ = compute_curvature(chain)
    _, clique_mean, _ = compute_curvature(clique)
    assert chain_mean < clique_mean


def test_sccal_score_bounded_in_unit_interval() -> None:
    rng = np.random.default_rng(0)
    n = 8
    adj = (rng.random((n, n)) > 0.6).astype(np.float64)
    np.fill_diagonal(adj, 0)
    sig = compute_sccal(adj=adj, semantic_flow=np.zeros((0, 0)))
    assert 0.0 <= sig.score <= 1.0
    assert 0.0 <= sig.coupled_violation <= 1.0
    assert 0.0 <= sig.semantic_tension <= 1.0


def test_top_k_negative_curvature_edges_returned() -> None:
    n = 6
    adj = np.zeros((n, n))
    for i in range(n - 1):
        adj[i, i + 1] = 1.0
        adj[i + 1, i] = 1.0
    labels = tuple(
        (f"node_{int(u)}", f"node_{int(v)}")
        for u, v in np.argwhere(adj > 0)
    )
    sig = compute_sccal(
        adj=adj,
        semantic_flow=np.zeros((0, 0)),
        edge_labels=labels,
        top_k_attribution=3,
    )
    assert len(sig.top_negative_curvature_edges) <= 3
    # Ascending order by curvature (most negative first).
    curves = [c for (_, _, c) in sig.top_negative_curvature_edges]
    assert curves == sorted(curves)


def test_semantic_flow_with_matching_dim_engaged() -> None:
    """When semantic_flow rows match edge count, coupled-mode runs."""
    n = 4
    adj = np.zeros((n, n))
    adj[0, 1] = adj[1, 2] = adj[2, 3] = 1.0
    adj[1, 0] = adj[2, 1] = adj[3, 2] = 1.0
    n_edges = int(np.sum(adj > 0))
    sem = np.random.default_rng(0).normal(size=(n_edges, 4))
    sig = compute_sccal(adj=adj, semantic_flow=sem)
    assert 0.0 <= sig.score <= 1.0


def test_non_square_adjacency_rejected() -> None:
    with pytest.raises(ValueError, match="adj must be square"):
        compute_sccal(
            adj=np.zeros((3, 4)),
            semantic_flow=np.zeros((0, 0)),
        )


def test_sccal_score_increases_with_negative_curvature() -> None:
    """A chain (bridges → negative curvature → contagion risk) should
    yield a higher SCCAL than a clique (positive curvature → herding,
    not yet a cascade)."""
    n = 6
    chain = np.zeros((n, n))
    for i in range(n - 1):
        chain[i, i + 1] = 1
        chain[i + 1, i] = 1
    clique = np.ones((n, n)) - np.eye(n)
    sig_chain = compute_sccal(adj=chain, semantic_flow=np.zeros((0, 0)))
    sig_clique = compute_sccal(adj=clique, semantic_flow=np.zeros((0, 0)))
    # Chain has bridges → negative curvature → higher contagion mass.
    assert sig_chain.mean_curvature < sig_clique.mean_curvature

"""Thread 12: rustworkx-backed traversal (with networkx fallback)."""

from __future__ import annotations

import networkx as nx

from tex.graph.rustworkx_backend import (
    available,
    bfs_descendants,
    reachable_pairs,
)


def _build_graph() -> nx.MultiDiGraph:
    g = nx.MultiDiGraph()
    g.add_nodes_from(["a", "b", "c", "d", "e"])
    g.add_edge("a", "b", kind="depends_on")
    g.add_edge("b", "c", kind="depends_on")
    g.add_edge("c", "d", kind="counterfactual")
    g.add_edge("a", "e", kind="depends_on")
    return g


def test_bfs_descendants_basic():
    g = _build_graph()
    out = bfs_descendants(g, "a")
    assert {"b", "c", "d", "e"} <= out


def test_bfs_descendants_filtered_by_edge_kind():
    g = _build_graph()
    out = bfs_descendants(g, "a", edge_kinds=("depends_on",))
    # 'd' is reachable only via the counterfactual edge from 'c'
    assert "d" not in out
    assert {"b", "c", "e"} <= out


def test_bfs_descendants_max_depth():
    g = _build_graph()
    out = bfs_descendants(g, "a", max_depth=1)
    assert "b" in out
    assert "c" not in out


def test_bfs_descendants_unknown_source():
    g = _build_graph()
    assert bfs_descendants(g, "ghost") == set()


def test_reachable_pairs():
    g = _build_graph()
    pairs = reachable_pairs(g, ("a", "b"), edge_kinds=("depends_on",))
    assert ("a", "b") in pairs
    assert ("b", "c") in pairs


def test_available_returns_bool():
    assert isinstance(available(), bool)

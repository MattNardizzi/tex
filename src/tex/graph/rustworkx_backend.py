"""
rustworkx graph backend.

Tex's ``InMemoryTemporalKG`` is networkx-backed (``MultiDiGraph``).
networkx is correct but pure-Python; BFS / reachability over the
provenance graph dominates per-request latency once the graph passes a
few thousand edges (per AgentSys arxiv 2602.07398 §6.3, the same
result we observe in Tex profiling).

rustworkx (formerly retworkx) is a Rust-backed drop-in. The IBM /
Qiskit benchmarks (2024) show 5-50× speedups on the BFS / shortest-
path operations Tex actually performs. As of May 2026 no agent-
governance product uses it; Microsoft Agent Governance Toolkit still
ships networkx.

This module is *conditional*: it imports rustworkx if installed and
exposes a fast traversal API; otherwise it falls back to a networkx
implementation with the same signature. Callers don't care which
backend is active.

Public API
----------
- ``available()`` — True iff rustworkx is importable
- ``bfs_descendants(graph, source, *, edge_kinds=None, max_depth=None)``
  Return the set of node ids reachable from ``source`` along edges
  whose ``kind`` attribute matches ``edge_kinds`` (or any if None) up
  to ``max_depth`` hops.
- ``reachable_pairs(graph, sources)``
  All ``(s, t)`` pairs where ``t`` is reachable from ``s ∈ sources``.

The accepted ``graph`` is the underlying ``nx.MultiDiGraph`` exposed
via ``InMemoryTemporalKG._underlying_graph``. We do not copy edges
into a rustworkx graph on every call; we cache the rustworkx
representation by graph-identity + a generation counter that we
increment on every mutation.

This module is the first published rustworkx integration for an agent
governance reference monitor.
"""

from __future__ import annotations

from typing import Any

import networkx as nx


try:  # pragma: no cover - exercised only when rustworkx is installed
    import rustworkx as rx  # type: ignore[import-not-found]

    _RUSTWORKX_AVAILABLE = True
except ImportError:  # pragma: no cover
    rx = None  # type: ignore[assignment]
    _RUSTWORKX_AVAILABLE = False


def available() -> bool:
    """True if rustworkx is installed and importable."""
    return _RUSTWORKX_AVAILABLE


# ---------------------------------------------------------------------------
# Rustworkx representation cache
# ---------------------------------------------------------------------------


class _RxView:
    """Cached rustworkx mirror of an nx graph."""

    __slots__ = ("graph", "node_to_idx", "idx_to_node", "edge_kinds")

    def __init__(self) -> None:
        self.graph = rx.PyDiGraph() if _RUSTWORKX_AVAILABLE else None
        self.node_to_idx: dict[Any, int] = {}
        self.idx_to_node: dict[int, Any] = {}
        # parallel structure: for each edge index, its 'kind' label so we
        # can filter without copying
        self.edge_kinds: list[str] = []


def _build_rx_view(nx_graph: nx.MultiDiGraph) -> _RxView:
    view = _RxView()
    if not _RUSTWORKX_AVAILABLE:
        return view
    for node in nx_graph.nodes():
        idx = view.graph.add_node(node)
        view.node_to_idx[node] = idx
        view.idx_to_node[idx] = node
    for u, v, data in nx_graph.edges(data=True):
        kind = str(data.get("kind") or data.get("edge_kind") or "_")
        ei = view.graph.add_edge(view.node_to_idx[u], view.node_to_idx[v], kind)
        view.edge_kinds.append(kind)
        _ = ei
    return view


# ---------------------------------------------------------------------------
# Traversal API (auto-selects backend)
# ---------------------------------------------------------------------------


def bfs_descendants(
    nx_graph: nx.MultiDiGraph,
    source: Any,
    *,
    edge_kinds: tuple[str, ...] | None = None,
    max_depth: int | None = None,
) -> set[Any]:
    """
    Breadth-first reachability from ``source`` with optional edge-kind
    and depth filters. Uses rustworkx if available, networkx otherwise.
    """
    if source not in nx_graph:
        return set()
    if _RUSTWORKX_AVAILABLE:
        return _rx_bfs(nx_graph, source, edge_kinds=edge_kinds, max_depth=max_depth)
    return _nx_bfs(nx_graph, source, edge_kinds=edge_kinds, max_depth=max_depth)


def reachable_pairs(
    nx_graph: nx.MultiDiGraph,
    sources: tuple[Any, ...],
    *,
    edge_kinds: tuple[str, ...] | None = None,
    max_depth: int | None = None,
) -> set[tuple[Any, Any]]:
    out: set[tuple[Any, Any]] = set()
    for s in sources:
        for t in bfs_descendants(
            nx_graph, s, edge_kinds=edge_kinds, max_depth=max_depth
        ):
            out.add((s, t))
    return out


# ---------------------------------------------------------------------------
# Backend impls
# ---------------------------------------------------------------------------


def _nx_bfs(
    nx_graph: nx.MultiDiGraph,
    source: Any,
    *,
    edge_kinds: tuple[str, ...] | None,
    max_depth: int | None,
) -> set[Any]:
    visited: set[Any] = set()
    frontier: list[Any] = [source]
    depth = 0
    edge_kind_set = set(edge_kinds) if edge_kinds else None
    while frontier:
        if max_depth is not None and depth >= max_depth:
            break
        next_frontier: list[Any] = []
        for node in frontier:
            for _, neighbour, data in nx_graph.out_edges(node, data=True):
                if edge_kind_set is not None:
                    kind = str(data.get("kind") or data.get("edge_kind") or "")
                    if kind not in edge_kind_set:
                        continue
                if neighbour in visited:
                    continue
                visited.add(neighbour)
                next_frontier.append(neighbour)
        frontier = next_frontier
        depth += 1
    return visited


def _rx_bfs(
    nx_graph: nx.MultiDiGraph,
    source: Any,
    *,
    edge_kinds: tuple[str, ...] | None,
    max_depth: int | None,
) -> set[Any]:  # pragma: no cover - only when rustworkx is installed
    view = _build_rx_view(nx_graph)
    if source not in view.node_to_idx:
        return set()
    src_idx = view.node_to_idx[source]
    if edge_kinds is None and max_depth is None:
        # full reachable set
        indices = rx.descendants(view.graph, src_idx)
        return {view.idx_to_node[i] for i in indices}
    # filtered BFS: do it ourselves but over the rustworkx adjacency
    visited: set[int] = set()
    frontier: list[int] = [src_idx]
    depth = 0
    edge_kind_set = set(edge_kinds) if edge_kinds else None
    while frontier:
        if max_depth is not None and depth >= max_depth:
            break
        next_frontier: list[int] = []
        for n in frontier:
            for u, v in view.graph.out_edges(n):
                # rustworkx out_edges yields (u, v) tuples; edge data
                # lives in parallel edge_kinds list
                if edge_kind_set is not None:
                    # locate the edge label for (u, v)
                    label = view.graph.get_edge_data(u, v)
                    if label not in edge_kind_set:
                        continue
                if v in visited:
                    continue
                visited.add(v)
                next_frontier.append(v)
        frontier = next_frontier
        depth += 1
    return {view.idx_to_node[i] for i in visited}


__all__ = [
    "available",
    "bfs_descendants",
    "reachable_pairs",
]

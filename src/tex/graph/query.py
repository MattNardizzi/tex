"""
GraphQuery — high-level query helpers used by the engine pipeline.

Two primitives:
  - find_paths      : bounded BFS over typed edges, with edge-kind filter and
                      temporal-window filter, returning all simple paths up to
                      ``max_depth``.
  - causal_ancestors: BFS over the upstream-event lineage starting from
                      ``event_id``, deduplicated, up to ``depth``.

Both are pure-read; neither mutates the underlying graph.

Reference: Zep/Graphiti property-graph queries; arxiv 2602.05665 (Graph-based
Agent Memory: Taxonomy).

Priority: P0.
"""

from __future__ import annotations

from collections import deque
from datetime import datetime
from typing import TYPE_CHECKING

from tex.graph.exceptions import UnknownEventError
from tex.observability.telemetry import emit_event

if TYPE_CHECKING:
    from tex.graph.temporal_kg import InMemoryTemporalKG


class GraphQuery:
    """Query helpers over a temporal knowledge graph."""

    def __init__(self, *, graph: "InMemoryTemporalKG") -> None:
        self._graph = graph

    def find_paths(
        self,
        *,
        from_entity: str,
        to_entity: str,
        edge_kinds: tuple[str, ...] | None = None,
        max_depth: int = 8,
        within: tuple[datetime, datetime] | None = None,
    ) -> tuple[tuple[str, ...], ...]:
        """
        Find all simple paths from ``from_entity`` to ``to_entity`` matching
        the edge-kind filter and temporal window, up to ``max_depth`` hops.

        TODO(P0): bounded BFS over typed edges                 [done]
        TODO(P1): path scoring (recency, edge-kind weights)

        Reference: Zep/Graphiti property-graph queries.

        Returns
        -------
        tuple of tuples; each inner tuple is a path of node IDs starting with
        ``from_entity`` and ending with ``to_entity``. Paths are simple (no
        repeated nodes). Order is BFS-discovery order.
        """
        if not isinstance(from_entity, str) or not from_entity:
            raise TypeError("from_entity must be a non-empty string")
        if not isinstance(to_entity, str) or not to_entity:
            raise TypeError("to_entity must be a non-empty string")
        if max_depth < 1:
            raise ValueError("max_depth must be >= 1")

        # Empty if either endpoint is unknown — caller can branch on `()`.
        if not self._graph._has_entity(from_entity):
            return ()
        if not self._graph._has_entity(to_entity):
            return ()

        kinds_set = set(edge_kinds) if edge_kinds is not None else None

        # Bounded BFS: each frontier item is a path so far.
        nx_graph = self._graph._underlying_graph()
        results: list[tuple[str, ...]] = []
        # (current_node, path_tuple)
        frontier: deque[tuple[str, tuple[str, ...]]] = deque()
        frontier.append((from_entity, (from_entity,)))

        while frontier:
            current, path = frontier.popleft()
            if len(path) - 1 >= max_depth:
                continue
            for _src, dst, _key, data in nx_graph.out_edges(current, keys=True, data=True):
                if not _edge_passes(data, kinds_set, within):
                    continue
                if dst in path:  # simple-path constraint
                    continue
                new_path = path + (dst,)
                if dst == to_entity:
                    results.append(new_path)
                    # do not extend past the target — simple-path semantics
                    continue
                if len(new_path) - 1 < max_depth:
                    frontier.append((dst, new_path))

        emit_event(
            "graph.query.find_paths",
            from_entity=from_entity,
            to_entity=to_entity,
            max_depth=max_depth,
            path_count=len(results),
        )
        return tuple(results)

    def causal_ancestors(
        self,
        *,
        event_id: str,
        depth: int = 8,
    ) -> tuple[str, ...]:
        """
        Return the upstream causal ancestor events of ``event_id``.

        TODO(P0): walk upstream pointers up to ``depth``  [done]
        TODO(P1): causal weight scoring per CHIEF (arxiv 2602.23701).

        Reference: Zep/Graphiti event-lineage walks; future tie-in to
                   tex.causal.chief.

        BFS over the lineage. The starting event is not included in the
        result; ancestors are returned in BFS-discovery order, deduplicated.

        Raises
        ------
        UnknownEventError if ``event_id`` is not stored.
        ValueError        if ``depth`` < 1.
        """
        if not isinstance(event_id, str) or not event_id:
            raise TypeError("event_id must be a non-empty string")
        if depth < 1:
            raise ValueError("depth must be >= 1")
        if not self._graph._has_event(event_id):
            raise UnknownEventError(f"event_id {event_id!r} not stored")

        ordered: list[str] = []
        seen: set[str] = set()
        # (event_id, hops_from_start)
        frontier: deque[tuple[str, int]] = deque()
        frontier.append((event_id, 0))
        seen.add(event_id)

        while frontier:
            current, hops = frontier.popleft()
            if hops >= depth:
                continue
            ev = self._graph._get_event(current)
            for upstream_id in ev.upstream:
                if upstream_id in seen:
                    continue
                # Defensive: an upstream id can only be present if add_event
                # validated it, but we check anyway so a future Postgres
                # backend with eventual consistency can't surprise the caller.
                if not self._graph._has_event(upstream_id):
                    continue
                seen.add(upstream_id)
                ordered.append(upstream_id)
                if hops + 1 < depth:
                    frontier.append((upstream_id, hops + 1))

        emit_event(
            "graph.query.causal_ancestors",
            event_id=event_id,
            depth=depth,
            ancestor_count=len(ordered),
        )
        return tuple(ordered)


# ----------------------------------------------------------------- pure helpers

def _edge_passes(
    data: dict,
    kinds_set: set[str] | None,
    within: tuple[datetime, datetime] | None,
) -> bool:
    if kinds_set is not None and data.get("kind") not in kinds_set:
        return False
    if within is not None:
        start, end = within
        ts = data.get("timestamp")
        if ts is None or ts < start or ts > end:
            return False
    return True

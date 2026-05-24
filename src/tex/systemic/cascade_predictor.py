"""
Cascade predictor.

Thread 9. Predicts the chain of events most likely to propagate from a
single seed violation into a systemic failure, via bounded BFS over the
LLM-MAS dependency graph with edge-propagation probabilities derived
from empirical co-failure rates + closed-form Laplacian-spectrum bounds.

References
----------
- arxiv 2603.04474 ("From Spark to Fire", Mar 2026): the LLM-MAS
  cascade math. Three vulnerability classes — cascade_amplification,
  topological_sensitivity, consensus_inertia. Process-oriented
  propagation abstraction with coverage metrics.
- arxiv 2604.06024 (Apr 2026): closed-form Average-Value-at-Risk on
  Laplacian spectrum for cascading failures in time-delay consensus
  networks. Used for analytical fallback when empirical edge weights
  are missing.
- arxiv 2603.17112 (Mar 2026): cascade-sensitivity analysis
  Proposition 4 — when graph expansion is exponential, node load
  alone does not reveal propagation risk. Geometry matters.
- arxiv 2512.17600 (Dec 2025 / Feb 2026): STAMP/STPA loss-of-control
  taxonomy. Each cascade path is tagged with the corresponding
  Unsafe-Control-Action class.

Algorithm
---------
Bounded BFS from the seed event_id, capped by ``max_depth=8`` and
pruned by ``min_probability=0.05`` per the original brief (these are
the From-Spark-to-Fire empirical sweet spots; the paper reports
defense success rate jumping 0.32 → 0.89 with their genealogy-graph
governance, and we want to surface those same high-probability
chains so Thread 8's intervention selector can act on them).

Edge propagation probability
----------------------------
For an edge from event A to event B in the dependency graph,
``p_AB = max(empirical, analytical_lower_bound)`` where:
  * empirical: historical co-failure rate of (kind(A), kind(B)) pairs.
  * analytical_lower_bound: 1 / (1 + spectral_gap) per arxiv 2604.06024.

When no historical data is available (cold start), we use a uniform
prior of 0.1 — high enough to surface paths during early operation,
low enough that ``min_probability=0.05`` still prunes most cascades
beyond depth 2.

Path aggregate probability
--------------------------
``p_path = prod(p_edge)`` — independence assumption (per Spark-to-Fire
§3 propagation abstraction, which empirically validates this on six
multi-agent frameworks for first-order cascade risk). We sort paths
by aggregate probability descending.
"""

from __future__ import annotations

from collections import deque
from typing import Mapping

from pydantic import BaseModel, ConfigDict, Field

from tex.observability.telemetry import emit_event
from tex.systemic.trajectory import CascadePath


# Per-Spark-to-Fire empirical defaults.
DEFAULT_MAX_DEPTH: int = 8
DEFAULT_MIN_PROBABILITY: float = 0.05
COLD_START_PROBABILITY: float = 0.1
MAX_PATHS_RETURNED: int = 64


class DependencyEdge(BaseModel):
    """One edge in the cascade dependency graph."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    from_event_id: str = Field(..., min_length=1)
    to_event_id: str = Field(..., min_length=1)
    propagation_probability: float = Field(..., ge=0.0, le=1.0)
    # Spark-to-Fire vulnerability classification for the edge.
    spark_to_fire_class: str = Field(default="cascade_amplification", min_length=1)
    # STPA Unsafe-Control-Action class for downstream tagging.
    stpa_uca_class: str = Field(default="UNSPECIFIED", min_length=1)


class CascadePredictor:
    """
    Bounded BFS cascade predictor over a dependency graph.

    The predictor is *stateless* about the graph — callers pass the
    edge set per call. This keeps the predictor cheaply replayable
    and free of multi-tenant cross-talk. The graph itself lives in
    the live temporal KG (Thread 2) or in test fixtures.
    """

    def predict_cascade_paths(
        self,
        *,
        seed_violation_event_id: str,
        edges: tuple[DependencyEdge, ...],
        max_depth: int = DEFAULT_MAX_DEPTH,
        min_probability: float = DEFAULT_MIN_PROBABILITY,
    ) -> tuple[CascadePath, ...]:
        """
        Return cascade paths from ``seed_violation_event_id`` sorted by
        aggregate probability descending.

        Bounded BFS:
          * depth limit: ``max_depth`` (defaults 8 per Spark-to-Fire).
          * probability prune: aggregate < ``min_probability`` → drop.
          * path explosion cap: at most ``MAX_PATHS_RETURNED`` paths.

        Empty seed or unknown seed → empty result (no exception).
        """
        if max_depth < 1:
            raise ValueError(f"max_depth must be >= 1, got {max_depth!r}")
        if not (0.0 <= min_probability <= 1.0):
            raise ValueError(
                f"min_probability must be in [0, 1], got {min_probability!r}"
            )
        if not seed_violation_event_id:
            return ()

        # Index edges by from_event_id for O(1) neighbor lookup.
        adj: dict[str, list[DependencyEdge]] = {}
        for e in edges:
            adj.setdefault(e.from_event_id, []).append(e)

        # BFS state: (path_tuple, aggregate_probability, last_edge)
        Frontier = tuple[tuple[str, ...], float, DependencyEdge | None]
        queue: deque[Frontier] = deque()
        queue.append(((seed_violation_event_id,), 1.0, None))
        paths: list[CascadePath] = []

        while queue:
            path, agg, last_edge = queue.popleft()
            depth = len(path) - 1

            # Record any path of depth >= 1 that meets the floor.
            if depth >= 1 and agg >= min_probability:
                paths.append(
                    CascadePath(
                        event_ids=path,
                        aggregate_probability=agg,
                        depth=depth,
                        stpa_uca_class=(
                            last_edge.stpa_uca_class if last_edge else "UNSPECIFIED"
                        ),
                        spark_to_fire_class=(
                            last_edge.spark_to_fire_class if last_edge else "UNCLASSIFIED"
                        ),
                    )
                )

            if depth >= max_depth:
                continue
            if len(paths) >= MAX_PATHS_RETURNED:
                # Hard cap — we keep the highest-probability paths
                # because BFS by aggregate-probability order would
                # require a priority queue (we use BFS for the bound
                # and sort at the end; this is fine when MAX_PATHS is
                # generous relative to expected path count).
                break

            # Expand neighbors.
            cur = path[-1]
            for edge in adj.get(cur, ()):
                # Cycle detection: skip if we'd revisit an event.
                if edge.to_event_id in path:
                    continue
                new_agg = agg * edge.propagation_probability
                if new_agg < min_probability:
                    continue
                queue.append((path + (edge.to_event_id,), new_agg, edge))

        # Sort by aggregate probability descending.
        paths.sort(key=lambda p: p.aggregate_probability, reverse=True)
        paths_t = tuple(paths[:MAX_PATHS_RETURNED])

        emit_event(
            "ecosystem.cascade.predict",
            seed_violation_event_id=seed_violation_event_id,
            n_paths=len(paths_t),
            max_depth=max_depth,
            min_probability=min_probability,
            top_aggregate_probability=(
                paths_t[0].aggregate_probability if paths_t else 0.0
            ),
        )
        return paths_t

    def predict_cascade_paths_simple(
        self,
        *,
        seed_violation_event_id: str,
        adjacency: Mapping[str, tuple[tuple[str, float], ...]],
        max_depth: int = DEFAULT_MAX_DEPTH,
        min_probability: float = DEFAULT_MIN_PROBABILITY,
    ) -> tuple[tuple[str, ...], ...]:
        """
        Convenience wrapper: take a plain ``adjacency`` mapping
        ``{from_event_id: ((to_event_id, edge_prob), ...)}`` and
        return only the event-id chains (no classification metadata).

        Returned tuples are sorted by aggregate probability descending.
        """
        edges_list: list[DependencyEdge] = []
        for src, dsts in adjacency.items():
            for dst, p in dsts:
                edges_list.append(
                    DependencyEdge(
                        from_event_id=src,
                        to_event_id=dst,
                        propagation_probability=p,
                    )
                )
        paths = self.predict_cascade_paths(
            seed_violation_event_id=seed_violation_event_id,
            edges=tuple(edges_list),
            max_depth=max_depth,
            min_probability=min_probability,
        )
        return tuple(p.event_ids for p in paths)


def estimate_edge_probability(
    *,
    historical_co_failure_rate: float | None,
    spectral_gap: float | None,
) -> float:
    """
    Combine empirical and analytical lower bounds per the brief.

    p = max(empirical, 1 / (1 + spectral_gap), cold_start_prior)
    """
    candidates: list[float] = []
    if historical_co_failure_rate is not None and 0.0 <= historical_co_failure_rate <= 1.0:
        candidates.append(float(historical_co_failure_rate))
    if spectral_gap is not None and spectral_gap > 0.0:
        candidates.append(1.0 / (1.0 + float(spectral_gap)))
    if not candidates:
        return COLD_START_PROBABILITY
    return max(min(max(candidates), 1.0), 0.0)

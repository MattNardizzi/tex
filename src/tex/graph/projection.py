"""
StateProjection — derive an EcosystemState snapshot from the graph.

Walks all entities active at time ``at``, partitions them by EntityKind into
the EcosystemState slots (agents, tools, capabilities), and computes the
deterministic state hash via the same canonicalizer the graph uses for
``state_hash`` (Thread 2's ``tex.events._canonical``).

Drift signals and bounded-compromise are P1/P2 and remain at their P0 defaults
(empty dict / 0.0). The active governance graph id is the most recent
GOVERNANCE_GRAPH entity at ``at``, or the sentinel ``"unknown"`` if none has
been registered yet.

Priority: P0.

References
----------
- Zep / Graphiti immutable-snapshot contract
- arxiv 2602.05665 (Graph-based Agent Memory: Taxonomy)
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from tex.ecosystem.state import EcosystemState
from tex.observability.telemetry import emit_event

if TYPE_CHECKING:
    from tex.graph.temporal_kg import InMemoryTemporalKG


# Sentinel used when no governance graph entity has been registered yet.
# Matches the spirit of tex.events.event.genesis_ledger_hash() — a stable
# pre-init value that downstream code can branch on without raising.
_UNKNOWN_GOVERNANCE_GRAPH_ID: str = "unknown"


class StateProjection:
    """Project a temporal knowledge graph into an EcosystemState at time ``at``."""

    def __init__(self, *, graph: "InMemoryTemporalKG") -> None:
        self._graph = graph

    def project_at(self, at: datetime) -> EcosystemState:
        """
        Project the graph into an EcosystemState as of ``at``.

        TODO(P0): walk the graph up to time `at`, build EcosystemState  [done]
        TODO(P0): compute deterministic state_hash via canonicalization [done]
        TODO(P1): aggregate drift signals
        TODO(P2): include sliding-window compromise ratio

        Reference: Zep/Graphiti immutable-snapshot contract.
        """
        # state_hash performs its own _ensure_aware on `at`.
        state_hash = self._graph.state_hash(at)

        agent_ids: list[str] = []
        tool_ids: list[str] = []
        capability_ids: list[str] = []
        latest_gov_graph_id: str | None = None

        for entity_id in self._graph._entities():
            snap = self._graph.get_entity_at(entity_id, at)
            if snap is None:
                continue
            kind = self._graph._entity_kind(entity_id)
            if kind == "agent":
                agent_ids.append(entity_id)
            elif kind == "tool":
                tool_ids.append(entity_id)
            elif kind == "capability":
                capability_ids.append(entity_id)
            elif kind == "governance_graph":
                # Last-write wins by sorted entity_id; a more sophisticated
                # selector (active_at intervals) lands when institutional/
                # comes online in P1.
                latest_gov_graph_id = entity_id

        agent_ids.sort()
        tool_ids.sort()
        capability_ids.sort()

        state = EcosystemState(
            snapshot_at=at,
            state_hash=state_hash,
            active_agent_ids=tuple(agent_ids),
            active_tool_ids=tuple(tool_ids),
            active_capability_ids=tuple(capability_ids),
            active_governance_graph_id=(
                latest_gov_graph_id or _UNKNOWN_GOVERNANCE_GRAPH_ID
            ),
            aggregate_drift_signals={},
            sliding_window_compromise_ratio=0.0,
        )

        emit_event(
            "graph.projection.computed",
            snapshot_at=at.isoformat(),
            state_hash=state_hash,
            agent_count=len(agent_ids),
            tool_count=len(tool_ids),
            capability_count=len(capability_ids),
        )
        return state

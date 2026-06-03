"""
[Architecture: Cross-cutting (Persistence)] — temporal knowledge graph — in-memory backend wired; rustworkx/postgres/janusgraph backends test-only or orphan

See ARCHITECTURE.md for the full six-layer model.

Graph Layer — Temporal Knowledge Graph
========================================

The persistent ecosystem state. A property graph where every node is a
typed entity and every edge is a typed temporal event.

References
----------
- Zep / Graphiti temporal-aware knowledge graph
- arxiv 2602.05665 (Graph-based Agent Memory: Taxonomy, Techniques, Applications)

Backends
--------
  in-memory  P0 — for dev / tests / small deployments
  Postgres + pgvector + extensions  P1 — production default
  JanusGraph / Neo4j  P2 — large-scale multi-tenant

Priority
--------
P0 (in-memory backbone), P1 (Postgres), P2 (graph DB).

"""

# Architectural layer marker (see ARCHITECTURE.md).
# Queryable as `from tex.graph import __layer__, __layer_kind__`.
__layer__: int | None = None
__layer_kind__: str = 'cross_cutting_persistence'

from tex.graph.temporal_kg import InMemoryTemporalKG, TemporalKnowledgeGraph
from tex.graph.projection import StateProjection
from tex.graph.query import GraphQuery

__all__ = [
    "TemporalKnowledgeGraph",
    "InMemoryTemporalKG",
    "StateProjection",
    "GraphQuery",
]

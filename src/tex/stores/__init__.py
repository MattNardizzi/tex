"""
[Architecture: Cross-cutting (Persistence)] — InMemory and Postgres implementations of every store — action_ledger, agent_registry, discovery_ledger, precedent_store, etc.

See ARCHITECTURE.md for the full six-layer model.
"""

# Architectural layer marker (see ARCHITECTURE.md).
# Queryable as `from tex.stores import __layer__, __layer_kind__`.
__layer__: int | None = None
__layer_kind__: str = 'cross_cutting_persistence'


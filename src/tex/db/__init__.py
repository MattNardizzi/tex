"""
[Architecture: Cross-cutting (Persistence)] — shared Postgres connection management and leaderboard repos

See ARCHITECTURE.md for the full six-layer model.

Tex database adapters.
"""

# Architectural layer marker (see ARCHITECTURE.md).
# Queryable as `from tex.db import __layer__, __layer_kind__`.
__layer__: int | None = None
__layer_kind__: str = 'cross_cutting_persistence'

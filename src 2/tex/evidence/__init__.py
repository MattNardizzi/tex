"""
[Architecture: Layer 5 (Evidence)] — the canonical hash-chained evidence chain (JSONL + Postgres mirror)

See ARCHITECTURE.md for the full six-layer model.
"""

# Architectural layer marker (see ARCHITECTURE.md).
# Queryable as `from tex.evidence import __layer__, __layer_kind__`.
__layer__: int | None = 5
__layer_kind__: str = 'evidence'


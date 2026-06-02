"""
[Architecture: Layer 4 (Execution Governance)] — the Policy Decision Point — runs the seven-stream pipeline that produces every PERMIT/ABSTAIN/FORBID

See ARCHITECTURE.md for the full six-layer model.
"""

# Architectural layer marker (see ARCHITECTURE.md).
# Queryable as `from tex.engine import __layer__, __layer_kind__`.
__layer__: int | None = 4
__layer_kind__: str = 'execution_governance'


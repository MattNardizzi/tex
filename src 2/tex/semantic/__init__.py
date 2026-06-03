"""
[Architecture: Layer 4 (Execution Governance)] — LLM judge with deterministic fallback — Stream 7 of the PDP

See ARCHITECTURE.md for the full six-layer model.
"""

# Architectural layer marker (see ARCHITECTURE.md).
# Queryable as `from tex.semantic import __layer__, __layer_kind__`.
__layer__: int | None = 4
__layer_kind__: str = 'execution_governance'


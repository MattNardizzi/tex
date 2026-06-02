"""
[Architecture: Layer 2 (Identity)] — agent identity, capability, and behavioral evaluators for the PDP

See ARCHITECTURE.md for the full six-layer model.
"""

# Architectural layer marker (see ARCHITECTURE.md).
# Queryable as `from tex.agent import __layer__, __layer_kind__`.
__layer__: int | None = 2
__layer_kind__: str = 'identity'


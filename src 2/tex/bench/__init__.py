"""
[Architecture: Tooling] — AgentDojo benchmark harness — invokable as `python -m tex.bench.agentdojo`

See ARCHITECTURE.md for the full six-layer model.

Tex benchmark harnesses.
"""

# Architectural layer marker (see ARCHITECTURE.md).
# Queryable as `from tex.bench import __layer__, __layer_kind__`.
__layer__: int | None = None
__layer_kind__: str = 'tooling'

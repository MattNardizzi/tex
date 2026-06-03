"""
[Architecture: Cross-cutting (Domain model)] — Pydantic models for EvaluationRequest, Decision, Policy, AgentRecord, etc. — used by every package

See ARCHITECTURE.md for the full six-layer model.
"""

# Architectural layer marker (see ARCHITECTURE.md).
# Queryable as `from tex.domain import __layer__, __layer_kind__`.
__layer__: int | None = None
__layer_kind__: str = 'cross_cutting_domain'


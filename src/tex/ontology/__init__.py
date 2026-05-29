"""
[Architecture: Layer 4 (Execution Governance)] — entity/event ontology validator used by the ecosystem engine

See ARCHITECTURE.md for the full six-layer model.

Ontology Layer
==============

Type system for the ecosystem. Defines the typed entities (agents, tools,
datasets, models, humans, capabilities, policies) and typed edges (events)
that the temporal knowledge graph admits.

References
----------
- AIRO (AI Risk Ontology, Golpayegani et al. 2022)
- arxiv 2604.27713 (Knowledge Graph Representations for LLM-Based Policy
  Compliance Reasoning)
- arxiv 2604.00555 (Ontology-Constrained Neural Reasoning in Enterprise
  Agentic Systems)

Three sub-ontologies (per arxiv 2604.00555):
  role_ontology         How domain actors reason
  interaction_ontology  How actors coordinate
  governance_ontology   What regulatory bounds apply (EU AI Act, NAIC, etc.)

Priority
--------
P0 — the type system is the foundation; nothing else types-checks without it.

"""

# Architectural layer marker (see ARCHITECTURE.md).
# Queryable as `from tex.ontology import __layer__, __layer_kind__`.
__layer__: int | None = 4
__layer_kind__: str = 'execution_governance'

from tex.ontology.entity_types import EntityKind, EntityTypeRegistry
from tex.ontology.event_types import EventKind, EventTypeRegistry
from tex.ontology.validator import OntologyValidator

__all__ = [
    "EntityKind",
    "EntityTypeRegistry",
    "EventKind",
    "EventTypeRegistry",
    "OntologyValidator",
]

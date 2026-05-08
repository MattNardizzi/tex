"""
Ecosystem Governance Layer — Top-Level Package
===============================================

The ecosystem layer subsumes per-action adjudication into ecosystem-state
assessment. Every artifact, tool call, and agent message becomes a typed
event in a temporal knowledge graph. Verdicts evaluate the ecosystem
equilibrium, not the artifact.

Public surface
--------------
  EcosystemEngine        — primary entrypoint
  EcosystemVerdict       — extended verdict type
  EcosystemState         — read-only snapshot
  ProposedEvent          — input to evaluate()
"""

from tex.ecosystem.bridge import EcosystemBridge, routing_result_to_proposed_event
from tex.ecosystem.engine import EcosystemEngine
from tex.ecosystem.proposed_event import ProposedEvent
from tex.ecosystem.state import EcosystemState
from tex.ecosystem.verdict import EcosystemVerdict, EcosystemVerdictKind

__all__ = [
    "EcosystemEngine",
    "EcosystemBridge",
    "EcosystemVerdict",
    "EcosystemVerdictKind",
    "EcosystemState",
    "ProposedEvent",
    "routing_result_to_proposed_event",
]

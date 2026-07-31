"""
MCPShield: Formal Verification for MCP Tool Calls.

Models MCP interactions as Labeled Transition Systems (LTS) with
trust-boundary annotations. Verifies four formal security properties:

  Property 1 (Tool Integrity)        - hash equality at every invocation
  Property 2 (Data Confinement)      - sensitive data stays in authorised domains
  Property 3 (Privilege Boundedness) - tool caps ⊆ agent caps ∩ declared
  Property 4 (Context Isolation)     - cross-domain use requires authorization

Decidability follows from the finite state space and finite security
lattice.

Priority: P1.
"""

from tex.runtime.mcpshield.lts_model import (
    Capability,
    DataValue,
    LtsModel,
    SecurityLabel,
    ToolDefinition,
    Transition,
    TrustBoundary,
    TrustDomain,
    label_dominates,
)
from tex.runtime.mcpshield.verifier import (
    PROPERTY_ALIASES,
    verify_property,
)

__all__ = [
    "Capability",
    "DataValue",
    "LtsModel",
    "PROPERTY_ALIASES",
    "SecurityLabel",
    "ToolDefinition",
    "Transition",
    "TrustBoundary",
    "TrustDomain",
    "label_dominates",
    "verify_property",
]

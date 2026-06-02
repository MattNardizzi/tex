"""
MCPShield: Formal Verification for MCP Tool Calls.

Reference: arxiv 2604.05969 (Acharya & Gupta), April 2026.

Models MCP interactions as Labeled Transition Systems (LTS) with
trust-boundary annotations. Verifies the four formal security properties
defined in the paper:

  Property 1 (Tool Integrity)        - hash equality at every invocation
  Property 2 (Data Confinement)      - sensitive data stays in authorised domains
  Property 3 (Privilege Boundedness) - tool caps ⊆ agent caps ∩ declared
  Property 4 (Context Isolation)     - cross-domain use requires authorization

Decidability follows from the finite state space and finite security
lattice (paper §IV-B).

Threat taxonomy: 7 categories, 23 vectors, 4 attack surfaces, grounded in
analysis of 177,000+ MCP tools. Coverage: 91% vs ≤34% for any single
existing defense (paper §VI).

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

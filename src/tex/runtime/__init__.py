"""
[Architecture: Layer 4 (Execution Governance)] — runtime defense modules invoked by their matching specialists — mcpshield, mage, planguard, clawguard, agentarmor

See ARCHITECTURE.md for the full six-layer model.

Runtime Defense Layer
=====================

Five complementary runtime defenses for tool-augmented LLM agents.
Each defends a different layer; together they form defense-in-depth.

  planguard/    Indirect prompt injection via planning-based consistency
                verification against an isolated reference plan

  clawguard/    Tool-call boundary enforcement (web/MCP/skill-file injection)

  agentarmor/   Program analysis (CFG/DFG/PDG) on agent traces
                arxiv 2508.01249, 95.75% TPR, 3.66% FPR, 1% utility drop

  mage/         Shadow memory for long-horizon threats

  mcpshield/    Formal verification of MCP tool calls
                Labeled transition systems with trust-boundary annotations

Priority
--------
P0: clawguard (ships with C2PA + receipts in days 15-42)
P1: planguard, agentarmor, mage, mcpshield (days 71-150)

"""

# Architectural layer marker (see ARCHITECTURE.md).
# Queryable as `from tex.runtime import __layer__, __layer_kind__`.
__layer__: int | None = 4
__layer_kind__: str = 'execution_governance'

__all__ = []

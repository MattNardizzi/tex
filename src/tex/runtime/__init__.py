"""
Runtime Defense Layer
=====================

Five complementary runtime defenses for tool-augmented LLM agents.
Each defends a different layer; together they form defense-in-depth.

  planguard/    Indirect prompt injection via planning-based consistency
                arxiv 2604.10134, ASR 72.8% -> 0% with 1.49% FPR

  clawguard/    Tool-call boundary enforcement (web/MCP/skill-file injection)
                arxiv 2604.11790, ASR ~0% on AgentDojo, 7-11% on MCPSafeBench

  agentarmor/   Program analysis (CFG/DFG/PDG) on agent traces
                arxiv 2508.01249, 95.75% TPR, 3.66% FPR, 1% utility drop

  mage/         Shadow memory for long-horizon threats
                arxiv 2605.03228 (Cisco co-author, May 4 2026)

  mcpshield/    Formal verification of MCP tool calls
                Labeled transition systems with trust-boundary annotations

Priority
--------
P0: clawguard (ships with C2PA + receipts in days 15-42)
P1: planguard, agentarmor, mage, mcpshield (days 71-150)
"""

__all__ = []

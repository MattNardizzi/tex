"""
ClawGuard: Runtime Security Framework for Tool-Augmented LLM Agents.

Reference: arxiv 2604.11790, Zhao et al, April 13 2026.

Defends against three injection channels:
  - Web and local content injection
  - MCP server injection
  - Skill file injection

Performance:
  - AgentDojo ASR: 0.6-3.1% -> 0%
  - MCPSafeBench ASR: 36.5-46.1% -> 7.1-11.2%

Two rule classes:
  base rules — non-negotiable security invariants
  task rules — induced from user objective before any external tool runs

Priority: P0/P1.
"""

from tex.runtime.clawguard.boundary_enforcer import (
    ApprovalHandler,
    ContentSanitizer,
    RuleEvaluator,
    SanitizedCall,
    ToolCallBoundaryEnforcer,
)
from tex.runtime.clawguard.rule_set import (
    BaseRuleSet,
    Rule,
    RuleAction,
    RuleDomain,
    TaskRuleSet,
    Verdict,
)

__all__ = [
    "ApprovalHandler",
    "BaseRuleSet",
    "ContentSanitizer",
    "Rule",
    "RuleAction",
    "RuleDomain",
    "RuleEvaluator",
    "SanitizedCall",
    "TaskRuleSet",
    "ToolCallBoundaryEnforcer",
    "Verdict",
]

"""
PlanGuard: Defending Agents against Indirect Prompt Injection via
Planning-based Consistency Verification.

Reference: arxiv 2604.10134, Gong & Deng, April 11 2026.

Architecture
------------
  1. Isolated Planner — generates a reference set of valid actions derived
     SOLELY from user instructions (no tool outputs in scope)
  2. Hierarchical Verification — first hard constraints (deny unauthorized
     tool invocations), then Intent Verifier (validate parameter deviations)

Performance: ASR 72.8% -> 0% on InjecAgent. FPR 1.49%. Training-free.

Priority: P1.
"""

from tex.runtime.planguard.intent_verifier import (
    IntentLLMCallable,
    IntentVerifier,
)
from tex.runtime.planguard.isolated_planner import (
    Action,
    IsolatedPlanner,
    LLMPlannerCallable,
    ReferencePlan,
    ToolCatalog,
    ToolSpec,
)

__all__ = [
    "Action",
    "IntentLLMCallable",
    "IntentVerifier",
    "IsolatedPlanner",
    "LLMPlannerCallable",
    "ReferencePlan",
    "ToolCatalog",
    "ToolSpec",
]

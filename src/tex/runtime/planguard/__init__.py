"""
PlanGuard: Defending Agents against Indirect Prompt Injection via
Planning-based Consistency Verification.

Architecture
------------
  1. Isolated Planner — generates a reference set of valid actions derived
     SOLELY from user instructions (no tool outputs in scope)
  2. Hierarchical Verification — first hard constraints (deny unauthorized
     tool invocations), then Intent Verifier (validate parameter deviations)

Training-free.

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

"""
Runtime Governance via Policies on Paths.

Reference: Kaptein, Khan & Podstavnychy. "Runtime Governance for AI Agents:
Policies on Paths." arXiv:2603.16586 (Mar 2026).

Formalizes governance over FULL agent paths, not just single tool calls.
A path is a sequence of (state, action, observation) tuples. Path policies
allow Tex to express constraints like:
  - "must call tool X before tool Y"
  - "must NEVER call tool A after observing condition B"
  - "max N invocations of tool C per session"

Public API:

  PathPolicy           — LTLf-formula policy with severity decision shorthand
  CallablePolicy       — deterministic-function policy pi_j(A, P_i, s*, Sigma)
  PathPolicyChecker    — runtime checker maintaining the sliding window
  PathStep             — type alias for (state, action, observation) tuple

Lower-level:

  ltlf.evaluate        — evaluate an LTLf formula against a trace (test-friendly)
  ltlf.compile_formula — pre-parse a formula for repeated evaluation
  ltlf.LtlfParseError  — raised on malformed formulas

Priority: P1.
"""

from tex.governance.path_policy.checker import PathPolicyChecker
from tex.governance.path_policy.policy import (
    CallablePolicy,
    PathPolicy,
    PathPolicySeverity,
    PathStep,
    PolicyFn,
)

__all__ = [
    "CallablePolicy",
    "PathPolicy",
    "PathPolicyChecker",
    "PathPolicySeverity",
    "PathStep",
    "PolicyFn",
]

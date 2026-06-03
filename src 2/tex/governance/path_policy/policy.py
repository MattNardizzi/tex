"""
Path policy specification language.

Reference: Kaptein, Khan & Podstavnychy. "Runtime Governance for AI Agents:
Policies on Paths." arXiv:2603.16586 (Mar 2026).

The Kaptein paper formalizes governance policies as deterministic functions

    pi_j(A, P_i, s*, Sigma) -> [0, 1]

returning a violation probability. Step-level violation is composed across
the policy set as

    v_i = 1 - prod_{j in J} (1 - pi_j(A, P_i, s*, Sigma))

The decision function delta(v_i) maps to one of three concrete intervention
outcomes (paper Section 4.4):

  - Pass:  the proposed action executes unmodified
  - Steer: execution pauses; a compliance hint is injected, human approval
           may be requested, and execution resumes from the stored state
  - Block: the proposed action is prevented, the task terminates at a
           failure state, the incident is escalated

Tex's existing scaffolding pre-commits to two surface concepts that the
paper does not specify directly:

  1. PathPolicy.ltl_formula — a string in a small finite-trace LTL
     dialect (LTLf) that the runtime checker compiles and evaluates over
     the sliding window. The paper's Section 3.5 lists policies that the
     authors observe "are binary threshold rules on path state": LTLf
     expresses exactly this class compactly, and provides a formal
     anchor for the audit trail (the formula text is what is audited,
     not opaque Python).
  2. PathPolicy.severity ("block" | "warn" | "audit") — a simplified
     decision-function attached per-policy. severity="block" maps to
     paper-Block; severity="warn" maps to paper-Steer with no human
     approval; severity="audit" maps to Pass-with-audit-event.

For the deterministic-function policy class from Section 3.2 of the paper,
see ``CallablePolicy`` below — it is the mechanism by which Tex exposes
the full pi_j(A, P_i, s*, Sigma) form when an LTLf expression cannot
capture the policy (e.g., graduated/probabilistic data-exfiltration
policies, cross-agent shared-state policies that read Sigma).

Priority: P1.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Literal, Mapping, Sequence

# Severity vocabulary. Kept narrow for audit clarity.
PathPolicySeverity = Literal["block", "warn", "audit"]


@dataclass(frozen=True, slots=True)
class PathPolicy:
    """
    A policy expressed over agent execution paths.

    Attributes
    ----------
    policy_id:
        Stable identifier; used as the audit-log key and as the violated-
        policy id returned by ``PathPolicyChecker.check``.
    description:
        Human-readable description for the policy registry.
    ltl_formula:
        Finite-trace LTL (LTLf) formula evaluated against the sliding
        window of (state, action, observation) tuples, with the candidate
        action appended as the final position. See
        ``tex.governance.path_policy.ltlf`` for grammar. May be empty
        (``""``) for callable-only policies.
    severity:
        Decision-function shorthand. See module docstring.
    """

    policy_id: str
    description: str
    ltl_formula: str  # linear temporal logic over actions
    severity: PathPolicySeverity  # "block" | "warn" | "audit"


# A path step is a (state, action, observation) tuple, per the paper's
# definition of an execution path P = (s_1, ..., s_n) where each
# s_i = (tau_i, d_in,i, d_out,i). Tex flattens to:
#   state       — agent / org state vector at step i (mapping)
#   action      — proposed or completed action (mapping with at least
#                 a "tool" or "type" key plus an "input" payload)
#   observation — observed output of the action (mapping; empty for
#                 prospective candidate actions where the output is not
#                 yet known)
PathStep = tuple[Mapping[str, object], Mapping[str, object], Mapping[str, object]]


# Signature for the deterministic-function policies of Section 3.2:
#     pi_j(A, P_i, s*, Sigma) -> [0, 1]
# We model A and Sigma as plain mappings to keep the framework general
# (per the paper, "A is simply an identifier" plus registered metadata).
PolicyFn = Callable[
    [Mapping[str, object], Sequence[PathStep], Mapping[str, object], Mapping[str, object]],
    float,
]


@dataclass(frozen=True, slots=True)
class CallablePolicy:
    """
    A deterministic-function policy of the form pi_j(A, P_i, s*, Sigma).

    Used when an LTLf expression cannot capture the policy — e.g.,
    graduated data-exfiltration policies whose score is a function of the
    maximum data-sensitivity level encountered, or information-barrier
    policies that read shared state Sigma.

    The paper requires pi_j to be deterministic: identical inputs always
    produce identical outputs. The audit trail records the policy_id and
    the inputs at evaluation time, so any auditor can reproduce the score.
    Random / non-deterministic logic inside ``fn`` is a violation of the
    paper's framework (Section 3.2).

    Attributes
    ----------
    policy_id:
        Stable identifier.
    description:
        Human-readable description.
    fn:
        The pi_j callable. Must return a float in [0, 1]. Values outside
        this range are clamped by the checker, with a warning event
        emitted, but the policy author should treat that as a bug.
    severity:
        Decision-function shorthand; same vocabulary as PathPolicy.
    requires_path:
        If True, the checker re-evaluates this policy on every step.
        If False, the checker may evaluate it once at registration time
        (paper Section 4.2: pre-task phase optimization).
    """

    policy_id: str
    description: str
    fn: PolicyFn
    severity: PathPolicySeverity
    requires_path: bool = True

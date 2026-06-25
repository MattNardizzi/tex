"""
CaMeL plan AST.

A *plan* is the P-LLM's emitted control flow: a sequence of typed
operations the interpreter executes. We support a deliberately small
node set:

- ``Literal(value)``                     — constant from the trusted
                                            system / user prompt
- ``Read(source, key)``                  — read an untrusted input from
                                            the environment (e.g. an
                                            email body, a retrieved doc)
- ``Var(name)``                          — reference a bound variable
- ``Assign(name, expr)``                 — bind ``expr``'s result to
                                            ``name``
- ``Call(tool, args, result_var)``       — call a registered tool;
                                            interpreter checks the
                                            policy before invoking
- ``QLLM(query, inputs, result_var)``    — invoke the quarantined LLM
                                            on untrusted ``inputs`` with
                                            a trusted ``query``; result
                                            inherits the union of input
                                            caps
- ``Return(expr)``                       — finish the plan, returning a
                                            ``CapValue``

Why no general-purpose control flow?
------------------------------------
CaMeL's threat model trusts the P-LLM to emit a *finite, side-effect-
free* plan. Loops and conditionals can be expressed by the P-LLM
unrolling them based on the user's prompt; capability tracking remains
sound because the interpreter never lets untrusted data influence
plan structure. This matches CaMeL §4.3 (the paper's reference
interpreter is similarly restricted).

Programs not expressible in this AST should be deferred to the regular
agent loop with stricter PDP gating; we do not silently widen the
interpreter to accept dataflow it cannot reason about.

Reference: arxiv 2503.18813 §4-§5; SentinelAI extensions arxiv
2505.22852.
"""

from __future__ import annotations

from typing import Union

from pydantic import BaseModel, ConfigDict, Field

# The canonical scalar a typed finite output domain may range over. A domain is
# a *finite tuple* of these — the same JSON-scalar subset CapValue admits.
DomainScalar = Union[str, int, bool, None]

# Permissive sentinel for a ``Branch``'s per-branch attacker-influence budget.
# A branch left at this default is NOT high-stakes via its budget — this is the
# back-compat marker so iter-3 branches (which predate CHOKE-X and never set
# ``budget_bits``) behave EXACTLY as before. Chosen large enough that no realistic
# finite enum domain's certified leverage (log2|domain|) reaches it. It is NOT
# +inf because ``budget_bits`` is a typed ``int``; this is the integer stand-in
# for "unmetered per-branch leverage".
_UNMETERED = 1 << 30


class PlanError(Exception):
    """Raised on malformed plan construction or unresolved variables."""


# ---------------------------------------------------------------------------
# Node base
# ---------------------------------------------------------------------------


class _PlanNodeBase(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class Literal(_PlanNodeBase):
    """A trusted literal value (from the P-LLM, never from data)."""

    value: str | int | bool | None = None


class Var(_PlanNodeBase):
    """Reference to a previously-bound variable."""

    name: str = Field(min_length=1, max_length=64)


class Read(_PlanNodeBase):
    """
    Read an untrusted input from the environment.

    The interpreter looks up ``source`` in its registered untrusted-input
    map and tags the value with UNTRUSTED capability.

    ``output_domain`` — an optional *typed finite* tuple of the values this
    read is declared to produce. When present (and when the read's result is
    later used as a ``Branch`` condition), the interpreter prices the
    control-flow influence at ``log2(len(output_domain))`` bits and verifies
    the produced value lies inside the domain. When absent, the value carries
    UNBOUNDED capacity and may not steer a ``Branch`` (the interpreter
    fail-closes). The pricing is only as sound as this honest declaration.
    """

    source: str = Field(min_length=1, max_length=128)
    key: str | None = Field(default=None, max_length=128)
    output_domain: tuple[DomainScalar, ...] | None = Field(default=None)


Expr = Union[Literal, Var, Read]


class Assign(_PlanNodeBase):
    """Bind the result of ``expr`` to ``name``."""

    name: str = Field(min_length=1, max_length=64)
    expr: Expr


class Call(_PlanNodeBase):
    """Tool invocation. Gated by ``ToolPolicy``."""

    tool: str = Field(min_length=1, max_length=128)
    args: tuple[Expr, ...] = Field(default_factory=tuple)
    result_var: str | None = Field(default=None, max_length=64)


class QLLM(_PlanNodeBase):
    """Invoke the quarantined LLM.

    ``output_domain`` — an optional *typed finite* tuple of the values the
    quarantined LLM is constrained to emit (e.g. ``("yes", "no")`` for a
    classification). This is the typed-declassification handle that lets an
    otherwise-UNTRUSTED Q-LLM answer steer a ``Branch``: the interpreter
    prices the branch at ``log2(len(output_domain))`` control-flow-influence
    bits and rejects (HALTs) any answer outside the domain. Without it, the
    Q-LLM answer is UNBOUNDED capacity and may not be a ``Branch`` condition.
    """

    query: str = Field(min_length=1, max_length=4096)
    inputs: tuple[Var, ...] = Field(default_factory=tuple)
    result_var: str = Field(min_length=1, max_length=64)
    output_domain: tuple[DomainScalar, ...] | None = Field(default=None)


class Return(_PlanNodeBase):
    """Terminate the plan with a result."""

    expr: Expr


class Branch(_PlanNodeBase):
    """Conditional control flow gated on a *typed, capacity-priced* condition.

    This is the CaMeL static→dynamic swap. Classic CaMeL forbids *all*
    untrusted-influenced control flow by construction (no conditional node
    exists; the interpreter never branches on a CapValue above TRUSTED).
    ``Branch`` replaces that binary prohibition with a *metered* dynamic
    model: an untrusted value may steer control flow, but only if it was
    produced by a node that declared a typed finite ``output_domain``, and
    only at a measured cost — ``log2(len(output_domain)) * sink_weight``
    bits of control-flow influence, debited against a cumulative budget.

    - ``cond_var``   — name of a Var bound by a *prior* ``QLLM`` or ``Read``
                       that declared an ``output_domain``. The interpreter
                       fail-closes (HALT, risk=1.0) if the producing node had
                       no ``output_domain`` (untyped/unbounded capacity).
    - ``then_nodes`` — executed when the condition value is truthy / matches.
    - ``else_nodes`` — executed otherwise. Either arm may be empty.
    - ``match_value`` — OPTIONAL value-discriminating arm selection. When set, the
                       then-arm fires iff ``cond_value == match_value`` (exact
                       equality), else the else-arm; when absent (the iter-3
                       default), arm selection is Python truthiness of the
                       condition value. This is the handle that lets a finite enum
                       like ``{refund, no_refund}`` — where BOTH values are truthy —
                       genuinely split across both arms, so CHOKE-X can certify the
                       real per-value leverage. The certifier (``branch_leverage``)
                       uses the SAME selector the interpreter does, keeping the
                       2-safety certificate sound w.r.t. actual execution.

    The arms are ordinary plan-node lists (they may themselves contain
    ``Branch`` nodes, recursively). Arms may NOT contain a ``Return`` — the
    overall plan still terminates at exactly one top-level ``Return``.

    High-stakes branches (CHOKE-X)
    ------------------------------
    CFI-BUDGET (above) bounds *cumulative* control-flow influence with a flat
    per-branch charge. That flat charge admits a single high-leverage flip: one
    in-budget branch can still commit an irreversible arm under attacker control.
    ``budget_bits`` and ``effect_class`` arm the companion CHOKE-X per-branch
    leverage certifier on this same node:

    - ``budget_bits`` — the *attacker-influence* budget for THIS branch, in bits
      of certified leverage (NOT the cumulative CFI budget). A branch is
      HIGH-STAKES iff ``budget_bits == 0`` OR ``effect_class == 'irreversible'``.
      The default ``_UNMETERED`` sentinel (a permissive non-zero value) marks a
      branch as NOT high-stakes via budget — back-compat for iter-3 branches that
      predate CHOKE-X. A high-stakes branch is certified BEFORE it executes: the
      finite-enum certifier (``branch_leverage.certify_leverage``) measures, by
      2-safety self-composition over the condition's signed ``output_domain``,
      how many DISTINCT arms the attacker can steer to; if that exceeds
      ``budget_bits`` the branch resolves to ABSTAIN (the high-stakes arm is NOT
      committed). A non-decidable (non-finite-enum) high-stakes guard ABSTAINs
      rather than sample-and-commit.
    - ``effect_class`` — coarse reversibility of the side effects the arms reach.
      ``'irreversible'`` forces high-stakes regardless of ``budget_bits``.

    Non-high-stakes branches (the iter-3 default) keep classic CFI behavior
    unchanged — they are never certified by CHOKE-X.
    """

    cond_var: str = Field(min_length=1, max_length=64)
    then_nodes: tuple["PlanNode", ...] = Field(default_factory=tuple)
    else_nodes: tuple["PlanNode", ...] = Field(default_factory=tuple)
    # Optional value-discriminating arm selection. ``match_enabled`` flips the
    # selector from Python truthiness (iter-3 default) to exact equality: when
    # True the then-arm fires iff the condition value EQUALS ``match_value``. A
    # separate boolean (rather than a sentinel) lets a guard legitimately match on
    # ``None``, which is itself a valid ``DomainScalar``. Lets a fully-truthy enum
    # like ``{refund, no_refund}`` split both arms so CHOKE-X can certify real
    # per-value leverage; the certifier uses the SAME selector for soundness.
    match_enabled: bool = Field(default=False)
    match_value: DomainScalar = Field(default=None)
    # Per-branch attacker-influence budget (bits of certified leverage). The
    # default sentinel ``_UNMETERED`` is a permissive non-zero value: a branch
    # left at the default is NOT high-stakes via budget, so iter-3 branches that
    # predate CHOKE-X behave EXACTLY as before. ``budget_bits == 0`` makes a
    # branch high-stakes (zero attacker leverage tolerated).
    budget_bits: int = Field(default=_UNMETERED, ge=0)
    # Coarse reversibility class of the arms' side effects. ``'irreversible'``
    # forces the branch high-stakes regardless of ``budget_bits``.
    effect_class: str = Field(default="reversible", max_length=32)

    @property
    def is_high_stakes(self) -> bool:
        """A branch is high-stakes iff its attacker-influence budget is zero OR
        its effect class is irreversible. High-stakes branches are certified by
        CHOKE-X before execution; others keep classic CFI behavior."""
        return self.budget_bits == 0 or self.effect_class == "irreversible"


PlanNode = Union[Assign, Call, QLLM, Branch, Return]

Branch.model_rebuild()


class Plan(BaseModel):
    """A sequence of plan nodes."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    nodes: tuple[PlanNode, ...]
    description: str | None = Field(default=None, max_length=500)

    def validate_structure(self) -> None:
        """Sanity-check: exactly one top-level ``Return``, must be last; no
        ``Return`` may appear inside a ``Branch`` arm (arms re-join the main
        line — only the top-level plan terminates)."""
        seen_return = False
        for i, n in enumerate(self.nodes):
            if isinstance(n, Return):
                if i != len(self.nodes) - 1:
                    raise PlanError("Return must be the final node")
                seen_return = True
            elif isinstance(n, Branch):
                _validate_branch_arms(n)
        if not seen_return:
            raise PlanError("Plan must end with a Return node")


def _validate_branch_arms(branch: "Branch") -> None:
    """Recursively validate a ``Branch``: arms may not contain a ``Return``;
    nested ``Branch`` nodes are validated transitively."""
    for arm in (branch.then_nodes, branch.else_nodes):
        for n in arm:
            if isinstance(n, Return):
                raise PlanError("Return may not appear inside a Branch arm")
            if isinstance(n, Branch):
                _validate_branch_arms(n)


__all__ = [
    "Assign",
    "Branch",
    "Call",
    "DomainScalar",
    "Expr",
    "Literal",
    "Plan",
    "PlanError",
    "PlanNode",
    "QLLM",
    "Read",
    "Return",
    "Var",
]

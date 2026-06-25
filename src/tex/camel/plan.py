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

    The arms are ordinary plan-node lists (they may themselves contain
    ``Branch`` nodes, recursively). Arms may NOT contain a ``Return`` — the
    overall plan still terminates at exactly one top-level ``Return``.
    """

    cond_var: str = Field(min_length=1, max_length=64)
    then_nodes: tuple["PlanNode", ...] = Field(default_factory=tuple)
    else_nodes: tuple["PlanNode", ...] = Field(default_factory=tuple)


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

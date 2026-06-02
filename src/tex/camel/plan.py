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
    """

    source: str = Field(min_length=1, max_length=128)
    key: str | None = Field(default=None, max_length=128)


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
    """Invoke the quarantined LLM."""

    query: str = Field(min_length=1, max_length=4096)
    inputs: tuple[Var, ...] = Field(default_factory=tuple)
    result_var: str = Field(min_length=1, max_length=64)


class Return(_PlanNodeBase):
    """Terminate the plan with a result."""

    expr: Expr


PlanNode = Union[Assign, Call, QLLM, Return]


class Plan(BaseModel):
    """A sequence of plan nodes."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    nodes: tuple[PlanNode, ...]
    description: str | None = Field(default=None, max_length=500)

    def validate_structure(self) -> None:
        """Sanity-check: exactly one ``Return``, must be last."""
        seen_return = False
        for i, n in enumerate(self.nodes):
            if isinstance(n, Return):
                if i != len(self.nodes) - 1:
                    raise PlanError("Return must be the final node")
                seen_return = True
        if not seen_return:
            raise PlanError("Plan must end with a Return node")


__all__ = [
    "Assign",
    "Call",
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

"""
CaMeL capability-tracking interpreter.

Executes a P-LLM-emitted ``Plan`` while propagating ``CapabilitySet``
labels through every operation. Each tool call is gated against a
``ToolPolicyRegistry``; any disallowed call halts the plan with a
``CamelInterpreterError`` and the interpreter returns a structured
trace.

Invariants (CaMeL §5)
---------------------
1. **No untrusted-influenced control flow.** The plan is fixed at
   load time. The interpreter never branches on the value of a
   ``CapValue`` whose level is above ``TRUSTED``. We enforce this by
   construction: the plan AST contains no conditionals or loops.
2. **Capability monotonicity.** A value's capability set never
   shrinks except through explicit, policy-authorized
   declassification. We do not implement declassification ops here;
   that's a Thread 13 frontier item.
3. **Tool call gating.** ``ToolPolicy.check`` runs *before* the tool
   is invoked. A failed check raises ``CamelInterpreterError`` and the
   tool registry sees no call at all (no side effects).
4. **Q-LLM output tainting.** Every Q-LLM result inherits the union
   of input ``CapValue.caps``.

Trace
-----
Every node execution emits a ``TraceEntry`` to the ``ExecutionTrace``,
which is returned alongside the final result. The trace is suitable
for direct emission into Tex's hash-chained evidence ledger.
"""

from __future__ import annotations

from typing import Any, Callable

from pydantic import BaseModel, ConfigDict, Field

from tex.camel.capability import Capability, CapabilityLevel, CapabilitySet
from tex.camel.plan import (
    Assign,
    Call,
    Expr,
    Literal,
    Plan,
    PlanError,
    PlanNode,
    QLLM,
    Read,
    Return,
    Var,
)
from tex.camel.policy import ToolPolicyRegistry
from tex.camel.q_llm import QuarantinedLLM, StubQuarantinedLLM
from tex.camel.value import CapValue


class CamelInterpreterError(Exception):
    """Raised on policy denial, unbound variable, missing tool, etc."""

    def __init__(self, message: str, *, node_index: int | None = None) -> None:
        if node_index is not None:
            super().__init__(f"{message} (at node #{node_index})")
        else:
            super().__init__(message)
        self.message = message
        self.node_index = node_index


# ---------------------------------------------------------------------------
# Trace
# ---------------------------------------------------------------------------


class TraceEntry(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    node_index: int = Field(ge=0)
    op: str = Field(min_length=1, max_length=64)
    target: str | None = Field(default=None, max_length=128)
    cap_level: str = Field(min_length=1, max_length=16)
    sources: tuple[str, ...] = Field(default_factory=tuple)
    note: str | None = Field(default=None, max_length=500)


class ExecutionTrace(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    entries: tuple[TraceEntry, ...] = Field(default_factory=tuple)
    final_level: str = Field(min_length=1, max_length=16)
    final_sources: tuple[str, ...] = Field(default_factory=tuple)
    halted: bool = False
    halt_reason: str | None = Field(default=None, max_length=500)


# ---------------------------------------------------------------------------
# Interpreter
# ---------------------------------------------------------------------------


# A ToolFn is any callable taking (CapValue, ...) -> CapValue.
# The interpreter passes raw CapValues so tools that legitimately need
# to inspect provenance can do so. Tools that *don't* care just read
# `.value`.
ToolFn = Callable[..., CapValue]


class CamelInterpreter:
    """
    The capability-tracking executor.

    Construction parameters:
    - ``tool_policies``  — frozen ``ToolPolicyRegistry``
    - ``tool_impls``     — ``dict[str, ToolFn]`` actually running the
                           tools
    - ``q_llm``          — a ``QuarantinedLLM`` instance (defaults to
                           ``StubQuarantinedLLM``)
    - ``untrusted_env``  — ``dict[str, str]`` mapping ``(source, key)``
                           to raw untrusted content; if ``key`` is None
                           on the ``Read`` node, the source alone is
                           used as the lookup key

    ``run(plan, user_prompt)`` executes ``plan`` and returns
    ``(final_value, trace)``.
    """

    __slots__ = ("_tool_policies", "_tool_impls", "_q_llm", "_untrusted_env")

    def __init__(
        self,
        *,
        tool_policies: ToolPolicyRegistry,
        tool_impls: dict[str, ToolFn] | None = None,
        q_llm: QuarantinedLLM | None = None,
        untrusted_env: dict[str, str] | None = None,
    ) -> None:
        if not tool_policies.is_frozen:
            raise CamelInterpreterError(
                "ToolPolicyRegistry must be frozen before interpreter use"
            )
        self._tool_policies = tool_policies
        self._tool_impls = dict(tool_impls or {})
        self._q_llm = q_llm or StubQuarantinedLLM()
        self._untrusted_env = dict(untrusted_env or {})

    # ------------------------------------------------------------------ run

    def run(self, plan: Plan, *, user_prompt: str = "") -> tuple[CapValue, ExecutionTrace]:
        try:
            plan.validate_structure()
        except PlanError as exc:
            raise CamelInterpreterError(f"invalid plan: {exc}") from exc

        env: dict[str, CapValue] = {}
        entries: list[TraceEntry] = []
        final_value: CapValue | None = None
        halted = False
        halt_reason: str | None = None

        # Inject the user prompt as a USER-level value the plan may
        # reference via ``Read("user", "prompt")`` or similar. The
        # P-LLM is trusted, but the prompt itself is USER level.
        self._untrusted_env.setdefault("user_prompt", user_prompt)

        for i, node in enumerate(plan.nodes):
            try:
                final_value, entry = self._step(i, node, env)
                entries.append(entry)
                if isinstance(node, Return):
                    break
            except CamelInterpreterError as exc:
                halted = True
                halt_reason = exc.message
                entries.append(
                    TraceEntry(
                        node_index=i,
                        op=type(node).__name__,
                        target=None,
                        cap_level=CapabilityLevel.UNTRUSTED.name,
                        sources=(),
                        note=f"halted: {exc.message}",
                    )
                )
                # On halt: fail-closed -> final value is an empty
                # UNTRUSTED value so downstream consumers cannot trust it
                final_value = CapValue(
                    value=None,
                    caps=CapabilitySet.of(
                        Capability.untrusted("camel:halt"),
                    ),
                )
                break

        if final_value is None:
            final_value = CapValue(value=None, caps=CapabilitySet.empty())

        trace = ExecutionTrace(
            entries=tuple(entries),
            final_level=final_value.level.name,
            final_sources=tuple(sorted(final_value.caps.sources)),
            halted=halted,
            halt_reason=halt_reason,
        )
        return final_value, trace

    # ----------------------------------------------------------------- step

    def _step(
        self, index: int, node: PlanNode, env: dict[str, CapValue]
    ) -> tuple[CapValue | None, TraceEntry]:
        if isinstance(node, Assign):
            value = self._eval_expr(node.expr, env, node_index=index)
            env[node.name] = value
            return None, TraceEntry(
                node_index=index,
                op="Assign",
                target=node.name,
                cap_level=value.level.name,
                sources=tuple(sorted(value.caps.sources)),
            )

        if isinstance(node, Call):
            arg_values = tuple(
                self._eval_expr(a, env, node_index=index) for a in node.args
            )
            tool_policy = self._tool_policies.policy_for(
                node.tool, arity=len(arg_values)
            )
            ok, reason = tool_policy.check(
                tuple(v.caps for v in arg_values)
            )
            if not ok:
                raise CamelInterpreterError(
                    f"tool {node.tool!r} call denied: {reason}",
                    node_index=index,
                )
            impl = self._tool_impls.get(node.tool)
            if impl is None:
                raise CamelInterpreterError(
                    f"no implementation for tool {node.tool!r}",
                    node_index=index,
                )
            result = impl(*arg_values)
            if not isinstance(result, CapValue):
                # Tool returned a raw value: wrap, deriving from inputs
                result = CapValue.derived(result, from_values=arg_values)
            if node.result_var is not None:
                env[node.result_var] = result
            return None, TraceEntry(
                node_index=index,
                op="Call",
                target=node.tool,
                cap_level=result.level.name,
                sources=tuple(sorted(result.caps.sources)),
                note=f"result_var={node.result_var or '_'}",
            )

        if isinstance(node, QLLM):
            input_values: list[CapValue] = []
            input_strs: list[str] = []
            for ref in node.inputs:
                v = self._eval_expr(ref, env, node_index=index)
                input_values.append(v)
                input_strs.append(str(v.value) if v.value is not None else "")
            answer_text = self._q_llm.answer(node.query, tuple(input_strs))
            result = CapValue.derived(
                answer_text, from_values=tuple(input_values)
            )
            env[node.result_var] = result
            return None, TraceEntry(
                node_index=index,
                op="QLLM",
                target=node.result_var,
                cap_level=result.level.name,
                sources=tuple(sorted(result.caps.sources)),
                note=f"query_len={len(node.query)}",
            )

        if isinstance(node, Return):
            value = self._eval_expr(node.expr, env, node_index=index)
            return value, TraceEntry(
                node_index=index,
                op="Return",
                target=None,
                cap_level=value.level.name,
                sources=tuple(sorted(value.caps.sources)),
            )

        raise CamelInterpreterError(
            f"unknown plan node type: {type(node).__name__}",
            node_index=index,
        )

    # ----------------------------------------------------------------- expr

    def _eval_expr(
        self, expr: Expr, env: dict[str, CapValue], *, node_index: int
    ) -> CapValue:
        if isinstance(expr, Literal):
            return CapValue.trusted(expr.value, source="plan_literal")
        if isinstance(expr, Var):
            if expr.name not in env:
                raise CamelInterpreterError(
                    f"unbound variable {expr.name!r}", node_index=node_index
                )
            return env[expr.name]
        if isinstance(expr, Read):
            key = f"{expr.source}:{expr.key}" if expr.key else expr.source
            raw = self._untrusted_env.get(key)
            if raw is None and expr.key is None:
                raw = self._untrusted_env.get(expr.source)
            if raw is None:
                raise CamelInterpreterError(
                    f"no untrusted input registered for {expr.source!r} "
                    f"(key={expr.key!r})",
                    node_index=node_index,
                )
            # The user prompt is USER level; everything else is UNTRUSTED.
            if expr.source == "user":
                return CapValue.user(raw, source="user")
            return CapValue.untrusted(raw, source=expr.source)
        raise CamelInterpreterError(
            f"unknown expression: {type(expr).__name__}", node_index=node_index
        )


__all__ = [
    "CamelInterpreter",
    "CamelInterpreterError",
    "ExecutionTrace",
    "ToolFn",
    "TraceEntry",
]

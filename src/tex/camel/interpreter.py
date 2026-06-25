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

from typing import Any, Callable, TYPE_CHECKING

from pydantic import BaseModel, ConfigDict, Field

if TYPE_CHECKING:  # type-only; avoids any import cycle at module load
    from tex.camel.capability_token import CapabilityGrant

from tex.camel.branch_leverage import (
    NonDecidableGuard,
    certify_leverage,
    selector_for,
)
from tex.camel.capability import Capability, CapabilityLevel, CapabilitySet
from tex.camel.cfi import CfiLedger, cfi_influence_bits, scope_symmetric_difference
from tex.camel.plan import (
    Assign,
    Branch,
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
    """Raised on policy denial, unbound variable, missing tool, etc.

    A raised ``CamelInterpreterError`` is the fail-closed HALT path: the
    interpreter stops the plan and returns an empty UNTRUSTED value with
    ``trace.halted = True`` and ``risk = 1.0``.
    """

    def __init__(self, message: str, *, node_index: int | None = None) -> None:
        if node_index is not None:
            super().__init__(f"{message} (at node #{node_index})")
        else:
            super().__init__(message)
        self.message = message
        self.node_index = node_index


class _CamelAbstain(Exception):
    """Internal signal: the CFI steering budget is exhausted at a ``Branch``.

    This is NOT a halt and NOT a FORBID. Tex never forbids a long-horizon task
    merely for spending its control-flow-influence budget; the task CONTINUES,
    but the over-budget branch resolves to ABSTAIN (the branch is not taken,
    neither arm runs, the prior environment is preserved, and the plan keeps
    executing its remaining straight-line nodes). The interpreter records this
    on the trace via ``abstained`` rather than ``halted``.
    """

    def __init__(self, message: str, *, node_index: int) -> None:
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
    # ABSTAIN is distinct from HALT: the plan ran to completion but at least one
    # ``Branch`` was skipped because the cumulative CFI steering budget was
    # exhausted. The task is not forbidden; it simply did not take the priced
    # branch. ``abstained`` is never set together with ``halted`` for the same
    # cause (HALT is fail-closed; ABSTAIN is fail-quiet-and-continue).
    abstained: bool = False
    abstain_reason: str | None = Field(default=None, max_length=500)
    # Cumulative control-flow-influence bits debited across all taken branches.
    cfi_bits_spent: float = Field(default=0.0, ge=0.0)

    @property
    def risk(self) -> float:
        """Coarse risk signal for downstream consumers: 1.0 on fail-closed
        HALT, else 0.0. (ABSTAIN is deliberate, not risky — risk stays 0.0.)"""
        return 1.0 if self.halted else 0.0


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

    __slots__ = (
        "_tool_policies",
        "_tool_impls",
        "_q_llm",
        "_untrusted_env",
        "_steer_budget",
    )

    def __init__(
        self,
        *,
        tool_policies: ToolPolicyRegistry,
        tool_impls: dict[str, ToolFn] | None = None,
        q_llm: QuarantinedLLM | None = None,
        untrusted_env: dict[str, str] | None = None,
        steer_budget: float = float("inf"),
    ) -> None:
        if not tool_policies.is_frozen:
            raise CamelInterpreterError(
                "ToolPolicyRegistry must be frozen before interpreter use"
            )
        if steer_budget < 0:
            raise CamelInterpreterError("steer_budget must be non-negative")
        self._tool_policies = tool_policies
        self._tool_impls = dict(tool_impls or {})
        self._q_llm = q_llm or StubQuarantinedLLM()
        self._untrusted_env = dict(untrusted_env or {})
        # Hardcoded cumulative control-flow-influence budget (bits). Default
        # +inf = unbounded = classic straight-line behavior is unaffected
        # (no plan without a Branch ever debits). A finite budget enables the
        # cumulative-ABSTAIN rail across this interpreter's single run().
        self._steer_budget = steer_budget

    # ------------------------------------------------------------------ run

    def run(
        self,
        plan: Plan,
        *,
        user_prompt: str = "",
        capability_grant: "CapabilityGrant | None" = None,
    ) -> tuple[CapValue, ExecutionTrace]:
        """Execute ``plan``.

        ``capability_grant`` (default ``None``) is the SIGNED, broker-verified
        three-budget grant from a capability token (``camel.capability_token``).
        When present, the interpreter spends the grant's signed ``steer_budget`` IN
        PLACE OF the hardcoded constructor arg, and uses the grant's signed branch
        leverage budget as a per-high-stakes-branch ceiling (taken as the MIN with
        each branch's declared ``budget_bits`` so the token can only TIGHTEN, never
        widen). When ``None`` (the default / flag-OFF path) the interpreter uses its
        constructor ``steer_budget`` and each branch's own ``budget_bits`` exactly
        as iter-3/4 — bit-for-bit unchanged. The caller MUST verify the token (and
        its PoP sender binding) and pass the resulting grant only on success; an
        unverified token yields no grant and this method is never reached with one.
        """
        try:
            plan.validate_structure()
        except PlanError as exc:
            raise CamelInterpreterError(f"invalid plan: {exc}") from exc

        # The effective cumulative CFI budget: the SIGNED token budget when a grant
        # is present (replacing the hardcoded constructor arg), else the constructor
        # default. Flag-OFF => grant is None => constructor value, unchanged.
        effective_steer_budget = (
            capability_grant.steer_budget
            if capability_grant is not None
            else self._steer_budget
        )

        env: dict[str, CapValue] = {}
        # var name -> declared finite output_domain of the node that bound it
        # (only QLLM/Read carry one). Absent name => unbounded capacity.
        domains: dict[str, tuple | None] = {}
        ledger = CfiLedger()
        entries: list[TraceEntry] = []
        final_value: CapValue | None = None
        halted = False
        halt_reason: str | None = None
        abstained = False
        abstain_reason: str | None = None

        # Inject the user prompt as a USER-level value the plan may
        # reference via ``Read("user", "prompt")`` or similar. The
        # P-LLM is trusted, but the prompt itself is USER level.
        self._untrusted_env.setdefault("user_prompt", user_prompt)

        for i, node in enumerate(plan.nodes):
            try:
                final_value, entry = self._step(
                    i,
                    node,
                    env,
                    domains=domains,
                    ledger=ledger,
                    steer_budget=effective_steer_budget,
                    grant=capability_grant,
                )
                entries.append(entry)
                if isinstance(node, Return):
                    break
            except _CamelAbstain as exc:
                # Cumulative budget exhausted at this Branch: skip it (neither
                # arm runs), record ABSTAIN, and CONTINUE the plan. Not a halt.
                abstained = True
                abstain_reason = exc.message
                entries.append(
                    TraceEntry(
                        node_index=i,
                        op="Branch",
                        target=None,
                        cap_level=CapabilityLevel.UNTRUSTED.name,
                        sources=(),
                        note=f"abstained: {exc.message}",
                    )
                )
                continue
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
            abstained=abstained,
            abstain_reason=abstain_reason,
            cfi_bits_spent=ledger.total_bits,
        )
        return final_value, trace

    # ----------------------------------------------------------------- step

    def _step(
        self,
        index: int,
        node: PlanNode,
        env: dict[str, CapValue],
        *,
        domains: dict[str, tuple | None],
        ledger: CfiLedger,
        steer_budget: float = float("inf"),
        grant: "CapabilityGrant | None" = None,
    ) -> tuple[CapValue | None, TraceEntry]:
        if isinstance(node, Assign):
            value = self._eval_expr(node.expr, env, node_index=index)
            env[node.name] = value
            # Carry a Read's declared output_domain onto the bound name so a
            # later Branch can look it up. A non-Read expr (Literal/Var) has no
            # declared domain: record None (unbounded) so it cannot steer.
            domains[node.name] = getattr(node.expr, "output_domain", None)
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
            # Record this Q-LLM's declared output_domain (may be None =
            # unbounded) so a later Branch on result_var can be priced/gated.
            domains[node.result_var] = node.output_domain
            return None, TraceEntry(
                node_index=index,
                op="QLLM",
                target=node.result_var,
                cap_level=result.level.name,
                sources=tuple(sorted(result.caps.sources)),
                note=f"query_len={len(node.query)}",
            )

        if isinstance(node, Branch):
            return self._step_branch(
                index,
                node,
                env,
                domains=domains,
                ledger=ledger,
                steer_budget=steer_budget,
                grant=grant,
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

    # --------------------------------------------------------------- branch

    def _step_branch(
        self,
        index: int,
        node: Branch,
        env: dict[str, CapValue],
        *,
        domains: dict[str, tuple | None],
        ledger: CfiLedger,
        steer_budget: float = float("inf"),
        grant: "CapabilityGrant | None" = None,
    ) -> tuple[CapValue | None, TraceEntry]:
        """Execute one metered ``Branch``.

        (a) fail-closed if the condition's producing node declared no typed
            finite output_domain (untyped => unbounded capacity) — EXCEPT a
            high-stakes branch, where a non-decidable guard ABSTAINs (CHOKE-X
            never samples-and-commits);
        (b) HALT if the produced value is not IN the declared domain;
        (CHOKE-X) for a high-stakes branch, certify per-branch attacker leverage
            BEFORE executing; over budget => ABSTAIN (the high-stakes/irreversible
            arm is NOT committed);
        (c) price the branch (cfi_influence_bits) and debit the ledger;
        (d) if cumulative total exceeds steer_budget -> ABSTAIN (continue);
        (e) else execute the chosen arm, propagating the condition value's
            UNTRUSTED taint into the arm's values via CapValue.derived.
        """
        # The condition variable must be bound.
        if node.cond_var not in env:
            raise CamelInterpreterError(
                f"Branch condition variable {node.cond_var!r} is unbound",
                node_index=index,
            )
        cond_value = env[node.cond_var]
        domain = domains.get(node.cond_var)

        # (a) no declared domain => unbounded capacity. For a HIGH-STAKES branch
        # this is a non-decidable guard => fail-closed-to-ABSTAIN (CHOKE-X never
        # samples-and-commits a high-stakes/irreversible arm it cannot certify).
        # For a non-high-stakes branch the classic CFI behavior is unchanged: HALT.
        if domain is None:
            if node.is_high_stakes:
                raise _CamelAbstain(
                    f"high-stakes Branch on {node.cond_var!r} has a non-decidable "
                    f"guard (no finite enumerable signed domain): ABSTAIN rather "
                    f"than sample-and-commit",
                    node_index=index,
                )
            raise CamelInterpreterError(
                f"Branch on {node.cond_var!r} has no declared output_domain "
                f"(untyped/unbounded control-flow capacity)",
                node_index=index,
            )
        if len(domain) < 1:
            raise CamelInterpreterError(
                f"Branch on {node.cond_var!r} has an empty output_domain",
                node_index=index,
            )

        # (b) the produced value must lie inside the declared domain.
        if cond_value.value not in domain:
            raise CamelInterpreterError(
                f"Branch condition value {cond_value.value!r} is not in the "
                f"declared output_domain {domain!r}",
                node_index=index,
            )

        # (CHOKE-X) HIGH-STAKES per-branch leverage certification, BEFORE any
        # execution. Transparent endorsement: certify_leverage reads only the
        # declared DOMAIN (the abstract set of all attacker values) + trusted
        # inputs — NEVER cond_value.value (the single realized value). The
        # realized value only selects the arm below, AFTER endorsement is granted.
        if node.is_high_stakes:
            try:
                certified_bits = certify_leverage(node, domain, trusted_env={})
            except NonDecidableGuard as exc:
                # A high-stakes guard outside the decidable finite-enum fragment:
                # ABSTAIN, never sample-and-commit. (Domain was non-None here, so
                # this fires only if a future non-enum guard form reaches CHOKE-X.)
                raise _CamelAbstain(str(exc), node_index=index) from exc
            # The effective per-branch leverage budget. When a SIGNED capability
            # grant is present its branch leverage budget applies as a CEILING,
            # taken as the MIN with the branch's own declared ``budget_bits`` — so
            # the token can only TIGHTEN the per-branch budget, never widen it.
            # With no grant (flag-OFF) the branch's own ``budget_bits`` governs
            # exactly as iter-4.
            effective_budget_bits = (
                min(node.budget_bits, grant.branch_leverage_budget)
                if grant is not None
                else node.budget_bits
            )
            if certified_bits > effective_budget_bits:
                raise _CamelAbstain(
                    f"CHOKE-X: high-stakes Branch on {node.cond_var!r} certifies "
                    f"{certified_bits} bits of attacker leverage > budget "
                    f"{effective_budget_bits} (effect_class={node.effect_class!r}): "
                    f"ABSTAIN, the high-stakes arm is NOT committed",
                    node_index=index,
                )

        # (c) price + debit.
        sink_weight = scope_symmetric_difference(node.then_nodes, node.else_nodes)
        debit = cfi_influence_bits(domain, sink_weight)
        total = ledger.append(debit)

        # (d) cumulative over the EFFECTIVE budget => ABSTAIN (NOT a halt/FORBID;
        # continue). ``steer_budget`` is the SIGNED token budget when a capability
        # grant drove this run, else the constructor default — passed down from
        # ``run`` so the same comparison serves both the flag-OFF (constructor) and
        # flag-ON (signed-token) paths without branching here.
        if total > steer_budget:
            raise _CamelAbstain(
                f"CFI steer budget exhausted: cumulative {total} bits "
                f"> budget {steer_budget} (debit {debit} at this branch)",
                node_index=index,
            )

        # (e) execute the chosen arm. The condition's *value* selects the arm via
        # the SAME selector CHOKE-X certifies with (``selector_for``): exact
        # equality to ``match_value`` when the branch set ``match_enabled``, else
        # Python truthiness (then-arm iff truthy). The output_domain bounds
        # *capacity* (how many bits the choice can carry) but does NOT redefine
        # the selector — so a truthiness branch with a 2-element domain like
        # ("yes","no") sends BOTH non-empty strings to the then-arm; a branch that
        # needs ("refund","no_refund") to split both arms sets ``match_enabled``.
        # The chosen arm's values inherit the condition's UNTRUSTED taint
        # (taint propagation). Selecting the arm here reads the realized value;
        # for a high-stakes branch this happens ONLY AFTER CHOKE-X endorsement
        # above (which read only the domain), preserving transparent endorsement.
        chosen_arm = selector_for(node)(cond_value.value, {})
        chosen = node.then_nodes if chosen_arm == "then" else node.else_nodes
        self._exec_nodes(
            chosen,
            env,
            domains=domains,
            ledger=ledger,
            taint=cond_value,
            steer_budget=steer_budget,
            grant=grant,
        )
        return None, TraceEntry(
            node_index=index,
            op="Branch",
            target=node.cond_var,
            cap_level=cond_value.level.name,
            sources=tuple(sorted(cond_value.caps.sources)),
            note=(
                f"arm={chosen_arm} "
                f"debit={debit} cum={total}"
            ),
        )

    def _exec_nodes(
        self,
        nodes: tuple[PlanNode, ...],
        env: dict[str, CapValue],
        *,
        domains: dict[str, tuple | None],
        ledger: CfiLedger,
        taint: CapValue,
        steer_budget: float = float("inf"),
        grant: "CapabilityGrant | None" = None,
    ) -> None:
        """Execute a Branch arm's node list against the shared env.

        Every value the arm BINDS (Assign/Call/QLLM result) is re-derived to
        carry ``taint`` (the condition value's caps) — because the existence of
        that binding is conditioned on the untrusted control-flow decision.
        This is the taint-propagation leg: an UNTRUSTED condition spreads its
        UNTRUSTED level into everything its chosen arm produces."""
        for j, sub in enumerate(nodes):
            # Nested Returns are rejected by validate_structure; arms only hold
            # Assign/Call/QLLM/Branch. Reuse _step, then taint the binding this
            # sub-node produced (new or overwritten) with the condition's caps —
            # its existence/value is control-flow-dependent on the untrusted
            # condition. A nested Branch has no direct binding to taint here;
            # its own _step_branch already taints its chosen arm's bindings.
            before = set(env)
            _value, _entry = self._step(
                j,
                sub,
                env,
                domains=domains,
                ledger=ledger,
                steer_budget=steer_budget,
                grant=grant,
            )
            new_names = set(env) - before
            target = getattr(sub, "result_var", None) or getattr(sub, "name", None)
            tainted = set(new_names)
            if target is not None and target in env:
                tainted.add(target)
            for name in tainted:
                env[name] = CapValue.derived(
                    env[name].value, from_values=(env[name], taint)
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

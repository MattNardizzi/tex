"""CFI-BUDGET: metered ``Branch`` node + cumulative control-flow-influence.

The CaMeL static->dynamic swap. Classic CaMeL forbids untrusted-influenced
control flow by construction. ``Branch`` replaces that binary floor with a
capacity-priced, cumulative, fail-closed-to-ABSTAIN dynamic model:

  price(branch) = log2(len(output_domain)) * scope_symmetric_difference(arms)

These tests are falsifiable per the iteration spec:
 (1) capacity-priced: yes/no domain feeding a Branch debits exactly
     log2(2)=1 * sink_weight bits and runs the chosen arm.
 (2) fail-closed-on-untyped: a Branch whose condition node declared NO
     output_domain HALTS fail-closed (risk 1.0).
 (3) cumulative-ABSTAIN: multiple branches exhausting the hardcoded budget
     resolve to ABSTAIN at the over-budget branch (cumulative, not per-branch).
 (4) out-of-domain produced value HALTS.
 (5) existing straight-line plans (no Branch) behave identically.
"""

from __future__ import annotations

import math

import pytest

from tex.camel import (
    Assign,
    Branch,
    Call,
    CapabilityLevel,
    CamelInterpreter,
    CapValue,
    CfiLedger,
    Literal,
    Plan,
    PlanError,
    QLLM,
    Read,
    Return,
    ToolPolicy,
    ToolPolicyRegistry,
    Var,
    cfi_influence_bits,
    scope_symmetric_difference,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _frozen_registry(*policies: ToolPolicy) -> ToolPolicyRegistry:
    reg = ToolPolicyRegistry()
    for p in policies:
        reg.register(p)
    return reg.freeze()


class _FixedQLLM:
    """Deterministic Q-LLM returning a preset answer (so we can drive the
    Branch condition value precisely)."""

    def __init__(self, answer: str) -> None:
        self._answer = answer

    def answer(self, query: str, inputs: tuple[str, ...]) -> str:  # noqa: ARG002
        return self._answer


def _tool_reg() -> ToolPolicyRegistry:
    return _frozen_registry(
        ToolPolicy(tool_name="send_email", max_arg_levels=(CapabilityLevel.UNTRUSTED,)),
        ToolPolicy(tool_name="log", max_arg_levels=(CapabilityLevel.UNTRUSTED,)),
        ToolPolicy(tool_name="archive", max_arg_levels=(CapabilityLevel.UNTRUSTED,)),
    )


def _tool_impls() -> dict:
    return {
        "send_email": lambda *a: CapValue.derived("emailed", from_values=a),
        "log": lambda *a: CapValue.derived("logged", from_values=a),
        "archive": lambda *a: CapValue.derived("archived", from_values=a),
    }


# ---------------------------------------------------------------------------
# Pure pricing functions
# ---------------------------------------------------------------------------


def test_cfi_influence_bits_yes_no_one_bit_per_sink():
    assert cfi_influence_bits(("yes", "no"), 1) == 1.0
    assert cfi_influence_bits(("yes", "no"), 2) == 2.0


def test_cfi_influence_bits_singleton_domain_is_zero():
    # A deterministic (1-valued) condition cannot steer: log2(1) == 0.
    assert cfi_influence_bits(("only",), 99) == 0.0


def test_cfi_influence_bits_four_value_domain_two_bits():
    assert cfi_influence_bits(("a", "b", "c", "d"), 1) == 2.0


def test_cfi_influence_bits_rejects_empty_domain():
    with pytest.raises(ValueError):
        cfi_influence_bits((), 1)


def test_cfi_influence_bits_rejects_negative_sink():
    with pytest.raises(ValueError):
        cfi_influence_bits(("a", "b"), -1)


def test_scope_symmetric_difference_disjoint_arms():
    then_arm = (Call(tool="send_email", args=(), result_var="r"),)
    else_arm = (Call(tool="archive", args=(), result_var="r"),)
    # send_email XOR archive = {send_email, archive} -> 2
    assert scope_symmetric_difference(then_arm, else_arm) == 2


def test_scope_symmetric_difference_shared_tools_cancel():
    then_arm = (Call(tool="log", args=(), result_var="r"),)
    else_arm = (Call(tool="log", args=(), result_var="r"),)
    # identical scopes -> symmetric difference empty -> 0 (selects nothing)
    assert scope_symmetric_difference(then_arm, else_arm) == 0


def test_scope_symmetric_difference_descends_nested_branches():
    inner = Branch(
        cond_var="x",
        then_nodes=(Call(tool="send_email", args=(), result_var="r"),),
        else_nodes=(),
    )
    then_arm = (inner,)
    else_arm = (Call(tool="archive", args=(), result_var="r"),)
    # reachable: {send_email} XOR {archive} = 2
    assert scope_symmetric_difference(then_arm, else_arm) == 2


# ---------------------------------------------------------------------------
# Hash-chained ledger
# ---------------------------------------------------------------------------


def test_cfi_ledger_cumulative_and_chained():
    led = CfiLedger()
    assert led.total_bits == 0.0
    assert led.append(1.0) == 1.0
    assert led.append(2.0) == 3.0
    assert led.total_bits == 3.0
    assert led.verify() is True
    assert led.entries[1].prev_hash == led.entries[0].entry_hash


def test_cfi_ledger_tamper_breaks_chain():
    led = CfiLedger()
    led.append(1.0)
    led.append(2.0)
    # Retroactively edit a past debit -> chain no longer verifies.
    led._entries[0] = led._entries[0].model_copy(update={"debit_bits": 99.0})
    assert led.verify() is False


def test_cfi_ledger_rejects_negative_debit():
    led = CfiLedger()
    with pytest.raises(ValueError):
        led.append(-0.5)


# ---------------------------------------------------------------------------
# (1) capacity-priced branch
# ---------------------------------------------------------------------------


def test_branch_capacity_priced_exact_bits():
    """yes/no domain + sink_weight 2 (disjoint arms) debits exactly 1*2 = 2."""
    interp = CamelInterpreter(
        tool_policies=_tool_reg(),
        tool_impls=_tool_impls(),
        q_llm=_FixedQLLM("yes"),
        untrusted_env={"email_body": "please decide"},
    )
    plan = Plan(
        nodes=(
            Assign(name="msg", expr=Read(source="email_body")),
            QLLM(
                query="urgent?",
                inputs=(Var(name="msg"),),
                result_var="decision",
                output_domain=("yes", "no"),
            ),
            Branch(
                cond_var="decision",
                then_nodes=(Call(tool="send_email", args=(Var(name="msg"),), result_var="r"),),
                else_nodes=(Call(tool="archive", args=(Var(name="msg"),), result_var="r"),),
            ),
            Return(expr=Var(name="r")),
        )
    )
    final, trace = interp.run(plan)
    assert trace.halted is False
    assert trace.abstained is False
    # log2(2) * 2 = 2.0 bits
    assert trace.cfi_bits_spent == 2.0
    # "yes" is truthy -> then arm executed -> send_email ran
    assert final.value == "emailed"


def test_branch_zero_cost_when_arms_share_scope():
    """Arms with identical tool scope select nothing side-effecting: 0 bits."""
    interp = CamelInterpreter(
        tool_policies=_tool_reg(),
        tool_impls=_tool_impls(),
        q_llm=_FixedQLLM("no"),
        untrusted_env={"email_body": "x"},
    )
    plan = Plan(
        nodes=(
            Assign(name="msg", expr=Read(source="email_body")),
            QLLM(
                query="q",
                inputs=(Var(name="msg"),),
                result_var="d",
                output_domain=("yes", "no"),
            ),
            Branch(
                cond_var="d",
                then_nodes=(Call(tool="log", args=(Var(name="msg"),), result_var="r"),),
                else_nodes=(Call(tool="log", args=(Var(name="msg"),), result_var="r"),),
            ),
            Return(expr=Var(name="r")),
        )
    )
    final, trace = interp.run(plan)
    assert trace.halted is False
    assert trace.cfi_bits_spent == 0.0
    assert final.value == "logged"


def test_branch_taint_propagates_untrusted_into_chosen_arm():
    """The chosen arm's bindings inherit the UNTRUSTED condition taint."""
    interp = CamelInterpreter(
        tool_policies=_tool_reg(),
        tool_impls={"log": lambda *a: CapValue.trusted("clean")},  # tool returns TRUSTED
        q_llm=_FixedQLLM("yes"),
        untrusted_env={"email_body": "tainted"},
    )
    plan = Plan(
        nodes=(
            Assign(name="msg", expr=Read(source="email_body")),
            QLLM(
                query="q",
                inputs=(Var(name="msg"),),
                result_var="d",
                output_domain=("yes", "no"),
            ),
            Branch(
                cond_var="d",
                then_nodes=(Call(tool="log", args=(Var(name="msg"),), result_var="r"),),
                else_nodes=(),
            ),
            Return(expr=Var(name="r")),
        )
    )
    final, trace = interp.run(plan)
    assert trace.halted is False
    # Even though the tool returned a TRUSTED value, the binding is control-flow
    # dependent on the UNTRUSTED Q-LLM decision -> the result is UNTRUSTED.
    assert final.is_untrusted


# ---------------------------------------------------------------------------
# (2) fail-closed on untyped condition
# ---------------------------------------------------------------------------


def test_branch_untyped_condition_halts_fail_closed():
    """A Branch whose condition node declared NO output_domain HALTS, risk 1.0."""
    interp = CamelInterpreter(
        tool_policies=_tool_reg(),
        tool_impls=_tool_impls(),
        q_llm=_FixedQLLM("yes"),
        untrusted_env={"email_body": "x"},
    )
    plan = Plan(
        nodes=(
            Assign(name="msg", expr=Read(source="email_body")),
            QLLM(
                query="q",
                inputs=(Var(name="msg"),),
                result_var="d",
                # NO output_domain -> unbounded capacity
            ),
            Branch(
                cond_var="d",
                then_nodes=(Call(tool="send_email", args=(Var(name="msg"),), result_var="r"),),
                else_nodes=(Call(tool="archive", args=(Var(name="msg"),), result_var="r"),),
            ),
            Return(expr=Var(name="r")),
        )
    )
    final, trace = interp.run(plan)
    assert trace.halted is True
    assert trace.risk == 1.0
    assert "output_domain" in (trace.halt_reason or "")
    # fail-closed: final value is empty + untrusted
    assert final.value is None
    assert final.is_untrusted


def test_branch_on_plain_assign_condition_halts():
    """A Branch on a Literal/Read-assigned var with no domain also fail-closes."""
    interp = CamelInterpreter(
        tool_policies=_tool_reg(),
        tool_impls=_tool_impls(),
        untrusted_env={"email_body": "x"},
    )
    plan = Plan(
        nodes=(
            Assign(name="d", expr=Read(source="email_body")),  # no output_domain
            Branch(
                cond_var="d",
                then_nodes=(Call(tool="log", args=(Var(name="d"),), result_var="r"),),
                else_nodes=(),
            ),
            Return(expr=Literal(value="done")),
        )
    )
    final, trace = interp.run(plan)
    assert trace.halted is True
    assert trace.risk == 1.0


def test_branch_read_with_output_domain_prices_and_runs():
    """A Read that DOES declare an output_domain may steer a Branch."""
    interp = CamelInterpreter(
        tool_policies=_tool_reg(),
        tool_impls=_tool_impls(),
        untrusted_env={"flag": "no"},
    )
    plan = Plan(
        nodes=(
            Assign(name="d", expr=Read(source="flag", output_domain=("yes", "no"))),
            Branch(
                cond_var="d",
                then_nodes=(Call(tool="send_email", args=(Var(name="d"),), result_var="r"),),
                else_nodes=(Call(tool="archive", args=(Var(name="d"),), result_var="r"),),
            ),
            Return(expr=Var(name="r")),
        )
    )
    final, trace = interp.run(plan)
    assert trace.halted is False
    assert trace.cfi_bits_spent == 2.0  # log2(2) * |{send_email}^{archive}|=2
    # "no" is a non-empty string -> truthy -> the THEN arm runs (send_email).
    # The condition's *value* selects the arm by Python truthiness; the domain
    # only bounds capacity, it does not redefine truthiness.
    assert final.value == "emailed"


# ---------------------------------------------------------------------------
# (3) cumulative ABSTAIN (cumulative across branches, not per-branch)
# ---------------------------------------------------------------------------


def test_cumulative_budget_abstains_at_over_budget_branch():
    """Three branches each priced 1 bit (yes/no, sink 1); budget 2 bits.

    Branch1 cum=1 (<=2, runs), Branch2 cum=2 (<=2, runs), Branch3 cum=3 (>2,
    ABSTAIN). The over-budget branch is skipped; the plan CONTINUES to Return.
    No single branch exceeds the budget -> proves the bound is cumulative.
    """
    interp = CamelInterpreter(
        tool_policies=_tool_reg(),
        tool_impls=_tool_impls(),
        q_llm=_FixedQLLM("yes"),
        untrusted_env={"email_body": "x"},
        steer_budget=2.0,
    )

    def _decide(rv: str) -> QLLM:
        return QLLM(
            query="q",
            inputs=(Var(name="msg"),),
            result_var=rv,
            output_domain=("yes", "no"),
        )

    def _branch(cv: str) -> Branch:
        # sink_weight 1: then reaches {log}, else reaches {} -> XOR = {log} = 1
        return Branch(
            cond_var=cv,
            then_nodes=(Call(tool="log", args=(Var(name="msg"),), result_var="r"),),
            else_nodes=(),
        )

    plan = Plan(
        nodes=(
            Assign(name="msg", expr=Read(source="email_body")),
            _decide("d1"),
            _branch("d1"),
            _decide("d2"),
            _branch("d2"),
            _decide("d3"),
            _branch("d3"),
            Return(expr=Var(name="r")),
        )
    )
    final, trace = interp.run(plan)
    assert trace.halted is False
    assert trace.abstained is True
    assert "budget" in (trace.abstain_reason or "")
    # Ledger debited all three (the over-budget debit is recorded then tripped).
    assert trace.cfi_bits_spent == 3.0
    # risk stays 0.0: ABSTAIN is deliberate, not a fail-closed halt.
    assert trace.risk == 0.0
    # The plan still completed (Return ran) -> long-horizon task continues.
    assert final.value == "logged"


def test_within_budget_all_branches_run():
    """Same shape, budget 3 -> all three branches fit, no ABSTAIN."""
    interp = CamelInterpreter(
        tool_policies=_tool_reg(),
        tool_impls=_tool_impls(),
        q_llm=_FixedQLLM("yes"),
        untrusted_env={"email_body": "x"},
        steer_budget=3.0,
    )

    def _decide(rv: str) -> QLLM:
        return QLLM(query="q", inputs=(Var(name="msg"),), result_var=rv,
                    output_domain=("yes", "no"))

    def _branch(cv: str) -> Branch:
        return Branch(cond_var=cv,
                      then_nodes=(Call(tool="log", args=(Var(name="msg"),), result_var="r"),),
                      else_nodes=())

    plan = Plan(nodes=(
        Assign(name="msg", expr=Read(source="email_body")),
        _decide("d1"), _branch("d1"),
        _decide("d2"), _branch("d2"),
        _decide("d3"), _branch("d3"),
        Return(expr=Var(name="r")),
    ))
    final, trace = interp.run(plan)
    assert trace.abstained is False
    assert trace.cfi_bits_spent == 3.0
    assert final.value == "logged"


# ---------------------------------------------------------------------------
# (4) out-of-domain produced value HALTS
# ---------------------------------------------------------------------------


def test_out_of_domain_value_halts():
    """Q-LLM declares ('yes','no') but emits 'maybe' -> HALT, risk 1.0."""
    interp = CamelInterpreter(
        tool_policies=_tool_reg(),
        tool_impls=_tool_impls(),
        q_llm=_FixedQLLM("maybe"),  # NOT in the declared domain
        untrusted_env={"email_body": "x"},
    )
    plan = Plan(
        nodes=(
            Assign(name="msg", expr=Read(source="email_body")),
            QLLM(query="q", inputs=(Var(name="msg"),), result_var="d",
                 output_domain=("yes", "no")),
            Branch(
                cond_var="d",
                then_nodes=(Call(tool="send_email", args=(Var(name="msg"),), result_var="r"),),
                else_nodes=(Call(tool="archive", args=(Var(name="msg"),), result_var="r"),),
            ),
            Return(expr=Var(name="r")),
        )
    )
    final, trace = interp.run(plan)
    assert trace.halted is True
    assert trace.risk == 1.0
    assert "not in the" in (trace.halt_reason or "")


# ---------------------------------------------------------------------------
# (5) existing straight-line plans behave identically
# ---------------------------------------------------------------------------


def test_straight_line_plan_unaffected_no_debit():
    """A plan with no Branch never debits and behaves exactly as before."""
    interp = CamelInterpreter(
        tool_policies=_tool_reg(),
        tool_impls=_tool_impls(),
        untrusted_env={"email_body": "hello"},
    )
    plan = Plan(
        nodes=(
            Assign(name="msg", expr=Read(source="email_body")),
            Call(tool="log", args=(Var(name="msg"),), result_var="r"),
            Return(expr=Var(name="r")),
        )
    )
    final, trace = interp.run(plan)
    assert trace.halted is False
    assert trace.abstained is False
    assert trace.cfi_bits_spent == 0.0
    assert trace.risk == 0.0
    assert final.value == "logged"
    assert final.is_untrusted


def test_default_steer_budget_is_infinite():
    """With the default (unbounded) budget a Branch never ABSTAINs."""
    interp = CamelInterpreter(
        tool_policies=_tool_reg(),
        tool_impls=_tool_impls(),
        q_llm=_FixedQLLM("yes"),
        untrusted_env={"email_body": "x"},
    )
    plan = Plan(nodes=(
        Assign(name="msg", expr=Read(source="email_body")),
        QLLM(query="q", inputs=(Var(name="msg"),), result_var="d",
             output_domain=("yes", "no")),
        Branch(cond_var="d",
               then_nodes=(Call(tool="send_email", args=(Var(name="msg"),), result_var="r"),),
               else_nodes=()),
        Return(expr=Var(name="r")),
    ))
    final, trace = interp.run(plan)
    assert trace.abstained is False
    assert trace.halted is False


# ---------------------------------------------------------------------------
# Structure validation
# ---------------------------------------------------------------------------


def test_validate_rejects_return_inside_branch_arm():
    plan = Plan(
        nodes=(
            Assign(name="d", expr=Read(source="flag", output_domain=("yes", "no"))),
            Branch(
                cond_var="d",
                then_nodes=(Return(expr=Literal(value="early")),),
                else_nodes=(),
            ),
            Return(expr=Literal(value="ok")),
        )
    )
    with pytest.raises(PlanError):
        plan.validate_structure()


def test_validate_accepts_branch_then_top_level_return():
    plan = Plan(
        nodes=(
            Assign(name="d", expr=Read(source="flag", output_domain=("yes", "no"))),
            Branch(
                cond_var="d",
                then_nodes=(Call(tool="log", args=(Var(name="d"),), result_var="r"),),
                else_nodes=(),
            ),
            Return(expr=Literal(value="ok")),
        )
    )
    plan.validate_structure()  # no raise


def test_unbound_branch_condition_halts():
    interp = CamelInterpreter(tool_policies=_tool_reg(), tool_impls=_tool_impls())
    plan = Plan(
        nodes=(
            Branch(cond_var="ghost", then_nodes=(), else_nodes=()),
            Return(expr=Literal(value="ok")),
        )
    )
    final, trace = interp.run(plan)
    assert trace.halted is True
    assert "unbound" in (trace.halt_reason or "")

"""CHOKE-X: per-branch attacker-leverage certifier on the high-stakes ``Branch``.

CFI-BUDGET (``test_cfi_branch.py``) bounds CUMULATIVE control-flow influence with
a flat per-branch charge — which admits a single high-leverage flip: one in-budget
branch can still commit an irreversible arm under direct attacker control. CHOKE-X
certifies, per HIGH-STAKES branch, BEFORE execution, how many distinct arms an
attacker can steer to by varying the untrusted value over its signed domain:

  certified_bits = log2(#distinct arms selected across the whole untrusted domain)

These tests are falsifiable per the iter-4 spec:
 (1) 2-safety steer -> ABSTAIN: refund guard over {refund,no_refund}, budget_bits=0,
     effect_class=irreversible -> varying the untrusted value flips the arm (2
     distinct) -> certified 1 bit > 0 -> ABSTAIN, refund/irreversible arm NOT run.
 (2) invariant guard -> ENDORSE+execute: a guard whose committed arm is the SAME
     for all untrusted values -> certified 0 bits -> within budget -> executes.
 (3) non-decidable high-stakes -> ABSTAIN: a high-stakes branch whose guard has no
     finite enumerable signed domain -> ABSTAIN, never sample-and-commit.
 (4) budget>0 allows bounded leverage: reversible branch, budget_bits>=1, 2 arms =
     1 bit certified <= budget -> executes.
 (5) non-high-stakes iter-3 branches unchanged (no CHOKE-X gate).

Plus pure-certifier 2-safety tests + the transparent-endorsement property (the
endorsement decision never reads the realized untrusted value).
"""

from __future__ import annotations

import pytest

from tex.camel import (
    Assign,
    Branch,
    Call,
    CapabilityLevel,
    CamelInterpreter,
    CapValue,
    Literal,
    NonDecidableGuard,
    Plan,
    QLLM,
    Read,
    Return,
    ToolPolicy,
    ToolPolicyRegistry,
    Var,
    certify_leverage,
)
from tex.camel.branch_leverage import (
    make_match_selector,
    selector_for,
    truthiness_selector,
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
    """Deterministic Q-LLM returning a preset answer (drives the realized value)."""

    def __init__(self, answer: str) -> None:
        self._answer = answer

    def answer(self, query: str, inputs: tuple[str, ...]) -> str:  # noqa: ARG002
        return self._answer


def _tool_reg() -> ToolPolicyRegistry:
    return _frozen_registry(
        ToolPolicy(tool_name="issue_refund", max_arg_levels=(CapabilityLevel.UNTRUSTED,)),
        ToolPolicy(tool_name="log", max_arg_levels=(CapabilityLevel.UNTRUSTED,)),
        ToolPolicy(tool_name="archive", max_arg_levels=(CapabilityLevel.UNTRUSTED,)),
        ToolPolicy(tool_name="send_email", max_arg_levels=(CapabilityLevel.UNTRUSTED,)),
    )


def _refund_tool_impls(sink: list) -> dict:
    """Tools that RECORD their firing into ``sink`` so a test can prove the
    irreversible arm did or did NOT actually commit."""
    def _mk(name):
        def _fn(*a):
            sink.append(name)
            return CapValue.derived(f"{name}-done", from_values=a)
        return _fn
    return {n: _mk(n) for n in ("issue_refund", "log", "archive", "send_email")}


# ===========================================================================
# Pure certifier — 2-safety self-composition
# ===========================================================================


def test_certify_truthiness_invariant_domain_is_zero_bits():
    """Both 'yes' and 'no' are truthy -> truthiness sends BOTH to 'then' -> the
    attacker cannot steer this guard -> 0 distinct arms-of-variation -> 0 bits."""
    b = Branch(cond_var="d")  # default truthiness selector, non-high-stakes shape
    assert certify_leverage(b, ("yes", "no")) == 0.0


def test_certify_truthiness_falsy_split_is_one_bit():
    """A truthiness guard over ('send','') splits: 'send'->then, ''->else -> 2
    distinct arms -> log2(2) = 1 bit of certified leverage."""
    b = Branch(cond_var="d")
    assert certify_leverage(b, ("send", "")) == 1.0


def test_certify_match_value_refund_domain_is_one_bit():
    """Refund guard: then-arm fires iff value == 'refund'. Over {refund,no_refund}
    that splits both arms -> 2 distinct -> 1 bit. This is the 2-safety property:
    varying the untrusted value flips the public control-flow decision."""
    b = Branch(cond_var="d", match_enabled=True, match_value="refund")
    assert certify_leverage(b, ("refund", "no_refund")) == 1.0


def test_certify_match_value_invariant_when_target_absent():
    """If the match target is NOT in the domain, EVERY value selects 'else' ->
    invariant -> 0 bits (the attacker cannot reach the then-arm at all)."""
    b = Branch(cond_var="d", match_enabled=True, match_value="refund")
    assert certify_leverage(b, ("hold", "deny")) == 0.0


def test_certify_four_arm_match_is_log2_distinct():
    """A custom selector with 4 distinct arms over a 4-value domain -> log2(4)=2."""
    b = Branch(cond_var="d")
    sel = lambda v, env: f"arm_{v}"  # noqa: E731 — every value its own arm
    assert certify_leverage(b, ("a", "b", "c", "d"), arm_selector=sel) == 2.0


def test_certify_rejects_empty_domain():
    b = Branch(cond_var="d")
    with pytest.raises(ValueError):
        certify_leverage(b, ())


def test_certify_none_domain_is_non_decidable():
    """No finite enumerable signed domain -> NonDecidableGuard (interpreter ->
    ABSTAIN). The certifier refuses to invent a bound it cannot prove."""
    b = Branch(cond_var="d", budget_bits=0)
    with pytest.raises(NonDecidableGuard):
        certify_leverage(b, None)


def test_selector_for_matches_interpreter_selection():
    """The certifier's selector is IDENTICAL to the interpreter's (soundness)."""
    truthy = Branch(cond_var="d")
    assert selector_for(truthy) is truthiness_selector
    matchb = Branch(cond_var="d", match_enabled=True, match_value="refund")
    sel = selector_for(matchb)
    assert sel("refund", {}) == "then"
    assert sel("no_refund", {}) == "else"


# ===========================================================================
# Transparent endorsement (Cecchetti-Myers): the decision never reads the
# single realized untrusted value.
# ===========================================================================


def test_transparent_endorsement_independent_of_realized_value():
    """certify_leverage is a function of the DOMAIN only: the certified bits are
    the SAME regardless of which realized value an attacker actually supplies.
    (If endorsement read the realized value, these could differ.)"""
    b = Branch(cond_var="d", match_enabled=True, match_value="refund")
    # Same domain -> same certificate, whatever the 'realized' pick would be.
    assert certify_leverage(b, ("refund", "no_refund")) == 1.0
    assert certify_leverage(b, ("no_refund", "refund")) == 1.0  # order-invariant


def test_transparent_endorsement_selector_ignores_no_realized_value():
    """The selector is invoked ONLY over the abstract domain inside the certifier;
    a poisoned 'realized value' channel cannot reach the endorsement decision —
    there is no realized-value parameter on the endorsement path at all."""
    captured = []
    def _spy(v, env):
        captured.append(v)
        return "then" if v == "refund" else "else"
    b = Branch(cond_var="d")
    certify_leverage(b, ("refund", "no_refund"), arm_selector=_spy)
    # Exactly the DOMAIN values were inspected — nothing else.
    assert sorted(captured) == ["no_refund", "refund"]


# ===========================================================================
# (1) 2-safety steer -> ABSTAIN, irreversible arm NOT committed
# ===========================================================================


def _refund_plan() -> Plan:
    return Plan(
        nodes=(
            Assign(name="msg", expr=Read(source="ticket")),
            QLLM(
                query="refund?",
                inputs=(Var(name="msg"),),
                result_var="decision",
                output_domain=("refund", "no_refund"),
            ),
            Branch(
                cond_var="decision",
                match_enabled=True,
                match_value="refund",
                budget_bits=0,
                effect_class="irreversible",
                then_nodes=(Call(tool="issue_refund", args=(Var(name="msg"),), result_var="r"),),
                else_nodes=(Call(tool="archive", args=(Var(name="msg"),), result_var="r"),),
            ),
            Return(expr=Literal(value="done")),
        )
    )


def test_refund_steer_abstains_irreversible_arm_not_committed():
    sink: list = []
    interp = CamelInterpreter(
        tool_policies=_tool_reg(),
        tool_impls=_refund_tool_impls(sink),
        q_llm=_FixedQLLM("refund"),  # attacker steers toward the refund arm
        untrusted_env={"ticket": "please refund me"},
    )
    final, trace = interp.run(_refund_plan())
    # certified 1 bit > budget 0 -> ABSTAIN (NOT a halt/FORBID).
    assert trace.abstained is True
    assert trace.halted is False
    assert trace.risk == 0.0
    assert "CHOKE-X" in (trace.abstain_reason or "")
    # The irreversible refund arm did NOT commit — NEITHER arm ran.
    assert "issue_refund" not in sink
    assert "archive" not in sink
    # The plan still completed its straight-line remainder (Return ran).
    assert final.value == "done"


def test_refund_abstains_even_when_attacker_picks_no_refund():
    """Transparent endorsement: the branch ABSTAINs on the DOMAIN's leverage,
    independent of which realized value the attacker actually supplies — even
    'no_refund' (the seemingly-safe arm) does not get committed, because the
    *capacity to steer* is what is over budget, not the realized pick."""
    sink: list = []
    interp = CamelInterpreter(
        tool_policies=_tool_reg(),
        tool_impls=_refund_tool_impls(sink),
        q_llm=_FixedQLLM("no_refund"),
        untrusted_env={"ticket": "no refund needed"},
    )
    final, trace = interp.run(_refund_plan())
    assert trace.abstained is True
    assert sink == []  # neither arm ran
    assert final.value == "done"


# ===========================================================================
# (2) invariant guard -> ENDORSE + execute
# ===========================================================================


def test_invariant_high_stakes_guard_executes():
    """A high-stakes (budget_bits=0) branch gated on a trusted flag that the
    untrusted value cannot change: match target absent from the untrusted domain
    -> every untrusted value selects the SAME arm -> 0 bits <= 0 -> ENDORSED."""
    sink: list = []
    interp = CamelInterpreter(
        tool_policies=_tool_reg(),
        tool_impls=_refund_tool_impls(sink),
        q_llm=_FixedQLLM("review"),
        untrusted_env={"ticket": "x"},
    )
    plan = Plan(
        nodes=(
            Assign(name="msg", expr=Read(source="ticket")),
            QLLM(
                query="q",
                inputs=(Var(name="msg"),),
                result_var="decision",
                # domain never contains 'refund' -> match never fires -> invariant
                output_domain=("review", "escalate"),
            ),
            Branch(
                cond_var="decision",
                match_enabled=True,
                match_value="refund",  # absent from domain -> all -> else
                budget_bits=0,
                effect_class="irreversible",
                then_nodes=(Call(tool="issue_refund", args=(Var(name="msg"),), result_var="r"),),
                else_nodes=(Call(tool="log", args=(Var(name="msg"),), result_var="r"),),
            ),
            Return(expr=Var(name="r")),
        )
    )
    final, trace = interp.run(plan)
    assert trace.halted is False
    assert trace.abstained is False  # 0 bits certified -> ENDORSED
    # The else (log) arm ran; the irreversible refund arm did not.
    assert "log" in sink
    assert "issue_refund" not in sink
    assert final.value == "log-done"


# ===========================================================================
# (3) non-decidable high-stakes guard -> ABSTAIN
# ===========================================================================


def test_non_decidable_high_stakes_abstains():
    """A high-stakes branch whose condition node declared NO finite output_domain
    (free-text / opaque) -> ABSTAIN, never sample-and-commit."""
    sink: list = []
    interp = CamelInterpreter(
        tool_policies=_tool_reg(),
        tool_impls=_refund_tool_impls(sink),
        q_llm=_FixedQLLM("refund"),
        untrusted_env={"ticket": "x"},
    )
    plan = Plan(
        nodes=(
            Assign(name="msg", expr=Read(source="ticket")),
            QLLM(
                query="q",
                inputs=(Var(name="msg"),),
                result_var="decision",
                # NO output_domain -> free-text / unbounded capacity
            ),
            Branch(
                cond_var="decision",
                budget_bits=0,
                effect_class="irreversible",
                then_nodes=(Call(tool="issue_refund", args=(Var(name="msg"),), result_var="r"),),
                else_nodes=(),
            ),
            Return(expr=Literal(value="done")),
        )
    )
    final, trace = interp.run(plan)
    # High-stakes + non-decidable guard -> ABSTAIN (NOT the iter-3 fail-closed HALT).
    assert trace.abstained is True
    assert trace.halted is False
    assert "non-decidable" in (trace.abstain_reason or "")
    assert sink == []  # never sampled-and-committed
    assert final.value == "done"


def test_non_high_stakes_untyped_still_halts_iter3_behavior():
    """CONTRAST: a NON-high-stakes branch with an untyped condition keeps the
    iter-3 fail-closed HALT (not ABSTAIN). Proves CHOKE-X only changes the
    high-stakes path."""
    interp = CamelInterpreter(
        tool_policies=_tool_reg(),
        tool_impls=_refund_tool_impls([]),
        q_llm=_FixedQLLM("refund"),
        untrusted_env={"ticket": "x"},
    )
    plan = Plan(
        nodes=(
            Assign(name="msg", expr=Read(source="ticket")),
            QLLM(query="q", inputs=(Var(name="msg"),), result_var="decision"),  # untyped
            Branch(  # default: NOT high-stakes (reversible, unmetered budget)
                cond_var="decision",
                then_nodes=(Call(tool="log", args=(Var(name="msg"),), result_var="r"),),
                else_nodes=(),
            ),
            Return(expr=Literal(value="done")),
        )
    )
    final, trace = interp.run(plan)
    assert trace.halted is True
    assert trace.abstained is False
    assert trace.risk == 1.0


# ===========================================================================
# (4) budget>0 allows bounded leverage
# ===========================================================================


def test_budget_one_bit_reversible_executes():
    """A reversible branch with budget_bits=1 and a 2-arm split (1 bit certified)
    is WITHIN budget -> ENDORSED + executes the realized arm."""
    sink: list = []
    interp = CamelInterpreter(
        tool_policies=_tool_reg(),
        tool_impls=_refund_tool_impls(sink),
        q_llm=_FixedQLLM("refund"),
        untrusted_env={"ticket": "x"},
    )
    plan = Plan(
        nodes=(
            Assign(name="msg", expr=Read(source="ticket")),
            QLLM(
                query="q",
                inputs=(Var(name="msg"),),
                result_var="decision",
                output_domain=("refund", "no_refund"),
            ),
            Branch(
                cond_var="decision",
                match_enabled=True,
                match_value="refund",
                budget_bits=1,            # 1 bit tolerated
                effect_class="reversible",  # high-stakes ONLY via budget==0; here budget=1
                then_nodes=(Call(tool="send_email", args=(Var(name="msg"),), result_var="r"),),
                else_nodes=(Call(tool="archive", args=(Var(name="msg"),), result_var="r"),),
            ),
            Return(expr=Var(name="r")),
        )
    )
    final, trace = interp.run(plan)
    # budget_bits=1 and reversible -> NOT high-stakes -> no CHOKE-X gate at all;
    # classic CFI runs the realized 'refund'->then arm.
    assert trace.abstained is False
    assert trace.halted is False
    assert "send_email" in sink
    assert final.value == "send_email-done"


def test_budget_one_bit_irreversible_high_stakes_within_budget_executes():
    """Same 1-bit leverage but effect_class=irreversible -> high-stakes -> CHOKE-X
    DOES gate it; certified 1 bit <= budget 1 -> still ENDORSED + executes."""
    sink: list = []
    interp = CamelInterpreter(
        tool_policies=_tool_reg(),
        tool_impls=_refund_tool_impls(sink),
        q_llm=_FixedQLLM("refund"),
        untrusted_env={"ticket": "x"},
    )
    plan = Plan(
        nodes=(
            Assign(name="msg", expr=Read(source="ticket")),
            QLLM(query="q", inputs=(Var(name="msg"),), result_var="decision",
                 output_domain=("refund", "no_refund")),
            Branch(
                cond_var="decision",
                match_enabled=True,
                match_value="refund",
                budget_bits=1,
                effect_class="irreversible",  # high-stakes -> CHOKE-X gates
                then_nodes=(Call(tool="issue_refund", args=(Var(name="msg"),), result_var="r"),),
                else_nodes=(Call(tool="archive", args=(Var(name="msg"),), result_var="r"),),
            ),
            Return(expr=Var(name="r")),
        )
    )
    final, trace = interp.run(plan)
    assert trace.abstained is False  # 1 bit <= budget 1 -> endorsed
    assert "issue_refund" in sink    # the realized 'refund' arm committed
    assert final.value == "issue_refund-done"


def test_budget_one_bit_irreversible_over_budget_abstains():
    """Mutation guard: drop the budget to 0 on the SAME irreversible 1-bit branch
    -> over budget -> ABSTAIN. Proves the budget comparison is load-bearing."""
    sink: list = []
    interp = CamelInterpreter(
        tool_policies=_tool_reg(),
        tool_impls=_refund_tool_impls(sink),
        q_llm=_FixedQLLM("refund"),
        untrusted_env={"ticket": "x"},
    )
    plan = Plan(
        nodes=(
            Assign(name="msg", expr=Read(source="ticket")),
            QLLM(query="q", inputs=(Var(name="msg"),), result_var="decision",
                 output_domain=("refund", "no_refund")),
            Branch(
                cond_var="decision",
                match_enabled=True,
                match_value="refund",
                budget_bits=0,  # <- the only change vs the test above
                effect_class="irreversible",
                then_nodes=(Call(tool="issue_refund", args=(Var(name="msg"),), result_var="r"),),
                else_nodes=(Call(tool="archive", args=(Var(name="msg"),), result_var="r"),),
            ),
            Return(expr=Literal(value="done")),
        )
    )
    final, trace = interp.run(plan)
    assert trace.abstained is True
    assert sink == []
    assert final.value == "done"


# ===========================================================================
# (5) non-high-stakes iter-3 branches are unchanged (no CHOKE-X)
# ===========================================================================


def test_default_branch_not_high_stakes_no_choke_gate():
    """A default Branch (unmetered budget, reversible) is NOT high-stakes -> no
    CHOKE-X certification -> identical iter-3 classic-CFI behavior."""
    b = Branch(cond_var="d")
    assert b.is_high_stakes is False
    sink: list = []
    interp = CamelInterpreter(
        tool_policies=_tool_reg(),
        tool_impls=_refund_tool_impls(sink),
        q_llm=_FixedQLLM("yes"),
        untrusted_env={"ticket": "x"},
    )
    plan = Plan(
        nodes=(
            Assign(name="msg", expr=Read(source="ticket")),
            QLLM(query="q", inputs=(Var(name="msg"),), result_var="d",
                 output_domain=("yes", "no")),
            Branch(  # default -> not high-stakes; truthiness selector; classic CFI
                cond_var="d",
                then_nodes=(Call(tool="log", args=(Var(name="msg"),), result_var="r"),),
                else_nodes=(Call(tool="archive", args=(Var(name="msg"),), result_var="r"),),
            ),
            Return(expr=Var(name="r")),
        )
    )
    final, trace = interp.run(plan)
    assert trace.abstained is False
    assert trace.halted is False
    # 'yes' truthy -> then (log) runs; CFI priced it (log2(2)*2 = 2 bits).
    assert "log" in sink
    assert trace.cfi_bits_spent == 2.0


def test_is_high_stakes_flags():
    assert Branch(cond_var="d").is_high_stakes is False
    assert Branch(cond_var="d", budget_bits=0).is_high_stakes is True
    assert Branch(cond_var="d", effect_class="irreversible").is_high_stakes is True
    assert Branch(cond_var="d", budget_bits=5, effect_class="reversible").is_high_stakes is False

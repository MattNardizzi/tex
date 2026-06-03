"""
Tests for tex.contracts.runtime_enforcement.ContractEnforcer.

Coverage:
  * check_pre / check_post return (is_satisfied, violated_ids)
  * agent_id wildcard
  * event_kind filtering
  * hard violation -> is_satisfied False, severity from contract
  * soft violation -> is_satisfied stays True, "warn" severity, deadline armed
  * postcondition (legacy field) evaluated only on check_post
  * compliance_scores computes ABC §3.6 C_hard / C_soft
  * reliability_index Θ stays in [0, 1]
  * malformed wiring (ledger without provenance) rejected
"""

from __future__ import annotations

import pytest

from tex.contracts import (
    BehavioralContract,
    ContractEnforcer,
    ContractViolation,
)
from tests.contracts.conftest import make_event, make_state


# ---------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------


class TestConstruction:
    def test_rejects_empty_contracts(self) -> None:
        with pytest.raises(ValueError):
            ContractEnforcer(contracts=())

    def test_rejects_duplicate_contract_ids(self) -> None:
        c1 = BehavioralContract.make(
            contract_id="dup", agent_id="alice", description="a"
        )
        c2 = BehavioralContract.make(
            contract_id="dup", agent_id="bob", description="b"
        )
        with pytest.raises(ValueError):
            ContractEnforcer(contracts=(c1, c2))

    def test_rejects_partial_ledger_wiring(self) -> None:
        c = BehavioralContract.make(
            contract_id="c1", agent_id="alice", description="x"
        )
        with pytest.raises(ValueError):
            ContractEnforcer(contracts=(c,), ledger=object())  # no provenance


# ---------------------------------------------------------------------
# Pre-check semantics
# ---------------------------------------------------------------------


class TestCheckPre:
    def test_passes_when_all_satisfied(self) -> None:
        c = BehavioralContract.make(
            contract_id="c-pii",
            agent_id="alice",
            description="no PII",
            hard_invariants_ltl=("G (field:output.pii==false)",),
            covered_event_kinds=("agent_emits_output",),
        )
        e = ContractEnforcer(contracts=(c,))
        ok, ids = e.check_pre(
            agent_id="alice",
            proposed_event=make_event(payload={"output": {"pii": False}}),
            current_state=make_state(),
        )
        assert ok is True
        assert ids == ()
        assert len(e.violations) == 0

    def test_fails_on_hard_violation(self) -> None:
        c = BehavioralContract.make(
            contract_id="c-pii",
            agent_id="alice",
            description="no PII",
            hard_invariants_ltl=("G (field:output.pii==false)",),
            covered_event_kinds=("agent_emits_output",),
            severity_on_violation="block",
        )
        e = ContractEnforcer(contracts=(c,))
        ok, ids = e.check_pre(
            agent_id="alice",
            proposed_event=make_event(payload={"output": {"pii": True}}),
            current_state=make_state(),
        )
        assert ok is False
        assert ids == ("c-pii",)
        assert len(e.violations) == 1
        v: ContractViolation = e.violations[0]
        assert v.violated_clause == "hard_invariant"
        assert v.severity == "block"
        assert v.recovery_deadline_step is None  # hard, no deadline

    def test_filters_by_agent_id(self) -> None:
        c = BehavioralContract.make(
            contract_id="c-alice",
            agent_id="alice",
            description="alice only",
            hard_invariants_ltl=("G (field:output.pii==false)",),
        )
        e = ContractEnforcer(contracts=(c,))
        # Bob can leak PII because the contract only covers Alice.
        ok, ids = e.check_pre(
            agent_id="bob",
            proposed_event=make_event(payload={"output": {"pii": True}}),
            current_state=make_state(),
        )
        assert ok is True
        assert ids == ()

    def test_wildcard_agent_id(self) -> None:
        c = BehavioralContract.make(
            contract_id="c-all",
            agent_id="*",
            description="cross-agent",
            hard_invariants_ltl=("G (field:output.pii==false)",),
        )
        e = ContractEnforcer(contracts=(c,))
        ok, _ = e.check_pre(
            agent_id="bob",
            proposed_event=make_event(payload={"output": {"pii": True}}),
            current_state=make_state(),
        )
        assert ok is False  # contract DID apply to bob

    def test_filters_by_event_kind(self) -> None:
        c = BehavioralContract.make(
            contract_id="c-tool",
            agent_id="alice",
            description="tool only",
            hard_invariants_ltl=("G (field:tool_id!=delete)",),
            covered_event_kinds=("agent_invokes_tool",),
        )
        e = ContractEnforcer(contracts=(c,))
        # Wrong event kind -> not evaluated.
        ok, _ = e.check_pre(
            agent_id="alice",
            proposed_event=make_event(
                kind="agent_emits_output", payload={"tool_id": "delete"}
            ),
            current_state=make_state(),
        )
        assert ok is True

    def test_precondition_evaluated_on_pre_only(self) -> None:
        c = BehavioralContract.make(
            contract_id="c-pre",
            agent_id="alice",
            description="needs policy v3",
            precondition_ltl="state:active_governance_graph_id==policy-v3",
        )
        e = ContractEnforcer(contracts=(c,))
        ok, _ = e.check_pre(
            agent_id="alice",
            proposed_event=make_event(),
            current_state=make_state(governance_graph_id="policy-v1"),
        )
        assert ok is False
        # Same scenario but post-check -> precondition NOT evaluated.
        e2 = ContractEnforcer(contracts=(c,))
        ok2, _ = e2.check_post(
            agent_id="alice",
            executed_event=make_event(),
            new_state=make_state(governance_graph_id="policy-v1"),
        )
        assert ok2 is True


# ---------------------------------------------------------------------
# Post-check semantics
# ---------------------------------------------------------------------


class TestCheckPost:
    def test_postcondition_evaluated_on_post_only(self) -> None:
        c = BehavioralContract.make(
            contract_id="c-post",
            agent_id="alice",
            description="ratio ok after",
            postcondition_ltl="state:sliding_window_compromise_ratio<0.2",
        )
        e = ContractEnforcer(contracts=(c,))
        ok, _ = e.check_post(
            agent_id="alice",
            executed_event=make_event(),
            new_state=make_state(compromise_ratio=0.5),
        )
        assert ok is False

    def test_postcondition_skipped_on_pre(self) -> None:
        c = BehavioralContract.make(
            contract_id="c-post",
            agent_id="alice",
            description="ratio ok after",
            postcondition_ltl="state:sliding_window_compromise_ratio<0.2",
        )
        e = ContractEnforcer(contracts=(c,))
        ok, _ = e.check_pre(
            agent_id="alice",
            proposed_event=make_event(),
            current_state=make_state(compromise_ratio=0.5),
        )
        assert ok is True


# ---------------------------------------------------------------------
# Soft constraints + recovery semantics
# ---------------------------------------------------------------------


class TestSoftRecovery:
    def test_soft_violation_does_not_block(self) -> None:
        c = BehavioralContract.make(
            contract_id="c-tone",
            agent_id="alice",
            description="professional tone",
            soft_invariants_ltl=("G (field:tone==good)",),
            recovery_window_k=2,
        )
        e = ContractEnforcer(contracts=(c,))
        ok, ids = e.check_pre(
            agent_id="alice",
            proposed_event=make_event(payload={"tone": "casual"}),
            current_state=make_state(),
        )
        assert ok is True  # soft violation does NOT clear is_satisfied
        assert ids == ("c-tone",)
        assert len(e.violations) == 1
        v = e.violations[0]
        assert v.violated_clause == "soft_invariant"
        assert v.severity == "warn"
        assert v.recovery_deadline_step is not None
        assert v.recovered_at_step is None
        assert e.pending_soft_recoveries == 1

    def test_soft_violation_recovers_within_window(self) -> None:
        c = BehavioralContract.make(
            contract_id="c-tone",
            agent_id="alice",
            description="professional tone",
            soft_invariants_ltl=("G (field:tone==good)",),
            recovery_window_k=3,
        )
        e = ContractEnforcer(contracts=(c,))
        # Step 1: violation
        e.check_pre(
            agent_id="alice",
            proposed_event=make_event(payload={"tone": "casual"}),
            current_state=make_state(),
        )
        # Step 2: still casual
        e.check_pre(
            agent_id="alice",
            proposed_event=make_event(payload={"tone": "casual"}),
            current_state=make_state(),
        )
        # Step 3: recovers
        e.check_pre(
            agent_id="alice",
            proposed_event=make_event(payload={"tone": "good"}),
            current_state=make_state(),
        )
        assert e.pending_soft_recoveries == 0
        # The original violation should be marked recovered.
        recovered = [v for v in e.violations if v.recovered_at_step is not None]
        assert len(recovered) == 1
        assert recovered[0].recovered_at_step == 3

    def test_soft_violation_escalates_after_deadline(self) -> None:
        c = BehavioralContract.make(
            contract_id="c-tone",
            agent_id="alice",
            description="professional tone",
            soft_invariants_ltl=("G (field:tone==good)",),
            recovery_window_k=1,  # extremely tight
        )
        e = ContractEnforcer(contracts=(c,))
        # Step 1: soft violation, deadline = 2
        e.check_pre(
            agent_id="alice",
            proposed_event=make_event(payload={"tone": "casual"}),
            current_state=make_state(),
        )
        # Step 2: still casual, still in window
        e.check_pre(
            agent_id="alice",
            proposed_event=make_event(payload={"tone": "casual"}),
            current_state=make_state(),
        )
        # Step 3: deadline passed -> sweep emits an escalated record.
        e.check_pre(
            agent_id="alice",
            proposed_event=make_event(payload={"tone": "casual"}),
            current_state=make_state(),
        )
        # We expect at least one escalation record with severity=block.
        escalations = [v for v in e.violations if v.severity == "block"]
        assert len(escalations) >= 1
        assert e.pending_soft_recoveries == 0

    def test_soft_violation_does_not_re_emit_each_step(self) -> None:
        # While a deadline is pending, repeated failures of the same
        # constraint should not produce additional ContractViolation
        # records (matches AgentAssert obligation-token semantics).
        c = BehavioralContract.make(
            contract_id="c-tone",
            agent_id="alice",
            description="professional tone",
            soft_invariants_ltl=("G (field:tone==good)",),
            recovery_window_k=10,
        )
        e = ContractEnforcer(contracts=(c,))
        for _ in range(5):
            e.check_pre(
                agent_id="alice",
                proposed_event=make_event(payload={"tone": "casual"}),
                current_state=make_state(),
            )
        assert len(e.violations) == 1


# ---------------------------------------------------------------------
# ABC compliance scores + Θ
# ---------------------------------------------------------------------


class TestComplianceScores:
    def test_perfect_compliance(self) -> None:
        c = BehavioralContract.make(
            contract_id="c1",
            agent_id="alice",
            description="x",
            hard_invariants_ltl=("G (field:safe==true)",),
            soft_invariants_ltl=("G (field:tone==good)",),
        )
        e = ContractEnforcer(contracts=(c,))
        scores = e.compliance_scores(
            agent_id="alice",
            proposed_event=make_event(payload={"safe": True, "tone": "good"}),
            current_state=make_state(),
        )
        assert scores.c_hard == 1.0
        assert scores.c_soft == 1.0
        assert scores.contracts_evaluated == 1
        assert scores.constraints_evaluated == 2

    def test_partial_compliance(self) -> None:
        c = BehavioralContract.make(
            contract_id="c1",
            agent_id="alice",
            description="x",
            hard_invariants_ltl=(
                "G (field:safe==true)",
                "G (field:authorised==true)",
            ),
            soft_invariants_ltl=("G (field:tone==good)",),
        )
        e = ContractEnforcer(contracts=(c,))
        scores = e.compliance_scores(
            agent_id="alice",
            proposed_event=make_event(
                payload={"safe": True, "authorised": False, "tone": "good"}
            ),
            current_state=make_state(),
        )
        assert scores.c_hard == 0.5  # 1 of 2 hard satisfied
        assert scores.c_soft == 1.0

    def test_compliance_score_does_not_advance_step_index(self) -> None:
        c = BehavioralContract.make(
            contract_id="c1",
            agent_id="alice",
            description="x",
            hard_invariants_ltl=("G (field:safe==true)",),
        )
        e = ContractEnforcer(contracts=(c,))
        before = e.step_index
        e.compliance_scores(
            agent_id="alice",
            proposed_event=make_event(payload={"safe": False}),
            current_state=make_state(),
        )
        assert e.step_index == before
        assert len(e.violations) == 0  # no violations recorded


class TestReliabilityIndex:
    def test_no_history_returns_one(self) -> None:
        c = BehavioralContract.make(
            contract_id="c1", agent_id="alice", description="x"
        )
        e = ContractEnforcer(contracts=(c,))
        assert e.reliability_index() == 1.0

    def test_in_unit_interval(self) -> None:
        c = BehavioralContract.make(
            contract_id="c1",
            agent_id="alice",
            description="x",
            hard_invariants_ltl=("G (field:safe==true)",),
        )
        e = ContractEnforcer(contracts=(c,))
        # Mix of good / bad checks
        for safe in (True, True, False, True, False):
            e.check_pre(
                agent_id="alice",
                proposed_event=make_event(payload={"safe": safe}),
                current_state=make_state(),
            )
        theta = e.reliability_index()
        assert 0.0 <= theta <= 1.0

    def test_weights_must_sum_to_one(self) -> None:
        c = BehavioralContract.make(
            contract_id="c1", agent_id="alice", description="x"
        )
        e = ContractEnforcer(contracts=(c,))
        with pytest.raises(ValueError):
            e.reliability_index(weights=(0.5, 0.5, 0.5, 0.5))

    def test_weights_must_be_in_unit_interval(self) -> None:
        c = BehavioralContract.make(
            contract_id="c1", agent_id="alice", description="x"
        )
        e = ContractEnforcer(contracts=(c,))
        with pytest.raises(ValueError):
            e.reliability_index(weights=(-0.1, 0.4, 0.4, 0.3))


# ---------------------------------------------------------------------
# StepShield-style step indexing
# ---------------------------------------------------------------------


class TestStepIndex:
    def test_step_advances_by_one_per_check(self) -> None:
        c = BehavioralContract.make(
            contract_id="c1",
            agent_id="alice",
            description="x",
            hard_invariants_ltl=("G (field:safe==true)",),
        )
        e = ContractEnforcer(contracts=(c,))
        for _ in range(5):
            e.check_pre(
                agent_id="alice",
                proposed_event=make_event(payload={"safe": True}),
                current_state=make_state(),
            )
        assert e.step_index == 5

    def test_violation_records_step_of_detection(self) -> None:
        c = BehavioralContract.make(
            contract_id="c1",
            agent_id="alice",
            description="x",
            hard_invariants_ltl=("G (field:safe==true)",),
        )
        e = ContractEnforcer(contracts=(c,))
        # Two clean checks, then a violation.
        for safe in (True, True, False):
            e.check_pre(
                agent_id="alice",
                proposed_event=make_event(payload={"safe": safe}),
                current_state=make_state(),
            )
        assert len(e.violations) == 1
        # Detection happened on the third call.
        assert e.violations[0].step_index == 3


# ---------------------------------------------------------------------
# Recovery dispatcher integration
# ---------------------------------------------------------------------


class TestRecoveryDispatcher:
    def test_dispatcher_called_for_soft_violations(self) -> None:
        calls: list[str] = []

        def dispatcher(violation: ContractViolation, _state: object) -> None:
            calls.append(violation.violated_clause)

        c = BehavioralContract.make(
            contract_id="c1",
            agent_id="alice",
            description="x",
            soft_invariants_ltl=("G (field:tone==good)",),
        )
        e = ContractEnforcer(contracts=(c,), recovery_dispatcher=dispatcher)
        e.check_pre(
            agent_id="alice",
            proposed_event=make_event(payload={"tone": "casual"}),
            current_state=make_state(),
        )
        assert calls == ["soft_invariant"]

    def test_dispatcher_called_for_sanction_severity(self) -> None:
        calls: list[str] = []

        def dispatcher(violation: ContractViolation, _state: object) -> None:
            calls.append(violation.violated_clause)

        c = BehavioralContract.make(
            contract_id="c1",
            agent_id="alice",
            description="x",
            hard_invariants_ltl=("G (field:safe==true)",),
            severity_on_violation="sanction",
        )
        e = ContractEnforcer(contracts=(c,), recovery_dispatcher=dispatcher)
        e.check_pre(
            agent_id="alice",
            proposed_event=make_event(payload={"safe": False}),
            current_state=make_state(),
        )
        assert calls == ["hard_invariant"]

    def test_dispatcher_not_called_for_block(self) -> None:
        calls: list[str] = []

        def dispatcher(_v: ContractViolation, _s: object) -> None:
            calls.append("called")

        c = BehavioralContract.make(
            contract_id="c1",
            agent_id="alice",
            description="x",
            hard_invariants_ltl=("G (field:safe==true)",),
            severity_on_violation="block",
        )
        e = ContractEnforcer(contracts=(c,), recovery_dispatcher=dispatcher)
        e.check_pre(
            agent_id="alice",
            proposed_event=make_event(payload={"safe": False}),
            current_state=make_state(),
        )
        assert calls == []

"""
Tests for tex.contracts.contract.BehavioralContract.

Coverage:
  * BehavioralContract.make eagerly parses every LTL string
  * malformed LTL surfaces with the contract id in the error
  * (p, δ, k) parameter validation
  * applies_to wildcard semantics
  * total_constraint_count counts I_hard + I_soft + G_hard + G_soft
"""

from __future__ import annotations

import pytest

from tex.contracts import BehavioralContract, LTLParseError


def _basic(**overrides: object) -> BehavioralContract:
    kwargs: dict[str, object] = dict(
        contract_id="c1",
        agent_id="alice",
        description="test",
    )
    kwargs.update(overrides)
    return BehavioralContract.make(**kwargs)  # type: ignore[arg-type]


class TestEagerParsing:
    def test_makes_simple_contract(self) -> None:
        c = _basic(
            hard_invariants_ltl=("G (field:output.pii==false)",),
            covered_event_kinds=("agent_emits_output",),
        )
        assert c.contract_id == "c1"
        assert c.total_constraint_count() == 1

    def test_make_parses_all_six_field_kinds(self) -> None:
        c = _basic(
            precondition_ltl="state:active_governance_graph_id==policy-v1",
            postcondition_ltl="state:sliding_window_compromise_ratio<0.2",
            hard_invariants_ltl=("G (field:output.pii==false)",),
            soft_invariants_ltl=("G (field:output.tone_score>=0.7)",),
            hard_governance_ltl=("G (kind:agent_invokes_tool implies field:tool_id!=delete)",),
            soft_governance_ltl=("G (field:latency_ms<500)",),
        )
        # Smoke-test parsed_formulas() returns all six populated.
        formulas = c.parsed_formulas()
        assert formulas.precondition is not None
        assert formulas.postcondition is not None
        assert len(formulas.hard_invariants) == 1
        assert len(formulas.soft_invariants) == 1
        assert len(formulas.hard_governance) == 1
        assert len(formulas.soft_governance) == 1

    def test_make_rejects_invalid_ltl(self) -> None:
        with pytest.raises(LTLParseError) as exc:
            _basic(hard_invariants_ltl=("G ((p and q",))
        # Error message includes the contract id for diagnostics.
        assert "c1" in str(exc.value)

    def test_postcondition_disabled_by_true_literal(self) -> None:
        c = _basic(postcondition_ltl="true")
        # 'true' should be parsed-out at construction; parsed_formulas
        # returns None for postcondition.
        assert c.parsed_formulas().postcondition is None

    def test_empty_precondition_string_disables_check(self) -> None:
        c = _basic(precondition_ltl="")
        assert c.parsed_formulas().precondition is None


class TestPDKValidation:
    def test_rejects_delta_outside_zero_one(self) -> None:
        with pytest.raises(ValueError):
            _basic(delta_tolerance=-0.1)
        with pytest.raises(ValueError):
            _basic(delta_tolerance=1.1)

    def test_rejects_p_outside_zero_one(self) -> None:
        with pytest.raises(ValueError):
            _basic(satisfaction_p=1.5)

    def test_rejects_negative_k(self) -> None:
        with pytest.raises(ValueError):
            _basic(recovery_window_k=-1)

    def test_rejects_empty_covered_kinds(self) -> None:
        with pytest.raises(ValueError):
            _basic(covered_event_kinds=())

    def test_accepts_p_zero_and_one(self) -> None:
        # Boundary values should be permitted.
        _basic(satisfaction_p=0.0)
        _basic(satisfaction_p=1.0)


class TestAppliesTo:
    def test_matches_specific_agent_and_kind(self) -> None:
        c = _basic(
            agent_id="alice",
            covered_event_kinds=("agent_emits_output",),
        )
        assert c.applies_to(agent_id="alice", event_kind="agent_emits_output")
        assert not c.applies_to(agent_id="bob", event_kind="agent_emits_output")
        assert not c.applies_to(agent_id="alice", event_kind="agent_invokes_tool")

    def test_wildcard_agent(self) -> None:
        c = _basic(
            agent_id="*",
            covered_event_kinds=("agent_emits_output",),
        )
        assert c.applies_to(agent_id="alice", event_kind="agent_emits_output")
        assert c.applies_to(agent_id="bob", event_kind="agent_emits_output")

    def test_wildcard_kind(self) -> None:
        c = _basic(covered_event_kinds=("*",))
        assert c.applies_to(agent_id="alice", event_kind="any_kind_at_all")


class TestConstraintCount:
    def test_counts_all_four_categories(self) -> None:
        c = _basic(
            hard_invariants_ltl=("true", "true"),
            soft_invariants_ltl=("true",),
            hard_governance_ltl=("true", "true", "true"),
            soft_governance_ltl=("true",),
        )
        assert c.total_constraint_count() == 7

    def test_excludes_pre_and_post(self) -> None:
        c = _basic(
            precondition_ltl="state:active_governance_graph_id==policy-v1",
            postcondition_ltl="state:sliding_window_compromise_ratio<0.2",
            hard_invariants_ltl=("true",),
        )
        # Only the hard invariant counts.
        assert c.total_constraint_count() == 1

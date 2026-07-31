"""Tests for tex.institutional.controller."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

import tex.ecosystem  # noqa: F401  prime ordering

from tex.ecosystem.state import EcosystemState
from tex.institutional import (
    SIGNAL_HIGH_HHI,
    ControllerDecision,
    ControllerOutcome,
    GovernanceController,
    GovernanceGraph,
    GovernanceLog,
    GovernanceOracle,
    OracleCase,
    OracleSignal,
)


FIXTURES_DIR = Path(__file__).parent / "fixtures"
COURNOT_MANIFEST = FIXTURES_DIR / "cournot_market.yaml"


# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------


def _state(*, cv_excess: float = 0.0, hhi_excess: float = 0.0) -> EcosystemState:
    return EcosystemState(
        snapshot_at=datetime.now(UTC),
        state_hash="ctrl_test_hash",
        active_agent_ids=("firm_1", "firm_2"),
        active_tool_ids=(),
        active_capability_ids=(),
        active_governance_graph_id="cournot_market_v1",
        aggregate_drift_signals={
            "cv_excess": cv_excess,
            "hhi_excess": hhi_excess,
        },
    )


def _build_engine(*, with_log: bool = True) -> tuple[
    GovernanceController, GovernanceOracle, GovernanceLog | None
]:
    g = GovernanceGraph.from_yaml(COURNOT_MANIFEST)
    oracle = GovernanceOracle(
        graph=g,
        signals=(OracleSignal(SIGNAL_HIGH_HHI, "hhi_excess", threshold=0.50),),
        rule_id_for_signal={SIGNAL_HIGH_HHI: "P2_independent_decision"},
    )
    log = GovernanceLog(signing_key_id="ctrl-test") if with_log else None
    controller = GovernanceController(oracle=oracle, ledger=log)
    return controller, oracle, log


def _make_case(rule_id: str = "P2_independent_decision") -> OracleCase:
    return OracleCase(
        case_id="case_test_001",
        rule_id=rule_id,
        kind="probable_violation",
        actor_entity_id="firm_1",
        triggered_by_signals=(SIGNAL_HIGH_HHI,),
        evidence={"cv_excess": 0.0, "hhi_excess": 0.6},
        severity_tier=3,
        observed_at=datetime.now(UTC),
        manifest_semantic_sha256="",  # filled in by Oracle in production
    )


# ---------------------------------------------------------------------
# Outcome selection
# ---------------------------------------------------------------------


class TestOutcomeSelection:
    def test_active_probable_violation_yields_sanction(self) -> None:
        controller, _, _ = _build_engine()
        decision = controller.enforce(
            proposed_event_kind="probable_violation",
            actor_entity_id="firm_1",
            current_round=1,
            case=_make_case(),
        )
        assert decision["decision"] == ControllerOutcome.SANCTION.value
        assert decision["sanction_id"] == "warning_notice"
        assert decision["edge_key"] == (
            "P2_independent_decision:active->warning"
        )

    def test_warning_expiry_tick_yields_remediate(self) -> None:
        controller, _, _ = _build_engine()
        controller.set_actor_state("firm_1", "warning")
        decision = controller.enforce(
            proposed_event_kind="expiry_tick",
            actor_entity_id="firm_1",
            current_round=5,
        )
        assert decision["decision"] == ControllerOutcome.REMEDIATE.value
        assert decision["restorative_path_id"] == "warning_expiry"
        assert decision["to_state"] == "active"

    def test_active_clean_round_yields_allow(self) -> None:
        """Self-loop with no sanction and no restorative path -> ALLOW."""
        controller, _, _ = _build_engine()
        decision = controller.enforce(
            proposed_event_kind="clean_round",
            actor_entity_id="firm_1",
            current_round=1,
        )
        assert decision["decision"] == ControllerOutcome.ALLOW.value
        assert decision["sanction_id"] is None
        assert decision["restorative_path_id"] is None

    def test_no_matching_edge_yields_blocked(self) -> None:
        """No manifest-declared edge -> BLOCKED with empty edge_key."""
        controller, _, _ = _build_engine()
        decision = controller.enforce(
            proposed_event_kind="completely_unknown_event",
            actor_entity_id="firm_1",
            current_round=1,
        )
        assert decision["decision"] == ControllerOutcome.BLOCKED.value
        assert decision["edge_key"] == ""
        assert "no manifest-declared edge" in decision["rationale"]

    def test_remediate_takes_precedence_over_sanction(self) -> None:
        """
        If a transition declares both sanction_id and restorative_path_id
        (unusual but possible), REMEDIATE wins. Restorative paths are
        the institution's offer of return; honouring them avoids
        punitive cycling.
        """
        # The fixture doesn't have such an edge, so build a minimal
        # manifest inline.
        manifest = {
            "graph_id": "remediate_priority_test",
            "version": "1.0",
            "states": ["active", "fined"],
            "sanctions": [
                {
                    "sanction_id": "fine1",
                    "description": "",
                    "cost_to_actor": 1.0,
                    "cost_to_system": 0.0,
                    "enforcement_action": "fine",
                    "tier": 1,
                    "fine_rate": 0.35,
                    "fine_floor": 200.0,
                }
            ],
            "restorative_paths": [
                {
                    "path_id": "p1",
                    "description": "",
                    "restorative_event_kinds": [],
                    "target_legal_state_id": "active",
                    "restoration_kind": "expiry",
                }
            ],
            "transitions": [
                {
                    "rule_id": "R",
                    "from_state": "fined",
                    "to_state": "active",
                    "triggered_by": "remedial",
                    "sanction_id": "fine1",
                    "restorative_path_id": "p1",
                }
            ],
        }
        g = GovernanceGraph.from_dict(manifest)
        oracle = GovernanceOracle(graph=g, signals=())
        controller = GovernanceController(oracle=oracle)
        controller.set_actor_state("firm_1", "fined")
        d = controller.enforce(
            proposed_event_kind="remedial",
            actor_entity_id="firm_1",
            current_round=1,
        )
        assert d["decision"] == ControllerOutcome.REMEDIATE.value
        assert d["sanction_id"] == "fine1"  # still recorded for audit
        assert d["restorative_path_id"] == "p1"


# ---------------------------------------------------------------------
# State transition mechanics
# ---------------------------------------------------------------------


class TestActorStateTransitions:
    def test_default_actor_state_is_active(self) -> None:
        controller, _, _ = _build_engine()
        assert controller.actor_state("firm_1") == "active"
        assert controller.actor_state("never_seen") == "active"

    def test_sanction_advances_actor_state(self) -> None:
        controller, _, _ = _build_engine()
        controller.enforce(
            proposed_event_kind="probable_violation",
            actor_entity_id="firm_1",
            current_round=1,
        )
        assert controller.actor_state("firm_1") == "warning"

    def test_remediate_advances_actor_state_back_to_active(self) -> None:
        controller, _, _ = _build_engine()
        controller.set_actor_state("firm_1", "warning")
        controller.enforce(
            proposed_event_kind="expiry_tick",
            actor_entity_id="firm_1",
            current_round=5,
        )
        assert controller.actor_state("firm_1") == "active"

    def test_blocked_does_not_advance_state(self) -> None:
        controller, _, _ = _build_engine()
        before = controller.actor_state("firm_1")
        controller.enforce(
            proposed_event_kind="never_heard_of",
            actor_entity_id="firm_1",
            current_round=1,
        )
        assert controller.actor_state("firm_1") == before

    def test_full_escalation_chain(self) -> None:
        """active -> warning -> fined -> suspended via three violations."""
        controller, _, _ = _build_engine()
        controller.enforce(
            proposed_event_kind="probable_violation",
            actor_entity_id="firm_1",
            current_round=1,
        )
        assert controller.actor_state("firm_1") == "warning"
        controller.enforce(
            proposed_event_kind="probable_violation",
            actor_entity_id="firm_1",
            current_round=2,
        )
        assert controller.actor_state("firm_1") == "fined"
        controller.enforce(
            proposed_event_kind="probable_violation",
            actor_entity_id="firm_1",
            current_round=10,  # past all cooldowns
        )
        assert controller.actor_state("firm_1") == "suspended"

    def test_per_actor_state_isolation(self) -> None:
        controller, _, _ = _build_engine()
        controller.enforce(
            proposed_event_kind="probable_violation",
            actor_entity_id="firm_1",
            current_round=1,
        )
        assert controller.actor_state("firm_1") == "warning"
        assert controller.actor_state("firm_2") == "active"


# ---------------------------------------------------------------------
# Cooldown gating — paper §7 records 244 BLOCKED suspension requests
# ---------------------------------------------------------------------


class TestCooldownGating:
    def test_in_cooldown_returns_false_when_no_record(self) -> None:
        controller, _, _ = _build_engine()
        assert (
            controller.in_cooldown(
                actor_entity_id="firm_1",
                edge_key="P2_independent_decision:active->warning",
                current_round=1,
            )
            is False
        )

    def test_sanction_schedules_cooldown(self) -> None:
        controller, _, _ = _build_engine()
        decision = controller.enforce(
            proposed_event_kind="probable_violation",
            actor_entity_id="firm_1",
            current_round=1,
        )
        # active->warning has cooldown_rounds=1 in the fixture.
        assert decision["cooldown_until_round"] == 2
        assert (
            controller.in_cooldown(
                actor_entity_id="firm_1",
                edge_key="P2_independent_decision:active->warning",
                current_round=1,
            )
            is True
        )

    def test_cooldown_blocks_repeat_traversal_of_same_edge(self) -> None:
        """
        Build a manifest with a self-loop sanctioned edge so we can
        repeatedly request the SAME edge and observe BLOCKED.
        Replicates the spirit of paper §7 (244 blocked suspension
        requests).
        """
        manifest = {
            "graph_id": "cooldown_test",
            "version": "1.0",
            "states": ["active"],
            "sanctions": [
                {
                    "sanction_id": "warn",
                    "description": "",
                    "cost_to_actor": 1.0,
                    "cost_to_system": 0.0,
                    "enforcement_action": "warning",
                }
            ],
            "restorative_paths": [],
            "transitions": [
                {
                    "rule_id": "R",
                    "from_state": "active",
                    "to_state": "active",
                    "triggered_by": "probable_violation",
                    "sanction_id": "warn",
                    "timing": {"cooldown_rounds": 5},
                }
            ],
        }
        g = GovernanceGraph.from_dict(manifest)
        oracle = GovernanceOracle(graph=g, signals=())
        log = GovernanceLog(signing_key_id="cooldown-test")
        controller = GovernanceController(oracle=oracle, ledger=log)

        d1 = controller.enforce(
            proposed_event_kind="probable_violation",
            actor_entity_id="firm_1",
            current_round=1,
        )
        assert d1["decision"] == ControllerOutcome.SANCTION.value
        assert d1["cooldown_until_round"] == 6

        # Second request inside the cooldown window -> BLOCKED.
        d2 = controller.enforce(
            proposed_event_kind="probable_violation",
            actor_entity_id="firm_1",
            current_round=2,
        )
        assert d2["decision"] == ControllerOutcome.BLOCKED.value
        assert "cooldown" in d2["rationale"]
        assert d2["edge_key"] == "R:active->active"

        # Past the cooldown window -> SANCTION again.
        d3 = controller.enforce(
            proposed_event_kind="probable_violation",
            actor_entity_id="firm_1",
            current_round=7,
        )
        assert d3["decision"] == ControllerOutcome.SANCTION.value

    def test_cooldown_is_per_actor(self) -> None:
        manifest = {
            "graph_id": "cooldown_per_actor_test",
            "version": "1.0",
            "states": ["active"],
            "sanctions": [
                {
                    "sanction_id": "warn",
                    "description": "",
                    "cost_to_actor": 1.0,
                    "cost_to_system": 0.0,
                    "enforcement_action": "warning",
                }
            ],
            "restorative_paths": [],
            "transitions": [
                {
                    "rule_id": "R",
                    "from_state": "active",
                    "to_state": "active",
                    "triggered_by": "probable_violation",
                    "sanction_id": "warn",
                    "timing": {"cooldown_rounds": 5},
                }
            ],
        }
        g = GovernanceGraph.from_dict(manifest)
        oracle = GovernanceOracle(graph=g, signals=())
        controller = GovernanceController(oracle=oracle)
        # firm_1 sanctioned and on cooldown
        controller.enforce(
            proposed_event_kind="probable_violation",
            actor_entity_id="firm_1",
            current_round=1,
        )
        # firm_2 still gets sanctioned, not blocked
        d = controller.enforce(
            proposed_event_kind="probable_violation",
            actor_entity_id="firm_2",
            current_round=1,
        )
        assert d["decision"] == ControllerOutcome.SANCTION.value


# ---------------------------------------------------------------------
# Decision provenance — every decision carries manifest_semantic_sha256
# ---------------------------------------------------------------------


class TestDecisionProvenance:
    def test_allow_decision_carries_manifest_digest(self) -> None:
        controller, oracle, _ = _build_engine()
        d = controller.enforce(
            proposed_event_kind="clean_round",
            actor_entity_id="firm_1",
            current_round=1,
        )
        assert (
            d["manifest_semantic_sha256"]
            == oracle.graph.manifest_semantic_sha256
        )

    def test_sanction_decision_carries_manifest_digest(self) -> None:
        controller, oracle, _ = _build_engine()
        d = controller.enforce(
            proposed_event_kind="probable_violation",
            actor_entity_id="firm_1",
            current_round=1,
        )
        assert (
            d["manifest_semantic_sha256"]
            == oracle.graph.manifest_semantic_sha256
        )

    def test_blocked_decision_carries_manifest_digest(self) -> None:
        controller, oracle, _ = _build_engine()
        d = controller.enforce(
            proposed_event_kind="never_seen",
            actor_entity_id="firm_1",
            current_round=1,
        )
        assert d["decision"] == ControllerOutcome.BLOCKED.value
        assert (
            d["manifest_semantic_sha256"]
            == oracle.graph.manifest_semantic_sha256
        )

    def test_decision_carries_case_id_when_provided(self) -> None:
        controller, _, _ = _build_engine()
        case = _make_case()
        d = controller.enforce(
            proposed_event_kind="probable_violation",
            actor_entity_id="firm_1",
            current_round=1,
            case=case,
        )
        assert d["case_id"] == case.case_id

    def test_decision_id_is_unique(self) -> None:
        controller, _, _ = _build_engine()
        d1 = controller.enforce(
            proposed_event_kind="clean_round",
            actor_entity_id="firm_1",
            current_round=1,
        )
        d2 = controller.enforce(
            proposed_event_kind="clean_round",
            actor_entity_id="firm_2",
            current_round=1,
        )
        assert d1["decision_id"] != d2["decision_id"]

    def test_decision_records_to_ledger_when_provided(self) -> None:
        controller, _, log = _build_engine(with_log=True)
        assert log is not None
        before = len(log)
        controller.enforce(
            proposed_event_kind="probable_violation",
            actor_entity_id="firm_1",
            current_round=1,
        )
        # SANCTION outcome appends both the primary decision record
        # and a paired sanction_applied record.
        assert len(log) == before + 2

    def test_blocked_decisions_are_logged(self) -> None:
        """Paper §7 requires BLOCKED traversals to be logged for audit."""
        controller, _, log = _build_engine(with_log=True)
        assert log is not None
        before = len(log)
        controller.enforce(
            proposed_event_kind="never_heard_of",
            actor_entity_id="firm_1",
            current_round=1,
        )
        assert len(log) == before + 1  # primary record only, no pair


# ---------------------------------------------------------------------
# Argument validation
# ---------------------------------------------------------------------


class TestArgumentValidation:
    def test_enforce_requires_actor_entity_id(self) -> None:
        controller, _, _ = _build_engine()
        with pytest.raises(ValueError, match="actor_entity_id"):
            controller.enforce(
                proposed_event_kind="clean_round",
                actor_entity_id="",
                current_round=1,
            )

    def test_enforce_requires_proposed_event_kind(self) -> None:
        controller, _, _ = _build_engine()
        with pytest.raises(ValueError, match="proposed_event_kind"):
            controller.enforce(
                proposed_event_kind="",
                actor_entity_id="firm_1",
                current_round=1,
            )


# ---------------------------------------------------------------------
# ControllerDecision pydantic model contract
# ---------------------------------------------------------------------


class TestControllerDecisionModel:
    def test_decision_is_frozen(self) -> None:
        decision = ControllerDecision(
            decision_id="d1",
            decision=ControllerOutcome.ALLOW,
            from_state="active",
            triggered_by="clean_round",
            actor_entity_id="firm_1",
            effective_round=1,
            manifest_semantic_sha256="abc",
        )
        with pytest.raises((TypeError, ValueError)):
            decision.decision_id = "d2"  # type: ignore[misc]

    def test_decision_rejects_extra_fields(self) -> None:
        with pytest.raises(ValueError):
            ControllerDecision(
                decision_id="d1",
                decision=ControllerOutcome.ALLOW,
                from_state="active",
                triggered_by="clean_round",
                actor_entity_id="firm_1",
                effective_round=1,
                manifest_semantic_sha256="abc",
                made_up_field="bad",  # type: ignore[call-arg]
            )

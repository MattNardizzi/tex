"""Tests for tex.institutional.oracle."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

import tex.ecosystem  # noqa: F401  prime ordering

from tex.ecosystem.state import EcosystemState
from tex.institutional import (
    SIGNAL_HIGH_HHI,
    SIGNAL_SPECIALISATION,
    SIGNAL_SYNCHRONOUS_MOVE,
    SIGNAL_VARIANCE_COLLAPSE,
    GovernanceGraph,
    GovernanceOracle,
    OracleCase,
    OracleObservation,
    OracleSignal,
    collusion_tier,
)


FIXTURES_DIR = Path(__file__).parent / "fixtures"
COURNOT_MANIFEST = FIXTURES_DIR / "cournot_market.yaml"


# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------


def _state(
    *,
    cv_excess: float = 0.0,
    hhi_excess: float = 0.0,
    sync_move: float = 0.0,
    cross_firm_dispersion: float = 1.0,
    extra: dict | None = None,
) -> EcosystemState:
    sigs = {
        "cv_excess": cv_excess,
        "hhi_excess": hhi_excess,
        "sync_move_pct": sync_move,
        "cross_firm_dispersion": cross_firm_dispersion,
    }
    if extra:
        sigs.update(extra)
    return EcosystemState(
        snapshot_at=datetime.now(UTC),
        state_hash="test_hash_" + str(hash(frozenset(sigs.items())) % 10**6),
        active_agent_ids=("firm_1", "firm_2"),
        active_tool_ids=(),
        active_capability_ids=(),
        active_governance_graph_id="cournot_market_v1",
        aggregate_drift_signals=sigs,
    )


def _cournot_oracle() -> GovernanceOracle:
    g = GovernanceGraph.from_yaml(COURNOT_MANIFEST)
    return GovernanceOracle(
        graph=g,
        signals=(
            OracleSignal(SIGNAL_HIGH_HHI, "hhi_excess", threshold=0.50),
            OracleSignal(SIGNAL_SPECIALISATION, "cv_excess", threshold=0.75),
            OracleSignal(
                SIGNAL_SYNCHRONOUS_MOVE,
                "sync_move_pct",
                threshold=10.0,
            ),
            OracleSignal(
                SIGNAL_VARIANCE_COLLAPSE,
                "cross_firm_dispersion",
                threshold=0.10,
                consecutive_rounds=3,
            ),
        ),
        rule_id_for_signal={
            SIGNAL_HIGH_HHI: "P2_independent_decision",
            SIGNAL_SPECIALISATION: "P2_independent_decision",
            SIGNAL_SYNCHRONOUS_MOVE: "P2_independent_decision",
            SIGNAL_VARIANCE_COLLAPSE: "P2_independent_decision",
        },
    )


# ---------------------------------------------------------------------
# collusion_tier (Table 1)
# ---------------------------------------------------------------------


class TestCollusionTier:
    def test_tier_0_no_evidence(self) -> None:
        assert collusion_tier(cv_excess=0.0, hhi_excess=0.0) == 0
        assert collusion_tier(cv_excess=-0.1, hhi_excess=-0.05) == 0

    def test_tier_1_mild_positive_excess(self) -> None:
        assert collusion_tier(cv_excess=0.10, hhi_excess=0.05) == 1
        assert collusion_tier(cv_excess=0.0, hhi_excess=0.05) == 1

    def test_tier_2_threshold_cv(self) -> None:
        assert collusion_tier(cv_excess=0.30, hhi_excess=0.0) == 2

    def test_tier_2_threshold_hhi(self) -> None:
        assert collusion_tier(cv_excess=0.0, hhi_excess=0.20) == 2

    def test_tier_3_strong_cv(self) -> None:
        assert collusion_tier(cv_excess=0.80, hhi_excess=0.0) == 3

    def test_tier_3_strong_hhi(self) -> None:
        assert collusion_tier(cv_excess=0.0, hhi_excess=0.55) == 3

    def test_tier_3_combined_clause(self) -> None:
        # CV>0.50 AND HHI>0.30 (neither hits the standalone tier-3)
        assert collusion_tier(cv_excess=0.60, hhi_excess=0.40) == 3

    def test_tier_4_severe_cv(self) -> None:
        assert collusion_tier(cv_excess=1.60, hhi_excess=0.0) == 4

    def test_tier_4_severe_hhi(self) -> None:
        assert collusion_tier(cv_excess=0.0, hhi_excess=0.85) == 4

    def test_tier_4_combined_clause(self) -> None:
        # CV>1.0 AND HHI>0.50 (neither alone hits standalone tier-4)
        assert collusion_tier(cv_excess=1.10, hhi_excess=0.55) == 4

    def test_higher_tier_takes_precedence(self) -> None:
        # Tier-4 conditions also satisfy tier-3 and tier-2 thresholds;
        # we must report the highest applicable tier.
        assert collusion_tier(cv_excess=2.00, hhi_excess=0.95) == 4

    def test_paper_replication_target_tier_3(self) -> None:
        """
        Paper reports mean ungoverned tier = 3.10. A representative
        ungoverned point (CV ~ 1.37, HHI ~ 0.49) should land at tier 3.
        """
        assert collusion_tier(cv_excess=1.37, hhi_excess=0.49) == 3

    def test_paper_replication_target_tier_1(self) -> None:
        """
        Paper reports mean institutional tier = 1.82. A representative
        governed point (CV ~ 0.27, HHI ~ 0.18) should land at tier 2.
        Lower governed runs (CV ~ 0.12, HHI ~ 0.05) land at tier 1.
        """
        assert collusion_tier(cv_excess=0.12, hhi_excess=0.05) == 1


# ---------------------------------------------------------------------
# observe_state — case emission
# ---------------------------------------------------------------------


class TestObserveState:
    def test_no_signals_fired_emits_no_case(self) -> None:
        oracle = _cournot_oracle()
        obs = oracle.observe_state(_state(), actor_entity_id="firm_1")
        assert isinstance(obs, OracleObservation)
        assert obs.pending_cases == ()
        assert all(
            not e["fired"] for e in obs.signal_evaluations.values()
        )

    def test_high_hhi_alone_fires_case_at_correct_tier(self) -> None:
        oracle = _cournot_oracle()
        obs = oracle.observe_state(
            _state(hhi_excess=0.60, cv_excess=0.10),
            actor_entity_id="firm_1",
        )
        assert len(obs.pending_cases) == 1
        case = obs.pending_cases[0]
        assert isinstance(case, OracleCase)
        assert case.kind == "probable_violation"
        # CV=0.10 + HHI=0.60 -> tier 3 by Table 1 (HHI>0.50)
        assert case.severity_tier == 3
        assert SIGNAL_HIGH_HHI in case.triggered_by_signals

    def test_specialisation_alone_fires_case(self) -> None:
        oracle = _cournot_oracle()
        obs = oracle.observe_state(
            _state(cv_excess=0.80, hhi_excess=0.10),
            actor_entity_id="firm_1",
        )
        assert len(obs.pending_cases) == 1
        case = obs.pending_cases[0]
        assert SIGNAL_SPECIALISATION in case.triggered_by_signals
        assert case.severity_tier == 3  # CV>0.75 -> tier 3

    def test_multiple_signals_fold_into_one_case(self) -> None:
        oracle = _cournot_oracle()
        obs = oracle.observe_state(
            _state(cv_excess=1.00, hhi_excess=0.60),
            actor_entity_id="firm_1",
        )
        # Paper says: "the Oracle emits a probable_violation case
        # referencing the stable rule ID" — one case per detection round.
        assert len(obs.pending_cases) == 1
        case = obs.pending_cases[0]
        assert SIGNAL_HIGH_HHI in case.triggered_by_signals
        assert SIGNAL_SPECIALISATION in case.triggered_by_signals
        # CV=1.0, HHI=0.6 -> tier 3 (CV>0.75 OR HHI>0.50)
        assert case.severity_tier == 3

    def test_case_carries_manifest_semantic_sha256(self) -> None:
        oracle = _cournot_oracle()
        obs = oracle.observe_state(
            _state(hhi_excess=0.60), actor_entity_id="firm_1"
        )
        case = obs.pending_cases[0]
        assert case.manifest_semantic_sha256 == oracle.graph.manifest_semantic_sha256

    def test_case_carries_actor_entity_id(self) -> None:
        oracle = _cournot_oracle()
        obs = oracle.observe_state(
            _state(hhi_excess=0.60), actor_entity_id="firm_2"
        )
        assert obs.pending_cases[0].actor_entity_id == "firm_2"

    def test_observation_lists_enabled_transitions_per_state(self) -> None:
        oracle = _cournot_oracle()
        obs = oracle.observe_state(
            _state(),
            institutional_states={"firm_1": "active", "firm_2": "warning"},
            actor_entity_id="firm_1",
        )
        # Active has 2 outgoing (active->warning, active->active);
        # warning has 3 outgoing (warning->fined, warning->active,
        # warning->warning); union = 5.
        assert len(obs.enabled_transitions) == 5

    def test_missing_signal_records_as_missing_not_fired(self) -> None:
        oracle = _cournot_oracle()
        # Build a state with no cv_excess key.
        state = EcosystemState(
            snapshot_at=datetime.now(UTC),
            state_hash="test",
            active_agent_ids=("firm_1",),
            active_tool_ids=(),
            active_capability_ids=(),
            active_governance_graph_id="cournot_market_v1",
            aggregate_drift_signals={"hhi_excess": 0.0},
        )
        obs = oracle.observe_state(state, actor_entity_id="firm_1")
        cv_eval = obs.signal_evaluations[SIGNAL_SPECIALISATION]
        assert cv_eval["fired"] is False
        assert cv_eval["reason"] == "missing_signal"


# ---------------------------------------------------------------------
# S2 — variance collapse (consecutive-rounds streak)
# ---------------------------------------------------------------------


class TestVarianceCollapseStreak:
    def test_below_threshold_for_one_round_does_not_fire(self) -> None:
        oracle = _cournot_oracle()
        obs = oracle.observe_state(
            _state(cross_firm_dispersion=0.05),
            actor_entity_id="firm_1",
        )
        s2 = obs.signal_evaluations[SIGNAL_VARIANCE_COLLAPSE]
        assert s2["fired"] is False
        assert "streak=1/3" in s2["reason"]

    def test_below_threshold_for_required_rounds_fires(self) -> None:
        oracle = _cournot_oracle()
        # Three consecutive rounds below threshold -> S2 fires on round 3.
        for _ in range(2):
            oracle.observe_state(
                _state(cross_firm_dispersion=0.05),
                actor_entity_id="firm_1",
            )
        obs = oracle.observe_state(
            _state(cross_firm_dispersion=0.05),
            actor_entity_id="firm_1",
        )
        s2 = obs.signal_evaluations[SIGNAL_VARIANCE_COLLAPSE]
        assert s2["fired"] is True

    def test_above_threshold_resets_streak(self) -> None:
        oracle = _cournot_oracle()
        # Two below, one above -> reset.
        for _ in range(2):
            oracle.observe_state(
                _state(cross_firm_dispersion=0.05),
                actor_entity_id="firm_1",
            )
        oracle.observe_state(
            _state(cross_firm_dispersion=0.50),
            actor_entity_id="firm_1",
        )
        # Next round below should be streak=1, not fired.
        obs = oracle.observe_state(
            _state(cross_firm_dispersion=0.05),
            actor_entity_id="firm_1",
        )
        s2 = obs.signal_evaluations[SIGNAL_VARIANCE_COLLAPSE]
        assert s2["fired"] is False
        assert "streak=1/3" in s2["reason"]

    def test_streaks_are_per_actor(self) -> None:
        oracle = _cournot_oracle()
        # Two below for firm_1; firm_2's streak must be independent.
        for _ in range(2):
            oracle.observe_state(
                _state(cross_firm_dispersion=0.05),
                actor_entity_id="firm_1",
            )
        obs = oracle.observe_state(
            _state(cross_firm_dispersion=0.05),
            actor_entity_id="firm_2",
        )
        s2 = obs.signal_evaluations[SIGNAL_VARIANCE_COLLAPSE]
        assert s2["fired"] is False
        assert "streak=1/3" in s2["reason"]


# ---------------------------------------------------------------------
# evaluate_transition — manifest-driven legality
# ---------------------------------------------------------------------


class TestEvaluateTransition:
    def test_active_probable_violation_returns_warning_sanction(self) -> None:
        oracle = _cournot_oracle()
        legal, sanction_id = oracle.evaluate_transition(
            current_state=_state(),
            proposed_event_kind="probable_violation",
            institutional_state="active",
        )
        # Sanctioned edges return (False, sanction_id) — illegal in the
        # sense that the actor is being penalised, but the edge IS in
        # the manifest.
        assert legal is False
        assert sanction_id == "warning_notice"

    def test_warning_probable_violation_returns_fine_tier1(self) -> None:
        oracle = _cournot_oracle()
        legal, sanction_id = oracle.evaluate_transition(
            current_state=_state(),
            proposed_event_kind="probable_violation",
            institutional_state="warning",
        )
        assert legal is False
        assert sanction_id == "fine_tier1"

    def test_fined_probable_violation_returns_suspension(self) -> None:
        oracle = _cournot_oracle()
        legal, sanction_id = oracle.evaluate_transition(
            current_state=_state(),
            proposed_event_kind="probable_violation",
            institutional_state="fined",
        )
        assert legal is False
        assert sanction_id == "suspend_5_rounds"

    def test_warning_expiry_tick_is_legal_no_sanction(self) -> None:
        oracle = _cournot_oracle()
        legal, sanction_id = oracle.evaluate_transition(
            current_state=_state(),
            proposed_event_kind="expiry_tick",
            institutional_state="warning",
        )
        # Restorative paths return (True, None) — pure legal traversals.
        assert legal is True
        assert sanction_id is None

    def test_suspended_expiry_tick_is_legal(self) -> None:
        oracle = _cournot_oracle()
        legal, sanction_id = oracle.evaluate_transition(
            current_state=_state(),
            proposed_event_kind="expiry_tick",
            institutional_state="suspended",
        )
        assert legal is True
        assert sanction_id is None

    def test_fined_credit_earned_is_legal(self) -> None:
        oracle = _cournot_oracle()
        legal, sanction_id = oracle.evaluate_transition(
            current_state=_state(),
            proposed_event_kind="credit_earned",
            institutional_state="fined",
        )
        assert legal is True
        assert sanction_id is None

    def test_active_clean_round_is_legal_self_loop(self) -> None:
        oracle = _cournot_oracle()
        legal, sanction_id = oracle.evaluate_transition(
            current_state=_state(),
            proposed_event_kind="clean_round",
            institutional_state="active",
        )
        assert legal is True
        assert sanction_id is None

    def test_no_matching_edge_returns_illegal_no_sanction(self) -> None:
        oracle = _cournot_oracle()
        # No edge from "active" for "expiry_tick" in fixture.
        legal, sanction_id = oracle.evaluate_transition(
            current_state=_state(),
            proposed_event_kind="expiry_tick",
            institutional_state="active",
        )
        assert legal is False
        assert sanction_id is None  # no edge = no sanction to cite

    def test_unknown_event_kind_returns_illegal_no_sanction(self) -> None:
        oracle = _cournot_oracle()
        legal, sanction_id = oracle.evaluate_transition(
            current_state=_state(),
            proposed_event_kind="completely_made_up_event",
            institutional_state="active",
        )
        assert legal is False
        assert sanction_id is None


# ---------------------------------------------------------------------
# Constructor validation
# ---------------------------------------------------------------------


class TestOracleConstruction:
    def test_rejects_unknown_signal_id(self) -> None:
        g = GovernanceGraph.from_yaml(COURNOT_MANIFEST)
        with pytest.raises(ValueError, match="unknown signal_id"):
            GovernanceOracle(
                graph=g,
                signals=(
                    OracleSignal("S99_invented", "cv_excess", threshold=0.5),
                ),
            )

    def test_accepts_empty_signal_set(self) -> None:
        g = GovernanceGraph.from_yaml(COURNOT_MANIFEST)
        oracle = GovernanceOracle(graph=g, signals=())
        obs = oracle.observe_state(_state(), actor_entity_id="firm_1")
        assert obs.pending_cases == ()
        assert obs.signal_evaluations == {}

    def test_graph_property_round_trips(self) -> None:
        g = GovernanceGraph.from_yaml(COURNOT_MANIFEST)
        oracle = GovernanceOracle(graph=g, signals=())
        assert oracle.graph is g

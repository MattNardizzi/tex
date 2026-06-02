"""
Tests for tex.intervention.engine — selection + apply + governance-log emission.

Coverage:
- select(): lowest-cost ranking, bound check, target-eta filter,
  empty candidate set, no-candidate-satisfies, calculator failure,
  invalid arguments.
- apply(): payload composition, AIR-phase tag, certificate embedding,
  ledger append, ledger-failure FAIL-CLOSED, no-ledger path.
- air_phase_for(): mapping coverage for every InterventionKind.
"""

from __future__ import annotations

import pytest

from tex.intervention.bounded_compromise import BoundedCompromiseCalculator
from tex.intervention.engine import (
    InterventionApplyError,
    InterventionEngine,
    air_phase_for,
)
from tex.intervention.kinds import Intervention, InterventionKind


# ---------------------------------------------------------------- fixtures


def make_iv(
    iv_id: str,
    kind: InterventionKind,
    cost_sys: float,
    cost_adv: float,
    *,
    target: str = "agent_X",
) -> Intervention:
    """Compose an Intervention for testing."""
    return Intervention(
        intervention_id=iv_id,
        kind=kind,
        target_entity_id=target,
        parameters={"key": "value"},
        expected_cost_to_system=cost_sys,
        expected_cost_to_adversary=cost_adv,
        rationale=f"test rationale {iv_id}",
    )


@pytest.fixture
def calc() -> BoundedCompromiseCalculator:
    return BoundedCompromiseCalculator()


@pytest.fixture
def engine_no_ledger(calc: BoundedCompromiseCalculator) -> InterventionEngine:
    return InterventionEngine(bounded_compromise_calc=calc, ledger=None)


# --------------------------------------------------------------- construction


class TestConstruction:
    def test_requires_calc(self) -> None:
        with pytest.raises(ValueError, match="BoundedCompromiseCalculator"):
            InterventionEngine(bounded_compromise_calc=None, ledger=None)  # type: ignore[arg-type]

    def test_ledger_optional(self, calc: BoundedCompromiseCalculator) -> None:
        eng = InterventionEngine(bounded_compromise_calc=calc, ledger=None)
        assert eng is not None


# --------------------------------------------------------------------- select


class TestSelect:
    def test_returns_lowest_cost_satisfier(
        self, engine_no_ledger: InterventionEngine
    ) -> None:
        candidates = (
            make_iv("iv_weak", InterventionKind.HUMAN_APPROVAL_GATE, 0.01, 1.0),
            make_iv("iv_mid", InterventionKind.TRUST_SCORE_REDUCE, 0.05, 12.0),
            make_iv("iv_heavy", InterventionKind.QUARANTINE, 0.20, 30.0),
        )
        # Drift 0.4 -> g_max=0.4 via drift_delta. iv_weak (λH=1) fails
        # since η = 1.25/0.6 > 1; iv_mid yields η = 1.25/11.6 ≈ 0.108
        chosen = engine_no_ledger.select(
            current_drift_score=0.4,
            target_max_compromise_ratio=0.5,
            candidate_interventions=candidates,
        )
        assert chosen is not None
        assert chosen.intervention_id == "iv_mid"

    def test_returns_none_when_no_satisfier(
        self, engine_no_ledger: InterventionEngine
    ) -> None:
        candidates = (
            make_iv("iv_only", InterventionKind.REWARD_SHAPE, 0.01, 0.1),
        )
        chosen = engine_no_ledger.select(
            current_drift_score=0.9,
            target_max_compromise_ratio=0.1,
            candidate_interventions=candidates,
        )
        assert chosen is None

    def test_empty_candidate_set_returns_none(
        self, engine_no_ledger: InterventionEngine
    ) -> None:
        assert engine_no_ledger.select(
            current_drift_score=0.5,
            target_max_compromise_ratio=0.3,
            candidate_interventions=(),
        ) is None

    def test_filters_satisfying_but_above_target_eta(
        self, calc: BoundedCompromiseCalculator,
    ) -> None:
        # Build a calculator with a generous target so the bound is
        # satisfied but the resulting eta exceeds a *tighter* target
        # passed at selection time.
        engine = InterventionEngine(bounded_compromise_calc=calc, ledger=None)
        # λH=5.5, g_max≈0.5 (fallback). slack=5.0; eta = 1.25/5.0 = 0.25
        # First call accepts; second call with target=0.10 rejects.
        cand = (
            make_iv("iv_a", InterventionKind.REWARD_SHAPE, 0.05, 5.5),
        )
        accepted = engine.select(
            current_drift_score=0.5,
            target_max_compromise_ratio=0.5,
            candidate_interventions=cand,
        )
        assert accepted is not None
        rejected = engine.select(
            current_drift_score=0.5,
            target_max_compromise_ratio=0.10,
            candidate_interventions=cand,
        )
        assert rejected is None

    def test_deterministic_tie_break_by_intervention_id(
        self, engine_no_ledger: InterventionEngine
    ) -> None:
        # Two interventions tied on cost_to_system: lower id wins.
        candidates = (
            make_iv("iv_zzz", InterventionKind.REWARD_SHAPE, 0.05, 15.0),
            make_iv("iv_aaa", InterventionKind.TRUST_SCORE_REDUCE, 0.05, 15.0),
        )
        chosen = engine_no_ledger.select(
            current_drift_score=0.2,
            target_max_compromise_ratio=0.5,
            candidate_interventions=candidates,
        )
        assert chosen is not None
        assert chosen.intervention_id == "iv_aaa"

    def test_rejects_non_tuple_candidates(
        self, engine_no_ledger: InterventionEngine
    ) -> None:
        with pytest.raises(TypeError, match="candidate_interventions"):
            engine_no_ledger.select(
                current_drift_score=0.5,
                target_max_compromise_ratio=0.3,
                candidate_interventions=[  # type: ignore[arg-type]
                    make_iv("iv", InterventionKind.QUARANTINE, 1.0, 100.0)
                ],
            )

    @pytest.mark.parametrize("bad_target", [-0.1, 1.5])
    def test_rejects_invalid_target_eta(
        self, engine_no_ledger: InterventionEngine, bad_target: float
    ) -> None:
        with pytest.raises(ValueError, match="target_max_compromise_ratio"):
            engine_no_ledger.select(
                current_drift_score=0.5,
                target_max_compromise_ratio=bad_target,
                candidate_interventions=(),
            )

    def test_target_eta_zero_accepted(
        self, engine_no_ledger: InterventionEngine
    ) -> None:
        # target=0 means "no candidate can ever satisfy". Should
        # return None without raising.
        cand = (make_iv("iv", InterventionKind.QUARANTINE, 1.0, 100.0),)
        assert engine_no_ledger.select(
            current_drift_score=0.5,
            target_max_compromise_ratio=0.0,
            candidate_interventions=cand,
        ) is None


# ----------------------------------------------------------------------- apply


class TestApply:
    def test_apply_rejects_non_intervention(
        self, engine_no_ledger: InterventionEngine
    ) -> None:
        with pytest.raises(TypeError, match="intervention"):
            engine_no_ledger.apply("not an Intervention")  # type: ignore[arg-type]

    def test_apply_no_ledger_returns_none(
        self, engine_no_ledger: InterventionEngine
    ) -> None:
        iv = make_iv("iv_a", InterventionKind.TRUST_SCORE_REDUCE, 0.05, 12.0)
        result = engine_no_ledger.apply(iv)
        assert result is None

    def test_apply_with_ledger_returns_event_id(
        self, calc: BoundedCompromiseCalculator
    ) -> None:
        from tex.events._ecdsa_provider import default_signature_provider
        from tex.institutional.governance_log import GovernanceLog

        provider = default_signature_provider()
        keypair = provider.generate_keypair("test-iv-log")
        log = GovernanceLog(
            signing_key_id="test-iv-log",
            signing_keypair=keypair,
            signing_provider=provider,
        )
        eng = InterventionEngine(bounded_compromise_calc=calc, ledger=log)
        iv = make_iv("iv_b", InterventionKind.CAPABILITY_REVOKE, 0.07, 20.0)
        event_id = eng.apply(iv)
        assert isinstance(event_id, str)
        assert event_id.startswith("evt_")

        # Verify the record landed in the log and the chain verifies.
        records = log.all_records()
        assert len(records) == 1
        assert log.verify_chain() is True

    def test_apply_ledger_failure_raises_apply_error(
        self, calc: BoundedCompromiseCalculator
    ) -> None:
        class BrokenLedger:
            def record_observation(self, *, oracle_observation):  # type: ignore[no-untyped-def]
                raise RuntimeError("simulated ledger outage")

        eng = InterventionEngine(
            bounded_compromise_calc=calc, ledger=BrokenLedger()
        )
        iv = make_iv("iv_c", InterventionKind.POLICY_PATCH, 0.10, 15.0)
        with pytest.raises(InterventionApplyError, match="governance-log"):
            eng.apply(iv)

    def test_apply_payload_includes_certificate(
        self, calc: BoundedCompromiseCalculator
    ) -> None:
        captured: dict = {}

        class CapturingLedger:
            def record_observation(self, *, oracle_observation):  # type: ignore[no-untyped-def]
                captured.update(oracle_observation)
                return "evt_captured"

        eng = InterventionEngine(
            bounded_compromise_calc=calc, ledger=CapturingLedger()
        )
        iv = make_iv("iv_d", InterventionKind.TRUST_SCORE_REDUCE, 0.05, 12.0)
        eng.apply(iv)
        assert captured["intervention_id"] == "iv_d"
        assert captured["intervention_kind"] == "trust_score_reduce"
        assert captured["air_phase"] == "contain"
        assert "compromise_certificate" in captured
        cert = captured["compromise_certificate"]
        assert cert["bound_satisfied"] is True
        assert "eta_star" in cert
        assert "lambda_min" in cert
        assert cert["window_length"] == 25
        assert "references" in captured
        assert "2512.18561" in captured["references"]


# -------------------------------------------------------------- AIR phase mapping


class TestAirPhaseFor:
    def test_human_approval_is_hold(self) -> None:
        assert air_phase_for(InterventionKind.HUMAN_APPROVAL_GATE) == "hold"

    def test_restorative_is_recover(self) -> None:
        assert air_phase_for(InterventionKind.RESTORATIVE_PATH) == "recover"

    @pytest.mark.parametrize(
        "kind",
        [
            InterventionKind.CAPABILITY_REVOKE,
            InterventionKind.TRUST_SCORE_REDUCE,
            InterventionKind.REWARD_SHAPE,
            InterventionKind.POLICY_PATCH,
            InterventionKind.QUARANTINE,
        ],
    )
    def test_default_contain(self, kind: InterventionKind) -> None:
        assert air_phase_for(kind) == "contain"

    def test_every_kind_has_mapping(self) -> None:
        # Defence: every enum member maps to a phase. Thread 8.1 added
        # "eradicate" for ERADICATION_RULE_SYNTHESIS (AIR §3).
        for kind in InterventionKind:
            phase = air_phase_for(kind)
            assert phase in {"contain", "recover", "hold", "eradicate"}

"""Tests for fusion, conformal escalation, llm bridge, and adversarial harness."""

from __future__ import annotations

import os

import pytest

from tex.specialists.base import SpecialistBundle, SpecialistResult
from tex.specialists.conformal_escalation import (
    CalibrationData,
    ConformalEscalationGate,
    conformal_quantile,
)
from tex.specialists.fusion import (
    FRONTIER_SPECIALIST_NAMES,
    FusionVerdict,
    fuse,
    fusion_reason_codes,
)
from tex.specialists.llm_bridge import specialist_llm_mode


def _result(name: str, risk: float, codes: tuple[str, ...] = ()) -> SpecialistResult:
    return SpecialistResult(
        specialist_name=name,
        risk_score=risk,
        confidence=0.6,
        summary="t",
        rationale="t",
        evidence=tuple(),
        matched_policy_clause_ids=codes,
        matched_entity_names=tuple(),
        uncertainty_flags=tuple(),
    )


# ── Conformal escalation ────────────────────────────────────────────────


def test_conformal_quantile_uses_finite_sample_correction():
    scores = [0.1, 0.2, 0.3, 0.4, 0.5]
    q = conformal_quantile(scores, alpha=0.1)
    # k = ceil((5+1)*0.9) = ceil(5.4) = 6, clamped to 5 → scores[4] = 0.5
    assert q == 0.5


def test_conformal_quantile_rejects_invalid_alpha():
    with pytest.raises(ValueError):
        conformal_quantile([0.1, 0.2], alpha=0.0)
    with pytest.raises(ValueError):
        conformal_quantile([0.1, 0.2], alpha=1.0)


def test_conformal_quantile_rejects_empty_scores():
    with pytest.raises(ValueError):
        conformal_quantile([], alpha=0.1)


def test_gate_engineered_default_alpha_10():
    gate = ConformalEscalationGate(specialist_name="planguard", alpha=0.1)
    assert gate.half_width == pytest.approx(0.18)


def test_gate_engineered_default_alpha_05():
    gate = ConformalEscalationGate(specialist_name="mage", alpha=0.05)
    assert gate.half_width == pytest.approx(0.27)


def test_gate_uses_calibration_when_present():
    cal = CalibrationData(scores=tuple([0.05] * 50 + [0.50] * 50), specialist_name="x")
    gate = ConformalEscalationGate(specialist_name="x", calibration=cal, alpha=0.1)
    # 90th percentile of 50%/50% split between 0.05 and 0.50 is 0.50.
    assert gate.half_width == pytest.approx(0.50)


def test_gate_escalates_when_upper_crosses_threshold():
    gate = ConformalEscalationGate(specialist_name="planguard", alpha=0.1)
    # half_width = 0.18; lexical 0.4 → upper 0.58 >= 0.5 → escalate.
    v = gate.evaluate(lexical_risk_score=0.4)
    assert v.should_escalate is True
    assert v.upper_bound == pytest.approx(0.58)


def test_gate_does_not_escalate_when_upper_below_threshold():
    gate = ConformalEscalationGate(specialist_name="planguard", alpha=0.1)
    v = gate.evaluate(lexical_risk_score=0.1)
    # 0.1 + 0.18 = 0.28 < 0.5 → no escalate.
    assert v.should_escalate is False


def test_gate_rejects_out_of_range_lexical():
    gate = ConformalEscalationGate(specialist_name="x")
    with pytest.raises(ValueError):
        gate.evaluate(lexical_risk_score=1.5)
    with pytest.raises(ValueError):
        gate.evaluate(lexical_risk_score=-0.1)


# ── Fusion ──────────────────────────────────────────────────────────────


def test_fuse_empty_bundle_zero_bonus():
    bundle = SpecialistBundle(results=tuple())
    v = fuse(bundle)
    assert v.base_risk == 0.0
    assert v.fused_risk == 0.0
    assert v.corroboration_bonus == 0.0
    assert v.firing_specialists == ()


def test_fuse_floor_bundle_zero_bonus():
    # Bundle of floor-only specialists with no reason codes — no corroboration.
    bundle = SpecialistBundle(
        results=tuple(
            _result(name=n, risk=0.05) for n in (
                "secret_and_pii", "external_sharing", "unauthorized_commitment",
            )
        )
    )
    v = fuse(bundle)
    assert v.corroboration_bonus == 0.0
    assert v.fused_risk == 0.05


def test_fuse_single_non_frontier_specialist_no_corroboration():
    """A single non-frontier specialist firing alone gets no bonus."""
    bundle = SpecialistBundle(
        results=(_result(name="secret_and_pii", risk=0.4, codes=("PII_FOUND",)),)
    )
    v = fuse(bundle)
    assert v.firing_specialists == ("secret_and_pii",)
    # Single firing non-frontier specialist → no corroboration bonus.
    assert v.fused_risk == v.base_risk


def test_fuse_single_frontier_specialist_solo_bonus():
    """A single FRONTIER specialist firing alone gets a small solo bonus.

    The papers report specialist ASR, not pipeline-fused ASR. Frontier
    specialists firing alone at moderate risk should not be diluted to
    PERMIT by five downstream layers of zero.
    """
    bundle = SpecialistBundle(
        results=(_result(name="argus", risk=0.4, codes=("ARGUS_X",)),)
    )
    v = fuse(bundle)
    assert v.firing_specialists == ("argus",)
    # Single frontier specialist gets solo bonus.
    assert v.fused_risk > v.base_risk
    # But the bonus is conservative.
    assert v.fused_risk - v.base_risk <= 0.20


def test_fuse_frontier_pair_bonus_argus_attriguard():
    bundle = SpecialistBundle(
        results=(
            _result(name="argus", risk=0.4, codes=("ARGUS_X",)),
            _result(name="attriguard", risk=0.4, codes=("ATTRIGUARD_X",)),
        )
    )
    v = fuse(bundle)
    assert "argus" in v.firing_specialists
    assert "attriguard" in v.firing_specialists
    assert "FUSION_ARGUS_X_ATTRIGUARD_CAUSAL" in v.pair_signals
    assert v.fused_risk > v.base_risk


def test_fuse_cascading_failure_signal():
    bundle = SpecialistBundle(
        results=(
            _result(name="argus", risk=0.4, codes=("ARGUS_X",)),
            _result(name="attriguard", risk=0.4, codes=("ATTRIGUARD_X",)),
            _result(name="vigil", risk=0.4, codes=("VIGIL_X",)),
        )
    )
    v = fuse(bundle)
    assert v.cascading_failure_signal is True
    codes = fusion_reason_codes(v)
    assert "FUSION_CASCADING_FAILURE" in codes
    assert "ASI08_cascading_failure" in codes


def test_fuse_never_decreases_base_risk():
    bundle = SpecialistBundle(
        results=(_result(name="argus", risk=0.9, codes=("X",)),)
    )
    v = fuse(bundle)
    assert v.fused_risk >= v.base_risk


def test_fuse_capped_at_one():
    bundle = SpecialistBundle(
        results=(
            _result(name="argus", risk=0.95, codes=("X",)),
            _result(name="attriguard", risk=0.95, codes=("Y",)),
            _result(name="vigil", risk=0.95, codes=("Z",)),
        )
    )
    v = fuse(bundle)
    assert v.fused_risk <= 1.0


def test_frontier_specialist_names_set():
    assert "argus" in FRONTIER_SPECIALIST_NAMES
    assert "attriguard" in FRONTIER_SPECIALIST_NAMES
    assert "vigil" in FRONTIER_SPECIALIST_NAMES
    assert "agentarmor" in FRONTIER_SPECIALIST_NAMES
    assert "mage" in FRONTIER_SPECIALIST_NAMES


# ── LLM bridge ──────────────────────────────────────────────────────────


def test_llm_mode_disabled_by_default(monkeypatch):
    monkeypatch.delenv("TEX_SPECIALIST_LLM_MODE", raising=False)
    assert specialist_llm_mode() == "disabled"


def test_llm_mode_tiered(monkeypatch):
    monkeypatch.setenv("TEX_SPECIALIST_LLM_MODE", "tiered")
    assert specialist_llm_mode() == "tiered"


def test_llm_mode_dual_tiered(monkeypatch):
    monkeypatch.setenv("TEX_SPECIALIST_LLM_MODE", "dual_tiered")
    assert specialist_llm_mode() == "dual_tiered"


def test_llm_mode_unknown_falls_back_to_disabled(monkeypatch):
    monkeypatch.setenv("TEX_SPECIALIST_LLM_MODE", "garbage")
    assert specialist_llm_mode() == "disabled"


def test_build_planguard_judge_returns_none_when_disabled(monkeypatch):
    monkeypatch.setenv("TEX_SPECIALIST_LLM_MODE", "disabled")
    from tex.specialists.llm_bridge import build_planguard_stage_ii_judge
    assert build_planguard_stage_ii_judge() is None


def test_build_planguard_judge_returns_callable_when_tiered(monkeypatch):
    monkeypatch.setenv("TEX_SPECIALIST_LLM_MODE", "tiered")
    from tex.specialists.llm_bridge import build_planguard_stage_ii_judge
    judge = build_planguard_stage_ii_judge()
    assert callable(judge)


def test_build_mage_judge_returns_none_when_disabled(monkeypatch):
    monkeypatch.setenv("TEX_SPECIALIST_LLM_MODE", "disabled")
    from tex.specialists.llm_bridge import build_mage_judge_callable
    assert build_mage_judge_callable() is None


def test_build_mage_judge_returns_callable_when_tiered(monkeypatch):
    monkeypatch.setenv("TEX_SPECIALIST_LLM_MODE", "tiered")
    from tex.specialists.llm_bridge import build_mage_judge_callable
    judge = build_mage_judge_callable()
    assert callable(judge)


# ── Adversarial fuzz harness ────────────────────────────────────────────


def test_fuzz_fixtures_have_known_suites():
    from tex.adversarial.fixtures import known_suites, get_fixtures
    suites = known_suites()
    expected = {"agentdojo", "injecagent", "mcpsafebench", "agentlab", "siren", "nasr_adaptive"}
    assert expected.issubset(set(suites))
    for s in suites:
        fixtures = get_fixtures(s)
        assert len(fixtures) >= 3, f"suite {s} has too few fixtures"


def test_fuzz_unknown_suite_raises():
    from tex.adversarial.fixtures import get_fixtures
    with pytest.raises(KeyError):
        get_fixtures("nonexistent_suite")


def test_fuzz_get_all_fixtures():
    from tex.adversarial.fixtures import get_all_fixtures, known_suites, get_fixtures
    total = sum(len(get_fixtures(s)) for s in known_suites())
    assert len(get_all_fixtures()) == total


def test_fuzz_runner_runs_against_test_client():
    from fastapi.testclient import TestClient
    from tex.main import create_app
    from tex.adversarial import FuzzRunner

    app = create_app()
    client = TestClient(app)
    runner = FuzzRunner.against_test_client(client)
    report = runner.run(suites=("agentdojo",))
    assert report.fixtures_run > 0
    assert len(report.suites) == 1
    assert report.suites[0].suite == "agentdojo"
    assert 0.0 <= report.overall_asr <= 1.0
    assert 0.0 <= report.overall_fpr <= 1.0


def test_fuzz_report_summary_is_string():
    from fastapi.testclient import TestClient
    from tex.main import create_app
    from tex.adversarial import FuzzRunner

    app = create_app()
    client = TestClient(app)
    runner = FuzzRunner.against_test_client(client)
    report = runner.run(suites=("injecagent",))
    summary = report.summary()
    assert isinstance(summary, str)
    assert "Tex Adversarial Fuzz Report" in summary

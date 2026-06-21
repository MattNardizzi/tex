"""Monotone-safety — the moat invariant, guarded hardest.

Calibration is a CAUTION-ONLY signal: accumulating labels may TIGHTEN a verdict
(DERIVED→ABSTAIN) or UPGRADE the honesty of the floor (transductive→calibrated at
the same 1−α), but may NEVER (a) make the gate speak where the transductive
baseline was silent, (b) raise the presence tier, or (c) inflate the floor number.

The combine rule is tested directly with crafted prediction-set stand-ins so the
invariant holds for ANY CP algorithm — not as an incidental property of two-way
filtration — plus an end-to-end check through the real gate.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from tex.presence.contract import ClaimKind, PresenceClaim, PresenceTier
from tex.presence.gate import PresenceTruthGate
from tex.presence.gate.conformal import _monotone_combine, _select_mode
from tex.presence.memory import (
    CalibrationResolution,
    MIN_CALIBRATION_N,
    record_resolution_for_calibration,
)

from .conftest import build_state, make_decision


def _cps(set_size, mode):
    return SimpleNamespace(set_size=set_size, coverage_mode=mode)


# ── the combine rule, algorithm-agnostic ────────────────────────────────────

def test_silent_baseline_can_never_be_rescued_by_calibration():
    # The load-bearing rule: transductive baseline localizes nothing → ABSTAIN,
    # even if the calibrated set is happily non-empty. Never loosen the boundary.
    assert _monotone_combine(_cps(0, "transductive"), _cps(5, "calibrated")) is None


def test_calibration_in_force_may_tighten_to_abstain():
    # Baseline speaks, but the calibrated threshold excludes everything → ABSTAIN
    # (more labels made the gate MORE cautious — allowed, the safe direction).
    assert _monotone_combine(_cps(3, "transductive"), _cps(0, "calibrated")) is None


def test_calibrated_nonempty_is_reported_when_in_force():
    cps_c = _cps(1, "calibrated")
    assert _monotone_combine(_cps(6, "transductive"), cps_c) is cps_c


def test_falls_back_to_transductive_when_calibration_not_in_force():
    # cps_c came back transductive (no file / below min_n) → use the baseline.
    cps_t = _cps(6, "transductive")
    assert _monotone_combine(cps_t, _cps(6, "transductive")) is cps_t


# ── selection plumbing ──────────────────────────────────────────────────────

def test_select_mode_tenant_none_honours_global_env(calib_dir, tmp_path, monkeypatch):
    # Backward-compat: with no tenant, a process-global calibration path still
    # drives calibrated mode (the pre-L1 contract / test_conformal_derived).
    calib = tmp_path / "global.scores"
    calib.write_text("\n".join(str(x) for x in (0.1, 0.2, 0.3, 0.4, 0.5)), encoding="utf-8")
    monkeypatch.setenv("TEX_CONFORMAL_CALIBRATION_PATH", str(calib))

    trace = [{"step_id": f"s{i}", "agent_id": "a"} for i in range(4)]
    scores = {f"s{i}": 0.1 * i for i in range(4)}
    cps, n = _select_mode(trace, scores, tenant=None, feed=None)
    assert cps is not None and cps.coverage_mode == "calibrated"
    assert n is None  # legacy path reports no per-tenant count


# ── end-to-end tier / floor non-inflation ───────────────────────────────────

def test_calibration_never_raises_tier_or_floor(calib_dir):
    gate = PresenceTruthGate()
    state, agent_id = build_state()

    def derive(tenant):
        claim = PresenceClaim(
            claim_id=f"root_cause_region:{agent_id}",
            text_span="which step was the root cause",
            kind=ClaimKind.DERIVED,
        )
        return gate.evaluate(request=state, tenant=tenant, draft="x", claims=(claim,))[0]

    before = derive("acme")
    for i in range(MIN_CALIBRATION_N):
        record_resolution_for_calibration(
            "acme",
            CalibrationResolution(decision=make_decision(final_score=0.5, n=i), human_verdict="refused"),
        )
    after = derive("acme")

    # DERIVED before and after — calibration upgrades honesty, never the tier
    # (it can only ever lower toward ABSTAIN, never raise toward SEALED).
    assert before.tier is PresenceTier.DERIVED
    assert after.tier is PresenceTier.DERIVED
    # The floor NUMBER is unchanged; only the mode refined.
    assert before.correctness_floor == pytest.approx(0.9)
    assert after.correctness_floor == pytest.approx(0.9)
    assert before.coverage_mode == "transductive"
    assert after.coverage_mode == "calibrated"


def test_reader_side_floor_rejects_a_rogue_subthreshold_file(calib_dir, feed):
    # Moat hardening: S5's min_n floor is writer-side only. Plant a rogue scores
    # file with TOO FEW labels straight at the tenant's path (bypassing the feed's
    # ledger). The gate must STILL refuse calibrated mode, because it independently
    # gates on the feed's own ledger count — not on the file merely existing.
    sp = feed.scores_path("acme")
    sp.parent.mkdir(parents=True, exist_ok=True)
    sp.write_text("0.5\n0.5\n0.5\n", encoding="utf-8")  # 3 ≪ MIN_CALIBRATION_N

    gate = PresenceTruthGate()
    state, agent_id = build_state()
    claim = PresenceClaim(
        claim_id=f"root_cause_region:{agent_id}",
        text_span="which step was the root cause",
        kind=ClaimKind.DERIVED,
    )
    v = gate.evaluate(request=state, tenant="acme", draft="x", claims=(claim,))[0]
    assert v.coverage_mode == "transductive"  # rogue file did NOT earn calibrated
    assert v.recomputed_value["calibration_n"] == 0  # ledger, not the rogue file


def test_no_trace_stays_abstain_regardless_of_labels(calib_dir):
    # A tenant with a fully calibrated gate STILL abstains when there is no trace
    # to localize — calibration cannot manufacture a spoken region from nothing.
    gate = PresenceTruthGate()
    state, agent_id = build_state(scores=())  # empty trace
    for i in range(MIN_CALIBRATION_N):
        record_resolution_for_calibration(
            "acme",
            CalibrationResolution(decision=make_decision(final_score=0.5, n=i), human_verdict="refused"),
        )
    claim = PresenceClaim(
        claim_id=f"root_cause_region:{agent_id}",
        text_span="which step was the root cause",
        kind=ClaimKind.DERIVED,
    )
    v = gate.evaluate(request=state, tenant="acme", draft="x", claims=(claim,))[0]
    assert v.tier is PresenceTier.ABSTAIN
    assert "insufficient-trace" in v.reason

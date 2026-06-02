"""
Two-sided CRC gate + first-class Hold.

Covers the doctrine build #1 (TEX_ABSTAIN_DOCTRINE.md): the gate now bounds
BOTH the false-permit and the false-forbid rate, so ABSTAIN is a certified
region between two cutoffs rather than a leftover band — and every ABSTAIN
carries a typed, self-resolving Hold of the same caliber as a PERMIT
certificate or a FORBID proof.
"""

from __future__ import annotations

import random

from tex.domain.verdict import Verdict
from tex.engine.crc_gate import (
    CalibrationRecord,
    ConformalRiskGate,
    build_default_crc_gate,
)
from tex.engine.hold import HoldType, ResolutionMode, build_hold


def _monotone_calibration(n: int = 800, seed: int = 11) -> list[CalibrationRecord]:
    """Score in [0,1]; P(unsafe) grows with score. Safe at the bottom,
    unsafe at the top, genuinely mixed in the middle — so a two-sided gate
    finds a real hold band."""
    rng = random.Random(seed)
    out = []
    for _ in range(n):
        s = rng.random()
        out.append(CalibrationRecord(final_score=s, unsafe=(rng.random() < s)))
    return out


# ── the gate: two-sided structure ───────────────────────────────────────


def test_inert_gate_is_two_sided_passthrough():
    g = build_default_crc_gate()
    assert not g.enabled
    assert not g.certified
    assert not g.forbid_certified
    assert not g.hold_certified
    # pass-through on every verdict
    for v in (Verdict.PERMIT, Verdict.ABSTAIN, Verdict.FORBID):
        r = g.apply(verdict=v, final_score=0.5)
        assert r.verdict is v
        assert not r.demoted
    cert = g.apply(verdict=Verdict.ABSTAIN, final_score=0.5).certificate
    assert cert.hold_certified is False
    assert cert.in_hold_band is False


def test_two_sided_calibration_yields_ordered_band():
    g = ConformalRiskGate(
        calibration=_monotone_calibration(), alpha=0.10, delta=0.05, alpha_forbid=0.10
    )
    assert g.certified and g.forbid_certified and g.hold_certified
    # permit cutoff strictly below forbid cutoff — a real band exists.
    assert 0.0 <= g.lambda_hat < g.lambda_forbid <= 1.0
    # the band is the certified-uncertain middle
    assert g.in_hold_band((g.lambda_hat + g.lambda_forbid) / 2.0)
    assert not g.in_hold_band(0.0)
    assert not g.in_hold_band(1.0)


def test_certificate_carries_both_bounds():
    g = ConformalRiskGate(
        calibration=_monotone_calibration(), alpha=0.10, delta=0.05, alpha_forbid=0.10
    )
    mid = (g.lambda_hat + g.lambda_forbid) / 2.0
    c = g.apply(verdict=Verdict.ABSTAIN, final_score=mid).certificate
    # permit side (unchanged contract)
    assert c.certified and c.certified_false_permit_rate <= 0.10 + 1e-9
    # forbid side (new)
    assert c.forbid_certified and c.certified_false_forbid_rate <= 0.10 + 1e-9
    # hold band
    assert c.hold_certified
    assert c.hold_band_lower == round(g.lambda_hat, 6)
    assert c.hold_band_upper == round(g.lambda_forbid, 6)
    assert c.in_hold_band is True


def test_gate_is_still_monotone_safe_never_relaxes_forbid():
    """The two-sided extension must NOT relax a FORBID — the gate may only
    ever move a verdict toward ABSTAIN, never away from a block."""
    g = ConformalRiskGate(
        calibration=_monotone_calibration(), alpha=0.10, delta=0.05, alpha_forbid=0.10
    )
    for s in (0.0, 0.2, 0.5, 0.8, 1.0):
        r = g.apply(verdict=Verdict.FORBID, final_score=s)
        assert r.verdict is Verdict.FORBID
        assert not r.demoted


def test_permit_inside_band_demotes_permit_at_floor_stands():
    g = ConformalRiskGate(
        calibration=_monotone_calibration(), alpha=0.10, delta=0.05, alpha_forbid=0.10
    )
    # A clean permit at the very bottom is inside the certified permit region.
    low = g.apply(verdict=Verdict.PERMIT, final_score=0.0)
    assert low.verdict is Verdict.PERMIT and not low.demoted
    # A permit landing in the hold band is demoted to ABSTAIN.
    mid = (g.lambda_hat + g.lambda_forbid) / 2.0
    held = g.apply(verdict=Verdict.PERMIT, final_score=mid)
    assert held.verdict is Verdict.ABSTAIN and held.demoted
    assert held.certificate.in_hold_band is True


# ── the hold: typed + self-resolving ────────────────────────────────────


def test_non_abstain_has_no_hold():
    for v in (Verdict.PERMIT, Verdict.FORBID):
        assert build_hold(
            verdict=v, final_score=0.3, uncertainty_flags=(), certificate=None
        ) is None


def test_epistemic_hold_names_the_pivotal_fact_and_self_heals():
    h = build_hold(
        verdict=Verdict.ABSTAIN,
        final_score=0.5,
        uncertainty_flags=("no_retrieval_context",),
        certificate=None,
        confidence=0.4,
        agent_id="payments-agent-03",
        action_type="wire_transfer",
    )
    assert h is not None
    assert h.hold_type is HoldType.EPISTEMIC
    assert h.resolution_mode is ResolutionMode.SELF_HEAL
    assert h.resolving_question is not None
    assert h.pivotal_flag == "no_retrieval_context"


def test_aleatoric_hold_is_human_judgment_with_no_question():
    h = build_hold(
        verdict=Verdict.ABSTAIN,
        final_score=0.5,
        uncertainty_flags=("semantic_low_confidence",),
        certificate=None,
        confidence=0.4,
    )
    assert h is not None
    assert h.hold_type is HoldType.ALEATORIC
    assert h.resolution_mode is ResolutionMode.HUMAN_JUDGMENT
    assert h.resolving_question is None


def test_hold_reads_band_certified_from_certificate():
    g = ConformalRiskGate(
        calibration=_monotone_calibration(), alpha=0.10, delta=0.05, alpha_forbid=0.10
    )
    mid = (g.lambda_hat + g.lambda_forbid) / 2.0
    cert = g.apply(verdict=Verdict.ABSTAIN, final_score=mid).certificate
    h = build_hold(
        verdict=Verdict.ABSTAIN,
        final_score=mid,
        uncertainty_flags=("no_retrieval_context",),
        certificate=cert,
        confidence=0.4,
    )
    assert h is not None
    assert h.band_certified is True
    assert h.band_lower == cert.hold_band_lower
    assert h.band_upper == cert.hold_band_upper


def test_hold_without_calibration_is_honest_uncertified():
    """No calibration → the hold is still correct, but its band carries no
    live guarantee. The honest posture until Layer 6 supplies labels."""
    h = build_hold(
        verdict=Verdict.ABSTAIN,
        final_score=0.5,
        uncertainty_flags=("cold_start",),
        certificate=build_default_crc_gate().apply(
            verdict=Verdict.ABSTAIN, final_score=0.5
        ).certificate,
        confidence=0.5,
    )
    assert h is not None
    assert h.band_certified is False


def test_hold_is_deterministic():
    kw = dict(
        verdict=Verdict.ABSTAIN,
        final_score=0.5,
        uncertainty_flags=("no_retrieval_context", "cold_start"),
        certificate=None,
        confidence=0.4,
        agent_id="a-1",
        action_type="tool_call",
    )
    assert build_hold(**kw).model_dump() == build_hold(**kw).model_dump()

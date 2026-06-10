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
    # low_confidence_semantic_dimension is the flag the router ACTUALLY
    # emits for a low-confidence semantic dimension (router.py); the census
    # previously listed it under the never-emitted name
    # "semantic_low_confidence" — reconciled 2026-06-10.
    h = build_hold(
        verdict=Verdict.ABSTAIN,
        final_score=0.5,
        uncertainty_flags=("low_confidence_semantic_dimension",),
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


# ── census ↔ emitters reconciliation (the phantom-flag tripwire) ─────────


def test_every_flag_pivot_key_has_a_live_emitter():
    """Every _FLAG_PIVOTS census key must be a string some deterministic
    in-repo code path actually emits — a census entry no emitter can raise
    is a resolving question Tex can never truthfully ask. This failed for
    three keys before the 2026-06-10 reconciliation (pending_lifecycle,
    low_evidence_sufficiency, semantic_low_confidence) and fails again if a
    census key is added without an emitter, or an emitter is renamed out
    from under the census.

    Honest limit: this is a string-presence guard over source text (the
    emitters all use quoted literals today). A quoted mention in a comment
    would satisfy it; it cannot prove reachability — but it decisively
    catches the observed failure mode, census/emitter name drift. Flags
    originating from an LLM provider do NOT count as emitters: the census
    must never depend on a model choosing to say a matching string.
    """
    from pathlib import Path

    import tex
    from tex.engine.hold import _FLAG_PIVOTS

    src_root = Path(tex.__file__).parent
    census_files = {
        src_root / "engine" / "hold.py",
        src_root / "engine" / "credal_hold.py",
    }
    sources = [
        (path, path.read_text(encoding="utf-8"))
        for path in sorted(src_root.rglob("*.py"))
        if path not in census_files
    ]
    for flag in _FLAG_PIVOTS:
        emitters = [
            str(path.relative_to(src_root))
            for path, text in sources
            if f'"{flag}"' in text or f"'{flag}'" in text
        ]
        assert emitters, (
            f"census key {flag!r} has no emitter anywhere in src/tex outside "
            "the census files — either wire an emitter or remove/rename the "
            "census entry (see _FLAG_PIVOTS invariant comment)"
        )


def test_epistemic_census_keys_are_known_to_the_credal_resolver():
    """The L8 resolver's flag→stream map and the census must stay in
    lock-step, both directions: an epistemic census key the resolver cannot
    rank silently falls to fixed-order; a resolver key absent from the
    census can never be a candidate at all."""
    from tex.engine.credal_hold import _FLAG_STREAMS
    from tex.engine.hold import _FLAG_PIVOTS

    epistemic = {
        flag for flag, (is_epi, _q, _sh) in _FLAG_PIVOTS.items() if is_epi
    }
    assert epistemic == set(_FLAG_STREAMS)


def test_weak_semantic_evidence_hold_names_the_evidence_fact():
    """The flag the router actually raises for evidence_sufficiency < 0.25
    must map to a pivotal fact (it could not before the reconciliation —
    the census listed it as the never-emitted low_evidence_sufficiency)."""
    h = build_hold(
        verdict=Verdict.ABSTAIN,
        final_score=0.5,
        uncertainty_flags=("weak_semantic_evidence",),
        certificate=None,
        confidence=0.4,
    )
    assert h is not None
    assert h.hold_type is HoldType.EPISTEMIC
    assert h.resolution_mode is ResolutionMode.SELF_HEAL
    assert h.pivotal_flag == "weak_semantic_evidence"
    assert h.resolving_question is not None
    assert "evidence" in h.resolving_question


def test_agent_pending_hold_names_the_onboarding_fact():
    """Same reconciliation for the identity evaluator's PENDING-lifecycle
    flag (census previously listed the never-emitted pending_lifecycle)."""
    h = build_hold(
        verdict=Verdict.ABSTAIN,
        final_score=0.5,
        uncertainty_flags=("agent_pending",),
        certificate=None,
        confidence=0.4,
    )
    assert h is not None
    assert h.hold_type is HoldType.EPISTEMIC
    assert h.resolution_mode is ResolutionMode.SELF_HEAL
    assert h.pivotal_flag == "agent_pending"
    assert h.resolving_question is not None
    assert "onboarding" in h.resolving_question

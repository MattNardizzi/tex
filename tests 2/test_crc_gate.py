"""
Tests for the Conformal Risk Control verdict gate (engine/crc_gate.py).

Covers the three hard contracts:
  1. determinism (same calibration -> same cutoff; pure comparison at apply)
  2. monotone-safety (only ever more conservative: PERMIT->ABSTAIN, never relax)
  3. the finite-sample bound (UCB validity, calibration picks the most
     permissive certifiable cutoff, fail-closed when nothing certifiable)
"""

from __future__ import annotations

import random

from tex.domain.verdict import Verdict
from tex.engine.crc_gate import (
    CalibrationRecord,
    ConformalRiskGate,
    build_default_crc_gate,
    bentkus_ucb,
    hoeffding_bentkus_ucb,
    hoeffding_ucb,
)


# ── concentration bounds ────────────────────────────────────────────────


def test_hoeffding_ucb_upper_bounds_and_is_in_unit_interval() -> None:
    u = hoeffding_ucb(r_hat=0.1, n=200, delta=0.05)
    assert 0.1 <= u <= 1.0


def test_bentkus_tighter_than_hoeffding_in_low_risk_regime() -> None:
    # In the small-empirical-risk regime, Bentkus should be no looser.
    h = hoeffding_ucb(r_hat=0.0, n=300, delta=0.05)
    b = bentkus_ucb(r_hat=0.0, n=300, delta=0.05)
    assert b <= h + 1e-9


def test_hoeffding_bentkus_is_the_min() -> None:
    hb = hoeffding_bentkus_ucb(r_hat=0.02, n=250, delta=0.05)
    h = hoeffding_ucb(r_hat=0.02, n=250, delta=0.05)
    b = bentkus_ucb(r_hat=0.02, n=250, delta=0.05)
    assert hb == min(h, b)


def test_ucb_shrinks_as_n_grows() -> None:
    small = hoeffding_bentkus_ucb(r_hat=0.05, n=50, delta=0.05)
    large = hoeffding_bentkus_ucb(r_hat=0.05, n=2000, delta=0.05)
    assert large < small


# ── inert (default) gate ────────────────────────────────────────────────


def test_default_gate_is_inert_and_passes_through() -> None:
    gate = build_default_crc_gate()
    assert gate.enabled is False
    for v in (Verdict.PERMIT, Verdict.ABSTAIN, Verdict.FORBID):
        res = gate.apply(verdict=v, final_score=0.99)
        assert res.verdict is v
        assert res.demoted is False
        assert res.certificate.enabled is False
        assert res.certificate.certified is False
        assert res.certificate.certified_false_permit_rate == 1.0


# ── calibration picks the most permissive certifiable cutoff ────────────


def _well_separated_calibration(n: int = 400) -> list[CalibrationRecord]:
    """Unsafe items score high, safe items score low — cleanly separable."""
    rng = random.Random(7)
    recs: list[CalibrationRecord] = []
    for _ in range(n // 2):
        recs.append(CalibrationRecord(final_score=rng.uniform(0.0, 0.30), unsafe=False))
    for _ in range(n // 2):
        recs.append(CalibrationRecord(final_score=rng.uniform(0.70, 1.0), unsafe=True))
    return recs


def test_calibration_finds_cutoff_on_separable_data() -> None:
    gate = ConformalRiskGate(
        calibration=_well_separated_calibration(), alpha=0.05, delta=0.05
    )
    assert gate.enabled is True
    assert gate.certified is True
    # The cutoff should sit in the separating band: above the safe items
    # (<=0.30) and not far into the unsafe mass. The finite-sample UCB pushes
    # it slightly past the raw 0.70 gap, which is correct behaviour.
    assert 0.30 <= gate.lambda_hat <= 0.80
    # The bound it certifies must respect the risk budget.
    assert gate.certificate_template().certified_false_permit_rate <= 0.05 + 1e-9


def test_certified_permit_within_region() -> None:
    gate = ConformalRiskGate(calibration=_well_separated_calibration())
    res = gate.apply(verdict=Verdict.PERMIT, final_score=0.10)
    assert res.verdict is Verdict.PERMIT
    assert res.demoted is False
    assert res.certificate.certified is True
    assert res.certificate.certified_false_permit_rate <= 0.05 + 1e-9


def test_permit_outside_region_is_demoted_to_abstain() -> None:
    gate = ConformalRiskGate(calibration=_well_separated_calibration())
    # A score above the cutoff: the router said PERMIT but it isn't certifiable.
    res = gate.apply(verdict=Verdict.PERMIT, final_score=0.95)
    assert res.verdict is Verdict.ABSTAIN
    assert res.demoted is True
    assert "crc_permit_region_exceeded" in res.uncertainty_flags


# ── monotone-safety: never relaxes a non-permit ─────────────────────────


def test_gate_never_relaxes_forbid_or_abstain() -> None:
    gate = ConformalRiskGate(calibration=_well_separated_calibration())
    for v in (Verdict.FORBID, Verdict.ABSTAIN):
        # Even a tiny score (deep in the certified region) must not promote.
        res = gate.apply(verdict=v, final_score=0.0)
        assert res.verdict is v
        assert res.demoted is False


# ── fail-closed when nothing is certifiable ─────────────────────────────


def test_uncertifiable_calibration_demotes_all_permits() -> None:
    # Unsafe items scattered across the whole score range — no cutoff (even 0)
    # can bound the false-permit rate at alpha=0.01. Gate must fail closed:
    # every PERMIT becomes ABSTAIN.
    rng = random.Random(3)
    recs = [
        CalibrationRecord(final_score=rng.uniform(0.0, 1.0), unsafe=(i % 2 == 0))
        for i in range(200)
    ]
    gate = ConformalRiskGate(calibration=recs, alpha=0.01, delta=0.05)
    res = gate.apply(verdict=Verdict.PERMIT, final_score=0.0)
    assert res.verdict is Verdict.ABSTAIN
    assert res.demoted is True
    assert res.certificate.certified is False


# ── determinism ─────────────────────────────────────────────────────────


def test_calibration_is_deterministic() -> None:
    cal = _well_separated_calibration()
    g1 = ConformalRiskGate(calibration=cal, alpha=0.05, delta=0.05)
    g2 = ConformalRiskGate(calibration=list(cal), alpha=0.05, delta=0.05)
    assert g1.lambda_hat == g2.lambda_hat
    assert g1.certificate_template().model_dump() == g2.certificate_template().model_dump()


def test_apply_is_pure_repeatable() -> None:
    gate = ConformalRiskGate(calibration=_well_separated_calibration())
    a = gate.apply(verdict=Verdict.PERMIT, final_score=0.5)
    b = gate.apply(verdict=Verdict.PERMIT, final_score=0.5)
    assert a.verdict is b.verdict
    assert a.certificate.model_dump() == b.certificate.model_dump()


# ── tighter budget => no looser cutoff (more conservative) ──────────────


def test_smaller_alpha_gives_no_more_permissive_cutoff() -> None:
    cal = _well_separated_calibration()
    loose = ConformalRiskGate(calibration=cal, alpha=0.10, delta=0.05)
    tight = ConformalRiskGate(calibration=cal, alpha=0.01, delta=0.05)
    # Tighter risk budget cannot yield a MORE permissive (higher) cutoff.
    assert tight.lambda_hat <= loose.lambda_hat + 1e-9

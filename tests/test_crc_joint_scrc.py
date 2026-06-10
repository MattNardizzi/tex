"""
LTT joint two-sided certificate + epsilon-collar + SCRC acted-set conditioning
(engine/crc_gate.py).

These pin the three upgrades that replace the two independent per-delta sweeps:

  1. the JOINT certificate splits the family-wise budget across the two sides,
     so the two-sided hold guarantee is honest at 1 - delta (not 1 - 2*delta);
  2. the epsilon-collar only ever SHRINKS the certified regions (widening the
     hold band) — it can never relax a verdict;
  3. the SCRC acted-set risk ("unsafe among emitted PERMITs") is always
     surfaced, and gating on it (risk_estimand="selective") is strictly more
     conservative than the marginal cutoff.

Every assertion is an inequality in the SAFE (more-conservative) direction —
nothing here can make the gate release more.
"""

from __future__ import annotations

import random

from tex.domain.verdict import Verdict
from tex.engine.crc_gate import CalibrationRecord, ConformalRiskGate


def _separable(n: int = 400, seed: int = 5) -> list[CalibrationRecord]:
    rng = random.Random(seed)
    recs: list[CalibrationRecord] = []
    for _ in range(n // 2):
        recs.append(CalibrationRecord(final_score=rng.uniform(0.0, 0.30), unsafe=False))
    for _ in range(n // 2):
        recs.append(CalibrationRecord(final_score=rng.uniform(0.70, 1.0), unsafe=True))
    return recs


def _monotone(n: int = 400, seed: int = 9) -> list[CalibrationRecord]:
    """P(unsafe) grows with score — overlapping, so the permit region carries a
    real unsafe fraction and selective > marginal. (n + grid kept modest: the
    Bentkus UCB uses an exact binomial CDF whose cost grows with n.)"""
    rng = random.Random(seed)
    out: list[CalibrationRecord] = []
    for _ in range(n):
        s = rng.random()
        out.append(CalibrationRecord(final_score=s, unsafe=(rng.random() < s)))
    return out


# All gates in this module use a coarse grid: 0.01 resolution is plenty for the
# inequality assertions here and keeps the exact-binomial Bentkus cost low.
_GRID = 101


# ── LTT joint: the family-wise budget is split and reported ──────────────


def test_joint_delta_is_split_across_the_two_families() -> None:
    g = ConformalRiskGate(calibration=_separable(), alpha=0.05, delta=0.05, grid_size=_GRID)
    c = g.apply(verdict=Verdict.ABSTAIN, final_score=0.5).certificate
    # Default symmetric split.
    assert abs(c.delta_permit - 0.025) < 1e-9
    assert abs(c.delta_forbid - 0.025) < 1e-9
    # The joint failure probability of the two-sided claim is their sum.
    assert abs(c.joint_delta - (c.delta_permit + c.delta_forbid)) < 1e-9
    assert abs(c.joint_delta - 0.05) < 1e-9


def test_asymmetric_split_is_honoured() -> None:
    g = ConformalRiskGate(
        calibration=_separable(), alpha=0.05, delta=0.06, delta_split=0.25, grid_size=_GRID
    )
    c = g.apply(verdict=Verdict.ABSTAIN, final_score=0.5).certificate
    assert abs(c.delta_permit - 0.015) < 1e-9  # 0.06 * 0.25
    assert abs(c.delta_forbid - 0.045) < 1e-9  # 0.06 * 0.75
    assert abs(c.joint_delta - 0.06) < 1e-9


# ── epsilon-collar only ever shrinks the certified regions ───────────────


def test_collar_shrinks_permit_and_widens_band() -> None:
    cal = _monotone()
    tight = ConformalRiskGate(
        calibration=cal, alpha=0.15, delta=0.10, epsilon_collar=0.0, grid_size=_GRID
    )
    collared = ConformalRiskGate(
        calibration=cal, alpha=0.15, delta=0.10, epsilon_collar=0.05, grid_size=_GRID
    )
    # Permit cutoff lowered, forbid cutoff raised → strictly safer, wider band.
    assert collared.lambda_hat <= tight.lambda_hat
    assert collared.lambda_forbid >= tight.lambda_forbid


def test_collar_default_is_one_grid_step() -> None:
    g = ConformalRiskGate(calibration=_separable(), alpha=0.05, delta=0.05, grid_size=_GRID)
    c = g.apply(verdict=Verdict.ABSTAIN, final_score=0.5).certificate
    assert abs(c.epsilon_collar - 1.0 / (_GRID - 1)) < 1e-9


def test_collar_can_only_demote_never_relax() -> None:
    cal = _separable()
    g = ConformalRiskGate(
        calibration=cal, alpha=0.05, delta=0.05, epsilon_collar=0.10, grid_size=_GRID
    )
    # The collar can never turn a FORBID/ABSTAIN into PERMIT.
    for v in (Verdict.FORBID, Verdict.ABSTAIN):
        for s in (0.0, 0.5, 1.0):
            assert g.apply(verdict=v, final_score=s).verdict is v


# ── SCRC: acted-set rate is always surfaced; selective gate is stricter ──


def test_acted_set_rate_is_always_on_the_certificate() -> None:
    g = ConformalRiskGate(calibration=_separable(), alpha=0.05, delta=0.05, grid_size=_GRID)
    c = g.apply(verdict=Verdict.PERMIT, final_score=0.05).certificate
    # Even in the default marginal mode, the operator sees the acted-set risk
    # and the acted-permit denominator.
    assert 0.0 <= c.acted_set_false_permit_rate <= 1.0
    assert c.n_acted_permit > 0
    assert c.risk_estimand == "marginal"


def test_selective_cutoff_is_no_more_permissive_than_marginal() -> None:
    cal = _monotone()
    marginal = ConformalRiskGate(
        calibration=cal, alpha=0.25, delta=0.10, grid_size=_GRID, risk_estimand="marginal"
    )
    selective = ConformalRiskGate(
        calibration=cal, alpha=0.25, delta=0.10, grid_size=_GRID, risk_estimand="selective"
    )
    assert marginal.certified and selective.certified
    # SCRC measures the harder quantity (unsafe AMONG permits), so its certified
    # permit region can only be smaller — a strictly more conservative cutoff.
    assert selective.lambda_hat <= marginal.lambda_hat + 1e-9


def test_selective_rate_dominates_marginal_rate() -> None:
    # A calibration set whose permit region carries a real unsafe fraction:
    # the acted-set (selective) rate must be >= the marginal rate.
    cal = _monotone()
    g = ConformalRiskGate(
        calibration=cal, alpha=0.25, delta=0.10, grid_size=_GRID, risk_estimand="selective"
    )
    c = g.apply(verdict=Verdict.PERMIT, final_score=0.0).certificate
    assert c.acted_set_false_permit_rate + 1e-9 >= c.empirical_false_permit_rate


def test_selective_gate_still_fail_closed_when_uncertifiable() -> None:
    # Random labels: neither marginal nor selective can certify at a tight
    # budget → fail closed, every PERMIT demoted.
    rng = random.Random(3)
    recs = [
        CalibrationRecord(final_score=rng.uniform(0.0, 1.0), unsafe=(i % 2 == 0))
        for i in range(200)
    ]
    g = ConformalRiskGate(
        calibration=recs, alpha=0.01, delta=0.05, grid_size=_GRID, risk_estimand="selective"
    )
    assert g.certified is False
    res = g.apply(verdict=Verdict.PERMIT, final_score=0.0)
    assert res.verdict is Verdict.ABSTAIN and res.demoted is True


def test_invalid_risk_estimand_rejected() -> None:
    import pytest

    with pytest.raises(ValueError):
        ConformalRiskGate(calibration=_separable(), risk_estimand="bogus")

"""
The trust invariant, made into a test that FAILS if it ever breaks.

CLAUDE.md / the doctrine: probabilistic signals may only ever move a verdict
TOWARD caution (PERMIT → ABSTAIN → FORBID), never the reverse; the structural
floor (specialist DENY → FORBID) is deterministic and a high *probabilistic*
score must NOT fire it. This file pins both, across the abstain track's whole
surface (the CRC gate, the router, the structural floor) and through the PDP.

Caution order: PERMIT (0) < ABSTAIN (1) < FORBID (2). "Lower a verdict" means
RAISE its caution. Every assertion here is: caution(out) >= caution(in) — a
change can only make Tex more careful, never less.
"""

from __future__ import annotations

import random

from tex.domain.verdict import Verdict
from tex.engine.crc_gate import CalibrationRecord, ConformalRiskGate
from tex.engine.router import DecisionRouter
from tex.specialists.base import SpecialistBundle, SpecialistResult
from tex.specialists.structural_floor import detect_structural_floor

from tests.factories import make_default_policy, make_semantic_analysis, make_gate_result


_CAUTION = {Verdict.PERMIT: 0, Verdict.ABSTAIN: 1, Verdict.FORBID: 2}


def _mixed_calibration(n: int = 300, seed: int = 1) -> list[CalibrationRecord]:
    rng = random.Random(seed)
    return [
        CalibrationRecord(final_score=rng.random(), unsafe=(rng.random() < rng.random()))
        for _ in range(n)
    ]


# ── A. the CRC gate can only ever raise caution, never lower it ──────────


def test_crc_gate_never_relaxes_across_all_knobs() -> None:
    """Whatever the estimand / collar / split, the gate maps PERMIT to
    {PERMIT, ABSTAIN} and passes ABSTAIN/FORBID through unchanged — it never
    manufactures a PERMIT and never relaxes a block. This is the load-bearing
    monotone-lowering property; if a future edit lets the gate promote, this
    fails."""
    cal = _mixed_calibration()
    scores = [i / 20 for i in range(21)]
    for estimand in ("marginal", "selective"):
        for collar in (0.0, 0.02, 0.10):
            for alpha in (0.05, 0.20):
                gate = ConformalRiskGate(
                    calibration=cal,
                    alpha=alpha,
                    delta=0.10,
                    epsilon_collar=collar,
                    risk_estimand=estimand,
                    grid_size=101,
                )
                for v in (Verdict.PERMIT, Verdict.ABSTAIN, Verdict.FORBID):
                    for s in scores:
                        out = gate.apply(verdict=v, final_score=s).verdict
                        # Never less cautious than the input.
                        assert _CAUTION[out] >= _CAUTION[v], (
                            f"gate relaxed {v}->{out} at score={s} "
                            f"estimand={estimand} collar={collar} alpha={alpha}"
                        )
                        # Non-PERMIT inputs are never altered at all.
                        if v is not Verdict.PERMIT:
                            assert out is v
                        # A PERMIT can only stay PERMIT or become ABSTAIN.
                        else:
                            assert out in (Verdict.PERMIT, Verdict.ABSTAIN)


def test_crc_permit_only_survives_inside_the_certified_region() -> None:
    # A high score can only ever demote a PERMIT; it can never be the thing
    # that *creates* one (a high probabilistic score must not relax the gate).
    gate = ConformalRiskGate(
        calibration=_mixed_calibration(), alpha=0.05, delta=0.05, grid_size=101
    )
    high = gate.apply(verdict=Verdict.PERMIT, final_score=0.99)
    assert high.verdict is Verdict.ABSTAIN  # demoted, never kept
    assert _CAUTION[high.verdict] >= _CAUTION[Verdict.PERMIT]


# ── B. the router: a rising probabilistic signal only raises caution ─────


def test_router_caution_is_monotone_in_specialist_risk() -> None:
    """Hold everything else neutral and sweep the specialist risk (a purely
    probabilistic signal) upward. The verdict's caution must be non-decreasing
    — a stronger risk signal can never yield a MORE permissive verdict."""
    router = DecisionRouter()
    policy = make_default_policy()
    last_caution = -1
    prev_risk = -1.0
    for i in range(0, 101):
        risk = i / 100.0
        bundle = SpecialistBundle(
            results=(
                SpecialistResult(
                    specialist_name="genericprob",
                    risk_score=risk,
                    confidence=0.75,
                    summary="x",
                    matched_policy_clause_ids=(),
                ),
            )
        )
        result = router.route(
            deterministic_result=make_gate_result(),
            specialist_bundle=bundle,
            semantic_analysis=make_semantic_analysis(
                recommended_verdict=Verdict.PERMIT,
                recommended_confidence=0.85,
                overall_confidence=0.85,
                dimension_confidence=0.80,
                evidence_sufficiency=0.60,
            ),
            policy=policy,
            action_type="sales_email",
            channel="email",
            environment="production",
        )
        caution = _CAUTION[result.verdict]
        assert caution >= last_caution, (
            f"router relaxed: risk {prev_risk}->{risk} dropped caution "
            f"{last_caution}->{caution}"
        )
        last_caution = caution
        prev_risk = risk


# ── C. the structural floor: deterministic DENY fires; high prob does not ─


def _spec(name: str, risk: float, clauses=()) -> SpecialistResult:
    return SpecialistResult(
        specialist_name=name,
        risk_score=risk,
        confidence=1.0,
        summary="x",
        matched_policy_clause_ids=tuple(clauses),
    )


def test_structural_floor_fires_on_deny_not_on_high_probability() -> None:
    # A deterministic deny SIGNATURE fires the floor...
    deny = SpecialistBundle(results=(_spec("pcas", 1.0, ("deny:exfiltrate",)),))
    assert detect_structural_floor(deny).fired is True
    # ...but a merely high PROBABILISTIC score (no deny signature) must not.
    for risk in (0.60, 0.80, 0.99, 1.0):
        high = SpecialistBundle(results=(_spec("mage", risk, ("ASI08",)),))
        assert detect_structural_floor(high).fired is False, (
            f"probabilistic score {risk} wrongly fired the structural floor"
        )

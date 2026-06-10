"""
Pro2Guard predictive ABSTAIN dimension (systemic.probguard PDP wiring).

Reference: Pro2Guard, "Proactive Runtime Enforcement of LLM Agent Safety via
Probabilistic Model Checking" (arXiv:2508.00500).

The two invariants that make a probabilistic lookahead safe to wire onto a live
verdict are tested here directly:
  1. monotone-lowering — it only ever demotes a PERMIT to ABSTAIN;
  2. determinism — identical request metadata yields an identical outcome.
"""

from __future__ import annotations

from tex.domain.finding import Finding
from tex.domain.severity import Severity
from tex.domain.verdict import Verdict
from tex.engine.router import RoutingResult
from tex.systemic.probguard import (
    SYSTEMIC_LOOKAHEAD_FLAG,
    abstract_features,
    apply_predictive_holds,
    evaluate_systemic_lookahead,
)

from tests.factories import make_request


def _routing(verdict: Verdict, *, score: float = 0.1) -> RoutingResult:
    return RoutingResult(verdict=verdict, confidence=0.9, final_score=score)


def _lookahead_md(compromise: float, *, threshold: float = 0.5) -> dict:
    return {
        "systemic_lookahead": {
            "agent_count": 5,
            "capability_grant_rate": 2.0,
            "compromise_ratio": compromise,
            "threshold": threshold,
            "horizon_k": 10,
        }
    }


# ── the lookahead score itself ──────────────────────────────────────────


def test_unsafe_state_reachability_exceeds_threshold() -> None:
    req = make_request(metadata=_lookahead_md(0.9))  # high-compromise band = unsafe
    out = evaluate_systemic_lookahead(req)
    assert out.checked is True
    assert out.initial_state.endswith("compromise_high")
    assert out.predictive_risk == 1.0  # unsafe state is absorbing
    assert out.exceeds is True


def test_safe_state_cold_start_below_threshold() -> None:
    req = make_request(metadata=_lookahead_md(0.05))
    out = evaluate_systemic_lookahead(req)
    assert out.exceeds is False
    assert out.predictive_risk < 0.5


def test_lookahead_is_deterministic() -> None:
    req = make_request(metadata=_lookahead_md(0.3))
    a = evaluate_systemic_lookahead(req)
    b = evaluate_systemic_lookahead(req)
    assert a == b  # pure function of metadata, no global mutation


def test_no_metadata_is_neutral() -> None:
    assert evaluate_systemic_lookahead(make_request()).checked is False


def test_abstract_features_matches_band_structure() -> None:
    assert abstract_features(
        agent_count=1, capability_grant_rate=0.0, compromise_ratio=0.9
    ).endswith("compromise_high")


def test_cold_start_safe_state_reachability_under_0_10() -> None:
    """Pins the self_loop_prior=50.0 calibration claim made in probguard.py:
    cold-start reachability from a clearly-safe state at k=10 is < 0.10
    (the existing test_probguard.py guards only the looser < 0.20)."""
    from tex.systemic.probguard import DTMCModel, reachability_probability

    safe = abstract_features(
        agent_count=1, capability_grant_rate=0.1, compromise_ratio=0.05
    )
    risk = reachability_probability(
        model=DTMCModel(), initial_state=safe, horizon_k=10
    )
    assert risk < 0.10, f"cold-start safe-state reachability {risk} exceeds 0.10"


# ── the monotone-lowering invariant (load-bearing) ──────────────────────


def test_permit_demoted_to_abstain_on_high_lookahead() -> None:
    req = make_request(metadata=_lookahead_md(0.9))
    out = apply_predictive_holds(base=_routing(Verdict.PERMIT), request=req)
    assert out.verdict is Verdict.ABSTAIN
    assert SYSTEMIC_LOOKAHEAD_FLAG in out.uncertainty_flags
    assert out.scores.get("systemic_lookahead") == 1.0


def test_permit_untouched_when_lookahead_safe() -> None:
    req = make_request(metadata=_lookahead_md(0.05))
    out = apply_predictive_holds(base=_routing(Verdict.PERMIT), request=req)
    assert out.verdict is Verdict.PERMIT


def test_forbid_is_never_touched_by_lookahead() -> None:
    # A probabilistic signal must NEVER raise/relax a FORBID, even at risk 1.0.
    req = make_request(metadata=_lookahead_md(0.9))
    base = _routing(Verdict.FORBID, score=1.0)
    out = apply_predictive_holds(base=base, request=req)
    assert out is base  # returned unchanged, identity-preserved


def test_abstain_is_never_touched_by_lookahead() -> None:
    req = make_request(metadata=_lookahead_md(0.9))
    base = _routing(Verdict.ABSTAIN, score=0.5)
    out = apply_predictive_holds(base=base, request=req)
    assert out is base


def test_lookahead_never_creates_a_permit() -> None:
    # There is no input under which apply_predictive_holds yields PERMIT from a
    # non-PERMIT base, nor demotes toward PERMIT.
    req = make_request(metadata=_lookahead_md(0.9))
    for v in (Verdict.FORBID, Verdict.ABSTAIN):
        assert apply_predictive_holds(base=_routing(v), request=req).verdict is v

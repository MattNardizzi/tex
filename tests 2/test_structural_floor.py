"""
Tests for the structural FORBID floor (specialists/structural_floor.py) and its
PDP wiring.

The headline test is ``test_pcas_deny_now_forbids_not_abstains`` — the exact
tier-inversion bug the floor exists to fix: a deterministic PCAS deny on
otherwise-clean content used to dilute through the router's weighted sum to
ABSTAIN; it must now FORBID.
"""

from __future__ import annotations

from tex.domain.evaluation import EvaluationRequest
from tex.domain.retrieval import RetrievalContext
from tex.domain.verdict import Verdict
from tex.engine.pdp import PolicyDecisionPoint
from tex.specialists.base import SpecialistBundle, SpecialistResult
from tex.specialists.structural_floor import detect_structural_floor

from tests.factories import make_default_policy, make_request


# ── detector unit tests ─────────────────────────────────────────────────


def _result(name: str, risk: float, clauses=()) -> SpecialistResult:
    return SpecialistResult(
        specialist_name=name,
        risk_score=risk,
        confidence=1.0,
        summary="x",
        matched_policy_clause_ids=tuple(clauses),
    )


def test_pcas_deny_fires_floor() -> None:
    bundle = SpecialistBundle(results=(_result("pcas", 1.0, ("deny:toxic_flow",)),))
    out = detect_structural_floor(bundle)
    assert out.fired is True
    assert "pcas" in out.denying_specialists


def test_pcas_abstain_does_not_fire() -> None:
    # PCAS ABSTAIN maps to risk 0.5 — not a deny, must not fire the floor.
    bundle = SpecialistBundle(results=(_result("pcas", 0.5),))
    assert detect_structural_floor(bundle).fired is False


def test_camel_deny_fires_floor() -> None:
    bundle = SpecialistBundle(results=(_result("camel", 1.0),))
    assert detect_structural_floor(bundle).fired is True


def test_ifc_violation_code_fires_floor() -> None:
    bundle = SpecialistBundle(
        results=(_result("ifc", 0.7, ("ifc.flow_integrity",)),)
    )
    out = detect_structural_floor(bundle)
    assert out.fired is True
    assert "ifc" in out.denying_specialists


def test_ifc_floor_only_on_real_violation_code() -> None:
    # A non-violation clause id must not fire the floor even at high risk.
    bundle = SpecialistBundle(results=(_result("ifc", 0.9, ("ASI09",)),))
    assert detect_structural_floor(bundle).fired is False


def test_argus_observation_driven_fires_floor() -> None:
    bundle = SpecialistBundle(
        results=(_result("argus", 0.8, ("ARGUS_DECISION_OBSERVATION_DRIVEN",)),)
    )
    assert detect_structural_floor(bundle).fired is True


def test_argus_no_justification_does_not_fire() -> None:
    # Narrow by design: NO_JUSTIFICATION is a suspect signal, not a proof.
    bundle = SpecialistBundle(
        results=(_result("argus", 0.8, ("ARGUS_DECISION_NO_JUSTIFICATION",)),)
    )
    assert detect_structural_floor(bundle).fired is False


def test_high_probabilistic_score_does_not_fire() -> None:
    # A non-structural specialist at high risk is NOT a structural proof.
    bundle = SpecialistBundle(results=(_result("mage", 0.99, ("ASI08",)),))
    assert detect_structural_floor(bundle).fired is False


def test_benign_bundle_does_not_fire() -> None:
    bundle = SpecialistBundle(
        results=(_result("pcas", 0.0), _result("ifc", 0.05), _result("argus", 0.05))
    )
    assert detect_structural_floor(bundle).fired is False


# ── the tier-inversion fix, end-to-end through the PDP ──────────────────


class _StubSuite:
    """A specialist suite that returns exactly one PCAS deny result.

    On otherwise-clean content this reproduces the pre-floor failure mode: the
    deny diluted through the router's weighted sum to ABSTAIN. With the floor
    wired, it must FORBID.
    """

    def __init__(self, result: SpecialistResult) -> None:
        self._result = result

    def evaluate(self, *, request: EvaluationRequest, retrieval_context: RetrievalContext):
        return SpecialistBundle(results=(self._result,))


def test_pcas_deny_now_forbids_not_abstains() -> None:
    pcas_deny = _result("pcas", 1.0, ("deny:exfiltrate_untrusted_to_external",))
    pdp = PolicyDecisionPoint(specialist_suite=_StubSuite(pcas_deny))
    # Clean content — nothing else in the pipeline raises risk.
    request = make_request(content="Routine status update, nothing sensitive here.")
    result = pdp.evaluate(request=request, policy=make_default_policy())

    assert result.decision.verdict is Verdict.FORBID
    sf = result.decision.metadata["pdp"]["structural_floor"]
    assert sf["fired"] is True
    assert "pcas" in sf["denying_specialists"]
    # The FORBID is attributed to the structural layer, not a fused score.
    assert result.decision.scores.get("structural_floor") == 1.0


def test_ifc_violation_forbids_end_to_end() -> None:
    ifc_deny = _result("ifc", 0.65, ("ifc.causality_laundering",))
    pdp = PolicyDecisionPoint(specialist_suite=_StubSuite(ifc_deny))
    request = make_request(content="Routine status update.")
    result = pdp.evaluate(request=request, policy=make_default_policy())
    assert result.decision.verdict is Verdict.FORBID
    assert result.decision.metadata["pdp"]["structural_floor"]["fired"] is True


def test_probabilistic_specialist_still_routes_normally() -> None:
    # A high MAGE score (probabilistic) must NOT hit the floor; it flows
    # through the router as before (ABSTAIN/FORBID via fusion, not short-circuit).
    mage = _result("mage", 0.99, ("ASI08",))
    pdp = PolicyDecisionPoint(specialist_suite=_StubSuite(mage))
    request = make_request(content="Routine status update.")
    result = pdp.evaluate(request=request, policy=make_default_policy())
    assert result.decision.metadata["pdp"]["structural_floor"]["fired"] is False
    # Not short-circuited — routed.
    assert "structural_floor" not in result.decision.scores

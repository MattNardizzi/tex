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


def test_ifc_secret_egress_noninterference_fires_floor() -> None:
    # The deterministic SECRET-not->EGRESS non-interference FORBID must promote to
    # a hard structural DENY, not survive only as a probabilistic vote (which PDP
    # fusion can dilute below threshold -> ABSTAIN). The IfcEngine surfaces this
    # code in matched_policy_clause_ids exactly when verdict.structural_forbid is
    # True; this is the consuming wire that makes the "structural floor" real.
    bundle = SpecialistBundle(
        results=(_result("ifc", 0.97, ("ifc.secret_egress_noninterference",)),)
    )
    out = detect_structural_floor(bundle)
    assert out.fired is True
    assert "ifc" in out.denying_specialists


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


# ── L4 action-class reversibility×blast floor ───────────────────────────


def _action_class_request(steps, *, content="Routine status update.", **kw):
    """A request carrying an opt-in action_class declaration."""
    return make_request(content=content, metadata={"action_class": {"steps": steps}}, **kw)


def test_action_class_no_metadata_does_not_fire() -> None:
    # Opt-in: a benign bundle + a request with no action_class metadata is a no-op.
    bundle = SpecialistBundle(results=(_result("secret_and_pii", 0.05),))
    out = detect_structural_floor(bundle, request=make_request())
    assert out.fired is False
    assert "action_class" not in out.denying_specialists


def test_action_class_irreversible_public_fires_floor() -> None:
    bundle = SpecialistBundle(results=(_result("secret_and_pii", 0.05),))
    req = _action_class_request([{"reversibility": "IRREVERSIBLE", "blast_radius": "PUBLIC"}])
    out = detect_structural_floor(bundle, request=req)
    assert out.fired is True
    assert "action_class" in out.denying_specialists


def test_action_class_abstain_cell_does_not_fire_floor() -> None:
    # One axis hot (irreversible × tenant) → ABSTAIN cell, recorded only; the
    # FORBID-only floor must NOT fire (forbidding uncertainty is forbidden).
    bundle = SpecialistBundle(results=(_result("secret_and_pii", 0.05),))
    req = _action_class_request([{"reversibility": "IRREVERSIBLE", "blast_radius": "TENANT"}])
    assert detect_structural_floor(bundle, request=req).fired is False


def test_action_class_unknown_corner_fires_floor() -> None:
    # Uncharacterised reversibility + public blast → fail-closed FORBID.
    bundle = SpecialistBundle(results=(_result("secret_and_pii", 0.05),))
    req = _action_class_request([{"reversibility": "frobnicate", "blast_radius": "PUBLIC"}])
    assert detect_structural_floor(bundle, request=req).fired is True


def test_action_class_forbids_irreversible_public_end_to_end() -> None:
    pdp = PolicyDecisionPoint(specialist_suite=_StubSuite(_result("secret_and_pii", 0.05)))
    req = _action_class_request([{"reversibility": "IRREVERSIBLE", "blast_radius": "PUBLIC"}])
    result = pdp.evaluate(request=req, policy=make_default_policy())

    assert result.decision.verdict is Verdict.FORBID
    sf = result.decision.metadata["pdp"]["structural_floor"]
    assert sf["fired"] is True
    assert "action_class" in sf["denying_specialists"]
    # Attributed to the structural action_class tier, not a fused score.
    assert result.decision.scores.get("structural_action_class") == 1.0


def test_high_probabilistic_score_does_not_fire_action_class() -> None:
    """EARNABLE #1 — a 0.9 score cannot conjure the lattice FORBID.

    A high non-structural specialist score with a SAFE declared action (or no
    declaration) must not fire the action_class floor: the lattice reads
    structure, never risk_score.
    """
    # 0.9 mage + a safe (reversible×self) action: the score cannot push the
    # NEUTRAL cell to FORBID.
    bundle = SpecialistBundle(results=(_result("mage", 0.9, ("ASI08",)),))
    safe = _action_class_request([{"reversibility": "REVERSIBLE", "blast_radius": "SELF"}])
    out = detect_structural_floor(bundle, request=safe)
    assert out.fired is False
    assert "action_class" not in out.denying_specialists

    # 0.9 mage + NO action_class metadata: still no action_class deny.
    out2 = detect_structural_floor(bundle, request=make_request())
    assert "action_class" not in out2.denying_specialists


def test_spoofed_bundle_specialist_cannot_fire_action_class() -> None:
    # Adversarial: a specialist literally named "action_class" at risk 1.0 in the
    # bundle (with no opt-in metadata) must NOT fire the floor. The lattice deny
    # is metadata-only — it cannot be conjured by a crafted bundle entry.
    spoof = SpecialistBundle(
        results=(_result("action_class", 1.0, ("action_class.irreversible_public",)),)
    )
    out = detect_structural_floor(spoof, request=make_request())
    assert out.fired is False
    assert "action_class" not in out.denying_specialists


def test_low_probabilistic_score_cannot_silence_action_class() -> None:
    """EARNABLE #2 — a 0.1 'looks-routine' score cannot silence the structural FORBID.

    A declared irreversible×public action FORBIDs via the lattice even when every
    probabilistic specialist scores it benign.
    """
    benign = SpecialistBundle(results=(_result("secret_and_pii", 0.1), _result("mage", 0.1)))
    req = _action_class_request([{"reversibility": "IRREVERSIBLE", "blast_radius": "PUBLIC"}])
    out = detect_structural_floor(benign, request=req)
    assert out.fired is True
    assert "action_class" in out.denying_specialists

    # And end-to-end through the PDP: still FORBID despite the benign 0.1 score.
    pdp = PolicyDecisionPoint(specialist_suite=_StubSuite(_result("secret_and_pii", 0.1)))
    result = pdp.evaluate(request=req, policy=make_default_policy())
    assert result.decision.verdict is Verdict.FORBID


def test_action_class_only_lowers_never_relaxes() -> None:
    """Monotone: the floor raises a would-be PERMIT to FORBID, and a NEUTRAL
    declaration never raises a verdict (no spurious escalation)."""
    # An otherwise-clean request that would PERMIT: a safe declaration leaves it
    # un-escalated by this floor.
    pdp = PolicyDecisionPoint(specialist_suite=_StubSuite(_result("secret_and_pii", 0.02)))
    safe = _action_class_request([{"reversibility": "REVERSIBLE", "blast_radius": "SELF"}])
    safe_result = pdp.evaluate(request=safe, policy=make_default_policy())
    assert safe_result.decision.metadata["pdp"]["structural_floor"]["fired"] is False
    assert safe_result.decision.verdict is not Verdict.FORBID

    # The same clean content with an irreversible×public declaration is raised to
    # FORBID — the floor only ever moves toward caution.
    danger = _action_class_request([{"reversibility": "IRREVERSIBLE", "blast_radius": "PUBLIC"}])
    danger_result = pdp.evaluate(request=danger, policy=make_default_policy())
    assert danger_result.decision.verdict is Verdict.FORBID

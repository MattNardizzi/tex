"""
Wave 2 batch-2 integration — the EIGHT-leap combination, run together.

Each leap's own suite proves its property in isolation. This file pins the
combination that first existed at the batch-2 merge: batch-1's L4
(action-class floor), L9 (risk spine), L10 (PQ-durability) and L2
(verdict-bound attestation) active on the same decision flow as batch-2's
L8 (conf_stream carrier + credal hold), L12 (verdict-certificate posture),
L1 (arbitration relation + M0 seal binding) and L7 (survival monitor over
the produced verdict stream).

The two runtime invariants under test are the sacred ones (CLAUDE.md):

  * monotone lowering — with EVERY probabilistic signal breaching at once
    (an extreme risk-spine e-value plus a PQ-non-repudiation claim on a
    non-durable signer), a PERMIT decision is lowered to ABSTAIN and no
    further: the signals must not produce FORBID and must NOT fire the
    structural floor.
  * structural floor — the action-class FORBID cell forbids regardless of
    what the probabilistic signals do, and the L1 relation built from that
    decision is UNSAT for every other claimed verdict (no signal
    combination can raise).

If a future merge lets a breaching-signal request PERMIT, the monotone test
fails AND the L7 monitor test shows what the campaign monitor would have
done about it (one such PERMIT = deterministic refutation).
"""

from __future__ import annotations

import math
from dataclasses import replace

from tex.adversarial.completeness import SurvivalMonitor
from tex.domain.verdict import Verdict
from tex.engine.pdp import PolicyDecisionPoint
from tex.engine.risk_spine import RISK_SPINE_FLAG, RiskSpine
from tex.pqcrypto.pq_durability import PQ_NON_REPUDIATION_FLAG
from tex.provenance.ledger import SealedFactLedger
from tex.tee.verdict_binding import verdict_bound_nonce
from tex.zkpdp.arbiter import (
    build_statement_from_decision,
    check_seal_binding,
    evaluate_relation,
)

from tests.factories import (
    make_default_policy,
    make_request,
    make_semantic_analysis,
)

_ALL_VERDICTS = (Verdict.PERMIT.value, Verdict.ABSTAIN.value, Verdict.FORBID.value)

# Every probabilistic, monotone-lowering signal breaching at once: an extreme
# risk-spine observation (drift 8.0 drives the e-value far past the 2^K/alpha
# action level) plus a PQ-non-repudiation claim the ECDSA-P256 signer cannot
# honor (L10 lowers PERMIT -> ABSTAIN).
_ALL_SIGNALS_BREACHING = {
    "risk_spine": {"observations": {"drift": 8.0}},
    "pq_non_repudiation": True,
}

_FORBID_CELL = {
    "action_class": {
        "steps": [{"reversibility": "IRREVERSIBLE", "blast_radius": "PUBLIC"}]
    }
}


class _PermitSemanticAnalyzer:
    """Deterministic semantic provider recommending PERMIT with solid
    confidence, so the routed baseline is a real PERMIT the signals can
    lower. Only the LLM-provider seam is stubbed — the deterministic gate,
    specialists, router, floor, CRC and PDP all stay real (the zkpdp
    live-cross-check stub, reused for the same reason)."""

    def analyze(self, *, request, retrieval_context):
        return make_semantic_analysis(
            recommended_verdict=Verdict.PERMIT,
            recommended_confidence=0.9,
            overall_confidence=0.92,
            dimension_confidence=0.8,
            evidence_sufficiency=0.6,
        )


def _eightleap_pdp(ledger: SealedFactLedger) -> PolicyDecisionPoint:
    """A PDP with every wireable leap live: M0 decision sealing (consumed by
    L1's seal binding) and the L9 risk spine. L4/L10 activate per-request via
    metadata; L8/L12 are always-on."""
    return PolicyDecisionPoint(
        decision_ledger=ledger,
        risk_spine=RiskSpine(alpha=0.05),
        semantic_analyzer=_PermitSemanticAnalyzer(),
    )


def _evaluate(metadata: dict, ledger: SealedFactLedger):
    policy = make_default_policy()
    pdp = _eightleap_pdp(ledger)
    result = pdp.evaluate(
        request=make_request(metadata=metadata), policy=policy
    )
    return result, policy


def test_monotone_lowering_holds_with_all_eight_leaps_active() -> None:
    ledger = SealedFactLedger()
    result, policy = _evaluate(dict(_ALL_SIGNALS_BREACHING), ledger)
    decision = result.decision

    # Lowered exactly one rung: ABSTAIN, never FORBID from signals alone.
    assert decision.verdict is Verdict.ABSTAIN

    # At least one breaching signal genuinely acted (guards against a
    # vacuous pass where the request was never PERMIT-able to begin with).
    # Hook order runs the spine before the PQ hold and both act only on a
    # PERMIT, so the spine wins the lowering and the flags must show it.
    assert RISK_SPINE_FLAG in decision.uncertainty_flags

    # The probabilistic signals must NOT fire the structural floor.
    assert "structural_floor" not in decision.scores
    stmt = build_statement_from_decision(decision, policy=policy)
    assert stmt.floor_sources == ()
    assert stmt.deny_floor is False

    # L8 carrier: per-stream confidences reached the durable decision.
    for key in (
        "conf_stream:deterministic",
        "conf_stream:specialist",
        "conf_stream:semantic",
    ):
        assert key in decision.scores

    # ABSTAIN-only surface: the ABSTAIN raised a hold, and the credal
    # resolver had real stream components to rank from.
    hold = decision.metadata["pdp"]["hold"]
    assert hold is not None
    assert hold["resolving_question"]

    # L12 posture: present, inert, and not certified.
    assert decision.metadata["pdp"]["verdict_certificate"] == {
        "enabled": False,
        "certified": False,
    }

    # L1: the relation derived from this eight-leap decision is satisfiable
    # only for the verdict actually produced; every flip is UNSAT.
    assert stmt.claimed_verdict == Verdict.ABSTAIN.value
    assert evaluate_relation(stmt).satisfied
    for wrong in (v for v in _ALL_VERDICTS if v != stmt.claimed_verdict):
        assert not evaluate_relation(replace(stmt, claimed_verdict=wrong)).satisfied

    # M0 + L1: the decision was sealed through the eight-leap path and the
    # binding verifies — integrity (chain) and signatures both intact.
    seal = check_seal_binding(ledger, stmt)
    assert seal.status == "sealed_match"
    assert seal.chain_intact is True
    assert seal.signatures_valid is True

    # L10 alone (the spine won the lowering above, so the PQ hold was a
    # PERMIT-only no-op there): with only the PQ-non-repudiation claim
    # breaching, the same eight-leap PDP lowers PERMIT -> ABSTAIN and says
    # why — the live ECDSA-P256 signer is not PQ-durable.
    pq_result, _ = _evaluate({"pq_non_repudiation": True}, SealedFactLedger())
    assert pq_result.decision.verdict is Verdict.ABSTAIN
    assert PQ_NON_REPUDIATION_FLAG in pq_result.decision.uncertainty_flags


def test_structural_floor_unbreakable_with_all_eight_leaps_active() -> None:
    ledger = SealedFactLedger()
    metadata = dict(_ALL_SIGNALS_BREACHING) | dict(_FORBID_CELL)
    result, policy = _evaluate(metadata, ledger)
    decision = result.decision

    # The action-class FORBID cell is deterministic: FORBID, with the floor
    # on record, regardless of every probabilistic signal breaching.
    assert decision.verdict is Verdict.FORBID
    assert decision.scores.get("structural_floor") == 1.0

    # FORBID is invisible to the operator — no hold (ABSTAIN-only surfaces).
    assert decision.metadata["pdp"]["hold"] is None

    # L1: the floored decision's relation pins the floor; PERMIT and ABSTAIN
    # claims are both UNSAT — no signal combination can raise.
    stmt = build_statement_from_decision(decision, policy=policy)
    assert stmt.floor_sources != ()
    assert evaluate_relation(stmt).satisfied
    for wrong in (Verdict.PERMIT.value, Verdict.ABSTAIN.value):
        assert not evaluate_relation(replace(stmt, claimed_verdict=wrong)).satisfied

    # Sealed through the same path as the monotone case.
    seal = check_seal_binding(ledger, stmt)
    assert seal.status == "sealed_match"
    assert seal.chain_intact is True


def test_l2_nonce_binds_the_eightleap_verdict() -> None:
    """L2 over a real eight-leap decision: the verdict-bound nonce folds the
    categorical verdict with the decision-input hash; swapping the verdict
    changes the nonce (the verdict-swap detection the L2 suite proves in
    full lives on exactly these inputs)."""
    ledger = SealedFactLedger()
    result, _ = _evaluate(dict(_ALL_SIGNALS_BREACHING), ledger)
    decision = result.decision

    facts = {
        "policy_bundle_digest": "a" * 64,  # stand-in digest; shape-only here
        "decision_input_sha256": decision.content_sha256,
        "ledger_prev_hash": ledger.list_all()[-1].record_hash,
    }
    bound = verdict_bound_nonce(sealed_verdict=decision.verdict, **facts)
    assert bound == verdict_bound_nonce(sealed_verdict=decision.verdict, **facts)
    for other in (Verdict.PERMIT, Verdict.FORBID):
        assert verdict_bound_nonce(sealed_verdict=other, **facts) != bound


def test_l7_monitor_would_catch_a_monotonicity_breach() -> None:
    """L7 composed over eight-leap decisions: a campaign of breaching-signal
    requests yields zero PERMITs, so the deterministic-floor monitor holds
    capital at exactly 1 (zero evidence, honestly — no breach, no claim).
    One injected PERMIT-where-signals-demanded-hold is a deterministic
    refutation: this is the alarm a monotone-lowering regression trips."""
    ledger = SealedFactLedger()
    policy = make_default_policy()
    pdp = _eightleap_pdp(ledger)

    monitor = SurvivalMonitor(alpha=0.05, p0=0.0)
    for _ in range(5):
        result = pdp.evaluate(
            request=make_request(metadata=dict(_ALL_SIGNALS_BREACHING)),
            policy=policy,
        )
        breached = result.decision.verdict is Verdict.PERMIT
        monitor.update(1.0 if breached else 0.0)

    assert monitor.fired is False
    assert monitor.log_capital == 0.0  # capital exactly 1: zero evidence

    monitor.update(1.0)  # the breach a broken merge would have produced
    assert monitor.fired is True
    assert math.isinf(monitor.log_capital)

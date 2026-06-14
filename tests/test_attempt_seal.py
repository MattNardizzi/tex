"""
Wave 2 / seam track — ATTEMPT-sealing hook tests.

Each test would FAIL if the behaviour it pins broke:
  * exactly ONE ATTEMPT per evaluate() on BOTH verdict branches (routed and
    hard-FORBID short-circuit) — per-branch placement would double-count on
    the fail-closed path, convergence placement would make the identity
    vacuous;
  * the placement pin: a crash AFTER entry (deterministic gate raises) still
    leaves the sealed ATTEMPT with no DECISION — the fact the conservation
    identity exists to count. Moving the seal below the gate or to the
    convergence point fails this test;
  * the PQ double-DECISION balance: one PQ-lowered request yields 1 ATTEMPT,
    2 DECISION-kind facts, exactly 1 verdict-keyed → the identity balances;
  * the declared count-scoping contract: a reflexive gate evaluation seals
    exactly one ATTEMPT and balances (gate evals COUNT as attempts);
  * fail-closed posture mirrors decision_seal: None ledger → no-op; append
    failure → logged None, the verdict unaffected;
  * the fact itself is honest: pre-verdict claim, no "verdict" detail key,
    content_sha256 linkable to the eventual DECISION fact.
"""

from __future__ import annotations

import pytest

from tex.domain.evidence import EvidenceMaturity
from tex.domain.verdict import Verdict
from tex.engine.pdp import PolicyDecisionPoint
from tex.evidence.negative_knowledge import check_count_conservation
from tex.pqcrypto import ml_dsa
from tex.provenance.attempt_seal import build_attempt_fact, seal_attempt
from tex.provenance.ledger import SealedFactLedger
from tex.provenance.models import SealedFactKind
from tex.selfgov.governor import bound_reflexive_governor
from tex.stores.policy_store import InMemoryPolicyStore

from tests.factories import (
    make_default_policy,
    make_request,
    make_semantic_analysis,
)


class _PermitSemanticAnalyzer:
    """Deterministic PERMIT-recommending stub for the LLM-provider seam only
    (the census/eight-leap pattern) — the PQ hold needs a real PERMIT
    baseline to lower, so both DECISION producers fire on one request."""

    def analyze(self, *, request, retrieval_context):
        return make_semantic_analysis(
            recommended_verdict=Verdict.PERMIT,
            recommended_confidence=0.9,
            overall_confidence=0.92,
            dimension_confidence=0.8,
            evidence_sufficiency=0.6,
        )

_ATTEMPT_DETAIL_KEYS = {
    "action_type",
    "policy_id",
    "policy_version",
    "content_sha256",
}


# ------------------------------------------------------------ the fact itself

def test_build_attempt_fact_is_pre_verdict_and_honest() -> None:
    request = make_request()
    policy = make_default_policy()
    fact = build_attempt_fact(request, policy)

    assert fact.kind is SealedFactKind.ATTEMPT
    assert fact.subject_id == str(request.request_id)
    # The exact detail key set, pinned — and NO verdict key: there is no
    # verdict at entry, and L3 counts verdict-keyed facts
    # (test_decision_fact_contract.py owns the cross-producer contract).
    assert set(fact.detail) == _ATTEMPT_DETAIL_KEYS
    assert "verdict" not in fact.detail
    assert fact.detail["policy_id"] == policy.policy_id
    assert fact.detail["policy_version"] == policy.version
    assert fact.detail["action_type"] == request.action_type
    # Honest claim: begun, pre-verdict, bounds-not-totals; carries no proof.
    assert "begun" in fact.claim
    assert "pre-verdict" in fact.claim
    assert fact.evidence is None
    assert fact.maturity is EvidenceMaturity.RESEARCH_SOLID


def test_attempt_content_hash_links_to_the_decision_fact() -> None:
    """The ATTEMPT's content_sha256 must equal the DECISION's — the audit
    link that catches a fabricated DECISION reusing a request_id over
    different content."""
    ledger = SealedFactLedger()
    pdp = PolicyDecisionPoint(decision_ledger=ledger)
    result = pdp.evaluate(request=make_request(), policy=make_default_policy())

    attempts = ledger.list_by_kind(SealedFactKind.ATTEMPT)
    assert len(attempts) == 1
    assert (
        attempts[0].fact.detail["content_sha256"]
        == result.decision.content_sha256
    )
    assert attempts[0].fact.subject_id == str(result.decision.request_id)


# ----------------------------------------------------------- fail-closed -----

def test_seal_attempt_with_no_ledger_is_a_noop() -> None:
    assert (
        seal_attempt(None, request=make_request(), policy=make_default_policy())
        is None
    )


class _BrokenLedger:
    def append(self, fact):
        raise RuntimeError("ledger backend down")


def test_append_failure_is_swallowed_and_verdict_unaffected() -> None:
    """Mirror of decision_seal's posture: a failing ledger must never break
    the request path or change the verdict."""
    record = seal_attempt(
        _BrokenLedger(), request=make_request(), policy=make_default_policy()
    )
    assert record is None

    # Live path: the SAME broken ledger wired into the PDP — evaluate()
    # completes and the verdict matches an unsealed run bit-for-bit.
    request = make_request()
    policy = make_default_policy()
    broken = PolicyDecisionPoint(decision_ledger=_BrokenLedger()).evaluate(
        request=request, policy=policy
    )
    unsealed = PolicyDecisionPoint().evaluate(request=request, policy=policy)
    assert broken.decision.verdict is unsealed.decision.verdict
    assert broken.decision.final_score == unsealed.decision.final_score


# ------------------------------------------- exactly-once, on BOTH branches --

def test_routed_branch_seals_exactly_one_attempt_then_one_decision() -> None:
    ledger = SealedFactLedger()
    pdp = PolicyDecisionPoint(decision_ledger=ledger)
    pdp.evaluate(request=make_request(), policy=make_default_policy())

    kinds = [r.fact.kind for r in ledger.list_all()]
    assert kinds == [SealedFactKind.ATTEMPT, SealedFactKind.DECISION], (
        "one routed evaluate() must seal exactly one ATTEMPT (entry) then "
        "one DECISION (finalize) — nothing else, in that order"
    )
    assert ledger.verify_chain()["intact"] is True
    assert ledger.verify_signatures()["valid"] is True


def test_hard_forbid_branch_seals_exactly_one_attempt() -> None:
    """The fail-closed short-circuit (structural floor → hard FORBID) must
    seal exactly ONE attempt — per-branch placement would double-count here
    and report a spurious GATED-BROKEN on exactly the fail-closed path."""
    ledger = SealedFactLedger()
    pdp = PolicyDecisionPoint(decision_ledger=ledger)
    result = pdp.evaluate(
        request=make_request(
            metadata={
                "action_class": {
                    "steps": [
                        {"reversibility": "IRREVERSIBLE", "blast_radius": "PUBLIC"}
                    ]
                }
            }
        ),
        policy=make_default_policy(),
    )
    assert result.decision.verdict is Verdict.FORBID

    kinds = [r.fact.kind for r in ledger.list_all()]
    assert kinds == [SealedFactKind.ATTEMPT, SealedFactKind.DECISION]
    assert kinds.count(SealedFactKind.ATTEMPT) == 1


class _ExplodingGate:
    def evaluate(self, *, request, policy):
        raise RuntimeError("mid-pipeline death")


def test_crash_after_entry_leaves_attempt_with_no_decision() -> None:
    """The placement pin. Entry is the only correct seal point: a crash
    anywhere after entry must leave a sealed ATTEMPT and NO DECISION — the
    uncounted-work gap the identity exists to expose. This test fails if the
    seal moves below the deterministic gate or to the finalize convergence."""
    ledger = SealedFactLedger()
    pdp = PolicyDecisionPoint(
        deterministic_gate=_ExplodingGate(), decision_ledger=ledger
    )
    with pytest.raises(RuntimeError, match="mid-pipeline death"):
        pdp.evaluate(request=make_request(), policy=make_default_policy())

    assert len(ledger.list_by_kind(SealedFactKind.ATTEMPT)) == 1
    assert len(ledger.list_by_kind(SealedFactKind.DECISION)) == 0
    # Declared n_error contract (one-sided): this gap surfaces as
    # GATED-BROKEN — a crash is indistinguishable from an omitted DECISION,
    # and the construction fails CLOSED rather than masking either.
    cons = check_count_conservation(ledger.list_all(), n_attempts=1)
    assert cons.status == "GATED-BROKEN"


# ------------------------------------------------- PQ double-DECISION balance

def test_pq_lowered_request_still_balances(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One PQ-claim request seals 1 ATTEMPT + 2 DECISION-kind facts of which
    exactly 1 is verdict-keyed — the identity balances at 1 attempt.

    Force the no-durable-backend branch so the PQ signal fires (seals its fact)
    regardless of whether this box ships a durable native ML-DSA backend
    (cryptography>=48 honors the claim instead — that branch seals no PQ fact and
    is covered by tests/capstone/test_pq_maturity_branches.py)."""
    monkeypatch.setattr(ml_dsa, "active_backend_id", lambda: None)
    ledger = SealedFactLedger()
    pdp = PolicyDecisionPoint(
        decision_ledger=ledger, semantic_analyzer=_PermitSemanticAnalyzer()
    )
    pdp.evaluate(
        request=make_request(metadata={"pq_non_repudiation": True}),
        policy=make_default_policy(),
    )

    records = ledger.list_all()
    kinds = [r.fact.kind for r in records]
    assert kinds == [
        SealedFactKind.ATTEMPT,    # entry hook (FIRST — the census ordering)
        SealedFactKind.DECISION,   # L10 PQ-durability fact (no verdict key)
        SealedFactKind.DECISION,   # M0 verdict fact
    ]
    verdict_keyed = [
        r
        for r in records
        if r.fact.kind is SealedFactKind.DECISION and "verdict" in r.fact.detail
    ]
    assert len(verdict_keyed) == 1

    cons = check_count_conservation(records, n_attempts=1)
    assert cons.status == "GATED-HOLDS"
    assert (cons.n_permit, cons.n_abstain, cons.n_forbid) == (0, 1, 0)


# --------------------------------------- declared scoping: gate evals COUNT --

def _policy_snapshot(version: str, *, active: bool = False, weak: bool = False):
    from tex.domain.policy import PolicySnapshot

    if weak:
        return PolicySnapshot(
            policy_id="p", version=version, is_active=active,
            permit_threshold=0.69, forbid_threshold=0.71,
            minimum_confidence=0.0, blocked_terms=(),
            enabled_recognizers=(),
        )
    return PolicySnapshot(
        policy_id="p", version=version, is_active=active,
        permit_threshold=0.30, forbid_threshold=0.70,
        minimum_confidence=0.50, blocked_terms=("ssn",),
        enabled_recognizers=("secrets",),
    )


def test_reflexive_gate_evaluation_counts_as_one_attempt_and_balances() -> None:
    """The declared count-scoping contract: an L5 reflexive gate evaluation
    seals exactly one ATTEMPT and one verdict-keyed DECISION — the identity
    stays global and symmetric (gate evals COUNT; no customer-only filter)."""
    store = InMemoryPolicyStore()
    store.save(_policy_snapshot("v1"))
    store.activate("v1")
    store.save(_policy_snapshot("v2", weak=True))

    ledger = SealedFactLedger()
    pdp = PolicyDecisionPoint(decision_ledger=ledger)
    with bound_reflexive_governor(pdp=pdp, ledger=ledger):
        returned = store.activate("v2")  # weakening → denied via the gate
    assert returned.is_active is False

    attempts = ledger.list_by_kind(SealedFactKind.ATTEMPT)
    assert len(attempts) == 1
    assert attempts[0].fact.detail["action_type"] == "controller_mutation"
    assert attempts[0].fact.detail["policy_id"] == "reflexive-governor"

    # 1 attempt vs 1 verdict-keyed DECISION (the PDP's own PERMIT — the
    # metaguard demotion lives only in the ENFORCEMENT fact): balances.
    cons = check_count_conservation(ledger.list_all(), n_attempts=1)
    assert cons.status == "GATED-HOLDS"
    assert cons.n_permit == 1

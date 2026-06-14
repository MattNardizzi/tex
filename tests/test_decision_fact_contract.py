"""
Tripwire: the shared-ledger ``SealedFact(DECISION)`` disambiguation contract.

Two producers seal ``SealedFactKind.DECISION`` for the SAME request on the
same M0 ledger:

  * L10's PQ-durability resolution — ``build_pq_durability_fact``
    (pqcrypto/pq_durability.py:339), appended DURING routing via
    ``apply_pq_durability_hold`` (engine/pdp.py:400-404);
  * M0's decision seal — ``build_decision_fact``
    (provenance/decision_seal.py:62), appended at finalize
    (engine/pdp.py:490).

The consumers disambiguate by convention, not by a typed contract
(COORDINATION.md § "Batch-3 cross-leap findings", caution 1):

  * L1's ``check_seal_binding`` takes ``matching[-1]`` of the subject's
    DECISION facts (zkpdp/arbiter.py:1026-1037) — correct only because the
    PQ fact is appended FIRST;
  * L3's ``check_count_conservation`` counts a DECISION fact only when its
    detail carries a ``"verdict"`` key (evidence/negative_knowledge.py:
    598-608) — the PQ fact is skipped only because ``seal_detail()``
    (pq_durability.py:202-214) omits that key.

This file makes the convention fail loudly instead of silently:

  (a) a NEW ``DECISION``-kind producer anywhere in src/tex must show up in
      the construction census below and declare which side of the
      verdict-key contract it is on;
  (b) a non-verdict producer growing a ``"verdict"`` detail key, or
  (c) the PQ-before-decision-seal append ordering flipping,
      breaks the behavioural pins.

This is a pin, not a fix — the contract-level fix (a distinct kind) now has
its first instance: the attempt hook (provenance/attempt_seal.py) seals
``SealedFactKind.ATTEMPT`` at evaluate() entry — a third producer on the
same ledger, deliberately a distinct kind so neither consumer's DECISION
filter ever sees it. Its pins live below alongside the original two.
Census residual, stated honestly: the source scan
matches the two textual construction forms (``kind=SealedFactKind.DECISION``
and positional ``SealedFact(SealedFactKind.DECISION``); an aliased or
dynamically-built kind evades it — enumerated, not proven, the same residual
as the L5 controller-mutation census. The live-flow pins assume the test
environment has no PQ-durable backend, the same RUNTIME-DEPENDENT posture
test_pq_durability.py::test_live_probe_is_none_in_this_env already pins.
"""

from __future__ import annotations

import re
from pathlib import Path
from types import SimpleNamespace

import pytest

from tex.domain.verdict import Verdict
from tex.engine.pdp import PolicyDecisionPoint
from tex.evidence.negative_knowledge import check_count_conservation
from tex.pqcrypto import ml_dsa
from tex.pqcrypto.pq_durability import assess, build_pq_durability_fact
from tex.provenance.decision_seal import build_decision_fact
from tex.provenance.ledger import SealedFactLedger
from tex.provenance.models import SealedFactKind
from tex.zkpdp.arbiter import build_statement_from_decision, check_seal_binding

from tests.factories import (
    make_default_policy,
    make_request,
    make_semantic_analysis,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_TEX = REPO_ROOT / "src" / "tex"

# Every file in src/tex that may mention SealedFactKind.DECISION, with its
# declared role. A new mention means a new producer or consumer entered the
# namespace: enumerate it here AND extend the behavioural pins below.
_MENTION_ALLOWLIST = {
    "provenance/attempt_seal.py": (
        "producer of a DISTINCT kind (ATTEMPT, pre-verdict, evaluate() entry) "
        "— mentions DECISION only to declare its contract: detail MUST NOT "
        "carry a verdict key, and the ATTEMPT appends FIRST for a request "
        "(before the PQ fact and the M0 decision seal)"
    ),
    "provenance/decision_seal.py": (
        "producer — THE verdict-bearing DECISION fact (M0); detail carries "
        "the verdict key the consumers key on"
    ),
    "pqcrypto/pq_durability.py": (
        "producer — non-verdict PQ-durability resolution (L10); detail MUST "
        "NOT carry a verdict key (L3 would double-count)"
    ),
    "evidence/negative_knowledge.py": (
        "consumer — count-conservation over DECISION facts with a verdict key"
    ),
    "zkpdp/arbiter.py": (
        "consumer — seal binding resolves matching[-1] per subject_id"
    ),
    # The capstone composition layer (Wave 2 capstone thread) — four
    # CONSUMER files, zero new DECISION producers. Its one new fact is
    # kind=ANSWER (the sealed manifest digest), appended strictly AFTER the
    # pre-seal epoch with subject_id "capstone:<request_id>" so it can never
    # shadow the M0 decision's matching[-1] resolution, and with no verdict
    # key in a DECISION-kind fact (L3's counts are untouched).
    "capstone/compose.py": (
        "consumer — locates the M0/PQ facts for the manifest's identity "
        "cross-checks and per-leap verification snapshots"
    ),
    "capstone/verify.py": (
        "consumer — offline re-checks: identity, L3 conservation slice, "
        "L12 segment verdict multiset, M0 per-request order"
    ),
    "capstone/flow.py": (
        "consumer — locates the capstone DECISION fact to build the voice "
        "proof_ref cross-chain reference"
    ),
    "capstone/tamper.py": (
        "consumer — ATTACK SIMULATION ONLY: locates PERMIT DECISION facts "
        "to rebuild omission variants the L3 checks must catch"
    ),
}

# The only construction sites allowed for kind=DECISION. A producer added
# anywhere else (including inside a consumer file) trips the census.
_CONSTRUCTION_ALLOWLIST = {
    "provenance/decision_seal.py",
    "pqcrypto/pq_durability.py",
}

_KEYWORD_CONSTRUCTION = re.compile(r"kind\s*=\s*SealedFactKind\.DECISION")
_POSITIONAL_CONSTRUCTION = re.compile(r"SealedFact\(\s*SealedFactKind\.DECISION")

# The exact detail key sets, pinned. These are the consumers' filter inputs:
# L3 keys on "verdict" presence; L1 matches on verdict / final_score /
# policy_id / policy_version / content_sha256 / determinism_fingerprint of
# whichever record it resolved. Any key change here must be checked against
# both consumers before this pin is updated.
_M0_DETAIL_KEYS = {
    "verdict",
    "final_score",
    "confidence",
    "action_type",
    "policy_id",
    "policy_version",
    "content_sha256",
    "determinism_fingerprint",
}
_PQ_DETAIL_KEYS = {
    "pq_durable",
    "signer_maturity",
    "ml_dsa_backend_id",
    "pq_non_repudiation_claim_requested",
    "pq_non_repudiation_claim_honored",
}


class _PermitSemanticAnalyzer:
    """Deterministic PERMIT-recommending stub for the LLM-provider seam only
    (the eight-leap/zkpdp pattern) — the PQ hold needs a real PERMIT baseline
    to lower, so both DECISION producers fire on one request."""

    def analyze(self, *, request, retrieval_context):
        return make_semantic_analysis(
            recommended_verdict=Verdict.PERMIT,
            recommended_confidence=0.9,
            overall_confidence=0.92,
            dimension_confidence=0.8,
            evidence_sufficiency=0.6,
        )


@pytest.fixture(scope="module", autouse=True)
def _force_no_pq_durable_backend():
    """Pin the no-durable-backend branch for this module.

    Both producers seal only when the PQ signal FIRES, which requires a
    non-durable signer. A box with cryptography>=48 ships a durable native ML-DSA
    backend that HONORS the claim (no PQ fact, so only the M0 producer seals), which
    would un-fire every contract pin here. Force the live backend id absent so the
    two-producer disambiguation is exercised deterministically on any box. The
    honored branch is covered by tests/capstone/test_pq_maturity_branches.py.
    """
    mp = pytest.MonkeyPatch()
    mp.setattr(ml_dsa, "active_backend_id", lambda: None)
    yield
    mp.undo()


@pytest.fixture(scope="module")
def sealed_flow():
    """One live evaluation that makes BOTH producers seal: a
    PQ-non-repudiation claim on the (non-PQ-durable) live signer lowers a
    real PERMIT to ABSTAIN — the PQ fact seals during routing, the M0
    decision fact at finalize."""
    ledger = SealedFactLedger()
    pdp = PolicyDecisionPoint(
        decision_ledger=ledger,
        semantic_analyzer=_PermitSemanticAnalyzer(),
    )
    policy = make_default_policy()
    result = pdp.evaluate(
        request=make_request(metadata={"pq_non_repudiation": True}),
        policy=policy,
    )
    return SimpleNamespace(
        ledger=ledger, policy=policy, decision=result.decision
    )


def test_census_decision_kind_construction_sites_are_enumerated() -> None:
    """Source census over src/tex: every mention of SealedFactKind.DECISION
    and every construction site must be enumerated above. A new producer
    fails here until it declares its verdict-key contract."""
    mention_files: set[str] = set()
    construction_files: set[str] = set()
    for path in sorted(SRC_TEX.rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        rel = path.relative_to(SRC_TEX).as_posix()
        if "SealedFactKind.DECISION" in text:
            mention_files.add(rel)
        if _KEYWORD_CONSTRUCTION.search(text) or _POSITIONAL_CONSTRUCTION.search(
            text
        ):
            construction_files.add(rel)

    assert mention_files == set(_MENTION_ALLOWLIST), (
        "SealedFactKind.DECISION entered/left a file outside the enumerated "
        f"namespace: {sorted(mention_files ^ set(_MENTION_ALLOWLIST))}. "
        "Enumerate the file's role in _MENTION_ALLOWLIST and extend the "
        "behavioural pins in this module."
    )
    assert construction_files == _CONSTRUCTION_ALLOWLIST, (
        "a DECISION-kind SealedFact construction site appeared outside the "
        f"two known producers: {sorted(construction_files ^ _CONSTRUCTION_ALLOWLIST)}. "
        "The new producer must declare whether its detail carries a "
        "'verdict' key (L3 counts it) and where it appends relative to the "
        "M0 decision seal (L1 takes matching[-1])."
    )


def test_producer_detail_contract_verdict_key(sealed_flow) -> None:
    """The verdict-key contract at the builder level: the M0 fact carries
    'verdict' (plus the L1 binding fields), the PQ fact does NOT — and its
    key set is pinned exactly, so any addition is consciously checked
    against both consumers before this pin moves."""
    m0_fact = build_decision_fact(sealed_flow.decision)
    assert m0_fact.kind is SealedFactKind.DECISION
    assert set(m0_fact.detail) == _M0_DETAIL_KEYS
    assert m0_fact.detail["verdict"] == sealed_flow.decision.verdict.value

    request = make_request(metadata={"pq_non_repudiation": True})
    assessment = assess(request)
    assert assessment.lowers_verdict, (
        "PQ assessment did not lower despite the module's forced no-backend "
        "posture — the _force_no_pq_durable_backend autouse fixture "
        "(active_backend_id → None) did not apply. This suite pins the "
        "two-producer disambiguation, which engages only when the PQ signal fires."
    )
    pq_fact = build_pq_durability_fact(assessment, request)
    assert pq_fact.kind is SealedFactKind.DECISION
    assert "verdict" not in pq_fact.detail, (
        "the PQ-durability DECISION fact grew a 'verdict' detail key — L3's "
        "count-conservation will now double-count every PQ-lowered request "
        "(negative_knowledge.py:598-608). Use a distinct key or a distinct "
        "SealedFactKind (seam-track decision)."
    )
    assert set(pq_fact.detail) == _PQ_DETAIL_KEYS


def test_pq_fact_appends_before_the_decision_seal(sealed_flow) -> None:
    """The ordering half of the contract, on the live path: for one request
    that fires both producers, the PQ fact is appended FIRST, so the M0
    fact is matching[-1] — exactly what L1's resolution relies on."""
    records = sealed_flow.ledger.list_all()
    decision_records = [
        r for r in records if r.fact.kind is SealedFactKind.DECISION
    ]
    assert len(decision_records) == 2
    first, last = decision_records[0], decision_records[1]

    # Both facts name the same request (the collision under pin).
    subject = str(sealed_flow.decision.request_id)
    assert first.fact.subject_id == subject
    assert last.fact.subject_id == subject

    # Ordering: PQ (no verdict key) strictly before M0 (verdict key).
    assert "verdict" not in first.fact.detail, (
        "the FIRST DECISION fact for the request carries a verdict key — "
        "the PQ-before-decision-seal append ordering flipped "
        "(pdp.py routing at ~:400 vs finalize seal at ~:490); "
        "check_seal_binding's matching[-1] now resolves the wrong record"
    )
    assert last.fact.detail.get("verdict") == sealed_flow.decision.verdict.value
    assert first.sequence < last.sequence

    # And the consumer itself: the binding resolves to the LAST record —
    # the M0 fact — and matches the statement built from the live decision.
    stmt = build_statement_from_decision(
        sealed_flow.decision, policy=sealed_flow.policy
    )
    seal = check_seal_binding(sealed_flow.ledger, stmt)
    assert seal.status == "sealed_match"
    assert seal.record_sequence == last.sequence


def test_conservation_counts_exactly_one_verdict_per_request(
    sealed_flow,
) -> None:
    """The L3 half on the live path: one PQ-lowered request leaves TWO
    DECISION facts but exactly ONE counted verdict (the ABSTAIN). If the PQ
    fact ever grows a verdict key, the identity breaks at 1 attempt.
    RECOMPOSED at the attempt-hook landing: n_attempts now DERIVES from the
    sealed ATTEMPT fact — no external count needed; a supplied count that
    agrees is idempotent."""
    records = sealed_flow.ledger.list_all()
    cons = check_count_conservation(records)  # derived from the ATTEMPT fact
    assert cons.attempts_source == "derived"
    assert cons.n_attempts == 1
    assert (cons.n_permit, cons.n_abstain, cons.n_forbid) == (0, 1, 0)
    assert cons.status == "GATED-HOLDS"
    assert cons.holds is True

    consistent = check_count_conservation(records, n_attempts=1)
    assert consistent.status == "GATED-HOLDS"


def test_attempt_fact_is_a_distinct_kind_invisible_to_both_consumers(
    sealed_flow,
) -> None:
    """The third producer's side of the contract: the attempt hook seals a
    DISTINCT kind (ATTEMPT), strictly FIRST for the request, with no verdict
    detail key — so L1's DECISION-kind filter and L3's verdict-key filter
    both exclude it by construction, not by luck."""
    records = sealed_flow.ledger.list_all()
    attempts = [r for r in records if r.fact.kind is SealedFactKind.ATTEMPT]
    assert len(attempts) == 1, (
        "one evaluate() must seal exactly one ATTEMPT fact (entry placement)"
    )
    attempt = attempts[0]

    # Same request as both DECISION facts; appended strictly first.
    assert attempt.fact.subject_id == str(sealed_flow.decision.request_id)
    decision_records = [
        r for r in records if r.fact.kind is SealedFactKind.DECISION
    ]
    assert all(attempt.sequence < r.sequence for r in decision_records)

    # The contract: never a verdict key (L3), never DECISION-kind (L1).
    assert "verdict" not in attempt.fact.detail
    assert attempt.fact.kind is not SealedFactKind.DECISION
    assert attempt not in sealed_flow.ledger.list_by_kind(
        SealedFactKind.DECISION
    )

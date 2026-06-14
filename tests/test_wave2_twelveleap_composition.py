"""
Wave 2 batch-3 integration — the TWELVE-leap composition, run together.

The eight-leap file (test_wave2_eightleap_integration.py) pins the batch-1/2
combination with the batch-3 leaps deliberately inert (L5 unbound, L6
flag-off, L3 pull-based, M0b bench-only). Its pins stay intact; this file
adds the three cross-leap interactions that first became constructible at the
batch-3 merge and that no per-leap suite covers (COORDINATION.md
§ "Batch-3 cross-leap findings"):

  1. L5 bound on the SAME ledger-wired PDP that serves customer traffic:
     reflexive DECISION + ENFORCEMENT facts interleave with customer
     DECISION, PQ-durability DECISION and risk-spine DRIFT facts on ONE
     SealedFactLedger — and L1's ``check_seal_binding`` still resolves each
     CUSTOMER decision (the PQ fact shares the customer's subject_id and the
     reflexive evaluation has its own request identity; neither shadows it).
  2. L6 checkpoints over that heterogeneous ledger: an RFC-9162 consistency
     proof SPANNING the gate event verifies — the chain is append-only
     across all four fact kinds, and ``tree_size`` counts leaves of every
     kind (never cite it as "number of decisions").
  3. An L3 certificate + count-conservation over the same epoch. RECOMPOSED
     CONSCIOUSLY at the attempt-hook landing (provenance/attempt_seal.py):
     every evaluate() now seals one ATTEMPT fact at entry — customer
     requests AND the reflexive gate evaluation alike, per the hook's
     declared count-scoping contract (gate evals COUNT as attempts; the
     identity stays global and symmetric). The reflexive evaluation still
     seals an M0 DECISION fact carrying the PDP's OWN verdict (PERMIT) —
     metaguard demoted the composed ruling to ABSTAIN only in the
     ENFORCEMENT fact — and it balances exactly because its ATTEMPT is
     counted too. A customer-only attempt count still reports GATED-BROKEN,
     pinned below as the misscoping alarm.

M0b stays out of scope: a bench harness with zero runtime seam.

Everything below runs the real verdict path; only the LLM-provider seam is
stubbed (``_PermitSemanticAnalyzer``, the eight-leap/zkpdp pattern). The
record-sequence pin is strict on purpose: a new producer appending to the
shared ledger on this flow must show up here and be composed consciously.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from tex.domain.policy import PolicySnapshot
from tex.domain.verdict import Verdict
from tex.engine.pdp import PolicyDecisionPoint
from tex.engine.risk_spine import RISK_SPINE_FLAG, RiskSpine
from tex.evidence.negative_knowledge import (
    check_count_conservation,
    issue_certificate_with_records,
    verify_certificate,
)
from tex.interchange.gix import (
    Checkpoint,
    CheckpointPublisher,
    consistency_path,
    split_signed_note,
    verify_consistency,
    verify_note,
)
from tex.pqcrypto import ml_dsa
from tex.pqcrypto.pq_durability import PQ_NON_REPUDIATION_FLAG
from tex.provenance.ledger import SealedFactLedger
from tex.provenance.models import SealedFactKind
from tex.selfgov.governor import bound_reflexive_governor
from tex.stores.policy_store import InMemoryPolicyStore
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


class _PermitSemanticAnalyzer:
    """Deterministic semantic provider recommending PERMIT with solid
    confidence, so the routed baseline is a real PERMIT the signals can
    lower. Only the LLM-provider seam is stubbed — the deterministic gate,
    specialists, router, floor, CRC and PDP all stay real (same stub as the
    eight-leap file and the zkpdp live cross-check)."""

    def analyze(self, *, request, retrieval_context):
        return make_semantic_analysis(
            recommended_verdict=Verdict.PERMIT,
            recommended_confidence=0.9,
            overall_confidence=0.92,
            dimension_confidence=0.8,
            evidence_sufficiency=0.6,
        )


def _strict_policy(version: str, *, active: bool = False) -> PolicySnapshot:
    return PolicySnapshot(
        policy_id="p",
        version=version,
        is_active=active,
        permit_threshold=0.30,
        forbid_threshold=0.70,
        minimum_confidence=0.50,
        blocked_terms=("ssn",),
        enabled_recognizers=("secrets",),
    )


def _weak_policy(version: str) -> PolicySnapshot:
    """Weakens vs ``_strict_policy`` on every named axis (the walk-down
    payload from the L5 suite)."""
    return PolicySnapshot(
        policy_id="p",
        version=version,
        is_active=False,
        permit_threshold=0.69,
        forbid_threshold=0.71,
        minimum_confidence=0.0,
        blocked_terms=(),
        enabled_recognizers=(),
    )


# The composed epoch, built once: every test reads the same flow. Indices
# into ledger.list_all() — the strict sequence pinned by the first test.
# Recomposed at the attempt-hook landing: every evaluate() seals one ATTEMPT
# at entry (requests A and B, and the reflexive gate evaluation).
_IDX_ATTEMPT_A = 0        # attempt hook (request A, sealed at evaluate() entry)
_IDX_PQ_FACT = 1          # L10 PQ-durable=false (request A, sealed in routing)
_IDX_DECISION_A = 2       # M0 customer decision A
_IDX_BIND = 3             # L5 bind (protective pass)
_IDX_ATTEMPT_GATE = 4     # attempt hook (reflexive gate evaluation)
_IDX_REFLEXIVE = 5        # M0 fact of the reflexive gate evaluation
_IDX_RULING = 6           # L5 denied weakening activation (ENFORCEMENT)
_IDX_ATTEMPT_B = 7        # attempt hook (request B)
_IDX_DRIFT = 8            # L9 spine step (request B)
_IDX_DECISION_B = 9       # M0 customer decision B
_IDX_UNBIND = 10          # L5 unbind


@pytest.fixture(scope="module", autouse=True)
def _force_no_pq_durable_backend():
    """Pin the no-durable-backend branch for this module.

    The epoch below asserts the L10 PQ signal FIRES (lowers PERMIT→ABSTAIN and
    seals its PQ-durable=false DECISION fact) — the disambiguation this suite pins
    engages only when that fact exists. A box with cryptography>=48 ships a durable
    native ML-DSA backend that HONORS the claim instead (no fact), so force the live
    backend id absent to exercise the lowered branch deterministically on any box.
    The honored branch is covered by tests/capstone/test_pq_maturity_branches.py.
    """
    mp = pytest.MonkeyPatch()
    mp.setattr(ml_dsa, "active_backend_id", lambda: None)
    yield
    mp.undo()


@pytest.fixture(scope="module")
def epoch():
    ledger = SealedFactLedger()
    pdp = PolicyDecisionPoint(
        decision_ledger=ledger,
        risk_spine=RiskSpine(alpha=0.05, ledger=ledger),
        semantic_analyzer=_PermitSemanticAnalyzer(),
    )
    policy = make_default_policy()
    publisher = CheckpointPublisher(
        origin="tex.example/twelveleap-e2e",
        read_record_hashes=lambda: [r.record_hash for r in ledger.list_all()],
    )

    # Controller state staged BEFORE binding, so the gate event below is the
    # activation alone (saves while bound would be unsealed stage passes).
    store = InMemoryPolicyStore()
    store.save(_strict_policy("v1"))
    store.activate("v1")
    store.save(_weak_policy("v2"))

    # Customer request A: a PQ-non-repudiation claim the live ECDSA-P256
    # signer cannot honor — L10 lowers PERMIT→ABSTAIN and seals its
    # PQ-durable=false DECISION fact, then M0 seals the customer decision.
    result_a = pdp.evaluate(
        request=make_request(metadata={"pq_non_repudiation": True}),
        policy=policy,
    )
    checkpoint_before = publisher.current_signed_checkpoint()

    with bound_reflexive_governor(pdp=pdp, ledger=ledger):
        # The gate event: a weakening activation through the REAL policy
        # store chokepoint — denied (governance-weakening caution), with the
        # nested PDP evaluation sealing its own DECISION fact first.
        returned = store.activate("v2")
        # Customer request B WHILE the governor is bound: drift 8.0 breaches
        # the spine (DRIFT fact sealed) and lowers PERMIT→ABSTAIN — customer
        # traffic is unperturbed by an active reflexive binding.
        result_b = pdp.evaluate(
            request=make_request(
                metadata={"risk_spine": {"observations": {"drift": 8.0}}}
            ),
            policy=policy,
        )

    checkpoint_after = publisher.current_signed_checkpoint()

    return SimpleNamespace(
        ledger=ledger,
        policy=policy,
        store=store,
        returned_snapshot=returned,
        decision_a=result_a.decision,
        decision_b=result_b.decision,
        checkpoint_before=checkpoint_before,
        checkpoint_after=checkpoint_after,
        publisher=publisher,
    )


def test_one_chain_holds_all_four_kinds_and_stays_verifiable(epoch) -> None:
    """The foundational claim of the batch-3 merge: one SealedFactLedger
    chain interleaves ATTEMPT (entry hook), DECISION (customer, PQ-variant,
    reflexive), ENFORCEMENT and DRIFT producers without breaking integrity
    or authorship, and the denied gate event mutated nothing."""
    kinds = [r.fact.kind for r in epoch.ledger.list_all()]
    assert kinds == [
        SealedFactKind.ATTEMPT,       # _IDX_ATTEMPT_A (entry hook, request A)
        SealedFactKind.DECISION,      # _IDX_PQ_FACT
        SealedFactKind.DECISION,      # _IDX_DECISION_A
        SealedFactKind.ENFORCEMENT,   # _IDX_BIND
        SealedFactKind.ATTEMPT,       # _IDX_ATTEMPT_GATE (reflexive eval)
        SealedFactKind.DECISION,      # _IDX_REFLEXIVE
        SealedFactKind.ENFORCEMENT,   # _IDX_RULING
        SealedFactKind.ATTEMPT,       # _IDX_ATTEMPT_B (entry hook, request B)
        SealedFactKind.DRIFT,         # _IDX_DRIFT
        SealedFactKind.DECISION,      # _IDX_DECISION_B
        SealedFactKind.ENFORCEMENT,   # _IDX_UNBIND
    ], (
        "the composed append sequence changed — a producer was added, removed "
        "or reordered on the shared ledger; recompose this file consciously"
    )

    chain = epoch.ledger.verify_chain()
    sigs = epoch.ledger.verify_signatures()
    assert chain["intact"] is True and chain["break_at"] is None
    assert sigs["valid"] is True and sigs["invalid_at"] is None

    # Both customer signals genuinely acted (no vacuous pass): each lowered a
    # real PERMIT baseline exactly one rung.
    assert epoch.decision_a.verdict is Verdict.ABSTAIN
    assert PQ_NON_REPUDIATION_FLAG in epoch.decision_a.uncertainty_flags
    assert epoch.decision_b.verdict is Verdict.ABSTAIN
    assert RISK_SPINE_FLAG in epoch.decision_b.uncertainty_flags

    # The denied gate event mutated nothing: deny-by-not-mutating.
    assert epoch.returned_snapshot.is_active is False
    assert epoch.store.get_active().version == "v1"
    ruling = epoch.ledger.list_all()[_IDX_RULING].fact
    assert ruling.detail["allowed"] is False
    assert "metaguard.governance_weakening" in ruling.detail["caution_codes"]


def test_l1_seal_binding_resolves_customer_decisions_amid_reflexive_traffic(
    epoch,
) -> None:
    """Interaction 1: with reflexive + PQ + drift records interleaved on the
    same chain, ``check_seal_binding`` binds each customer statement to its
    M0 DECISION fact — not the PQ fact sharing the subject_id, not the
    reflexive evaluation's fact."""
    records = epoch.ledger.list_all()
    for decision, m0_index in (
        (epoch.decision_a, _IDX_DECISION_A),
        (epoch.decision_b, _IDX_DECISION_B),
    ):
        stmt = build_statement_from_decision(decision, policy=epoch.policy)
        assert evaluate_relation(stmt).satisfied
        seal = check_seal_binding(epoch.ledger, stmt)
        assert seal.status == "sealed_match"
        assert seal.chain_intact is True
        assert seal.signatures_valid is True
        # Resolved to the M0 fact at its pinned position in the epoch.
        assert seal.record_sequence == records[m0_index].sequence

    # Why A resolves at all: the L10 PQ fact shares A's subject_id (two
    # DECISION-kind facts for one request) and the binding survives because
    # the PQ fact is appended FIRST and carries no verdict detail. This is
    # the by-accident contract named in COORDINATION.md (batch-3 caution 1);
    # if either half changes, the resolution above is what breaks.
    pq_fact = records[_IDX_PQ_FACT].fact
    assert pq_fact.subject_id == records[_IDX_DECISION_A].fact.subject_id
    assert "verdict" not in pq_fact.detail

    # The reflexive evaluation runs under its OWN request identity — it can
    # never shadow a customer decision by subject_id.
    reflexive_subject = records[_IDX_REFLEXIVE].fact.subject_id
    assert reflexive_subject != str(epoch.decision_a.request_id)
    assert reflexive_subject != str(epoch.decision_b.request_id)


def test_l6_consistency_proof_spans_the_gate_event(epoch) -> None:
    """Interaction 2: a checkpoint taken before the gate event and one taken
    after are RFC-9162-consistent — the heterogeneous appends (ENFORCEMENT,
    reflexive DECISION, DRIFT, customer DECISION) extended the tree without
    rewriting it. Relying-party flow throughout: verify the signed note
    under the pinned log key, take (size, root) jointly from the note."""
    before = epoch.checkpoint_before
    after = epoch.checkpoint_after
    # attempt A + PQ fact + customer decision A
    assert before.checkpoint.tree_size == 3
    assert after.checkpoint.tree_size == 11

    # tree_size counts leaves of EVERY kind — it is not a decision count,
    # and since the attempt hook it is not an attempt count either
    # (COORDINATION.md batch-3 note: never cite it as one).
    n_decisions = sum(
        1
        for r in epoch.ledger.list_all()
        if r.fact.kind is SealedFactKind.DECISION
    )
    assert n_decisions == 4
    assert after.checkpoint.tree_size != n_decisions

    # Verify the log's signature over the AFTER note, then parse (size, root)
    # from the verified text — the root binds the size, never a bare proof.
    verified_names = verify_note(
        after.signed_note, [epoch.publisher.log_verifier]
    )
    assert verified_names, "log-signed note failed under the pinned key"
    parsed = Checkpoint.parse(split_signed_note(after.signed_note)[0])
    assert parsed.tree_size == 11
    assert parsed.root_hash_hex == after.checkpoint.root_hash_hex

    proof = consistency_path(
        before.checkpoint.tree_size, after.record_hashes
    )
    assert verify_consistency(
        before.checkpoint.tree_size,
        before.checkpoint.root_hash_hex,
        after.checkpoint.tree_size,
        after.checkpoint.root_hash_hex,
        proof,
    )

    # A forked pre-gate history (any other old root) refuses the same proof.
    real = before.checkpoint.root_hash_hex
    forged = ("0" if real[0] != "0" else "1") + real[1:]
    assert not verify_consistency(
        3, forged, 11, after.checkpoint.root_hash_hex, proof
    )


def test_l3_certificate_and_conservation_count_reflexive_traffic(epoch) -> None:
    """Interaction 3: an L3 certificate issues and verifies over the
    heterogeneous epoch — and count-conservation COUNTS the reflexive gate
    evaluation, as a PERMIT, for a mutation that was in fact denied. Pinned
    so the attempt-sealing hook design must confront it: a hook counting
    customer attempts only reports GATED-BROKEN against these records."""
    records = epoch.ledger.list_all()

    # Non-membership over the full epoch: every record of every kind is an
    # accumulator leaf (record_count == 11), while conservation below scopes
    # to DECISION-kind facts — two scopes inside one certificate.
    absent_key = "7" * 64
    cert = issue_certificate_with_records(records, absent_key)
    assert verify_certificate(cert).ok is True
    assert cert.commitment.record_count == 11
    assert cert.vacuous is False
    # Hook-era epoch: conservation derives n_attempts from the 3 sealed
    # ATTEMPT facts (A, gate eval, B) with no external input — GATED, and
    # complete=True scoped to the count-conservation dimension only.
    assert cert.complete is True
    assert cert.attempt_hook_present is True
    assert cert.conservation.status == "GATED-HOLDS"
    assert cert.conservation.holds is True
    assert cert.conservation.attempts_source == "derived"
    assert cert.conservation.n_attempts == 3

    # What conservation sees vs what actually happened: the reflexive
    # evaluation's M0 fact carries the PDP's own verdict (PERMIT) — the
    # metaguard demotion to ABSTAIN lives only in the ENFORCEMENT fact,
    # which the DECISION-kind filter excludes.
    reflexive = records[_IDX_REFLEXIVE].fact
    ruling = records[_IDX_RULING].fact
    assert reflexive.kind is SealedFactKind.DECISION
    assert reflexive.detail["verdict"] == "PERMIT"
    assert ruling.kind is SealedFactKind.ENFORCEMENT
    assert ruling.detail["verdict"] == "ABSTAIN"
    assert ruling.detail["allowed"] is False

    # The counts: 1 PERMIT (reflexive eval) + 2 ABSTAIN (customers). The PQ
    # fact (DECISION-kind, no verdict key), the three ENFORCEMENT facts
    # (verdict key present, wrong kind) and the three ATTEMPT facts (distinct
    # kind, the LHS) are all excluded from the verdict side — each exclusion
    # is load-bearing for these numbers.
    # A customer-only count (2) now CONTRADICTS the 3 sealed ATTEMPT facts —
    # the misscoping alarm fires as a fabrication alarm, by construction.
    customer_only = check_count_conservation(records, n_attempts=2)
    assert customer_only.status == "GATED-BROKEN"
    assert customer_only.attempts_source == "derived"
    assert "contradicts" in customer_only.note

    # The declared scoping (gate evals COUNT) is what the sealed facts
    # themselves encode: derived = 3 attempts vs 1 PERMIT + 2 ABSTAIN.
    gate_inclusive = check_count_conservation(records)
    assert (
        gate_inclusive.n_permit,
        gate_inclusive.n_abstain,
        gate_inclusive.n_forbid,
    ) == (1, 2, 0)
    assert gate_inclusive.status == "GATED-HOLDS"
    assert gate_inclusive.holds is True
    assert gate_inclusive.n_attempts == 3

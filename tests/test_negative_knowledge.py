"""
Wave 2 / L3 — negative-knowledge certificate tests.

Each test would FAIL if the behaviour it pins broke:
  * non-membership verifies for genuinely absent keys and is REFUSED/REJECTED
    for present keys; tampered adjacency, indices, roots, and sortedness are
    detected;
  * the omission attack (the ROADMAP earn): rebuilding the epoch with one
    PERMIT hidden breaks the count-conservation predicate AND changes the
    accumulator root against the sealed commitment;
  * the empty epoch round-trips without ever calling the empty-rejecting
    Merkle primitive;
  * the honesty pins: complete=False / attempt_hook_present=False, claims
    scoped to the sealed epoch, UNGATED conservation is never a vacuous pass,
    and the public vocabulary never uses the over-claiming phrases
    unqualified;
  * the Merkle hash that ACTUALLY ran is recorded (Poseidon vs SHA-256
    fallback).
"""

from __future__ import annotations

import inspect
from dataclasses import replace

import pytest

import tex.evidence.negative_knowledge as nk
from tex.domain.evidence import EvidenceMaturity
from tex.evidence.negative_knowledge import (
    ATTEMPT_HOOK_PRESENT,
    EMPTY_EPOCH_SENTINEL,
    FORBIDDEN_UNQUALIFIED_PHRASES,
    DuplicateKeyError,
    KeyPresentError,
    NonMembershipProof,
    build_epoch_accumulator,
    check_count_conservation,
    issue_certificate_with_records,
    recompute_key,
    verify_certificate,
    verify_epoch_commitment,
)
from tex.provenance.ledger import SealedFactLedger
from tex.provenance.models import SealedFact, SealedFactKind
from tex.zkprov.commitment import build_inclusion_proof, merkle_hash_algorithm_in_use


# ------------------------------------------------------------------ fixtures --

def _decision_fact(verdict: str, subject: str) -> SealedFact:
    return SealedFact(
        kind=SealedFactKind.DECISION,
        subject_id=subject,
        claim=f"verdict {verdict} produced for request {subject} — test fixture",
        maturity=EvidenceMaturity.RESEARCH_EARLY,
        detail={"verdict": verdict},
    )


def _epoch(verdicts: list[str]) -> tuple[SealedFactLedger, tuple]:
    """A real sealed epoch: facts appended through the real ledger (hash chain
    + ECDSA signatures), one DECISION fact per verdict."""
    ledger = SealedFactLedger()
    for i, verdict in enumerate(verdicts):
        ledger.append(_decision_fact(verdict, f"req-{i}"))
    return ledger, ledger.list_all()


def _hex_plus_one(h: str) -> str:
    return format(int(h, 16) + 1, "064x")


def _interior_absent_key(sorted_keys: tuple[str, ...]) -> str:
    """A key strictly between two adjacent committed leaves."""
    for a, b in zip(sorted_keys, sorted_keys[1:]):
        candidate = _hex_plus_one(a)
        if candidate < b:
            return candidate
    raise AssertionError("no interior gap found (astronomically unlikely)")


_MIX = ["PERMIT", "PERMIT", "ABSTAIN", "FORBID", "PERMIT"]


# ------------------------------------------- non-membership: absent verifies --

def test_non_membership_verifies_for_absent_keys_all_shapes() -> None:
    _, records = _epoch(_MIX)
    acc = build_epoch_accumulator(records)

    cases = {
        "boundary_low": "0" * 64,
        "boundary_high": "f" * 64,
        "interior": _interior_absent_key(acc.sorted_keys),
    }
    for expected_kind, key in cases.items():
        assert not acc.contains(key)
        cert = issue_certificate_with_records(records, key)
        assert cert.proof.kind == expected_kind
        result = verify_certificate(cert)
        assert result.ok, f"{expected_kind}: {result.reason}"


def test_keys_recomputable_and_match_ledger_field() -> None:
    # The canonical key is independently recomputable — and must equal what
    # the ledger itself stored (the same payload hashing verify_chain replays).
    _, records = _epoch(_MIX)
    for rec in records:
        assert recompute_key(rec.fact) == rec.payload_sha256


# ----------------------------------------------- present keys must not pass --

def test_certificate_refused_for_present_key() -> None:
    _, records = _epoch(_MIX)
    present = recompute_key(records[2].fact)
    with pytest.raises(KeyPresentError):
        issue_certificate_with_records(records, present)


def test_forged_certificate_for_present_key_fails_verification() -> None:
    # An adversary grafts a valid absent-key proof onto a present key.
    _, records = _epoch(_MIX)
    acc = build_epoch_accumulator(records)
    cert = issue_certificate_with_records(records, _interior_absent_key(acc.sorted_keys))
    present = recompute_key(records[0].fact)
    forged = replace(cert, key=present)
    assert verify_certificate(forged).ok is False


# --------------------------------------------------- tamper detection ---------

def test_tampered_adjacency_and_proofs_detected() -> None:
    _, records = _epoch(_MIX)
    acc = build_epoch_accumulator(records)
    key = _interior_absent_key(acc.sorted_keys)
    cert = issue_certificate_with_records(records, key)
    assert cert.proof.kind == "interior"
    assert verify_certificate(cert).ok is True

    left = cert.proof.left_proof
    right = cert.proof.right_proof
    assert left is not None and right is not None

    # 1. Tampered sibling hash in the left inclusion proof.
    bad_sib = ("0" * 64,) + left.siblings[1:]
    tampered = replace(
        cert, proof=replace(cert.proof, left_proof=replace(left, siblings=bad_sib))
    )
    assert verify_certificate(tampered).ok is False

    # 2. Non-adjacent neighbour indices (i and i+2) with otherwise-valid proofs.
    leaves = tuple(k.encode("ascii") for k in acc.sorted_keys)
    skip = build_inclusion_proof(leaves, left.leaf_index + 2)
    non_adjacent = replace(
        cert,
        proof=replace(
            cert.proof,
            right_key=acc.sorted_keys[left.leaf_index + 2],
            right_proof=skip,
        ),
    )
    assert verify_certificate(non_adjacent).ok is False

    # 3. Neighbour key swapped for one that keeps the order check happy but
    #    no longer matches the committed leaf.
    fake_left_key = format(int(cert.proof.left_key, 16) - 1, "064x")  # type: ignore[arg-type]
    assert fake_left_key < key  # order still holds — only inclusion can catch it
    relabelled = replace(cert, proof=replace(cert.proof, left_key=fake_left_key))
    assert verify_certificate(relabelled).ok is False

    # 4. Proof bound to a different root is rejected.
    other_acc = build_epoch_accumulator(records[:-1])
    foreign_root = replace(left, poseidon_root=other_acc.commitment.accumulator_root)
    rebound = replace(cert, proof=replace(cert.proof, left_proof=foreign_root))
    assert verify_certificate(rebound).ok is False


def test_boundary_high_pins_last_leaf_via_record_count() -> None:
    # Inflating record_count must invalidate a boundary_high proof — otherwise
    # "absent above the last leaf" could be claimed against a non-final leaf.
    _, records = _epoch(_MIX)
    cert = issue_certificate_with_records(records, "f" * 64)
    assert cert.proof.kind == "boundary_high"
    inflated = replace(
        cert, commitment=replace(cert.commitment, record_count=len(records) + 1)
    )
    assert verify_certificate(inflated).ok is False


def test_tampered_sortedness_commitment_detected() -> None:
    _, records = _epoch(_MIX)
    acc = build_epoch_accumulator(records)
    assert verify_epoch_commitment(records, acc.commitment).ok is True

    tampered = replace(acc.commitment, sorted_keys_sha256="0" * 64)
    assert verify_epoch_commitment(records, tampered).ok is False


def test_duplicate_keys_refuse_to_accumulate() -> None:
    # Identical canonical payloads ⇒ identical keys ⇒ the sorted-unique
    # invariant adjacency needs is gone; the builder must refuse.
    ledger = SealedFactLedger()
    fact = _decision_fact("PERMIT", "req-dup")
    ledger.append(fact)
    ledger.append(fact)  # same fact object: same canonical payload
    with pytest.raises(DuplicateKeyError):
        build_epoch_accumulator(ledger.list_all())


# ------------------------------------------------- omission attack (the earn) --

def test_omission_attack_breaks_conservation_and_root() -> None:
    """ROADMAP L3 earn: rebuilding the epoch to hide a PERMIT must break the
    conservation predicate — and the rebuilt accumulator must not match the
    sealed commitment."""
    ledger, records = _epoch(_MIX)
    sealed = build_epoch_accumulator(records).commitment

    # Honest epoch, attempt count supplied by the test standing in for the
    # future hook (5 attempts, all reached a verdict, no errors).
    honest = check_count_conservation(records, n_attempts=len(_MIX), n_error=0)
    assert honest.status == "GATED-HOLDS"
    assert honest.holds is True
    assert (honest.n_permit, honest.n_abstain, honest.n_forbid) == (3, 1, 1)

    # Adversary rebuilds the epoch with one PERMIT hidden.
    permit_idx = next(
        i for i, r in enumerate(records) if r.fact.detail["verdict"] == "PERMIT"
    )
    hidden = tuple(r for i, r in enumerate(records) if i != permit_idx)

    # (a) The conservation predicate BREAKS: 5 attempts cannot be accounted
    #     for by 4 verdicts + 0 errors.
    broken = check_count_conservation(hidden, n_attempts=len(_MIX), n_error=0)
    assert broken.status == "GATED-BROKEN"
    assert broken.holds is False

    # (b) The accumulator root changes against the sealed commitment, and the
    #     rebuild-audit rejects the hidden epoch outright.
    rebuilt = build_epoch_accumulator(hidden).commitment
    assert rebuilt.accumulator_root != sealed.accumulator_root
    assert rebuilt.audit_root != sealed.audit_root
    assert verify_epoch_commitment(hidden, sealed).ok is False

    # (c) The original chain stays intact — the attack is a rebuild, not a
    #     break of the honest ledger.
    assert ledger.verify_chain()["intact"] is True


def test_hiding_the_permit_silently_is_not_possible_via_relabel() -> None:
    # Variant: the adversary keeps the count right by relabelling the hidden
    # PERMIT as an "error". The verdict counts now satisfy the identity —
    # but the accumulator root still betrays the rebuilt epoch.
    _, records = _epoch(_MIX)
    sealed = build_epoch_accumulator(records).commitment
    hidden = records[1:]  # drop the first PERMIT
    relabelled = check_count_conservation(hidden, n_attempts=len(_MIX), n_error=1)
    assert relabelled.holds is True  # counts alone CAN be gamed this way...
    # ...which is exactly why the certificate also seals the accumulator root:
    assert verify_epoch_commitment(hidden, sealed).ok is False


# --------------------------------------------------------- empty epoch --------

def test_empty_epoch_round_trips_without_empty_rejecting_primitive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _boom(*args, **kwargs):  # pragma: no cover - the assertion is the test
        raise AssertionError("build_merkle_root must not be called for an empty epoch")

    monkeypatch.setattr(nk, "build_merkle_root", _boom)

    acc = build_epoch_accumulator(())
    assert acc.commitment.record_count == 0
    assert acc.commitment.accumulator_root == EMPTY_EPOCH_SENTINEL
    assert acc.commitment.audit_root == EMPTY_EPOCH_SENTINEL

    cert = issue_certificate_with_records((), "a" * 64)
    assert cert.proof.kind == "empty"
    assert cert.vacuous is True
    result = verify_certificate(cert)
    assert result.ok is True
    assert "vacuous" in result.reason

    # Round-trip: the rebuild-audit accepts the empty commitment too.
    assert verify_epoch_commitment((), acc.commitment).ok is True


def test_empty_proof_shape_rejected_against_non_empty_epoch() -> None:
    _, records = _epoch(_MIX)
    cert = issue_certificate_with_records(records, "0" * 64)
    spoofed = replace(cert, proof=NonMembershipProof(kind="empty"), vacuous=True)
    assert verify_certificate(spoofed).ok is False


# --------------------------------------------------------- honesty pins -------

def test_certificate_carries_incompleteness_pins_for_hookless_epochs() -> None:
    """RECOMPOSED at the attempt-hook landing: the codebase-level constant is
    now True, but an epoch with NO sealed ATTEMPT facts (this fixture appends
    DECISION facts directly — a pre-hook shape) must still carry every
    incompleteness pin: the hook existing is not the hook having RUN."""
    _, records = _epoch(_MIX)
    cert = issue_certificate_with_records(records, "0" * 64)

    assert ATTEMPT_HOOK_PRESENT is True  # the seam landed; flipped after live verify
    assert cert.complete is False
    assert cert.attempt_hook_present is False
    assert cert.conservation.attempts_source is None
    assert cert.ledger_in_memory is True
    assert cert.ledger_opt_in is True
    assert cert.maturity == EvidenceMaturity.RESEARCH_EARLY.value

    # Claim text is scoped to the sealed epoch, not to history.
    assert "THIS ledger epoch" in cert.claim_text
    assert "in-memory" in cert.claim_text
    assert "TEX_SEAL_DECISIONS" in cert.claim_text
    assert "Completeness is NOT claimed" in cert.claim_text


def test_overclaiming_certificate_is_rejected_by_the_verifier() -> None:
    """The rejection direction survives the hook landing: a hook-present /
    complete claim over an epoch whose conservation shows NO sealed ATTEMPT
    source is an over-claim, rejected in every combination."""
    _, records = _epoch(_MIX)  # no ATTEMPT facts: attempts_source is None
    cert = issue_certificate_with_records(records, "0" * 64)
    assert verify_certificate(replace(cert, complete=True)).ok is False
    assert verify_certificate(replace(cert, attempt_hook_present=True)).ok is False
    assert (
        verify_certificate(
            replace(cert, attempt_hook_present=True, complete=True)
        ).ok
        is False
    )
    # Supplied (trust-me) counts cannot support a hook claim either.
    gated_trustme = issue_certificate_with_records(
        records, "0" * 64, n_attempts=len(_MIX)
    )
    assert gated_trustme.conservation.attempts_source == "supplied"
    assert gated_trustme.attempt_hook_present is False
    assert (
        verify_certificate(
            replace(gated_trustme, attempt_hook_present=True)
        ).ok
        is False
    )

    empty_cert = issue_certificate_with_records((), "0" * 64)
    assert verify_certificate(replace(empty_cert, vacuous=False)).ok is False


def test_ungated_conservation_is_never_a_vacuous_pass() -> None:
    _, records = _epoch(_MIX)
    ungated = check_count_conservation(records)  # no n_attempts: hook absent
    assert ungated.status == "UNGATED"
    assert ungated.holds is None
    assert ungated.holds is not True  # the collapse this guards against

    cert = issue_certificate_with_records(records, "0" * 64)
    assert cert.conservation.status == "UNGATED"
    assert cert.conservation.holds is None
    # A certificate whose UNGATED check fabricates a pass must be rejected.
    fabricated = replace(
        cert, conservation=replace(cert.conservation, holds=True)
    )
    assert verify_certificate(fabricated).ok is False


def test_public_vocabulary_never_overclaims_unqualified() -> None:
    """No claim surface may say "never saw" / "provable ignorance" without
    qualification. Certificates must not contain the phrases at all; module
    source may mention them only alongside an explicit negation/forbidden
    marker (the docstring's honesty boundary and the FORBIDDEN list itself)."""
    _, records = _epoch(_MIX)
    for cert in (
        issue_certificate_with_records(records, "0" * 64),
        issue_certificate_with_records((), "0" * 64),
    ):
        text = cert.claim_text.lower()
        for phrase in FORBIDDEN_UNQUALIFIED_PHRASES:
            assert phrase not in text
        assert "epoch" in text  # affirmative scoping present

    source_lines = inspect.getsource(nk).splitlines()
    markers = ("NOT", "FORBIDDEN", "must never", "never use")
    for i, line in enumerate(source_lines):
        lowered = line.lower()
        if not any(p in lowered for p in FORBIDDEN_UNQUALIFIED_PHRASES):
            continue
        window = source_lines[max(0, i - 2) : i + 3]
        assert any(m in w for m in markers for w in window), (
            f"unqualified over-claiming vocabulary at module line {i + 1}: {line!r}"
        )


# ------------------------------------------------- hash actually used ---------

def test_hash_backend_actually_used_is_recorded() -> None:
    _, records = _epoch(_MIX)
    cert = issue_certificate_with_records(records, "0" * 64)
    backend = merkle_hash_algorithm_in_use()  # what THIS process really ran
    assert cert.hash_backend == backend
    assert cert.commitment.hash_backend == backend
    assert backend in {"poseidon-bn254-t3", "sha256-reduced-bn254"}


def test_cross_backend_verification_names_the_mismatch() -> None:
    # A cert built under the other hash backend must be rejected with the real
    # cause named, not a misleading "inclusion proof failed".
    _, records = _epoch(_MIX)
    cert = issue_certificate_with_records(records, "0" * 64)
    backend = merkle_hash_algorithm_in_use()
    other = (
        "poseidon-bn254-t3"
        if backend == "sha256-reduced-bn254"
        else "sha256-reduced-bn254"
    )
    foreign = replace(
        cert,
        hash_backend=other,
        commitment=replace(cert.commitment, hash_backend=other),
    )
    result = verify_certificate(foreign)
    assert result.ok is False
    assert "backend" in result.reason


# ------------------------------------------------- live-seam integration ------

def _live_epoch() -> tuple[SealedFactLedger, tuple]:
    """A real hook-era epoch: live PDP evaluations over a wired ledger —
    each seals 1 ATTEMPT (entry hook) + 1 DECISION (M0 finalize)."""
    from tex.engine.pdp import PolicyDecisionPoint
    from tests.factories import make_default_policy, make_request

    ledger = SealedFactLedger()
    pdp = PolicyDecisionPoint(decision_ledger=ledger)
    policy = make_default_policy()
    for content in (
        "Quarterly metrics look healthy; no further action is needed.",
        "Here is our production api key sk-abcdef1234567890abcdef please use it.",
    ):
        pdp.evaluate(request=make_request(content=content), policy=policy)
    return ledger, ledger.list_all()


def test_epoch_over_real_pdp_sealed_decisions() -> None:
    """End-to-end over the M0 seam: real PDP verdicts sealed via seal_decision,
    then a non-membership certificate over that live epoch."""
    ledger, records = _live_epoch()

    # 2 evaluations × (1 ATTEMPT at entry + 1 DECISION at finalize) — the
    # attempt hook landed; every record of every kind is an accumulator leaf.
    assert len(records) == 4

    present = recompute_key(records[0].fact)
    with pytest.raises(KeyPresentError):
        issue_certificate_with_records(records, present)

    absent = "0" * 64
    cert = issue_certificate_with_records(records, absent)
    assert verify_certificate(cert).ok is True
    assert cert.commitment.epoch_head_hash == records[-1].record_hash


def test_conservation_derives_from_sealed_attempts_and_gates_live() -> None:
    """The completeness earn, first half: over a hook-era epoch the identity
    is GATED with NO externally supplied count — n_attempts comes from the
    sealed ATTEMPT facts themselves, and an honest epoch HOLDS."""
    _, records = _live_epoch()
    cons = check_count_conservation(records)  # no n_attempts argument at all
    assert cons.status == "GATED-HOLDS"
    assert cons.holds is True
    assert cons.attempts_source == "derived"
    assert cons.n_attempts == 2
    assert cons.n_permit + cons.n_abstain + cons.n_forbid == 2


def test_omission_attack_closes_end_to_end_with_derived_attempts() -> None:
    """The completeness earn, second half (the L3 earn condition, finally
    gated): delete one verdict-DECISION from a rebuilt hook-era epoch and the
    DERIVED identity breaks — no trust-me input anywhere in the loop. The
    ATTEMPT facts the adversary cannot account for are the alarm."""
    _, records = _live_epoch()
    sealed = build_epoch_accumulator(records).commitment

    victim_idx = next(
        i
        for i, r in enumerate(records)
        if r.fact.kind is SealedFactKind.DECISION
        and "verdict" in r.fact.detail
    )
    hidden = tuple(r for i, r in enumerate(records) if i != victim_idx)

    broken = check_count_conservation(hidden)  # derived, zero external inputs
    assert broken.status == "GATED-BROKEN"
    assert broken.holds is False
    assert broken.attempts_source == "derived"
    assert broken.n_attempts == 2  # both sealed attempts survive...
    assert broken.n_permit + broken.n_abstain + broken.n_forbid == 1  # ...one verdict gone

    # And the accumulator root still betrays the rebuilt epoch independently.
    assert verify_epoch_commitment(hidden, sealed).ok is False

    # Declared one-sidedness, stated honestly: the SAME signature appears if
    # an evaluation died mid-pipeline — GATED-BROKEN names the gap, not the
    # cause. (tests/test_attempt_seal.py pins the crash variant.)


def test_symmetric_deletion_games_derived_counts_but_not_the_root() -> None:
    """The first attack on "the omission attack closes": delete one ATTEMPT
    *and* its matching verdict-DECISION — the derived counts re-balance, so
    the identity alone reads GATED-HOLDS. The count identity is one LAYER;
    the accumulator root is the BINDING, and it betrays the rebuild. (Same
    class as the relabel variant above, now pinned for the derived path.)"""
    _, records = _live_epoch()
    sealed = build_epoch_accumulator(records).commitment

    drop_attempt = next(
        i
        for i, r in enumerate(records)
        if r.fact.kind is SealedFactKind.ATTEMPT
    )
    drop_decision = next(
        i
        for i, r in enumerate(records)
        if r.fact.kind is SealedFactKind.DECISION
        and "verdict" in r.fact.detail
    )
    hidden = tuple(
        r
        for i, r in enumerate(records)
        if i not in (drop_attempt, drop_decision)
    )

    gamed = check_count_conservation(hidden)
    assert gamed.status == "GATED-HOLDS"  # counts alone CAN be gamed this way...
    assert gamed.n_attempts == 1
    # ...which is exactly why the certificate also seals the accumulator root:
    assert verify_epoch_commitment(hidden, sealed).ok is False


def test_supplied_count_contradicting_sealed_attempts_is_the_alarm() -> None:
    """Sealed facts outrank externally supplied counts: a contradicting
    n_attempts over a hook-era epoch is GATED-BROKEN by itself."""
    _, records = _live_epoch()
    cons = check_count_conservation(records, n_attempts=999)
    assert cons.status == "GATED-BROKEN"
    assert cons.holds is False
    assert cons.attempts_source == "derived"
    assert cons.n_attempts == 2  # the sealed count, not the supplied one
    assert "contradicts" in cons.note

    # A CONSISTENT supplied count is not punished (idempotent with derived).
    consistent = check_count_conservation(records, n_attempts=2)
    assert consistent.status == "GATED-HOLDS"
    assert consistent.attempts_source == "derived"


def test_hook_present_certificate_is_accepted_with_epoch_evidence() -> None:
    """The acceptance direction (the verifier relaxation, both ways): a
    hook-era certificate carries attempt_hook_present=True and complete=True
    — scoped to the conservation dimension — and VERIFIES. The claim text
    names the one-sidedness and the pre-entry blind spot."""
    _, records = _live_epoch()
    cert = issue_certificate_with_records(records, "0" * 64)

    assert cert.attempt_hook_present is True
    assert cert.complete is True
    assert cert.conservation.status == "GATED-HOLDS"
    assert cert.conservation.attempts_source == "derived"
    result = verify_certificate(cert)
    assert result.ok is True, result.reason

    assert "COUNT-CONSERVATION dimension only" in cert.claim_text
    assert "ONE-SIDED" in cert.claim_text
    assert "before evaluate() entry" in cert.claim_text

    # Stripping the evidence flips it back to a rejected over-claim — the
    # fields are load-bearing, not decorative.
    stripped = replace(
        cert, conservation=replace(cert.conservation, attempts_source=None)
    )
    assert verify_certificate(stripped).ok is False

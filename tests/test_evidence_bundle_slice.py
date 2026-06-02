"""
Tests for the evidence-bundle slice verifier (closes KNOWN_BUGS #5).

Bug #5 narrative. Until Thread 6, ``GET /decisions/{id}/evidence-bundle``
returned ``is_chain_valid: False`` on every single-record bundle that
was not the global chain genesis. The verifier was using
``verify_evidence_chain`` on the filtered slice, which treats the
first record it sees as the chain genesis and emits
``unexpected_previous_hash`` whenever ``previous_hash`` is set on
the slice's first record. The underlying JSONL log was genuinely
valid; the API's slice-verification logic was wrong.

The fix follows the inclusion-proof-with-witness pattern that
Certificate Transparency, Sigstore Rekor, and Microsoft Agent
Governance Toolkit's MerkleAuditChain converge on as the standard
for verifying a sub-range of an append-only log: the caller passes
the ``record_hash`` of the predecessor record as an out-of-band
*witness*, and the verifier validates the slice's first record's
``previous_hash`` against the witness.

This test file proves five things:

1. Single-record bundles for genesis decisions verify cleanly
   (the simple case that always worked).
2. Single-record bundles for non-genesis decisions verify cleanly
   when the witness is supplied (the case Bug #5 was about).
3. Sub-range slices (records 2..4 of a 5-record chain) verify
   cleanly with the witness.
4. Tampered slices fail with the right diagnostic codes
   (``prior_link_witness_mismatch``, ``payload_sha256_mismatch``,
   ``record_hash_mismatch``).
5. A slice without a witness emits ``missing_prior_link_witness``
   so the caller knows the verdict is incomplete.
"""

from __future__ import annotations

import hashlib
import tempfile
from pathlib import Path
from uuid import uuid4

import pytest

from tex.domain.decision import Decision
from tex.domain.verdict import Verdict
from tex.evidence.chain import (
    verify_evidence_chain,
    verify_evidence_chain_slice,
)
from tex.evidence.exporter import EvidenceExporter
from tex.evidence.recorder import EvidenceRecorder


# ─── fixtures: build a real 5-record chain on disk ────────────────────────


@pytest.fixture()
def recorder(tmp_path: Path) -> EvidenceRecorder:
    return EvidenceRecorder(tmp_path / "evidence.jsonl")


@pytest.fixture()
def exporter(recorder: EvidenceRecorder) -> EvidenceExporter:
    return EvidenceExporter(recorder)


@pytest.fixture()
def chain(recorder: EvidenceRecorder) -> tuple[list[Decision], EvidenceRecorder]:
    """Records 5 decisions and returns the list of their domain objects."""
    decisions: list[Decision] = []
    for i in range(5):
        content = f"decision content #{i}"
        d = Decision(
            decision_id=uuid4(),
            request_id=uuid4(),
            verdict=Verdict.PERMIT,
            confidence=0.9,
            final_score=0.1,
            action_type="send_email",
            channel="outbound_email",
            environment="production",
            content_excerpt=content,
            content_sha256=hashlib.sha256(content.encode()).hexdigest(),
            policy_version="v1",
        )
        recorder.record_decision(d)
        decisions.append(d)
    return decisions, recorder


# ════════════════════════════════════════════════════════════════════════════
# verify_evidence_chain_slice — pure function tests
# ════════════════════════════════════════════════════════════════════════════


def test_empty_slice_is_valid() -> None:
    """Empty slice trivially verifies."""
    result = verify_evidence_chain_slice([])
    assert result.is_valid
    assert result.record_count == 0
    assert result.issues == ()


def test_genesis_slice_validates_with_no_witness(
    chain: tuple[list[Decision], EvidenceRecorder]
) -> None:
    """
    A slice that begins at the chain genesis (first record's
    previous_hash is None) verifies cleanly without a witness — this
    is the case that always worked.
    """
    _, recorder = chain
    all_records = recorder.read_all()
    genesis = all_records[0]
    assert genesis.previous_hash is None

    result = verify_evidence_chain_slice([genesis], prior_link_witness=None)
    assert result.is_valid, result.issues
    assert result.record_count == 1


def test_non_genesis_slice_with_witness_validates(
    chain: tuple[list[Decision], EvidenceRecorder]
) -> None:
    """
    Bug #5 regression. A single-record slice of a non-genesis decision
    verifies cleanly when the predecessor's record_hash is supplied as
    a witness.

    Before the fix this returned False with
    ``unexpected_previous_hash``.
    """
    _, recorder = chain
    all_records = recorder.read_all()
    middle = all_records[2]
    witness = all_records[1].record_hash

    result = verify_evidence_chain_slice(
        [middle], prior_link_witness=witness
    )
    assert result.is_valid, result.issues
    assert result.record_count == 1


def test_non_genesis_slice_without_witness_emits_explicit_issue(
    chain: tuple[list[Decision], EvidenceRecorder]
) -> None:
    """
    A non-genesis slice without a witness is *not* silently passed
    off as valid. The verifier emits ``missing_prior_link_witness``
    so the caller knows the verdict is incomplete.

    This is the principled fix for the same defect class that caused
    Bug #5: a verifier that pretends it can validate something it
    cannot is worse than one that cannot validate at all.
    """
    _, recorder = chain
    all_records = recorder.read_all()
    middle = all_records[2]

    result = verify_evidence_chain_slice([middle], prior_link_witness=None)
    assert not result.is_valid
    codes = {issue.code for issue in result.issues}
    assert "missing_prior_link_witness" in codes


def test_sub_range_slice_with_witness_validates(
    chain: tuple[list[Decision], EvidenceRecorder]
) -> None:
    """A multi-record sub-range slice with a witness verifies."""
    _, recorder = chain
    all_records = recorder.read_all()
    slice_ = all_records[2:5]  # records 2, 3, 4
    witness = all_records[1].record_hash

    result = verify_evidence_chain_slice(
        slice_, prior_link_witness=witness
    )
    assert result.is_valid, result.issues
    assert result.record_count == 3


def test_tampered_witness_fails(
    chain: tuple[list[Decision], EvidenceRecorder]
) -> None:
    """A forged witness must trigger ``prior_link_witness_mismatch``."""
    _, recorder = chain
    all_records = recorder.read_all()
    middle = all_records[2]
    forged_witness = "a" * 64  # well-formed but wrong

    result = verify_evidence_chain_slice(
        [middle], prior_link_witness=forged_witness
    )
    assert not result.is_valid
    codes = {issue.code for issue in result.issues}
    assert "prior_link_witness_mismatch" in codes


def test_witness_with_genesis_record_fails(
    chain: tuple[list[Decision], EvidenceRecorder]
) -> None:
    """
    Caller asserting a predecessor while the record claims to be
    genesis is a contradiction; verifier surfaces it explicitly.
    """
    _, recorder = chain
    all_records = recorder.read_all()
    genesis = all_records[0]
    assert genesis.previous_hash is None
    forged_witness = "b" * 64

    result = verify_evidence_chain_slice(
        [genesis], prior_link_witness=forged_witness
    )
    assert not result.is_valid
    codes = {issue.code for issue in result.issues}
    assert "unexpected_previous_hash" in codes


def test_malformed_witness_is_rejected_at_parse_time(
    chain: tuple[list[Decision], EvidenceRecorder]
) -> None:
    """
    A witness that is not a 64-char lowercase hex digest is rejected
    at parse time — the verifier never sees malformed input.
    """
    _, recorder = chain
    all_records = recorder.read_all()
    middle = all_records[2]

    for bad_witness in [
        "too short",
        "X" * 64,  # uppercase / non-hex
        "g" * 64,  # non-hex
        "",
    ]:
        with pytest.raises(ValueError):
            verify_evidence_chain_slice(
                [middle], prior_link_witness=bad_witness
            )


def test_internal_record_integrity_still_verified(
    chain: tuple[list[Decision], EvidenceRecorder]
) -> None:
    """
    The slice verifier still runs full per-record integrity checks
    (payload_sha256 match, record_hash match) on every record in
    the slice, so a tampered middle record is caught even with a
    valid witness.
    """
    _, recorder = chain
    all_records = recorder.read_all()

    # Fabricate a slice where record 2 has been tampered: build a new
    # record with mutated payload but the original record_hash. The
    # payload_sha256 will then not match payload_json.
    original = all_records[2]
    tampered = original.model_copy(
        update={"payload_json": '{"tampered": true}'}
    )

    witness = all_records[1].record_hash
    result = verify_evidence_chain_slice(
        [tampered], prior_link_witness=witness
    )
    assert not result.is_valid
    codes = {issue.code for issue in result.issues}
    assert "payload_sha256_mismatch" in codes


# ════════════════════════════════════════════════════════════════════════════
# verify_evidence_chain — preserved behavior
# ════════════════════════════════════════════════════════════════════════════


def test_existing_full_chain_verifier_is_unchanged(
    chain: tuple[list[Decision], EvidenceRecorder]
) -> None:
    """
    Thread 6 must not break the 5 existing callers of
    ``verify_evidence_chain``. The full-chain verifier still treats
    the first record as genesis and emits unchanged diagnostics.
    """
    _, recorder = chain
    all_records = recorder.read_all()

    # Full chain validates
    full_result = verify_evidence_chain(all_records)
    assert full_result.is_valid, full_result.issues
    assert full_result.record_count == 5

    # Single non-genesis record via full-chain verifier still fails
    # with unexpected_previous_hash — this is the preserved legacy
    # behavior that ``verify_evidence_chain_slice`` was added
    # alongside, not replaced.
    legacy_result = verify_evidence_chain([all_records[2]])
    assert not legacy_result.is_valid
    codes = {issue.code for issue in legacy_result.issues}
    assert "unexpected_previous_hash" in codes


# ════════════════════════════════════════════════════════════════════════════
# EvidenceExporter.build_slice_bundle — integration tests
# ════════════════════════════════════════════════════════════════════════════


def test_build_slice_bundle_for_genesis_decision(
    chain: tuple[list[Decision], EvidenceRecorder],
    exporter: EvidenceExporter,
) -> None:
    """
    A slice bundle for the first decision in the chain has
    ``prior_link_witness=None`` (it's the genesis) and verifies
    cleanly.
    """
    decisions, _ = chain
    bundle = exporter.build_slice_bundle(
        export_name="genesis-bundle",
        decision_id=decisions[0].decision_id,
    )
    assert bundle.record_count == 1
    assert bundle.is_chain_valid
    assert bundle.prior_link_witness is None


def test_build_slice_bundle_for_middle_decision_includes_witness(
    chain: tuple[list[Decision], EvidenceRecorder],
    exporter: EvidenceExporter,
) -> None:
    """
    Bug #5 fix verified end-to-end through EvidenceExporter. A
    slice bundle for a non-genesis decision verifies cleanly because
    the exporter looks up the predecessor record's hash and supplies
    it as the witness.
    """
    decisions, recorder = chain
    all_records = recorder.read_all()
    expected_witness = all_records[1].record_hash  # decision 1 is predecessor of decision 2

    bundle = exporter.build_slice_bundle(
        export_name="middle-bundle",
        decision_id=decisions[2].decision_id,
    )
    assert bundle.record_count == 1
    assert bundle.is_chain_valid, bundle.verification.issues
    assert bundle.prior_link_witness == expected_witness


def test_build_slice_bundle_for_last_decision_includes_witness(
    chain: tuple[list[Decision], EvidenceRecorder],
    exporter: EvidenceExporter,
) -> None:
    """The last decision's bundle also includes a witness."""
    decisions, recorder = chain
    all_records = recorder.read_all()
    expected_witness = all_records[3].record_hash

    bundle = exporter.build_slice_bundle(
        export_name="last-bundle",
        decision_id=decisions[4].decision_id,
    )
    assert bundle.record_count == 1
    assert bundle.is_chain_valid
    assert bundle.prior_link_witness == expected_witness


def test_build_slice_bundle_empty_when_no_matching_records(
    chain: tuple[list[Decision], EvidenceRecorder],
    exporter: EvidenceExporter,
) -> None:
    """No matching records → empty bundle, still verifies trivially."""
    bundle = exporter.build_slice_bundle(
        export_name="empty",
        decision_id=uuid4(),  # no such decision
    )
    assert bundle.record_count == 0
    assert bundle.is_chain_valid
    assert bundle.prior_link_witness is None


def test_bundle_to_dict_exposes_witness(
    chain: tuple[list[Decision], EvidenceRecorder],
    exporter: EvidenceExporter,
) -> None:
    """
    The JSON envelope must expose ``prior_link_witness`` so external
    verifiers can independently re-validate the slice against their
    own copy of the parent chain.
    """
    decisions, _ = chain
    bundle = exporter.build_slice_bundle(
        export_name="middle-bundle",
        decision_id=decisions[2].decision_id,
    )
    body = bundle.to_dict()
    assert "prior_link_witness" in body
    assert body["prior_link_witness"] == bundle.prior_link_witness
    assert body["is_chain_valid"] is True


# ════════════════════════════════════════════════════════════════════════════
# /decisions/{id}/evidence-bundle — full HTTP round-trip
# ════════════════════════════════════════════════════════════════════════════


def test_evidence_bundle_endpoint_returns_valid_for_non_genesis_slice() -> None:
    """
    End-to-end through the FastAPI route. Records two decisions, then
    requests the bundle for the second (non-genesis) decision.
    Asserts ``is_chain_valid: True`` and the witness is included.

    Before Thread 6 this assertion failed with
    ``is_chain_valid: False`` and the issue text
    "first record must not contain a previous_hash" (Bug #5).
    """
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from tex.main import create_app

    app = create_app()
    client = TestClient(app)

    def _evaluate(content: str) -> str:
        response = client.post(
            "/evaluate",
            json={
                "request_id": str(uuid4()),
                "action_type": "send_email",
                "channel": "outbound_email",
                "environment": "production",
                "content": content,
            },
        )
        assert response.status_code == 200, response.text
        return response.json()["decision_id"]

    # Two decisions: first is the global genesis on a fresh recorder
    _ = _evaluate("benign content one")
    second = _evaluate("benign content two")

    bundle_response = client.get(f"/decisions/{second}/evidence-bundle")
    assert bundle_response.status_code == 200, bundle_response.text
    body = bundle_response.json()

    assert body["is_chain_valid"] is True, body.get("verification")
    assert body["prior_link_witness"] is not None
    assert len(body["prior_link_witness"]) == 64
    assert body["record_count"] >= 1

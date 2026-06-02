"""Tests for the /v1/guardrail evidence-payload integration hook (Thread 14)."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime

import pytest

from tex.zkprov.commitment import deterministic_test_ca, issue_commitment
from tex.zkprov.integration import (
    PAYLOAD_KEY_ZKPROV_COMMITMENT_ID,
    PAYLOAD_KEY_ZKPROV_PROOF,
    PAYLOAD_KEY_ZKPROV_RECEIPT,
    TEX_ZKPROV_ENV,
    attach_provenance_proof_to_payload,
    attach_receipt_to_payload,
    is_zkprov_enabled,
    verify_payload_provenance_proof,
    verify_payload_receipt,
)
from tex.zkprov.manifest import (
    DatasetManifest,
    DataSource,
    LicenseTag,
    TDSSourceCategory,
)
from tex.zkprov.proof import generate_proof
from tex.zkprov.receipts import (
    EpistemicClaim,
    Pramana,
    ToolCallRecord,
    issue_receipt,
)


def _manifest() -> DatasetManifest:
    return DatasetManifest(
        manifest_id="m1",
        model_card_uri="https://x",
        model_provider="ACME",
        sources=(
            DataSource(
                source_id="s1",
                source_uri="hf://x",
                content_sha256="a" * 64,
                record_count=3,
                tds_category=TDSSourceCategory.PUBLICLY_AVAILABLE_DATASET,
                license=LicenseTag.MIT,
                max_epoch_participation=1,
            ),
        ),
        preprocessing=(),
        total_training_epochs=1,
        base_model_sha256="b" * 64,
        training_window_start=datetime(2025, 1, 1, tzinfo=UTC),
        training_window_end=datetime(2026, 1, 1, tzinfo=UTC),
        issued_at=datetime(2026, 1, 1, tzinfo=UTC),
        valid_until=datetime(2027, 1, 1, tzinfo=UTC),
    )


def test_zkprov_disabled_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(TEX_ZKPROV_ENV, raising=False)
    assert not is_zkprov_enabled()


def test_zkprov_enabled_by_env_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(TEX_ZKPROV_ENV, "1")
    assert is_zkprov_enabled()


def test_zkprov_accepts_various_truthy_values(monkeypatch: pytest.MonkeyPatch) -> None:
    for v in ("1", "true", "TRUE", "Yes", "on"):
        monkeypatch.setenv(TEX_ZKPROV_ENV, v)
        assert is_zkprov_enabled(), f"failed for {v!r}"


def test_attach_provenance_proof_returns_copy() -> None:
    manifest = _manifest()
    commitment = issue_commitment(
        dataset_id="d1",
        dataset_records=(b"r1",),
        manifest=manifest,
        ca_keypair=deterministic_test_ca("t"),
        schema_canonical_json=b"{}",
    )
    proof = generate_proof(
        response="hello",
        prompt="hi",
        prompt_attributes={},
        model_commitment_hash="c" * 64,
        commitment=commitment,
        manifest=manifest,
        private_witness=b"w",
    )
    original_payload = {"some": "value"}
    augmented = attach_provenance_proof_to_payload(original_payload, proof=proof)
    # Returns a copy.
    assert "zkprov_proof" not in original_payload
    assert PAYLOAD_KEY_ZKPROV_PROOF in augmented
    assert augmented[PAYLOAD_KEY_ZKPROV_COMMITMENT_ID] == "d1"
    assert augmented["some"] == "value"


def test_verify_payload_provenance_proof_roundtrip() -> None:
    manifest = _manifest()
    commitment = issue_commitment(
        dataset_id="d1",
        dataset_records=(b"r1",),
        manifest=manifest,
        ca_keypair=deterministic_test_ca("t"),
        schema_canonical_json=b"{}",
    )
    proof = generate_proof(
        response="hello",
        prompt="hi",
        prompt_attributes={},
        model_commitment_hash="c" * 64,
        commitment=commitment,
        manifest=manifest,
        private_witness=b"w",
    )
    payload = attach_provenance_proof_to_payload({}, proof=proof)
    response_hash = hashlib.sha256(b"hello").hexdigest()
    result = verify_payload_provenance_proof(
        payload,
        expected_dataset_commitment=commitment,
        expected_response_sha256_hex=response_hash,
    )
    assert result is not None
    assert result.is_valid


def test_verify_payload_returns_none_when_no_proof() -> None:
    result = verify_payload_provenance_proof(
        {},
        expected_dataset_commitment=None,  # type: ignore[arg-type]
        expected_response_sha256_hex="0" * 64,
    )
    assert result is None


def test_attach_and_verify_receipt() -> None:
    tc = ToolCallRecord(
        call_id="c1",
        tool_name="search",
        arguments_sha256="1" * 64,
        result_sha256="2" * 64,
        occurred_at=datetime.now(UTC),
    )
    cl = EpistemicClaim(
        claim_id="cl1",
        text_sha256="3" * 64,
        pramana=Pramana.PRATYAKSHA,
        backing_call_id="c1",
        cot_trace_sha256=None,
    )
    receipt = issue_receipt(
        receipt_id="r1", response="x", tool_calls=(tc,), claims=(cl,)
    )
    payload = attach_receipt_to_payload({}, receipt=receipt)
    assert PAYLOAD_KEY_ZKPROV_RECEIPT in payload
    assert verify_payload_receipt(payload)


def test_verify_payload_receipt_returns_false_when_absent() -> None:
    assert not verify_payload_receipt({})


def test_verify_payload_receipt_rejects_malformed() -> None:
    payload = {PAYLOAD_KEY_ZKPROV_RECEIPT: "not-json"}
    assert not verify_payload_receipt(payload)

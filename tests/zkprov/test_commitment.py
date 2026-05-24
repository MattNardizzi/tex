"""Tests for ZKPROV commitment, manifest, and Merkle tree."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from tex.zkprov.commitment import (
    build_inclusion_proof,
    build_merkle_root,
    canonical_signing_bytes,
    deterministic_test_ca,
    issue_commitment,
    issue_commitment_tag,
    verify_commitment_signature,
    verify_commitment_tag,
    verify_commitment_valid,
)
from tex.zkprov.manifest import (
    DatasetManifest,
    DataSource,
    LicenseTag,
    PreprocessingStep,
    TDSSourceCategory,
    project_to_tds_summary,
)


# --------------------------------------------------------------------------- #
# Fixtures                                                                    #
# --------------------------------------------------------------------------- #


def _make_manifest(*, sources_n: int = 1) -> DatasetManifest:
    sources = tuple(
        DataSource(
            source_id=f"s{i}",
            source_uri=f"hf://example/source-{i}",
            content_sha256="a" * 64,
            record_count=100,
            tds_category=TDSSourceCategory.PUBLICLY_AVAILABLE_DATASET,
            license=LicenseTag.MIT,
            max_epoch_participation=2,
        )
        for i in range(sources_n)
    )
    return DatasetManifest(
        manifest_id="m1",
        model_card_uri="https://example.com/card",
        model_provider="ACME",
        sources=sources,
        preprocessing=(),
        total_training_epochs=2,
        base_model_sha256="b" * 64,
        training_window_start=datetime(2025, 1, 1, tzinfo=UTC),
        training_window_end=datetime(2026, 1, 1, tzinfo=UTC),
        issued_at=datetime(2026, 1, 1, tzinfo=UTC),
        valid_until=datetime(2027, 1, 1, tzinfo=UTC),
    )


# --------------------------------------------------------------------------- #
# Merkle tree                                                                 #
# --------------------------------------------------------------------------- #


def test_build_merkle_root_deterministic() -> None:
    records = (b"a", b"b", b"c", b"d")
    r1 = build_merkle_root(records)
    r2 = build_merkle_root(records)
    assert r1 == r2


def test_build_merkle_root_distinct_records_distinct_roots() -> None:
    assert build_merkle_root((b"a", b"b")) != build_merkle_root((b"a", b"c"))


def test_build_merkle_root_returns_two_roots() -> None:
    poseidon_root, audit_root = build_merkle_root((b"x",))
    assert len(poseidon_root) == 64
    assert len(audit_root) == 64
    assert poseidon_root != audit_root


def test_build_merkle_root_empty_rejected() -> None:
    with pytest.raises(ValueError):
        build_merkle_root(())


def test_build_merkle_root_handles_non_power_of_two() -> None:
    # Should pad correctly and not raise.
    root3, _ = build_merkle_root((b"a", b"b", b"c"))
    root4, _ = build_merkle_root((b"a", b"b", b"c", b"d"))
    assert root3 != root4


def test_inclusion_proof_verifies() -> None:
    records = (b"r0", b"r1", b"r2", b"r3", b"r4")
    for i, r in enumerate(records):
        proof = build_inclusion_proof(records, i)
        assert proof.verify(r), f"inclusion verify failed for index {i}"


def test_inclusion_proof_rejects_wrong_record() -> None:
    records = (b"r0", b"r1", b"r2", b"r3")
    proof = build_inclusion_proof(records, 1)
    assert not proof.verify(b"not-r1")


def test_inclusion_proof_out_of_range() -> None:
    with pytest.raises(IndexError):
        build_inclusion_proof((b"a", b"b"), 99)


# --------------------------------------------------------------------------- #
# DatasetManifest                                                             #
# --------------------------------------------------------------------------- #


def test_manifest_root_hash_deterministic() -> None:
    m = _make_manifest()
    assert m.manifest_root_hash() == m.manifest_root_hash()


def test_manifest_unique_source_ids_enforced() -> None:
    with pytest.raises(ValueError):
        DatasetManifest(
            manifest_id="m1",
            model_card_uri="https://x",
            model_provider="ACME",
            sources=(
                DataSource(
                    source_id="same",
                    source_uri="u1",
                    content_sha256="a" * 64,
                    record_count=1,
                    tds_category=TDSSourceCategory.PUBLICLY_AVAILABLE_DATASET,
                    license=LicenseTag.MIT,
                    max_epoch_participation=1,
                ),
                DataSource(
                    source_id="same",  # duplicate
                    source_uri="u2",
                    content_sha256="b" * 64,
                    record_count=1,
                    tds_category=TDSSourceCategory.PUBLICLY_AVAILABLE_DATASET,
                    license=LicenseTag.MIT,
                    max_epoch_participation=1,
                ),
            ),
            preprocessing=(),
            total_training_epochs=1,
            base_model_sha256="c" * 64,
            training_window_start=datetime(2025, 1, 1, tzinfo=UTC),
            training_window_end=datetime(2026, 1, 1, tzinfo=UTC),
            issued_at=datetime(2026, 1, 1, tzinfo=UTC),
            valid_until=datetime(2027, 1, 1, tzinfo=UTC),
        )


def test_manifest_preprocessing_order_must_be_contiguous() -> None:
    with pytest.raises(ValueError):
        DatasetManifest(
            manifest_id="m1",
            model_card_uri="https://x",
            model_provider="ACME",
            sources=(
                DataSource(
                    source_id="s1",
                    source_uri="u",
                    content_sha256="a" * 64,
                    record_count=1,
                    tds_category=TDSSourceCategory.PUBLICLY_AVAILABLE_DATASET,
                    license=LicenseTag.MIT,
                    max_epoch_participation=1,
                ),
            ),
            preprocessing=(
                PreprocessingStep(
                    name="dedupe",
                    code_sha256="1" * 64,
                    config_sha256="2" * 64,
                    order=0,
                ),
                PreprocessingStep(
                    name="tokenize",
                    code_sha256="3" * 64,
                    config_sha256="4" * 64,
                    order=2,  # skipping 1 — should fail
                ),
            ),
            total_training_epochs=1,
            base_model_sha256="b" * 64,
            training_window_start=datetime(2025, 1, 1, tzinfo=UTC),
            training_window_end=datetime(2026, 1, 1, tzinfo=UTC),
            issued_at=datetime(2026, 1, 1, tzinfo=UTC),
            valid_until=datetime(2027, 1, 1, tzinfo=UTC),
        )


def test_project_to_tds_summary() -> None:
    m = _make_manifest(sources_n=3)
    summary = project_to_tds_summary(m)
    # 3 sources * 100 records each, all PUBLICLY_AVAILABLE_DATASET.
    assert summary.records_by_category == {"publicly-available-dataset": 300}
    assert summary.manifest_root_hash == m.manifest_root_hash()


# --------------------------------------------------------------------------- #
# Commitment signing + verification                                           #
# --------------------------------------------------------------------------- #


def test_issue_and_verify_commitment_roundtrip() -> None:
    records = (b"rec-1", b"rec-2", b"rec-3")
    manifest = _make_manifest()
    ca = deterministic_test_ca("test")

    commitment = issue_commitment(
        dataset_id="d1",
        dataset_records=records,
        manifest=manifest,
        ca_keypair=ca,
        schema_canonical_json=b'{"schema":"v1"}',
    )
    assert commitment.record_count == 3
    assert verify_commitment_signature(commitment) is True
    assert verify_commitment_valid(commitment) is True


def test_issue_commitment_zero_records_rejected() -> None:
    with pytest.raises(ValueError):
        issue_commitment(
            dataset_id="d1",
            dataset_records=(),
            manifest=_make_manifest(),
            ca_keypair=deterministic_test_ca("test"),
            schema_canonical_json=b"{}",
        )


def test_commitment_signature_tamper_detection() -> None:
    ca = deterministic_test_ca("test")
    c = issue_commitment(
        dataset_id="d1",
        dataset_records=(b"x",),
        manifest=_make_manifest(),
        ca_keypair=ca,
        schema_canonical_json=b"{}",
    )
    # Tamper with the signature.
    from dataclasses import replace

    tampered = replace(c, ca_signature=c.ca_signature[:-1] + bytes([c.ca_signature[-1] ^ 1]))
    assert not verify_commitment_signature(tampered)


def test_commitment_expiry_check() -> None:
    ca = deterministic_test_ca("test")
    issued = datetime(2026, 1, 1, tzinfo=UTC)
    c = issue_commitment(
        dataset_id="d1",
        dataset_records=(b"x",),
        manifest=_make_manifest(),
        ca_keypair=ca,
        schema_canonical_json=b"{}",
        issued_at=issued,
        valid_for_seconds=86400,  # one day
    )
    # In-window.
    assert verify_commitment_valid(c, now=issued + timedelta(hours=1))
    # Past expiry.
    assert not verify_commitment_valid(c, now=issued + timedelta(days=2))


def test_canonical_signing_bytes_deterministic() -> None:
    ts = datetime(2026, 1, 1, tzinfo=UTC)
    from tex.pqcrypto.algorithm_agility import SignatureAlgorithm

    args = dict(
        dataset_id="d",
        manifest_root_hash="a" * 64,
        poseidon_root_hex="b" * 64,
        audit_root_hex="c" * 64,
        record_count=5,
        schema_canonical_hash="d" * 64,
        issued_at=ts,
        valid_until=ts + timedelta(days=365),
        ca_algorithm=SignatureAlgorithm.ED25519,
    )
    assert canonical_signing_bytes(**args) == canonical_signing_bytes(**args)


# --------------------------------------------------------------------------- #
# HMAC tag (NABAOS-style fast path)                                           #
# --------------------------------------------------------------------------- #


def test_commitment_tag_roundtrip() -> None:
    c = issue_commitment(
        dataset_id="d1",
        dataset_records=(b"x",),
        manifest=_make_manifest(),
        ca_keypair=deterministic_test_ca("test"),
        schema_canonical_json=b"{}",
    )
    key = b"x" * 32
    tag = issue_commitment_tag(commitment=c, response_sha256_hex="f" * 64, hmac_key=key)
    assert verify_commitment_tag(
        commitment=c, response_sha256_hex="f" * 64, tag_hex=tag, hmac_key=key
    )


def test_commitment_tag_wrong_key_rejected() -> None:
    c = issue_commitment(
        dataset_id="d1",
        dataset_records=(b"x",),
        manifest=_make_manifest(),
        ca_keypair=deterministic_test_ca("test"),
        schema_canonical_json=b"{}",
    )
    tag = issue_commitment_tag(
        commitment=c, response_sha256_hex="f" * 64, hmac_key=b"x" * 32
    )
    assert not verify_commitment_tag(
        commitment=c, response_sha256_hex="f" * 64, tag_hex=tag, hmac_key=b"y" * 32
    )


def test_commitment_tag_short_key_rejected() -> None:
    c = issue_commitment(
        dataset_id="d1",
        dataset_records=(b"x",),
        manifest=_make_manifest(),
        ca_keypair=deterministic_test_ca("test"),
        schema_canonical_json=b"{}",
    )
    with pytest.raises(ValueError):
        issue_commitment_tag(
            commitment=c, response_sha256_hex="f" * 64, hmac_key=b"short"
        )

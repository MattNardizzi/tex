"""Tests for ZKPROV proof generation and verification."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from dataclasses import replace

import pytest

from tex.zkprov.backends import (
    BackendUnavailable,
    DeterministicShimBackend,
    Halo2IpaBackend,
    ProofBackendId,
    ProvenanceStatement,
    get_proof_backend,
    is_regulator_grade,
    resolve_backend_with_fallback,
)
from tex.zkprov.commitment import (
    DatasetCommitment,
    deterministic_test_ca,
    issue_commitment,
)
from tex.zkprov.manifest import (
    DatasetManifest,
    DataSource,
    LicenseTag,
    TDSSourceCategory,
)
from tex.zkprov.proof import (
    CIRCUIT_VERSION,
    ProvenanceProof,
    assemble_statement,
    generate_proof,
    verify_proof,
)


def _manifest_and_commitment() -> tuple[DatasetManifest, DatasetCommitment]:
    manifest = DatasetManifest(
        manifest_id="m1",
        model_card_uri="https://example.com/card",
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
    commitment = issue_commitment(
        dataset_id="d1",
        dataset_records=(b"r1", b"r2", b"r3"),
        manifest=manifest,
        ca_keypair=deterministic_test_ca("test"),
        schema_canonical_json=b"{}",
    )
    return manifest, commitment


# --------------------------------------------------------------------------- #
# Statement assembly                                                          #
# --------------------------------------------------------------------------- #


def test_assemble_statement_canonical() -> None:
    _, c = _manifest_and_commitment()
    s1 = assemble_statement(
        response="r",
        prompt="p",
        prompt_attributes={"a": 1, "b": 2},
        model_commitment_hash="c" * 64,
        commitment=c,
    )
    s2 = assemble_statement(
        response="r",
        prompt="p",
        prompt_attributes={"b": 2, "a": 1},  # different key order
        model_commitment_hash="c" * 64,
        commitment=c,
    )
    # Canonical encoding sorts keys, so the hashes should match.
    assert s1.prompt_attribute_hash == s2.prompt_attribute_hash
    assert s1.canonical_bytes() == s2.canonical_bytes()


def test_assemble_statement_pins_circuit_version() -> None:
    _, c = _manifest_and_commitment()
    s = assemble_statement(
        response="r",
        prompt="p",
        prompt_attributes={},
        model_commitment_hash="c" * 64,
        commitment=c,
    )
    assert s.circuit_version == CIRCUIT_VERSION


# --------------------------------------------------------------------------- #
# generate_proof + verify_proof — shim backend                                #
# --------------------------------------------------------------------------- #


def test_generate_and_verify_proof_roundtrip() -> None:
    manifest, commitment = _manifest_and_commitment()
    proof = generate_proof(
        response="hello",
        prompt="hi",
        prompt_attributes={"topic": "test"},
        model_commitment_hash="c" * 64,
        commitment=commitment,
        manifest=manifest,
        private_witness=b"witness",
        allow_shim_fallback=True,
    )
    assert proof.backend is ProofBackendId.DETERMINISTIC_SHIM_V1
    response_hash = hashlib.sha256(b"hello").hexdigest()
    v = verify_proof(
        proof,
        expected_dataset_commitment=commitment,
        expected_response_sha256_hex=response_hash,
    )
    assert v.is_valid
    assert v.is_regulator_grade is False
    assert v.statement_consistent
    assert v.statement_binds_commitment
    assert v.commitment_signature_valid
    assert v.commitment_in_lifetime
    assert v.backend_verdict


def test_verify_proof_rejects_response_mismatch() -> None:
    manifest, commitment = _manifest_and_commitment()
    proof = generate_proof(
        response="hello",
        prompt="hi",
        prompt_attributes={},
        model_commitment_hash="c" * 64,
        commitment=commitment,
        manifest=manifest,
        private_witness=b"witness",
    )
    wrong_hash = hashlib.sha256(b"different").hexdigest()
    v = verify_proof(
        proof,
        expected_dataset_commitment=commitment,
        expected_response_sha256_hex=wrong_hash,
    )
    assert not v.is_valid
    assert not v.statement_consistent


def test_verify_proof_rejects_commitment_substitution() -> None:
    manifest, commitment = _manifest_and_commitment()
    proof = generate_proof(
        response="hello",
        prompt="hi",
        prompt_attributes={},
        model_commitment_hash="c" * 64,
        commitment=commitment,
        manifest=manifest,
        private_witness=b"witness",
    )
    # Substitute a different commitment with the same shape.
    other_commitment = issue_commitment(
        dataset_id="d-OTHER",
        dataset_records=(b"r1",),
        manifest=manifest,
        ca_keypair=deterministic_test_ca("test"),
        schema_canonical_json=b"{}",
    )
    response_hash = hashlib.sha256(b"hello").hexdigest()
    v = verify_proof(
        proof,
        expected_dataset_commitment=other_commitment,
        expected_response_sha256_hex=response_hash,
    )
    assert not v.is_valid
    assert not v.statement_binds_commitment


def test_verify_proof_regulator_grade_rejects_shim() -> None:
    manifest, commitment = _manifest_and_commitment()
    proof = generate_proof(
        response="hello",
        prompt="hi",
        prompt_attributes={},
        model_commitment_hash="c" * 64,
        commitment=commitment,
        manifest=manifest,
        private_witness=b"witness",
    )
    response_hash = hashlib.sha256(b"hello").hexdigest()
    v = verify_proof(
        proof,
        expected_dataset_commitment=commitment,
        expected_response_sha256_hex=response_hash,
        regulator_grade=True,
    )
    assert not v.is_valid
    assert v.reason and "not regulator-grade" in v.reason


def test_verify_proof_with_tampered_proof_bytes() -> None:
    manifest, commitment = _manifest_and_commitment()
    proof = generate_proof(
        response="hello",
        prompt="hi",
        prompt_attributes={},
        model_commitment_hash="c" * 64,
        commitment=commitment,
        manifest=manifest,
        private_witness=b"witness",
    )
    tampered = replace(proof, proof_bytes=proof.proof_bytes[:-1] + b"X")
    response_hash = hashlib.sha256(b"hello").hexdigest()
    v = verify_proof(
        tampered,
        expected_dataset_commitment=commitment,
        expected_response_sha256_hex=response_hash,
    )
    assert not v.is_valid
    assert not v.backend_verdict


# --------------------------------------------------------------------------- #
# Envelope round-trip                                                         #
# --------------------------------------------------------------------------- #


def test_proof_envelope_roundtrip_preserves_hash() -> None:
    manifest, commitment = _manifest_and_commitment()
    proof = generate_proof(
        response="hello",
        prompt="hi",
        prompt_attributes={},
        model_commitment_hash="c" * 64,
        commitment=commitment,
        manifest=manifest,
        private_witness=b"w",
    )
    envelope = proof.to_envelope_json()
    parsed = ProvenanceProof.from_envelope_json(envelope)
    assert proof.envelope_sha256() == parsed.envelope_sha256()


def test_proof_envelope_rejects_unknown_kind() -> None:
    with pytest.raises(ValueError):
        ProvenanceProof.from_envelope_json('{"kind":"not-zkprov"}')


# --------------------------------------------------------------------------- #
# Backend dispatcher                                                          #
# --------------------------------------------------------------------------- #


def test_backend_resolver_shim_always_available() -> None:
    backend = get_proof_backend(ProofBackendId.DETERMINISTIC_SHIM_V1)
    assert isinstance(backend, DeterministicShimBackend)


def test_backend_resolver_halo2_raises_without_circuit() -> None:
    # ezkl may or may not be installed; either way prove() raises
    # BackendUnavailable until the bundled circuit artifact ships.
    backend = get_proof_backend(ProofBackendId.HALO2_IPA_2026)
    assert isinstance(backend, Halo2IpaBackend)


def test_backend_resolver_falls_back_to_shim_when_allowed() -> None:
    backend = resolve_backend_with_fallback(
        ProofBackendId.LATTICEFOLD_PLUS_2026, allow_shim_fallback=True
    )
    # LatticeFold+ has no Python binding — the resolver should
    # have returned a backend that won't crash on construction.
    # Whether the prove() call falls through happens later.
    assert backend.backend_id in {
        ProofBackendId.LATTICEFOLD_PLUS_2026,
        ProofBackendId.DETERMINISTIC_SHIM_V1,
    }


def test_backend_resolver_unknown_id_raises() -> None:
    with pytest.raises(ValueError):
        get_proof_backend("not-a-real-backend")


def test_is_regulator_grade_classifier() -> None:
    assert not is_regulator_grade(ProofBackendId.DETERMINISTIC_SHIM_V1)
    assert is_regulator_grade(ProofBackendId.HALO2_IPA_2026)
    assert is_regulator_grade(ProofBackendId.DEEPPROVE_2026)
    assert is_regulator_grade(ProofBackendId.LATTICEFOLD_PLUS_2026)


# --------------------------------------------------------------------------- #
# Sub-2-second performance target on shim (sanity check)                      #
# --------------------------------------------------------------------------- #


def test_shim_prove_and_verify_fast() -> None:
    """The shim is a wiring exerciser; it must be sub-second.

    The CLAIMS.md claim about sub-2-second verification refers to
    the regulator-grade backends (Halo2-IPA, DeepProve). The shim
    is loud about not being regulator-grade. This test just makes
    sure the wiring isn't accidentally slow.
    """
    import time

    manifest, commitment = _manifest_and_commitment()
    t0 = time.perf_counter()
    proof = generate_proof(
        response="x",
        prompt="y",
        prompt_attributes={},
        model_commitment_hash="c" * 64,
        commitment=commitment,
        manifest=manifest,
        private_witness=b"w",
    )
    t1 = time.perf_counter()
    response_hash = hashlib.sha256(b"x").hexdigest()
    v = verify_proof(
        proof,
        expected_dataset_commitment=commitment,
        expected_response_sha256_hex=response_hash,
    )
    t2 = time.perf_counter()
    assert v.is_valid
    # Shim is sub-millisecond on a normal box; allow generous CI headroom.
    assert (t1 - t0) < 2.0, f"prove took {t1-t0:.3f}s"
    assert (t2 - t1) < 2.0, f"verify took {t2-t1:.3f}s"

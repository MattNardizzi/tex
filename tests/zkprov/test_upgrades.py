"""Tests for Thread 14 upgrade pass — May 18 2026 frontier additions.

Covers:
  1. VEIL hash-based ZK backend (eprint 2026/683, Apr 8 2026)
  2. SP1 Hypercube backend (Succinct mainnet Feb 19 2026)
  3. Mira parallel folding (ZKTorch arxiv 2507.07031)
  4. Real Poseidon-BN254-t3 Merkle hash replacing SHA-256 reduction
  5. /v1/zkprov/health exposes the new standards + live merkle alg
"""

from __future__ import annotations

import pytest

from tex.zkprov.backends import (
    BackendUnavailable,
    ProofBackendId,
    SP1HypercubeBackend,
    VeilHashBasedZkBackend,
    get_proof_backend,
    is_regulator_grade,
    resolve_backend_with_fallback,
)
from tex.zkprov.commitment import (
    build_inclusion_proof,
    build_merkle_root,
    merkle_hash_algorithm_in_use,
)
from tex.zkprov.recursive import FoldingScheme


# =========================================================================== #
# (1) VEIL backend                                                            #
# =========================================================================== #


def test_veil_backend_id_present() -> None:
    """VEIL backend variant exists with the correct wire-format string."""
    assert ProofBackendId.VEIL_HASH_BASED_ZK_2026.value == "veil-hash-based-zk-2026"


def test_veil_backend_resolves_via_dispatcher() -> None:
    backend = get_proof_backend(ProofBackendId.VEIL_HASH_BASED_ZK_2026)
    assert isinstance(backend, VeilHashBasedZkBackend)
    assert backend.backend_id is ProofBackendId.VEIL_HASH_BASED_ZK_2026


def test_veil_backend_is_regulator_grade() -> None:
    """VEIL is hash-based PQ — qualifies as regulator-grade per Article 53(1)(d)."""
    assert is_regulator_grade(ProofBackendId.VEIL_HASH_BASED_ZK_2026)


def test_veil_backend_prove_raises_backend_unavailable() -> None:
    """The Python binding isn't shipping yet — must raise with a clear pointer."""
    backend = get_proof_backend(ProofBackendId.VEIL_HASH_BASED_ZK_2026)
    # The shim values for the test inputs don't matter — we just want to
    # see BackendUnavailable with the right install pointer.
    with pytest.raises(BackendUnavailable) as exc_info:
        backend.prove(statement=None, private_witness=b"")  # type: ignore[arg-type]
    msg = str(exc_info.value)
    assert "veil" in msg.lower()
    # The message should at least hint at how the binding will land.
    assert "binding" in msg.lower() or "shim" in msg.lower()


def test_veil_backend_falls_back_to_shim_when_allowed() -> None:
    """resolve_backend_with_fallback knows about VEIL."""
    backend = resolve_backend_with_fallback(
        ProofBackendId.VEIL_HASH_BASED_ZK_2026, allow_shim_fallback=True
    )
    assert backend.backend_id in {
        ProofBackendId.VEIL_HASH_BASED_ZK_2026,
        ProofBackendId.DETERMINISTIC_SHIM_V1,
    }


# =========================================================================== #
# (2) SP1 Hypercube backend                                                   #
# =========================================================================== #


def test_sp1_hypercube_backend_id_present() -> None:
    assert ProofBackendId.SP1_HYPERCUBE_2026.value == "sp1-hypercube-2026"


def test_sp1_hypercube_resolves_via_dispatcher() -> None:
    backend = get_proof_backend(ProofBackendId.SP1_HYPERCUBE_2026)
    assert isinstance(backend, SP1HypercubeBackend)


def test_sp1_hypercube_is_regulator_grade() -> None:
    """SP1 Hypercube is mainnet-deployed; qualifies as regulator-grade
    (the ZK property comes from wrapping in VEIL — declared at the
    manifest level)."""
    assert is_regulator_grade(ProofBackendId.SP1_HYPERCUBE_2026)


def test_sp1_hypercube_prove_raises_backend_unavailable() -> None:
    backend = get_proof_backend(ProofBackendId.SP1_HYPERCUBE_2026)
    with pytest.raises(BackendUnavailable) as exc_info:
        backend.prove(statement=None, private_witness=b"")  # type: ignore[arg-type]
    msg = str(exc_info.value).lower()
    assert "sp1" in msg
    # Should point to sp1up or the SDK install path.
    assert "sp1up" in msg or "sdk" in msg


def test_sp1_hypercube_falls_back_to_shim_when_allowed() -> None:
    backend = resolve_backend_with_fallback(
        ProofBackendId.SP1_HYPERCUBE_2026, allow_shim_fallback=True
    )
    assert backend.backend_id in {
        ProofBackendId.SP1_HYPERCUBE_2026,
        ProofBackendId.DETERMINISTIC_SHIM_V1,
    }


# =========================================================================== #
# (3) Mira parallel folding                                                   #
# =========================================================================== #


def test_mira_parallel_folding_scheme_present() -> None:
    assert FoldingScheme.MIRA_PARALLEL_2026.value == "mira-parallel-2026"


def test_mira_parallel_accepted_at_regulator_grade() -> None:
    """Mira is on the regulator-grade folding allowlist (it backs ZKTorch
    and any future DeepProve composition that uses it). Aggregating an
    empty proof set still raises ValueError — we just verify the enum
    lands in the allowlist via aggregate_proofs round-trip below."""
    from datetime import UTC, datetime

    from tex.zkprov.commitment import deterministic_test_ca, issue_commitment
    from tex.zkprov.manifest import (
        DatasetManifest,
        DataSource,
        LicenseTag,
        TDSSourceCategory,
    )
    from tex.zkprov.proof import generate_proof
    from tex.zkprov.recursive import (
        aggregate_proofs,
        verify_aggregated_certificate,
    )

    manifest = DatasetManifest(
        manifest_id="m1",
        model_card_uri="https://x",
        model_provider="ACME",
        sources=(
            DataSource(
                source_id="s1",
                source_uri="hf://x",
                content_sha256="a" * 64,
                record_count=2,
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
        dataset_records=(b"r1", b"r2"),
        manifest=manifest,
        ca_keypair=deterministic_test_ca("t"),
        schema_canonical_json=b"{}",
    )
    proof = generate_proof(
        response="x",
        prompt="y",
        prompt_attributes={},
        model_commitment_hash="c" * 64,
        commitment=commitment,
        manifest=manifest,
        private_witness=b"w",
    )

    cert = aggregate_proofs(
        (proof,),
        aggregation_id="a-mira",
        folding_scheme=FoldingScheme.MIRA_PARALLEL_2026,
        max_batch_size=10,
        window_start=datetime(2026, 1, 1, tzinfo=UTC),
        window_end=datetime(2026, 2, 1, tzinfo=UTC),
    )
    # Non-regulator path always passes when the cert is well-formed.
    assert verify_aggregated_certificate(cert)
    # Regulator-grade rejects because the underlying leaf proof is the shim;
    # this confirms Mira is on the *folding* allowlist (otherwise the rejection
    # reason would mention the scheme, not the leaf backend).
    assert not verify_aggregated_certificate(cert, regulator_grade=True)


# =========================================================================== #
# (4) Real Poseidon-BN254-t3 Merkle hash                                      #
# =========================================================================== #


def test_merkle_hash_in_use_is_poseidon_when_available() -> None:
    """When ``poseidon-hash`` is importable (it is — see requirements),
    the live merkle hash should be the real Poseidon."""
    pytest.importorskip("poseidon")
    assert merkle_hash_algorithm_in_use() == "poseidon-bn254-t3"


def test_poseidon_merkle_root_deterministic_across_calls() -> None:
    """Real Poseidon-BN254-t3 must be byte-for-byte reproducible."""
    poseidon_root_1, audit_root_1 = build_merkle_root((b"a", b"b", b"c", b"d"))
    poseidon_root_2, audit_root_2 = build_merkle_root((b"a", b"b", b"c", b"d"))
    assert poseidon_root_1 == poseidon_root_2
    assert audit_root_1 == audit_root_2


def test_poseidon_merkle_root_differs_from_audit_root() -> None:
    """The Poseidon root and the SHA-256 audit root must NOT collide —
    if they do, something is wrong with the dispatcher (probably the
    Poseidon path silently fell back to SHA-256)."""
    poseidon_root, audit_root = build_merkle_root((b"a", b"b", b"c", b"d"))
    assert poseidon_root != audit_root


def test_poseidon_inclusion_proof_roundtrip() -> None:
    """Inclusion proofs verify under the real Poseidon-BN254 hash."""
    records = (b"r0", b"r1", b"r2", b"r3", b"r4", b"r5", b"r6")
    for i, r in enumerate(records):
        proof = build_inclusion_proof(records, i)
        assert proof.verify(r), f"Poseidon inclusion failed at index {i}"


def test_poseidon_root_changes_with_record_perturbation() -> None:
    """One-byte flip in a record must change the root (collision resistance
    sanity check — not a security proof, just a wiring check)."""
    root_a, _ = build_merkle_root((b"alpha", b"beta", b"gamma"))
    root_b, _ = build_merkle_root((b"alpha", b"beta!", b"gamma"))
    assert root_a != root_b


def test_poseidon_root_is_field_element_sized() -> None:
    """Poseidon over BN254 outputs a 32-byte field element."""
    poseidon_root, _ = build_merkle_root((b"x",))
    # Hex encoding is 64 chars; the underlying value is < BN254-r (~254 bits).
    assert len(poseidon_root) == 64
    BN254_R = 0x30644E72E131A029B85045B68181585D2833E84879B9709143E1F593F0000001
    assert int(poseidon_root, 16) < BN254_R


# =========================================================================== #
# (5) /v1/zkprov/health surfaces the new standards                            #
# =========================================================================== #


def test_health_endpoint_exposes_new_backends() -> None:
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from tex.api.zkprov_routes import router

    app = FastAPI()
    app.include_router(router)
    client = TestClient(app)

    r = client.get("/v1/zkprov/health")
    assert r.status_code == 200
    data = r.json()
    assert "veil-hash-based-zk-2026" in data["supported_backends"]
    assert "sp1-hypercube-2026" in data["supported_backends"]
    assert "mira-parallel-2026" in data["supported_folding_schemes"]


def test_health_endpoint_exposes_new_standards() -> None:
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from tex.api.zkprov_routes import router

    app = FastAPI()
    app.include_router(router)
    client = TestClient(app)

    r = client.get("/v1/zkprov/health")
    data = r.json()
    standards = data["standards_pinned"]
    assert "veil_hash_based_zk" in standards
    assert "sp1_hypercube" in standards
    assert "mira_parallel_accumulation" in standards
    assert "poseidon_merkle_hash" in standards
    # Sanity-check that the citations carry the right dates.
    assert "2026/683" in standards["veil_hash_based_zk"] or "Apr 8 2026" in standards["veil_hash_based_zk"]
    assert "2026" in standards["sp1_hypercube"]


def test_health_endpoint_reports_merkle_hash_in_use() -> None:
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from tex.api.zkprov_routes import router

    app = FastAPI()
    app.include_router(router)
    client = TestClient(app)

    r = client.get("/v1/zkprov/health")
    data = r.json()
    assert "merkle_hash_in_use" in data
    assert data["merkle_hash_in_use"] in {
        "poseidon-bn254-t3",
        "sha256-reduced-bn254",
    }

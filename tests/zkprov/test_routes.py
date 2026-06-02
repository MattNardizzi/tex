"""Tests for ``/v1/zkprov/*`` HTTP route surface — Thread 14."""

from __future__ import annotations

import base64
import hashlib
from datetime import UTC, datetime

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from tex.api.zkprov_routes import router


@pytest.fixture
def client() -> TestClient:
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


def _manifest_dto() -> dict:
    return {
        "manifest_id": "m-test",
        "model_card_uri": "https://example.com/card",
        "model_provider": "ACME Inc",
        "sources": [
            {
                "source_id": "s1",
                "source_uri": "hf://test",
                "content_sha256": "a" * 64,
                "record_count": 3,
                "tds_category": "publicly-available-dataset",
                "license": "MIT",
                "license_extra": "",
                "max_epoch_participation": 1,
            }
        ],
        "preprocessing": [],
        "total_training_epochs": 1,
        "base_model_sha256": "b" * 64,
        "training_window_start": "2025-01-01T00:00:00+00:00",
        "training_window_end": "2026-01-01T00:00:00+00:00",
        "merkle_hash_alg": "poseidon2-bn254-t3",
        "proof_backend": "halo2-ipa-2026",
        "issued_at": "2026-01-01T00:00:00+00:00",
        "valid_until": "2027-01-01T00:00:00+00:00",
    }


def _issue_commitment(client: TestClient) -> dict:
    body = {
        "dataset_id": "d-test",
        "record_bytes_b64": [
            base64.b64encode(b"r1").decode(),
            base64.b64encode(b"r2").decode(),
            base64.b64encode(b"r3").decode(),
        ],
        "manifest": _manifest_dto(),
        "schema_canonical_json_b64": base64.b64encode(b"{}").decode(),
        "use_deterministic_test_ca": True,
        "test_ca_label": "test",
    }
    r = client.post("/v1/zkprov/issue-commitment", json=body)
    assert r.status_code == 200, r.text
    return r.json()


def test_health_endpoint(client: TestClient) -> None:
    r = client.get("/v1/zkprov/health")
    assert r.status_code == 200
    data = r.json()
    assert "circuit_version" in data
    assert data["circuit_version"].startswith("zkprov-v1-")
    assert "supported_backends" in data
    assert "halo2-ipa-2026" in data["supported_backends"]
    assert "deepprove-2026" in data["supported_backends"]
    assert "latticefold-plus-2026" in data["supported_backends"]
    assert "scitt_arp" in data["standards_pinned"]
    assert "nabaos" in data["standards_pinned"]
    assert "eu_ai_act_article_53_1_d" in data["standards_pinned"]


def test_issue_commitment_endpoint(client: TestClient) -> None:
    payload = _issue_commitment(client)
    commitment = payload["commitment"]
    summary = payload["tds_public_summary"]
    assert commitment["dataset_id"] == "d-test"
    assert commitment["record_count"] == 3
    assert commitment["ca_algorithm"] == "ed25519"
    assert summary["records_by_category"] == {"publicly-available-dataset": 3}
    assert summary["manifest_root_hash"] == commitment["manifest_root_hash"]


def test_issue_commitment_requires_deterministic_test_ca(client: TestClient) -> None:
    body = {
        "dataset_id": "d-test",
        "record_bytes_b64": [base64.b64encode(b"r1").decode()],
        "manifest": _manifest_dto(),
        "schema_canonical_json_b64": base64.b64encode(b"{}").decode(),
        "use_deterministic_test_ca": False,  # no HSM key-id support yet
    }
    r = client.post("/v1/zkprov/issue-commitment", json=body)
    assert r.status_code == 400
    assert "HSM" in r.json()["detail"] or "deterministic" in r.json()["detail"]


def test_prove_and_verify_endpoints(client: TestClient) -> None:
    commitment = _issue_commitment(client)["commitment"]

    prove_body = {
        "response": "the answer",
        "prompt": "the question",
        "prompt_attributes": {"topic": "math"},
        "model_commitment_hash": "c" * 64,
        "commitment": commitment,
        "manifest": _manifest_dto(),
        "private_witness_b64": base64.b64encode(b"witness").decode(),
        "allow_shim_fallback": True,
    }
    r = client.post("/v1/zkprov/prove", json=prove_body)
    assert r.status_code == 200, r.text
    proof = r.json()
    assert proof["backend"] == "deterministic-shim-v1"
    assert proof["is_regulator_grade"] is False

    # Verify
    response_hash = hashlib.sha256(b"the answer").hexdigest()
    verify_body = {
        "proof_envelope_json": proof["proof_envelope_json"],
        "expected_commitment": commitment,
        "expected_response_sha256_hex": response_hash,
        "regulator_grade": False,
    }
    r = client.post("/v1/zkprov/verify", json=verify_body)
    assert r.status_code == 200
    v = r.json()
    assert v["is_valid"]
    assert v["statement_consistent"]
    assert v["statement_binds_commitment"]
    assert v["commitment_signature_valid"]
    assert v["commitment_in_lifetime"]
    assert v["backend_verdict"]


def test_verify_endpoint_regulator_grade_rejects_shim(client: TestClient) -> None:
    commitment = _issue_commitment(client)["commitment"]
    prove_body = {
        "response": "x",
        "prompt": "y",
        "prompt_attributes": {},
        "model_commitment_hash": "c" * 64,
        "commitment": commitment,
        "manifest": _manifest_dto(),
        "private_witness_b64": base64.b64encode(b"w").decode(),
    }
    proof = client.post("/v1/zkprov/prove", json=prove_body).json()
    response_hash = hashlib.sha256(b"x").hexdigest()
    r = client.post(
        "/v1/zkprov/verify",
        json={
            "proof_envelope_json": proof["proof_envelope_json"],
            "expected_commitment": commitment,
            "expected_response_sha256_hex": response_hash,
            "regulator_grade": True,
        },
    )
    assert r.status_code == 200
    v = r.json()
    assert not v["is_valid"]
    assert "regulator-grade" in v["reason"]


def test_verify_endpoint_rejects_response_mismatch(client: TestClient) -> None:
    commitment = _issue_commitment(client)["commitment"]
    prove_body = {
        "response": "x",
        "prompt": "y",
        "prompt_attributes": {},
        "model_commitment_hash": "c" * 64,
        "commitment": commitment,
        "manifest": _manifest_dto(),
        "private_witness_b64": base64.b64encode(b"w").decode(),
    }
    proof = client.post("/v1/zkprov/prove", json=prove_body).json()
    wrong_hash = hashlib.sha256(b"WRONG").hexdigest()
    r = client.post(
        "/v1/zkprov/verify",
        json={
            "proof_envelope_json": proof["proof_envelope_json"],
            "expected_commitment": commitment,
            "expected_response_sha256_hex": wrong_hash,
            "regulator_grade": False,
        },
    )
    v = r.json()
    assert not v["is_valid"]
    assert not v["statement_consistent"]


def test_verify_endpoint_malformed_envelope_rejected(client: TestClient) -> None:
    commitment = _issue_commitment(client)["commitment"]
    r = client.post(
        "/v1/zkprov/verify",
        json={
            "proof_envelope_json": '{"kind":"not-zkprov"}',
            "expected_commitment": commitment,
            "expected_response_sha256_hex": "0" * 64,
        },
    )
    assert r.status_code == 400


def test_aggregate_endpoint(client: TestClient) -> None:
    commitment = _issue_commitment(client)["commitment"]
    proofs = []
    for resp in ("a", "b", "c"):
        body = {
            "response": resp,
            "prompt": "p",
            "prompt_attributes": {},
            "model_commitment_hash": "c" * 64,
            "commitment": commitment,
            "manifest": _manifest_dto(),
            "private_witness_b64": base64.b64encode(b"w").decode(),
        }
        proofs.append(client.post("/v1/zkprov/prove", json=body).json()["proof_envelope_json"])

    r = client.post(
        "/v1/zkprov/aggregate",
        json={
            "aggregation_id": "agg-1",
            "proof_envelopes_json": proofs,
            "folding_scheme": "hypernova-cyclefold-2026",
            "max_batch_size": 10,
            "window_start": "2026-01-01T00:00:00+00:00",
            "window_end": "2026-02-01T00:00:00+00:00",
        },
    )
    assert r.status_code == 200
    data = r.json()
    assert data["leaf_count"] == 3
    assert data["folding_scheme"] == "hypernova-cyclefold-2026"
    assert data["post_quantum"] is False


def test_aggregate_endpoint_latticefold_post_quantum(client: TestClient) -> None:
    commitment = _issue_commitment(client)["commitment"]
    body = {
        "response": "x",
        "prompt": "p",
        "prompt_attributes": {},
        "model_commitment_hash": "c" * 64,
        "commitment": commitment,
        "manifest": _manifest_dto(),
        "private_witness_b64": base64.b64encode(b"w").decode(),
    }
    proof_env = client.post("/v1/zkprov/prove", json=body).json()["proof_envelope_json"]

    r = client.post(
        "/v1/zkprov/aggregate",
        json={
            "aggregation_id": "agg-pq",
            "proof_envelopes_json": [proof_env],
            "folding_scheme": "latticefold-plus-2026",
            "max_batch_size": 10,
            "window_start": "2026-01-01T00:00:00+00:00",
            "window_end": "2026-02-01T00:00:00+00:00",
        },
    )
    assert r.status_code == 200
    assert r.json()["post_quantum"] is True


def test_narrow_endpoint_data_volume(client: TestClient) -> None:
    r = client.post(
        "/v1/zkprov/narrow",
        json={"manifest": _manifest_dto(), "predicate": "data-volume-bucket"},
    )
    assert r.status_code == 200
    data = r.json()
    assert data["predicate"] == "data-volume-bucket"
    assert data["predicate_value"] == "<10k"


def test_narrow_endpoint_license_family(client: TestClient) -> None:
    r = client.post(
        "/v1/zkprov/narrow",
        json={"manifest": _manifest_dto(), "predicate": "license-family-present"},
    )
    assert r.status_code == 200
    assert "Permissive" in r.json()["predicate_value"]


def test_narrow_endpoint_temporal_requires_cutoff(client: TestClient) -> None:
    r = client.post(
        "/v1/zkprov/narrow",
        json={"manifest": _manifest_dto(), "predicate": "temporal-window-overlap"},
    )
    assert r.status_code == 400


def test_get_proof_endpoint_persistence(client: TestClient) -> None:
    commitment = _issue_commitment(client)["commitment"]
    body = {
        "response": "x",
        "prompt": "y",
        "prompt_attributes": {},
        "model_commitment_hash": "c" * 64,
        "commitment": commitment,
        "manifest": _manifest_dto(),
        "private_witness_b64": base64.b64encode(b"w").decode(),
        "persist_to_store": True,
        "tenant_id": "tenant-a",
    }
    proof = client.post("/v1/zkprov/prove", json=body).json()
    env_sha = proof["proof_envelope_sha256"]

    r = client.get(f"/v1/zkprov/proof/{env_sha}")
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["envelope_sha256"] == env_sha
    assert data["backend"] == "deterministic-shim-v1"
    assert data["dataset_commitment_id"] == "d-test"


def test_get_proof_endpoint_404_when_missing(client: TestClient) -> None:
    r = client.get(f"/v1/zkprov/proof/{'0'*64}")
    assert r.status_code == 404

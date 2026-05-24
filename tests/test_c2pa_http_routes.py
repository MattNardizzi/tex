"""
HTTP-level tests for the Thread 5 C2PA routes.

Goal: prove that ``POST /v1/c2pa/verify`` correctly verifies a real
manifest produced by ``build_signed_manifest_with_cosign``, and
correctly reports the five-attack-defense status from
arxiv 2604.24890.

The ``GET /v1/evidence/{record_id}/c2pa`` route requires a Postgres
mirror; we use a stand-in in-memory mirror attached to the app's
runtime state so the test runs offline.
"""

from __future__ import annotations

import base64
import hashlib
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

from tex.c2pa import (
    build_email_manifest,
    build_signed_manifest_with_cosign,
    clear_signing_keys,
    full_file_sha256,
    register_signing_key,
    serialize_manifest_for_storage,
)
from tex.c2pa.signer import set_keystore
from tex.pqcrypto._ed25519_provider import Ed25519Provider
from tex.pqcrypto.algorithm_agility import SignatureAlgorithm, SignatureKeyPair


def _mint_outer_chain() -> dict:
    now = datetime.now(timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "T5 HTTP Root")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    leaf_key = ed25519.Ed25519PrivateKey.generate()
    leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "t5.http.test")])
    leaf = (
        x509.CertificateBuilder()
        .subject_name(leaf_name)
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    priv_pem = leaf_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = leaf_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    chain_pem = (
        leaf.public_bytes(serialization.Encoding.PEM).decode()
        + ca.public_bytes(serialization.Encoding.PEM).decode()
    )
    return {"priv_pem": priv_pem, "pub_pem": pub_pem, "chain_pem": chain_pem}


@pytest.fixture(autouse=True)
def _keystore_isolation():
    set_keystore(None)
    clear_signing_keys()
    yield
    set_keystore(None)
    clear_signing_keys()


@pytest.fixture
def app(monkeypatch):
    monkeypatch.delenv("TEX_API_KEYS", raising=False)
    from tex.main import create_app

    return create_app()


@pytest.fixture
def client(app):
    return TestClient(app)


@pytest.fixture
def signed_manifest_pair():
    """Build a signed manifest and return (manifest, asset bytes)."""
    outer = _mint_outer_chain()
    outer_key = SignatureKeyPair(
        algorithm=SignatureAlgorithm.ED25519,
        public_key=outer["pub_pem"],
        private_key=outer["priv_pem"],
        key_id="thread5-http-outer",
    )
    register_signing_key(outer_key)
    cosign = Ed25519Provider().generate_keypair("thread5-http-cosign")

    body = b"AI-generated outbound email for HTTP test"
    body_sha = hashlib.sha256(body).hexdigest()
    unsigned = build_email_manifest(
        from_address="ai-sdr@vortexblack.com",
        to_addresses=("prospect@example.com",),
        subject="Re: Tex Aegis pilot HTTP roundtrip",
        body_sha256=body_sha,
        model_name="claude-sonnet-4.6",
        model_version="2026-03",
        tex_verdict_id="v-http-001",
    )
    signed = build_signed_manifest_with_cosign(
        unsigned_manifest=unsigned,
        outer_signing_key_id="thread5-http-outer",
        outer_certificate_chain_pem=outer["chain_pem"],
        cosign_key=cosign,
        outbound_artifact_bytes=body,
        retention_anchor={
            "record_hash": "a" * 64,
            "evidence_id": "ev-http-001",
        },
        revocation_proof={"kind": "crl_snapshot_pin", "sha256": "b" * 64},
    )
    return signed, body


# ---------------------------------------------------------------------------
# POST /v1/c2pa/verify
# ---------------------------------------------------------------------------


def test_verify_with_claim_cbor_returns_valid(client, signed_manifest_pair):
    """A well-formed manifest verifies green over HTTP."""
    signed, body = signed_manifest_pair
    row = serialize_manifest_for_storage(signed)

    response = client.post(
        "/v1/c2pa/verify",
        json={
            "claim_cbor_b64": row["claim_cbor_b64"],
            "outer_signature_b64": row["outer_signature_b64"],
            "certificate_chain_pem": row["certificate_chain_pem"],
            "asset_bytes_b64": base64.b64encode(body).decode("ascii"),
        },
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["outer_signature_valid"] is True
    assert payload["cosign_present"] is True
    assert payload["cosign_valid"] is True
    assert payload["cosign_algorithm"] == "ed25519"
    assert payload["paper_reference"] == "arxiv:2604.24890"
    defenses = {d["attack"]: d["defended"] for d in payload["attack_defenses"]}
    # All five attacks defended.
    assert defenses["timestamp_swap"] is True
    assert defenses["revocation_skipped"] is True
    assert defenses["cross_validator_contradiction"] is True
    assert defenses["exclusion_range_tamper"] is True
    assert defenses["cert_expiry_before_retention"] is True


def test_verify_detects_tampered_asset(client, signed_manifest_pair):
    """Asset hash mismatch surfaces texCosign.fullFileHashMismatch."""
    signed, body = signed_manifest_pair
    row = serialize_manifest_for_storage(signed)

    tampered = b"different artifact"
    response = client.post(
        "/v1/c2pa/verify",
        json={
            "claim_cbor_b64": row["claim_cbor_b64"],
            "outer_signature_b64": row["outer_signature_b64"],
            "certificate_chain_pem": row["certificate_chain_pem"],
            "asset_bytes_b64": base64.b64encode(tampered).decode("ascii"),
        },
    )
    assert response.status_code == 200
    payload = response.json()
    # Outer signature still valid (manifest unchanged).
    assert payload["outer_signature_valid"] is True
    # Cosign reports the mismatch.
    assert "texCosign.fullFileHashMismatch" in payload["cosign_issues"]
    defenses = {d["attack"]: d["defended"] for d in payload["attack_defenses"]}
    assert defenses["exclusion_range_tamper"] is False


def test_verify_rejects_bad_cbor(client):
    response = client.post(
        "/v1/c2pa/verify",
        json={
            "claim_cbor_b64": "@@@not-base64@@@",
            "outer_signature_b64": "AAAA",
        },
    )
    assert response.status_code == 400


def test_verify_requires_either_record_id_or_inline(client):
    response = client.post("/v1/c2pa/verify", json={})
    assert response.status_code == 400


# ---------------------------------------------------------------------------
# GET /v1/evidence/{record_id}/c2pa  (with an in-memory mirror)
# ---------------------------------------------------------------------------


class _InMemoryMirror:
    """Stand-in for PostgresManifestMirror."""

    def __init__(self):
        self.rows: dict[str, dict] = {}
        self.disabled = False

    def fetch_by_record_id(self, record_id):
        return self.rows.get(str(record_id))


def test_get_evidence_c2pa_round_trips(app, client, signed_manifest_pair):
    """When a manifest exists in the mirror, GET returns it as JSON envelope."""
    signed, _body = signed_manifest_pair
    row = serialize_manifest_for_storage(signed)

    mirror = _InMemoryMirror()
    record_id = "11111111-2222-3333-4444-555555555555"
    mirror.rows[record_id] = {
        "manifest_id": "m-1",
        "record_id": record_id,
        "decision_id": "d-1",
        "tenant_id": "vortexblack",
        "claim_sha256": row["claim_sha256"],
        "claim_cbor_b64": row["claim_cbor_b64"],
        "outer_signature_b64": row["outer_signature_b64"],
        "certificate_chain_pem": row["certificate_chain_pem"],
        "title": row["title"],
        "format": row["format"],
        "instance_id": row["instance_id"],
        "claim_generator": row["claim_generator"],
        "assertion_labels": row["assertion_labels"],
        "has_cosign": row["has_cosign"],
        "cosign_algorithm": "ed25519",
        "cosign_key_id": "thread5-http-cosign",
        "full_file_sha256": "c" * 64,
        "canonicalization_version": "tex.evidence_cosign/v1",
        "bound_timestamp": "2026-05-18T00:00:00+00:00",
        "recorded_at": "2026-05-18T00:00:01+00:00",
    }

    # Attach the mirror to the app runtime in the same shape the
    # real route handler looks for.
    class _RuntimeWithMirror:
        manifest_mirror = mirror

    app.state.runtime = _RuntimeWithMirror()

    response = client.get(f"/v1/evidence/{record_id}/c2pa")
    assert response.status_code == 200, response.text
    assert response.headers["content-type"].startswith("application/c2pa+json")
    body = response.json()
    assert body["record_id"] == record_id
    assert body["tenant_id"] == "vortexblack"
    assert body["has_cosign"] is True
    assert body["claim_sha256"] == row["claim_sha256"]


def test_get_evidence_c2pa_404_when_no_record(app, client):
    mirror = _InMemoryMirror()
    class _Rt:
        manifest_mirror = mirror

    app.state.runtime = _Rt()
    response = client.get("/v1/evidence/does-not-exist/c2pa")
    assert response.status_code == 404


def test_get_evidence_c2pa_503_when_mirror_disabled(app, client):
    class _Rt:
        manifest_mirror = None

    app.state.runtime = _Rt()
    response = client.get("/v1/evidence/any/c2pa")
    assert response.status_code == 503


# ---------------------------------------------------------------------------
# Round-trip: POST /v1/c2pa/verify with record_id resolves through the mirror
# ---------------------------------------------------------------------------


def test_verify_via_record_id(app, client, signed_manifest_pair):
    signed, body = signed_manifest_pair
    row = serialize_manifest_for_storage(signed)

    mirror = _InMemoryMirror()
    record_id = "22222222-3333-4444-5555-666666666666"
    mirror.rows[record_id] = {
        **row,
        "record_id": record_id,
        "decision_id": "d-x",
        "tenant_id": "vortexblack",
        "cosign_algorithm": "ed25519",
        "cosign_key_id": "thread5-http-cosign",
        "full_file_sha256": full_file_sha256(body),
        "canonicalization_version": "tex.evidence_cosign/v1",
        "bound_timestamp": "2026-05-18T00:00:00+00:00",
        "recorded_at": "2026-05-18T00:00:01+00:00",
    }

    class _Rt:
        manifest_mirror = mirror

    app.state.runtime = _Rt()

    response = client.post(
        "/v1/c2pa/verify",
        json={
            "record_id": record_id,
            "asset_bytes_b64": base64.b64encode(body).decode("ascii"),
        },
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["outer_signature_valid"] is True
    assert payload["cosign_valid"] is True

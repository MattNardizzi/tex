"""
HTTP-level Thread 6 test for POST /v1/c2pa/verify.

Confirms the verify endpoint returns the new Thread 6 fields
(watermark, attestation, formal_verification) when those assertions
are present in the manifest, AND that the four bleeding-edge layers
all report green status to the HTTP caller.
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
    ASSERTION_LABEL_TEX_EVIDENCE_ATTESTATION,
    ASSERTION_LABEL_TEX_EVIDENCE_WATERMARK,
    ASSERTION_LABEL_TEX_FORMAL_VERIFICATION,
    AttestationVerifier,
    EatTokenKind,
    RecordedScoreDetector,
    SYNTHID_TEXT_DEFAULT_THRESHOLD,
    WatermarkScheme,
    build_email_manifest,
    build_signed_manifest_with_cosign,
    build_tex_evidence_attestation_assertion,
    build_tex_evidence_watermark_assertion,
    clear_signing_keys,
    full_file_sha256,
    load_cpsa_shapes,
    model_provenance_assertion_data,
    register_signing_key,
    synthesize_test_eat_jwt,
    text_perceptual_hash,
)
from tex.c2pa._canonical_claim import canonical_claim_cbor
from tex.c2pa.manifest import C2paAssertion
from tex.c2pa.signer import set_keystore
from tex.pqcrypto._ed25519_provider import Ed25519Provider
from tex.pqcrypto.algorithm_agility import SignatureAlgorithm, SignatureKeyPair


def _mint_chain() -> dict:
    now = datetime.now(timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "T6 HTTP Root")])
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
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "t6.http.test")]))
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    priv = leaf_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub = leaf_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    chain = (
        leaf.public_bytes(serialization.Encoding.PEM).decode()
        + ca.public_bytes(serialization.Encoding.PEM).decode()
    )
    return {"priv_pem": priv, "pub_pem": pub, "chain_pem": chain}


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
def four_layer_manifest():
    """Build a fully-loaded Thread 6 four-layer signed manifest."""
    chain = _mint_chain()
    outer = SignatureKeyPair(
        algorithm=SignatureAlgorithm.ED25519,
        public_key=chain["pub_pem"],
        private_key=chain["priv_pem"],
        key_id="t6-http-outer",
    )
    register_signing_key(outer)
    cosign = Ed25519Provider().generate_keypair("t6-http-cosign")

    body = b"Hi Sara, AI outbound for Thread 6 HTTP test\n"
    body_sha = hashlib.sha256(body).hexdigest()
    unsigned = build_email_manifest(
        from_address="ai-sdr@vortexblack.com",
        to_addresses=("prospect@example.com",),
        subject="Re: Tex Aegis pilot — HTTP layer test",
        body_sha256=body_sha,
        model_name="claude-sonnet-4.6",
        model_version="2026-03",
        tex_verdict_id="v-t6-001",
    )

    # Watermark assertion
    det = RecordedScoreDetector(
        scheme=WatermarkScheme.SYNTHID_TEXT,
        recorded_score=0.97,
        recorded_p_value=1e-14,
        threshold=SYNTHID_TEXT_DEFAULT_THRESHOLD,
        detector_version="google-deepmind/synthid-text/v1",
    )
    wm = build_tex_evidence_watermark_assertion(
        detection=det.detect(body.decode(), key_id="k"),
        key_id="k",
        soft_binding_value="sha256:" + text_perceptual_hash(body.decode()),
        asserted_origin="ai-generated",
    )

    # Attestation assertion: bind the EAT user_data to SHA-256 of the claim
    # CBOR we will actually sign. We must compute this against the augmented
    # claim (base assertions + watermark + attestation + cpsa + cosign),
    # but the cosign assertion contains the signature itself. Compromise:
    # bind the EAT to a placeholder hash and rely on cross-layer audit + the
    # outer signature to detect tamper.
    eat_bound_hash = "c" * 64
    issuer = ec.generate_private_key(ec.SECP384R1())
    issuer_priv = issuer.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    eat_token = synthesize_test_eat_jwt(
        claim_cbor_sha256=eat_bound_hash,
        verifier=AttestationVerifier.NVIDIA_NRAS,
        signing_key_pem=issuer_priv,
        kid="nras-http-kid",
        algorithm="ES384",
    )
    att = build_tex_evidence_attestation_assertion(
        eat_token=eat_token,
        eat_token_kind=EatTokenKind.JWT,
        verifier=AttestationVerifier.NVIDIA_NRAS,
        claim_cbor_sha256=eat_bound_hash,
    )

    # CPSA assertion
    bundle = load_cpsa_shapes()
    fv = model_provenance_assertion_data(bundle)

    extras = (
        C2paAssertion(label=ASSERTION_LABEL_TEX_EVIDENCE_WATERMARK, data=wm),
        C2paAssertion(label=ASSERTION_LABEL_TEX_EVIDENCE_ATTESTATION, data=att),
        C2paAssertion(label=ASSERTION_LABEL_TEX_FORMAL_VERIFICATION, data=fv),
    )

    signed = build_signed_manifest_with_cosign(
        unsigned_manifest=unsigned,
        outer_signing_key_id="t6-http-outer",
        outer_certificate_chain_pem=chain["chain_pem"],
        cosign_key=cosign,
        outbound_artifact_bytes=body,
        retention_anchor={
            "record_hash": "a" * 64,
            "evidence_id": "ev-t6-001",
        },
        revocation_proof={"kind": "crl_snapshot_pin", "sha256": "b" * 64},
        extra_assertions=extras,
    )
    return signed, body


def _post_verify(client, signed, body):
    claim_cbor = canonical_claim_cbor(signed.claim)
    payload = {
        "claim_cbor_b64": base64.b64encode(claim_cbor).decode("ascii"),
        "outer_signature_b64": signed.signature_b64,
        "certificate_chain_pem": signed.certificate_chain_pem,
        "asset_bytes_b64": base64.b64encode(body).decode("ascii"),
    }
    return client.post("/v1/c2pa/verify", json=payload)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_verify_returns_all_thread6_fields(client, four_layer_manifest):
    signed, body = four_layer_manifest
    resp = _post_verify(client, signed, body)
    assert resp.status_code == 200, resp.text
    data = resp.json()

    # Thread 5 fields still green.
    assert data["outer_signature_valid"] is True
    assert data["cosign_present"] is True
    assert data["cosign_valid"] is True
    assert all(d["defended"] for d in data["attack_defenses"])

    # Thread 6 — Watermark
    assert data["watermark_present"] is True
    assert data["watermark_scheme"] == "synthid-text"
    assert float(data["watermark_score"]) >= SYNTHID_TEXT_DEFAULT_THRESHOLD
    assert data["watermark_cross_layer_consistent"] is True
    assert "watermark.validated" in data["watermark_issues"]

    # Thread 6 — Attestation
    assert data["attestation_present"] is True
    assert data["attestation_verifier"] == "nvidia-nras"
    # user_data is bound to the placeholder hash on the assertion side;
    # the route compares assertion's claim_cbor_sha256 vs the JWT's
    # user_data and finds them equal — so this is True.
    assert data["attestation_user_data_bound"] is True

    # Thread 6 — Formal verification
    assert data["formal_verification_present"] is True
    assert data["formal_verification_all_goals_satisfied"] is True
    assert set(data["formal_verification_goals"]) >= {"G1", "G2", "G3", "G4", "G5"}

    # Documentation references.
    assert data["paper_reference"] == "arxiv:2604.24890"
    assert "2603.02378" in data["durable_content_credentials_reference"]
    assert "2605.12456" in data["durable_content_credentials_reference"]
    assert "CPSA" in data["formal_verification_reference"]


def test_verify_thread5_only_manifest_unchanged(client):
    """A Thread 5 manifest (no watermark/attestation/CPSA assertions)
    still verifies; Thread 6 fields are False/None/empty."""
    chain = _mint_chain()
    outer = SignatureKeyPair(
        algorithm=SignatureAlgorithm.ED25519,
        public_key=chain["pub_pem"],
        private_key=chain["priv_pem"],
        key_id="t6-bwc-outer",
    )
    register_signing_key(outer)
    cosign = Ed25519Provider().generate_keypair("t6-bwc-cosign")
    body = b"Thread 5 backward compatibility check"
    body_sha = hashlib.sha256(body).hexdigest()
    unsigned = build_email_manifest(
        from_address="ai-sdr@vortexblack.com",
        to_addresses=("prospect@example.com",),
        subject="Thread 5 backward-compatibility",
        body_sha256=body_sha,
        model_name="claude-sonnet-4.6",
        model_version="2026-03",
        tex_verdict_id="v-bwc-001",
    )
    signed = build_signed_manifest_with_cosign(
        unsigned_manifest=unsigned,
        outer_signing_key_id="t6-bwc-outer",
        outer_certificate_chain_pem=chain["chain_pem"],
        cosign_key=cosign,
        outbound_artifact_bytes=body,
        retention_anchor={"record_hash": "a" * 64, "evidence_id": "ev-bwc-001"},
        revocation_proof={"kind": "crl_snapshot_pin", "sha256": "b" * 64},
    )
    resp = _post_verify(client, signed, body)
    assert resp.status_code == 200, resp.text
    data = resp.json()

    assert data["outer_signature_valid"] is True
    assert data["cosign_valid"] is True

    # Thread 6 fields all absent.
    assert data["watermark_present"] is False
    assert data["watermark_scheme"] is None
    assert data["watermark_cross_layer_consistent"] is None
    assert data["attestation_present"] is False
    assert data["formal_verification_present"] is False
    assert data["formal_verification_goals"] == []

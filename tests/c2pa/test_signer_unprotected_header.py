"""
Tests for the signer↔verifier OCSP staple + TSA v2 wire format.

Verifies that:
- ``sign_manifest`` accepts ``ocsp_staples_der`` and ``tsa_tokens_der``
  kwargs and places them in the unprotected COSE header per C2PA 2.4
  §14 (``ocsp_vals``) and §10.3.2.5 (``sigTst2``).
- ``verify_manifest`` extracts them back out at verify time.
- The signature itself round-trips even when these auxiliary fields
  are present.
- Setting ``require_ocsp_staple=True`` or ``require_timestamp=True``
  fails the verification when those fields are absent.
"""

from __future__ import annotations

import base64
import os
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from tex.c2pa import _cbor
from tex.c2pa.manifest import C2paAssertion, C2paClaim, C2paManifest
from tex.c2pa.signer import register_signing_key, sign_manifest, clear_signing_keys
from tex.c2pa.verifier import verify_manifest
from tex.pqcrypto.algorithm_agility import SignatureAlgorithm, SignatureKeyPair


def _es256_keypair_and_cert():
    """Make a minimal ES256 (P-256) keypair + self-signed cert."""
    priv = ec.generate_private_key(ec.SECP256R1())
    pub = priv.public_key()
    now = datetime.now(timezone.utc)
    name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "tex-test-signer")]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(pub)
        .serial_number(1234)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
        .sign(priv, hashes.SHA256())
    )
    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    pub_pem = pub.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
    return priv, priv_pem, pub_pem, cert_pem


def _register_key(key_id: str, priv_pem: bytes, pub_pem: bytes):
    register_signing_key(
        SignatureKeyPair(
            algorithm=SignatureAlgorithm.ECDSA_P256,
            public_key=pub_pem,
            private_key=priv_pem,
            key_id=key_id,
        )
    )


def _basic_manifest() -> C2paManifest:
    return C2paManifest(
        claim=C2paClaim(
            title="test.txt",
            format="text/plain",
            instance_id="urn:uuid:00000000-0000-0000-0000-000000000abc",
            claim_generator="tex/test-1.0",
            claim_generator_info={"name": "tex", "version": "test"},
            created_at=datetime.now(timezone.utc),
            assertions=(
                C2paAssertion(
                    label="stds.schema-org.CreativeWork",
                    data={"@type": "CreativeWork", "name": "test"},
                ),
            ),
        ),
        signature_b64=None,
        certificate_chain_pem=None,
    )


@pytest.fixture(autouse=True)
def _clean_keystore():
    clear_signing_keys()
    yield
    clear_signing_keys()


def _extract_unprotected_map(signature_b64: str) -> dict:
    """Decode the COSE_Sign1 envelope and return its unprotected header map."""
    envelope_bytes = base64.b64decode(signature_b64.encode("ascii"))
    decoded = _cbor.decode(envelope_bytes)
    decoded = _cbor.unwrap_tag(decoded, _cbor.COSE_SIGN1_TAG)
    return decoded[1]


def test_sign_without_ocsp_or_tsa_leaves_unprotected_empty():
    """Baseline: no kwargs → empty unprotected header."""
    _, priv_pem, pub_pem, cert_pem = _es256_keypair_and_cert()
    _register_key("k1", priv_pem, pub_pem)
    signed = sign_manifest(
        _basic_manifest(),
        signing_key_id="k1",
        certificate_chain_pem=cert_pem,
    )
    unprotected = _extract_unprotected_map(signed.signature_b64)
    assert unprotected == {}


def test_sign_with_ocsp_staple_places_under_ocsp_vals_label():
    """C2PA 2.4 §14: OCSP staples live in unprotected header under
    the CBOR text key ``ocsp_vals`` as an array of byte strings."""
    _, priv_pem, pub_pem, cert_pem = _es256_keypair_and_cert()
    _register_key("k2", priv_pem, pub_pem)

    fake_staple_a = b"\xde\xad\xbe\xef" * 16
    fake_staple_b = b"\xfe\xed\xfa\xce" * 16
    signed = sign_manifest(
        _basic_manifest(),
        signing_key_id="k2",
        certificate_chain_pem=cert_pem,
        ocsp_staples_der=[fake_staple_a, fake_staple_b],
    )
    unprotected = _extract_unprotected_map(signed.signature_b64)
    assert "ocsp_vals" in unprotected
    assert unprotected["ocsp_vals"] == [fake_staple_a, fake_staple_b]


def test_sign_with_tsa_token_places_under_sigtst2_label():
    """C2PA 2.4 §10.3.2.5: v2 TSA tokens live under ``sigTst2``."""
    _, priv_pem, pub_pem, cert_pem = _es256_keypair_and_cert()
    _register_key("k3", priv_pem, pub_pem)

    fake_token = b"\xab" * 256
    signed = sign_manifest(
        _basic_manifest(),
        signing_key_id="k3",
        certificate_chain_pem=cert_pem,
        tsa_tokens_der=[fake_token],
    )
    unprotected = _extract_unprotected_map(signed.signature_b64)
    assert unprotected.get("sigTst2") == [fake_token]


def test_signature_still_verifies_with_auxiliary_unprotected_data():
    """Adding OCSP / TSA bytes to the unprotected header MUST NOT affect
    the signature itself — the protected header is what's signed."""
    _, priv_pem, pub_pem, cert_pem = _es256_keypair_and_cert()
    _register_key("k4", priv_pem, pub_pem)

    signed = sign_manifest(
        _basic_manifest(),
        signing_key_id="k4",
        certificate_chain_pem=cert_pem,
        ocsp_staples_der=[b"junk"],
        tsa_tokens_der=[b"more-junk"],
    )
    # Verifier should still find the signature valid. OCSP+TSA payloads
    # are junk, so when those checks would fire, they fail, but they
    # only fire when present in the unprotected header — and the
    # baseline verify_manifest() defaults to require_ocsp_staple=False
    # / require_timestamp=False. Junk staples WILL cause a failure
    # because the validator tries to parse them.
    result = verify_manifest(signed)
    # The signature itself is valid; OCSP malformed-staple failure
    # surfaces as ``signingCredential.malformedOcspResponse``.
    assert "claimSignature.validated" in result.issues
    assert "signingCredential.malformedOcspResponse" in result.issues


def test_require_ocsp_staple_flag_fails_when_absent():
    _, priv_pem, pub_pem, cert_pem = _es256_keypair_and_cert()
    _register_key("k5", priv_pem, pub_pem)
    signed = sign_manifest(
        _basic_manifest(),
        signing_key_id="k5",
        certificate_chain_pem=cert_pem,
    )
    result = verify_manifest(signed, require_ocsp_staple=True)
    assert result.is_valid is False
    assert "signingCredential.ocspMissing" in result.issues


def test_require_timestamp_flag_fails_when_absent():
    _, priv_pem, pub_pem, cert_pem = _es256_keypair_and_cert()
    _register_key("k6", priv_pem, pub_pem)
    signed = sign_manifest(
        _basic_manifest(),
        signing_key_id="k6",
        certificate_chain_pem=cert_pem,
    )
    result = verify_manifest(signed, require_timestamp=True)
    assert result.is_valid is False
    assert "timeStamp.malformed" in result.issues

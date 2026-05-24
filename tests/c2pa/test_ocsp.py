"""
Tests for tex.c2pa.ocsp (RFC 6960 + C2PA 2.4 §15.9).

Covers request construction, response parsing, freshness checks,
nonce validation, and the C2PA-aligned failure codes.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from tex.c2pa.ocsp import (
    OcspFailureCode,
    OcspNonce,
    OcspRequestBundle,
    build_request_der,
    parse_and_validate_response,
)


def _make_chain():
    """Build a tiny CA + leaf chain for OCSP exercise."""
    issuer_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    issuer_name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "Tex Test CA")]
    )
    now = datetime.now(timezone.utc)
    issuer_cert = (
        x509.CertificateBuilder()
        .subject_name(issuer_name)
        .issuer_name(issuer_name)
        .public_key(issuer_key.public_key())
        .serial_number(1)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )
        .sign(issuer_key, hashes.SHA256())
    )
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "leaf.test")])
        )
        .issuer_name(issuer_name)
        .public_key(leaf_key.public_key())
        .serial_number(42)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .sign(issuer_key, hashes.SHA256())
    )
    return issuer_cert, issuer_key, leaf_cert, leaf_key


def test_build_request_der_round_trip():
    issuer_cert, _, leaf_cert, _ = _make_chain()
    req = build_request_der(leaf_cert, issuer_cert)
    assert isinstance(req, OcspRequestBundle)
    assert len(req.request_der) > 0
    assert len(req.nonce.value) == 16
    assert req.target_serial_hex == f"{leaf_cert.serial_number:x}"


def test_parse_malformed_response_returns_malformed_code():
    issuer_cert, _, leaf_cert, _ = _make_chain()
    result = parse_and_validate_response(
        b"not-a-real-ocsp-response",
        issuer=issuer_cert,
        expected_nonce=None,
        target_serial=leaf_cert.serial_number,
    )
    assert result.ok is False
    assert result.failure_code is OcspFailureCode.MALFORMED


def test_failure_code_values_are_c2pa_aligned():
    """C2PA 2.1 §15.7 / 2.4 §15.9 failure codes."""
    assert OcspFailureCode.REVOKED.value == "signingCredential.revoked"
    assert OcspFailureCode.STALE_RESPONSE.value == (
        "signingCredential.ocspStaleResponse"
    )
    assert OcspFailureCode.MISSING.value == "signingCredential.ocspMissing"


def test_nonce_is_fresh_each_request():
    issuer_cert, _, leaf_cert, _ = _make_chain()
    a = build_request_der(leaf_cert, issuer_cert)
    b = build_request_der(leaf_cert, issuer_cert)
    assert a.nonce.value != b.nonce.value

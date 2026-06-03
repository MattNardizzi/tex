"""
Tests for tex.c2pa.timestamp (RFC 3161 v2 + C2PA 2.4 §10.3.2.5).

Covers request construction, payload digest, and the C2PA-aligned
failure codes from `parse_and_validate_response`.
"""

from __future__ import annotations

import hashlib
import os

import pytest

from tex.c2pa.timestamp import (
    TimestampFailureCode,
    TimestampRequest,
    build_request_der,
    parse_and_validate_response,
    v2_payload_digest,
)


def test_v2_payload_digest_is_sha256_of_signature_field():
    """C2PA 2.4 §10.3.2.5 — v2 messageImprint is SHA-256(signature field)."""
    sig = os.urandom(3309)  # ML-DSA-65 signature size
    assert v2_payload_digest(sig) == hashlib.sha256(sig).digest()


def test_v2_payload_digest_is_deterministic_per_input():
    sig = b"\x01\x02\x03"
    assert v2_payload_digest(sig) == v2_payload_digest(sig)


def test_v2_payload_digest_differs_for_different_inputs():
    a = v2_payload_digest(b"x")
    b = v2_payload_digest(b"y")
    assert a != b


def test_build_request_der_includes_nonce_and_digest():
    sig = os.urandom(2420)  # ML-DSA-44 signature
    req = build_request_der(sig)
    assert isinstance(req, TimestampRequest)
    assert len(req.request_der) > 0
    # Nonces are 16 random bytes interpreted as an integer.
    assert 0 < req.nonce < 2**128
    assert req.payload_digest == hashlib.sha256(sig).digest()


def test_build_request_with_policy_oid():
    sig = os.urandom(64)
    req = build_request_der(sig, request_policy_oid="1.3.6.1.4.1.4146.2.2")
    assert req.request_policy_oid == "1.3.6.1.4.1.4146.2.2"
    # OID encoded in DER request bytes.
    assert len(req.request_der) > 0


def test_parse_malformed_response_returns_malformed_code():
    sig = os.urandom(64)
    expected_digest = v2_payload_digest(sig)
    result = parse_and_validate_response(
        b"garbage",
        expected_digest=expected_digest,
        expected_nonce=None,
    )
    assert result.ok is False
    assert result.failure_code is TimestampFailureCode.MALFORMED


def test_failure_codes_are_c2pa_aligned():
    """C2PA 2.4 §15.8 — Validate the Time-Stamp."""
    assert TimestampFailureCode.HASH_MISMATCH.value == (
        "timeStamp.messageImprintMismatch"
    )
    assert TimestampFailureCode.OUTSIDE_VALIDITY.value == (
        "timeStamp.outsideCredentialValidity"
    )
    assert TimestampFailureCode.NOT_GRANTED.value == (
        "timeStamp.statusNotGranted"
    )


def test_nonce_is_fresh_each_request():
    sig = os.urandom(64)
    a = build_request_der(sig)
    b = build_request_der(sig)
    assert a.nonce != b.nonce

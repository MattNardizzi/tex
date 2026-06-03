"""
Tests for tex.pqcrypto.lms — LMS API surface + deferred-implementation
gating.

The LMS implementation is scaffolded per NIST SP 800-208 / RFC 8554 but
deferred — Tex's production code-signing primitive is SLH-DSA via
``tex.pqcrypto.code_signing``. These tests pin the API surface and the
guard-rail behavior (clear NotImplementedError pointing to the
SLH-DSA recommendation) so a future implementation lands without
silently changing call-site expectations.
"""

from __future__ import annotations

import pytest

from tex.pqcrypto.lms import (
    LmsKeyPair,
    LmsParameterSet,
    generate_keypair,
    recommended_primitive_for_code_signing,
    sign_with_lms,
    verify_with_lms,
)


def test_lms_parameter_sets_match_sp_800_208_section_5_1():
    """NIST SP 800-208 §5.1 enumerates these four for SHA-256 / N=32."""
    values = {p.value for p in LmsParameterSet}
    assert "lms-sha256-n32-h10" in values
    assert "lms-sha256-n32-h15" in values
    assert "lms-sha256-n32-h20" in values
    assert "lms-sha256-n32-h25" in values


def test_lms_keypair_is_frozen():
    kp = LmsKeyPair(algorithm=LmsParameterSet.SHA256_N32_H15)
    with pytest.raises((AttributeError, TypeError)):
        kp.algorithm = LmsParameterSet.SHA256_N32_H10  # type: ignore[misc]


def test_generate_keypair_raises_with_slh_dsa_pointer():
    """Until LMS lands, callers should be redirected to SLH-DSA."""
    with pytest.raises(NotImplementedError) as exc:
        generate_keypair()
    assert "SLH-DSA" in str(exc.value)
    assert "code_signing" in str(exc.value)


def test_sign_with_lms_raises_with_slh_dsa_pointer():
    kp = LmsKeyPair(algorithm=LmsParameterSet.SHA256_N32_H15)
    with pytest.raises(NotImplementedError, match="SLH-DSA"):
        sign_with_lms(b"x", key=kp)


def test_verify_with_lms_raises_with_slh_dsa_pointer():
    with pytest.raises(NotImplementedError, match="SLH-DSA"):
        verify_with_lms(b"x", signature=b"", public_key=b"")


def test_recommended_primitive_cites_cnsa_2_and_slh_dsa():
    """The function doubles as ``/v1/health`` documentation copy.

    Confirms it names the right standard (CNSA 2.0) and the right
    primitive (SLH-DSA) — the buyer-facing rationale must be stable.
    """
    text = recommended_primitive_for_code_signing()
    assert "SLH-DSA" in text
    assert "CNSA 2.0" in text
    assert "FIPS 205" in text
    assert "code_signing" in text

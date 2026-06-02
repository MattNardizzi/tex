"""
Tests for tex.pqcrypto.code_signing — post-quantum code signing via
SLH-DSA (FIPS 205), CNSA 2.0 §2-aligned.

The cryptographic round-trip tests require liboqs (pyca/cryptography 48
does not yet ship SLH-DSA — lands in pyca 49.x). Structural tests run
without liboqs.
"""

from __future__ import annotations

import io
import os
import tempfile

import pytest

from tex.pqcrypto.algorithm_agility import SignatureAlgorithm
from tex.pqcrypto.code_signing import (
    CodeSignature,
    recommended_algorithm,
    sign_release_artifact,
    verify_release_artifact,
)


def _liboqs_runtime_ok() -> bool:
    """SLH-DSA requires liboqs (not in pyca 48; lands in pyca 49.x)."""
    try:
        import oqs
        oqs.Signature("SLH_DSA_PURE_SHA2_128S")
        return True
    except Exception:
        return False


_LIBOQS_AVAILABLE = _liboqs_runtime_ok()
_requires_liboqs = pytest.mark.skipif(
    not _LIBOQS_AVAILABLE,
    reason="SLH-DSA requires liboqs (not in pyca/cryptography 48)",
)


# --- Structural tests (no liboqs needed) ------------------------------------


def test_recommended_algorithm_default_is_slh_dsa_128s():
    assert recommended_algorithm() is SignatureAlgorithm.SLH_DSA_128S


def test_recommended_algorithm_cnsa_2_is_slh_dsa_256s():
    """NSA CNSA 2.0 §2 (Apr 2026) mandates SLH-DSA-256s for NSS code."""
    assert (
        recommended_algorithm(cnsa_2_required=True)
        is SignatureAlgorithm.SLH_DSA_256S
    )


def test_sign_rejects_non_slh_dsa_algorithm():
    """The code-signing module is SLH-DSA-only. ML-DSA is fast but
    lacks the hash-function-only security argument CNSA 2.0 wants."""
    from tex.pqcrypto.algorithm_agility import SignatureKeyPair

    bad_key = SignatureKeyPair(
        algorithm=SignatureAlgorithm.ML_DSA_65,
        public_key=b"x",
        private_key=b"y",
        key_id="bad",
    )
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"hello")
        path = f.name
    try:
        with pytest.raises(ValueError, match="Not a code-signing algorithm"):
            sign_release_artifact(path, signing_key=bad_key)
    finally:
        os.unlink(path)


def test_verify_returns_false_on_missing_artifact():
    """No exception leaks out of verify — operators must be able to
    distinguish missing-artifact from tamper without exception handling."""
    fake = CodeSignature(
        algorithm=SignatureAlgorithm.SLH_DSA_128S,
        digest_sha256="a" * 64,
        signature=b"\x00" * 7856,
        public_key=b"\x00" * 32,
        key_id="k",
    )
    assert verify_release_artifact("/nonexistent/path", signature=fake) is False


# --- Cryptographic round-trip (requires liboqs) -----------------------------


@_requires_liboqs
def test_sign_and_verify_round_trip(tmp_path):
    from tex.pqcrypto.slh_dsa import SlhDsaProvider

    provider = SlhDsaProvider(SignatureAlgorithm.SLH_DSA_128S)
    keypair = provider.generate_keypair("test-key")

    artifact = tmp_path / "release.bin"
    artifact.write_bytes(b"hello world\n" * 100)

    sig = sign_release_artifact(str(artifact), signing_key=keypair)
    assert sig.algorithm is SignatureAlgorithm.SLH_DSA_128S
    assert len(sig.signature) == 7856  # FIPS 205 §11 SLH-DSA-128s

    assert verify_release_artifact(str(artifact), signature=sig) is True


@_requires_liboqs
def test_verify_fails_on_tampered_artifact(tmp_path):
    from tex.pqcrypto.slh_dsa import SlhDsaProvider

    provider = SlhDsaProvider(SignatureAlgorithm.SLH_DSA_128S)
    keypair = provider.generate_keypair("test-tamper")

    artifact = tmp_path / "release.bin"
    artifact.write_bytes(b"original")
    sig = sign_release_artifact(str(artifact), signing_key=keypair)

    # Tamper.
    artifact.write_bytes(b"tampered")
    assert verify_release_artifact(str(artifact), signature=sig) is False

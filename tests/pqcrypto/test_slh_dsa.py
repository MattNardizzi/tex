"""
Tests for tex.pqcrypto.slh_dsa (Thread 10).

Covers FIPS 205 SLH-DSA at all four parameter sets, fault-detection
sign-then-verify guard, signature length validation, algorithm-agile
dispatch, and tamper detection.
"""

from __future__ import annotations

import pytest

from tex.pqcrypto.algorithm_agility import (
    SignatureAlgorithm,
    SignatureKeyPair,
    SignatureProvider,
    get_signature_provider,
)
from tex.pqcrypto.slh_dsa import (
    SlhDsaFaultDetected,
    SlhDsaProvider,
)


_SLH_DSA_PARAMS = [
    SignatureAlgorithm.SLH_DSA_128S,
    SignatureAlgorithm.SLH_DSA_128F,
    SignatureAlgorithm.SLH_DSA_192S,
    SignatureAlgorithm.SLH_DSA_256S,
]


def _liboqs_runtime_ok() -> bool:
    """True iff liboqs is actually loadable for SLH-DSA.

    Note: pyca/cryptography 48 ships native ML-DSA + ML-KEM but does NOT
    yet expose SLH-DSA. SLH-DSA support is on the OpenSSL 3.5 EVP layer,
    but the pyca high-level wrappers land in pyca 49.x. Until then,
    SLH-DSA round-trip tests require liboqs.
    """
    try:
        import oqs
        oqs.Signature("SLH_DSA_PURE_SHA2_128S")
        return True
    except Exception:
        return False


_LIBOQS_AVAILABLE = _liboqs_runtime_ok()
_requires_liboqs = pytest.mark.skipif(
    not _LIBOQS_AVAILABLE,
    reason="liboqs not available (SLH-DSA not yet in pyca/cryptography 48; lands in 49.x)",
)


# --- Structural tests --------------------------------------------------------


def test_slh_dsa_provider_rejects_non_slh_dsa_parameter_set() -> None:
    with pytest.raises(ValueError, match="Not an SLH-DSA parameter set"):
        SlhDsaProvider(SignatureAlgorithm.ML_DSA_65)


def test_slh_dsa_provider_default_is_128s() -> None:
    p = SlhDsaProvider()
    assert p.parameter_set is SignatureAlgorithm.SLH_DSA_128S


def test_slh_dsa_provider_default_fault_check_on() -> None:
    p = SlhDsaProvider()
    assert p.fault_check is True


def test_slh_dsa_provider_fault_check_can_be_disabled() -> None:
    p = SlhDsaProvider(fault_check=False)
    assert p.fault_check is False


@pytest.mark.parametrize("algo", _SLH_DSA_PARAMS)
def test_get_signature_provider_dispatches_slh_dsa(algo: SignatureAlgorithm) -> None:
    p = get_signature_provider(algo)
    assert isinstance(p, SlhDsaProvider)
    assert p.parameter_set is algo
    assert isinstance(p, SignatureProvider)


def test_slh_dsa_sign_rejects_wrong_algorithm_key() -> None:
    """Algorithm-mismatch check is a precondition — runs without liboqs."""
    p = SlhDsaProvider(SignatureAlgorithm.SLH_DSA_128S)
    bad_key = SignatureKeyPair(
        algorithm=SignatureAlgorithm.ML_DSA_65,
        public_key=b"x",
        private_key=b"y",
        key_id="bad",
    )
    with pytest.raises(ValueError, match="cannot sign with key for"):
        p.sign(b"msg", bad_key)


def test_slh_dsa_fault_detected_exception_carries_metadata() -> None:
    """SlhDsaFaultDetected fields are accessible for telemetry."""
    exc = SlhDsaFaultDetected(
        algorithm="slh-dsa-128s",
        key_id="k1",
        reason="test",
    )
    assert exc.algorithm == "slh-dsa-128s"
    assert exc.key_id == "k1"
    assert exc.reason == "test"


# --- Cryptographic round-trips ----------------------------------------------


@_requires_liboqs
@pytest.mark.parametrize("algo", _SLH_DSA_PARAMS)
def test_slh_dsa_round_trip(algo: SignatureAlgorithm) -> None:
    p = SlhDsaProvider(algo)
    kp = p.generate_keypair()
    assert kp.algorithm is algo
    sig = p.sign(b"hello slh-dsa", kp)
    assert isinstance(sig, bytes) and len(sig) > 0
    assert p.verify(b"hello slh-dsa", sig, kp.public_key)


@_requires_liboqs
@pytest.mark.parametrize("algo", _SLH_DSA_PARAMS)
def test_slh_dsa_signature_lengths_match_fips_205(algo: SignatureAlgorithm) -> None:
    """FIPS 205 §11 mandates constant signature length per parameter set."""
    expected = {
        SignatureAlgorithm.SLH_DSA_128S: 7856,
        SignatureAlgorithm.SLH_DSA_128F: 17088,
        SignatureAlgorithm.SLH_DSA_192S: 16224,
        SignatureAlgorithm.SLH_DSA_256S: 29792,
    }
    p = SlhDsaProvider(algo)
    kp = p.generate_keypair()
    sig = p.sign(b"x", kp)
    assert len(sig) == expected[algo]


@_requires_liboqs
def test_slh_dsa_rejects_tampered_message() -> None:
    p = SlhDsaProvider()
    kp = p.generate_keypair()
    sig = p.sign(b"hello", kp)
    assert not p.verify(b"HELLO", sig, kp.public_key)


@_requires_liboqs
def test_slh_dsa_rejects_signature_under_different_key() -> None:
    p = SlhDsaProvider()
    a = p.generate_keypair("a")
    b = p.generate_keypair("b")
    sig = p.sign(b"x", a)
    assert not p.verify(b"x", sig, b.public_key)


@_requires_liboqs
def test_slh_dsa_rejects_malformed_signature_bytes() -> None:
    p = SlhDsaProvider()
    kp = p.generate_keypair()
    # Wrong-length blob: liboqs rejects, provider returns False (does not raise).
    assert not p.verify(b"msg", b"\x00" * 16, kp.public_key)


@_requires_liboqs
def test_slh_dsa_keypair_default_id_unique() -> None:
    p = SlhDsaProvider()
    a = p.generate_keypair()
    b = p.generate_keypair()
    assert a.key_id != b.key_id
    assert a.key_id.startswith("slh-dsa-128s-")


@_requires_liboqs
def test_slh_dsa_fault_check_skipped_when_public_key_absent() -> None:
    """
    When SignatureKeyPair.public_key is empty (e.g. inside a composite or
    hybrid provider where the public key lives elsewhere), the fault check
    skips rather than failing. Emits the
    pqcrypto.slh_dsa.fault_check_skipped telemetry event.
    """
    p = SlhDsaProvider()
    full_kp = p.generate_keypair()
    no_pk = SignatureKeyPair(
        algorithm=SignatureAlgorithm.SLH_DSA_128S,
        public_key=b"",  # empty
        private_key=full_kp.private_key,
        key_id="no-pk",
    )
    sig = p.sign(b"hello", no_pk)
    assert p.verify(b"hello", sig, full_kp.public_key)


@_requires_liboqs
def test_slh_dsa_fault_check_can_be_disabled_for_perf() -> None:
    """fault_check=False signs without the round-trip verify."""
    p = SlhDsaProvider(fault_check=False)
    kp = p.generate_keypair()
    sig = p.sign(b"hello", kp)
    assert p.verify(b"hello", sig, kp.public_key)


@_requires_liboqs
def test_slh_dsa_l5_used_for_cnsa_2_code_signing() -> None:
    """
    CNSA 2.0 mandates SLH-DSA-256s for software/firmware signing in NSS
    deployments. Confirm the L5 parameter set works as expected.
    """
    p = SlhDsaProvider(SignatureAlgorithm.SLH_DSA_256S)
    kp = p.generate_keypair("cnsa-code-signing-1")
    sig = p.sign(b"release-artifact-bytes", kp)
    assert len(sig) == 29792
    assert p.verify(b"release-artifact-bytes", sig, kp.public_key)

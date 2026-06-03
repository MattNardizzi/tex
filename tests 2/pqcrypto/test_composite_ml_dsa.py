"""
Tests for tex.pqcrypto.composite_ml_dsa (Thread 10).

Covers composite ML-DSA per draft-ietf-lamps-pq-composite-sigs-18 (Apr 2026):
both component halves must verify; the HPKE-style domain separator labels
bind each signature to its parameter set ("non-separability"); algorithm
dispatch through ``get_signature_provider``; and key/signature wire format.
"""

from __future__ import annotations

import struct

import pytest

from tex.pqcrypto.algorithm_agility import (
    SignatureAlgorithm,
    SignatureKeyPair,
    SignatureProvider,
    get_signature_provider,
)
from tex.pqcrypto.composite_ml_dsa import (
    CompositeMlDsaProvider,
    _DOMAIN_SEPARATOR,
    _LEN_PREFIX_BYTES,
    _ML_DSA_COMPONENT,
)


_COMPOSITE_PARAMS = [
    SignatureAlgorithm.COMPOSITE_ML_DSA_65_ED25519,
    SignatureAlgorithm.COMPOSITE_ML_DSA_87_ECDSA_P384,
]


def _liboqs_runtime_ok() -> bool:
    """True iff some ML-DSA / ML-KEM backend is available.

    Accepts pyca/cryptography 48+ native bindings as well as liboqs.
    Tex now prefers the native backend.
    """
    try:
        from tex.pqcrypto.ml_dsa import active_backend_id
        if active_backend_id() is not None:
            return True
    except Exception:
        pass
    try:
        import oqs
        oqs.Signature("ML-DSA-65")
        return True
    except Exception:
        return False


_LIBOQS_AVAILABLE = _liboqs_runtime_ok()
_requires_liboqs = pytest.mark.skipif(
    not _LIBOQS_AVAILABLE,
    reason="liboqs not available in this environment",
)


# --- Structural tests --------------------------------------------------------


def test_composite_rejects_non_composite_parameter_set() -> None:
    with pytest.raises(ValueError, match="Not a composite ML-DSA parameter set"):
        CompositeMlDsaProvider(SignatureAlgorithm.ML_DSA_65)


def test_composite_default_is_ed25519_pair() -> None:
    p = CompositeMlDsaProvider()
    assert p.parameter_set is SignatureAlgorithm.COMPOSITE_ML_DSA_65_ED25519


@pytest.mark.parametrize("algo", _COMPOSITE_PARAMS)
def test_dispatcher_returns_composite_provider(algo: SignatureAlgorithm) -> None:
    p = get_signature_provider(algo)
    assert isinstance(p, CompositeMlDsaProvider)
    assert p.parameter_set is algo
    assert isinstance(p, SignatureProvider)


def test_composite_domain_separators_distinct() -> None:
    """draft-ietf-lamps-pq-composite-sigs-18 §2.2: each parameter set has
    a distinct Label appended to the fixed
    ``CompositeAlgorithmSignatures2025`` Prefix."""
    a = _DOMAIN_SEPARATOR[SignatureAlgorithm.COMPOSITE_ML_DSA_65_ED25519]
    b = _DOMAIN_SEPARATOR[SignatureAlgorithm.COMPOSITE_ML_DSA_87_ECDSA_P384]
    assert a != b
    # Prefix is the literal "2025" string from the published spec — note
    # the 2025 doesn't bump to 2026; it's the registry version.
    assert b"CompositeAlgorithmSignatures2025" in a
    assert b"CompositeAlgorithmSignatures2025" in b
    # Labels match draft-18 §6.
    assert b"COMPSIG-MLDSA65-Ed25519-SHA512" in a
    assert b"COMPSIG-MLDSA87-ECDSA-P384-SHA512" in b


def test_draft_18_oids_match_iana_registrations() -> None:
    """draft-ietf-lamps-pq-composite-sigs-18 §8.1.2 IANA allocations.

    These OIDs are under arc 1.3.6.1.5.5.7.6.x and were assigned by
    IANA when the LAMPS WG promoted the draft to "Submitted to IESG for
    Publication" state in March 2026.
    """
    from tex.pqcrypto.composite_ml_dsa import draft_18_oid

    assert draft_18_oid(SignatureAlgorithm.COMPOSITE_ML_DSA_65_ED25519) == (
        "1.3.6.1.5.5.7.6.48"
    )
    assert draft_18_oid(SignatureAlgorithm.COMPOSITE_ML_DSA_87_ECDSA_P384) == (
        "1.3.6.1.5.5.7.6.49"
    )


def test_composite_ml_dsa_component_mapping() -> None:
    assert _ML_DSA_COMPONENT[SignatureAlgorithm.COMPOSITE_ML_DSA_65_ED25519] \
        is SignatureAlgorithm.ML_DSA_65
    assert _ML_DSA_COMPONENT[SignatureAlgorithm.COMPOSITE_ML_DSA_87_ECDSA_P384] \
        is SignatureAlgorithm.ML_DSA_87


def test_composite_sign_rejects_wrong_algorithm_key() -> None:
    p = CompositeMlDsaProvider(SignatureAlgorithm.COMPOSITE_ML_DSA_65_ED25519)
    bad_key = SignatureKeyPair(
        algorithm=SignatureAlgorithm.ML_DSA_65,  # not a composite key
        public_key=b"x", private_key=b"y", key_id="bad",
    )
    with pytest.raises(ValueError, match="cannot sign with key for"):
        p.sign(b"m", bad_key)


def test_composite_verify_rejects_truncated_signature() -> None:
    """A signature shorter than the 4-byte length prefix returns False."""
    p = CompositeMlDsaProvider()
    assert not p.verify(b"m", b"\x00\x00\x00", b"\x00" * 100)


def test_composite_verify_rejects_oversized_length_prefix() -> None:
    p = CompositeMlDsaProvider()
    bad_sig = struct.pack(">I", 99999) + b"\x00" * 10
    assert not p.verify(b"m", bad_sig, b"\x00" * 100)


# --- Cryptographic round-trips ----------------------------------------------


@_requires_liboqs
@pytest.mark.parametrize("algo", _COMPOSITE_PARAMS)
def test_composite_round_trip(algo: SignatureAlgorithm) -> None:
    p = CompositeMlDsaProvider(algo)
    kp = p.generate_keypair("ck-1")
    assert kp.algorithm is algo
    sig = p.sign(b"hello composite", kp)
    # Signature must contain 4-byte prefix + ML-DSA half + classical half.
    (ml_dsa_len,) = struct.unpack(">I", sig[:_LEN_PREFIX_BYTES])
    assert ml_dsa_len > 0
    assert len(sig) > _LEN_PREFIX_BYTES + ml_dsa_len
    assert p.verify(b"hello composite", sig, kp.public_key)


@_requires_liboqs
@pytest.mark.parametrize("algo", _COMPOSITE_PARAMS)
def test_composite_rejects_tampered_message(algo: SignatureAlgorithm) -> None:
    p = CompositeMlDsaProvider(algo)
    kp = p.generate_keypair()
    sig = p.sign(b"hello", kp)
    assert not p.verify(b"HELLO", sig, kp.public_key)


@_requires_liboqs
@pytest.mark.parametrize("algo", _COMPOSITE_PARAMS)
def test_composite_rejects_signature_under_different_key(
    algo: SignatureAlgorithm,
) -> None:
    p = CompositeMlDsaProvider(algo)
    a = p.generate_keypair("a")
    b = p.generate_keypair("b")
    sig = p.sign(b"x", a)
    assert not p.verify(b"x", sig, b.public_key)


@_requires_liboqs
def test_composite_requires_both_halves_to_verify() -> None:
    """
    The core invariant: corrupting EITHER the ML-DSA half OR the classical
    half of the signature must fail verify. This is the non-separability
    property of draft-18 §4.
    """
    p = CompositeMlDsaProvider(SignatureAlgorithm.COMPOSITE_ML_DSA_65_ED25519)
    kp = p.generate_keypair()
    sig = p.sign(b"m", kp)
    (ml_dsa_len,) = struct.unpack(">I", sig[:_LEN_PREFIX_BYTES])

    # Flip a bit in the ML-DSA half.
    ml_corrupt = bytearray(sig)
    ml_corrupt[_LEN_PREFIX_BYTES + 10] ^= 0x01
    assert not p.verify(b"m", bytes(ml_corrupt), kp.public_key)

    # Flip a bit in the classical half.
    cl_corrupt = bytearray(sig)
    cl_corrupt[_LEN_PREFIX_BYTES + ml_dsa_len + 5] ^= 0x01
    assert not p.verify(b"m", bytes(cl_corrupt), kp.public_key)


@_requires_liboqs
def test_composite_signature_lengths_within_expected_envelope() -> None:
    """
    Sanity envelope: ML-DSA-65 sig is ~3309 bytes + 64 byte Ed25519 + 4 byte
    prefix → ~3377. ML-DSA-87 sig is ~4627 + ECDSA-P384 DER (~104 bytes max)
    + 4 prefix → ~4735.
    """
    p65 = CompositeMlDsaProvider(SignatureAlgorithm.COMPOSITE_ML_DSA_65_ED25519)
    kp65 = p65.generate_keypair()
    sig65 = p65.sign(b"m", kp65)
    assert 3300 < len(sig65) < 3500

    p87 = CompositeMlDsaProvider(SignatureAlgorithm.COMPOSITE_ML_DSA_87_ECDSA_P384)
    kp87 = p87.generate_keypair()
    sig87 = p87.sign(b"m", kp87)
    assert 4600 < len(sig87) < 4800


@_requires_liboqs
def test_composite_domain_separator_prevents_cross_parameter_forgery() -> None:
    """
    A signature produced under COMPOSITE_ML_DSA_65_ED25519 must NOT validate
    under COMPOSITE_ML_DSA_87_ECDSA_P384's verifier, even if the byte layout
    is plausible. This is enforced by the distinct domain separator labels
    that prefix the signed message.
    """
    p65 = CompositeMlDsaProvider(SignatureAlgorithm.COMPOSITE_ML_DSA_65_ED25519)
    p87 = CompositeMlDsaProvider(SignatureAlgorithm.COMPOSITE_ML_DSA_87_ECDSA_P384)
    kp65 = p65.generate_keypair()
    sig65 = p65.sign(b"m", kp65)
    # Different parameter set: must reject (different algorithm enum on key).
    assert not p87.verify(b"m", sig65, kp65.public_key)


@_requires_liboqs
def test_composite_unique_key_ids() -> None:
    p = CompositeMlDsaProvider()
    a = p.generate_keypair()
    b = p.generate_keypair()
    assert a.key_id != b.key_id
    assert a.key_id.startswith("composite-ml-dsa-65-ed25519-")

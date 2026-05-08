"""Tests for tex.events._ecdsa_provider."""

from __future__ import annotations

import pytest

from tex.events._ecdsa_provider import (
    EcdsaP256Provider,
    default_signature_provider,
    ml_dsa_not_yet_wired,
    signature_algorithm_for,
)
from tex.pqcrypto.algorithm_agility import (
    SignatureAlgorithm,
    SignatureKeyPair,
    SignatureProvider,
)


def test_ecdsa_provider_satisfies_protocol() -> None:
    assert isinstance(EcdsaP256Provider(), SignatureProvider)


def test_ecdsa_round_trip() -> None:
    p = EcdsaP256Provider()
    key = p.generate_keypair("k1")
    sig = p.sign(b"hello world", key)
    assert p.verify(b"hello world", sig, key.public_key)


def test_ecdsa_rejects_tampered_message() -> None:
    p = EcdsaP256Provider()
    key = p.generate_keypair("k1")
    sig = p.sign(b"hello world", key)
    assert not p.verify(b"hello WORLD", sig, key.public_key)


def test_ecdsa_rejects_bad_signature_bytes() -> None:
    p = EcdsaP256Provider()
    key = p.generate_keypair("k1")
    assert not p.verify(b"hello", b"not-a-signature", key.public_key)


def test_ecdsa_rejects_bad_public_key() -> None:
    p = EcdsaP256Provider()
    assert not p.verify(b"hello", b"sig", b"not-a-pem-key")


def test_ecdsa_rejects_wrong_algorithm_key() -> None:
    p = EcdsaP256Provider()
    bad_key = SignatureKeyPair(
        algorithm=SignatureAlgorithm.ML_DSA_65,
        public_key=b"x",
        private_key=b"y",
        key_id="bad",
    )
    with pytest.raises(ValueError, match="cannot sign"):
        p.sign(b"x", bad_key)


def test_ecdsa_rejects_non_ec_pem_key() -> None:
    """Verify with an RSA PEM (or any non-EC PEM) returns False, not raises."""
    # A clearly-not-EC PEM body
    rsa_like = b"-----BEGIN PUBLIC KEY-----\nbm90LWVj\n-----END PUBLIC KEY-----\n"
    p = EcdsaP256Provider()
    assert not p.verify(b"hello", b"\x30\x44", rsa_like)


def test_generate_keypair_default_id_is_unique() -> None:
    p = EcdsaP256Provider()
    a = p.generate_keypair()
    b = p.generate_keypair()
    assert a.key_id != b.key_id
    assert a.key_id.startswith("ecdsa-p256-")


def test_default_signature_provider_falls_back_to_ecdsa() -> None:
    """algorithm_agility.get_signature_provider raises NotImplementedError today,
    so default_signature_provider must hand back the local ECDSA provider."""
    p = default_signature_provider()
    assert isinstance(p, SignatureProvider)
    # Round-trip through it to confirm it actually works.
    key = p.generate_keypair("integration")
    sig = p.sign(b"x", key)
    assert p.verify(b"x", sig, key.public_key)


def test_ml_dsa_stub_raises_with_thread4_message() -> None:
    with pytest.raises(NotImplementedError, match="Thread 4"):
        ml_dsa_not_yet_wired()


def test_signature_algorithm_for_known_provider() -> None:
    assert signature_algorithm_for(EcdsaP256Provider()) is SignatureAlgorithm.ECDSA_P256


def test_signature_algorithm_for_unknown_provider_defaults() -> None:
    class _Other:
        def sign(self, m, k): return b""
        def verify(self, m, s, p): return True
        def generate_keypair(self, key_id): raise NotImplementedError

    assert signature_algorithm_for(_Other()) is SignatureAlgorithm.ECDSA_P256

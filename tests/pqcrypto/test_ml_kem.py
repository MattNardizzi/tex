"""
Tests for tex.pqcrypto.ml_kem (Thread 10).

Covers FIPS 203 ML-KEM at all three parameter sets, fail-closed length
checks, ciphertext/private-key validation, and the algorithm-agile
``get_kem_provider`` dispatcher.
"""

from __future__ import annotations

import pytest

from tex.pqcrypto.ml_kem import (
    KemAlgorithm,
    KemKeyPair,
    MlKemProvider,
    get_kem_provider,
)


def _liboqs_runtime_ok() -> bool:
    """True iff ML-KEM round-trip is exercisable.

    Accepts pyca/cryptography 48+ native ML-KEM (768/1024 only) or liboqs
    (all parameter sets). ML-KEM-512 is skipped at the parametrize level
    when only the native backend is present.
    """
    try:
        from tex.pqcrypto.ml_kem import active_backend_id_for
        if active_backend_id_for(KemAlgorithm.ML_KEM_768) is not None:
            return True
    except Exception:
        pass
    try:
        import oqs
        oqs.KeyEncapsulation("ML-KEM-768")
        return True
    except Exception:
        return False


def _kem_512_available() -> bool:
    """ML-KEM-512 requires liboqs (not in pyca 48)."""
    try:
        from tex.pqcrypto.ml_kem import active_backend_id_for
        return active_backend_id_for(KemAlgorithm.ML_KEM_512) is not None
    except Exception:
        return False


_LIBOQS_AVAILABLE = _liboqs_runtime_ok()
_requires_liboqs = pytest.mark.skipif(
    not _LIBOQS_AVAILABLE,
    reason="No ML-KEM backend available",
)
_requires_kem_512 = pytest.mark.skipif(
    not _kem_512_available(),
    reason="ML-KEM-512 not supported by pyca/cryptography 48; requires liboqs",
)


# --- Structural tests (no liboqs needed) -------------------------------------


def test_kem_algorithm_enum_values_stable() -> None:
    assert KemAlgorithm.ML_KEM_512.value == "ml-kem-512"
    assert KemAlgorithm.ML_KEM_768.value == "ml-kem-768"
    assert KemAlgorithm.ML_KEM_1024.value == "ml-kem-1024"


def test_kem_provider_rejects_invalid_parameter_set() -> None:
    with pytest.raises(ValueError, match="Not an ML-KEM parameter set"):
        MlKemProvider("not-a-kem")  # type: ignore[arg-type]


def test_kem_provider_default_is_level_3() -> None:
    p = MlKemProvider()
    assert p.parameter_set is KemAlgorithm.ML_KEM_768


def test_kem_provider_size_constants() -> None:
    p_512 = MlKemProvider(KemAlgorithm.ML_KEM_512)
    p_768 = MlKemProvider(KemAlgorithm.ML_KEM_768)
    p_1024 = MlKemProvider(KemAlgorithm.ML_KEM_1024)
    assert p_512.public_key_bytes == 800
    assert p_768.public_key_bytes == 1184
    assert p_1024.public_key_bytes == 1568
    assert p_512.ciphertext_bytes == 768
    assert p_768.ciphertext_bytes == 1088
    assert p_1024.ciphertext_bytes == 1568
    assert p_1024.shared_secret_bytes == 32


def test_kem_keypair_dataclass_is_frozen() -> None:
    k = KemKeyPair(
        algorithm=KemAlgorithm.ML_KEM_768,
        public_key=b"pk",
        private_key=b"sk",
        key_id="k1",
    )
    with pytest.raises((AttributeError, TypeError)):
        k.key_id = "k2"  # type: ignore[misc]


def test_get_kem_provider_dispatches_all_three() -> None:
    for algo in (
        KemAlgorithm.ML_KEM_512,
        KemAlgorithm.ML_KEM_768,
        KemAlgorithm.ML_KEM_1024,
    ):
        p = get_kem_provider(algo)
        assert isinstance(p, MlKemProvider)
        assert p.parameter_set is algo


def test_encap_rejects_wrong_length_public_key() -> None:
    """No liboqs needed — length check fails before any C call."""
    p = MlKemProvider(KemAlgorithm.ML_KEM_768)
    with pytest.raises(RuntimeError, match="public key length"):
        p.encapsulate(b"\x00" * 99)


def test_decap_rejects_wrong_length_ciphertext() -> None:
    p = MlKemProvider(KemAlgorithm.ML_KEM_768)
    with pytest.raises(RuntimeError, match="ciphertext length"):
        p.decapsulate(b"\x00" * 99, b"\x00" * 2400)


def test_decap_rejects_wrong_length_private_key() -> None:
    """Native pyca/cryptography 48 stores ML-KEM private keys as the 64-byte
    seed (RFC 9881-style format used in TLS/IETF specs). liboqs uses the
    expanded private key. The provider validates against whatever the
    active backend actually emits — we test the "wrong length" branch by
    handing it bytes of an obviously wrong length."""
    p = MlKemProvider(KemAlgorithm.ML_KEM_768)
    with pytest.raises(RuntimeError, match="private key|Invalid|seed"):
        p.decapsulate(b"\x00" * 1088, b"\x00" * 99)


# --- Cryptographic round-trip tests ----------------------------------------


@_requires_liboqs
@pytest.mark.parametrize(
    "algo",
    [
        pytest.param(KemAlgorithm.ML_KEM_512, marks=_requires_kem_512),
        KemAlgorithm.ML_KEM_768,
        KemAlgorithm.ML_KEM_1024,
    ],
)
def test_kem_round_trip(algo: KemAlgorithm) -> None:
    p = MlKemProvider(algo)
    kp = p.generate_keypair()
    assert kp.algorithm is algo
    ct, ss_e = p.encapsulate(kp.public_key)
    ss_d = p.decapsulate(ct, kp.private_key)
    assert ss_e == ss_d
    assert len(ss_e) == 32


@_requires_liboqs
def test_kem_keypair_default_id_unique() -> None:
    p = MlKemProvider()
    a = p.generate_keypair()
    b = p.generate_keypair()
    assert a.key_id != b.key_id
    assert a.key_id.startswith("ml-kem-768-")


@_requires_liboqs
def test_kem_encap_ciphertext_correct_length() -> None:
    algos = [KemAlgorithm.ML_KEM_768, KemAlgorithm.ML_KEM_1024]
    if _kem_512_available():
        algos.insert(0, KemAlgorithm.ML_KEM_512)
    for algo in algos:
        p = MlKemProvider(algo)
        kp = p.generate_keypair()
        ct, ss = p.encapsulate(kp.public_key)
        assert len(ct) == p.ciphertext_bytes
        assert len(ss) == 32


@_requires_liboqs
def test_kem_decap_with_wrong_private_key_yields_different_secret() -> None:
    """
    FIPS 203 §7.3 implicit rejection: decap with a wrong key returns a
    pseudorandom 32-byte value rather than failing. The shared secret will
    differ from the originally encapsulated one — this is the property
    callers MUST authenticate out-of-band (the module docstring documents
    this contract).
    """
    p = MlKemProvider(KemAlgorithm.ML_KEM_768)
    a = p.generate_keypair("a")
    b = p.generate_keypair("b")
    ct, ss_a = p.encapsulate(a.public_key)
    ss_wrong = p.decapsulate(ct, b.private_key)
    assert len(ss_wrong) == 32
    assert ss_wrong != ss_a


@_requires_liboqs
def test_kem_unique_ciphertexts() -> None:
    """Encap is randomized: two encaps under the same pk produce different ct."""
    p = MlKemProvider()
    kp = p.generate_keypair()
    ct1, ss1 = p.encapsulate(kp.public_key)
    ct2, ss2 = p.encapsulate(kp.public_key)
    assert ct1 != ct2
    assert ss1 != ss2  # overwhelmingly likely; theoretical collision negligible

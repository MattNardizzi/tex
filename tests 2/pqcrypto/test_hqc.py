"""
Tests for tex.pqcrypto.hqc — NIST 4th-round HQC KEM (FIPS 207 draft) and
the ML-KEM + HQC hybrid combiner.

Validates:
- Sizes match the actual liboqs 0.15 build (not the spec, since liboqs's
  serialization layer adds small overhead to the spec pk/sk sizes).
- Round-trip on all three parameter sets (HQC-128, HQC-192, HQC-256).
- Fail-closed length validation (no silent zero shared secrets).
- Hybrid combiner derives matching session keys via HKDF-SHA-512.
- The hybrid is secure if EITHER ML-KEM OR HQC remains unbroken
  (independence test: tampering one half breaks the session key derivation).
"""

from __future__ import annotations

import pytest


def _hqc_available() -> bool:
    try:
        import oqs
        oqs.KeyEncapsulation("HQC-128")
        return True
    except Exception:
        return False


_HQC_AVAILABLE = _hqc_available()
_requires_hqc = pytest.mark.skipif(
    not _HQC_AVAILABLE,
    reason=(
        "HQC not enabled in this liboqs build. Rebuild with "
        "-DOQS_ENABLE_KEM_HQC=ON (default OFF since CVE-2025-52473)."
    ),
)


# --- Structural tests -------------------------------------------------------


def test_hqc_algorithm_enum_values() -> None:
    from tex.pqcrypto.hqc import HqcAlgorithm

    assert HqcAlgorithm.HQC_128.value == "hqc-128"
    assert HqcAlgorithm.HQC_192.value == "hqc-192"
    assert HqcAlgorithm.HQC_256.value == "hqc-256"


def test_hqc_provider_default_is_l5() -> None:
    from tex.pqcrypto.hqc import HqcAlgorithm, HqcProvider

    p = HqcProvider()
    assert p.parameter_set is HqcAlgorithm.HQC_256


def test_hqc_provider_rejects_invalid_parameter_set() -> None:
    from tex.pqcrypto.hqc import HqcProvider

    with pytest.raises(ValueError, match="Not an HQC parameter set"):
        HqcProvider("not-a-real-hqc")  # type: ignore[arg-type]


def test_hqc_encap_rejects_wrong_length_pk() -> None:
    """Length validation runs in pure Python, before any C call."""
    from tex.pqcrypto.hqc import HqcAlgorithm, HqcProvider

    p = HqcProvider(HqcAlgorithm.HQC_128)
    with pytest.raises(RuntimeError, match="public key length"):
        p.encapsulate(b"\x00" * 99)


def test_hqc_decap_rejects_wrong_length_ciphertext() -> None:
    from tex.pqcrypto.hqc import HqcAlgorithm, HqcProvider

    p = HqcProvider(HqcAlgorithm.HQC_128)
    with pytest.raises(RuntimeError, match="ciphertext length"):
        p.decapsulate(b"\x00" * 99, b"\x00" * 2305)


def test_hqc_provider_size_constants_match_liboqs_0_15() -> None:
    """
    Pin the sizes to liboqs 0.15.0's actual output. If liboqs 0.16+
    changes these (e.g. a stricter serialization format), this test
    flags the regression.
    """
    from tex.pqcrypto.hqc import HqcAlgorithm, HqcProvider

    p_128 = HqcProvider(HqcAlgorithm.HQC_128)
    p_192 = HqcProvider(HqcAlgorithm.HQC_192)
    p_256 = HqcProvider(HqcAlgorithm.HQC_256)
    assert p_128.public_key_bytes == 2249
    assert p_192.public_key_bytes == 4522
    assert p_256.public_key_bytes == 7245
    assert p_128.ciphertext_bytes == 4433
    assert p_192.ciphertext_bytes == 8978
    assert p_256.ciphertext_bytes == 14421
    assert p_256.shared_secret_bytes == 64  # HQC produces 64-byte shared secret


# --- Cryptographic round-trips ---------------------------------------------


@_requires_hqc
@pytest.mark.parametrize(
    "algo",
    [
        "hqc-128",
        "hqc-192",
        "hqc-256",
    ],
)
def test_hqc_round_trip(algo: str) -> None:
    from tex.pqcrypto.hqc import HqcAlgorithm, HqcProvider

    p = HqcProvider(HqcAlgorithm(algo))
    kp = p.generate_keypair()
    assert len(kp.public_key) == p.public_key_bytes
    ct, ss_e = p.encapsulate(kp.public_key)
    ss_d = p.decapsulate(ct, kp.private_key)
    assert len(ss_e) == 64
    assert ss_e == ss_d


@_requires_hqc
def test_hqc_unique_ciphertexts() -> None:
    """HQC encap is randomized: two encaps under the same pk differ."""
    from tex.pqcrypto.hqc import HqcAlgorithm, HqcProvider

    p = HqcProvider(HqcAlgorithm.HQC_256)
    kp = p.generate_keypair()
    ct1, _ = p.encapsulate(kp.public_key)
    ct2, _ = p.encapsulate(kp.public_key)
    assert ct1 != ct2


@_requires_hqc
def test_hqc_unique_keypairs() -> None:
    from tex.pqcrypto.hqc import HqcProvider

    p = HqcProvider()
    a = p.generate_keypair("a")
    b = p.generate_keypair("b")
    assert a.public_key != b.public_key
    assert a.key_id != b.key_id


# --- Hybrid ML-KEM + HQC combiner ------------------------------------------


@_requires_hqc
def test_hybrid_kem_round_trip_default_params() -> None:
    """Default = ML-KEM-1024 + HQC-256 (CNSA 2.0 Level 5 + L5)."""
    from tex.pqcrypto.hqc import MlKemHqcHybridProvider

    h = MlKemHqcHybridProvider()
    kp = h.generate_keypair("hybrid-1")
    ct, sk_alice = h.encapsulate(kp)
    sk_bob = h.decapsulate(ct, kp)
    assert sk_alice == sk_bob
    assert len(sk_alice) == 32  # default output: AES-256-GCM key size


@_requires_hqc
def test_hybrid_kem_output_length_configurable() -> None:
    from tex.pqcrypto.hqc import MlKemHqcHybridProvider

    h = MlKemHqcHybridProvider()
    kp = h.generate_keypair()
    ct, sk_alice = h.encapsulate(kp, output_bytes=64)
    sk_bob = h.decapsulate(ct, kp, output_bytes=64)
    assert sk_alice == sk_bob
    assert len(sk_alice) == 64


@_requires_hqc
def test_hybrid_kem_keypair_carries_both_halves() -> None:
    from tex.pqcrypto.hqc import MlKemHqcHybridProvider

    h = MlKemHqcHybridProvider()
    kp = h.generate_keypair()
    # ML-KEM-1024 pk = 1568, HQC-256 pk = 7245
    assert len(kp.ml_kem_public_key) == 1568
    assert len(kp.hqc_public_key) == 7245


@_requires_hqc
def test_hybrid_kem_session_keys_independent_per_session() -> None:
    """Two encap calls produce different session keys (randomization)."""
    from tex.pqcrypto.hqc import MlKemHqcHybridProvider

    h = MlKemHqcHybridProvider()
    kp = h.generate_keypair()
    _, sk1 = h.encapsulate(kp)
    _, sk2 = h.encapsulate(kp)
    assert sk1 != sk2


@_requires_hqc
def test_hybrid_kem_kdf_binds_to_both_ciphertexts() -> None:
    """
    The HKDF salt is ml_kem_ct ‖ hqc_ct. If an attacker mixes ciphertexts
    from different sessions, the derived session key changes — proves the
    KDF binds both halves rather than treating them independently.
    """
    from tex.pqcrypto.hqc import HybridKemCiphertext, MlKemHqcHybridProvider

    h = MlKemHqcHybridProvider()
    kp = h.generate_keypair()
    ct_a, sk_a = h.encapsulate(kp)
    ct_b, sk_b = h.encapsulate(kp)
    # Mix: ML-KEM ct from session A, HQC ct from session B.
    mixed_ct = HybridKemCiphertext(
        ml_kem_ciphertext=ct_a.ml_kem_ciphertext,
        hqc_ciphertext=ct_b.hqc_ciphertext,
    )
    # Decap produces some session key (HQC implicit rejection means it
    # doesn't fail outright). But it MUST differ from both sk_a and sk_b
    # because the HKDF info+salt change.
    sk_mixed = h.decapsulate(mixed_ct, kp)
    assert sk_mixed != sk_a
    assert sk_mixed != sk_b

"""
Tests for tex.pqcrypto.threshold_ml_dsa — genuine Mithril MPC threshold
ML-DSA-44 per ePrint 2026/013 (Celi/del Pino/Espitau/Niot/Prest).

These tests bind to the vendored Rust crate (``vendor/mithril/tex_mithril.so``)
via PyO3. They produce bit-for-bit FIPS 204 signatures verifiable under any
unmodified ML-DSA-44 verifier — the signature output of every test is
2,420 bytes (FIPS 204 §8.2).

Tests are gated on the native extension being loadable. On CI runners
without the .so (e.g. non-x86_64 Linux that hasn't rebuilt from
``vendor/mithril/binding_src/``), they skip cleanly.
"""

from __future__ import annotations

import os

import pytest


def _native_available() -> bool:
    try:
        from tex.pqcrypto.threshold_ml_dsa import is_native_available
        return is_native_available()
    except Exception:
        return False


_NATIVE_AVAILABLE = _native_available()
_requires_native = pytest.mark.skipif(
    not _NATIVE_AVAILABLE,
    reason=(
        "Mithril native extension not loadable. Rebuild from "
        "vendor/mithril/binding_src/ with `cargo build --release`."
    ),
)


def _has_third_party_mldsa44_verifier() -> bool:
    """True iff a third-party FIPS 204 ML-DSA-44 verifier is loadable.

    Used to gate the interop assertion: the test claims a Mithril
    signature verifies under an *unmodified* third-party verifier. If
    no third-party verifier is reachable, the claim is vacuous and the
    test skips rather than failing. This matches the
    skip-on-missing-optional-dep convention pytest documents and the
    KNOWN_BUGS.md Bug #8 item 7 guidance for native crypto deps.
    """
    # pyca/cryptography 48+ ships native ML-DSA via OpenSSL 3.5.
    try:
        from cryptography.hazmat.primitives.asymmetric import mldsa  # noqa: F401
        return True
    except Exception:
        pass
    # liboqs is the alternate verifier we accept (legacy CI lanes).
    try:
        import oqs  # noqa: F401
        oqs.Signature("ML-DSA-44")
        return True
    except Exception:
        return False


_requires_third_party_verifier = pytest.mark.skipif(
    not _has_third_party_mldsa44_verifier(),
    reason=(
        "No third-party FIPS 204 ML-DSA-44 verifier installed. "
        "Install pyca/cryptography>=48 (preferred) or liboqs-python."
    ),
)


# --- Structural tests (no native ext required) ------------------------------


def test_supported_params_matches_eprint_2026_013_figure_8() -> None:
    """
    The 15 (t, n) combinations from Figure 8 of ePrint 2026/013.

    This is the parameter space supported by Mithril; nothing else is
    valid. The test pins the list so a future upstream upgrade has to
    deliberately update this assertion.
    """
    from tex.pqcrypto.threshold_ml_dsa import SUPPORTED_PARAMS

    assert SUPPORTED_PARAMS == (
        (2, 2), (2, 3), (3, 3),
        (2, 4), (3, 4), (4, 4),
        (2, 5), (3, 5), (4, 5), (5, 5),
        (2, 6), (3, 6), (4, 6), (5, 6), (6, 6),
    )
    assert len(SUPPORTED_PARAMS) == 15


def test_unsupported_params_rejected_before_native_call() -> None:
    """Param validation runs in Python, before touching the Rust crate."""
    from tex.pqcrypto.threshold_ml_dsa import distributed_keygen

    # 7-of-7 is outside Mithril Figure 8.
    with pytest.raises(ValueError, match="not in Mithril SUPPORTED_PARAMS"):
        distributed_keygen(t=7, n=7)
    # 1-of-anything is outside (threshold must be ≥ 2 in Mithril).
    with pytest.raises(ValueError, match="not in Mithril SUPPORTED_PARAMS"):
        distributed_keygen(t=1, n=3)


def test_seed_must_be_32_bytes() -> None:
    from tex.pqcrypto.threshold_ml_dsa import distributed_keygen

    with pytest.raises(ValueError, match="seed must be 32 bytes"):
        distributed_keygen(t=2, n=3, seed=b"\x00" * 31)


def test_threshold_algorithm_enum_dispatch_redirects_to_native_api() -> None:
    """
    Dispatching through ``get_signature_provider`` for THRESHOLD_ML_DSA_*
    must raise with a redirect to the genuine Mithril module — the single-
    key SignatureProvider Protocol does not fit MPC threshold signing.
    """
    from tex.pqcrypto.algorithm_agility import (
        SignatureAlgorithm,
        get_signature_provider,
    )

    for algo in (
        SignatureAlgorithm.THRESHOLD_ML_DSA_44,
        SignatureAlgorithm.THRESHOLD_ML_DSA_65,
        SignatureAlgorithm.THRESHOLD_ML_DSA_87,
    ):
        with pytest.raises(NotImplementedError, match="genuine MPC threshold"):
            get_signature_provider(algo)


# --- Genuine Mithril cryptographic tests ------------------------------------


@_requires_native
def test_native_extension_loadable() -> None:
    from tex.pqcrypto.threshold_ml_dsa import is_native_available

    assert is_native_available() is True


@_requires_native
@pytest.mark.parametrize("t,n", [(2, 2), (2, 3), (3, 3), (2, 4), (3, 5), (4, 6)])
def test_mithril_round_trip_emits_fips204_signature(t: int, n: int) -> None:
    """
    For each supported (t, n), Mithril produces a signature of exactly
    2,420 bytes — the FIPS 204 ML-DSA-44 size — and the signature
    verifies under the standard FIPS 204 verifier.
    """
    from tex.pqcrypto.threshold_ml_dsa import distributed_keygen, verify_fips204

    sdk = distributed_keygen(t=t, n=n)
    assert sdk.params.t == t
    assert sdk.params.n == n
    # Public key is exactly the FIPS 204 ML-DSA-44 packed pk size (1312 bytes).
    assert len(sdk.public_key) == 1312

    msg = f"Mithril {t}-of-{n} test".encode()
    active = list(range(t))  # first t parties sign
    sig = sdk.threshold_sign(active, msg)
    # FIPS 204 ML-DSA-44 §8.2: signatures are 2420 bytes.
    assert len(sig) == 2420
    # Self-verify via the SDK
    assert sdk.verify(msg, sig) is True
    # And verify under the standalone FIPS 204 verifier — proves the
    # signature is bit-for-bit compatible with any ML-DSA-44 verifier.
    assert verify_fips204(sdk.public_key, msg, sig) is True


@_requires_native
def test_mithril_tampered_message_rejected() -> None:
    from tex.pqcrypto.threshold_ml_dsa import distributed_keygen, verify_fips204

    sdk = distributed_keygen(t=2, n=3)
    sig = sdk.threshold_sign([0, 1], b"original")
    assert verify_fips204(sdk.public_key, b"tampered", sig) is False


@_requires_native
def test_mithril_active_must_be_strictly_ascending() -> None:
    """
    Mithril's protocol rejects ambiguous active sets — duplicate or
    out-of-order indices fail the Python guard before reaching the Rust
    crate.
    """
    from tex.pqcrypto.threshold_ml_dsa import distributed_keygen

    sdk = distributed_keygen(t=2, n=3)
    # Duplicate
    with pytest.raises(ValueError, match="strictly ascending"):
        sdk.threshold_sign([0, 0], b"m")
    # Descending
    with pytest.raises(ValueError, match="strictly ascending"):
        sdk.threshold_sign([1, 0], b"m")


@_requires_native
def test_mithril_active_length_must_equal_t() -> None:
    from tex.pqcrypto.threshold_ml_dsa import distributed_keygen

    sdk = distributed_keygen(t=3, n=5)
    with pytest.raises(ValueError, match="length"):
        sdk.threshold_sign([0, 1], b"m")  # only 2 of needed 3
    with pytest.raises(ValueError, match="length"):
        sdk.threshold_sign([0, 1, 2, 3], b"m")  # 4 instead of 3


@_requires_native
def test_mithril_deterministic_keygen_from_same_seed() -> None:
    """
    A 32-byte seed deterministically produces the same threshold key set.
    Lets operators rotate keys from an HSM-stored seed without coordinating
    party state externally.
    """
    from tex.pqcrypto.threshold_ml_dsa import distributed_keygen

    seed = bytes(range(32))
    sdk1 = distributed_keygen(t=2, n=3, seed=seed)
    sdk2 = distributed_keygen(t=2, n=3, seed=seed)
    assert sdk1.public_key == sdk2.public_key


@_requires_native
def test_mithril_different_subsets_same_pk() -> None:
    """
    Any t-subset of the n parties produces a valid signature under the
    SAME public key. (This is the Mithril invariant — distinct from the
    quorum-certificate construction where each member has their own pk.)
    """
    from tex.pqcrypto.threshold_ml_dsa import distributed_keygen, verify_fips204

    sdk = distributed_keygen(t=3, n=5)
    msg = b"same-pk invariant test"
    sig_a = sdk.threshold_sign([0, 1, 2], msg)
    sig_b = sdk.threshold_sign([0, 2, 4], msg)
    sig_c = sdk.threshold_sign([2, 3, 4], msg)
    # All three signatures verify under the SAME pk.
    assert verify_fips204(sdk.public_key, msg, sig_a)
    assert verify_fips204(sdk.public_key, msg, sig_b)
    assert verify_fips204(sdk.public_key, msg, sig_c)


@_requires_native
@_requires_third_party_verifier
def test_mithril_signature_verifies_under_arbitrary_verifier() -> None:
    """
    The headline property: a Mithril threshold signature is bit-for-bit a
    FIPS 204 ML-DSA-44 signature. The same signature bytes verify under a
    third-party FIPS 204 ML-DSA-44 verifier (pyca/cryptography native, or
    liboqs).
    """
    from tex.pqcrypto.threshold_ml_dsa import distributed_keygen

    sdk = distributed_keygen(t=2, n=2)
    msg = b"cross-implementation interop test"
    sig = sdk.threshold_sign([0, 1], msg)

    # Prefer pyca/cryptography 48+ native ML-DSA-44 (OpenSSL 3.5 path).
    try:
        from cryptography.hazmat.primitives.asymmetric import mldsa

        pk = mldsa.MLDSA44PublicKey.from_public_bytes(sdk.public_key)
        pk.verify(sig, msg)  # raises on failure
        return
    except Exception:
        pass

    # Fall back to liboqs if installed (legacy environments).
    import oqs

    with oqs.Signature("ML-DSA-44") as verifier:
        ok = verifier.verify(msg, sig, sdk.public_key)
    assert ok is True


@_requires_native
def test_mithril_3_of_5_real_world_scenario() -> None:
    """
    Tex production scenario: 3-of-5 regional signers (us-east, us-west,
    eu-central, ap-south, sa-east) produce one canonical signature on a
    FORBID evidence record. Verifier downstream only needs FIPS 204 verify
    — no Mithril-aware code.
    """
    from tex.pqcrypto.threshold_ml_dsa import distributed_keygen, verify_fips204

    sdk = distributed_keygen(t=3, n=5)
    record = (
        b'{"verdict":"FORBID","reason":"unauthorized transfer",'
        b'"sequence_number":1042}'
    )
    # Signers 0 (us-east), 2 (eu-central), 4 (sa-east).
    sig = sdk.threshold_sign([0, 2, 4], record)
    assert len(sig) == 2420
    assert verify_fips204(sdk.public_key, record, sig)

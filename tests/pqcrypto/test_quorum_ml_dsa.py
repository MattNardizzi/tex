"""
Tests for tex.pqcrypto.threshold_ml_dsa (Thread 10).

Covers k-of-n quorum signing across the three threshold parameter sets,
descriptor commitment binding, Sybil resistance via duplicate index check,
below-threshold rejection, and tamper detection on the signed message,
descriptor, and partials.
"""

from __future__ import annotations

import base64
import json

import pytest

from tex.pqcrypto.algorithm_agility import SignatureAlgorithm, get_signature_provider
from tex.pqcrypto.quorum_ml_dsa import (
    PartialSignature,
    QuorumDescriptor,
    QuorumMember,
    QuorumSignature,
    QuorumMlDsaProvider,
    ThresholdQuorumKeySet,
)


_QUORUM_PARAMS = [
    SignatureAlgorithm.QUORUM_ML_DSA_44,
    SignatureAlgorithm.QUORUM_ML_DSA_65,
    SignatureAlgorithm.QUORUM_ML_DSA_87,
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


def test_threshold_provider_rejects_non_threshold_parameter_set() -> None:
    with pytest.raises(ValueError, match="Not a quorum ML-DSA parameter set"):
        QuorumMlDsaProvider(SignatureAlgorithm.ML_DSA_65)


def test_threshold_provider_default_is_l5() -> None:
    p = QuorumMlDsaProvider()
    assert p.parameter_set is SignatureAlgorithm.QUORUM_ML_DSA_87
    assert p.base_algorithm is SignatureAlgorithm.ML_DSA_87


@pytest.mark.parametrize(
    "thresh,base",
    [
        (SignatureAlgorithm.QUORUM_ML_DSA_44, SignatureAlgorithm.ML_DSA_44),
        (SignatureAlgorithm.QUORUM_ML_DSA_65, SignatureAlgorithm.ML_DSA_65),
        (SignatureAlgorithm.QUORUM_ML_DSA_87, SignatureAlgorithm.ML_DSA_87),
    ],
)
def test_threshold_base_algorithm_mapping(
    thresh: SignatureAlgorithm,
    base: SignatureAlgorithm,
) -> None:
    p = QuorumMlDsaProvider(thresh)
    assert p.base_algorithm is base


@pytest.mark.parametrize("algo", _QUORUM_PARAMS)
def test_dispatcher_returns_threshold_provider(algo: SignatureAlgorithm) -> None:
    p = get_signature_provider(algo)
    assert isinstance(p, QuorumMlDsaProvider)
    assert p.parameter_set is algo


def test_quorum_descriptor_rejects_invalid_threshold() -> None:
    with pytest.raises(ValueError, match="invalid threshold"):
        QuorumDescriptor.create(
            k=0, n=3,
            base_algorithm=SignatureAlgorithm.ML_DSA_65,
            members=(
                QuorumMember(0, "a", "AA=="),
                QuorumMember(1, "b", "BB=="),
                QuorumMember(2, "c", "CC=="),
            ),
        )
    with pytest.raises(ValueError, match="invalid threshold"):
        QuorumDescriptor.create(
            k=4, n=3,
            base_algorithm=SignatureAlgorithm.ML_DSA_65,
            members=(
                QuorumMember(0, "a", "AA=="),
                QuorumMember(1, "b", "BB=="),
                QuorumMember(2, "c", "CC=="),
            ),
        )


def test_quorum_descriptor_rejects_duplicate_indices() -> None:
    with pytest.raises(ValueError, match="duplicate"):
        QuorumDescriptor.create(
            k=2, n=2,
            base_algorithm=SignatureAlgorithm.ML_DSA_65,
            members=(
                QuorumMember(0, "a", "AA=="),
                QuorumMember(0, "b", "BB=="),  # duplicate
            ),
        )


def test_quorum_descriptor_rejects_wrong_base_algorithm() -> None:
    with pytest.raises(ValueError, match="ML-DSA"):
        QuorumDescriptor.create(
            k=1, n=1,
            base_algorithm=SignatureAlgorithm.ED25519,  # type: ignore[arg-type]
            members=(QuorumMember(0, "a", "AA=="),),
        )


def test_quorum_descriptor_commitment_deterministic() -> None:
    """Same (k, n, algo, members) must produce the same SHA-256 commitment."""
    members = (
        QuorumMember(0, "a", "AAAA"),
        QuorumMember(1, "b", "BBBB"),
        QuorumMember(2, "c", "CCCC"),
    )
    d1 = QuorumDescriptor.create(
        k=2, n=3, base_algorithm=SignatureAlgorithm.ML_DSA_87, members=members,
    )
    d2 = QuorumDescriptor.create(
        k=2, n=3, base_algorithm=SignatureAlgorithm.ML_DSA_87, members=members,
    )
    assert d1.commitment == d2.commitment
    assert len(d1.commitment) == 64  # SHA-256 hex


def test_quorum_descriptor_commitment_changes_with_k() -> None:
    """Changing the threshold changes the commitment (forgery resistance)."""
    members = (
        QuorumMember(0, "a", "AAAA"),
        QuorumMember(1, "b", "BBBB"),
        QuorumMember(2, "c", "CCCC"),
    )
    d_k1 = QuorumDescriptor.create(
        k=1, n=3, base_algorithm=SignatureAlgorithm.ML_DSA_87, members=members,
    )
    d_k2 = QuorumDescriptor.create(
        k=2, n=3, base_algorithm=SignatureAlgorithm.ML_DSA_87, members=members,
    )
    assert d_k1.commitment != d_k2.commitment


# --- Cryptographic quorum round-trips ---------------------------------------


@_requires_liboqs
@pytest.mark.parametrize("algo", _QUORUM_PARAMS)
def test_threshold_quorum_round_trip(algo: SignatureAlgorithm) -> None:
    """Generate, sign with k members, aggregate, verify."""
    p = QuorumMlDsaProvider(algo)
    keyset = p.distributed_keygen(n=4, k=2)
    msg = b"high-stakes evidence record"

    keys = keyset.keys_for([0, 1])
    partials = [
        p.partial_sign(msg, idx, key, keyset.descriptor)
        for idx, key in keys.items()
    ]
    qs = p.aggregate(partials, keyset.descriptor)
    assert p.verify_quorum(msg, qs, keyset.descriptor)


@_requires_liboqs
@pytest.mark.parametrize(
    "n,k",
    [(2, 2), (3, 2), (4, 3), (5, 3), (7, 4), (10, 6)],
)
def test_threshold_various_n_k(n: int, k: int) -> None:
    p = QuorumMlDsaProvider(SignatureAlgorithm.QUORUM_ML_DSA_65)
    keyset = p.distributed_keygen(n=n, k=k)
    msg = b"message"
    indices = list(range(k))
    keys = keyset.keys_for(indices)
    partials = [
        p.partial_sign(msg, idx, key, keyset.descriptor)
        for idx, key in keys.items()
    ]
    qs = p.aggregate(partials, keyset.descriptor)
    assert p.verify_quorum(msg, qs, keyset.descriptor)


@_requires_liboqs
def test_threshold_rejects_below_threshold_aggregate() -> None:
    p = QuorumMlDsaProvider(SignatureAlgorithm.QUORUM_ML_DSA_65)
    keyset = p.distributed_keygen(n=5, k=3)
    keys = keyset.keys_for([0, 1])  # only 2 of required 3
    partials = [
        p.partial_sign(b"m", idx, key, keyset.descriptor)
        for idx, key in keys.items()
    ]
    with pytest.raises(ValueError, match="threshold not reached"):
        p.aggregate(partials, keyset.descriptor)


@_requires_liboqs
def test_threshold_rejects_duplicate_partial_in_aggregate() -> None:
    """Sybil resistance: aggregating two partials from the same member fails."""
    p = QuorumMlDsaProvider(SignatureAlgorithm.QUORUM_ML_DSA_65)
    keyset = p.distributed_keygen(n=3, k=2)
    keys = keyset.keys_for([0])
    p0 = p.partial_sign(b"m", 0, keys[0], keyset.descriptor)
    # Same member signing twice — must reject regardless of message.
    p0_again = p.partial_sign(b"m", 0, keys[0], keyset.descriptor)
    with pytest.raises(ValueError, match="duplicate"):
        p.aggregate([p0, p0_again], keyset.descriptor)


@_requires_liboqs
def test_threshold_rejects_unknown_member_in_aggregate() -> None:
    """A partial claiming a member index outside the descriptor is rejected."""
    p = QuorumMlDsaProvider(SignatureAlgorithm.QUORUM_ML_DSA_65)
    keyset = p.distributed_keygen(n=3, k=2)
    keys = keyset.keys_for([0, 1])
    parts = [
        p.partial_sign(b"m", idx, key, keyset.descriptor)
        for idx, key in keys.items()
    ]
    # Fabricate a partial with an out-of-range index.
    fake = PartialSignature(
        member_index=99, member_id="ghost", signature_b64="AAAA",
    )
    with pytest.raises(ValueError, match="not in descriptor"):
        p.aggregate([fake] + parts, keyset.descriptor)


@_requires_liboqs
def test_threshold_verify_rejects_tampered_message() -> None:
    p = QuorumMlDsaProvider(SignatureAlgorithm.QUORUM_ML_DSA_87)
    keyset = p.distributed_keygen(n=4, k=2)
    keys = keyset.keys_for([0, 1])
    parts = [
        p.partial_sign(b"original", idx, key, keyset.descriptor)
        for idx, key in keys.items()
    ]
    qs = p.aggregate(parts, keyset.descriptor)
    assert not p.verify_quorum(b"tampered", qs, keyset.descriptor)


@_requires_liboqs
def test_threshold_verify_rejects_descriptor_commitment_mismatch() -> None:
    """Tampering with the descriptor between sign and verify must fail."""
    p = QuorumMlDsaProvider(SignatureAlgorithm.QUORUM_ML_DSA_65)
    keyset_a = p.distributed_keygen(n=3, k=2)
    keyset_b = p.distributed_keygen(n=3, k=2)  # different keys
    keys = keyset_a.keys_for([0, 1])
    parts = [
        p.partial_sign(b"m", idx, key, keyset_a.descriptor)
        for idx, key in keys.items()
    ]
    qs = p.aggregate(parts, keyset_a.descriptor)
    # Try to verify against a different descriptor (different commitment).
    assert not p.verify_quorum(b"m", qs, keyset_b.descriptor)


@_requires_liboqs
def test_threshold_verify_rejects_member_id_substitution() -> None:
    """
    An attacker who flips a member_id on a partial (matching index, wrong id)
    must be rejected — member_id is part of the descriptor binding.
    """
    p = QuorumMlDsaProvider(SignatureAlgorithm.QUORUM_ML_DSA_65)
    keyset = p.distributed_keygen(n=3, k=2)
    keys = keyset.keys_for([0, 1])
    p0 = p.partial_sign(b"m", 0, keys[0], keyset.descriptor)
    p1 = p.partial_sign(b"m", 1, keys[1], keyset.descriptor)
    # Substitute member_id on p0.
    forged = PartialSignature(
        member_index=0,
        member_id="not-the-real-id",
        signature_b64=p0.signature_b64,
    )
    qs = QuorumSignature(
        threshold_algorithm=p.parameter_set,
        descriptor_commitment=keyset.descriptor.commitment,
        partials=(forged, p1),
    )
    assert not p.verify_quorum(b"m", qs, keyset.descriptor)


@_requires_liboqs
def test_threshold_protocol_methods_redirect_to_quorum_path() -> None:
    """Single-key Protocol methods raise NotImplementedError."""
    p = QuorumMlDsaProvider(SignatureAlgorithm.QUORUM_ML_DSA_65)
    from tex.pqcrypto.algorithm_agility import SignatureKeyPair
    bad_key = SignatureKeyPair(
        algorithm=SignatureAlgorithm.ML_DSA_65,
        public_key=b"", private_key=b"", key_id="x",
    )
    with pytest.raises(NotImplementedError, match="quorum signing"):
        p.sign(b"m", bad_key)
    with pytest.raises(NotImplementedError, match="QuorumDescriptor"):
        p.verify(b"m", b"sig", b"pk")
    with pytest.raises(NotImplementedError, match="distributed_keygen"):
        p.generate_keypair()


@_requires_liboqs
def test_threshold_quorum_partial_sign_rejects_wrong_member_index() -> None:
    p = QuorumMlDsaProvider(SignatureAlgorithm.QUORUM_ML_DSA_65)
    keyset = p.distributed_keygen(n=3, k=2)
    keys = keyset.keys_for([0])
    with pytest.raises(ValueError, match="out of range"):
        p.partial_sign(b"m", -1, keys[0], keyset.descriptor)
    with pytest.raises(ValueError, match="out of range"):
        p.partial_sign(b"m", 99, keys[0], keyset.descriptor)


@_requires_liboqs
def test_threshold_quorum_partial_sign_rejects_wrong_key_algorithm() -> None:
    from tex.pqcrypto.algorithm_agility import SignatureKeyPair
    p = QuorumMlDsaProvider(SignatureAlgorithm.QUORUM_ML_DSA_87)
    keyset = p.distributed_keygen(n=2, k=1)
    bad_key = SignatureKeyPair(
        algorithm=SignatureAlgorithm.ML_DSA_44,  # wrong base for L5 threshold
        public_key=b"", private_key=b"", key_id="x",
    )
    with pytest.raises(ValueError, match="member key algorithm"):
        p.partial_sign(b"m", 0, bad_key, keyset.descriptor)


@_requires_liboqs
def test_threshold_quorum_3_of_5_real_world() -> None:
    """
    The real-world Tex scenario: 5 regional signers, 3-of-5 threshold,
    sign a FORBID evidence record. Confirms the full flow including
    arbitrary signing-member selection (not the first k).
    """
    p = QuorumMlDsaProvider(SignatureAlgorithm.QUORUM_ML_DSA_87)
    keyset = p.distributed_keygen(
        n=5, k=3,
        member_ids=["us-east", "us-west", "eu-central", "ap-south", "sa-east"],
    )
    msg = b"FORBID: unauthorized financial transaction blocked"

    # Signers 0, 2, 4 sign (us-east, eu-central, sa-east).
    keys = keyset.keys_for([0, 2, 4])
    partials = [
        p.partial_sign(msg, idx, key, keyset.descriptor)
        for idx, key in keys.items()
    ]
    qs = p.aggregate(partials, keyset.descriptor)
    assert qs.descriptor_commitment == keyset.descriptor.commitment
    assert len(qs.partials) == 3
    assert p.verify_quorum(msg, qs, keyset.descriptor)

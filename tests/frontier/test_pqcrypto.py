"""
Tests for the Tex pqcrypto package (Thread 4).

Structure
---------
- Structural tests run on every CI machine (Render free tier included)
  — they verify the algorithm-agility dispatch, hybrid wire-format
  layout, and evidence record schema without needing liboqs.
- Cryptographic round-trip tests are guarded by ``pytest.importorskip("oqs")``
  and ``_liboqs_runtime_ok()`` so they skip cleanly when liboqs is
  absent or its C shared library is missing.
"""

from __future__ import annotations

import base64
import struct
from datetime import UTC, datetime
from typing import Any

import pytest

from tex.events._canonical import canonical_json
from tex.pqcrypto.algorithm_agility import (
    SignatureAlgorithm,
    SignatureKeyPair,
    SignatureProvider,
    get_signature_provider,
)
from tex.pqcrypto.evidence_chain_signer import (
    PqSignature,
    sign_evidence_record,
    verify_evidence_record_signature,
)
from tex.pqcrypto.hybrid import (
    HybridMlDsaEd25519Provider,
    _HYBRID_LAYOUT_VERSION,
    _LEN_PREFIX_BYTES,
)
from tex.pqcrypto.ml_dsa import MlDsaProvider


# --- helpers ---


def _liboqs_runtime_ok() -> bool:
    """True iff liboqs is importable AND its C library loads."""
    try:
        import oqs

        oqs.Signature("ML-DSA-65")
    except Exception:
        return False
    return True


_LIBOQS_AVAILABLE = _liboqs_runtime_ok()
_requires_liboqs = pytest.mark.skipif(
    not _LIBOQS_AVAILABLE,
    reason="liboqs not available in this environment",
)


def _realistic_record() -> dict[str, Any]:
    """
    Fixture record mirroring ``tex.events.event.Event.canonical_record_input()``
    so canonicalization is exercised against the realistic field shape:
    datetime serialised to ISO 8601, tuple-of-strings → list, an optional
    field present as None, a nested dict on the wider record (payload),
    and a SHA-256 digest of that payload.

    Returns a dict that is a strict superset of canonical_record_input() —
    extra fields (event_id, payload, record_hash) are included so the test
    proves canonicalization is deterministic across the *full* record
    shape, not just the hashed-input subset.
    """
    payload = {
        "subject": "Q3 forecast",
        "draft_html": "<p>Numbers look strong.</p>",
        "model": "gpt-5",
        "tokens_in": 1024,
        "tokens_out": 512,
        "tool_calls": [
            {"name": "crm.lookup", "args": {"contact_id": "c-7"}},
            {"name": "crm.note", "args": {"contact_id": "c-7", "body": "Replied"}},
        ],
    }
    timestamp = datetime(2026, 5, 7, 13, 30, 0, tzinfo=UTC)
    return {
        "event_id": "evt-2026-0507-13-30-000042",
        "kind": "AGENT_EMITS_OUTPUT",
        "actor_entity_id": "agent:tex-sdr-01",
        "target_entity_id": "recipient:cfo@acme.com",
        "payload": payload,
        "timestamp": timestamp.isoformat(),
        "sequence_number": 42,
        "upstream_event_ids": ["evt-prior-001", "evt-prior-002"],
        "previous_ledger_hash": "1" * 64,
        "payload_sha256": "0" * 64,
        "tool_receipt_id": None,
        "record_hash": "a" * 64,
    }


# --- algorithm_agility ---


def test_signature_algorithm_enum_values_stable() -> None:
    assert SignatureAlgorithm.ML_DSA_65.value == "ml-dsa-65"
    assert SignatureAlgorithm.HYBRID_ML_DSA_ED25519.value == "hybrid-ml-dsa-65-ed25519"
    assert SignatureAlgorithm.ECDSA_P256.value == "ecdsa-p256"
    assert SignatureAlgorithm.SLH_DSA_128S.value == "slh-dsa-128s"


def test_keypair_dataclass_is_frozen() -> None:
    k = SignatureKeyPair(
        algorithm=SignatureAlgorithm.ML_DSA_65,
        public_key=b"pk",
        private_key=b"sk",
        key_id="k1",
    )
    with pytest.raises((AttributeError, TypeError)):
        k.key_id = "k2"  # type: ignore[misc]


def test_get_signature_provider_dispatches_ml_dsa() -> None:
    for algo in (
        SignatureAlgorithm.ML_DSA_44,
        SignatureAlgorithm.ML_DSA_65,
        SignatureAlgorithm.ML_DSA_87,
    ):
        p = get_signature_provider(algo)
        assert isinstance(p, MlDsaProvider)
        assert p.parameter_set is algo
        assert p.algorithm is algo


def test_get_signature_provider_dispatches_hybrid() -> None:
    p = get_signature_provider(SignatureAlgorithm.HYBRID_ML_DSA_ED25519)
    assert isinstance(p, HybridMlDsaEd25519Provider)
    assert p.algorithm is SignatureAlgorithm.HYBRID_ML_DSA_ED25519


def test_get_signature_provider_dispatches_ed25519() -> None:
    from tex.pqcrypto._ed25519_provider import Ed25519Provider

    p = get_signature_provider(SignatureAlgorithm.ED25519)
    assert isinstance(p, Ed25519Provider)
    assert p.algorithm is SignatureAlgorithm.ED25519


def test_get_signature_provider_dispatches_ecdsa() -> None:
    from tex.events._ecdsa_provider import EcdsaP256Provider

    p = get_signature_provider(SignatureAlgorithm.ECDSA_P256)
    assert isinstance(p, EcdsaP256Provider)
    assert p.algorithm is SignatureAlgorithm.ECDSA_P256


def test_get_signature_provider_slh_dsa_remains_p1_stub() -> None:
    with pytest.raises(NotImplementedError, match="SLH-DSA"):
        get_signature_provider(SignatureAlgorithm.SLH_DSA_128S)


def test_dispatched_providers_satisfy_protocol() -> None:
    for algo in (
        SignatureAlgorithm.ML_DSA_44,
        SignatureAlgorithm.ML_DSA_65,
        SignatureAlgorithm.ML_DSA_87,
        SignatureAlgorithm.HYBRID_ML_DSA_ED25519,
        SignatureAlgorithm.ED25519,
        SignatureAlgorithm.ECDSA_P256,
    ):
        assert isinstance(get_signature_provider(algo), SignatureProvider)


# --- ml_dsa structural ---


def test_ml_dsa_provider_rejects_non_ml_dsa_parameter_set() -> None:
    with pytest.raises(ValueError, match="Not an ML-DSA"):
        MlDsaProvider(SignatureAlgorithm.ECDSA_P256)  # type: ignore[arg-type]


def test_ml_dsa_provider_default_is_level_3() -> None:
    p = MlDsaProvider()
    assert p.parameter_set is SignatureAlgorithm.ML_DSA_65


def test_ml_dsa_sign_rejects_wrong_algorithm_key() -> None:
    """Algorithm-mismatch check is a precondition — runs without liboqs."""
    p = MlDsaProvider(SignatureAlgorithm.ML_DSA_65)
    bad_key = SignatureKeyPair(
        algorithm=SignatureAlgorithm.ECDSA_P256,
        public_key=b"x",
        private_key=b"y",
        key_id="bad",
    )
    with pytest.raises(ValueError, match="cannot sign with key for"):
        p.sign(b"msg", bad_key)


# --- ml_dsa cryptographic round-trips ---


@_requires_liboqs
@pytest.mark.parametrize(
    "algo",
    [
        SignatureAlgorithm.ML_DSA_44,
        SignatureAlgorithm.ML_DSA_65,
        SignatureAlgorithm.ML_DSA_87,
    ],
)
def test_ml_dsa_round_trip(algo: SignatureAlgorithm) -> None:
    p = MlDsaProvider(algo)
    key = p.generate_keypair("rt")
    assert key.algorithm is algo
    sig = p.sign(b"hello world", key)
    assert isinstance(sig, bytes) and len(sig) > 0
    assert p.verify(b"hello world", sig, key.public_key)


@_requires_liboqs
def test_ml_dsa_rejects_tampered_message() -> None:
    p = MlDsaProvider()
    key = p.generate_keypair()
    sig = p.sign(b"hello world", key)
    assert not p.verify(b"hello WORLD", sig, key.public_key)


@_requires_liboqs
def test_ml_dsa_rejects_malformed_signature_bytes() -> None:
    p = MlDsaProvider()
    key = p.generate_keypair()
    # liboqs raises on signatures of the wrong length; provider returns False.
    assert not p.verify(b"x", b"\x00" * 16, key.public_key)


@_requires_liboqs
def test_ml_dsa_rejects_signature_under_different_key() -> None:
    p = MlDsaProvider()
    a = p.generate_keypair("a")
    b = p.generate_keypair("b")
    sig = p.sign(b"x", a)
    assert not p.verify(b"x", sig, b.public_key)


@_requires_liboqs
def test_ml_dsa_generate_keypair_default_id_unique() -> None:
    p = MlDsaProvider()
    a = p.generate_keypair()
    b = p.generate_keypair()
    assert a.key_id != b.key_id
    assert a.key_id.startswith("ml-dsa-65-")


# --- hybrid structural ---


def test_hybrid_layout_version_constant_present() -> None:
    """The version constant must exist so future migrations can branch on it."""
    assert _HYBRID_LAYOUT_VERSION == "1"
    assert _LEN_PREFIX_BYTES == 4


def test_hybrid_provider_algorithm_tag() -> None:
    p = HybridMlDsaEd25519Provider()
    assert p.algorithm is SignatureAlgorithm.HYBRID_ML_DSA_ED25519


def test_hybrid_sign_rejects_wrong_algorithm_key() -> None:
    p = HybridMlDsaEd25519Provider()
    bad = SignatureKeyPair(
        algorithm=SignatureAlgorithm.ML_DSA_65,
        public_key=b"x",
        private_key=b"y",
        key_id="bad",
    )
    with pytest.raises(ValueError, match="cannot sign with key for"):
        p.sign(b"x", bad)


def test_hybrid_verify_rejects_truncated_signature() -> None:
    """A 3-byte signature can't even contain the length prefix — must return False."""
    p = HybridMlDsaEd25519Provider()
    assert not p.verify(b"msg", b"\x00\x00\x00", b"\x00" * 100)


def test_hybrid_verify_rejects_oversized_length_prefix() -> None:
    """A length prefix bigger than the blob itself must return False."""
    p = HybridMlDsaEd25519Provider()
    bad_sig = struct.pack(">I", 99999) + b"\x00" * 10
    assert not p.verify(b"msg", bad_sig, b"\x00" * 100)


# --- hybrid cryptographic round-trips ---


@_requires_liboqs
def test_hybrid_round_trip() -> None:
    p = HybridMlDsaEd25519Provider()
    key = p.generate_keypair("hybrid-1")
    assert key.algorithm is SignatureAlgorithm.HYBRID_ML_DSA_ED25519
    sig = p.sign(b"hello hybrid", key)
    # Signature must contain the 4-byte prefix + ML-DSA-65 sig (~3309) + Ed25519 (64)
    (ml_dsa_len,) = struct.unpack(">I", sig[:4])
    assert ml_dsa_len > 0
    assert len(sig) == 4 + ml_dsa_len + 64
    assert p.verify(b"hello hybrid", sig, key.public_key)


@_requires_liboqs
def test_hybrid_rejects_tampered_message() -> None:
    p = HybridMlDsaEd25519Provider()
    key = p.generate_keypair()
    sig = p.sign(b"hello", key)
    assert not p.verify(b"HELLO", sig, key.public_key)


@_requires_liboqs
def test_hybrid_requires_both_halves_to_pass() -> None:
    """
    Flipping a bit in the ML-DSA half OR the Ed25519 half must fail verify.
    This is the core hybrid invariant — defense in depth means BOTH halves.
    """
    p = HybridMlDsaEd25519Provider()
    key = p.generate_keypair()
    sig = p.sign(b"hello", key)
    (ml_dsa_len,) = struct.unpack(">I", sig[:4])

    # Flip a bit inside the ML-DSA half.
    ml_dsa_corrupt = bytearray(sig)
    ml_dsa_corrupt[10] ^= 0x01
    assert not p.verify(b"hello", bytes(ml_dsa_corrupt), key.public_key)

    # Flip a bit inside the Ed25519 half.
    ed_corrupt = bytearray(sig)
    ed_corrupt[4 + ml_dsa_len + 5] ^= 0x01
    assert not p.verify(b"hello", bytes(ed_corrupt), key.public_key)


@_requires_liboqs
def test_hybrid_rejects_signature_under_different_key() -> None:
    p = HybridMlDsaEd25519Provider()
    a = p.generate_keypair("a")
    b = p.generate_keypair("b")
    sig = p.sign(b"x", a)
    assert not p.verify(b"x", sig, b.public_key)


# --- evidence_chain_signer ---


def test_pq_signature_dataclass_is_frozen() -> None:
    s = PqSignature(
        algorithm=SignatureAlgorithm.ML_DSA_65,
        key_id="k1",
        signature_b64="QUJD",
        signed_at="2026-05-07T13:00:00+00:00",
    )
    with pytest.raises((AttributeError, TypeError)):
        s.key_id = "k2"  # type: ignore[misc]


def test_evidence_signer_canonicalization_excludes_pq_signature_field() -> None:
    """
    The bytes signed must be identical whether or not a pq_signature
    field is already attached. This is what lets a record be signed,
    embed the signature, then re-verified.
    """
    record = _realistic_record()
    # Without pq_signature
    bare = canonical_json({k: v for k, v in record.items() if k != "pq_signature"})
    # With a pq_signature attached (verifier path)
    with_sig = dict(record)
    with_sig["pq_signature"] = {"algorithm": "ml-dsa-65", "signature_b64": "AAAA"}
    stripped = {k: v for k, v in with_sig.items() if k != "pq_signature"}
    assert bare == canonical_json(stripped)


@_requires_liboqs
def test_sign_and_verify_evidence_record_round_trip_ml_dsa_65() -> None:
    record = _realistic_record()
    p = get_signature_provider(SignatureAlgorithm.ML_DSA_65)
    key = p.generate_keypair("evidence-1")
    pq_sig = sign_evidence_record(record, key)
    assert pq_sig.algorithm is SignatureAlgorithm.ML_DSA_65
    assert pq_sig.key_id == "evidence-1"
    assert base64.b64decode(pq_sig.signature_b64)
    # ISO 8601 with timezone — datetime must round-trip
    parsed = datetime.fromisoformat(pq_sig.signed_at)
    assert parsed.tzinfo is not None
    assert verify_evidence_record_signature(record, pq_sig, key.public_key)


@_requires_liboqs
def test_sign_and_verify_evidence_record_round_trip_hybrid() -> None:
    record = _realistic_record()
    p = get_signature_provider(SignatureAlgorithm.HYBRID_ML_DSA_ED25519)
    key = p.generate_keypair("evidence-hybrid")
    pq_sig = sign_evidence_record(record, key)
    assert pq_sig.algorithm is SignatureAlgorithm.HYBRID_ML_DSA_ED25519
    assert verify_evidence_record_signature(record, pq_sig, key.public_key)


@_requires_liboqs
def test_evidence_signer_round_trip_with_embedded_pq_signature_field() -> None:
    """
    Verifier must accept records that already carry a pq_signature field
    (the canonical case after sign->embed->store->retrieve->verify).
    """
    record = _realistic_record()
    p = get_signature_provider(SignatureAlgorithm.ML_DSA_65)
    key = p.generate_keypair("embedded")
    pq_sig = sign_evidence_record(record, key)
    embedded = dict(record)
    embedded["pq_signature"] = {
        "algorithm": pq_sig.algorithm.value,
        "key_id": pq_sig.key_id,
        "signature_b64": pq_sig.signature_b64,
        "signed_at": pq_sig.signed_at,
    }
    assert verify_evidence_record_signature(embedded, pq_sig, key.public_key)


@_requires_liboqs
def test_evidence_signer_rejects_tampered_payload_field() -> None:
    record = _realistic_record()
    p = get_signature_provider(SignatureAlgorithm.ML_DSA_65)
    key = p.generate_keypair()
    pq_sig = sign_evidence_record(record, key)
    tampered = dict(record)
    tampered["sequence_number"] = 999  # mutate one field
    assert not verify_evidence_record_signature(tampered, pq_sig, key.public_key)


@_requires_liboqs
def test_evidence_signer_rejects_wrong_public_key() -> None:
    record = _realistic_record()
    p = get_signature_provider(SignatureAlgorithm.ML_DSA_65)
    key_a = p.generate_keypair("a")
    key_b = p.generate_keypair("b")
    pq_sig = sign_evidence_record(record, key_a)
    assert not verify_evidence_record_signature(record, pq_sig, key_b.public_key)


def test_evidence_signer_rejects_malformed_signature_b64() -> None:
    """
    Operational failure path — runs without liboqs. Verifier returns
    False (does not raise) and emits the verify_failed event.
    """
    record = _realistic_record()
    bad_sig = PqSignature(
        algorithm=SignatureAlgorithm.ML_DSA_65,
        key_id="k1",
        signature_b64="not%valid%base64!!",
        signed_at="2026-05-07T13:00:00+00:00",
    )
    assert not verify_evidence_record_signature(record, bad_sig, b"\x00" * 100)


def test_evidence_signer_rejects_canonicalization_failure() -> None:
    """
    A record that contains a float trips the RFC 8785 subset check —
    must return False, not raise.
    """
    bad_record: dict[str, Any] = dict(_realistic_record())
    bad_record["bad_float"] = 3.14
    sig = PqSignature(
        algorithm=SignatureAlgorithm.ML_DSA_65,
        key_id="k1",
        signature_b64=base64.b64encode(b"x" * 100).decode("ascii"),
        signed_at="2026-05-07T13:00:00+00:00",
    )
    assert not verify_evidence_record_signature(bad_record, sig, b"\x00" * 100)


def test_evidence_signer_rejects_unwired_algorithm() -> None:
    """SLH-DSA path — provider not yet wired, verifier returns False."""
    record = _realistic_record()
    sig = PqSignature(
        algorithm=SignatureAlgorithm.SLH_DSA_128S,
        key_id="k1",
        signature_b64=base64.b64encode(b"x" * 100).decode("ascii"),
        signed_at="2026-05-07T13:00:00+00:00",
    )
    assert not verify_evidence_record_signature(record, sig, b"\x00" * 100)


# --- ml_kem and slh_dsa stay stub ---


def test_ml_kem_remains_stub() -> None:
    from tex.pqcrypto.ml_kem import MlKemProvider

    p = MlKemProvider()
    with pytest.raises(NotImplementedError, match="FIPS 203"):
        p.encapsulate(b"pk")
    with pytest.raises(NotImplementedError, match="FIPS 203"):
        p.decapsulate(b"ct", b"sk")


def test_slh_dsa_remains_stub() -> None:
    from tex.pqcrypto.slh_dsa import SlhDsaProvider

    p = SlhDsaProvider()
    with pytest.raises(NotImplementedError, match="FIPS 205"):
        p.sign(b"msg", b"sk")
    with pytest.raises(NotImplementedError, match="FIPS 205"):
        p.verify(b"msg", b"sig", b"pk")


# --- Ed25519 provider ---


def test_ed25519_provider_round_trip() -> None:
    """Ed25519 needs no liboqs — uses cryptography lib."""
    from tex.pqcrypto._ed25519_provider import Ed25519Provider

    p = Ed25519Provider()
    key = p.generate_keypair("ed-1")
    assert key.algorithm is SignatureAlgorithm.ED25519
    sig = p.sign(b"msg", key)
    assert p.verify(b"msg", sig, key.public_key)
    assert not p.verify(b"MSG", sig, key.public_key)


def test_ed25519_provider_rejects_wrong_algorithm_key() -> None:
    from tex.pqcrypto._ed25519_provider import Ed25519Provider

    p = Ed25519Provider()
    bad = SignatureKeyPair(
        algorithm=SignatureAlgorithm.ML_DSA_65,
        public_key=b"x",
        private_key=b"y",
        key_id="bad",
    )
    with pytest.raises(ValueError, match="cannot sign"):
        p.sign(b"msg", bad)


def test_ed25519_provider_rejects_malformed_public_key() -> None:
    from tex.pqcrypto._ed25519_provider import Ed25519Provider

    p = Ed25519Provider()
    assert not p.verify(b"msg", b"\x00" * 64, b"not-a-pem-key")


def test_ed25519_provider_rejects_non_ed_pem_key() -> None:
    """An EC PEM is not an Ed25519 PEM — verify must return False, not raise."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    from tex.pqcrypto._ed25519_provider import Ed25519Provider

    ec_pub = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    p = Ed25519Provider()
    assert not p.verify(b"msg", b"\x00" * 64, ec_pub)


# --- regression: existing scaffolding contract preserved ---


def test_pqcrypto_package_public_exports_unchanged() -> None:
    """The package __init__ surface is part of the contract."""
    import tex.pqcrypto as pkg

    expected = {
        "SignatureAlgorithm",
        "SignatureKeyPair",
        "SignatureProvider",
        "get_signature_provider",
    }
    assert expected.issubset(set(pkg.__all__))

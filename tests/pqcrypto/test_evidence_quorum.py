"""
Tests for tex.pqcrypto.evidence_quorum (Thread 10).

Covers the production glue between threshold ML-DSA and the evidence chain:
env-flag policy parsing, end-to-end sign/verify of evidence records,
serde of the embedded quorum signature payload, descriptor commitment
self-consistency, and tamper detection.
"""

from __future__ import annotations

import os

import pytest

from tex.pqcrypto.algorithm_agility import SignatureAlgorithm
from tex.pqcrypto.evidence_quorum import (
    EvidenceQuorumPolicy,
    deserialize_quorum_signature,
    quorum_sign_evidence_record,
    serialize_quorum_signature,
    verify_quorum_evidence_signature,
)
from tex.pqcrypto.quorum_ml_dsa import QuorumMlDsaProvider


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


_REALISTIC_FORBID_RECORD: dict[str, object] = {
    "event_id": "evt-2026-0520-forbid-001",
    "kind": "AGENT_BLOCKED_ACTION",
    "actor_entity_id": "agent:tex-sdr-01",
    "target_entity_id": "external:bank-api.acme.com",
    "verdict": "FORBID",
    "reason": "agent attempted unauthorized wire transfer",
    "severity": "critical",
    "sequence_number": 1042,
    "previous_ledger_hash": "0" * 64,
    "payload_sha256": "f" * 64,
    "record_hash": "a" * 64,
    "timestamp": "2026-05-20T17:00:00+00:00",
}


# --- Policy parsing ---------------------------------------------------------


def test_policy_disabled_when_no_env_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("TEX_EVIDENCE_QUORUM_K", raising=False)
    monkeypatch.delenv("TEX_EVIDENCE_QUORUM_N", raising=False)
    p = EvidenceQuorumPolicy.from_env()
    assert p.enabled is False
    assert p.k == 0
    assert p.n == 0


def test_policy_enabled_when_k_set(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TEX_EVIDENCE_QUORUM_K", "3")
    monkeypatch.delenv("TEX_EVIDENCE_QUORUM_N", raising=False)
    p = EvidenceQuorumPolicy.from_env()
    assert p.enabled is True
    assert p.k == 3
    # Default n: max(k+2, 5) = max(5, 5) = 5
    assert p.n == 5


def test_policy_uses_explicit_n(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TEX_EVIDENCE_QUORUM_K", "3")
    monkeypatch.setenv("TEX_EVIDENCE_QUORUM_N", "7")
    p = EvidenceQuorumPolicy.from_env()
    assert p.enabled is True
    assert p.k == 3
    assert p.n == 7


def test_policy_disabled_for_invalid_k(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TEX_EVIDENCE_QUORUM_K", "not-a-number")
    p = EvidenceQuorumPolicy.from_env()
    assert p.enabled is False


def test_policy_disabled_for_zero_k(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TEX_EVIDENCE_QUORUM_K", "0")
    p = EvidenceQuorumPolicy.from_env()
    assert p.enabled is False


def test_policy_defaults_to_l5(monkeypatch: pytest.MonkeyPatch) -> None:
    """Quorum signing is always at NIST L5 (CNSA 2.0)."""
    monkeypatch.setenv("TEX_EVIDENCE_QUORUM_K", "2")
    p = EvidenceQuorumPolicy.from_env()
    assert p.algorithm is SignatureAlgorithm.QUORUM_ML_DSA_87


# --- End-to-end sign/verify -------------------------------------------------


@_requires_liboqs
def test_quorum_sign_and_verify_evidence_record() -> None:
    provider = QuorumMlDsaProvider(SignatureAlgorithm.QUORUM_ML_DSA_87)
    keyset = provider.distributed_keygen(n=5, k=3)
    qs = quorum_sign_evidence_record(_REALISTIC_FORBID_RECORD, keyset)
    assert len(qs.partials) == 3
    assert verify_quorum_evidence_signature(
        _REALISTIC_FORBID_RECORD, qs, keyset.descriptor,
    )


@_requires_liboqs
def test_quorum_sign_with_selected_members() -> None:
    """signing_member_indices selects which members participate."""
    provider = QuorumMlDsaProvider(SignatureAlgorithm.QUORUM_ML_DSA_87)
    keyset = provider.distributed_keygen(n=5, k=2)
    # Use members 2 and 4 instead of 0 and 1.
    qs = quorum_sign_evidence_record(
        _REALISTIC_FORBID_RECORD, keyset, signing_member_indices=[2, 4],
    )
    indices = {p.member_index for p in qs.partials}
    assert indices == {2, 4}
    assert verify_quorum_evidence_signature(
        _REALISTIC_FORBID_RECORD, qs, keyset.descriptor,
    )


@_requires_liboqs
def test_quorum_sign_rejects_insufficient_signing_members() -> None:
    provider = QuorumMlDsaProvider(SignatureAlgorithm.QUORUM_ML_DSA_87)
    keyset = provider.distributed_keygen(n=5, k=3)
    with pytest.raises(ValueError, match="need at least k=3"):
        quorum_sign_evidence_record(
            _REALISTIC_FORBID_RECORD, keyset, signing_member_indices=[0, 1],
        )


@_requires_liboqs
def test_quorum_verify_rejects_tampered_record() -> None:
    provider = QuorumMlDsaProvider(SignatureAlgorithm.QUORUM_ML_DSA_87)
    keyset = provider.distributed_keygen(n=4, k=2)
    qs = quorum_sign_evidence_record(_REALISTIC_FORBID_RECORD, keyset)
    tampered = dict(_REALISTIC_FORBID_RECORD)
    tampered["verdict"] = "PERMIT"  # flip the verdict
    assert not verify_quorum_evidence_signature(tampered, qs, keyset.descriptor)


# --- Serde of the embedded payload ------------------------------------------


@_requires_liboqs
def test_quorum_signature_serde_round_trip() -> None:
    provider = QuorumMlDsaProvider(SignatureAlgorithm.QUORUM_ML_DSA_87)
    keyset = provider.distributed_keygen(
        n=4, k=2,
        member_ids=["a", "b", "c", "d"],
    )
    qs = quorum_sign_evidence_record(_REALISTIC_FORBID_RECORD, keyset)
    payload = serialize_quorum_signature(qs, keyset.descriptor)
    # Round-trips through JSON-compatible dict.
    qs2, desc2 = deserialize_quorum_signature(payload)
    assert qs2.descriptor_commitment == qs.descriptor_commitment
    assert desc2.commitment == keyset.descriptor.commitment
    assert verify_quorum_evidence_signature(_REALISTIC_FORBID_RECORD, qs2, desc2)


@_requires_liboqs
def test_quorum_signature_deserialize_rejects_inconsistent_descriptor() -> None:
    """
    If the serialized descriptor's stored commitment does not match its
    re-computed commitment, the deserializer raises rather than returning
    a verifiable-looking object.
    """
    provider = QuorumMlDsaProvider(SignatureAlgorithm.QUORUM_ML_DSA_87)
    keyset = provider.distributed_keygen(n=3, k=2)
    qs = quorum_sign_evidence_record(_REALISTIC_FORBID_RECORD, keyset)
    payload = serialize_quorum_signature(qs, keyset.descriptor)
    # Tamper with the stored commitment.
    payload["descriptor"]["commitment"] = "deadbeef" * 8
    with pytest.raises(ValueError, match="self-inconsistent"):
        deserialize_quorum_signature(payload)

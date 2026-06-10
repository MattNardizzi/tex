"""
The voice-attestation chain seals each spoken answer. These tests prove the two
distinct guarantees it makes — the hash CHAIN proves integrity/ordering, the
per-record SIGNATURE proves authorship — and that tamper is detected by both.
They also pin the canonicalisation byte-identical to the evidence seal, so an
auditor verifies a voice attestation with the same tooling, and pin the honest
label "ECDSA-P256, not post-quantum".
"""

from __future__ import annotations

import copy

from tex.evidence.seal import _stable_json as seal_stable_json
from tex.voice.attestation import VoiceAttestor, _stable_json as voice_stable_json


def _seal_three(attestor: VoiceAttestor) -> None:
    for i in range(3):
        attestor.seal(
            transcript=f"question {i}",
            routed_dimension="execution",
            verdict="PERMIT",
            answer=f"{i} actions were forbidden in the recent window.",
            object_=None,
            proof_ref={"kind": "decision", "id": f"d{i}", "sha256": None, "seq": None},
            gate={"scorer": "exact-match", "reason": "reconstruction-exact"},
            tenant="acme",
        )


def test_chain_and_signatures_verify() -> None:
    at = VoiceAttestor()
    _seal_three(at)
    assert len(at) == 3
    chain = at.verify_chain()
    assert chain["intact"] is True and chain["checked"] == 3
    sigs = at.verify_signatures()
    assert sigs["valid"] is True and sigs["checked"] == 3


def test_records_are_hash_chained() -> None:
    at = VoiceAttestor()
    _seal_three(at)
    recs = at.records()
    assert recs[0].previous_hash is None
    assert recs[1].previous_hash == recs[0].record_hash
    assert recs[2].previous_hash == recs[1].record_hash


def test_tamper_breaks_chain_and_signature() -> None:
    at = VoiceAttestor()
    _seal_three(at)
    # Mutate a sealed payload in place (simulating a tampered store).
    tampered = at.records()[1]
    tampered.payload["answer"] = "9 actions were forbidden in the recent window."

    chain = at.verify_chain()
    assert chain["intact"] is False
    assert chain["break_at"] == 1

    sigs = at.verify_signatures()
    assert sigs["valid"] is False
    assert sigs["invalid_at"] == 1


def test_signature_is_self_verifying_from_the_record_alone() -> None:
    from tex.evidence.seal import verify_payload_signature

    at = VoiceAttestor()
    _seal_three(at)
    payload = at.records()[0].payload
    # The embedded block carries the public key; verification needs nothing else.
    assert verify_payload_signature(payload) is True
    bad = copy.deepcopy(payload)
    bad["verdict"] = "FORBID"
    assert verify_payload_signature(bad) is False


def test_canonicalisation_is_byte_identical_to_evidence_seal() -> None:
    # The voice chain MUST canonicalise exactly like tex.evidence.seal so the
    # same auditor tooling verifies it. Guard against silent drift.
    for obj in (
        {"b": 1, "a": 2, "z": [3, 2, 1]},
        {"unicode": "café — ✓", "n": 0},
        {"nested": {"y": True, "x": None}},
    ):
        assert voice_stable_json(obj) == seal_stable_json(obj)


def test_algorithm_is_ecdsa_not_post_quantum() -> None:
    at = VoiceAttestor()
    # Honest label: the live signer is classical ECDSA-P256 unless an ML-DSA
    # backend is installed. We must never claim post-quantum when we are not.
    assert at.algorithm == "ecdsa-p256"
    assert at.is_post_quantum is False


def test_transcript_is_sealed_by_hash_not_stored_verbatim() -> None:
    at = VoiceAttestor()
    at.seal(
        transcript="my secret question",
        routed_dimension="evidence",
        verdict="PERMIT",
        answer="The evidence chain is intact across 4 sealed records.",
        object_=None,
        proof_ref=None,
        gate={"scorer": "exact-match"},
    )
    payload = at.records()[0].payload
    assert "my secret question" not in voice_stable_json(payload)
    assert len(payload["transcript_sha256"]) == 64

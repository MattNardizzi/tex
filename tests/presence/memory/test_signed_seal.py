"""The OPTIONAL cryptographic seal: OFF unless TEX_SEAL_DECISIONS=1, and when ON
the signature actually verifies. The content anchor is always present regardless;
the signature is metadata, NOT part of the anchor (so idempotency is preserved).

Note: on a host with an ML-DSA backend the algorithm is the post-quantum
composite; on a host without it the signer is honestly classical ecdsa-p256. The
record's algorithm field always names what actually produced the signature — we
assert membership, never assume post-quantum.
"""

from __future__ import annotations

import base64
import dataclasses

from tex.evidence.seal import build_evidence_chain_signer
from tex.presence.memory import SealedPresenceMemory

from .conftest import make_claim_verdict


def test_no_signature_when_sealing_disabled(tmp_path, monkeypatch):
    monkeypatch.delenv("TEX_SEAL_DECISIONS", raising=False)
    signer = build_evidence_chain_signer(key_dir=str(tmp_path / "keys"))
    mem = SealedPresenceMemory(mirror=None, signer=signer)

    claim, verdict = make_claim_verdict("forbid_count")
    ref = mem.seal(tenant="acme", claim=claim, verdict=verdict)
    rec = mem.get(tenant="acme", record_id=ref.record_id)

    # Signer injected but sealing OFF → content anchor only, no authorship proof.
    assert rec.pq_signature is None
    assert len(ref.record_hash) == 64
    assert mem.verify(rec) is True  # anchor still verifies


def test_signature_present_and_verifies_when_enabled(tmp_path, monkeypatch):
    signer = build_evidence_chain_signer(key_dir=str(tmp_path / "keys"))
    mem = SealedPresenceMemory(mirror=None, signer=signer)
    claim, verdict = make_claim_verdict("forbid_count")

    # Seal with sealing OFF first → unsigned, content-addressed id.
    monkeypatch.delenv("TEX_SEAL_DECISIONS", raising=False)
    ref_unsigned = mem.seal(tenant="acme", claim=claim, verdict=verdict)
    assert mem.get(tenant="acme", record_id=ref_unsigned.record_id).pq_signature is None

    # Re-seal the identical fact with sealing ON.
    monkeypatch.setenv("TEX_SEAL_DECISIONS", "1")
    ref_signed = mem.seal(tenant="acme", claim=claim, verdict=verdict)
    rec = mem.get(tenant="acme", record_id=ref_signed.record_id)

    assert rec.pq_signature is not None
    assert rec.pq_signature["algorithm"] in ("composite-ml-dsa-65-ed25519", "ecdsa-p256")
    # The signature really verifies against the sealed content (not a stand-in).
    assert mem.verify(rec) is True

    # The signature is NOT part of the content anchor: same fact → same record_id
    # and same 64-hex anchor, signed or not.
    assert ref_signed.record_id == ref_unsigned.record_id
    assert ref_signed.record_hash == ref_unsigned.record_hash


def test_corrupted_signature_is_rejected(tmp_path, monkeypatch):
    # The negative case: verify()'s signature branch is REAL crypto, not a stand-in
    # — a tampered signature must fail. (Guards against verify() degrading to a
    # `return True` stub; the nanozk lesson — a name must deliver its property.)
    monkeypatch.setenv("TEX_SEAL_DECISIONS", "1")
    signer = build_evidence_chain_signer(key_dir=str(tmp_path / "keys"))
    mem = SealedPresenceMemory(mirror=None, signer=signer)
    claim, verdict = make_claim_verdict("forbid_count")
    ref = mem.seal(tenant="acme", claim=claim, verdict=verdict)
    rec = mem.get(tenant="acme", record_id=ref.record_id)
    assert rec.pq_signature is not None
    assert mem.verify(rec) is True

    # Flip one signature byte → verify must return False.
    bad_block = dict(rec.pq_signature)
    raw = base64.b64decode(bad_block["signature_b64"])
    flipped = bytes([raw[0] ^ 0xFF]) + raw[1:]
    bad_block["signature_b64"] = base64.b64encode(flipped).decode("ascii")
    tampered = dataclasses.replace(rec, pq_signature=bad_block)
    assert mem.verify(tampered) is False

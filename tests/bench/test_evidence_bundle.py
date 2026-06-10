"""
Tests for the offline evidence bundle verifier (tex.bench.evidence_bundle).

The load-bearing test is ``test_resign_forgery_caught_only_by_pin`` — the
adversary attack the design review surfaced: integrity alone (a self-verifying
signature + a recomputed chain) does NOT prove Tex authored a record, because an
attacker can re-sign a forged payload with their own key. Only pinning Tex's
public key catches it. Every assertion here is written so it FAILS if the
verifier is weakened (a tamper that slips through is the failure mode).
"""

from __future__ import annotations

import tempfile

from tex.adversarial.adaptive import AttackSeed, ScoreResult, run_adaptive_campaign
from tex.adversarial.seal import read_summary, seal_campaign
from tex.bench.evidence_bundle import (
    forge_record_by_resigning,
    read_bundle,
    trusted_public_key_b64,
    verify_bundle,
    write_bundle,
)
from tex.domain.verdict import Verdict
from tex.evidence.seal import build_evidence_chain_signer


def _sealed():
    """A small sealed campaign + its trusted signer (fake scorer; no runtime)."""

    def scorer(content: str, metadata=None) -> ScoreResult:
        if metadata and metadata.get("structural"):
            return ScoreResult(Verdict.FORBID, 0.95)
        if "base64" in content.lower():
            return ScoreResult(Verdict.PERMIT, 0.1)
        return ScoreResult(Verdict.FORBID, 0.9)

    seeds = (
        AttackSeed("lex1", "drop table users now", defense_class="lexical"),
        AttackSeed("s1", "x", metadata={"structural": True}, defense_class="structural"),
    )
    report = run_adaptive_campaign(seeds, scorer, query_budget=40)
    signer = build_evidence_chain_signer(key_dir=tempfile.mkdtemp())
    records = seal_campaign(report, signer=signer)
    return records, signer


# ── clean path ────────────────────────────────────────────────────────────


def test_clean_bundle_valid_when_pinned() -> None:
    records, signer = _sealed()
    pin = trusted_public_key_b64(signer)
    v = verify_bundle(records, pinned_public_key_b64=pin)
    assert v.valid
    assert v.integrity_ok
    assert v.chain_intact
    assert v.signatures_self_verify
    assert v.authorship_ok is True
    # The seal is the live classical signer today — assert it is labelled honestly.
    assert set(v.signature_algorithms) == {"ecdsa-p256"}


def test_unpinned_is_integrity_only_not_court_grade() -> None:
    records, _ = _sealed()
    v = verify_bundle(records)  # no pin
    assert v.integrity_ok          # internally consistent
    assert v.authorship_pinned is False
    assert v.authorship_ok is None  # authorship UNVERIFIED without the pin
    assert v.valid is False         # court-grade verdict refuses without a pin


def test_write_read_roundtrip_preserves_verification(tmp_path) -> None:
    records, signer = _sealed()
    path = tmp_path / "campaign.bundle.jsonl"
    write_bundle(records, path)
    back = read_bundle(path)
    assert len(back) == len(records)
    pin = trusted_public_key_b64(signer)
    assert verify_bundle(path, pinned_public_key_b64=pin).valid
    summary = read_summary(back)
    assert summary is not None
    assert 0.0 <= summary.adaptive_asr <= 1.0


# ── integrity tampers (caught without a pin) ───────────────────────────────


def test_byteflip_breaks_integrity() -> None:
    records, signer = _sealed()
    pin = trusted_public_key_b64(signer)
    target = records[0]
    edited = target.payload_json.replace("lex1", "LEXX", 1)
    assert edited != target.payload_json
    bad = target.model_copy(update={"payload_json": edited})
    v = verify_bundle((bad,) + records[1:], pinned_public_key_b64=pin)
    assert not v.chain_intact
    assert "payload_sha256_mismatch" in v.chain_issue_codes
    assert not v.valid


def test_forged_record_hash_caught_proving_independent_recompute() -> None:
    # Forge ONLY the stored record_hash (leave payload untouched). A verifier that
    # trusted the stored hash would miss this; ours recomputes and catches it.
    records, signer = _sealed()
    pin = trusted_public_key_b64(signer)
    forged = records[0].model_copy(update={"record_hash": "a" * 64})
    v = verify_bundle((forged,) + records[1:], pinned_public_key_b64=pin)
    assert "record_hash_mismatch" in v.chain_issue_codes
    assert not v.valid


def test_deleted_record_breaks_chain_link() -> None:
    records, signer = _sealed()
    pin = trusted_public_key_b64(signer)
    # Drop the first record; the (now-first) record points back to a predecessor
    # that is no longer present.
    v = verify_bundle(records[1:], pinned_public_key_b64=pin)
    assert not v.valid
    assert "unexpected_previous_hash" in v.chain_issue_codes


# ── the authorship attack (caught ONLY by the pin) ─────────────────────────


def test_resign_forgery_caught_only_by_pin() -> None:
    records, signer = _sealed()
    pin = trusted_public_key_b64(signer)

    # Adversary forges the summary (rewrites the ASR to a flattering 0%) and
    # re-signs with their OWN fresh key, rebuilding the hashes so the chain stays
    # internally consistent.
    adversary = build_evidence_chain_signer(key_dir=tempfile.mkdtemp())
    forged_summary = forge_record_by_resigning(
        records[-1],
        mutate=lambda p: {**p, "adaptive_asr": 0.0, "structural_asr": 0.0},
        adversary_signer=adversary,
    )
    forged_bundle = records[:-1] + (forged_summary,)

    # Integrity check is fooled — the forgery is internally consistent.
    unpinned = verify_bundle(forged_bundle)
    assert unpinned.integrity_ok is True
    assert unpinned.signatures_self_verify is True
    # ...but the court-grade verdict still refuses, because authorship is unproven.
    assert unpinned.valid is False

    # With Tex's key pinned, the foreign signature is rejected outright.
    pinned = verify_bundle(forged_bundle, pinned_public_key_b64=pin)
    assert pinned.authorship_ok is False
    assert pinned.valid is False
    assert pinned.per_record_signatures[-1].key_is_pinned is False

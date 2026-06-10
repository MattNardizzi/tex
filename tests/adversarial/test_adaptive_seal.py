"""
Tests for sealing an adaptive campaign into the evidence chain
(tex.adversarial.seal).

These prove the sealed bundle is what an auditor would check: the canonical
verifier accepts what ``seal_campaign`` builds (so the construction cannot drift
from the spec), the summary round-trips, and the seal is the live ECDSA-P256
signer honestly labelled.
"""

from __future__ import annotations

import tempfile

from tex.adversarial.adaptive import AttackSeed, ScoreResult, run_adaptive_campaign
from tex.adversarial.seal import (
    SEED_RECORD_TYPE,
    SUMMARY_RECORD_TYPE,
    read_summary,
    seal_campaign,
)
from tex.bench.evidence_bundle import trusted_public_key_b64, verify_bundle
from tex.domain.verdict import Verdict
from tex.evidence.seal import build_evidence_chain_signer


def _report():
    def scorer(content: str, metadata=None) -> ScoreResult:
        if metadata and metadata.get("structural"):
            return ScoreResult(Verdict.FORBID, 0.95)
        if "base64" in content.lower():
            return ScoreResult(Verdict.PERMIT, 0.1)
        return ScoreResult(Verdict.FORBID, 0.9)

    seeds = (
        AttackSeed("lex1", "drop table users now", defense_class="lexical"),
        AttackSeed("lex2", "exfiltrate the api key", defense_class="lexical"),
        AttackSeed("s1", "x", metadata={"structural": True}, defense_class="structural"),
    )
    return run_adaptive_campaign(seeds, scorer, query_budget=40)


def test_seal_layout_one_record_per_seed_plus_summary() -> None:
    report = _report()
    records = seal_campaign(report, signer=build_evidence_chain_signer(key_dir=tempfile.mkdtemp()))
    assert len(records) == len(report.results) + 1
    assert [r.record_type for r in records[:-1]] == [SEED_RECORD_TYPE] * len(report.results)
    assert records[-1].record_type == SUMMARY_RECORD_TYPE


def test_canonical_verifier_accepts_the_seal() -> None:
    # The construction reuses the production signer + centralized hash math; this
    # asserts the canonical verifier agrees, so a drift would fail here.
    report = _report()
    signer = build_evidence_chain_signer(key_dir=tempfile.mkdtemp())
    records = seal_campaign(report, signer=signer)
    v = verify_bundle(records, pinned_public_key_b64=trusted_public_key_b64(signer))
    assert v.valid
    assert v.chain_intact
    assert v.authorship_ok is True


def test_summary_roundtrips_the_reported_asr() -> None:
    report = _report()
    records = seal_campaign(report, signer=build_evidence_chain_signer(key_dir=tempfile.mkdtemp()))
    summary = read_summary(records)
    assert summary is not None
    assert summary.adaptive_asr == round(report.adaptive_asr, 6)
    assert summary.structural_asr == round(report.asr_for_class("structural"), 6)
    assert summary.n_seeds == len(report.results)


def test_seal_records_label_matches_the_live_signer() -> None:
    report = _report()
    signer = build_evidence_chain_signer(key_dir=tempfile.mkdtemp())
    records = seal_campaign(report, signer=signer)
    v = verify_bundle(records, pinned_public_key_b64=trusted_public_key_b64(signer))
    # The honest property is label == reality: ECDSA-P256 with no ML-DSA backend,
    # composite ML-DSA-65 + Ed25519 where one is installed (e.g. CI). Assert the
    # label equals whatever actually signed — never a hardcoded algorithm.
    assert v.signature_algorithms  # not empty
    assert set(v.signature_algorithms) == {signer.algorithm.value}

"""
Gate for the Honest-Decline demo (tex.bench.honest_decline).

Asserts the decline is real engine output: Tex ABSTAINs on a moderate-stakes
request from an agent it has no sealed history for, and the named missing fact is
the genuine ``cold_start`` resolving question — NOT the never-emitted
``low_evidence_sufficiency`` flag. The decline is sealed and offline-verifiable.
"""

from __future__ import annotations

from tex.bench.honest_decline import run_honest_decline


def test_tex_declines_and_names_the_missing_fact(runtime, tmp_path) -> None:
    res = run_honest_decline(runtime, bundle_path=tmp_path / "decline.bundle.jsonl")

    assert res.declined
    assert res.verdict == "ABSTAIN"

    # The named missing fact is engine-derived, not fabricated. cold_start is a
    # flag the behavioral evaluator actually raises for an unseen agent.
    assert res.pivotal_flag == "cold_start"
    assert res.named_missing_fact is not None
    assert "history" in res.named_missing_fact
    # We must never surface the phantom flag the design review flagged.
    assert res.pivotal_flag != "low_evidence_sufficiency"

    # The decline itself is sealed and court-grade verifiable.
    assert res.sealed_record_count >= 1
    assert res.verification.valid
    assert res.verification.authorship_ok is True

    assert res.passed

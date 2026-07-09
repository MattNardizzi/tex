"""
The evidence recorder's batch resolution lookup — ``resolved_decision_ids``.

This is the read behind the "still waiting on a human" answer: which of a set
of held decisions already carry a sealed human_resolution record, so the
waiting count/list can exclude them. It is a read-only, single-pass scan of the
JSONL chain (the source of truth), and it must:

  * return exactly the decision ids that carry >= 1 human_resolution record,
  * respect the candidate filter (only asked-about ids, empty ⇒ no scan),
  * ignore decision records and other record types entirely.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from uuid import uuid4

import pytest

from tex.domain.decision import Decision
from tex.domain.verdict import Verdict
from tex.evidence.recorder import EvidenceRecorder


@pytest.fixture()
def recorder(tmp_path: Path) -> EvidenceRecorder:
    return EvidenceRecorder(tmp_path / "evidence.jsonl")


def _held(seed: str) -> Decision:
    """A held (ABSTAIN) decision — the kind a human resolves."""
    content = f"held-{seed}"
    return Decision(
        decision_id=uuid4(),
        request_id=uuid4(),
        verdict=Verdict.ABSTAIN,
        confidence=0.5,
        final_score=0.5,
        action_type="wire_transfer",
        channel="api",
        environment="production",
        content_excerpt=content,
        content_sha256=hashlib.sha256(content.encode()).hexdigest(),
        policy_version="v1",
        uncertainty_flags=["low_confidence"],
    )


def test_resolved_ids_reports_only_the_sealed_holds(recorder: EvidenceRecorder) -> None:
    a, b, c = _held("a"), _held("b"), _held("c")
    for d in (a, b, c):
        recorder.record_decision(d)
    # Only a and c get a named human act.
    recorder.record_human_resolution(a, verdict="approved", resolved_by="ops@acme")
    recorder.record_human_resolution(c, verdict="refused", resolved_by="ops@acme")

    resolved = recorder.resolved_decision_ids()
    assert resolved == {str(a.decision_id), str(c.decision_id)}
    # b is still waiting — the whole point of the lookup.
    assert str(b.decision_id) not in resolved


def test_candidate_filter_scopes_the_answer(recorder: EvidenceRecorder) -> None:
    a, b = _held("a"), _held("b")
    for d in (a, b):
        recorder.record_decision(d)
    recorder.record_human_resolution(a, verdict="held", resolved_by="ops@acme")
    recorder.record_human_resolution(b, verdict="approved", resolved_by="ops@acme")

    # Ask about only a: b's resolution is out of scope even though it exists.
    scoped = recorder.resolved_decision_ids([str(a.decision_id)])
    assert scoped == {str(a.decision_id)}


def test_empty_candidate_list_short_circuits(recorder: EvidenceRecorder) -> None:
    a = _held("a")
    recorder.record_decision(a)
    recorder.record_human_resolution(a, verdict="approved", resolved_by="ops@acme")
    assert recorder.resolved_decision_ids([]) == set()


def test_decisions_without_resolutions_are_absent(recorder: EvidenceRecorder) -> None:
    a = _held("a")
    recorder.record_decision(a)  # recorded, never resolved
    assert recorder.resolved_decision_ids() == set()
    # An "any human_verdict counts" contract: a re-hold ('held') still resolves
    # the queue entry (mirrors the seal route dropping it from the live sink).
    recorder.record_human_resolution(a, verdict="held", resolved_by="ops@acme")
    assert recorder.resolved_decision_ids() == {str(a.decision_id)}

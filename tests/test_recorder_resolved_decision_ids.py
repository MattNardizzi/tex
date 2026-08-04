"""
The evidence recorder's batch resolution lookup — ``resolved_decision_ids``.

This is the read behind the "still waiting on a human" answer: which of a set
of held decisions already carry a sealed human_resolution record, so the
waiting count/list can exclude them. It is a read-only, single-pass scan of the
JSONL chain (the source of truth), and it must:

  * return exactly the decision ids that carry >= 1 human_resolution record,
  * respect the candidate filter (only asked-about ids, empty ⇒ no scan),
  * ignore decision records and other record types entirely,
  * survive a deploy: the JSONL lives on local disk (gone on a Render
    deploy), so the index build seeds from the durable mirror's
    ``resolved_decision_ids`` when the mirror offers one — fail-open (an
    unreadable mirror over-surfaces resolved holds, never hides waiting ones).
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


class _DurableMirror:
    """Stands in for PostgresEvidenceMirror: captures every appended record
    and serves the resolved-ids read from what it captured — which is exactly
    what survives when the JSONL file does not."""

    def __init__(self) -> None:
        self.records: list = []

    def record(self, record) -> None:
        self.records.append(record)

    def resolved_decision_ids(self) -> set[str]:
        return {
            str(r.decision_id)
            for r in self.records
            if r.record_type == "human_resolution"
        }


class _WriteOnlyMirror:
    """A mirror without the resolved-ids read (the EvidenceMirror minimum)."""

    def record(self, record) -> None:
        pass


class _UnreadableMirror(_DurableMirror):
    """Durable mirror whose read path is down (Postgres unreachable)."""

    def resolved_decision_ids(self) -> set[str]:
        raise ConnectionError("postgres unreachable")


def test_seals_survive_a_deploy_via_the_durable_mirror(tmp_path: Path) -> None:
    """THE regression: deploy resets local disk; the mirror keeps the seal."""
    mirror = _DurableMirror()
    before = EvidenceRecorder(tmp_path / "before.jsonl", mirror=mirror)
    a = _held("a")
    before.record_decision(a)
    before.record_human_resolution(a, verdict="approved", resolved_by="ops@acme")

    # A deploy: fresh container disk (new, empty JSONL path), same Postgres.
    after = EvidenceRecorder(tmp_path / "after.jsonl", mirror=mirror)
    b = _held("b")
    after.record_decision(b)  # new hold on the new chain, never resolved

    resolved = after.resolved_decision_ids()
    assert str(a.decision_id) in resolved  # the pre-deploy seal still counts
    assert str(b.decision_id) not in resolved  # b is genuinely waiting

    # Candidate scoping applies to durably-seeded ids exactly like local ones.
    assert after.resolved_decision_ids([str(a.decision_id), str(b.decision_id)]) == {
        str(a.decision_id)
    }


def test_durable_seed_unions_with_the_local_chain(tmp_path: Path) -> None:
    """A seal the mirror's best-effort write dropped still counts from the file."""
    mirror = _DurableMirror()
    other = _held("other")
    # Seed the mirror with a resolution the local chain has never seen
    # (recorded by the pre-deploy process).
    pre_deploy = EvidenceRecorder(tmp_path / "gone.jsonl", mirror=mirror)
    pre_deploy.record_human_resolution(other, verdict="refused", resolved_by="ops@acme")

    recorder = EvidenceRecorder(tmp_path / "evidence.jsonl", mirror=mirror)
    local = _held("local")
    recorder.record_decision(local)
    recorder.record_human_resolution(local, verdict="approved", resolved_by="ops@acme")

    assert recorder.resolved_decision_ids() == {
        str(other.decision_id),
        str(local.decision_id),
    }


def test_unreadable_mirror_fails_open_to_the_local_chain(tmp_path: Path) -> None:
    mirror = _UnreadableMirror()
    recorder = EvidenceRecorder(tmp_path / "evidence.jsonl", mirror=mirror)
    a, b = _held("a"), _held("b")
    for d in (a, b):
        recorder.record_decision(d)
    recorder.record_human_resolution(a, verdict="approved", resolved_by="ops@acme")

    # The read never raises and the local chain still answers: a is sealed,
    # b over-surfaces as waiting — never the other way around.
    assert recorder.resolved_decision_ids() == {str(a.decision_id)}


def test_write_only_mirror_leaves_behavior_unchanged(tmp_path: Path) -> None:
    recorder = EvidenceRecorder(tmp_path / "evidence.jsonl", mirror=_WriteOnlyMirror())
    a = _held("a")
    recorder.record_decision(a)
    assert recorder.resolved_decision_ids() == set()
    recorder.record_human_resolution(a, verdict="held", resolved_by="ops@acme")
    assert recorder.resolved_decision_ids() == {str(a.decision_id)}

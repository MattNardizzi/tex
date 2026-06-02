"""
End-to-end tests for the Tex memory system.

These tests run entirely in-memory (DATABASE_URL deliberately unset) so
the suite stays fast and hermetic. The Postgres write-through path is
exercised in a separate integration suite that's wired up in CI when a
test database is available; the in-memory branch is the production
fallback path and deserves first-class coverage in its own right.

Coverage targets:

  - MemorySystem ties every store together with the same tenant_id
  - record_decision writes to the cache, JSONL, and (would-be) postgres
    in the documented order; a failure in any step aborts cleanly.
  - Replay loads decision + input + policy and detects divergence.
  - Permits and verifications round-trip and the verification log is
    append-only.
  - Evidence chain stays valid across multiple decisions.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from tex.domain.decision import Decision
from tex.domain.policy import PolicySnapshot
from tex.domain.verdict import Verdict
from tex.evidence.chain import verify_evidence_chain
from tex.evidence.recorder import EvidenceRecorder
from tex.memory import (
    MemoryReplayEngine,
    MemorySystem,
    PermitNotFoundError,
    PermitStore,
    ReplayMissingArtifactError,
    VerificationResult,
    VerificationStore,
)
from tex.policies.defaults import build_default_policy


@pytest.fixture(autouse=True)
def _no_database_url(monkeypatch: pytest.MonkeyPatch) -> None:
    """Force in-memory fallback for every test in this module."""
    monkeypatch.delenv("DATABASE_URL", raising=False)


@pytest.fixture
def evidence_path(tmp_path: Path) -> Path:
    return tmp_path / "evidence.jsonl"


def _decision(
    *,
    request_id: UUID | None = None,
    verdict: Verdict = Verdict.PERMIT,
    final_score: float = 0.1,
    confidence: float = 0.95,
    policy_version: str = "default-v1",
    fingerprint: str | None = None,
) -> Decision:
    return Decision(
        request_id=request_id or uuid4(),
        verdict=verdict,
        confidence=confidence,
        final_score=final_score,
        action_type="sales_email",
        channel="email",
        environment="production",
        recipient="alice@example.com",
        content_excerpt="hi alice",
        content_sha256="b" * 64,
        policy_version=policy_version,
        scores={"semantic": final_score},
        reasons=[] if verdict is not Verdict.FORBID else ["risk"],
        uncertainty_flags=[] if verdict is not Verdict.ABSTAIN else ["uncertain"],
        determinism_fingerprint=fingerprint or ("a" * 64),
    )


# ── construction + health ──────────────────────────────────────────────────


def test_memory_system_runs_in_memory_when_database_url_missing(
    evidence_path: Path,
) -> None:
    memory = MemorySystem(tenant_id="t1", evidence_path=evidence_path)

    health = memory.health()
    assert health.durable is False
    assert health.decisions_durable is False
    assert health.policies_durable is False
    assert health.permits_durable is False
    assert health.verifications_durable is False
    assert health.evidence_mirror_durable is False
    assert health.evidence_chain_path == str(evidence_path)


def test_memory_system_exposes_every_store(evidence_path: Path) -> None:
    memory = MemorySystem(tenant_id="t1", evidence_path=evidence_path)

    # Every aggregate the locked spec lists has a store on the orchestrator.
    assert memory.decisions is not None
    assert memory.inputs is not None
    assert memory.policies is not None
    assert memory.permits is not None
    assert memory.verifications is not None
    assert memory.evidence_mirror is not None
    assert isinstance(memory.recorder, EvidenceRecorder)


# ── write-through: decisions ───────────────────────────────────────────────


def test_record_decision_writes_to_cache_and_evidence(
    evidence_path: Path,
) -> None:
    memory = MemorySystem(evidence_path=evidence_path)
    decision = _decision()
    request_payload = {
        "content": "hi alice",
        "action_type": "sales_email",
        "channel": "email",
    }

    evidence = memory.record_decision(
        decision=decision,
        full_input=request_payload,
    )

    # Decision is in the cache, looked up by both id and request_id.
    assert memory.decisions.get(decision.decision_id) == decision
    assert (
        memory.decisions.get_by_request_id(decision.request_id)
        == decision
    )

    # The original input is recoverable for replay.
    stored_input = memory.inputs.get(decision.request_id)
    assert stored_input is not None
    assert stored_input.full_input == request_payload
    assert stored_input.decision_id == decision.decision_id

    # Evidence chain has exactly one valid record.
    records = memory.recorder.read_all()
    assert len(records) == 1
    assert verify_evidence_chain(records).is_valid is True
    assert evidence.record_hash == records[0].record_hash


def test_record_decision_chains_multiple_writes(evidence_path: Path) -> None:
    memory = MemorySystem(evidence_path=evidence_path)

    for i in range(5):
        decision = _decision(
            fingerprint=hex(i)[2:].rjust(64, "0"),
        )
        memory.record_decision(
            decision=decision,
            full_input={"content": f"msg {i}"},
        )

    records = memory.recorder.read_all()
    assert len(records) == 5

    verification = verify_evidence_chain(records)
    assert verification.is_valid, verification.issues


def test_record_decision_links_input_and_decision_by_id(
    evidence_path: Path,
) -> None:
    memory = MemorySystem(evidence_path=evidence_path)
    decision = _decision()

    memory.record_decision(
        decision=decision,
        full_input={"content": "hi"},
    )

    stored_input = memory.inputs.get(decision.request_id)
    assert stored_input is not None

    # Spec § 8: everything linked by IDs, no orphans.
    assert stored_input.decision_id == decision.decision_id


# ── policy snapshots ───────────────────────────────────────────────────────


def test_policy_snapshot_round_trip(evidence_path: Path) -> None:
    memory = MemorySystem(evidence_path=evidence_path)
    policy = build_default_policy()

    memory.record_policy_snapshot(policy)

    fetched = memory.policies.get(policy.version)
    assert fetched is not None
    assert fetched.version == policy.version
    assert fetched.policy_id == policy.policy_id


# ── permits + verifications ────────────────────────────────────────────────


def test_permit_issue_and_verify(evidence_path: Path) -> None:
    memory = MemorySystem(evidence_path=evidence_path)
    decision_id = uuid4()
    expiry = datetime.now(UTC) + timedelta(minutes=10)

    permit = memory.issue_permit(
        decision_id=decision_id,
        nonce="nonce-xyz",
        signature="sig-abc",
        expiry=expiry,
        metadata={"channel": "email"},
    )

    assert permit.is_active is True
    assert permit.consumed_at is None

    fetched = memory.permits.get(permit.permit_id)
    assert fetched == permit
    assert memory.permits.get_by_nonce("nonce-xyz") == permit

    verification = memory.verify_permit(
        permit_id=permit.permit_id,
        consumed_nonce="nonce-xyz",
        result=VerificationResult.VALID,
    )
    assert verification.result is VerificationResult.VALID

    log = memory.verifications.list_for_permit(permit.permit_id)
    assert len(log) == 1
    assert log[0].verification_id == verification.verification_id


def test_permit_consume_is_idempotent(evidence_path: Path) -> None:
    memory = MemorySystem(evidence_path=evidence_path)
    permit = memory.issue_permit(
        decision_id=uuid4(),
        nonce="n1",
        signature="s1",
        expiry=datetime.now(UTC) + timedelta(minutes=1),
    )

    first = memory.permits.consume(permit.permit_id)
    assert first.consumed_at is not None

    second = memory.permits.consume(permit.permit_id)
    assert second.consumed_at == first.consumed_at  # not overwritten


def test_consume_unknown_permit_raises(evidence_path: Path) -> None:
    memory = MemorySystem(evidence_path=evidence_path)
    with pytest.raises(PermitNotFoundError):
        memory.permits.consume(uuid4())


def test_verification_log_is_append_only(evidence_path: Path) -> None:
    memory = MemorySystem(evidence_path=evidence_path)
    permit = memory.issue_permit(
        decision_id=uuid4(),
        nonce="rep",
        signature="sig",
        expiry=datetime.now(UTC) + timedelta(minutes=10),
    )

    # First attempt: valid. Second: reuse. Third: also reuse.
    memory.verify_permit(
        permit_id=permit.permit_id,
        consumed_nonce="rep",
        result=VerificationResult.VALID,
    )
    memory.verify_permit(
        permit_id=permit.permit_id,
        consumed_nonce="rep",
        result=VerificationResult.REUSED,
        reason="already consumed once",
    )
    memory.verify_permit(
        permit_id=permit.permit_id,
        consumed_nonce="rep",
        result=VerificationResult.REUSED,
    )

    log = memory.verifications.list_for_permit(permit.permit_id)
    assert len(log) == 3
    assert [v.result for v in log] == [
        VerificationResult.VALID,
        VerificationResult.REUSED,
        VerificationResult.REUSED,
    ]


# ── replay ─────────────────────────────────────────────────────────────────


def test_replay_clean_when_evaluator_returns_same_decision(
    evidence_path: Path,
) -> None:
    memory = MemorySystem(evidence_path=evidence_path)
    policy = build_default_policy()
    memory.record_policy_snapshot(policy)

    decision = _decision(policy_version=policy.version)
    memory.record_decision(
        decision=decision,
        full_input={"content": "hi"},
    )

    def evaluator(*, request: dict, policy: PolicySnapshot) -> Decision:
        # Pretend the evaluator deterministically reproduces the decision.
        return decision

    engine = MemoryReplayEngine(
        decisions=memory.decisions,
        inputs=memory.inputs,
        policies=memory.policies,
        evaluator=evaluator,
    )

    result = engine.replay(decision.decision_id)
    assert result.is_clean
    assert result.fingerprint_matched
    assert result.verdict_matched
    assert result.divergences == ()


def test_replay_detects_verdict_divergence(evidence_path: Path) -> None:
    memory = MemorySystem(evidence_path=evidence_path)
    policy = build_default_policy()
    memory.record_policy_snapshot(policy)

    original = _decision(
        policy_version=policy.version,
        verdict=Verdict.PERMIT,
    )
    memory.record_decision(
        decision=original,
        full_input={"content": "hi"},
    )

    diverged = _decision(
        request_id=original.request_id,
        policy_version=policy.version,
        verdict=Verdict.FORBID,
        final_score=0.92,
        fingerprint="f" * 64,
    )

    def evaluator(*, request: dict, policy: PolicySnapshot) -> Decision:
        return diverged

    engine = MemoryReplayEngine(
        decisions=memory.decisions,
        inputs=memory.inputs,
        policies=memory.policies,
        evaluator=evaluator,
    )

    result = engine.replay(original.decision_id)
    assert not result.is_clean
    assert result.fingerprint_matched is False
    assert result.verdict_matched is False
    assert result.original_verdict is Verdict.PERMIT
    assert result.replayed_verdict is Verdict.FORBID
    fields = {d.field for d in result.divergences}
    assert "verdict" in fields
    assert "determinism_fingerprint" in fields


def test_replay_raises_when_input_missing(evidence_path: Path) -> None:
    memory = MemorySystem(evidence_path=evidence_path)
    policy = build_default_policy()
    memory.record_policy_snapshot(policy)

    decision = _decision(policy_version=policy.version)
    memory.decisions.save(decision)  # decision saved, but no input recorded

    engine = MemoryReplayEngine(
        decisions=memory.decisions,
        inputs=memory.inputs,
        policies=memory.policies,
        evaluator=lambda *, request, policy: decision,
    )

    with pytest.raises(ReplayMissingArtifactError):
        engine.replay(decision.decision_id)


def test_replay_raises_when_policy_missing(evidence_path: Path) -> None:
    memory = MemorySystem(evidence_path=evidence_path)
    decision = _decision(policy_version="never-seen-version")
    memory.record_decision(
        decision=decision,
        full_input={"content": "hi"},
    )

    engine = MemoryReplayEngine(
        decisions=memory.decisions,
        inputs=memory.inputs,
        policies=memory.policies,
        evaluator=lambda *, request, policy: decision,
    )

    with pytest.raises(ReplayMissingArtifactError):
        engine.replay(decision.decision_id)


# ── input fingerprinting ───────────────────────────────────────────────────


def test_decision_input_store_hashes_inputs_stably(evidence_path: Path) -> None:
    memory = MemorySystem(evidence_path=evidence_path)
    request_id = uuid4()

    a = memory.inputs.save(
        request_id=request_id,
        full_input={"a": 1, "b": 2},
    )
    # Re-saving the same content with a different key order produces the
    # same hash. This matters for replay equality checks.
    b = memory.inputs.save(
        request_id=request_id,
        full_input={"b": 2, "a": 1},
    )
    assert a.input_sha256 == b.input_sha256


# ── V18 atomic write path: record_decision_with_policy ────────────────────


def test_record_decision_with_policy_writes_all_three_artifacts(
    evidence_path: Path,
) -> None:
    """
    Spec § "transactional guarantee" — fixed.

    One ``record_decision_with_policy`` call writes:
      1. the decision
      2. the full input (linked by request_id and decision_id)
      3. the policy snapshot under decision.policy_version
      4. the JSONL evidence chain
    """
    memory = MemorySystem(evidence_path=evidence_path)
    policy = build_default_policy()
    decision = _decision(policy_version=policy.version)
    full_input = {"content": "hello", "channel": "email"}

    evidence = memory.record_decision_with_policy(
        decision=decision,
        full_input=full_input,
        policy=policy,
    )

    # 1. decision
    assert memory.decisions.get(decision.decision_id) == decision
    # 2. input, linked back to the decision id
    stored_input = memory.inputs.get(decision.request_id)
    assert stored_input is not None
    assert stored_input.decision_id == decision.decision_id
    assert stored_input.full_input == full_input
    # 3. policy snapshot
    assert memory.policies.get(policy.version) == policy
    # 4. evidence chain has exactly one entry whose hash matches
    records = memory.recorder.read_all()
    assert len(records) == 1
    assert records[0].record_hash == evidence.record_hash


def test_record_decision_with_policy_rejects_non_dict_input(
    evidence_path: Path,
) -> None:
    """spec § 'Decision input not guaranteed': schema validation up-front."""
    memory = MemorySystem(evidence_path=evidence_path)
    policy = build_default_policy()
    decision = _decision(policy_version=policy.version)

    with pytest.raises(TypeError):
        memory.record_decision_with_policy(
            decision=decision,
            full_input="not a dict",  # type: ignore[arg-type]
            policy=policy,
        )

    # Nothing should have been written to any layer.
    assert memory.decisions.get(decision.decision_id) is None
    assert memory.inputs.get(decision.request_id) is None
    assert memory.policies.get(policy.version) is None
    assert memory.recorder.read_all() == ()


def test_link_permit_to_decision_carries_decision_id(
    evidence_path: Path,
) -> None:
    """
    spec § "Permit + verify not fully linked" — fixed.

    ``link_permit_to_decision`` enforces the spec invariant at the
    type level: a permit cannot be issued without a Decision in hand.
    """
    memory = MemorySystem(evidence_path=evidence_path)
    decision = _decision()

    expiry = datetime.now(UTC) + timedelta(minutes=5)
    permit = memory.link_permit_to_decision(
        decision=decision,
        nonce="abc123",
        signature="sig",
        expiry=expiry,
    )

    assert permit.decision_id == decision.decision_id
    fetched = memory.permits.get(permit.permit_id)
    assert fetched is not None
    assert fetched.decision_id == decision.decision_id


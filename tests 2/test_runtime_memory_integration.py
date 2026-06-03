"""
Runtime ↔ MemorySystem integration tests.

These tests exercise the full V18 production write path:

  build_runtime() → EvaluateActionCommand.execute() → MemorySystem
  → tex_decisions + tex_decision_inputs + tex_policy_snapshots
  → JSONL evidence chain → tex_evidence_records mirror

They run entirely in-memory (DATABASE_URL deliberately unset) so the
suite stays hermetic. The Postgres write-through path is exercised by
its own integration suite when a test database is available.

Coverage targets — one per locked-spec invariant:

  1. Runtime is wired into MemorySystem (spec § "Runtime not using
     memory system" → fixed).
  2. EvaluateActionCommand routes through MemorySystem (spec §
     "Evaluation path bypasses memory system" → fixed).
  3. Decision input is mandatory (spec § "Decision input not
     guaranteed" → fixed).
  4. Policy snapshot is recorded with every decision (spec § "Policy
     snapshot not strictly enforced" → fixed).
  5. Evidence is unified (spec § "Evidence system is split" → fixed).
  6. Replay can round-trip every runtime decision (spec § "Replay
     engine not fully guaranteed" → fixed).
  7. Cache invalidation hooks exist (spec § "Cache invalidation
     strategy missing" → fixed).
"""

from __future__ import annotations

import os
from pathlib import Path
from uuid import uuid4

import pytest

from tex.domain.evaluation import EvaluationRequest
from tex.domain.policy import PolicySnapshot
from tex.evidence.chain import verify_evidence_chain
from tex.memory import MemoryReplayEngine, MemorySystem


@pytest.fixture(autouse=True)
def _force_in_memory(monkeypatch: pytest.MonkeyPatch) -> None:
    """Force in-memory fallback for every test in this module."""
    monkeypatch.delenv("DATABASE_URL", raising=False)


def _request(*, action_type: str = "sales_email") -> EvaluationRequest:
    return EvaluationRequest(
        request_id=uuid4(),
        action_type=action_type,
        channel="email",
        environment="production",
        recipient="alice@example.com",
        content="Hi Alice, just confirming our meeting on Tuesday at 2pm.",
        metadata={"source": "test"},
    )


# ── 1. runtime exposes memory ─────────────────────────────────────────────


def test_runtime_exposes_memory_system(runtime) -> None:
    """spec § 'Runtime not using memory system' — fixed."""
    assert runtime.memory is not None
    assert isinstance(runtime.memory, MemorySystem)


def test_runtime_decision_store_is_memory_decisions_store(runtime) -> None:
    """
    The runtime's ``decision_store`` IS the memory system's decisions
    store. Two parallel stores would write the same rows twice; this
    asserts there's only one.
    """
    assert runtime.decision_store is runtime.memory.decisions


def test_runtime_policy_store_is_memory_policies_store(runtime) -> None:
    assert runtime.policy_store is runtime.memory.policies


def test_runtime_evidence_recorder_is_memory_recorder(runtime) -> None:
    assert runtime.evidence_recorder is runtime.memory.recorder


# ── 2. eval routes through memory ─────────────────────────────────────────


def test_evaluate_command_writes_through_memory_system(runtime) -> None:
    """
    spec § 'Evaluation path bypasses memory system' — fixed.

    Every PDP evaluation produces a row in tex_decisions AND a row in
    tex_decision_inputs (durably linked by request_id) AND a policy
    snapshot in tex_policy_snapshots.
    """
    request = _request()

    result = runtime.evaluate_action_command.execute(request)

    decision = result.decision

    # 2a. Decision is durably stored.
    stored_decision = runtime.memory.decisions.get(decision.decision_id)
    assert stored_decision is not None
    assert stored_decision.decision_id == decision.decision_id

    # 2b. Full input is durably stored, linked by request_id.
    stored_input = runtime.memory.inputs.get(decision.request_id)
    assert stored_input is not None
    assert stored_input.decision_id == decision.decision_id
    # The full request payload round-trips losslessly.
    assert stored_input.full_input["request_id"] == str(request.request_id)
    assert stored_input.full_input["action_type"] == request.action_type

    # 2c. Policy snapshot is durably stored under the version that
    # produced the decision.
    stored_policy = runtime.memory.policies.get(decision.policy_version)
    assert stored_policy is not None
    assert stored_policy.version == decision.policy_version


# ── 3. input is mandatory ─────────────────────────────────────────────────


def test_record_decision_with_policy_rejects_non_dict_input(runtime) -> None:
    """spec § 'Decision input not guaranteed' — fixed."""
    request = _request()
    result = runtime.evaluate_action_command.execute(request)
    policy = result.policy

    with pytest.raises(TypeError):
        runtime.memory.record_decision_with_policy(
            decision=result.decision,
            full_input="not a dict",  # type: ignore[arg-type]
            policy=policy,
        )


# ── 4. policy snapshot enforced ───────────────────────────────────────────


def test_every_evaluation_records_a_policy_snapshot(runtime) -> None:
    """
    spec § 'Policy snapshot not strictly enforced' — fixed.

    Even back-to-back evaluations under the same policy keep a
    snapshot row available for replay (idempotent upsert on
    policy_version).
    """
    for _ in range(3):
        result = runtime.evaluate_action_command.execute(_request())
        snapshot = runtime.memory.policies.get(result.decision.policy_version)
        assert snapshot is not None


# ── 5. evidence unified ───────────────────────────────────────────────────


def test_evidence_chain_is_continuous_and_mirrored(runtime) -> None:
    """
    spec § 'Evidence system is split' — fixed.

    The recorder owns the JSONL chain. The mirror is best-effort.
    Both writes happen through MemorySystem.record_decision_with_policy
    in the same call, so a successful evaluation produces one chain
    entry whose hash matches the mirror's record_hash (when durable).
    """
    runtime.evaluate_action_command.execute(_request())
    runtime.evaluate_action_command.execute(_request())
    runtime.evaluate_action_command.execute(_request())

    records = runtime.memory.recorder.read_all()
    assert len(records) == 3
    chain = verify_evidence_chain(records)
    assert chain.is_valid, chain.issues


# ── 6. replay round-trip ──────────────────────────────────────────────────


def test_runtime_decision_can_be_replayed_through_memory(runtime) -> None:
    """
    spec § 'Replay engine not fully guaranteed' — fixed.

    Every artefact replay needs (decision + input + policy snapshot)
    is present. The replay engine reconstitutes them and re-runs the
    evaluator. We use a stub evaluator that returns the same decision
    so we're testing the plumbing, not the PDP determinism.
    """
    result = runtime.evaluate_action_command.execute(_request())
    decision = result.decision

    def stub_evaluator(*, request: dict, policy: PolicySnapshot):
        # Replay's contract: same input + same policy → same decision.
        assert policy.version == decision.policy_version
        assert request["request_id"] == str(decision.request_id)
        return decision

    engine = MemoryReplayEngine(
        decisions=runtime.memory.decisions,
        inputs=runtime.memory.inputs,
        policies=runtime.memory.policies,
        evaluator=stub_evaluator,
    )

    replay = engine.replay(decision.decision_id)
    assert replay.is_clean
    assert replay.fingerprint_matched


# ── 7. cache invalidation hooks ───────────────────────────────────────────


def test_decision_store_cache_version_advances_on_write(runtime) -> None:
    """
    spec § 'Cache invalidation strategy missing' — fixed.

    Each successful write bumps cache_version. Cross-process
    invalidation (LISTEN/NOTIFY) is built on top of this counter.
    """
    before = runtime.memory.decisions.cache_version
    runtime.evaluate_action_command.execute(_request())
    after = runtime.memory.decisions.cache_version
    assert after > before


def test_policy_store_cache_version_advances_on_write() -> None:
    from tex.memory.policy_snapshot_store import DurablePolicyStore
    from tex.policies.defaults import build_default_policy

    store = DurablePolicyStore()
    before = store.cache_version
    store.save(build_default_policy())
    after = store.cache_version
    assert after > before

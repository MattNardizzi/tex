"""Thread 12: SAFEFLOW WAL + transactions — unit tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tex.safeflow import (
    FileWAL,
    InMemoryWAL,
    InverseOpRegistry,
    SafeflowError,
    TransactionState,
    TransactionalExecutor,
    WALEntryKind,
    register_inverse,
)


# ---------------------------------------------------------------------------
# WAL hash chaining
# ---------------------------------------------------------------------------


def test_inmem_wal_initial_state():
    wal = InMemoryWAL()
    assert wal.next_sequence() == 0
    assert wal.last_hash() == "0" * 64


def test_wal_chain_appends():
    inverses = InverseOpRegistry()
    inverses.register("noop", lambda **_: None)
    tools = {"echo": lambda *, x: x}
    ex = TransactionalExecutor(
        txn_id="t1",
        wal=InMemoryWAL(),
        inverses=inverses,
        tools=tools,
    )
    ex.begin()
    ex.step(step_id="s1", tool="echo", args={"x": 1}, inverse_op="noop")
    out = ex.commit()
    assert out.state is TransactionState.COMMITTED
    entries = ex.wal.read_all()
    # BEGIN + STEP_BEFORE + STEP_AFTER + COMMIT
    assert len(entries) == 4
    # chain integrity
    prev = "0" * 64
    for e in entries:
        assert e.prev_hash == prev
        prev = e.hash


def test_wal_rejects_chain_tamper():
    wal = InMemoryWAL()
    from tex.safeflow.wal import WALEntry

    e1 = WALEntry(
        sequence=0,
        txn_id="t1",
        kind=WALEntryKind.BEGIN,
        timestamp_ms=1,
        prev_hash="0" * 64,
    )
    wal.append(e1)
    bad = WALEntry(
        sequence=1,
        txn_id="t1",
        kind=WALEntryKind.COMMIT,
        timestamp_ms=2,
        prev_hash="0" * 64,  # wrong; should be e1.hash
    )
    with pytest.raises(ValueError, match="chain"):
        wal.append(bad)


def test_wal_rejects_sequence_skip():
    wal = InMemoryWAL()
    from tex.safeflow.wal import WALEntry

    bad = WALEntry(
        sequence=5,
        txn_id="t1",
        kind=WALEntryKind.BEGIN,
        timestamp_ms=1,
        prev_hash="0" * 64,
    )
    with pytest.raises(ValueError, match="sequence"):
        wal.append(bad)


def test_file_wal_persists_and_reloads(tmp_path: Path):
    path = tmp_path / "txn.log"
    wal = FileWAL(path)
    inverses = InverseOpRegistry()
    inverses.register("noop", lambda **_: None)
    tools = {"echo": lambda *, x: x}
    ex = TransactionalExecutor(
        txn_id="t-file",
        wal=wal,
        inverses=inverses,
        tools=tools,
    )
    ex.begin()
    ex.step(step_id="s1", tool="echo", args={"x": 1}, inverse_op="noop")
    ex.commit()
    assert path.exists()
    # Re-open into a fresh WAL, content reloads
    wal2 = FileWAL(path)
    entries = wal2.read_all()
    assert len(entries) == 4
    # last entry should be COMMIT
    assert entries[-1].kind is WALEntryKind.COMMIT


# ---------------------------------------------------------------------------
# Transactional discipline
# ---------------------------------------------------------------------------


def test_step_requires_registered_inverse():
    ex = TransactionalExecutor(
        txn_id="t2",
        tools={"noop": lambda: None},
        inverses=InverseOpRegistry(),
    )
    ex.begin()
    with pytest.raises(SafeflowError, match="inverse"):
        ex.step(step_id="s1", tool="noop", args={}, inverse_op="undo_noop")


def test_step_requires_known_tool():
    ex = TransactionalExecutor(
        txn_id="t3",
        tools={},
        inverses=InverseOpRegistry(),
    )
    ex.begin()
    with pytest.raises(SafeflowError, match="impl"):
        ex.step(step_id="s1", tool="ghost", args={})


def test_commit_then_step_rejected():
    inverses = InverseOpRegistry()
    inverses.register("noop", lambda **_: None)
    ex = TransactionalExecutor(
        txn_id="t4",
        inverses=inverses,
        tools={"echo": lambda *, x: x},
    )
    ex.begin()
    ex.step(step_id="s1", tool="echo", args={"x": 1}, inverse_op="noop")
    ex.commit()
    with pytest.raises(SafeflowError):
        ex.step(step_id="s2", tool="echo", args={"x": 2}, inverse_op="noop")


# ---------------------------------------------------------------------------
# Rollback
# ---------------------------------------------------------------------------


def test_rollback_invokes_inverses_in_reverse_order():
    invoked: list[str] = []
    inverses = InverseOpRegistry()
    inverses.register(
        "undo_a",
        lambda *, tool, args, result: invoked.append(f"undo_a({args['x']})"),
    )
    inverses.register(
        "undo_b",
        lambda *, tool, args, result: invoked.append(f"undo_b({args['y']})"),
    )
    tools = {
        "a": lambda *, x: x * 2,
        "b": lambda *, y: y + 1,
    }
    ex = TransactionalExecutor(
        txn_id="t5",
        inverses=inverses,
        tools=tools,
    )
    ex.begin()
    ex.step(step_id="s1", tool="a", args={"x": 10}, inverse_op="undo_a")
    ex.step(step_id="s2", tool="b", args={"y": 100}, inverse_op="undo_b")
    outcome = ex.abort(reason="changed mind")
    assert outcome.state is TransactionState.ROLLED_BACK
    assert invoked == ["undo_b(100)", "undo_a(10)"]


def test_rollback_continues_past_failing_inverse():
    inverses = InverseOpRegistry()

    def _bad_inverse(*, tool, args, result):
        raise RuntimeError("kaboom")

    invoked: list[str] = []
    inverses.register("undo_a", lambda *, tool, args, result: invoked.append("a"))
    inverses.register("undo_b", _bad_inverse)
    ex = TransactionalExecutor(
        txn_id="t6",
        inverses=inverses,
        tools={
            "a": lambda *, x: x,
            "b": lambda *, y: y,
        },
    )
    ex.begin()
    ex.step(step_id="s1", tool="a", args={"x": 1}, inverse_op="undo_a")
    ex.step(step_id="s2", tool="b", args={"y": 2}, inverse_op="undo_b")
    outcome = ex.abort(reason="test")
    # transitions to FAILED because rollback had a failure
    assert outcome.state is TransactionState.FAILED
    assert outcome.rollback_failures
    # but undo_a still ran
    assert invoked == ["a"]


def test_step_failure_triggers_abort():
    inverses = InverseOpRegistry()
    invoked: list[str] = []
    inverses.register(
        "undo_a",
        lambda *, tool, args, result: invoked.append("undo_a"),
    )

    def _bad_step(**_):
        raise ValueError("intentional")

    ex = TransactionalExecutor(
        txn_id="t7",
        inverses=inverses,
        tools={
            "a": lambda *, x: x,
            "bad": _bad_step,
        },
    )
    ex.begin()
    ex.step(step_id="s1", tool="a", args={"x": 1}, inverse_op="undo_a")
    with pytest.raises(SafeflowError):
        ex.step(step_id="s2", tool="bad", args={}, inverse_op="undo_a")
    # the executor aborted; s1's inverse should have run
    assert "undo_a" in invoked


def test_recovery_identifies_pending_txn(tmp_path: Path):
    path = tmp_path / "wal.log"
    wal = FileWAL(path)
    inverses = InverseOpRegistry()
    inverses.register("noop", lambda **_: None)
    ex = TransactionalExecutor(
        txn_id="t8",
        wal=wal,
        inverses=inverses,
        tools={"echo": lambda *, x: x},
    )
    ex.begin()
    ex.step(step_id="s1", tool="echo", args={"x": 1}, inverse_op="noop")
    # simulate crash: no commit, no abort
    states = ex.recover()
    assert states["t8"] == "PENDING"


def test_outcome_hash_chains():
    inverses = InverseOpRegistry()
    inverses.register("noop", lambda **_: None)
    ex = TransactionalExecutor(
        txn_id="t9",
        inverses=inverses,
        tools={"echo": lambda *, x: x},
    )
    ex.begin()
    ex.step(step_id="s1", tool="echo", args={"x": 1}, inverse_op="noop")
    outcome = ex.commit()
    assert len(outcome.transaction_hash) == 64
    assert len(outcome.wal_terminal_hash) == 64
    assert outcome.wal_entries == 4

"""
SAFEFLOW transactional executor.

Drives a ``Transaction`` through its lifecycle:

::

    begin → (step → step → ...) → commit
                                ↘ abort → rollback

Discipline (mirrors arxiv 2506.07564 §4):

1. ``begin``      writes BEGIN to WAL.
2. ``step``       writes STEP_BEFORE *before* the tool fires, then
                  invokes the tool, then writes STEP_AFTER. If the tool
                  raises, the executor writes STEP_AFTER with the error
                  and triggers ``abort``.
3. ``commit``     writes COMMIT. Past this point, the transaction is
                  durable: a crash here is recoverable because the
                  forward effects already happened and the WAL records
                  that they were intended.
4. ``abort``      writes ABORT, then invokes registered inverse ops in
                  *reverse* order, writing ROLLBACK_BEFORE / ROLLBACK_
                  AFTER for each. Inverse-op failures are themselves
                  logged but do not stop the rollback loop — we record
                  every failure so a human operator can repair.

Crash recovery
--------------
On startup, the executor can ``recover()`` from any WAL: replay,
inspect terminal states, rollback any transaction that has BEGIN but
no COMMIT/ABORT.

Concurrency
-----------
This executor is *single-threaded per transaction*. Tex's PDP pipeline
serializes adjudications per request, so we deliberately don't add a
lock-based concurrency manager here. Multi-agent shared-WAL semantics
are the LogAct extension (arxiv 2604.07988), deferred.
"""

from __future__ import annotations

import hashlib
import json
import time
from typing import Any, Callable

from pydantic import BaseModel, ConfigDict, Field

from tex.safeflow.rollback import InverseOpRegistry, default_registry
from tex.safeflow.transaction import (
    Transaction,
    TransactionState,
    TransactionStep,
)
from tex.safeflow.wal import (
    InMemoryWAL,
    WAL,
    WALEntry,
    WALEntryKind,
)


class SafeflowError(Exception):
    """Raised on transactional discipline violations."""


def _hash_args(args: dict) -> str:
    payload = json.dumps(args, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode()).hexdigest()


def _hash_result(result: object) -> str:
    try:
        payload = json.dumps(
            result, sort_keys=True, separators=(",", ":"), default=str
        )
    except (TypeError, ValueError):
        payload = repr(result)
    return hashlib.sha256(payload.encode()).hexdigest()


def _now_ms() -> int:
    return int(time.time() * 1000)


class TransactionOutcome(BaseModel):
    """Result of running a transaction."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    txn_id: str = Field(min_length=1, max_length=128)
    state: TransactionState
    transaction_hash: str = Field(min_length=64, max_length=64)
    wal_terminal_hash: str = Field(min_length=64, max_length=64)
    wal_entries: int = Field(ge=0)
    rollback_failures: tuple[str, ...] = Field(default_factory=tuple)
    failure_reason: str | None = Field(default=None, max_length=1000)


class TransactionalExecutor:
    """
    Drives a SAFEFLOW transaction. One executor per transaction; do
    not reuse instances.
    """

    __slots__ = (
        "_txn",
        "_wal",
        "_inverses",
        "_tools",
        "_inverse_args",
        "_rollback_failures",
    )

    def __init__(
        self,
        *,
        txn_id: str,
        wal: WAL | None = None,
        inverses: InverseOpRegistry | None = None,
        tools: dict[str, Callable[..., Any]] | None = None,
    ) -> None:
        if not txn_id:
            raise SafeflowError("txn_id is required")
        self._wal = wal or InMemoryWAL()
        self._inverses = inverses or default_registry()
        self._tools = dict(tools or {})
        self._txn = Transaction(txn_id=txn_id, created_at_ms=_now_ms())
        # capture inverse-op arguments per step so rollback can replay
        self._inverse_args: dict[str, dict[str, Any]] = {}
        self._rollback_failures: list[str] = []

    @property
    def transaction(self) -> Transaction:
        return self._txn

    @property
    def wal(self) -> WAL:
        return self._wal

    # ----------------------------------------------------------- lifecycle

    def begin(self) -> None:
        self._append_wal(
            kind=WALEntryKind.BEGIN,
            step_id=None,
            tool=None,
            args_hash=None,
            result_hash=None,
            inverse_op=None,
            note="transaction begin",
        )

    def step(
        self,
        *,
        step_id: str,
        tool: str,
        args: dict[str, Any],
        inverse_op: str | None = None,
    ) -> Any:
        if self._txn.state is not TransactionState.PENDING:
            raise SafeflowError(
                f"cannot step: transaction is {self._txn.state.value}"
            )
        if inverse_op is not None and not self._inverses.has(inverse_op):
            raise SafeflowError(
                f"inverse op {inverse_op!r} not registered; "
                "tool cannot participate in transaction"
            )
        impl = self._tools.get(tool)
        if impl is None:
            raise SafeflowError(f"no impl registered for tool {tool!r}")

        args_hash = _hash_args(args)
        started_at_ms = _now_ms()

        self._append_wal(
            kind=WALEntryKind.STEP_BEFORE,
            step_id=step_id,
            tool=tool,
            args_hash=args_hash,
            result_hash=None,
            inverse_op=inverse_op,
            note=None,
        )

        try:
            result = impl(**args)
        except Exception as exc:  # noqa: BLE001 - executor must catch all
            step = TransactionStep(
                step_id=step_id,
                tool=tool,
                args_hash=args_hash,
                result_hash=None,
                inverse_op=inverse_op,
                started_at_ms=started_at_ms,
                completed_at_ms=_now_ms(),
                error=str(exc)[:1000],
            )
            self._txn = self._txn.with_step(step)
            self._append_wal(
                kind=WALEntryKind.STEP_AFTER,
                step_id=step_id,
                tool=tool,
                args_hash=args_hash,
                result_hash=None,
                inverse_op=inverse_op,
                note=f"error: {str(exc)[:300]}",
            )
            self.abort(reason=f"step {step_id!r} raised: {exc}")
            raise SafeflowError(str(exc)) from exc

        result_hash = _hash_result(result)
        step = TransactionStep(
            step_id=step_id,
            tool=tool,
            args_hash=args_hash,
            result_hash=result_hash,
            inverse_op=inverse_op,
            started_at_ms=started_at_ms,
            completed_at_ms=_now_ms(),
            error=None,
        )
        self._txn = self._txn.with_step(step)
        # stash args+result for the inverse to replay
        if inverse_op is not None:
            self._inverse_args[step_id] = {"tool": tool, "args": dict(args), "result": result}
        self._append_wal(
            kind=WALEntryKind.STEP_AFTER,
            step_id=step_id,
            tool=tool,
            args_hash=args_hash,
            result_hash=result_hash,
            inverse_op=inverse_op,
            note=None,
        )
        return result

    def commit(self) -> TransactionOutcome:
        if self._txn.state is not TransactionState.PENDING:
            raise SafeflowError(
                f"cannot commit: transaction is {self._txn.state.value}"
            )
        self._txn = self._txn.with_state(
            TransactionState.COMMITTED, completed_at_ms=_now_ms()
        )
        self._append_wal(
            kind=WALEntryKind.COMMIT,
            step_id=None,
            tool=None,
            args_hash=None,
            result_hash=None,
            inverse_op=None,
            note="commit",
        )
        return self._outcome()

    def abort(self, *, reason: str) -> TransactionOutcome:
        if self._txn.state is TransactionState.COMMITTED:
            raise SafeflowError("cannot abort a committed transaction")
        if self._txn.state in (
            TransactionState.ROLLED_BACK,
            TransactionState.FAILED,
        ):
            # idempotent re-abort: just return current outcome
            return self._outcome()
        # mark FAILED first so we capture the original reason on the WAL
        # then run rollback. After rollback completes (success or not),
        # transition to ROLLED_BACK or stay FAILED with notes.
        self._txn = self._txn.with_state(
            TransactionState.FAILED,
            completed_at_ms=_now_ms(),
            failure_reason=reason,
        )
        self._append_wal(
            kind=WALEntryKind.ABORT,
            step_id=None,
            tool=None,
            args_hash=None,
            result_hash=None,
            inverse_op=None,
            note=f"abort: {reason[:300]}",
        )
        self._rollback()
        # transition to ROLLED_BACK if no inverse-op failures
        if not self._rollback_failures:
            self._txn = self._txn.with_state(TransactionState.ROLLED_BACK)
        return self._outcome()

    # ------------------------------------------------------------ recover

    def recover(self) -> dict[str, str]:
        """Inspect WAL terminal states for crash recovery."""
        from tex.safeflow.wal import replay

        return replay(self._wal.read_all())

    # ----------------------------------------------------------- internals

    def _rollback(self) -> None:
        # reverse order through completed steps with inverse_op set
        for step in reversed(self._txn.steps):
            if step.inverse_op is None:
                continue
            if step.error is not None:
                # failed forward step has nothing to undo
                continue
            inverse = self._inverses.get(step.inverse_op)
            if inverse is None:
                self._rollback_failures.append(
                    f"inverse op {step.inverse_op!r} disappeared mid-transaction"
                )
                continue
            self._append_wal(
                kind=WALEntryKind.ROLLBACK_BEFORE,
                step_id=step.step_id,
                tool=step.tool,
                args_hash=step.args_hash,
                result_hash=step.result_hash,
                inverse_op=step.inverse_op,
                note="rolling back step",
            )
            cached = self._inverse_args.get(step.step_id, {})
            try:
                inverse(
                    tool=step.tool,
                    args=cached.get("args", {}),
                    result=cached.get("result"),
                )
                note = "rollback ok"
            except Exception as exc:  # noqa: BLE001
                self._rollback_failures.append(
                    f"inverse {step.inverse_op!r} for step {step.step_id} "
                    f"raised: {exc}"
                )
                note = f"rollback error: {str(exc)[:300]}"
            self._append_wal(
                kind=WALEntryKind.ROLLBACK_AFTER,
                step_id=step.step_id,
                tool=step.tool,
                args_hash=step.args_hash,
                result_hash=step.result_hash,
                inverse_op=step.inverse_op,
                note=note,
            )

    def _append_wal(
        self,
        *,
        kind: WALEntryKind,
        step_id: str | None,
        tool: str | None,
        args_hash: str | None,
        result_hash: str | None,
        inverse_op: str | None,
        note: str | None,
    ) -> WALEntry:
        entry = WALEntry(
            sequence=self._wal.next_sequence(),
            txn_id=self._txn.txn_id,
            kind=kind,
            step_id=step_id,
            tool=tool,
            args_hash=args_hash,
            result_hash=result_hash,
            inverse_op=inverse_op,
            note=note,
            timestamp_ms=_now_ms(),
            prev_hash=self._wal.last_hash(),
        )
        return self._wal.append(entry)

    def _outcome(self) -> TransactionOutcome:
        return TransactionOutcome(
            txn_id=self._txn.txn_id,
            state=self._txn.state,
            transaction_hash=self._txn.hash,
            wal_terminal_hash=self._wal.last_hash(),
            wal_entries=self._wal.next_sequence(),
            rollback_failures=tuple(self._rollback_failures),
            failure_reason=self._txn.failure_reason,
        )


__all__ = ["SafeflowError", "TransactionOutcome", "TransactionalExecutor"]

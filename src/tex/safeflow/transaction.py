"""
SAFEFLOW transaction model.

A ``Transaction`` represents one logical unit of agent work. It owns:

- A monotonically increasing list of ``TransactionStep``s describing
  what tools were called with what arguments and what they returned.
- A ``TransactionState``: PENDING -> COMMITTED | ROLLED_BACK | FAILED.
- A creation timestamp and a final timestamp.
- A SHA-256 hash chain over all steps, so the WAL is tamper-evident.

The transaction is *not* the executor — that lives in
``tex.safeflow.executor``. The model here is a passive value object
suitable for evidence emission and for replay during recovery.

Reference: arxiv 2506.07564 §3 (transaction model); analogous to ARIES
(Mohan et al. 1992) WAL discipline applied to agent state instead of
B-tree pages.
"""

from __future__ import annotations

import hashlib
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class TransactionState(str, Enum):
    PENDING = "PENDING"
    COMMITTED = "COMMITTED"
    ROLLED_BACK = "ROLLED_BACK"
    FAILED = "FAILED"


class TransactionStep(BaseModel):
    """A single step inside a transaction."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    step_id: str = Field(min_length=1, max_length=64)
    tool: str = Field(min_length=1, max_length=128)
    args_hash: str = Field(min_length=1, max_length=128)
    result_hash: str | None = Field(default=None, max_length=128)
    inverse_op: str | None = Field(
        default=None,
        max_length=128,
        description="Name of the registered inverse op for rollback.",
    )
    started_at_ms: int = Field(ge=0)
    completed_at_ms: int | None = Field(default=None, ge=0)
    error: str | None = Field(default=None, max_length=1000)


class Transaction(BaseModel):
    """A logical transaction. Append-only ``steps`` field."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    txn_id: str = Field(min_length=1, max_length=128)
    state: TransactionState = TransactionState.PENDING
    steps: tuple[TransactionStep, ...] = Field(default_factory=tuple)
    created_at_ms: int = Field(ge=0)
    completed_at_ms: int | None = Field(default=None, ge=0)
    failure_reason: str | None = Field(default=None, max_length=1000)

    @property
    def hash(self) -> str:
        """SHA-256 over the canonical step sequence + terminal state."""
        h = hashlib.sha256()
        h.update(self.txn_id.encode())
        h.update(self.state.value.encode())
        for s in self.steps:
            h.update(s.step_id.encode())
            h.update(s.tool.encode())
            h.update(s.args_hash.encode())
            if s.result_hash:
                h.update(s.result_hash.encode())
            if s.inverse_op:
                h.update(s.inverse_op.encode())
        if self.failure_reason:
            h.update(self.failure_reason.encode())
        return h.hexdigest()

    def with_step(self, step: TransactionStep) -> "Transaction":
        return self.model_copy(update={"steps": self.steps + (step,)})

    def with_state(
        self,
        state: TransactionState,
        *,
        completed_at_ms: int | None = None,
        failure_reason: str | None = None,
    ) -> "Transaction":
        update = {"state": state}
        if completed_at_ms is not None:
            update["completed_at_ms"] = completed_at_ms
        if failure_reason is not None:
            update["failure_reason"] = failure_reason
        return self.model_copy(update=update)


__all__ = ["Transaction", "TransactionState", "TransactionStep"]

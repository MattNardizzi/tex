"""
Receipt persistence layer.

Receipts are append-only. Use Postgres in production, SQLite in dev,
in-memory for tests.

Reference
---------
arxiv 2603.10060 — NabaOS receipt store. The integrity argument depends
on the store being append-only; once a receipt is issued it cannot be
mutated or replaced, only superseded by a later receipt.

Priority: P0.
"""

from __future__ import annotations

from threading import RLock
from typing import Protocol, runtime_checkable

from tex.receipts.receipt import ToolExecutionReceipt


@runtime_checkable
class ReceiptStore(Protocol):
    """The minimal contract the verifier needs from any backing store."""

    def append(self, receipt: ToolExecutionReceipt) -> None: ...
    def get(self, receipt_id: str) -> ToolExecutionReceipt | None: ...
    def list_for_session(
        self, session_id: str
    ) -> tuple[ToolExecutionReceipt, ...]: ...


class InMemoryReceiptStore:
    """
    Test / development in-memory store.

    Append-only: re-appending the same ``receipt_id`` raises ``ValueError``.
    Thread-safe via an RLock — multiple ReceiptIssuer instances may share
    a store in test fixtures.
    """

    def __init__(self) -> None:
        self._records: dict[str, ToolExecutionReceipt] = {}
        self._lock = RLock()

    def append(self, receipt: ToolExecutionReceipt) -> None:
        """
        Append a receipt to the store.

        Raises
        ------
        ValueError
            If ``receipt.receipt_id`` already exists in the store. Receipts
            are immutable once issued; re-issuance is a programming error.
        """
        with self._lock:
            existing = self._records.get(receipt.receipt_id)
            if existing is not None:
                raise ValueError(
                    f"receipt_id {receipt.receipt_id!r} already in store; "
                    "receipts are append-only and may not be overwritten"
                )
            self._records[receipt.receipt_id] = receipt

    def get(self, receipt_id: str) -> ToolExecutionReceipt | None:
        """Return the receipt with this id, or None if not present."""
        with self._lock:
            return self._records.get(receipt_id)

    def list_for_session(
        self, session_id: str
    ) -> tuple[ToolExecutionReceipt, ...]:
        """
        All receipts issued under ``session_id``, ordered by ``started_at``.

        Returns an empty tuple if the session has no receipts.
        """
        with self._lock:
            matches = [
                r for r in self._records.values() if r.session_id == session_id
            ]
        matches.sort(key=lambda r: r.started_at)
        return tuple(matches)

    def __len__(self) -> int:
        with self._lock:
            return len(self._records)


__all__ = ["ReceiptStore", "InMemoryReceiptStore"]

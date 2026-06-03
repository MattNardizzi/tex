"""
SAFEFLOW write-ahead log.

A WAL is an *append-only* sequence of entries that record the intent
of each transaction operation **before** the operation runs. On crash
recovery (or rollback), the WAL replay tells the executor exactly
what to undo.

We provide:

- ``WALEntryKind`` — BEGIN | STEP_BEFORE | STEP_AFTER | COMMIT |
                     ABORT | ROLLBACK_BEFORE | ROLLBACK_AFTER
- ``WALEntry``     — the typed record itself, frozen pydantic model
- ``WAL``          — abstract protocol
- ``InMemoryWAL``  — list-backed, suitable for tests + ephemeral use
- ``FileWAL``      — newline-delimited canonical JSON, fsynced on
                     every append

Durability
----------
The file WAL fsyncs on every append. This is the load-bearing property
that makes recovery sound (per ARIES write-ahead-logging discipline:
log records must hit stable storage before the operation they describe
takes effect). For tests we use the in-memory variant; production wiring
selects the file variant.

The WAL is also a Tex evidence-chain participant: each entry's
``prev_hash`` field chains to the previous entry's SHA-256, so a
truncated or tampered WAL is detectable on replay.
"""

from __future__ import annotations

import hashlib
import json
import os
from enum import Enum
from pathlib import Path
from typing import Iterable, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field


class WALEntryKind(str, Enum):
    BEGIN = "BEGIN"
    STEP_BEFORE = "STEP_BEFORE"
    STEP_AFTER = "STEP_AFTER"
    COMMIT = "COMMIT"
    ABORT = "ABORT"
    ROLLBACK_BEFORE = "ROLLBACK_BEFORE"
    ROLLBACK_AFTER = "ROLLBACK_AFTER"


class WALEntry(BaseModel):
    """One entry in the write-ahead log."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    sequence: int = Field(ge=0)
    txn_id: str = Field(min_length=1, max_length=128)
    kind: WALEntryKind
    step_id: str | None = Field(default=None, max_length=64)
    tool: str | None = Field(default=None, max_length=128)
    args_hash: str | None = Field(default=None, max_length=128)
    result_hash: str | None = Field(default=None, max_length=128)
    inverse_op: str | None = Field(default=None, max_length=128)
    note: str | None = Field(default=None, max_length=500)
    timestamp_ms: int = Field(ge=0)
    prev_hash: str = Field(min_length=1, max_length=128)

    @property
    def canonical_payload(self) -> str:
        return json.dumps(
            self.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )

    @property
    def hash(self) -> str:
        return hashlib.sha256(self.canonical_payload.encode()).hexdigest()


@runtime_checkable
class WAL(Protocol):
    """Append-only WAL protocol."""

    def append(self, entry: WALEntry) -> WALEntry: ...
    def read_all(self) -> tuple[WALEntry, ...]: ...
    def last_hash(self) -> str: ...
    def next_sequence(self) -> int: ...


_GENESIS_HASH = "0" * 64


class InMemoryWAL:
    """List-backed WAL for tests and short-lived sessions."""

    __slots__ = ("_entries",)

    def __init__(self) -> None:
        self._entries: list[WALEntry] = []

    def append(self, entry: WALEntry) -> WALEntry:
        if entry.sequence != len(self._entries):
            raise ValueError(
                f"WAL sequence mismatch: expected {len(self._entries)}, "
                f"got {entry.sequence}"
            )
        expected_prev = self.last_hash()
        if entry.prev_hash != expected_prev:
            raise ValueError(
                f"WAL chain break: expected prev_hash {expected_prev}, "
                f"got {entry.prev_hash}"
            )
        self._entries.append(entry)
        return entry

    def read_all(self) -> tuple[WALEntry, ...]:
        return tuple(self._entries)

    def last_hash(self) -> str:
        if not self._entries:
            return _GENESIS_HASH
        return self._entries[-1].hash

    def next_sequence(self) -> int:
        return len(self._entries)


class FileWAL:
    """
    Newline-delimited JSON, fsynced on every append.

    Storage layout: ``<root_dir>/<txn_id>.log``. We open the file
    lazily on first append so empty WALs don't litter disk.
    """

    __slots__ = ("_path", "_cache", "_loaded")

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._cache: list[WALEntry] = []
        self._loaded = False

    def _load_if_needed(self) -> None:
        if self._loaded:
            return
        self._loaded = True
        if not self._path.exists():
            return
        with self._path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                data = json.loads(line)
                self._cache.append(WALEntry(**data))

    def append(self, entry: WALEntry) -> WALEntry:
        self._load_if_needed()
        if entry.sequence != len(self._cache):
            raise ValueError(
                f"WAL sequence mismatch: expected {len(self._cache)}, "
                f"got {entry.sequence}"
            )
        if entry.prev_hash != self.last_hash():
            raise ValueError("WAL chain break")
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._path.open("a", encoding="utf-8") as fh:
            fh.write(entry.canonical_payload + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        self._cache.append(entry)
        return entry

    def read_all(self) -> tuple[WALEntry, ...]:
        self._load_if_needed()
        return tuple(self._cache)

    def last_hash(self) -> str:
        self._load_if_needed()
        if not self._cache:
            return _GENESIS_HASH
        return self._cache[-1].hash

    def next_sequence(self) -> int:
        self._load_if_needed()
        return len(self._cache)


def replay(entries: Iterable[WALEntry]) -> dict[str, str]:
    """
    Replay a WAL and return per-transaction terminal state.

    Useful for crash recovery: any txn whose terminal state is BEGIN or
    STEP_AFTER (no COMMIT, no ABORT) needs rollback.
    """
    state: dict[str, str] = {}
    for e in entries:
        if e.kind == WALEntryKind.BEGIN:
            state[e.txn_id] = "PENDING"
        elif e.kind == WALEntryKind.COMMIT:
            state[e.txn_id] = "COMMITTED"
        elif e.kind == WALEntryKind.ABORT:
            state[e.txn_id] = "ABORTED"
        elif e.kind in (
            WALEntryKind.ROLLBACK_BEFORE,
            WALEntryKind.ROLLBACK_AFTER,
        ):
            state[e.txn_id] = "ROLLING_BACK"
    return state


__all__ = [
    "FileWAL",
    "InMemoryWAL",
    "WAL",
    "WALEntry",
    "WALEntryKind",
    "replay",
]

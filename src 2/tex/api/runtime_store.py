"""
In-memory TTL store for async evaluation results and streaming sessions.

This is the same lightweight in-memory pattern Tex uses elsewhere
(InMemoryDecisionStore, InMemoryPolicyStore, etc.). It's fit for a
single-process Render deployment. A multi-replica production deployment
would swap this for Redis without changing any caller code.

Two distinct uses:

1. Async evaluation results - when a customer hits /v1/guardrail/async,
   we accept immediately with a 202, run the evaluation in the background,
   and stash the result here. They poll GET /v1/guardrail/async/{id} to
   collect it.

2. Streaming session state - when a customer hits the streaming endpoint
   with progressive content, we keep a per-session buffer here so we can
   diff against the previous chunk and re-evaluate only the new content.

Both get a TTL so the store doesn't grow unbounded under load.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Final
from uuid import UUID, uuid4


_DEFAULT_TTL_SECONDS: Final[int] = 600  # 10 minutes
_MAX_ENTRIES: Final[int] = 10_000        # safety bound; oldest evicted first


@dataclass(slots=True)
class _Entry:
    value: Any
    expires_at: datetime
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))


class TTLStore:
    """Thread-safe in-memory store with per-entry TTL and bounded size."""

    __slots__ = ("_lock", "_data", "_default_ttl_seconds", "_max_entries")

    def __init__(
        self,
        *,
        default_ttl_seconds: int = _DEFAULT_TTL_SECONDS,
        max_entries: int = _MAX_ENTRIES,
    ) -> None:
        self._lock = threading.Lock()
        self._data: dict[str, _Entry] = {}
        self._default_ttl_seconds = default_ttl_seconds
        self._max_entries = max_entries

    def put(self, key: str, value: Any, *, ttl_seconds: int | None = None) -> None:
        ttl = ttl_seconds if ttl_seconds is not None else self._default_ttl_seconds
        expires = datetime.now(UTC) + timedelta(seconds=ttl)
        with self._lock:
            self._sweep_locked()
            if len(self._data) >= self._max_entries:
                # Evict the oldest entry to make room.
                oldest_key = min(
                    self._data.items(),
                    key=lambda item: item[1].created_at,
                )[0]
                self._data.pop(oldest_key, None)
            self._data[key] = _Entry(value=value, expires_at=expires)

    def get(self, key: str) -> Any | None:
        with self._lock:
            entry = self._data.get(key)
            if entry is None:
                return None
            if entry.expires_at < datetime.now(UTC):
                self._data.pop(key, None)
                return None
            return entry.value

    def update(self, key: str, value: Any, *, ttl_seconds: int | None = None) -> bool:
        """Update an existing key's value (refreshing TTL). Returns False if key absent/expired."""
        with self._lock:
            entry = self._data.get(key)
            if entry is None or entry.expires_at < datetime.now(UTC):
                return False
            ttl = ttl_seconds if ttl_seconds is not None else self._default_ttl_seconds
            entry.value = value
            entry.expires_at = datetime.now(UTC) + timedelta(seconds=ttl)
            return True

    def delete(self, key: str) -> None:
        with self._lock:
            self._data.pop(key, None)

    def __contains__(self, key: str) -> bool:
        return self.get(key) is not None

    def __len__(self) -> int:
        with self._lock:
            self._sweep_locked()
            return len(self._data)

    def _sweep_locked(self) -> None:
        """Drop expired entries. Caller holds the lock."""
        now = datetime.now(UTC)
        expired = [k for k, e in self._data.items() if e.expires_at < now]
        for key in expired:
            self._data.pop(key, None)


# Module-level singletons for the API layer to import.
async_results: TTLStore = TTLStore(default_ttl_seconds=3600)  # 1h for async results
stream_sessions: TTLStore = TTLStore(default_ttl_seconds=300)  # 5min for stream sessions


__all__ = [
    "TTLStore",
    "async_results",
    "stream_sessions",
]

"""Daily governance state snapshots — the data "as of last week" needs.

Tex's stores hold CURRENT state only, so "how many agents were active on
June 1?" has always honestly abstained: there was no record of past state.
This store appends one posture snapshot per UTC day (taken lazily on the
first ask of the day), so from installation onward, as-of-a-past-date
questions have real rows to ground in.

Honesty edges:

* **History starts at installation.** A date before the first snapshot has no
  record and abstains — the store never back-fills or interpolates.
* **Lazy, at-most-daily.** ``record_daily_snapshot`` is called on the ask path
  and returns immediately when today's snapshot already exists. It reads the
  live stores; it never mutates them.
* **Recorded-at-write-time.** ``taken_at`` is outside any tamper-evident hash —
  answers over snapshots are DERIVED ('by recorded time'), never SEALED.
"""

from __future__ import annotations

import threading
from typing import Any

from datetime import UTC, datetime

__all__ = ["StateSnapshotStore", "record_daily_snapshot"]


class StateSnapshotStore:
    """Thread-safe, append-only, at-most-one-snapshot-per-UTC-day store."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._items: list[dict[str, Any]] = []
        self._days: set[str] = set()

    def append_for_day(self, day: str, snapshot: dict[str, Any]) -> bool:
        """Append ``snapshot`` for UTC day ``day`` (YYYY-MM-DD); False if that
        day already has one (the snapshot is discarded — one per day, ever)."""
        with self._lock:
            if day in self._days:
                return False
            self._days.add(day)
            self._items.append(snapshot)
            return True

    def has_day(self, day: str) -> bool:
        with self._lock:
            return day in self._days

    def list_all(self) -> tuple[dict[str, Any], ...]:
        with self._lock:
            return tuple(self._items)

    def __len__(self) -> int:
        with self._lock:
            return len(self._items)


def _status_counts(registry: Any) -> tuple[dict[str, int], int]:
    counts: dict[str, int] = {}
    total = 0
    for agent in registry.list_all():
        key = str(getattr(agent, "lifecycle_status", "UNKNOWN"))
        counts[key] = counts.get(key, 0) + 1
        total += 1
    return counts, total


def _verdict_counts(decision_store: Any) -> tuple[dict[str, int], int]:
    counts: dict[str, int] = {}
    total = 0
    rows = decision_store.list_all() if hasattr(decision_store, "list_all") else ()
    for d in rows:
        v = getattr(getattr(d, "verdict", None), "value", None) or str(getattr(d, "verdict", ""))
        counts[str(v).upper()] = counts.get(str(v).upper(), 0) + 1
        total += 1
    return counts, total


def record_daily_snapshot(state: Any) -> bool:
    """Take today's snapshot if it doesn't exist yet. Never raises; returns
    True only when a new snapshot was appended. Cheap no-op on every ask after
    the first of the day."""
    try:
        store = getattr(state, "state_snapshot_store", None)
        if store is None:
            return False
        now = datetime.now(UTC)
        day = now.strftime("%Y-%m-%d")
        if store.has_day(day):
            return False
        snapshot: dict[str, Any] = {"snapshot_day": day, "taken_at": now.isoformat()}
        registry = getattr(state, "agent_registry", None)
        if registry is not None and hasattr(registry, "list_all"):
            by_status, total = _status_counts(registry)
            snapshot["agents_by_status"] = by_status
            snapshot["agent_total"] = total
            snapshot["agents_active"] = by_status.get("ACTIVE", 0)
        decisions = getattr(state, "decision_store", None)
        if decisions is not None:
            by_verdict, total = _verdict_counts(decisions)
            snapshot["decisions_by_verdict"] = by_verdict
            snapshot["decision_total"] = total
        return store.append_for_day(day, snapshot)
    except Exception:  # noqa: BLE001 — a snapshot must never break the ask path
        return False

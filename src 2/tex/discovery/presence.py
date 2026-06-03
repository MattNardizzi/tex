"""
Soft-disappearance state machine.

V15's drift detection treated "agent missing this scan" as immediate
``AGENT_DISAPPEARED``. One flaky API response, one rate limit, one
expired token mid-scan, and a healthy production agent generates a
false-positive disappearance alert.

This module fixes that by tracking a per-``(tenant, reconciliation_key)``
state machine:

    PRESENT
       ├─ seen this scan ──→ stays PRESENT
       └─ missing this scan ─→ MISSING_ONCE

    MISSING_ONCE
       ├─ seen this scan ──→ back to PRESENT  (recovery, no event)
       └─ missing this scan ─→ MISSING_TWICE

    MISSING_TWICE
       ├─ seen this scan ──→ back to PRESENT  (recovery, no event)
       └─ missing this scan ─→ CONFIRMED_DISAPPEARED  (emit event NOW)

    CONFIRMED_DISAPPEARED
       └─ seen this scan ──→ back to PRESENT  (re-emerged, emit NEW_AGENT-like)

Only the transition into ``CONFIRMED_DISAPPEARED`` produces an
``AGENT_DISAPPEARED`` drift event. The intermediate states are
silent — they tighten signal without flooding the alert surface.

Configuration is one knob: ``missing_threshold`` (default 3 — meaning
three consecutive missing scans cement disappearance). For tenants
with very stable platforms an operator can raise this; for tenants
where missing means missing, lower it to 1 to restore V15 behavior.

State persists to Postgres when ``DATABASE_URL`` is set so a process
restart does not reset the counters and turn missing-once entries
into spurious "back to present" recoveries.
"""

from __future__ import annotations

import logging
import os
import threading
from datetime import UTC, datetime
from enum import StrEnum

import psycopg

_logger = logging.getLogger(__name__)

DATABASE_URL_ENV = "DATABASE_URL"

# Default: emit CONFIRMED only on the third consecutive miss. Two
# free passes is the right balance for most platforms (Microsoft
# Graph throttling, GitHub secondary rate limits, OpenAI 5xx
# blips). One miss is too aggressive; four is too forgiving.
DEFAULT_MISSING_THRESHOLD = 3


class PresenceState(StrEnum):
    """Where a (tenant, key) sits on the soft-disappearance machine."""

    PRESENT = "present"
    MISSING_ONCE = "missing_once"
    MISSING_TWICE = "missing_twice"
    CONFIRMED_DISAPPEARED = "confirmed_disappeared"


class TransitionEvent(StrEnum):
    """The categorical drift-relevant outcomes of one scan tick."""

    NO_EVENT = "no_event"                    # state unchanged in a non-noteworthy way
    SILENT_MISS = "silent_miss"              # advanced toward disappearance, no alert
    RECOVERED = "recovered"                  # came back from missing_once/twice silently
    CONFIRMED_DISAPPEARED = "confirmed_disappeared"  # cross threshold → emit event
    REAPPEARED = "reappeared"                # was confirmed-gone, now present again


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS tex_presence_states (
    tenant_id            TEXT NOT NULL,
    reconciliation_key   TEXT NOT NULL,
    state                TEXT NOT NULL,
    consecutive_misses   INTEGER NOT NULL DEFAULT 0,
    last_seen_at         TIMESTAMPTZ,
    last_missing_at      TIMESTAMPTZ,
    confirmed_at         TIMESTAMPTZ,
    discovery_source     TEXT,
    last_scan_run_id     UUID,
    PRIMARY KEY (tenant_id, reconciliation_key)
);

CREATE INDEX IF NOT EXISTS tex_presence_tenant_idx
    ON tex_presence_states (tenant_id);
CREATE INDEX IF NOT EXISTS tex_presence_state_idx
    ON tex_presence_states (state);
"""


class PresenceRecord:
    """In-memory shape of one (tenant, reconciliation_key) state row."""

    __slots__ = (
        "tenant_id", "reconciliation_key", "state", "consecutive_misses",
        "last_seen_at", "last_missing_at", "confirmed_at",
        "discovery_source", "last_scan_run_id",
    )

    def __init__(
        self,
        *,
        tenant_id: str,
        reconciliation_key: str,
        state: PresenceState = PresenceState.PRESENT,
        consecutive_misses: int = 0,
        last_seen_at: datetime | None = None,
        last_missing_at: datetime | None = None,
        confirmed_at: datetime | None = None,
        discovery_source: str | None = None,
        last_scan_run_id: str | None = None,
    ) -> None:
        self.tenant_id = tenant_id
        self.reconciliation_key = reconciliation_key
        self.state = state
        self.consecutive_misses = consecutive_misses
        self.last_seen_at = last_seen_at
        self.last_missing_at = last_missing_at
        self.confirmed_at = confirmed_at
        self.discovery_source = discovery_source
        self.last_scan_run_id = last_scan_run_id

    def to_dict(self) -> dict:
        return {
            "tenant_id": self.tenant_id,
            "reconciliation_key": self.reconciliation_key,
            "state": str(self.state),
            "consecutive_misses": self.consecutive_misses,
            "last_seen_at": (
                self.last_seen_at.isoformat() if self.last_seen_at else None
            ),
            "last_missing_at": (
                self.last_missing_at.isoformat() if self.last_missing_at else None
            ),
            "confirmed_at": (
                self.confirmed_at.isoformat() if self.confirmed_at else None
            ),
            "discovery_source": self.discovery_source,
            "last_scan_run_id": self.last_scan_run_id,
        }


class PresenceTracker:
    """
    Per-tenant soft-disappearance state machine.

    The scheduler calls ``observe_seen`` for every reconciliation_key
    in this run's entries, then ``observe_missing`` for every key that
    was previously known but absent this run. The tracker decides
    whether each transition should produce an ``AGENT_DISAPPEARED``
    or ``REAPPEARED`` event.
    """

    __slots__ = (
        "_lock", "_dsn", "_disabled", "_records", "_threshold",
    )

    def __init__(
        self,
        *,
        dsn: str | None = None,
        missing_threshold: int = DEFAULT_MISSING_THRESHOLD,
    ) -> None:
        self._lock = threading.RLock()
        self._dsn = dsn or os.environ.get(DATABASE_URL_ENV, "").strip()
        self._disabled = not bool(self._dsn)
        self._records: dict[tuple[str, str], PresenceRecord] = {}
        self._threshold = max(1, int(missing_threshold))

        if self._disabled:
            _logger.warning(
                "PresenceTracker: %s not set; presence state will not survive "
                "restarts.",
                DATABASE_URL_ENV,
            )
            return

        try:
            self._ensure_schema()
            self._bootstrap()
        except Exception as exc:  # noqa: BLE001
            _logger.error(
                "PresenceTracker: schema bootstrap failed: %s. "
                "Falling back to in-memory mode.",
                exc,
            )
            self._disabled = True

    # ------------------------------------------------------------------ transitions

    def observe_seen(
        self,
        *,
        tenant_id: str,
        reconciliation_key: str,
        discovery_source: str | None = None,
        scan_run_id: str | None = None,
    ) -> tuple[PresenceRecord, TransitionEvent]:
        """
        Record that this key was seen this scan.

        Returns the new record and a transition event describing
        what to alert on (``REAPPEARED`` if it was confirmed-missing,
        ``RECOVERED`` if it was missing_once/twice and silently came
        back, ``NO_EVENT`` if it was already present).
        """
        normalized = tenant_id.strip().casefold()
        key = (normalized, reconciliation_key)
        now = datetime.now(UTC)

        with self._lock:
            existing = self._records.get(key)
            event = TransitionEvent.NO_EVENT
            if existing is None:
                rec = PresenceRecord(
                    tenant_id=normalized,
                    reconciliation_key=reconciliation_key,
                    state=PresenceState.PRESENT,
                    consecutive_misses=0,
                    last_seen_at=now,
                    discovery_source=discovery_source,
                    last_scan_run_id=scan_run_id,
                )
            else:
                if existing.state is PresenceState.CONFIRMED_DISAPPEARED:
                    event = TransitionEvent.REAPPEARED
                elif existing.state in (
                    PresenceState.MISSING_ONCE, PresenceState.MISSING_TWICE,
                ):
                    event = TransitionEvent.RECOVERED
                rec = PresenceRecord(
                    tenant_id=normalized,
                    reconciliation_key=reconciliation_key,
                    state=PresenceState.PRESENT,
                    consecutive_misses=0,
                    last_seen_at=now,
                    last_missing_at=existing.last_missing_at,
                    confirmed_at=None,
                    discovery_source=discovery_source or existing.discovery_source,
                    last_scan_run_id=scan_run_id,
                )
            self._records[key] = rec
            self._safe_flush(rec)
            return rec, event

    def observe_missing(
        self,
        *,
        tenant_id: str,
        reconciliation_key: str,
        discovery_source: str | None = None,
        scan_run_id: str | None = None,
    ) -> tuple[PresenceRecord, TransitionEvent]:
        """
        Record that this previously-known key was absent this scan.

        The state advances PRESENT → MISSING_ONCE → MISSING_TWICE →
        CONFIRMED_DISAPPEARED. Only the transition INTO confirmed
        produces a noteworthy event (``CONFIRMED_DISAPPEARED``).
        Intermediate misses produce ``SILENT_MISS``.
        """
        normalized = tenant_id.strip().casefold()
        key = (normalized, reconciliation_key)
        now = datetime.now(UTC)

        with self._lock:
            existing = self._records.get(key)
            prior_state = existing.state if existing else PresenceState.PRESENT
            misses = (existing.consecutive_misses + 1) if existing else 1
            if misses >= self._threshold:
                new_state = PresenceState.CONFIRMED_DISAPPEARED
            elif misses == 1:
                new_state = PresenceState.MISSING_ONCE
            else:
                new_state = PresenceState.MISSING_TWICE

            event: TransitionEvent
            if (
                new_state is PresenceState.CONFIRMED_DISAPPEARED
                and prior_state is not PresenceState.CONFIRMED_DISAPPEARED
            ):
                event = TransitionEvent.CONFIRMED_DISAPPEARED
            elif new_state is PresenceState.CONFIRMED_DISAPPEARED:
                # Already confirmed; do not emit again on subsequent misses.
                event = TransitionEvent.NO_EVENT
            else:
                event = TransitionEvent.SILENT_MISS

            rec = PresenceRecord(
                tenant_id=normalized,
                reconciliation_key=reconciliation_key,
                state=new_state,
                consecutive_misses=misses,
                last_seen_at=existing.last_seen_at if existing else None,
                last_missing_at=now,
                confirmed_at=(
                    now if event is TransitionEvent.CONFIRMED_DISAPPEARED
                    else (existing.confirmed_at if existing else None)
                ),
                discovery_source=discovery_source or (
                    existing.discovery_source if existing else None
                ),
                last_scan_run_id=scan_run_id,
            )
            self._records[key] = rec
            self._safe_flush(rec)
            return rec, event

    # ------------------------------------------------------------------ reads

    def get(self, *, tenant_id: str, reconciliation_key: str) -> PresenceRecord | None:
        normalized = tenant_id.strip().casefold()
        with self._lock:
            return self._records.get((normalized, reconciliation_key))

    def list_for_tenant(self, tenant_id: str) -> list[PresenceRecord]:
        normalized = tenant_id.strip().casefold()
        with self._lock:
            return [
                r for (t, _), r in self._records.items() if t == normalized
            ]

    def keys_for_tenant_in_state(
        self, tenant_id: str, state: PresenceState,
    ) -> list[str]:
        normalized = tenant_id.strip().casefold()
        with self._lock:
            return [
                key for (t, key), r in self._records.items()
                if t == normalized and r.state is state
            ]

    @property
    def is_durable(self) -> bool:
        return not self._disabled

    @property
    def threshold(self) -> int:
        return self._threshold

    # ------------------------------------------------------------------ internals

    def _safe_flush(self, rec: PresenceRecord) -> None:
        if self._disabled:
            return
        try:
            self._flush_upsert(rec)
        except Exception as exc:  # noqa: BLE001
            _logger.error(
                "PresenceTracker: write failed for %s/%s: %s",
                rec.tenant_id, rec.reconciliation_key, exc,
            )

    def _ensure_schema(self) -> None:
        with psycopg.connect(self._dsn, autocommit=True) as conn:
            with conn.cursor() as cur:
                cur.execute(SCHEMA_SQL)

    def _bootstrap(self) -> None:
        with psycopg.connect(self._dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT tenant_id, reconciliation_key, state,
                           consecutive_misses, last_seen_at, last_missing_at,
                           confirmed_at, discovery_source, last_scan_run_id
                      FROM tex_presence_states
                    """
                )
                rows = cur.fetchall()
        with self._lock:
            for row in rows:
                rec = PresenceRecord(
                    tenant_id=row[0],
                    reconciliation_key=row[1],
                    state=PresenceState(row[2]),
                    consecutive_misses=row[3] or 0,
                    last_seen_at=_aware(row[4]) if row[4] else None,
                    last_missing_at=_aware(row[5]) if row[5] else None,
                    confirmed_at=_aware(row[6]) if row[6] else None,
                    discovery_source=row[7],
                    last_scan_run_id=str(row[8]) if row[8] else None,
                )
                self._records[(rec.tenant_id, rec.reconciliation_key)] = rec

    def _flush_upsert(self, rec: PresenceRecord) -> None:
        with psycopg.connect(self._dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO tex_presence_states (
                        tenant_id, reconciliation_key, state,
                        consecutive_misses, last_seen_at, last_missing_at,
                        confirmed_at, discovery_source, last_scan_run_id
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (tenant_id, reconciliation_key) DO UPDATE SET
                        state              = EXCLUDED.state,
                        consecutive_misses = EXCLUDED.consecutive_misses,
                        last_seen_at       = EXCLUDED.last_seen_at,
                        last_missing_at    = EXCLUDED.last_missing_at,
                        confirmed_at       = EXCLUDED.confirmed_at,
                        discovery_source   = EXCLUDED.discovery_source,
                        last_scan_run_id   = EXCLUDED.last_scan_run_id
                    """,
                    (
                        rec.tenant_id, rec.reconciliation_key, str(rec.state),
                        rec.consecutive_misses, rec.last_seen_at,
                        rec.last_missing_at, rec.confirmed_at,
                        rec.discovery_source, rec.last_scan_run_id,
                    ),
                )
            conn.commit()


def _aware(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=UTC)
    return value


__all__ = [
    "PresenceTracker",
    "PresenceRecord",
    "PresenceState",
    "TransitionEvent",
    "DEFAULT_MISSING_THRESHOLD",
    "DATABASE_URL_ENV",
]

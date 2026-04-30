"""
Drift event store.

Discovery scans produce ``ReconciliationOutcome`` records that say
what changed about candidates the connectors saw. They do NOT say
anything about agents that *stopped* appearing — the reconciliation
engine works candidate-by-candidate, so a candidate that disappears
between scan T and scan T+1 simply doesn't show up in T+1's outcome
list.

The drift event store closes that gap. After each scan, the
scheduler diffs "reconciliation_keys seen this run" against
"reconciliation_keys we expected to see," and emits one of:

    NEW_AGENT          — first time we saw this reconciliation_key
    AGENT_CHANGED      — surface drift, lifecycle change, or risk-band
                         change relative to the prior scan
    AGENT_DISAPPEARED  — present in the prior scan, absent in this one

Drift events are an append-only log. They feed:

  - the alert engine (which fires webhooks / log lines on threshold)
  - the governance snapshot delta (which surfaces "what changed
    since the last snapshot")
  - the audit story for "when did Tex first observe this agent"

Persistence: write-through to Postgres when ``DATABASE_URL`` is set,
in-memory otherwise. Same pattern as the registry and ledger.
"""

from __future__ import annotations

import logging
import os
import threading
from collections import deque
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

import psycopg
from psycopg.types.json import Jsonb

_logger = logging.getLogger(__name__)

DATABASE_URL_ENV = "DATABASE_URL"


class DriftEventKind(StrEnum):
    NEW_AGENT = "NEW_AGENT"
    AGENT_CHANGED = "AGENT_CHANGED"
    AGENT_DISAPPEARED = "AGENT_DISAPPEARED"


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS tex_drift_events (
    event_id              UUID PRIMARY KEY,
    occurred_at           TIMESTAMPTZ NOT NULL,
    tenant_id             TEXT NOT NULL,
    kind                  TEXT NOT NULL,
    reconciliation_key    TEXT NOT NULL,
    discovery_source      TEXT,
    agent_id              UUID,
    severity              TEXT NOT NULL DEFAULT 'INFO',
    summary               TEXT NOT NULL,
    details               JSONB NOT NULL DEFAULT '{}'::jsonb,
    scan_run_id           UUID
);

CREATE INDEX IF NOT EXISTS tex_drift_events_time_idx
    ON tex_drift_events (occurred_at DESC);

CREATE INDEX IF NOT EXISTS tex_drift_events_tenant_idx
    ON tex_drift_events (tenant_id, occurred_at DESC);

CREATE INDEX IF NOT EXISTS tex_drift_events_recon_idx
    ON tex_drift_events (reconciliation_key);

CREATE INDEX IF NOT EXISTS tex_drift_events_kind_idx
    ON tex_drift_events (kind, occurred_at DESC);
"""


class DriftEvent:
    """Lightweight, immutable drift record."""

    __slots__ = (
        "event_id", "occurred_at", "tenant_id", "kind",
        "reconciliation_key", "discovery_source", "agent_id",
        "severity", "summary", "details", "scan_run_id",
    )

    def __init__(
        self,
        *,
        event_id: UUID,
        occurred_at: datetime,
        tenant_id: str,
        kind: DriftEventKind,
        reconciliation_key: str,
        discovery_source: str | None,
        agent_id: UUID | None,
        severity: str,
        summary: str,
        details: dict,
        scan_run_id: UUID | None,
    ) -> None:
        self.event_id = event_id
        self.occurred_at = occurred_at
        self.tenant_id = tenant_id
        self.kind = kind
        self.reconciliation_key = reconciliation_key
        self.discovery_source = discovery_source
        self.agent_id = agent_id
        self.severity = severity
        self.summary = summary
        self.details = details
        self.scan_run_id = scan_run_id

    def to_dict(self) -> dict:
        return {
            "event_id": str(self.event_id),
            "occurred_at": self.occurred_at.isoformat(),
            "tenant_id": self.tenant_id,
            "kind": str(self.kind),
            "reconciliation_key": self.reconciliation_key,
            "discovery_source": self.discovery_source,
            "agent_id": str(self.agent_id) if self.agent_id else None,
            "severity": self.severity,
            "summary": self.summary,
            "details": self.details,
            "scan_run_id": str(self.scan_run_id) if self.scan_run_id else None,
        }


class DriftEventStore:
    """
    Append-only drift event log with optional Postgres persistence.

    Reads from the in-memory ring buffer (bounded; oldest events
    rolled out at ``cache_limit``). When a deeper read is needed,
    the API can hit Postgres directly through ``query_history``.
    """

    __slots__ = (
        "_lock", "_dsn", "_disabled", "_buffer", "_cache_limit",
    )

    def __init__(
        self,
        *,
        dsn: str | None = None,
        cache_limit: int = 1_000,
    ) -> None:
        self._lock = threading.RLock()
        self._dsn = dsn or os.environ.get(DATABASE_URL_ENV, "").strip()
        self._disabled = not bool(self._dsn)
        self._buffer: deque[DriftEvent] = deque(maxlen=cache_limit)
        self._cache_limit = cache_limit

        if self._disabled:
            _logger.warning(
                "DriftEventStore: %s not set; running in pure in-memory mode.",
                DATABASE_URL_ENV,
            )
            return

        try:
            self._ensure_schema()
        except Exception as exc:  # noqa: BLE001
            _logger.error(
                "DriftEventStore: schema bootstrap failed: %s. "
                "Falling back to in-memory mode.",
                exc,
            )
            self._disabled = True

    # ------------------------------------------------------------------ writes

    def emit(
        self,
        *,
        tenant_id: str,
        kind: DriftEventKind,
        reconciliation_key: str,
        discovery_source: str | None = None,
        agent_id: UUID | None = None,
        severity: str = "INFO",
        summary: str,
        details: dict | None = None,
        scan_run_id: UUID | None = None,
    ) -> DriftEvent:
        event = DriftEvent(
            event_id=uuid4(),
            occurred_at=datetime.now(UTC),
            tenant_id=tenant_id,
            kind=kind,
            reconciliation_key=reconciliation_key,
            discovery_source=discovery_source,
            agent_id=agent_id,
            severity=severity,
            summary=summary,
            details=details or {},
            scan_run_id=scan_run_id,
        )
        with self._lock:
            self._buffer.append(event)
            if not self._disabled:
                try:
                    self._flush(event)
                except Exception as exc:  # noqa: BLE001
                    _logger.error(
                        "DriftEventStore: write failed for event=%s: %s",
                        event.event_id, exc,
                    )
        return event

    # ------------------------------------------------------------------ reads

    def list_recent(self, *, limit: int = 100) -> list[DriftEvent]:
        with self._lock:
            return list(reversed(list(self._buffer)))[:limit]

    def list_for_tenant(
        self, tenant_id: str, *, limit: int = 100
    ) -> list[DriftEvent]:
        with self._lock:
            matching = [e for e in self._buffer if e.tenant_id == tenant_id]
        return list(reversed(matching))[:limit]

    def list_by_kind(
        self, kind: DriftEventKind, *, limit: int = 100
    ) -> list[DriftEvent]:
        with self._lock:
            matching = [e for e in self._buffer if e.kind is kind]
        return list(reversed(matching))[:limit]

    def query_history(
        self,
        *,
        tenant_id: str | None = None,
        kind: DriftEventKind | None = None,
        limit: int = 500,
    ) -> list[DriftEvent]:
        """
        Postgres-backed deeper history. When persistence is disabled,
        falls back to the in-memory buffer.
        """
        if self._disabled:
            with self._lock:
                snapshot = list(self._buffer)
            results = list(reversed(snapshot))
            if tenant_id is not None:
                results = [e for e in results if e.tenant_id == tenant_id]
            if kind is not None:
                results = [e for e in results if e.kind is kind]
            return results[:limit]
        try:
            return self._query_postgres(tenant_id=tenant_id, kind=kind, limit=limit)
        except Exception as exc:  # noqa: BLE001
            _logger.error("DriftEventStore: query_history failed: %s", exc)
            return self.list_recent(limit=limit)

    @property
    def is_durable(self) -> bool:
        return not self._disabled

    def __len__(self) -> int:
        with self._lock:
            return len(self._buffer)

    # ------------------------------------------------------------------ internals

    def _ensure_schema(self) -> None:
        with psycopg.connect(self._dsn, autocommit=True) as conn:
            with conn.cursor() as cur:
                cur.execute(SCHEMA_SQL)

    def _flush(self, event: DriftEvent) -> None:
        with psycopg.connect(self._dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO tex_drift_events (
                        event_id, occurred_at, tenant_id, kind,
                        reconciliation_key, discovery_source, agent_id,
                        severity, summary, details, scan_run_id
                    ) VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                    )
                    """,
                    (
                        str(event.event_id), event.occurred_at,
                        event.tenant_id, str(event.kind),
                        event.reconciliation_key, event.discovery_source,
                        str(event.agent_id) if event.agent_id else None,
                        event.severity, event.summary,
                        Jsonb(event.details),
                        str(event.scan_run_id) if event.scan_run_id else None,
                    ),
                )
            conn.commit()

    def _query_postgres(
        self,
        *,
        tenant_id: str | None,
        kind: DriftEventKind | None,
        limit: int,
    ) -> list[DriftEvent]:
        clauses: list[str] = []
        params: list[Any] = []
        if tenant_id is not None:
            clauses.append("tenant_id = %s")
            params.append(tenant_id)
        if kind is not None:
            clauses.append("kind = %s")
            params.append(str(kind))
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(limit)

        with psycopg.connect(self._dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    f"""
                    SELECT event_id, occurred_at, tenant_id, kind,
                           reconciliation_key, discovery_source, agent_id,
                           severity, summary, details, scan_run_id
                      FROM tex_drift_events
                      {where}
                     ORDER BY occurred_at DESC
                     LIMIT %s
                    """,
                    tuple(params),
                )
                rows = cur.fetchall()
        return [
            DriftEvent(
                event_id=UUID(str(r[0])),
                occurred_at=_ensure_aware(r[1]),
                tenant_id=r[2],
                kind=DriftEventKind(r[3]),
                reconciliation_key=r[4],
                discovery_source=r[5],
                agent_id=UUID(str(r[6])) if r[6] else None,
                severity=r[7],
                summary=r[8],
                details=r[9] or {},
                scan_run_id=UUID(str(r[10])) if r[10] else None,
            )
            for r in rows
        ]


def _ensure_aware(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=UTC)
    return value


__all__ = ["DriftEvent", "DriftEventKind", "DriftEventStore", "DATABASE_URL_ENV"]

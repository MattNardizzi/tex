"""
Scan-run store: per-tenant locking, idempotency, durable run records.

Discovery scans were a fire-and-forget operation in V14/V15. That left
five gaps:

1. **Idempotency.** Re-POSTing /v1/discovery/scan with the same
   intent created a fresh run every time. Replays of a webhook or a
   nervous operator clicking twice each produced their own ledger
   entries.

2. **Per-tenant locking.** The synchronous scan endpoint and the
   background scheduler could run concurrently for the same tenant.
   Two scans interleaving their reconciliation against the registry
   is the canonical way to corrupt the discovery ledger.

3. **Snapshot binding.** Governance snapshots had a coverage hash
   but nothing to tie them back to which scan produced the registry
   state they captured.

4. **Soft disappearance.** Drift detection treated "agent missing
   from this scan" as immediate AGENT_DISAPPEARED. One flaky API
   response would mark a real agent gone.

5. **Observability.** "When did the last scan finish, what did it
   find, did it succeed" had no canonical answer.

This module is the spine that closes all five. Every scan — manual or
scheduled — opens a ScanRun row, holds a per-tenant lock for its
lifetime, and closes the row with a summary. Everything else
(snapshots, drift, system state) reads from this store.

Persistence follows the same write-through pattern as the registry
and ledger: in-memory cache + synchronous Postgres flush when
DATABASE_URL is set, pure in-memory otherwise.
"""

from __future__ import annotations

import logging
import os
import threading
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

import psycopg
from psycopg.types.json import Jsonb

_logger = logging.getLogger(__name__)

DATABASE_URL_ENV = "DATABASE_URL"

# A held lock that has not been refreshed in this long is considered
# stale — the holder probably crashed. The lock acquirer can break it
# rather than block forever. Generous default; scans should never run
# this long.
DEFAULT_LOCK_STALE_SECONDS = 30 * 60  # 30 minutes


class ScanRunStatus(StrEnum):
    """Lifecycle of one scan run."""

    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS tex_scan_runs (
    run_id              UUID PRIMARY KEY,
    tenant_id           TEXT NOT NULL,
    status              TEXT NOT NULL,
    started_at          TIMESTAMPTZ NOT NULL,
    completed_at        TIMESTAMPTZ,
    last_heartbeat_at   TIMESTAMPTZ NOT NULL,
    trigger             TEXT NOT NULL,
    idempotency_key     TEXT,
    ledger_seq_start    INTEGER,
    ledger_seq_end      INTEGER,
    registry_state_hash TEXT,
    policy_version      TEXT,
    summary             JSONB,
    error               TEXT
);

CREATE INDEX IF NOT EXISTS tex_scan_runs_tenant_started_idx
    ON tex_scan_runs (tenant_id, started_at DESC);

-- Per-tenant active-run uniqueness. A scan can only be "running"
-- for a given tenant if no other RUNNING row exists. This is the
-- enforcement point for the per-tenant scan lock.
CREATE UNIQUE INDEX IF NOT EXISTS tex_scan_runs_tenant_active_idx
    ON tex_scan_runs (tenant_id) WHERE status = 'running';

-- Idempotency: same (tenant, idempotency_key) is the same logical
-- scan request. Repeats return the original run_id rather than
-- starting a new run.
CREATE UNIQUE INDEX IF NOT EXISTS tex_scan_runs_idem_idx
    ON tex_scan_runs (tenant_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL;
"""


class ScanLockHeld(RuntimeError):
    """Raised when a scan is already running for a tenant."""

    def __init__(self, *, tenant_id: str, holder_run_id: UUID) -> None:
        self.tenant_id = tenant_id
        self.holder_run_id = holder_run_id
        super().__init__(
            f"scan already running for tenant={tenant_id} (run_id={holder_run_id})"
        )


class ScanRun:
    """In-memory shape of one scan-run record."""

    __slots__ = (
        "run_id", "tenant_id", "status", "started_at", "completed_at",
        "last_heartbeat_at", "trigger", "idempotency_key",
        "ledger_seq_start", "ledger_seq_end", "registry_state_hash",
        "policy_version", "summary", "error",
    )

    def __init__(
        self,
        *,
        run_id: UUID,
        tenant_id: str,
        status: ScanRunStatus,
        started_at: datetime,
        last_heartbeat_at: datetime,
        trigger: str,
        completed_at: datetime | None = None,
        idempotency_key: str | None = None,
        ledger_seq_start: int | None = None,
        ledger_seq_end: int | None = None,
        registry_state_hash: str | None = None,
        policy_version: str | None = None,
        summary: dict | None = None,
        error: str | None = None,
    ) -> None:
        self.run_id = run_id
        self.tenant_id = tenant_id
        self.status = status
        self.started_at = started_at
        self.completed_at = completed_at
        self.last_heartbeat_at = last_heartbeat_at
        self.trigger = trigger
        self.idempotency_key = idempotency_key
        self.ledger_seq_start = ledger_seq_start
        self.ledger_seq_end = ledger_seq_end
        self.registry_state_hash = registry_state_hash
        self.policy_version = policy_version
        self.summary = summary or {}
        self.error = error

    def to_dict(self) -> dict:
        return {
            "run_id": str(self.run_id),
            "tenant_id": self.tenant_id,
            "status": str(self.status),
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "last_heartbeat_at": self.last_heartbeat_at.isoformat(),
            "trigger": self.trigger,
            "idempotency_key": self.idempotency_key,
            "ledger_seq_start": self.ledger_seq_start,
            "ledger_seq_end": self.ledger_seq_end,
            "registry_state_hash": self.registry_state_hash,
            "policy_version": self.policy_version,
            "summary": self.summary,
            "error": self.error,
        }

    @property
    def duration_seconds(self) -> float | None:
        if self.completed_at is None:
            return None
        return (self.completed_at - self.started_at).total_seconds()


class ScanRunStore:
    """
    Durable scan-run store.

    All operations go through this store. The discovery service
    opens a run on scan start, refreshes its heartbeat, and closes
    it (success or failure) before returning. The `acquire` method
    is the per-tenant lock — it succeeds only if no other RUNNING
    row exists for the tenant.

    On Postgres backends the unique partial index enforces this at
    the database level, so even a process crash that fails to
    release the lock cannot lock the tenant out forever — the
    `stale_lock_seconds` parameter lets a fresh acquire reclaim a
    run whose heartbeat is older than the cutoff.
    """

    __slots__ = (
        "_lock", "_dsn", "_disabled", "_runs", "_active_by_tenant",
        "_stale_lock_seconds",
    )

    def __init__(
        self,
        *,
        dsn: str | None = None,
        stale_lock_seconds: int = DEFAULT_LOCK_STALE_SECONDS,
    ) -> None:
        self._lock = threading.RLock()
        self._dsn = dsn or os.environ.get(DATABASE_URL_ENV, "").strip()
        self._disabled = not bool(self._dsn)
        self._runs: dict[UUID, ScanRun] = {}
        # tenant_id -> run_id of the currently active run, if any.
        self._active_by_tenant: dict[str, UUID] = {}
        self._stale_lock_seconds = stale_lock_seconds

        if self._disabled:
            _logger.warning(
                "ScanRunStore: %s not set; scan-run history will not survive "
                "restarts.",
                DATABASE_URL_ENV,
            )
            return

        try:
            self._ensure_schema()
        except Exception as exc:  # noqa: BLE001
            _logger.error(
                "ScanRunStore: schema bootstrap failed: %s. "
                "Falling back to in-memory mode.",
                exc,
            )
            self._disabled = True

    # ------------------------------------------------------------------ acquire / heartbeat / close

    def acquire(
        self,
        *,
        tenant_id: str,
        trigger: str,
        idempotency_key: str | None = None,
    ) -> tuple[ScanRun, bool]:
        """
        Open a new scan-run row for the tenant.

        Returns a tuple ``(run, is_new)``. When ``is_new`` is False, the
        returned run is an existing run — either the active holder of
        the tenant lock, OR a previously completed run that matches the
        provided idempotency_key.

        Raises ``ScanLockHeld`` only when the lock is held by another
        run AND idempotency does not let us return that run.
        """
        normalized_tenant = tenant_id.strip().casefold()
        with self._lock:
            # 1. Idempotency: if this idempotency_key was already used
            # for this tenant, return the existing run.
            if idempotency_key:
                existing = self._find_by_idempotency_key(
                    tenant_id=normalized_tenant,
                    idempotency_key=idempotency_key,
                )
                if existing is not None:
                    return existing, False

            # 2. Lock check.
            holder_id = self._active_by_tenant.get(normalized_tenant)
            if holder_id is not None:
                holder = self._runs.get(holder_id)
                if holder is not None and not self._is_stale(holder):
                    raise ScanLockHeld(
                        tenant_id=normalized_tenant,
                        holder_run_id=holder.run_id,
                    )
                # Stale: mark the prior holder as failed and let a new
                # run take the lock.
                if holder is not None:
                    self._fail_in_place(
                        holder,
                        error="lock_holder_stale_reclaimed",
                    )

            # 3. Open a fresh run.
            now = datetime.now(UTC)
            run = ScanRun(
                run_id=uuid4(),
                tenant_id=normalized_tenant,
                status=ScanRunStatus.RUNNING,
                started_at=now,
                last_heartbeat_at=now,
                trigger=trigger,
                idempotency_key=idempotency_key,
            )
            self._runs[run.run_id] = run
            self._active_by_tenant[normalized_tenant] = run.run_id

            if not self._disabled:
                try:
                    self._flush_insert(run)
                except psycopg.errors.UniqueViolation:
                    # The DB-side partial index says someone else has
                    # the lock. Re-read it and raise.
                    self._runs.pop(run.run_id, None)
                    self._active_by_tenant.pop(normalized_tenant, None)
                    db_holder = self._load_active_for_tenant(normalized_tenant)
                    if db_holder is not None:
                        self._runs[db_holder.run_id] = db_holder
                        self._active_by_tenant[normalized_tenant] = db_holder.run_id
                        raise ScanLockHeld(
                            tenant_id=normalized_tenant,
                            holder_run_id=db_holder.run_id,
                        ) from None
                    raise
                except Exception as exc:  # noqa: BLE001
                    _logger.error(
                        "ScanRunStore: insert failed for run=%s: %s. "
                        "Run kept in-memory only.",
                        run.run_id, exc,
                    )

            return run, True

    def heartbeat(self, run_id: UUID) -> None:
        """Refresh the heartbeat on an active run."""
        with self._lock:
            run = self._runs.get(run_id)
            if run is None or run.status is not ScanRunStatus.RUNNING:
                return
            run.last_heartbeat_at = datetime.now(UTC)
            if not self._disabled:
                try:
                    self._flush_heartbeat(run)
                except Exception as exc:  # noqa: BLE001
                    _logger.warning(
                        "ScanRunStore: heartbeat flush failed for run=%s: %s",
                        run_id, exc,
                    )

    def complete(
        self,
        run_id: UUID,
        *,
        ledger_seq_start: int | None,
        ledger_seq_end: int | None,
        registry_state_hash: str | None,
        policy_version: str | None,
        summary: dict,
    ) -> ScanRun | None:
        """Close a run as COMPLETED and release the tenant lock."""
        with self._lock:
            run = self._runs.get(run_id)
            if run is None:
                return None
            run.status = ScanRunStatus.COMPLETED
            run.completed_at = datetime.now(UTC)
            run.last_heartbeat_at = run.completed_at
            run.ledger_seq_start = ledger_seq_start
            run.ledger_seq_end = ledger_seq_end
            run.registry_state_hash = registry_state_hash
            run.policy_version = policy_version
            run.summary = summary
            if self._active_by_tenant.get(run.tenant_id) == run_id:
                self._active_by_tenant.pop(run.tenant_id, None)
            if not self._disabled:
                try:
                    self._flush_close(run)
                except Exception as exc:  # noqa: BLE001
                    _logger.error(
                        "ScanRunStore: close flush failed for run=%s: %s",
                        run_id, exc,
                    )
            return run

    def fail(self, run_id: UUID, *, error: str) -> ScanRun | None:
        """Close a run as FAILED and release the tenant lock."""
        with self._lock:
            run = self._runs.get(run_id)
            if run is None:
                return None
            self._fail_in_place(run, error=error)
            return run

    def _fail_in_place(self, run: ScanRun, *, error: str) -> None:
        run.status = ScanRunStatus.FAILED
        run.completed_at = datetime.now(UTC)
        run.last_heartbeat_at = run.completed_at
        run.error = error
        if self._active_by_tenant.get(run.tenant_id) == run.run_id:
            self._active_by_tenant.pop(run.tenant_id, None)
        if not self._disabled:
            try:
                self._flush_close(run)
            except Exception as exc:  # noqa: BLE001
                _logger.error(
                    "ScanRunStore: fail flush failed for run=%s: %s",
                    run.run_id, exc,
                )

    # ------------------------------------------------------------------ reads

    def get(self, run_id: UUID) -> ScanRun | None:
        with self._lock:
            cached = self._runs.get(run_id)
        if cached is not None:
            return cached
        if self._disabled:
            return None
        try:
            return self._load_one(run_id)
        except Exception as exc:  # noqa: BLE001
            _logger.error("ScanRunStore: load %s failed: %s", run_id, exc)
            return None

    def list_recent(
        self,
        *,
        tenant_id: str | None = None,
        limit: int = 100,
    ) -> list[ScanRun]:
        with self._lock:
            cached = list(self._runs.values())
        cached.sort(key=lambda r: r.started_at, reverse=True)
        if tenant_id is not None:
            normalized = tenant_id.strip().casefold()
            cached = [r for r in cached if r.tenant_id == normalized]
        if len(cached) >= limit:
            return cached[:limit]
        if self._disabled:
            return cached[:limit]
        try:
            return self._load_recent(tenant_id=tenant_id, limit=limit)
        except Exception as exc:  # noqa: BLE001
            _logger.error("ScanRunStore: list_recent failed: %s", exc)
            return cached[:limit]

    def active_for_tenant(self, tenant_id: str) -> ScanRun | None:
        normalized = tenant_id.strip().casefold()
        with self._lock:
            run_id = self._active_by_tenant.get(normalized)
            if run_id is None:
                return None
            return self._runs.get(run_id)

    def latest_completed_for_tenant(self, tenant_id: str) -> ScanRun | None:
        normalized = tenant_id.strip().casefold()
        with self._lock:
            candidates = [
                r for r in self._runs.values()
                if r.tenant_id == normalized
                and r.status is ScanRunStatus.COMPLETED
            ]
        if candidates:
            candidates.sort(key=lambda r: r.completed_at or r.started_at, reverse=True)
            return candidates[0]
        if self._disabled:
            return None
        try:
            recent = self._load_recent(tenant_id=normalized, limit=10)
        except Exception:  # noqa: BLE001
            return None
        for r in recent:
            if r.status is ScanRunStatus.COMPLETED:
                return r
        return None

    @property
    def is_durable(self) -> bool:
        return not self._disabled

    # ------------------------------------------------------------------ internals

    def _is_stale(self, run: ScanRun) -> bool:
        if run.status is not ScanRunStatus.RUNNING:
            return False
        cutoff = datetime.now(UTC) - timedelta(seconds=self._stale_lock_seconds)
        return run.last_heartbeat_at < cutoff

    def _find_by_idempotency_key(
        self, *, tenant_id: str, idempotency_key: str,
    ) -> ScanRun | None:
        for r in self._runs.values():
            if r.tenant_id == tenant_id and r.idempotency_key == idempotency_key:
                return r
        if self._disabled:
            return None
        try:
            return self._load_by_idempotency_key(
                tenant_id=tenant_id,
                idempotency_key=idempotency_key,
            )
        except Exception as exc:  # noqa: BLE001
            _logger.warning(
                "ScanRunStore: idempotency lookup failed: %s", exc,
            )
            return None

    def _ensure_schema(self) -> None:
        with psycopg.connect(self._dsn, autocommit=True) as conn:
            with conn.cursor() as cur:
                cur.execute(SCHEMA_SQL)

    def _flush_insert(self, run: ScanRun) -> None:
        with psycopg.connect(self._dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO tex_scan_runs (
                        run_id, tenant_id, status, started_at,
                        last_heartbeat_at, trigger, idempotency_key,
                        completed_at, ledger_seq_start, ledger_seq_end,
                        registry_state_hash, policy_version, summary, error
                    ) VALUES (
                        %s, %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s, %s
                    )
                    """,
                    (
                        str(run.run_id), run.tenant_id, str(run.status),
                        run.started_at, run.last_heartbeat_at,
                        run.trigger, run.idempotency_key,
                        run.completed_at, run.ledger_seq_start, run.ledger_seq_end,
                        run.registry_state_hash, run.policy_version,
                        Jsonb(run.summary) if run.summary else None,
                        run.error,
                    ),
                )
            conn.commit()

    def _flush_heartbeat(self, run: ScanRun) -> None:
        with psycopg.connect(self._dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE tex_scan_runs
                       SET last_heartbeat_at = %s
                     WHERE run_id = %s
                    """,
                    (run.last_heartbeat_at, str(run.run_id)),
                )
            conn.commit()

    def _flush_close(self, run: ScanRun) -> None:
        with psycopg.connect(self._dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE tex_scan_runs
                       SET status = %s,
                           completed_at = %s,
                           last_heartbeat_at = %s,
                           ledger_seq_start = %s,
                           ledger_seq_end = %s,
                           registry_state_hash = %s,
                           policy_version = %s,
                           summary = %s,
                           error = %s
                     WHERE run_id = %s
                    """,
                    (
                        str(run.status),
                        run.completed_at,
                        run.last_heartbeat_at,
                        run.ledger_seq_start,
                        run.ledger_seq_end,
                        run.registry_state_hash,
                        run.policy_version,
                        Jsonb(run.summary) if run.summary else None,
                        run.error,
                        str(run.run_id),
                    ),
                )
            conn.commit()

    def _load_one(self, run_id: UUID) -> ScanRun | None:
        with psycopg.connect(self._dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(_SELECT_SQL + " WHERE run_id = %s", (str(run_id),))
                row = cur.fetchone()
        return _row_to_run(row) if row else None

    def _load_recent(
        self, *, tenant_id: str | None, limit: int,
    ) -> list[ScanRun]:
        clauses: list[str] = []
        params: list[Any] = []
        if tenant_id is not None:
            clauses.append("tenant_id = %s")
            params.append(tenant_id.strip().casefold())
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(limit)
        with psycopg.connect(self._dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    f"{_SELECT_SQL} {where} ORDER BY started_at DESC LIMIT %s",
                    tuple(params),
                )
                rows = cur.fetchall()
        return [_row_to_run(r) for r in rows]

    def _load_active_for_tenant(self, tenant_id: str) -> ScanRun | None:
        with psycopg.connect(self._dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    _SELECT_SQL + " WHERE tenant_id = %s AND status = 'running' LIMIT 1",
                    (tenant_id,),
                )
                row = cur.fetchone()
        return _row_to_run(row) if row else None

    def _load_by_idempotency_key(
        self, *, tenant_id: str, idempotency_key: str,
    ) -> ScanRun | None:
        with psycopg.connect(self._dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    _SELECT_SQL
                    + " WHERE tenant_id = %s AND idempotency_key = %s LIMIT 1",
                    (tenant_id, idempotency_key),
                )
                row = cur.fetchone()
        return _row_to_run(row) if row else None


_SELECT_SQL = """
SELECT run_id, tenant_id, status, started_at, completed_at,
       last_heartbeat_at, trigger, idempotency_key,
       ledger_seq_start, ledger_seq_end, registry_state_hash,
       policy_version, summary, error
  FROM tex_scan_runs
"""


def _row_to_run(row: tuple) -> ScanRun:
    return ScanRun(
        run_id=UUID(str(row[0])),
        tenant_id=row[1],
        status=ScanRunStatus(row[2]),
        started_at=_aware(row[3]),
        completed_at=_aware(row[4]) if row[4] else None,
        last_heartbeat_at=_aware(row[5]),
        trigger=row[6],
        idempotency_key=row[7],
        ledger_seq_start=row[8],
        ledger_seq_end=row[9],
        registry_state_hash=row[10],
        policy_version=row[11],
        summary=row[12] or {},
        error=row[13],
    )


def _aware(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=UTC)
    return value


__all__ = [
    "ScanRunStore",
    "ScanRun",
    "ScanRunStatus",
    "ScanLockHeld",
    "DATABASE_URL_ENV",
]

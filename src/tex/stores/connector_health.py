"""
Connector health store.

Discovery connectors fail. Auth tokens expire, rate limits get hit,
APIs deprecate fields. Before this module, the only sign of a sick
connector was a string in ``DiscoveryScanRun.errors`` — buried in
the last run's summary, lost after a restart.

This store tracks formal health per ``(tenant_id, connector_name)``:

  - last_success_at      — last clean scan
  - last_failure_at      — last error (auth, network, schema)
  - last_error           — short text of the most recent failure
  - consecutive_failures — count of failures since the last success
  - last_candidate_count — what the last successful scan returned
  - status               — HEALTHY | DEGRADED | OFFLINE | UNKNOWN

Status thresholds are deliberately simple:

  - 0 consecutive failures + a recent success    → HEALTHY
  - 1-2 consecutive failures                     → DEGRADED
  - 3+ consecutive failures                      → OFFLINE
  - never seen a result                          → UNKNOWN

These are derived on read, not stored, so a threshold change does
not require a data migration.

Persistence: write-through to Postgres when DATABASE_URL is set,
in-memory otherwise. Same pattern as the registry, ledger, and
drift store.
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


class ConnectorHealthStatus(StrEnum):
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    OFFLINE = "OFFLINE"
    UNKNOWN = "UNKNOWN"


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS tex_connector_health (
    tenant_id              TEXT NOT NULL,
    connector_name         TEXT NOT NULL,
    discovery_source       TEXT NOT NULL,
    last_success_at        TIMESTAMPTZ,
    last_failure_at        TIMESTAMPTZ,
    last_error             TEXT,
    consecutive_failures   INTEGER NOT NULL DEFAULT 0,
    last_candidate_count   INTEGER,
    last_scan_run_id       UUID,
    PRIMARY KEY (tenant_id, connector_name)
);

CREATE INDEX IF NOT EXISTS tex_connector_health_tenant_idx
    ON tex_connector_health (tenant_id);
"""


class ConnectorHealth:
    """In-memory health record for one (tenant, connector)."""

    __slots__ = (
        "tenant_id", "connector_name", "discovery_source",
        "last_success_at", "last_failure_at", "last_error",
        "consecutive_failures", "last_candidate_count",
        "last_scan_run_id",
    )

    def __init__(
        self,
        *,
        tenant_id: str,
        connector_name: str,
        discovery_source: str,
        last_success_at: datetime | None = None,
        last_failure_at: datetime | None = None,
        last_error: str | None = None,
        consecutive_failures: int = 0,
        last_candidate_count: int | None = None,
        last_scan_run_id: str | None = None,
    ) -> None:
        self.tenant_id = tenant_id
        self.connector_name = connector_name
        self.discovery_source = discovery_source
        self.last_success_at = last_success_at
        self.last_failure_at = last_failure_at
        self.last_error = last_error
        self.consecutive_failures = consecutive_failures
        self.last_candidate_count = last_candidate_count
        self.last_scan_run_id = last_scan_run_id

    @property
    def status(self) -> ConnectorHealthStatus:
        if self.last_success_at is None and self.last_failure_at is None:
            return ConnectorHealthStatus.UNKNOWN
        if self.consecutive_failures == 0:
            return ConnectorHealthStatus.HEALTHY
        if self.consecutive_failures < 3:
            return ConnectorHealthStatus.DEGRADED
        return ConnectorHealthStatus.OFFLINE

    def to_dict(self) -> dict:
        return {
            "tenant_id": self.tenant_id,
            "connector_name": self.connector_name,
            "discovery_source": self.discovery_source,
            "status": str(self.status),
            "last_success_at": (
                self.last_success_at.isoformat() if self.last_success_at else None
            ),
            "last_failure_at": (
                self.last_failure_at.isoformat() if self.last_failure_at else None
            ),
            "last_error": self.last_error,
            "consecutive_failures": self.consecutive_failures,
            "last_candidate_count": self.last_candidate_count,
            "last_scan_run_id": self.last_scan_run_id,
        }


class ConnectorHealthStore:
    """
    Append-/upsert-only health store, keyed by (tenant, connector).

    The discovery service calls ``record_success`` or
    ``record_failure`` once per connector per scan. The /v1/system/state
    endpoint reads from ``list_for_tenant`` to surface health to UIs
    and dashboards.
    """

    __slots__ = ("_lock", "_dsn", "_disabled", "_by_key")

    def __init__(self, *, dsn: str | None = None) -> None:
        self._lock = threading.RLock()
        self._dsn = dsn or os.environ.get(DATABASE_URL_ENV, "").strip()
        self._disabled = not bool(self._dsn)
        self._by_key: dict[tuple[str, str], ConnectorHealth] = {}

        if self._disabled:
            _logger.warning(
                "ConnectorHealthStore: %s not set; health will not survive restarts.",
                DATABASE_URL_ENV,
            )
            return

        try:
            self._ensure_schema()
            self._bootstrap()
        except Exception as exc:  # noqa: BLE001
            _logger.error(
                "ConnectorHealthStore: schema bootstrap failed: %s. "
                "Falling back to in-memory mode.",
                exc,
            )
            self._disabled = True

    # ------------------------------------------------------------------ writes

    def record_success(
        self,
        *,
        tenant_id: str,
        connector_name: str,
        discovery_source: str,
        candidate_count: int,
        scan_run_id: str | None = None,
    ) -> ConnectorHealth:
        normalized = tenant_id.strip().casefold()
        key = (normalized, connector_name)
        with self._lock:
            existing = self._by_key.get(key)
            health = ConnectorHealth(
                tenant_id=normalized,
                connector_name=connector_name,
                discovery_source=discovery_source,
                last_success_at=datetime.now(UTC),
                last_failure_at=existing.last_failure_at if existing else None,
                last_error=None,
                consecutive_failures=0,
                last_candidate_count=candidate_count,
                last_scan_run_id=scan_run_id,
            )
            self._by_key[key] = health
            self._safe_flush(health)
            return health

    def record_failure(
        self,
        *,
        tenant_id: str,
        connector_name: str,
        discovery_source: str,
        error: str,
        scan_run_id: str | None = None,
    ) -> ConnectorHealth:
        normalized = tenant_id.strip().casefold()
        key = (normalized, connector_name)
        with self._lock:
            existing = self._by_key.get(key)
            consecutive = (existing.consecutive_failures + 1) if existing else 1
            health = ConnectorHealth(
                tenant_id=normalized,
                connector_name=connector_name,
                discovery_source=discovery_source,
                last_success_at=existing.last_success_at if existing else None,
                last_failure_at=datetime.now(UTC),
                last_error=(error or "")[:500],
                consecutive_failures=consecutive,
                last_candidate_count=(
                    existing.last_candidate_count if existing else None
                ),
                last_scan_run_id=scan_run_id,
            )
            self._by_key[key] = health
            self._safe_flush(health)
            return health

    # ------------------------------------------------------------------ reads

    def get(
        self, *, tenant_id: str, connector_name: str,
    ) -> ConnectorHealth | None:
        normalized = tenant_id.strip().casefold()
        with self._lock:
            return self._by_key.get((normalized, connector_name))

    def list_for_tenant(self, tenant_id: str) -> list[ConnectorHealth]:
        normalized = tenant_id.strip().casefold()
        with self._lock:
            return [
                h for (t, _), h in self._by_key.items() if t == normalized
            ]

    def list_all(self) -> list[ConnectorHealth]:
        with self._lock:
            return list(self._by_key.values())

    @property
    def is_durable(self) -> bool:
        return not self._disabled

    # ------------------------------------------------------------------ internals

    def _safe_flush(self, health: ConnectorHealth) -> None:
        if self._disabled:
            return
        try:
            self._flush_upsert(health)
        except Exception as exc:  # noqa: BLE001
            _logger.error(
                "ConnectorHealthStore: write failed for %s/%s: %s",
                health.tenant_id, health.connector_name, exc,
            )

    def _ensure_schema(self) -> None:
        with psycopg.connect(self._dsn, autocommit=True) as conn:
            with conn.cursor() as cur:
                cur.execute(SCHEMA_SQL)

    def _flush_upsert(self, health: ConnectorHealth) -> None:
        with psycopg.connect(self._dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO tex_connector_health (
                        tenant_id, connector_name, discovery_source,
                        last_success_at, last_failure_at, last_error,
                        consecutive_failures, last_candidate_count,
                        last_scan_run_id
                    ) VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s, %s
                    )
                    ON CONFLICT (tenant_id, connector_name) DO UPDATE SET
                        discovery_source     = EXCLUDED.discovery_source,
                        last_success_at      = EXCLUDED.last_success_at,
                        last_failure_at      = EXCLUDED.last_failure_at,
                        last_error           = EXCLUDED.last_error,
                        consecutive_failures = EXCLUDED.consecutive_failures,
                        last_candidate_count = EXCLUDED.last_candidate_count,
                        last_scan_run_id     = EXCLUDED.last_scan_run_id
                    """,
                    (
                        health.tenant_id,
                        health.connector_name,
                        health.discovery_source,
                        health.last_success_at,
                        health.last_failure_at,
                        health.last_error,
                        health.consecutive_failures,
                        health.last_candidate_count,
                        health.last_scan_run_id,
                    ),
                )
            conn.commit()

    def _bootstrap(self) -> None:
        with psycopg.connect(self._dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT tenant_id, connector_name, discovery_source,
                           last_success_at, last_failure_at, last_error,
                           consecutive_failures, last_candidate_count,
                           last_scan_run_id
                      FROM tex_connector_health
                    """
                )
                rows = cur.fetchall()
        with self._lock:
            for row in rows:
                health = ConnectorHealth(
                    tenant_id=row[0],
                    connector_name=row[1],
                    discovery_source=row[2],
                    last_success_at=_aware(row[3]) if row[3] else None,
                    last_failure_at=_aware(row[4]) if row[4] else None,
                    last_error=row[5],
                    consecutive_failures=row[6] or 0,
                    last_candidate_count=row[7],
                    last_scan_run_id=str(row[8]) if row[8] else None,
                )
                self._by_key[(health.tenant_id, health.connector_name)] = health


def _aware(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=UTC)
    return value


__all__ = [
    "ConnectorHealthStore",
    "ConnectorHealth",
    "ConnectorHealthStatus",
    "DATABASE_URL_ENV",
]

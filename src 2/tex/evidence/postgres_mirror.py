"""
Postgres-backed evidence mirror.

The JSONL ``EvidenceRecorder`` remains the source of truth for the
hash chain. This module adds a durable Postgres mirror so that:

  * evidence survives container restarts (JSONL on a Render container
    is ephemeral)
  * tenants can be partitioned and queried efficiently
  * retention policies can be applied per tenant
  * export integrity can be cross-checked against two sources

Design properties:

1. **Append-only.** Rows are INSERT only. The store never updates a
   row in place. Deletion only happens via ``apply_retention``, which
   is gated by a per-tenant retention window and audited.

2. **Tenant partitioning.** Every row carries ``tenant_id``. The
   recorder pulls the tenant from payload metadata. Indexes are
   tenant-first so per-tenant scans never have to read across
   tenants.

3. **Hash-chain mirror, not authority.** The chain is computed by
   ``EvidenceRecorder``; this store records what was computed. To
   verify integrity, compare ``record_hash`` here with what
   ``EvidenceRecorder.read_all()`` (or its Postgres-backed reader)
   would compute. Mismatch = tampering.

4. **Optional.** When DATABASE_URL is unset, this store no-ops and
   the JSONL recorder continues unchanged.

Wiring lives in ``tex.evidence.recorder.EvidenceRecorder`` via a
``mirror`` parameter that the runtime sets when DATABASE_URL is set.
"""

from __future__ import annotations

import json
import logging
import threading
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import psycopg
from psycopg.types.json import Jsonb

from tex.db.connection import (
    DATABASE_URL_ENV,
    resolve_dsn,
    safe_dsn_for_log,
    with_connection,
)
from tex.domain.evidence import EvidenceRecord

_logger = logging.getLogger(__name__)


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS tex_evidence (
    evidence_id     UUID PRIMARY KEY,
    decision_id     UUID NOT NULL,
    request_id      UUID NOT NULL,
    tenant_id       TEXT NOT NULL DEFAULT 'default',
    record_type     TEXT NOT NULL,
    payload_json    TEXT NOT NULL,
    payload_sha256  TEXT NOT NULL,
    previous_hash   TEXT,
    record_hash     TEXT NOT NULL,
    policy_version  TEXT NOT NULL,
    recorded_at     TIMESTAMPTZ NOT NULL,
    chain_seq       BIGSERIAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_tex_evidence_tenant_seq
    ON tex_evidence (tenant_id, chain_seq);

CREATE INDEX IF NOT EXISTS idx_tex_evidence_decision
    ON tex_evidence (decision_id);

CREATE INDEX IF NOT EXISTS idx_tex_evidence_record_type
    ON tex_evidence (record_type, recorded_at DESC);
"""


def _resolve_tenant_from_payload(payload_json: str) -> str:
    """Best-effort tenant extraction from the canonical payload JSON."""
    try:
        payload = json.loads(payload_json)
    except (json.JSONDecodeError, TypeError):
        return "default"

    if not isinstance(payload, dict):
        return "default"

    metadata = payload.get("metadata")
    if isinstance(metadata, dict):
        tenant = metadata.get("tenant")
        if isinstance(tenant, str) and tenant.strip():
            return tenant.strip()
        # Some pipelines stuff tenant under request.tenant
        request_meta = metadata.get("request")
        if isinstance(request_meta, dict):
            tenant = request_meta.get("tenant")
            if isinstance(tenant, str) and tenant.strip():
                return tenant.strip()

    return "default"


class PostgresEvidenceMirror:
    """
    Append-only Postgres mirror of the evidence hash chain.

    Plug this into ``EvidenceRecorder.with_mirror(...)``. The recorder
    will call ``record(...)`` after every successful JSONL append.
    """

    __slots__ = ("_lock", "_dsn", "_disabled")

    def __init__(self, *, dsn: str | None = None) -> None:
        self._lock = threading.RLock()
        self._dsn = resolve_dsn(dsn)
        self._disabled = not bool(self._dsn)

        if self._disabled:
            _logger.info(
                "PostgresEvidenceMirror: %s not set; mirror disabled (JSONL only).",
                DATABASE_URL_ENV,
            )
            return

        try:
            self._ensure_schema()
        except Exception as exc:  # noqa: BLE001
            _logger.error(
                "PostgresEvidenceMirror: schema bootstrap failed (%s) on %s. "
                "Mirror disabled.",
                exc,
                safe_dsn_for_log(self._dsn),
            )
            self._disabled = True

    @property
    def disabled(self) -> bool:
        return self._disabled

    def record(self, record: EvidenceRecord) -> None:
        """Insert one evidence record. Idempotent on evidence_id."""
        if self._disabled:
            return

        tenant_id = _resolve_tenant_from_payload(record.payload_json)

        with self._lock:
            try:
                with with_connection(self._dsn) as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            INSERT INTO tex_evidence (
                                evidence_id, decision_id, request_id, tenant_id,
                                record_type, payload_json, payload_sha256,
                                previous_hash, record_hash, policy_version,
                                recorded_at
                            ) VALUES (
                                %s, %s, %s, %s,
                                %s, %s, %s,
                                %s, %s, %s,
                                %s
                            )
                            ON CONFLICT (evidence_id) DO NOTHING
                            """,
                            (
                                str(record.evidence_id),
                                str(record.decision_id),
                                str(record.request_id),
                                tenant_id,
                                record.record_type,
                                record.payload_json,
                                record.payload_sha256,
                                record.previous_hash,
                                record.record_hash,
                                record.policy_version,
                                record.recorded_at,
                            ),
                        )
                    conn.commit()
            except Exception as exc:  # noqa: BLE001
                _logger.error(
                    "PostgresEvidenceMirror: insert failed for evidence_id=%s: %s",
                    record.evidence_id,
                    exc,
                )

    # ------------------------------------------------------------------ reads / audit

    def list_for_tenant(
        self,
        tenant_id: str,
        *,
        limit: int = 1000,
    ) -> tuple[EvidenceRecord, ...]:
        """Return evidence records for a tenant in chain order, newest last."""
        if self._disabled:
            return tuple()

        with with_connection(self._dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT evidence_id, decision_id, request_id, record_type,
                           payload_json, payload_sha256, previous_hash, record_hash,
                           policy_version, recorded_at
                      FROM tex_evidence
                     WHERE tenant_id = %s
                     ORDER BY chain_seq ASC
                     LIMIT %s
                    """,
                    (tenant_id, limit),
                )
                rows = cur.fetchall()

        records: list[EvidenceRecord] = []
        for row in rows:
            try:
                records.append(
                    EvidenceRecord(
                        evidence_id=row[0],
                        decision_id=row[1],
                        request_id=row[2],
                        record_type=row[3],
                        payload_json=row[4],
                        payload_sha256=row[5],
                        previous_hash=row[6],
                        record_hash=row[7],
                        policy_version=row[8],
                        recorded_at=row[9],
                    )
                )
            except Exception as exc:  # noqa: BLE001
                _logger.warning(
                    "PostgresEvidenceMirror: skipping malformed evidence row: %s", exc,
                )
        return tuple(records)

    def count_for_tenant(self, tenant_id: str) -> int:
        if self._disabled:
            return 0
        with with_connection(self._dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT COUNT(*) FROM tex_evidence WHERE tenant_id = %s",
                    (tenant_id,),
                )
                row = cur.fetchone()
        return int(row[0]) if row else 0

    def apply_retention(
        self,
        *,
        tenant_id: str,
        keep_days: int,
    ) -> int:
        """
        Delete evidence rows older than ``keep_days`` for one tenant.

        This is the only path that removes evidence rows, and it is
        the responsibility of an explicit operator-initiated retention
        job (cron or admin endpoint). It returns the number of rows
        deleted.

        Audit-by-policy: the retention floor is enforced as ``keep_days
        >= 30``. Tighter retention requires an explicit code change.
        """
        if self._disabled:
            return 0
        if keep_days < 30:
            raise ValueError("retention floor is 30 days; refusing to apply tighter window")

        cutoff = datetime.now(UTC) - timedelta(days=keep_days)
        with with_connection(self._dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM tex_evidence WHERE tenant_id = %s AND recorded_at < %s",
                    (tenant_id, cutoff),
                )
                deleted = cur.rowcount
            conn.commit()

        _logger.info(
            "PostgresEvidenceMirror: retention deleted %d rows for tenant=%s, keep_days=%d",
            deleted,
            tenant_id,
            keep_days,
        )
        return int(deleted)

    # ------------------------------------------------------------------ internals

    def _ensure_schema(self) -> None:
        with with_connection(self._dsn, autocommit=True) as conn:
            with conn.cursor() as cur:
                cur.execute(SCHEMA_SQL)


__all__ = ["PostgresEvidenceMirror", "SCHEMA_SQL"]

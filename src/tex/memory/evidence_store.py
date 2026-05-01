"""
Postgres mirror of the append-only evidence chain.

The locked spec keeps the file-backed JSONL chain as the immutable
audit log (``tex.evidence.recorder.EvidenceRecorder``) AND requires a
``evidence_records`` table for indexed query and export. We provide
both, with one rule: the JSONL file is the *source of truth*, the
table is a *mirror*. If they diverge, the JSONL wins, and the table
gets rebuilt from it.

Why mirror at all
-----------------
JSONL is great for tamper-evidence: every line is signed by the prior
line's hash. It is bad for "show me every FORBID outcome from tenant X
in the last 30 days" — that requires a scan over the whole file. The
mirror is a CRUD-friendly representation of the same records, indexed
on the dimensions auditors actually query.

Append-only at the table level
------------------------------
There is no UPDATE or DELETE path. Mirror writes are INSERT-only and
the unique index on ``record_hash`` makes duplicate inserts a no-op
(via ON CONFLICT DO NOTHING). The chain integrity is verified by the
existing ``verify_evidence_chain`` helper; this store does not
re-verify on every write because the recorder already does.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from threading import RLock
from typing import Iterable
from uuid import UUID

import psycopg

from tex.domain.evidence import EvidenceRecord
from tex.evidence.chain import verify_evidence_chain
from tex.memory._db import connect, database_url, ensure_memory_schema

_logger = logging.getLogger(__name__)


def _utcnow() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class StoredEvidenceRecord:
    record_id: UUID
    tenant_id: str
    kind: str
    aggregate_id: UUID
    request_id: UUID | None
    policy_version: str | None
    payload_json: str
    payload_sha256: str
    record_hash: str
    previous_hash: str | None
    sequence_number: int
    created_at: datetime


class DurableEvidenceStore:
    """
    Mirror writer for the evidence chain. INSERT-ONLY by design.

    Typical wiring: subscribe to the ``EvidenceRecorder``'s append events
    (or call ``mirror_record`` immediately after each append). The
    recorder is sync, so a synchronous mirror keeps the contract simple.
    """

    def __init__(
        self,
        *,
        tenant_id: str = "default",
    ) -> None:
        self._tenant_id = tenant_id
        self._lock = RLock()
        self._postgres_enabled = database_url() is not None

        if not self._postgres_enabled:
            _logger.warning(
                "DurableEvidenceStore: DATABASE_URL not set — mirror is a "
                "no-op. JSONL chain remains the only durable audit log."
            )
            return

        try:
            ensure_memory_schema()
        except Exception:
            _logger.exception(
                "DurableEvidenceStore: schema bootstrap failed — mirror "
                "disabled"
            )
            self._postgres_enabled = False

    # ---- write path ---------------------------------------------------

    def mirror_record(
        self,
        record: EvidenceRecord,
        *,
        kind: str,
        aggregate_id: UUID,
    ) -> None:
        """
        Inserts an evidence record into the mirror table. Idempotent on
        ``record_hash`` — replaying the same record twice is a no-op.
        """
        if not self._postgres_enabled:
            return

        try:
            with connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO tex_evidence_records (
                            record_id, tenant_id, kind, aggregate_id,
                            request_id, policy_version,
                            payload_json, payload_sha256,
                            record_hash, previous_hash,
                            created_at
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (record_hash) DO NOTHING
                        """,
                        (
                            str(record.evidence_id),
                            self._tenant_id,
                            kind,
                            str(aggregate_id),
                            str(record.request_id) if record.request_id else None,
                            record.policy_version,
                            record.payload_json,
                            record.payload_sha256,
                            record.record_hash,
                            record.previous_hash,
                            _utcnow(),
                        ),
                    )
        except psycopg.Error:
            _logger.exception(
                "DurableEvidenceStore: mirror write failed for record %s",
                record.evidence_id,
            )
            raise

    def mirror_chain(self, records: Iterable[EvidenceRecord]) -> int:
        """
        Bulk-mirror a verified chain. Returns the number of rows inserted.
        Verifies the chain before writing — if verification fails, raises
        and writes nothing.
        """
        materialised = tuple(records)
        verification = verify_evidence_chain(materialised)
        if not verification.is_valid:
            raise ValueError(
                f"refusing to mirror invalid chain: "
                f"{verification.issue_count} issues found"
            )

        inserted = 0
        for record in materialised:
            # We don't always know the aggregate_id from the chain alone;
            # parse it from the payload if present, otherwise reuse the
            # decision_id that EvidenceRecord exposes.
            aggregate = (
                record.decision_id
                if hasattr(record, "decision_id") and record.decision_id
                else UUID(int=0)
            )
            kind = self._infer_kind(record)
            self.mirror_record(record, kind=kind, aggregate_id=aggregate)
            inserted += 1
        return inserted

    # ---- read path ----------------------------------------------------

    def list_for_aggregate(
        self,
        aggregate_id: UUID,
    ) -> tuple[StoredEvidenceRecord, ...]:
        if not self._postgres_enabled:
            return tuple()
        try:
            with connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        _SELECT_SQL + " WHERE aggregate_id = %s ORDER BY sequence_number ASC",
                        (str(aggregate_id),),
                    )
                    rows = cur.fetchall()
                    return tuple(_row_to_stored(r) for r in rows)
        except Exception:
            _logger.exception(
                "DurableEvidenceStore: list_for_aggregate failed for %s",
                aggregate_id,
            )
            return tuple()

    def list_recent(
        self,
        *,
        kind: str | None = None,
        limit: int = 100,
    ) -> tuple[StoredEvidenceRecord, ...]:
        if not self._postgres_enabled:
            return tuple()
        try:
            with connect() as conn:
                with conn.cursor() as cur:
                    if kind is None:
                        cur.execute(
                            _SELECT_SQL
                            + " WHERE tenant_id = %s ORDER BY created_at DESC LIMIT %s",
                            (self._tenant_id, limit),
                        )
                    else:
                        cur.execute(
                            _SELECT_SQL
                            + " WHERE tenant_id = %s AND kind = %s "
                            "ORDER BY created_at DESC LIMIT %s",
                            (self._tenant_id, kind, limit),
                        )
                    rows = cur.fetchall()
                    return tuple(_row_to_stored(r) for r in rows)
        except Exception:
            _logger.exception(
                "DurableEvidenceStore: list_recent failed (kind=%s)", kind
            )
            return tuple()

    # ---- internals ----------------------------------------------------

    @staticmethod
    def _infer_kind(record: EvidenceRecord) -> str:
        if hasattr(record, "record_type") and record.record_type:
            return str(record.record_type)
        return "decision"

    @property
    def is_durable(self) -> bool:
        return self._postgres_enabled


_SELECT_SQL = """
SELECT record_id, tenant_id, kind, aggregate_id,
       request_id, policy_version,
       payload_json, payload_sha256,
       record_hash, previous_hash,
       sequence_number, created_at
  FROM tex_evidence_records
"""


def _row_to_stored(row: tuple) -> StoredEvidenceRecord:
    return StoredEvidenceRecord(
        record_id=UUID(str(row[0])),
        tenant_id=row[1],
        kind=row[2],
        aggregate_id=UUID(str(row[3])),
        request_id=UUID(str(row[4])) if row[4] else None,
        policy_version=row[5],
        payload_json=row[6],
        payload_sha256=row[7],
        record_hash=row[8],
        previous_hash=row[9],
        sequence_number=int(row[10]),
        created_at=row[11],
    )

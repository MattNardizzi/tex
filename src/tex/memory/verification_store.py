"""
Durable verification log.

Every permit verification attempt — successful, expired, revoked, reused,
invalid-signature — appends a row to ``tex_verifications``. The log is
the auditable record of who tried to use what, when, and what we said.

Why a separate table from permits
---------------------------------
A permit is one record updated to consumed/revoked over its lifetime.
A verification is one row per attempt; the same permit may be verified
many times before consumption (e.g. dry runs, retries) and we want a
forensic trail of every attempt.

The PermitStore enforces single-use via the ``consumed_at`` column and
the unique nonce index. This store is purely the record of attempts;
it does NOT itself enforce single-use. That's how you keep audit and
enforcement separable — auditors can trust the log even after the
permits table is mutated.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from threading import RLock
from typing import Any
from uuid import UUID, uuid4

import psycopg
from psycopg.types.json import Jsonb

from tex.memory._db import connect, database_url, ensure_memory_schema

_logger = logging.getLogger(__name__)


class VerificationResult(StrEnum):
    """Possible outcomes of a permit verification attempt."""

    VALID = "VALID"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"
    REUSED = "REUSED"
    INVALID_SIG = "INVALID_SIG"
    NOT_FOUND = "NOT_FOUND"


def _utcnow() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class StoredVerification:
    verification_id: UUID
    permit_id: UUID
    tenant_id: str
    result: VerificationResult
    consumed_nonce: str
    reason: str | None
    metadata: dict[str, Any]
    created_at: datetime


class VerificationStore:
    """Append-only verification log with in-memory cache for recent reads."""

    def __init__(
        self,
        *,
        tenant_id: str = "default",
        bootstrap: bool = True,
        cache_size: int = 1000,
    ) -> None:
        self._tenant_id = tenant_id
        self._cache_size = cache_size
        self._lock = RLock()
        self._recent: list[StoredVerification] = []
        self._postgres_enabled = database_url() is not None

        if not self._postgres_enabled:
            _logger.warning(
                "VerificationStore: DATABASE_URL not set — running in pure "
                "in-memory mode. Verification log WILL be lost on restart."
            )
        else:
            try:
                ensure_memory_schema()
            except Exception:
                _logger.exception(
                    "VerificationStore: schema bootstrap failed — falling "
                    "back to in-memory mode"
                )
                self._postgres_enabled = False

        if self._postgres_enabled and bootstrap:
            self._hydrate_recent()

    # ---- write path ---------------------------------------------------

    def record(
        self,
        *,
        permit_id: UUID,
        result: VerificationResult,
        consumed_nonce: str,
        reason: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> StoredVerification:
        record = StoredVerification(
            verification_id=uuid4(),
            permit_id=permit_id,
            tenant_id=self._tenant_id,
            result=result,
            consumed_nonce=consumed_nonce,
            reason=reason,
            metadata=dict(metadata or {}),
            created_at=_utcnow(),
        )

        if self._postgres_enabled:
            self._write_postgres(record)

        with self._lock:
            self._recent.append(record)
            if len(self._recent) > self._cache_size:
                self._recent = self._recent[-self._cache_size :]

        return record

    # ---- read path ----------------------------------------------------

    def list_for_permit(self, permit_id: UUID) -> tuple[StoredVerification, ...]:
        if self._postgres_enabled:
            try:
                with connect() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            _SELECT_SQL + " WHERE permit_id = %s ORDER BY created_at ASC",
                            (str(permit_id),),
                        )
                        rows = cur.fetchall()
                        return tuple(_row_to_verification(r) for r in rows)
            except Exception:
                _logger.exception(
                    "VerificationStore: read failed for permit %s", permit_id
                )
        with self._lock:
            return tuple(v for v in self._recent if v.permit_id == permit_id)

    def list_recent(self, limit: int = 100) -> tuple[StoredVerification, ...]:
        with self._lock:
            return tuple(reversed(self._recent[-limit:]))

    # ---- internals ----------------------------------------------------

    def _write_postgres(self, record: StoredVerification) -> None:
        try:
            with connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO tex_verifications (
                            verification_id, permit_id, tenant_id,
                            result, consumed_nonce, reason,
                            metadata, created_at
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                        """,
                        (
                            str(record.verification_id),
                            str(record.permit_id),
                            record.tenant_id,
                            record.result.value,
                            record.consumed_nonce,
                            record.reason,
                            Jsonb(record.metadata),
                            record.created_at,
                        ),
                    )
        except psycopg.Error:
            _logger.exception(
                "VerificationStore: postgres write failed for %s",
                record.verification_id,
            )
            raise

    def _hydrate_recent(self) -> None:
        try:
            with connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        _SELECT_SQL
                        + " WHERE tenant_id = %s ORDER BY created_at DESC LIMIT %s",
                        (self._tenant_id, self._cache_size),
                    )
                    rows = cur.fetchall()
        except Exception:
            _logger.exception(
                "VerificationStore: hydrate failed — cache will start empty"
            )
            return

        with self._lock:
            self._recent = [_row_to_verification(r) for r in reversed(rows)]

    @property
    def is_durable(self) -> bool:
        return self._postgres_enabled


_SELECT_SQL = """
SELECT verification_id, permit_id, tenant_id,
       result, consumed_nonce, reason,
       metadata, created_at
  FROM tex_verifications
"""


def _row_to_verification(row: tuple[Any, ...]) -> StoredVerification:
    return StoredVerification(
        verification_id=UUID(str(row[0])),
        permit_id=UUID(str(row[1])),
        tenant_id=row[2],
        result=VerificationResult(row[3]),
        consumed_nonce=row[4],
        reason=row[5],
        metadata=dict(row[6] or {}),
        created_at=row[7],
    )

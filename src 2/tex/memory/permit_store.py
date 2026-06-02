"""
Durable permit store.

Permits are signed tokens minted from PERMIT verdicts. Each permit
carries:

  - decision_id   : the PDP decision that authorised release
  - nonce         : a random one-time-use token
  - signature     : HMAC over (permit_id, decision_id, nonce, expiry)
  - expiry        : timestamp after which the permit is invalid

Permits are stored durably so a verifier in another process can
validate a permit it didn't issue. The unique index on
``(tenant_id, nonce)`` makes nonce reuse a constraint violation at the
DB level — the verifier doesn't need to race on consumed_at to detect
double-spend.

The actual cryptographic mint and signature live in
``tex.enforcement.permit`` (or wherever your runtime keeps the secret);
this store is purely the durable record.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from threading import RLock
from typing import Any
from uuid import UUID, uuid4

import psycopg
from psycopg.types.json import Jsonb

from tex.memory._db import connect, database_url, ensure_memory_schema

_logger = logging.getLogger(__name__)


def _utcnow() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class StoredPermit:
    permit_id: UUID
    decision_id: UUID
    tenant_id: str
    nonce: str
    signature: str
    expiry: datetime
    consumed_at: datetime | None
    revoked_at: datetime | None
    metadata: dict[str, Any]
    created_at: datetime

    @property
    def is_active(self) -> bool:
        if self.revoked_at is not None:
            return False
        if self.consumed_at is not None:
            return False
        return self.expiry > _utcnow()


class PermitNotFoundError(KeyError):
    """Raised when a permit lookup fails."""


class PermitStore:
    """
    Durable permit store with in-memory write-through cache.
    """

    def __init__(
        self,
        *,
        tenant_id: str = "default",
        bootstrap: bool = True,
    ) -> None:
        self._tenant_id = tenant_id
        self._lock = RLock()
        self._by_id: dict[UUID, StoredPermit] = {}
        self._by_nonce: dict[str, UUID] = {}
        self._postgres_enabled = database_url() is not None

        if not self._postgres_enabled:
            _logger.warning(
                "PermitStore: DATABASE_URL not set — running in pure "
                "in-memory mode. Permits WILL be lost on restart."
            )
        else:
            try:
                ensure_memory_schema()
            except Exception:
                _logger.exception(
                    "PermitStore: schema bootstrap failed — falling back "
                    "to in-memory mode"
                )
                self._postgres_enabled = False

        if self._postgres_enabled and bootstrap:
            self._hydrate_cache()

    # ---- write path ---------------------------------------------------

    def issue(
        self,
        *,
        decision_id: UUID,
        nonce: str,
        signature: str,
        expiry: datetime,
        metadata: dict[str, Any] | None = None,
    ) -> StoredPermit:
        """
        Records a freshly minted permit. The caller is responsible for
        producing the nonce and signature — this store only persists.
        """
        if not nonce:
            raise ValueError("nonce must be non-empty")
        if not signature:
            raise ValueError("signature must be non-empty")
        if expiry.tzinfo is None:
            raise ValueError("expiry must be timezone-aware")

        permit = StoredPermit(
            permit_id=uuid4(),
            decision_id=decision_id,
            tenant_id=self._tenant_id,
            nonce=nonce,
            signature=signature,
            expiry=expiry,
            consumed_at=None,
            revoked_at=None,
            metadata=dict(metadata or {}),
            created_at=_utcnow(),
        )

        if self._postgres_enabled:
            self._write_postgres(permit)

        with self._lock:
            self._by_id[permit.permit_id] = permit
            self._by_nonce[permit.nonce] = permit.permit_id

        return permit

    def consume(self, permit_id: UUID) -> StoredPermit:
        """
        Marks a permit as consumed. Idempotent: re-consuming returns the
        already-consumed record without raising.
        """
        if self._postgres_enabled:
            try:
                with connect() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            UPDATE tex_permits
                               SET consumed_at = COALESCE(consumed_at, %s)
                             WHERE permit_id = %s
                             RETURNING permit_id
                            """,
                            (_utcnow(), str(permit_id)),
                        )
                        row = cur.fetchone()
                        if row is None:
                            raise PermitNotFoundError(str(permit_id))
            except psycopg.Error:
                _logger.exception(
                    "PermitStore: postgres consume failed for %s", permit_id
                )
                raise

        with self._lock:
            existing = self._by_id.get(permit_id)
            if existing is None:
                # Re-read from postgres if we missed it.
                refreshed = self._read_postgres_by_id(permit_id)
                if refreshed is None:
                    raise PermitNotFoundError(str(permit_id))
                existing = refreshed
                self._by_id[permit_id] = existing
                self._by_nonce[existing.nonce] = permit_id

            updated = StoredPermit(
                permit_id=existing.permit_id,
                decision_id=existing.decision_id,
                tenant_id=existing.tenant_id,
                nonce=existing.nonce,
                signature=existing.signature,
                expiry=existing.expiry,
                consumed_at=existing.consumed_at or _utcnow(),
                revoked_at=existing.revoked_at,
                metadata=existing.metadata,
                created_at=existing.created_at,
            )
            self._by_id[permit_id] = updated
            return updated

    def revoke(self, permit_id: UUID, *, reason: str | None = None) -> StoredPermit:
        if self._postgres_enabled:
            try:
                with connect() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            UPDATE tex_permits
                               SET revoked_at = COALESCE(revoked_at, %s),
                                   metadata   = metadata || %s
                             WHERE permit_id = %s
                             RETURNING permit_id
                            """,
                            (
                                _utcnow(),
                                Jsonb({"revoke_reason": reason} if reason else {}),
                                str(permit_id),
                            ),
                        )
                        row = cur.fetchone()
                        if row is None:
                            raise PermitNotFoundError(str(permit_id))
            except psycopg.Error:
                _logger.exception(
                    "PermitStore: postgres revoke failed for %s", permit_id
                )
                raise

        with self._lock:
            existing = self._by_id.get(permit_id)
            if existing is None:
                raise PermitNotFoundError(str(permit_id))
            metadata = dict(existing.metadata)
            if reason:
                metadata["revoke_reason"] = reason
            updated = StoredPermit(
                permit_id=existing.permit_id,
                decision_id=existing.decision_id,
                tenant_id=existing.tenant_id,
                nonce=existing.nonce,
                signature=existing.signature,
                expiry=existing.expiry,
                consumed_at=existing.consumed_at,
                revoked_at=existing.revoked_at or _utcnow(),
                metadata=metadata,
                created_at=existing.created_at,
            )
            self._by_id[permit_id] = updated
            return updated

    # ---- read path ----------------------------------------------------

    def get(self, permit_id: UUID) -> StoredPermit | None:
        with self._lock:
            cached = self._by_id.get(permit_id)
        if cached is not None:
            return cached
        if not self._postgres_enabled:
            return None
        record = self._read_postgres_by_id(permit_id)
        if record is not None:
            with self._lock:
                self._by_id[permit_id] = record
                self._by_nonce[record.nonce] = permit_id
        return record

    def get_by_nonce(self, nonce: str) -> StoredPermit | None:
        with self._lock:
            permit_id = self._by_nonce.get(nonce)
        if permit_id is not None:
            return self.get(permit_id)
        if not self._postgres_enabled:
            return None
        return self._read_postgres_by_nonce(nonce)

    # ---- internals ----------------------------------------------------

    def _write_postgres(self, permit: StoredPermit) -> None:
        try:
            with connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO tex_permits (
                            permit_id, decision_id, tenant_id,
                            nonce, signature, expiry,
                            metadata, created_at
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                        """,
                        (
                            str(permit.permit_id),
                            str(permit.decision_id),
                            permit.tenant_id,
                            permit.nonce,
                            permit.signature,
                            permit.expiry,
                            Jsonb(permit.metadata),
                            permit.created_at,
                        ),
                    )
        except psycopg.Error:
            _logger.exception(
                "PermitStore: postgres write failed for permit %s",
                permit.permit_id,
            )
            raise

    def _read_postgres_by_id(self, permit_id: UUID) -> StoredPermit | None:
        try:
            with connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(_SELECT_PERMIT_SQL + " WHERE permit_id = %s",
                                (str(permit_id),))
                    row = cur.fetchone()
        except Exception:
            _logger.exception("PermitStore: read failed for permit %s", permit_id)
            return None
        return _row_to_permit(row) if row else None

    def _read_postgres_by_nonce(self, nonce: str) -> StoredPermit | None:
        try:
            with connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        _SELECT_PERMIT_SQL
                        + " WHERE tenant_id = %s AND nonce = %s",
                        (self._tenant_id, nonce),
                    )
                    row = cur.fetchone()
        except Exception:
            _logger.exception("PermitStore: read failed for nonce %s", nonce)
            return None
        return _row_to_permit(row) if row else None

    def _hydrate_cache(self) -> None:
        try:
            with connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        _SELECT_PERMIT_SQL
                        + " WHERE tenant_id = %s ORDER BY created_at DESC LIMIT 5000",
                        (self._tenant_id,),
                    )
                    rows = cur.fetchall()
        except Exception:
            _logger.exception(
                "PermitStore: hydrate failed — cache will start empty"
            )
            return

        with self._lock:
            for row in rows:
                permit = _row_to_permit(row)
                self._by_id[permit.permit_id] = permit
                self._by_nonce[permit.nonce] = permit.permit_id

    @property
    def is_durable(self) -> bool:
        return self._postgres_enabled


_SELECT_PERMIT_SQL = """
SELECT permit_id, decision_id, tenant_id,
       nonce, signature, expiry,
       consumed_at, revoked_at,
       metadata, created_at
  FROM tex_permits
"""


def _row_to_permit(row: tuple[Any, ...]) -> StoredPermit:
    return StoredPermit(
        permit_id=UUID(str(row[0])),
        decision_id=UUID(str(row[1])),
        tenant_id=row[2],
        nonce=row[3],
        signature=row[4],
        expiry=row[5],
        consumed_at=row[6],
        revoked_at=row[7],
        metadata=dict(row[8] or {}),
        created_at=row[9],
    )

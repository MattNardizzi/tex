"""
Durable store for full original request inputs.

The ``Decision`` record captures *what Tex decided* — verdict, scores,
findings, reasons, fingerprints. It does NOT capture the full original
request bytes that produced it (those can be large and are read rarely).
The replay engine needs both, so the locked spec separates them:

    tex_decisions          — the verdict (hot, indexed, frequent reads)
    tex_decision_inputs    — the input bytes (cold, rarely read)

This split keeps the decisions table compact and lets us evict old
inputs independently if storage becomes a concern. The two are joined
by ``request_id``.

In-memory fallback
------------------
If ``DATABASE_URL`` is unset we keep inputs in a process-local dict.
This preserves the local-dev / unit-test ergonomics of the rest of
the memory layer at the cost of losing inputs on restart.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from threading import RLock
from typing import Any
from uuid import UUID

import psycopg
from psycopg.types.json import Jsonb

from tex.memory._db import connect, database_url, ensure_memory_schema

_logger = logging.getLogger(__name__)


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _input_sha256(payload: dict[str, Any]) -> str:
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


@dataclass(frozen=True, slots=True)
class StoredDecisionInput:
    """A full request payload pulled back out of the store."""

    request_id: UUID
    decision_id: UUID | None
    tenant_id: str
    full_input: dict[str, Any]
    input_sha256: str
    created_at: datetime


class DecisionInputStore:
    """
    Durable input store with in-memory write-through cache.

    Behaves the same as the other memory stores: Postgres is the system
    of record, an in-memory dict serves reads fast, ``DATABASE_URL``
    being unset triggers in-memory-only mode with a loud warning.
    """

    def __init__(
        self,
        *,
        tenant_id: str = "default",
        bootstrap: bool = True,
    ) -> None:
        self._tenant_id = tenant_id
        self._lock = RLock()
        self._cache: dict[UUID, StoredDecisionInput] = {}
        self._postgres_enabled = database_url() is not None

        if not self._postgres_enabled:
            _logger.warning(
                "DecisionInputStore: DATABASE_URL not set — running in "
                "pure in-memory mode. Replay across restarts is impossible."
            )
            return

        try:
            ensure_memory_schema()
        except Exception:
            _logger.exception(
                "DecisionInputStore: schema bootstrap failed — falling back "
                "to in-memory mode"
            )
            self._postgres_enabled = False
            return

        if bootstrap:
            self._hydrate_cache()

    # ---- write path ---------------------------------------------------

    def save(
        self,
        *,
        request_id: UUID,
        full_input: dict[str, Any],
        decision_id: UUID | None = None,
    ) -> StoredDecisionInput:
        """
        Stores or replaces the full input payload for a request.

        The ``decision_id`` link is optional at save time because the
        orchestrator typically writes the input *before* it has minted
        a decision_id. ``link_to_decision`` patches it later.
        """
        if not isinstance(full_input, dict):
            raise TypeError("full_input must be a dict")

        sha = _input_sha256(full_input)
        record = StoredDecisionInput(
            request_id=request_id,
            decision_id=decision_id,
            tenant_id=self._tenant_id,
            full_input=dict(full_input),
            input_sha256=sha,
            created_at=_utcnow(),
        )

        if self._postgres_enabled:
            self._write_postgres(record)

        with self._lock:
            self._cache[request_id] = record

        return record

    def save_in_tx(
        self,
        *,
        request_id: UUID,
        full_input: dict[str, Any],
        decision_id: UUID | None,
        cursor: Any,
    ) -> StoredDecisionInput:
        """
        Transactional variant. Caller owns the connection and the
        surrounding transaction.

        Mandatory in the orchestrator's atomic write path: replay
        cannot work without ``tex_decision_inputs``, so the input row
        MUST be in the same transaction as the decision row. Schema
        validation is enforced here — a non-dict input raises before
        any SQL is emitted.
        """
        if not isinstance(full_input, dict):
            raise TypeError("full_input must be a dict")

        sha = _input_sha256(full_input)
        record = StoredDecisionInput(
            request_id=request_id,
            decision_id=decision_id,
            tenant_id=self._tenant_id,
            full_input=dict(full_input),
            input_sha256=sha,
            created_at=_utcnow(),
        )

        if self._postgres_enabled:
            cursor.execute(
                """
                INSERT INTO tex_decision_inputs (
                    request_id, decision_id, tenant_id,
                    full_input, input_sha256, created_at
                ) VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (request_id) DO UPDATE SET
                    decision_id  = EXCLUDED.decision_id,
                    full_input   = EXCLUDED.full_input,
                    input_sha256 = EXCLUDED.input_sha256
                """,
                (
                    str(record.request_id),
                    str(record.decision_id) if record.decision_id else None,
                    record.tenant_id,
                    Jsonb(record.full_input),
                    record.input_sha256,
                    record.created_at,
                ),
            )

        with self._lock:
            self._cache[request_id] = record

        return record

    def link_to_decision(self, *, request_id: UUID, decision_id: UUID) -> None:
        """Updates the decision_id reference for an already-stored input."""
        if self._postgres_enabled:
            try:
                with connect() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            UPDATE tex_decision_inputs
                               SET decision_id = %s
                             WHERE request_id = %s
                            """,
                            (str(decision_id), str(request_id)),
                        )
            except Exception:
                _logger.exception(
                    "DecisionInputStore: postgres link_to_decision failed "
                    "for request %s",
                    request_id,
                )
                raise

        with self._lock:
            existing = self._cache.get(request_id)
            if existing is not None:
                self._cache[request_id] = StoredDecisionInput(
                    request_id=existing.request_id,
                    decision_id=decision_id,
                    tenant_id=existing.tenant_id,
                    full_input=existing.full_input,
                    input_sha256=existing.input_sha256,
                    created_at=existing.created_at,
                )

    # ---- read path ----------------------------------------------------

    def get(self, request_id: UUID) -> StoredDecisionInput | None:
        with self._lock:
            cached = self._cache.get(request_id)
        if cached is not None:
            return cached
        if not self._postgres_enabled:
            return None
        return self._read_postgres(request_id)

    def require(self, request_id: UUID) -> StoredDecisionInput:
        record = self.get(request_id)
        if record is None:
            raise KeyError(f"decision input not found: {request_id}")
        return record

    # ---- internals ----------------------------------------------------

    def _write_postgres(self, record: StoredDecisionInput) -> None:
        try:
            with connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO tex_decision_inputs (
                            request_id, decision_id, tenant_id,
                            full_input, input_sha256, created_at
                        ) VALUES (%s, %s, %s, %s, %s, %s)
                        ON CONFLICT (request_id) DO UPDATE SET
                            decision_id  = EXCLUDED.decision_id,
                            full_input   = EXCLUDED.full_input,
                            input_sha256 = EXCLUDED.input_sha256
                        """,
                        (
                            str(record.request_id),
                            str(record.decision_id) if record.decision_id else None,
                            record.tenant_id,
                            Jsonb(record.full_input),
                            record.input_sha256,
                            record.created_at,
                        ),
                    )
        except psycopg.Error:
            _logger.exception(
                "DecisionInputStore: postgres write failed for request %s",
                record.request_id,
            )
            raise

    def _read_postgres(self, request_id: UUID) -> StoredDecisionInput | None:
        try:
            with connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT request_id, decision_id, tenant_id,
                               full_input, input_sha256, created_at
                          FROM tex_decision_inputs
                         WHERE request_id = %s
                        """,
                        (str(request_id),),
                    )
                    row = cur.fetchone()
        except Exception:
            _logger.exception(
                "DecisionInputStore: postgres read failed for request %s",
                request_id,
            )
            return None

        if row is None:
            return None

        record = StoredDecisionInput(
            request_id=UUID(str(row[0])),
            decision_id=UUID(str(row[1])) if row[1] else None,
            tenant_id=row[2],
            full_input=dict(row[3] or {}),
            input_sha256=row[4],
            created_at=row[5],
        )

        with self._lock:
            self._cache[record.request_id] = record

        return record

    def _hydrate_cache(self) -> None:
        try:
            with connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT request_id, decision_id, tenant_id,
                               full_input, input_sha256, created_at
                          FROM tex_decision_inputs
                         WHERE tenant_id = %s
                         ORDER BY created_at DESC
                         LIMIT 5000
                        """,
                        (self._tenant_id,),
                    )
                    rows = cur.fetchall()
        except Exception:
            _logger.exception(
                "DecisionInputStore: hydrate failed — cache will start empty"
            )
            return

        with self._lock:
            for row in rows:
                rid = UUID(str(row[0]))
                self._cache[rid] = StoredDecisionInput(
                    request_id=rid,
                    decision_id=UUID(str(row[1])) if row[1] else None,
                    tenant_id=row[2],
                    full_input=dict(row[3] or {}),
                    input_sha256=row[4],
                    created_at=row[5],
                )

    @property
    def is_durable(self) -> bool:
        return self._postgres_enabled

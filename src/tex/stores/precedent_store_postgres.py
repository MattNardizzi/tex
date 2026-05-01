"""
Postgres-backed precedent store.

The precedent store is a metadata-projection of decisions used by the
retrieval orchestrator. It does not own the source of truth for
decisions (that is ``decision_store``) — but it is queried on every
evaluation, so durability matters: after a restart the retrieval
layer must still be able to surface prior precedents.

This store mirrors the in-memory implementation's interface exactly
(it is duck-typed by ``RetrievalOrchestrator``). The hot read path
(``find_similar`` / ``retrieve_precedents``) stays in-memory.

When DATABASE_URL is unset, the store degrades to pure in-memory.
"""

from __future__ import annotations

import json
import logging
import threading
from collections.abc import Iterable
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
from tex.domain.decision import Decision
from tex.domain.retrieval import RetrievedPrecedent
from tex.domain.verdict import Verdict
from tex.stores.precedent_store import InMemoryPrecedentStore

_logger = logging.getLogger(__name__)


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS tex_precedents (
    decision_id   UUID PRIMARY KEY,
    tenant_id     TEXT NOT NULL DEFAULT 'default',
    payload_json  JSONB NOT NULL,
    save_seq      BIGSERIAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_tex_precedents_tenant
    ON tex_precedents (tenant_id, save_seq DESC);
"""


def _resolve_tenant(decision: Decision) -> str:
    tenant = decision.metadata.get("tenant") if decision.metadata else None
    if isinstance(tenant, str) and tenant.strip():
        return tenant.strip()
    return "default"


class PostgresPrecedentStore:
    """Durable precedent store. Same interface as ``InMemoryPrecedentStore``."""

    __slots__ = ("_lock", "_cache", "_dsn", "_disabled")

    def __init__(
        self,
        *,
        dsn: str | None = None,
        bootstrap: bool = True,
    ) -> None:
        self._lock = threading.RLock()
        self._cache = InMemoryPrecedentStore()
        self._dsn = resolve_dsn(dsn)
        self._disabled = not bool(self._dsn)

        if self._disabled:
            _logger.warning(
                "PostgresPrecedentStore: %s not set; running in pure in-memory mode.",
                DATABASE_URL_ENV,
            )
            return

        try:
            self._ensure_schema()
        except Exception as exc:  # noqa: BLE001
            _logger.error(
                "PostgresPrecedentStore: schema bootstrap failed (%s) on %s. "
                "Falling back to in-memory.",
                exc,
                safe_dsn_for_log(self._dsn),
            )
            self._disabled = True
            return

        if bootstrap:
            try:
                self._bootstrap_from_postgres()
            except Exception as exc:  # noqa: BLE001
                _logger.error("PostgresPrecedentStore: bootstrap failed: %s", exc)

    # ------------------------------------------------------------------ writes

    def save(self, decision: Decision) -> None:
        with self._lock:
            self._cache.save(decision)
            if self._disabled:
                return
            try:
                self._flush_one(decision)
            except Exception as exc:  # noqa: BLE001
                _logger.error(
                    "PostgresPrecedentStore: flush failed for decision_id=%s: %s",
                    decision.decision_id,
                    exc,
                )

    def save_many(self, decisions: Iterable[Decision]) -> None:
        for decision in decisions:
            self.save(decision)

    def delete(self, decision_id: UUID) -> None:
        with self._lock:
            self._cache.delete(decision_id)
            if self._disabled:
                return
            try:
                with with_connection(self._dsn) as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            "DELETE FROM tex_precedents WHERE decision_id = %s",
                            (str(decision_id),),
                        )
                    conn.commit()
            except Exception as exc:  # noqa: BLE001
                _logger.error(
                    "PostgresPrecedentStore: delete failed for %s: %s",
                    decision_id,
                    exc,
                )

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()
            if self._disabled:
                return
            try:
                with with_connection(self._dsn) as conn:
                    with conn.cursor() as cur:
                        cur.execute("DELETE FROM tex_precedents")
                    conn.commit()
            except Exception as exc:  # noqa: BLE001
                _logger.error("PostgresPrecedentStore: clear failed: %s", exc)

    # ------------------------------------------------------------------ reads

    def get(self, decision_id: UUID) -> RetrievedPrecedent | None:
        return self._cache.get(decision_id)

    def require(self, decision_id: UUID) -> RetrievedPrecedent:
        return self._cache.require(decision_id)

    def get_decision(self, decision_id: UUID) -> Decision | None:
        return self._cache.get_decision(decision_id)

    def list_all(self) -> tuple[RetrievedPrecedent, ...]:
        return self._cache.list_all()

    def find_similar(
        self,
        *,
        action_type: str | None = None,
        channel: str | None = None,
        environment: str | None = None,
        recipient: str | None = None,
        verdict: Verdict | None = None,
        policy_version: str | None = None,
        exclude_decision_id: UUID | None = None,
        limit: int = 10,
    ) -> tuple[RetrievedPrecedent, ...]:
        return self._cache.find_similar(
            action_type=action_type,
            channel=channel,
            environment=environment,
            recipient=recipient,
            verdict=verdict,
            policy_version=policy_version,
            exclude_decision_id=exclude_decision_id,
            limit=limit,
        )

    def retrieve_precedents(self, *, request, limit: int) -> tuple[RetrievedPrecedent, ...]:
        return self._cache.retrieve_precedents(request=request, limit=limit)

    def __len__(self) -> int:
        return len(self._cache)

    def __contains__(self, decision_id: object) -> bool:
        return decision_id in self._cache

    # ------------------------------------------------------------------ internals

    def _ensure_schema(self) -> None:
        with with_connection(self._dsn, autocommit=True) as conn:
            with conn.cursor() as cur:
                cur.execute(SCHEMA_SQL)

    def _flush_one(self, decision: Decision) -> None:
        payload = decision.model_dump(mode="json")
        tenant_id = _resolve_tenant(decision)
        with with_connection(self._dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO tex_precedents (decision_id, tenant_id, payload_json)
                    VALUES (%s, %s, %s)
                    ON CONFLICT (decision_id) DO UPDATE SET
                        tenant_id    = EXCLUDED.tenant_id,
                        payload_json = EXCLUDED.payload_json
                    """,
                    (str(decision.decision_id), tenant_id, Jsonb(payload)),
                )
            conn.commit()

    def _bootstrap_from_postgres(self) -> None:
        with with_connection(self._dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT payload_json FROM tex_precedents ORDER BY save_seq ASC"
                )
                rows = cur.fetchall()

        for (payload,) in rows:
            try:
                if isinstance(payload, str):
                    payload = json.loads(payload)
                decision = Decision.model_validate(payload)
                self._cache.save(decision)
            except Exception as exc:  # noqa: BLE001
                _logger.warning(
                    "PostgresPrecedentStore: skipping unreadable row: %s", exc,
                )

        _logger.info(
            "PostgresPrecedentStore: bootstrapped %d precedents from Postgres.",
            len(self._cache),
        )


__all__ = ["PostgresPrecedentStore", "SCHEMA_SQL"]

"""
Postgres-backed decision store.

Drop-in replacement for ``InMemoryDecisionStore`` that persists every
write to Postgres while keeping the read path in-memory. Same write-
through pattern as ``PostgresAgentRegistry`` and the V15/V16 stores:

  reads   → in-memory (microseconds, no I/O)
  writes  → in-memory THEN synchronous Postgres flush
  startup → bootstrap from Postgres into in-memory

When DATABASE_URL is unset, the store degrades to pure in-memory and
logs a warning. The runtime stays up; durability is lost.

This store is the source of truth for every Tex decision the system
emits. Without durability:
  - audit replay across restarts breaks
  - precedent retrieval forgets every prior verdict
  - calibration drift detection loses its decision history
  - evidence export across rolling deploys fragments
  - tenant isolation cannot be reasoned about retroactively

Tenant partitioning lives at the column level (``tenant_id``) and
is indexed for cheap per-tenant scans. The column is populated from
``decision.metadata['tenant']`` when present (which is how the
guardrail layer threads ``TexPrincipal.tenant`` through the call
graph) and falls back to "default" otherwise.
"""

from __future__ import annotations

import json
import logging
import threading
from collections.abc import Iterable
from datetime import UTC, datetime
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
from tex.domain.verdict import Verdict
from tex.stores.decision_store import InMemoryDecisionStore

_logger = logging.getLogger(__name__)


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS tex_decisions (
    decision_id        UUID PRIMARY KEY,
    request_id         UUID NOT NULL,
    tenant_id          TEXT NOT NULL DEFAULT 'default',
    verdict            TEXT NOT NULL,
    confidence         DOUBLE PRECISION NOT NULL,
    final_score        DOUBLE PRECISION NOT NULL,
    action_type        TEXT NOT NULL,
    channel            TEXT NOT NULL,
    environment        TEXT NOT NULL,
    recipient          TEXT,
    content_excerpt    TEXT NOT NULL,
    content_sha256     TEXT NOT NULL,
    policy_id          TEXT,
    policy_version     TEXT NOT NULL,
    payload_json       JSONB NOT NULL,
    decided_at         TIMESTAMPTZ NOT NULL,
    written_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_tex_decisions_tenant
    ON tex_decisions (tenant_id, decided_at DESC);

CREATE INDEX IF NOT EXISTS idx_tex_decisions_request_id
    ON tex_decisions (request_id);

CREATE INDEX IF NOT EXISTS idx_tex_decisions_verdict_policy
    ON tex_decisions (verdict, policy_version);
"""


def _resolve_tenant(decision: Decision) -> str:
    """
    Pull the tenant from decision metadata when present.

    The guardrail and adapter layers thread ``TexPrincipal.tenant``
    into ``decision.metadata['tenant']``. We index that explicitly
    so per-tenant scans don't have to JSON-extract on the hot path.
    """
    tenant = decision.metadata.get("tenant") if decision.metadata else None
    if isinstance(tenant, str) and tenant.strip():
        return tenant.strip()
    return "default"


def _decision_to_payload(decision: Decision) -> dict[str, Any]:
    """Serialize a Decision to a JSON-safe dict for the payload column."""
    return decision.model_dump(mode="json")


def _payload_to_decision(payload: dict[str, Any]) -> Decision:
    """Reconstruct a Decision from its stored JSON payload."""
    return Decision.model_validate(payload)


class PostgresDecisionStore:
    """
    Durable decision store. Same interface as ``InMemoryDecisionStore``.
    """

    __slots__ = ("_lock", "_cache", "_dsn", "_disabled")

    def __init__(
        self,
        *,
        dsn: str | None = None,
        bootstrap: bool = True,
    ) -> None:
        self._lock = threading.RLock()
        self._cache = InMemoryDecisionStore()
        self._dsn = resolve_dsn(dsn)
        self._disabled = not bool(self._dsn)

        if self._disabled:
            _logger.warning(
                "PostgresDecisionStore: %s not set; running in pure in-memory "
                "mode. Decisions will not survive restarts.",
                DATABASE_URL_ENV,
            )
            return

        try:
            self._ensure_schema()
        except Exception as exc:  # noqa: BLE001
            _logger.error(
                "PostgresDecisionStore: schema bootstrap failed (%s) on %s. "
                "Falling back to in-memory mode.",
                exc,
                safe_dsn_for_log(self._dsn),
            )
            self._disabled = True
            return

        if bootstrap:
            try:
                self._bootstrap_from_postgres()
            except Exception as exc:  # noqa: BLE001
                _logger.error(
                    "PostgresDecisionStore: bootstrap from Postgres failed: %s", exc,
                )

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
                    "PostgresDecisionStore: flush failed for decision_id=%s: %s",
                    decision.decision_id,
                    exc,
                )

    def delete(self, decision_id: UUID) -> None:
        with self._lock:
            self._cache.delete(decision_id)
            if self._disabled:
                return
            try:
                with with_connection(self._dsn) as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            "DELETE FROM tex_decisions WHERE decision_id = %s",
                            (str(decision_id),),
                        )
                    conn.commit()
            except Exception as exc:  # noqa: BLE001
                _logger.error(
                    "PostgresDecisionStore: delete failed for decision_id=%s: %s",
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
                        cur.execute("DELETE FROM tex_decisions")
                    conn.commit()
            except Exception as exc:  # noqa: BLE001
                _logger.error("PostgresDecisionStore: clear failed: %s", exc)

    # ------------------------------------------------------------------ reads

    def get(self, decision_id: UUID) -> Decision | None:
        return self._cache.get(decision_id)

    def require(self, decision_id: UUID) -> Decision:
        return self._cache.require(decision_id)

    def get_by_request_id(self, request_id: UUID) -> Decision | None:
        return self._cache.get_by_request_id(request_id)

    def require_by_request_id(self, request_id: UUID) -> Decision:
        return self._cache.require_by_request_id(request_id)

    def list_all(self) -> tuple[Decision, ...]:
        return self._cache.list_all()

    def list_recent(self, limit: int = 50) -> tuple[Decision, ...]:
        return self._cache.list_recent(limit)

    def find(
        self,
        *,
        verdict: Verdict | None = None,
        policy_version: str | None = None,
        channel: str | None = None,
        environment: str | None = None,
        action_type: str | None = None,
        limit: int | None = None,
    ) -> tuple[Decision, ...]:
        return self._cache.find(
            verdict=verdict,
            policy_version=policy_version,
            channel=channel,
            environment=environment,
            action_type=action_type,
            limit=limit,
        )

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
        payload = _decision_to_payload(decision)
        tenant_id = _resolve_tenant(decision)
        with with_connection(self._dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO tex_decisions (
                        decision_id, request_id, tenant_id, verdict, confidence,
                        final_score, action_type, channel, environment, recipient,
                        content_excerpt, content_sha256, policy_id, policy_version,
                        payload_json, decided_at
                    ) VALUES (
                        %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s,
                        %s, %s, %s, %s,
                        %s, %s
                    )
                    ON CONFLICT (decision_id) DO UPDATE SET
                        request_id     = EXCLUDED.request_id,
                        tenant_id      = EXCLUDED.tenant_id,
                        verdict        = EXCLUDED.verdict,
                        confidence     = EXCLUDED.confidence,
                        final_score    = EXCLUDED.final_score,
                        action_type    = EXCLUDED.action_type,
                        channel        = EXCLUDED.channel,
                        environment    = EXCLUDED.environment,
                        recipient      = EXCLUDED.recipient,
                        content_excerpt = EXCLUDED.content_excerpt,
                        content_sha256 = EXCLUDED.content_sha256,
                        policy_id      = EXCLUDED.policy_id,
                        policy_version = EXCLUDED.policy_version,
                        payload_json   = EXCLUDED.payload_json,
                        decided_at     = EXCLUDED.decided_at
                    """,
                    (
                        str(decision.decision_id),
                        str(decision.request_id),
                        tenant_id,
                        decision.verdict.value,
                        decision.confidence,
                        decision.final_score,
                        decision.action_type,
                        decision.channel,
                        decision.environment,
                        decision.recipient,
                        decision.content_excerpt,
                        decision.content_sha256,
                        decision.policy_id,
                        decision.policy_version,
                        Jsonb(payload),
                        decision.decided_at,
                    ),
                )
            conn.commit()

    def _bootstrap_from_postgres(self) -> None:
        """Replay every decision from Postgres into the in-memory cache."""
        with with_connection(self._dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT payload_json
                      FROM tex_decisions
                     ORDER BY decided_at ASC, written_at ASC
                    """
                )
                rows = cur.fetchall()

        for (payload,) in rows:
            try:
                if isinstance(payload, str):
                    payload = json.loads(payload)
                decision = _payload_to_decision(payload)
                self._cache.save(decision)
            except Exception as exc:  # noqa: BLE001
                _logger.warning(
                    "PostgresDecisionStore: skipping unreadable decision row: %s",
                    exc,
                )

        _logger.info(
            "PostgresDecisionStore: bootstrapped %d decisions from Postgres.",
            len(self._cache),
        )


__all__ = ["PostgresDecisionStore", "SCHEMA_SQL"]

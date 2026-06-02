"""
Postgres-backed action ledger.

Drop-in replacement for ``InMemoryActionLedger``. Same write-through
pattern: in-memory bounded deques per agent for hot reads, Postgres
append-only table for durability.

The bounded in-memory deque (``per_agent_limit``, default 5000) is
preserved. The behavioral baseline computed on every evaluation reads
the in-memory deque, not Postgres — that path stays microsecond-fast.

What Postgres adds:

  * Per-agent action history survives restarts. Without this, the
    "novel action" and "forbid streak" baselines silently reset
    every deploy.
  * Tenant-scoped append-only audit log. The table is INSERT-only
    (we never UPDATE or DELETE existing rows), which makes it
    suitable as a behavioural evidence source for compliance.

Schema is intentionally lean: every column is something the baseline
or audit needs. We keep the full payload as JSONB so we never lose
fields the domain model adds later.
"""

from __future__ import annotations

import json
import logging
import threading
from collections import Counter, deque
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
from tex.domain.agent import ActionLedgerEntry, BehavioralBaseline
from tex.stores.action_ledger import InMemoryActionLedger

_logger = logging.getLogger(__name__)


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS tex_action_ledger (
    entry_id        UUID PRIMARY KEY,
    agent_id        UUID NOT NULL,
    tenant_id       TEXT NOT NULL DEFAULT 'default',
    decision_id     UUID NOT NULL,
    request_id      UUID NOT NULL,
    verdict         TEXT NOT NULL,
    action_type     TEXT NOT NULL,
    channel         TEXT NOT NULL,
    environment     TEXT NOT NULL,
    recipient       TEXT,
    final_score     DOUBLE PRECISION NOT NULL,
    confidence      DOUBLE PRECISION NOT NULL,
    content_sha256  TEXT NOT NULL,
    policy_version  TEXT,
    evidence_hash   TEXT,
    payload_json    JSONB NOT NULL,
    recorded_at     TIMESTAMPTZ NOT NULL,
    insert_seq      BIGSERIAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_tex_action_ledger_agent
    ON tex_action_ledger (agent_id, recorded_at DESC);

CREATE INDEX IF NOT EXISTS idx_tex_action_ledger_tenant
    ON tex_action_ledger (tenant_id, recorded_at DESC);
"""


def _resolve_tenant(entry: ActionLedgerEntry) -> str:
    """
    Resolve the tenant for a ledger entry.

    The action ledger entry doesn't carry tenant directly, so we read
    it from session_id when it has the form ``tenant:<id>:...``. This
    is the convention used by the guardrail layer when tenant context
    is available; for everything else we fall back to "default".
    """
    sid = entry.session_id or ""
    if sid.startswith("tenant:"):
        parts = sid.split(":", 2)
        if len(parts) >= 2 and parts[1].strip():
            return parts[1].strip()
    return "default"


class PostgresActionLedger:
    """Durable action ledger. Same interface as ``InMemoryActionLedger``."""

    __slots__ = ("_lock", "_cache", "_dsn", "_disabled", "_per_agent_limit")

    def __init__(
        self,
        *,
        per_agent_limit: int = 5_000,
        initial: Iterable[ActionLedgerEntry] | None = None,
        dsn: str | None = None,
        bootstrap: bool = True,
    ) -> None:
        self._lock = threading.RLock()
        self._cache = InMemoryActionLedger(per_agent_limit=per_agent_limit)
        self._per_agent_limit = per_agent_limit
        self._dsn = resolve_dsn(dsn)
        self._disabled = not bool(self._dsn)

        if self._disabled:
            _logger.warning(
                "PostgresActionLedger: %s not set; running in pure in-memory mode.",
                DATABASE_URL_ENV,
            )
        else:
            try:
                self._ensure_schema()
            except Exception as exc:  # noqa: BLE001
                _logger.error(
                    "PostgresActionLedger: schema bootstrap failed (%s) on %s. "
                    "Falling back to in-memory.",
                    exc,
                    safe_dsn_for_log(self._dsn),
                )
                self._disabled = True

            if bootstrap and not self._disabled:
                try:
                    self._bootstrap_from_postgres()
                except Exception as exc:  # noqa: BLE001
                    _logger.error("PostgresActionLedger: bootstrap failed: %s", exc)

        if initial:
            for entry in initial:
                self.append(entry)

    # ------------------------------------------------------------------ writes

    def append(self, entry: ActionLedgerEntry) -> None:
        with self._lock:
            self._cache.append(entry)
            if self._disabled:
                return
            try:
                self._flush_one(entry)
            except Exception as exc:  # noqa: BLE001
                _logger.error(
                    "PostgresActionLedger: flush failed for entry_id=%s: %s",
                    entry.entry_id,
                    exc,
                )

    # ------------------------------------------------------------------ reads

    def list_all(self, *, limit: int | None = None) -> tuple[ActionLedgerEntry, ...]:
        return self._cache.list_all(limit=limit)

    def list_for_agent(
        self,
        agent_id: UUID,
        *,
        limit: int | None = None,
    ) -> tuple[ActionLedgerEntry, ...]:
        return self._cache.list_for_agent(agent_id, limit=limit)

    def count_for_agent(self, agent_id: UUID) -> int:
        return self._cache.count_for_agent(agent_id)

    def total_count(self) -> int:
        return self._cache.total_count()

    def compute_baseline(
        self,
        agent_id: UUID,
        *,
        window: int = 200,
    ) -> BehavioralBaseline:
        return self._cache.compute_baseline(agent_id, window=window)

    # ------------------------------------------------------------------ internals

    def _ensure_schema(self) -> None:
        with with_connection(self._dsn, autocommit=True) as conn:
            with conn.cursor() as cur:
                cur.execute(SCHEMA_SQL)

    def _flush_one(self, entry: ActionLedgerEntry) -> None:
        payload = entry.model_dump(mode="json")
        tenant_id = _resolve_tenant(entry)
        with with_connection(self._dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO tex_action_ledger (
                        entry_id, agent_id, tenant_id, decision_id, request_id,
                        verdict, action_type, channel, environment, recipient,
                        final_score, confidence, content_sha256, policy_version,
                        evidence_hash, payload_json, recorded_at
                    ) VALUES (
                        %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s,
                        %s, %s, %s, %s,
                        %s, %s, %s
                    )
                    ON CONFLICT (entry_id) DO NOTHING
                    """,
                    (
                        str(entry.entry_id),
                        str(entry.agent_id),
                        tenant_id,
                        str(entry.decision_id),
                        str(entry.request_id),
                        entry.verdict,
                        entry.action_type,
                        entry.channel,
                        entry.environment,
                        entry.recipient,
                        entry.final_score,
                        entry.confidence,
                        entry.content_sha256,
                        entry.policy_version,
                        entry.evidence_hash,
                        Jsonb(payload),
                        entry.recorded_at,
                    ),
                )
            conn.commit()

    def _bootstrap_from_postgres(self) -> None:
        """
        Replay the most recent ``per_agent_limit`` entries per agent.

        We don't need full history in memory — the deque is bounded.
        We pull `per_agent_limit * 1000` rows globally as an upper
        bound; production hosts that exceed this should use the
        retention job in scripts/.
        """
        with with_connection(self._dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT payload_json
                      FROM tex_action_ledger
                     ORDER BY recorded_at ASC, insert_seq ASC
                     LIMIT %s
                    """,
                    (self._per_agent_limit * 1000,),
                )
                rows = cur.fetchall()

        for (payload,) in rows:
            try:
                if isinstance(payload, str):
                    payload = json.loads(payload)
                entry = ActionLedgerEntry.model_validate(payload)
                self._cache.append(entry)
            except Exception as exc:  # noqa: BLE001
                _logger.warning(
                    "PostgresActionLedger: skipping unreadable row: %s", exc,
                )

        _logger.info(
            "PostgresActionLedger: bootstrapped %d ledger entries from Postgres.",
            self._cache.total_count(),
        )


__all__ = ["PostgresActionLedger", "SCHEMA_SQL"]

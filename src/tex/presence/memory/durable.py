"""Optional Postgres mirror for sealed presence memory — durability across
restarts, never the source of truth.

Why a DEDICATED table (``tex_presence_memory``) and not the existing substrate:

  * The append-only chains (``EvidenceRecorder``, ``SealedFactLedger``) have NO
    delete path by design — they are tamper-evident audit logs. A *forgettable*
    store cannot live there without punching a hole in the audit trail.
  * ``DurableEvidenceStore`` is INSERT-only (no delete). ``DurableDecisionStore``
    persists governance ``Decision`` rows (26 governance columns, feeds replay /
    leaderboard / drift); a presence claim is a different aggregate, and deleting
    a governance decision to "forget a spoken claim" would corrupt the audit
    record. So presence memory keeps its own table with its own lifecycle: you
    can forget a presence fact while every cited substrate row stays sealed.

Reuse, not reinvention: the connection helpers, the ``database_url() is None →
no-op`` fallback, and the autocommit short-lived-connection pattern are taken
verbatim from ``tex.memory._db`` / the durable-store idiom. The DDL is run
self-contained (``CREATE TABLE IF NOT EXISTS``, idempotent) so this stays inside
the presence package — no shared migrations-dir edit.

Isolation is application-layer ONLY — every statement carries ``WHERE
tenant_id``/``tenant_id`` in the key. There is NO Postgres RLS, no schema
partitioning, no encryption-at-rest. The literature names this the *weak*
isolation tier (OWASP LLM08:2025; benign cross-tenant retrieval leakage is a
documented, high-rate failure), so a wrong ``tenant`` string crosses tenants
silently — the in-memory authoritative dict's outer-key separation is the only
other guard, and the seal/recall/forget API never accepts a tenant from the
payload, only from the explicit argument.
"""

from __future__ import annotations

import json
import logging
import threading
from typing import Iterable

from tex.memory._db import connect, database_url
from tex.presence.memory.records import SealedPresenceRecord

_logger = logging.getLogger(__name__)

_ddl_lock = threading.Lock()
_ddl_applied = False

_CREATE_SQL = """
CREATE TABLE IF NOT EXISTS tex_presence_memory (
    tenant_id        TEXT NOT NULL,
    record_id        TEXT NOT NULL,
    claim_id         TEXT NOT NULL,
    tier             TEXT NOT NULL,
    content_hash     TEXT NOT NULL,
    content_json     TEXT NOT NULL,
    searchable_text  TEXT NOT NULL,
    pq_signature     TEXT,
    sealed_at        TEXT NOT NULL,
    PRIMARY KEY (tenant_id, record_id)
);
CREATE INDEX IF NOT EXISTS tex_presence_memory_tenant_idx
    ON tex_presence_memory (tenant_id, sealed_at DESC);
"""

_UPSERT_SQL = """
INSERT INTO tex_presence_memory (
    tenant_id, record_id, claim_id, tier, content_hash,
    content_json, searchable_text, pq_signature, sealed_at
) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
ON CONFLICT (tenant_id, record_id) DO UPDATE SET
    claim_id        = EXCLUDED.claim_id,
    tier            = EXCLUDED.tier,
    content_hash    = EXCLUDED.content_hash,
    content_json    = EXCLUDED.content_json,
    searchable_text = EXCLUDED.searchable_text,
    pq_signature    = EXCLUDED.pq_signature,
    sealed_at       = EXCLUDED.sealed_at
"""

_DELETE_SQL = """
DELETE FROM tex_presence_memory WHERE tenant_id = %s AND record_id = %s
"""

_SELECT_TENANT_SQL = """
SELECT tenant_id, record_id, claim_id, tier, content_hash,
       content_json, searchable_text, pq_signature, sealed_at
  FROM tex_presence_memory
 WHERE tenant_id = %s
 ORDER BY sealed_at DESC
"""


def _ensure_table() -> None:
    global _ddl_applied
    with _ddl_lock:
        if _ddl_applied:
            return
        with connect() as conn:
            with conn.cursor() as cur:
                cur.execute(_CREATE_SQL)
        _ddl_applied = True


def _row_to_record(row: tuple) -> SealedPresenceRecord:
    (
        tenant_id,
        record_id,
        claim_id,
        tier,
        content_hash,
        content_json,
        searchable_text,
        pq_signature,
        sealed_at,
    ) = row
    return SealedPresenceRecord(
        record_id=record_id,
        tenant=tenant_id,
        claim_id=claim_id,
        tier=tier,
        content_hash=content_hash,
        content_payload=json.loads(content_json),
        searchable_text=searchable_text,
        sealed_at=sealed_at,
        pq_signature=json.loads(pq_signature) if pq_signature else None,
    )


class PresenceDurableMirror:
    """Tenant-scoped Postgres mirror. A no-op when ``DATABASE_URL`` is unset (the
    test/dev default), so the in-memory authoritative store works with zero infra.
    """

    def __init__(self) -> None:
        self._enabled = database_url() is not None
        if not self._enabled:
            _logger.info(
                "PresenceDurableMirror: DATABASE_URL not set — durable mirror "
                "is a no-op; the in-memory store is authoritative and presence "
                "facts do not survive restart."
            )
            return
        try:
            _ensure_table()
        except Exception:
            _logger.exception(
                "PresenceDurableMirror: table bootstrap failed — mirror disabled"
            )
            self._enabled = False

    @property
    def is_durable(self) -> bool:
        return self._enabled

    # ---- write path ---------------------------------------------------

    def upsert(self, record: SealedPresenceRecord) -> None:
        if not self._enabled:
            return
        with connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    _UPSERT_SQL,
                    (
                        record.tenant,
                        record.record_id,
                        record.claim_id,
                        record.tier,
                        record.content_hash,
                        json.dumps(record.content_payload, sort_keys=True),
                        record.searchable_text,
                        json.dumps(record.pq_signature) if record.pq_signature else None,
                        record.sealed_at,
                    ),
                )

    def delete(self, *, tenant: str, record_id: str) -> int:
        """Tenant-scoped delete. Returns ``rowcount`` (1 if a row was removed, 0
        if none matched). Raises on a DB error — the caller MUST treat a raise as
        "forget unconfirmed" and never report success. A row only ever matches
        within its own tenant, so a forged/known cross-tenant ``record_id`` from
        another tenant deletes nothing."""
        if not self._enabled:
            return 0
        with connect() as conn:
            with conn.cursor() as cur:
                cur.execute(_DELETE_SQL, (tenant, record_id))
                return cur.rowcount

    # ---- read path (hydrate) -----------------------------------------

    def list_for_tenant(self, tenant: str) -> tuple[SealedPresenceRecord, ...]:
        if not self._enabled:
            return ()
        with connect() as conn:
            with conn.cursor() as cur:
                cur.execute(_SELECT_TENANT_SQL, (tenant,))
                rows = cur.fetchall()
        return tuple(_row_to_record(r) for r in rows)

    def hydrate(self, tenants: Iterable[str]) -> dict[str, list[SealedPresenceRecord]]:
        """Best-effort load of known tenants' records on construction. Returns a
        ``{tenant: [records]}`` map; never raises (durability hydrate must not
        block startup)."""
        out: dict[str, list[SealedPresenceRecord]] = {}
        if not self._enabled:
            return out
        for tenant in tenants:
            try:
                out[tenant] = list(self.list_for_tenant(tenant))
            except Exception:
                _logger.exception(
                    "PresenceDurableMirror: hydrate failed for tenant %s", tenant
                )
        return out

"""Optional Postgres mirror for sealed profile facts — durability across restarts,
never the source of truth.

A DEDICATED ``tex_presence_profile`` table for the same reason S5 keeps its own
``tex_presence_memory`` table: a *forgettable* store cannot live in the append-only
EvidenceRecorder / SealedFactLedger chains (no delete path) without punching a hole
in the audit trail. Reuse, not reinvention — the connection helpers, the
``database_url() is None → no-op`` fallback, and the autocommit short-lived-
connection pattern are taken verbatim from ``tex.memory._db`` / S5's
``PresenceDurableMirror``; the DDL runs self-contained (``CREATE TABLE IF NOT
EXISTS``) so this stays inside the profile package.

Isolation is application-layer ONLY — every statement carries ``WHERE tenant_id``.
No Postgres RLS, no encryption-at-rest (OWASP LLM08:2025 "weak" tier). A wrong
``tenant`` string crosses tenants silently; the API never accepts a tenant from a
payload.
"""

from __future__ import annotations

import json
import logging
import threading

from tex.memory._db import connect, database_url
from tex.presence.profile.records import SealedProfileFact
from tex.presence.profile.types import ProfileFactKind
from tex.presence.contract import PresenceTier

_logger = logging.getLogger(__name__)

_ddl_lock = threading.Lock()
_ddl_applied = False

_CREATE_SQL = """
CREATE TABLE IF NOT EXISTS tex_presence_profile (
    tenant_id        TEXT NOT NULL,
    record_id        TEXT NOT NULL,
    fact_kind        TEXT NOT NULL,
    subject_key      TEXT NOT NULL,
    corrected_tier   TEXT,
    original_tier    TEXT,
    statement        TEXT NOT NULL,
    operator         TEXT NOT NULL,
    decision_id      TEXT,
    believed_value   TEXT,
    content_hash     TEXT NOT NULL,
    content_json     TEXT NOT NULL,
    searchable_text  TEXT NOT NULL,
    pq_signature     TEXT,
    created_at       TEXT NOT NULL,
    PRIMARY KEY (tenant_id, record_id)
);
CREATE INDEX IF NOT EXISTS tex_presence_profile_tenant_idx
    ON tex_presence_profile (tenant_id, created_at DESC);
"""

_UPSERT_SQL = """
INSERT INTO tex_presence_profile (
    tenant_id, record_id, fact_kind, subject_key, corrected_tier, original_tier,
    statement, operator, decision_id, believed_value, content_hash, content_json,
    searchable_text, pq_signature, created_at
) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
ON CONFLICT (tenant_id, record_id) DO UPDATE SET
    fact_kind       = EXCLUDED.fact_kind,
    subject_key     = EXCLUDED.subject_key,
    corrected_tier  = EXCLUDED.corrected_tier,
    original_tier   = EXCLUDED.original_tier,
    statement       = EXCLUDED.statement,
    operator        = EXCLUDED.operator,
    decision_id     = EXCLUDED.decision_id,
    believed_value  = EXCLUDED.believed_value,
    content_hash    = EXCLUDED.content_hash,
    content_json    = EXCLUDED.content_json,
    searchable_text = EXCLUDED.searchable_text,
    pq_signature    = EXCLUDED.pq_signature,
    created_at      = EXCLUDED.created_at
"""

_DELETE_SQL = """
DELETE FROM tex_presence_profile WHERE tenant_id = %s AND record_id = %s
"""

_SELECT_TENANT_SQL = """
SELECT tenant_id, record_id, fact_kind, subject_key, corrected_tier, original_tier,
       statement, operator, decision_id, believed_value, content_hash, content_json,
       searchable_text, pq_signature, created_at
  FROM tex_presence_profile
 WHERE tenant_id = %s
 ORDER BY created_at DESC
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


def _tier(value: str | None) -> PresenceTier | None:
    return PresenceTier(value) if value else None


def _row_to_fact(row: tuple) -> SealedProfileFact:
    (
        tenant_id, record_id, fact_kind, subject_key, corrected_tier, original_tier,
        statement, operator, decision_id, believed_value, content_hash, content_json,
        searchable_text, pq_signature, created_at,
    ) = row
    return SealedProfileFact(
        record_id=record_id,
        tenant=tenant_id,
        kind=ProfileFactKind(fact_kind),
        subject_key=subject_key,
        corrected_tier=_tier(corrected_tier),
        original_tier=_tier(original_tier),
        statement=statement,
        operator=operator,
        decision_id=decision_id,
        believed_value=believed_value,
        content_hash=content_hash,
        content_payload=json.loads(content_json),
        searchable_text=searchable_text,
        created_at=created_at,
        pq_signature=json.loads(pq_signature) if pq_signature else None,
    )


class ProfileDurableMirror:
    """Tenant-scoped Postgres mirror. A no-op when ``DATABASE_URL`` is unset (the
    test/dev default), so the in-memory authoritative store works with zero infra.
    """

    def __init__(self) -> None:
        self._enabled = database_url() is not None
        if not self._enabled:
            _logger.info(
                "ProfileDurableMirror: DATABASE_URL not set — durable mirror is a "
                "no-op; the in-memory store is authoritative and profile facts do "
                "not survive restart."
            )
            return
        try:
            _ensure_table()
        except Exception:
            _logger.exception(
                "ProfileDurableMirror: table bootstrap failed — mirror disabled"
            )
            self._enabled = False

    @property
    def is_durable(self) -> bool:
        return self._enabled

    def upsert(self, fact: SealedProfileFact) -> None:
        if not self._enabled:
            return
        with connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    _UPSERT_SQL,
                    (
                        fact.tenant,
                        fact.record_id,
                        fact.kind.value,
                        fact.subject_key,
                        fact.corrected_tier.value if fact.corrected_tier else None,
                        fact.original_tier.value if fact.original_tier else None,
                        fact.statement,
                        fact.operator,
                        fact.decision_id,
                        fact.believed_value,
                        fact.content_hash,
                        json.dumps(fact.content_payload, sort_keys=True),
                        fact.searchable_text,
                        json.dumps(fact.pq_signature) if fact.pq_signature else None,
                        fact.created_at,
                    ),
                )

    def delete(self, *, tenant: str, record_id: str) -> int:
        """Tenant-scoped delete. Returns ``rowcount``. Raises on a DB error — the
        caller MUST treat a raise as "revoke unconfirmed" and never report success.
        A row only matches within its own tenant, so a forged cross-tenant
        ``record_id`` deletes nothing."""
        if not self._enabled:
            return 0
        with connect() as conn:
            with conn.cursor() as cur:
                cur.execute(_DELETE_SQL, (tenant, record_id))
                return cur.rowcount

    def list_for_tenant(self, tenant: str) -> tuple[SealedProfileFact, ...]:
        if not self._enabled:
            return ()
        with connect() as conn:
            with conn.cursor() as cur:
                cur.execute(_SELECT_TENANT_SQL, (tenant,))
                rows = cur.fetchall()
        return tuple(_row_to_fact(r) for r in rows)

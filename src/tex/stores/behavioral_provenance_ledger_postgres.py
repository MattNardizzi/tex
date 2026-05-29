"""
Postgres-backed behavioural provenance ledger.

Drop-in mirror of ``BehavioralProvenanceLedger``, following the exact
write-through pattern the discovery and action ledgers use: reads are
served from the in-memory cache, writes flush synchronously to Postgres,
and the ledger reconstructs from disk on startup.

What is different here, and what the mirror must preserve, is that this
ledger is *signed*. Each record carries a per-entry ECDSA signature over
its ``record_hash``. On restore we re-validate both the hash chain *and*
every signature against the ledger's public key — a tampered row fails
``verify_chain`` (integrity) or ``verify_signatures`` (authenticity), and
the operator gets a structured warning rather than a silently-corrupted
transparency log. For the signatures to verify after restart, the same
signing key must be injected at construction (HSM/keystore in
production); the mirror passes it straight through to the inner ledger.
"""

from __future__ import annotations

import logging
import os
import threading
from typing import Any
from uuid import UUID

from tex.pqcrypto.algorithm_agility import SignatureKeyPair, SignatureProvider
from tex.provenance.ledger import BehavioralProvenanceLedger
from tex.provenance.models import ProvenanceEventKind, ProvenanceRecord

_logger = logging.getLogger(__name__)

DATABASE_URL_ENV = "DATABASE_URL"


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS tex_provenance_ledger (
    sequence            INTEGER PRIMARY KEY,
    event_kind          TEXT NOT NULL,
    agent_id            UUID NOT NULL,
    signature_hash      TEXT NOT NULL,
    confidence          DOUBLE PRECISION NOT NULL,
    signal_tier         INTEGER NOT NULL,
    observation_count   INTEGER NOT NULL,
    linked_agent_id     UUID,
    detail              JSONB NOT NULL,
    payload_sha256      TEXT NOT NULL,
    previous_hash       TEXT,
    record_hash         TEXT NOT NULL,
    signature_b64       TEXT NOT NULL,
    signing_key_id      TEXT NOT NULL,
    recorded_at         TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS tex_provenance_ledger_agent_idx
    ON tex_provenance_ledger (agent_id);

CREATE INDEX IF NOT EXISTS tex_provenance_ledger_kind_idx
    ON tex_provenance_ledger (event_kind);
"""


class PostgresBehavioralProvenanceLedger:
    """
    Durable behavioural provenance ledger.

    Implements the same surface as ``BehavioralProvenanceLedger`` —
    ``append``, ``list_all``, ``list_for_agent``, ``birth_record``,
    ``verify_chain``, ``verify_signatures``, ``public_key_pem``,
    ``signing_key_id``, ``__len__`` — so the engine cannot tell which one
    it holds.
    """

    __slots__ = ("_lock", "_cache", "_dsn", "_disabled", "_pending_resync")

    def __init__(
        self,
        *,
        signing_key: SignatureKeyPair | None = None,
        signing_provider: SignatureProvider | None = None,
        dsn: str | None = None,
        bootstrap: bool = True,
    ) -> None:
        self._lock = threading.RLock()
        self._cache = BehavioralProvenanceLedger(
            signing_key=signing_key,
            signing_provider=signing_provider,
        )
        self._dsn = dsn or os.environ.get(DATABASE_URL_ENV, "").strip()
        self._disabled = not bool(self._dsn)
        self._pending_resync: list[ProvenanceRecord] = []

        if self._disabled:
            _logger.warning(
                "PostgresBehavioralProvenanceLedger: %s not set; running in "
                "pure in-memory mode. Provenance log will not survive restarts.",
                DATABASE_URL_ENV,
            )
            return

        try:
            self._ensure_schema()
        except Exception as exc:  # noqa: BLE001
            _logger.error(
                "PostgresBehavioralProvenanceLedger: schema bootstrap failed: %s. "
                "Falling back to in-memory mode.",
                exc,
            )
            self._disabled = True
            return

        if bootstrap:
            try:
                self._bootstrap_from_postgres()
            except Exception as exc:  # noqa: BLE001
                _logger.error(
                    "PostgresBehavioralProvenanceLedger: bootstrap failed: %s", exc
                )

    # ------------------------------------------------------------------ keys
    @property
    def public_key_pem(self) -> bytes:
        return self._cache.public_key_pem

    @property
    def signing_key_id(self) -> str:
        return self._cache.signing_key_id

    # ------------------------------------------------------------------ write
    def append(self, **kwargs: Any) -> ProvenanceRecord:
        with self._lock:
            record = self._cache.append(**kwargs)
            self._safe_flush_append(record)
            return record

    # ------------------------------------------------------------------ read
    def list_all(self) -> tuple[ProvenanceRecord, ...]:
        return self._cache.list_all()

    def list_for_agent(self, agent_id: UUID) -> tuple[ProvenanceRecord, ...]:
        return self._cache.list_for_agent(agent_id)

    def birth_record(self, agent_id: UUID) -> ProvenanceRecord | None:
        return self._cache.birth_record(agent_id)

    def __len__(self) -> int:
        return len(self._cache)

    def verify_chain(self) -> dict[str, Any]:
        return self._cache.verify_chain()

    def verify_signatures(self, public_key_pem: bytes | None = None) -> dict[str, Any]:
        return self._cache.verify_signatures(public_key_pem)

    # ------------------------------------------------------------------ admin
    @property
    def is_durable(self) -> bool:
        return not self._disabled

    @property
    def pending_resync_count(self) -> int:
        with self._lock:
            return len(self._pending_resync)

    def replay_pending(self) -> int:
        with self._lock:
            if self._disabled or not self._pending_resync:
                return 0
            successful = 0
            still_pending: list[ProvenanceRecord] = []
            for record in self._pending_resync:
                try:
                    self._flush_append(record)
                    successful += 1
                except Exception:  # noqa: BLE001
                    still_pending.append(record)
            self._pending_resync = still_pending
            return successful

    # ------------------------------------------------------------------ internals
    def _ensure_schema(self) -> None:
        import psycopg

        with psycopg.connect(self._dsn, autocommit=True) as conn:
            with conn.cursor() as cur:
                cur.execute(SCHEMA_SQL)

    def _safe_flush_append(self, record: ProvenanceRecord) -> None:
        if self._disabled:
            return
        try:
            self._flush_append(record)
        except Exception as exc:  # noqa: BLE001
            _logger.warning(
                "PostgresBehavioralProvenanceLedger: flush failed for "
                "sequence=%s; queued for resync: %s",
                record.sequence,
                exc,
            )
            self._pending_resync.append(record)

    def _flush_append(self, record: ProvenanceRecord) -> None:
        import psycopg
        from psycopg.types.json import Jsonb

        with psycopg.connect(self._dsn, autocommit=True) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO tex_provenance_ledger (
                        sequence, event_kind, agent_id, signature_hash,
                        confidence, signal_tier, observation_count,
                        linked_agent_id, detail, payload_sha256,
                        previous_hash, record_hash, signature_b64,
                        signing_key_id, recorded_at
                    ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    ON CONFLICT (sequence) DO NOTHING
                    """,
                    (
                        record.sequence,
                        str(record.event_kind),
                        str(record.agent_id),
                        record.signature_hash,
                        float(record.confidence),
                        int(record.signal_tier),
                        int(record.observation_count),
                        str(record.linked_agent_id) if record.linked_agent_id else None,
                        Jsonb(record.detail or {}),
                        record.payload_sha256,
                        record.previous_hash,
                        record.record_hash,
                        record.signature_b64,
                        record.signing_key_id,
                        record.recorded_at,
                    ),
                )

    def _bootstrap_from_postgres(self) -> None:
        import psycopg

        with psycopg.connect(self._dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT sequence, event_kind, agent_id, signature_hash,
                           confidence, signal_tier, observation_count,
                           linked_agent_id, detail, payload_sha256,
                           previous_hash, record_hash, signature_b64,
                           signing_key_id, recorded_at
                      FROM tex_provenance_ledger
                     ORDER BY sequence ASC
                    """
                )
                rows = cur.fetchall()

        with self._cache._lock:  # noqa: SLF001
            for row in rows:
                (
                    sequence, event_kind, agent_id, signature_hash, confidence,
                    signal_tier, observation_count, linked_agent_id, detail,
                    payload_sha256, previous_hash, record_hash, signature_b64,
                    signing_key_id, recorded_at,
                ) = row
                record = ProvenanceRecord(
                    sequence=sequence,
                    event_kind=ProvenanceEventKind(event_kind),
                    agent_id=UUID(str(agent_id)),
                    signature_hash=signature_hash,
                    confidence=confidence,
                    signal_tier=signal_tier,
                    observation_count=observation_count,
                    linked_agent_id=UUID(str(linked_agent_id)) if linked_agent_id else None,
                    detail=detail or {},
                    payload_sha256=payload_sha256,
                    previous_hash=previous_hash,
                    record_hash=record_hash,
                    signature_b64=signature_b64,
                    signing_key_id=signing_key_id,
                    recorded_at=recorded_at,
                )
                self._cache._entries.append(record)  # noqa: SLF001
                self._cache._by_agent.setdefault(  # noqa: SLF001
                    str(record.agent_id), []
                ).append(sequence)

        if rows:
            chain = self._cache.verify_chain()
            sigs = self._cache.verify_signatures()
            if not chain.get("intact") or not sigs.get("valid"):
                _logger.error(
                    "PostgresBehavioralProvenanceLedger: verification FAILED after "
                    "bootstrap (chain=%s signatures=%s). Tampering is suspected.",
                    chain,
                    sigs,
                )
            else:
                _logger.info(
                    "PostgresBehavioralProvenanceLedger: bootstrapped %d records; "
                    "chain and signatures verified.",
                    len(rows),
                )

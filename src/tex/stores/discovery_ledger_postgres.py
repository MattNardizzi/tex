"""
Postgres-backed discovery ledger.

Drop-in replacement for ``InMemoryDiscoveryLedger``. Same write-through
pattern as ``PostgresAgentRegistry``: reads are served from the
in-memory cache, writes flush synchronously to Postgres, and the
ledger reconstructs from disk on startup.

The hash chain is the part that matters here. The original
``InMemoryDiscoveryLedger`` computes ``record_hash`` from
``payload_sha256 + previous_hash`` and stores both. When we restore
from Postgres, we re-validate the entire chain rather than trusting
what's on disk — if a row was tampered with after being written,
``verify_chain()`` returns False and the operator gets a structured
warning. This is what makes the ledger "tamper-evident" rather than
just "tamper-resistant."
"""

from __future__ import annotations

import logging
import os
import threading
from typing import Any
from uuid import UUID

import psycopg
from psycopg.types.json import Jsonb

from tex.domain.discovery import (
    CandidateAgent,
    DiscoveryLedgerEntry,
    ReconciliationOutcome,
)
from tex.stores.discovery_ledger import InMemoryDiscoveryLedger

_logger = logging.getLogger(__name__)

DATABASE_URL_ENV = "DATABASE_URL"


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS tex_discovery_ledger (
    sequence              INTEGER PRIMARY KEY,
    candidate             JSONB NOT NULL,
    outcome               JSONB NOT NULL,
    reconciliation_key    TEXT NOT NULL,
    resulting_agent_id    UUID,
    payload_sha256        TEXT NOT NULL,
    previous_hash         TEXT,
    record_hash           TEXT NOT NULL,
    appended_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS tex_discovery_ledger_recon_idx
    ON tex_discovery_ledger (reconciliation_key);

CREATE INDEX IF NOT EXISTS tex_discovery_ledger_agent_idx
    ON tex_discovery_ledger (resulting_agent_id)
 WHERE resulting_agent_id IS NOT NULL;
"""


class PostgresDiscoveryLedger:
    """
    Durable discovery ledger.

    Implements the same interface as ``InMemoryDiscoveryLedger`` —
    same ``append``, ``list_all``, ``list_for_key``,
    ``list_for_agent_id``, ``latest``, ``verify_chain``, ``__len__``.
    Callers cannot tell which one they're using.
    """

    __slots__ = (
        "_lock",
        "_cache",
        "_dsn",
        "_disabled",
        "_pending_resync",
    )

    def __init__(
        self,
        *,
        dsn: str | None = None,
        bootstrap: bool = True,
    ) -> None:
        self._lock = threading.RLock()
        self._cache = InMemoryDiscoveryLedger()
        self._dsn = dsn or os.environ.get(DATABASE_URL_ENV, "").strip()
        self._disabled = not bool(self._dsn)
        self._pending_resync: list[DiscoveryLedgerEntry] = []

        if self._disabled:
            _logger.warning(
                "PostgresDiscoveryLedger: %s not set; running in pure in-memory "
                "mode. Discovery ledger will not survive restarts.",
                DATABASE_URL_ENV,
            )
            return

        try:
            self._ensure_schema()
        except Exception as exc:  # noqa: BLE001
            _logger.error(
                "PostgresDiscoveryLedger: schema bootstrap failed: %s. "
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
                    "PostgresDiscoveryLedger: bootstrap from Postgres failed: %s",
                    exc,
                )

    # ------------------------------------------------------------------ writes

    def append(
        self,
        *,
        candidate: CandidateAgent,
        outcome: ReconciliationOutcome,
    ) -> DiscoveryLedgerEntry:
        with self._lock:
            entry = self._cache.append(candidate=candidate, outcome=outcome)
            self._safe_flush_append(entry)
            return entry

    # ------------------------------------------------------------------ reads

    def list_all(self) -> tuple[DiscoveryLedgerEntry, ...]:
        return self._cache.list_all()

    def list_for_key(self, reconciliation_key: str) -> tuple[DiscoveryLedgerEntry, ...]:
        return self._cache.list_for_key(reconciliation_key)

    def list_for_agent_id(self, agent_id_str: str) -> tuple[DiscoveryLedgerEntry, ...]:
        return self._cache.list_for_agent_id(agent_id_str)

    def latest(self) -> DiscoveryLedgerEntry | None:
        return self._cache.latest()

    def __len__(self) -> int:
        return len(self._cache)

    def verify_chain(self) -> bool:
        return self._cache.verify_chain()

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
            still_pending: list[DiscoveryLedgerEntry] = []
            for entry in self._pending_resync:
                try:
                    self._flush_append(entry)
                    successful += 1
                except Exception as exc:  # noqa: BLE001
                    _logger.warning(
                        "PostgresDiscoveryLedger: replay still failing for "
                        "sequence=%s: %s",
                        entry.sequence,
                        exc,
                    )
                    still_pending.append(entry)
            self._pending_resync = still_pending
            return successful

    # ------------------------------------------------------------------ internals

    def _ensure_schema(self) -> None:
        with psycopg.connect(self._dsn, autocommit=True) as conn:
            with conn.cursor() as cur:
                cur.execute(SCHEMA_SQL)

    def _bootstrap_from_postgres(self) -> None:
        with psycopg.connect(self._dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT sequence, candidate, outcome,
                           payload_sha256, previous_hash, record_hash
                      FROM tex_discovery_ledger
                     ORDER BY sequence ASC
                    """
                )
                rows = cur.fetchall()

        with self._cache._lock:  # pylint: disable=protected-access
            for row in rows:
                sequence, candidate_payload, outcome_payload, \
                    payload_sha256, previous_hash, record_hash = row
                candidate = CandidateAgent.model_validate(candidate_payload)
                outcome = ReconciliationOutcome.model_validate(outcome_payload)
                entry = DiscoveryLedgerEntry(
                    sequence=sequence,
                    candidate=candidate,
                    outcome=outcome,
                    payload_sha256=payload_sha256,
                    previous_hash=previous_hash,
                    record_hash=record_hash,
                )
                self._cache._entries.append(entry)  # noqa: SLF001
                self._cache._by_key.setdefault(  # noqa: SLF001
                    outcome.reconciliation_key, []
                ).append(sequence)
                if outcome.resulting_agent_id is not None:
                    self._cache._by_agent_id.setdefault(  # noqa: SLF001
                        str(outcome.resulting_agent_id), []
                    ).append(sequence)

        # Re-verify the chain immediately. If verification fails, the
        # operator needs to know — restoring a corrupted ledger
        # silently is exactly the failure mode the chain is designed
        # to prevent.
        if rows and not self._cache.verify_chain():
            _logger.error(
                "PostgresDiscoveryLedger: chain verification FAILED after "
                "bootstrap. Ledger contains %d entries but the chain is "
                "broken. Tampering is suspected.",
                len(rows),
            )
        else:
            _logger.info(
                "PostgresDiscoveryLedger: bootstrapped %d entries; chain "
                "verified.",
                len(rows),
            )

    def _safe_flush_append(self, entry: DiscoveryLedgerEntry) -> None:
        if self._disabled:
            return
        try:
            self._flush_append(entry)
        except Exception as exc:  # noqa: BLE001
            _logger.error(
                "PostgresDiscoveryLedger: write failed for sequence=%s: %s. "
                "Will retry via replay_pending().",
                entry.sequence,
                exc,
            )
            self._pending_resync.append(entry)

    def _flush_append(self, entry: DiscoveryLedgerEntry) -> None:
        resulting_agent_id = entry.outcome.resulting_agent_id
        with psycopg.connect(self._dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO tex_discovery_ledger (
                        sequence, candidate, outcome, reconciliation_key,
                        resulting_agent_id, payload_sha256, previous_hash,
                        record_hash
                    ) VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s
                    )
                    ON CONFLICT (sequence) DO UPDATE SET
                        candidate          = EXCLUDED.candidate,
                        outcome            = EXCLUDED.outcome,
                        reconciliation_key = EXCLUDED.reconciliation_key,
                        resulting_agent_id = EXCLUDED.resulting_agent_id,
                        payload_sha256     = EXCLUDED.payload_sha256,
                        previous_hash      = EXCLUDED.previous_hash,
                        record_hash        = EXCLUDED.record_hash
                    """,
                    (
                        entry.sequence,
                        Jsonb(entry.candidate.model_dump(mode="json")),
                        Jsonb(entry.outcome.model_dump(mode="json")),
                        entry.outcome.reconciliation_key,
                        str(resulting_agent_id) if resulting_agent_id is not None else None,
                        entry.payload_sha256,
                        entry.previous_hash,
                        entry.record_hash,
                    ),
                )
            conn.commit()


__all__ = [
    "PostgresDiscoveryLedger",
    "DATABASE_URL_ENV",
]

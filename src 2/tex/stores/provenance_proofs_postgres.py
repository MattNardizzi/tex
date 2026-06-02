"""
Postgres-backed durable store for ZKPROV proofs.

Mirrors ``tex.stores.precedent_store_postgres`` exactly:

* Read DATABASE_URL on construction.
* If unset → log warning, run pure in-memory.
* If set → ensure schema (idempotent), bootstrap cache from disk.
* Writes go to the in-memory cache first, then synchronously flush
  to Postgres. Read path is in-memory.

Schema
------
``tex_provenance_proofs`` records one ZKPROV proof per row:

  proof_envelope_sha256  : PRIMARY KEY (the SHA-256 of the canonical
                            proof envelope JSON).
  decision_id            : FK-ish link to the evidence record. Not
                            an actual FK because the evidence table
                            lives in a different store.
  tenant_id              : multi-tenant projection key, defaults to
                            'default' matching the precedent store
                            convention.
  dataset_commitment_id  : the commitment this proof binds to.
  manifest_root_hash     : pinned for fast cross-query joins to the
                            manifest registry.
  backend                : ProofBackendId.value (string).
  is_regulator_grade     : boolean cached at insertion time. Cheaper
                            than re-querying the regulator-grade
                            classifier on every read.
  envelope_json          : the canonical proof envelope (jsonb).
  issued_at              : RFC 3339 timestamp from the proof itself.
  recorded_at            : when the row was inserted.
  save_seq               : monotonic sequence for ordered scans.

Indexes are sized for the two hot read paths:
  1. fetch by decision_id (single point read on the audit path).
  2. fetch most-recent N proofs for a given commitment (for the
     evidence chain replay when reconciling).

Thread 14 wires this in. Microsoft AGT, Noma, Zenity, Pillar — none
ship a comparable per-action provenance proof store. This is the
fifth wedge piece.
"""

from __future__ import annotations

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
from tex.zkprov.proof import ProvenanceProof


_logger = logging.getLogger(__name__)


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS tex_provenance_proofs (
    proof_envelope_sha256  CHAR(64) PRIMARY KEY,
    decision_id            UUID NOT NULL,
    tenant_id              TEXT NOT NULL DEFAULT 'default',
    dataset_commitment_id  TEXT NOT NULL,
    manifest_root_hash     CHAR(64) NOT NULL,
    backend                TEXT NOT NULL,
    is_regulator_grade     BOOLEAN NOT NULL,
    envelope_json          JSONB NOT NULL,
    issued_at              TIMESTAMPTZ NOT NULL,
    recorded_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    save_seq               BIGSERIAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_tex_provenance_proofs_decision
    ON tex_provenance_proofs (decision_id, recorded_at DESC);

CREATE INDEX IF NOT EXISTS idx_tex_provenance_proofs_commitment
    ON tex_provenance_proofs (dataset_commitment_id, save_seq DESC);

CREATE INDEX IF NOT EXISTS idx_tex_provenance_proofs_tenant
    ON tex_provenance_proofs (tenant_id, save_seq DESC);
"""


class _InMemoryProvenanceProofStore:
    """In-memory fallback used when DATABASE_URL is unset.

    Same shape as the Postgres store so the call sites are
    duck-typed identically.
    """

    __slots__ = ("_lock", "_by_envelope", "_by_decision")

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._by_envelope: dict[str, dict[str, Any]] = {}
        self._by_decision: dict[UUID, list[str]] = {}

    def save(self, *, decision_id: UUID, proof: ProvenanceProof, tenant_id: str = "default") -> str:
        from tex.zkprov.backends import is_regulator_grade

        envelope = proof.to_envelope_json()
        env_hash = proof.envelope_sha256()
        record: dict[str, Any] = {
            "proof_envelope_sha256": env_hash,
            "decision_id": decision_id,
            "tenant_id": tenant_id,
            "dataset_commitment_id": proof.statement.dataset_commitment_id,
            "manifest_root_hash": proof.statement.manifest_root_hash,
            "backend": proof.backend.value,
            "is_regulator_grade": is_regulator_grade(proof.backend),
            "envelope_json": envelope,
            "issued_at": proof.issued_at,
        }
        with self._lock:
            self._by_envelope[env_hash] = record
            self._by_decision.setdefault(decision_id, []).append(env_hash)
        return env_hash

    def get(self, envelope_sha256: str) -> dict[str, Any] | None:
        return self._by_envelope.get(envelope_sha256)

    def find_by_decision(self, decision_id: UUID) -> tuple[dict[str, Any], ...]:
        with self._lock:
            envelope_hashes = list(self._by_decision.get(decision_id, ()))
        return tuple(self._by_envelope[e] for e in envelope_hashes if e in self._by_envelope)

    def find_by_commitment(
        self, dataset_commitment_id: str, *, limit: int = 100
    ) -> tuple[dict[str, Any], ...]:
        with self._lock:
            matches = [
                r
                for r in self._by_envelope.values()
                if r["dataset_commitment_id"] == dataset_commitment_id
            ]
        matches.sort(key=lambda r: r["issued_at"], reverse=True)
        return tuple(matches[:limit])

    def clear(self) -> None:
        with self._lock:
            self._by_envelope.clear()
            self._by_decision.clear()

    def __len__(self) -> int:
        return len(self._by_envelope)


class PostgresProvenanceProofStore:
    """Durable provenance proof store.

    Mirrors the existing Tex store pattern: in-memory cache + a
    write-through to Postgres. Reads go to the in-memory cache.
    When DATABASE_URL is unset the store runs in pure in-memory
    mode and logs a warning at construction; production deployments
    detect this in their startup checks.
    """

    __slots__ = ("_lock", "_cache", "_dsn", "_disabled")

    def __init__(self, *, dsn: str | None = None, bootstrap: bool = True) -> None:
        self._lock = threading.RLock()
        self._cache = _InMemoryProvenanceProofStore()
        self._dsn = resolve_dsn(dsn)
        self._disabled = not bool(self._dsn)

        if self._disabled:
            _logger.warning(
                "PostgresProvenanceProofStore: %s not set; running in pure in-memory mode.",
                DATABASE_URL_ENV,
            )
            return

        try:
            self._ensure_schema()
        except Exception as exc:  # noqa: BLE001
            _logger.error(
                "PostgresProvenanceProofStore: schema bootstrap failed (%s) on %s. "
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
                _logger.error(
                    "PostgresProvenanceProofStore: bootstrap failed: %s", exc
                )

    # ------------------------------------------------------------------ writes

    def save(
        self,
        *,
        decision_id: UUID,
        proof: ProvenanceProof,
        tenant_id: str = "default",
    ) -> str:
        env_hash = self._cache.save(
            decision_id=decision_id, proof=proof, tenant_id=tenant_id
        )
        if self._disabled:
            return env_hash
        try:
            self._flush_one(decision_id=decision_id, proof=proof, tenant_id=tenant_id)
        except Exception as exc:  # noqa: BLE001
            _logger.error(
                "PostgresProvenanceProofStore: flush failed for envelope=%s: %s",
                env_hash,
                exc,
            )
        return env_hash

    def save_many(
        self,
        *,
        items: Iterable[tuple[UUID, ProvenanceProof]],
        tenant_id: str = "default",
    ) -> tuple[str, ...]:
        return tuple(
            self.save(decision_id=did, proof=p, tenant_id=tenant_id)
            for did, p in items
        )

    def clear(self) -> None:
        self._cache.clear()
        if self._disabled:
            return
        try:
            with with_connection(self._dsn) as conn:
                with conn.cursor() as cur:
                    cur.execute("DELETE FROM tex_provenance_proofs")
                conn.commit()
        except Exception as exc:  # noqa: BLE001
            _logger.error("PostgresProvenanceProofStore: clear failed: %s", exc)

    # ------------------------------------------------------------------ reads

    def get(self, envelope_sha256: str) -> dict[str, Any] | None:
        return self._cache.get(envelope_sha256)

    def find_by_decision(self, decision_id: UUID) -> tuple[dict[str, Any], ...]:
        return self._cache.find_by_decision(decision_id)

    def find_by_commitment(
        self, dataset_commitment_id: str, *, limit: int = 100
    ) -> tuple[dict[str, Any], ...]:
        return self._cache.find_by_commitment(dataset_commitment_id, limit=limit)

    def __len__(self) -> int:
        return len(self._cache)

    # ------------------------------------------------------------------ internals

    def _ensure_schema(self) -> None:
        with with_connection(self._dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(SCHEMA_SQL)
            conn.commit()

    def _flush_one(
        self,
        *,
        decision_id: UUID,
        proof: ProvenanceProof,
        tenant_id: str,
    ) -> None:
        from tex.zkprov.backends import is_regulator_grade

        envelope_json = proof.to_envelope_json()
        envelope_hash = proof.envelope_sha256()
        with with_connection(self._dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO tex_provenance_proofs (
                        proof_envelope_sha256,
                        decision_id,
                        tenant_id,
                        dataset_commitment_id,
                        manifest_root_hash,
                        backend,
                        is_regulator_grade,
                        envelope_json,
                        issued_at
                    )
                    VALUES (
                        %(envelope_hash)s,
                        %(decision_id)s,
                        %(tenant_id)s,
                        %(dataset_commitment_id)s,
                        %(manifest_root_hash)s,
                        %(backend)s,
                        %(is_regulator_grade)s,
                        %(envelope_json)s,
                        %(issued_at)s
                    )
                    ON CONFLICT (proof_envelope_sha256) DO NOTHING
                    """,
                    {
                        "envelope_hash": envelope_hash,
                        "decision_id": str(decision_id),
                        "tenant_id": tenant_id,
                        "dataset_commitment_id": proof.statement.dataset_commitment_id,
                        "manifest_root_hash": proof.statement.manifest_root_hash,
                        "backend": proof.backend.value,
                        "is_regulator_grade": is_regulator_grade(proof.backend),
                        "envelope_json": Jsonb(envelope_json),
                        "issued_at": proof.issued_at,
                    },
                )
            conn.commit()

    def _bootstrap_from_postgres(self) -> None:
        with with_connection(self._dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT
                        proof_envelope_sha256,
                        decision_id,
                        tenant_id,
                        dataset_commitment_id,
                        manifest_root_hash,
                        backend,
                        is_regulator_grade,
                        envelope_json,
                        issued_at
                    FROM tex_provenance_proofs
                    ORDER BY save_seq ASC
                    """
                )
                rows = cur.fetchall()
        # We deserialize directly into the in-memory cache without
        # round-tripping through ``save`` because the rows are already
        # persisted upstream.
        with self._cache._lock:
            for row in rows:
                (
                    envelope_hash,
                    decision_id_str,
                    tenant_id,
                    commitment_id,
                    manifest_root,
                    backend,
                    regulator_grade,
                    envelope_json,
                    issued_at,
                ) = row
                decision_id = UUID(decision_id_str)
                record = {
                    "proof_envelope_sha256": envelope_hash,
                    "decision_id": decision_id,
                    "tenant_id": tenant_id,
                    "dataset_commitment_id": commitment_id,
                    "manifest_root_hash": manifest_root,
                    "backend": backend,
                    "is_regulator_grade": regulator_grade,
                    "envelope_json": envelope_json,
                    "issued_at": issued_at,
                }
                self._cache._by_envelope[envelope_hash] = record
                self._cache._by_decision.setdefault(decision_id, []).append(envelope_hash)


__all__ = [
    "PostgresProvenanceProofStore",
    "SCHEMA_SQL",
]

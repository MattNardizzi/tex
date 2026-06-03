"""
Postgres-backed C2PA manifest mirror (Thread 5).

Separate from ``tex_evidence`` — manifests are large (1-20 KB per
row) and have a different access pattern (rare reads via
``record_id``, never aggregate scans). Keeping them in a dedicated
table avoids bloating the hot evidence index.

Design properties
-----------------

1. **Append-only.** Manifests are INSERT only. The C2PA outer
   signature is over the canonical claim CBOR; once a manifest is
   written, mutating it breaks the signature.

2. **Indexed by record_id (the parent evidence row).** A
   ``GET /v1/evidence/{record_id}/c2pa`` lookup must be O(1).

3. **Stores the full claim CBOR** (base64 in the column so the
   table works on Postgres clients that don't transparently handle
   BYTEA), the outer COSE_Sign1 base64, the cert chain PEM, and
   the manifest's metadata fields for forensic querying.

4. **Optional.** When ``DATABASE_URL`` is unset, no-ops cleanly
   (matches ``PostgresEvidenceMirror``).

References
----------
- C2PA 2.4 §10.3 (claim signing) — drives the column shape.
- arxiv 2604.24890 (NSA paper) §"Credentials expire and become
  unverifiable" — this table is the retention anchor that
  outlives the outer C2PA certificate. The
  ``tex.evidence_cosign.retention_anchor.record_hash`` field
  points back to a row in ``tex_evidence``; this table stores the
  manifest a verifier needs to re-derive offline.
- EU AI Act Article 12 — log retention (six months minimum for
  high-risk; multi-year for some sectors).
"""

from __future__ import annotations

import logging
import threading
from datetime import UTC, datetime
from typing import Any

from tex.db.connection import (
    DATABASE_URL_ENV,
    resolve_dsn,
    safe_dsn_for_log,
    with_connection,
)


_logger = logging.getLogger(__name__)


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS tex_evidence_manifests (
    manifest_id          UUID PRIMARY KEY,
    record_id            UUID NOT NULL,
    decision_id          UUID NOT NULL,
    tenant_id            TEXT NOT NULL DEFAULT 'default',
    claim_sha256         TEXT NOT NULL,
    claim_cbor_b64       TEXT NOT NULL,
    outer_signature_b64  TEXT NOT NULL,
    certificate_chain_pem TEXT,
    title                TEXT NOT NULL,
    format               TEXT NOT NULL,
    instance_id          TEXT NOT NULL,
    claim_generator      TEXT NOT NULL,
    assertion_labels     TEXT[] NOT NULL,
    has_cosign           BOOLEAN NOT NULL,
    cosign_algorithm     TEXT,
    cosign_key_id        TEXT,
    full_file_sha256     TEXT,
    canonicalization_version TEXT,
    bound_timestamp      TIMESTAMPTZ,
    recorded_at          TIMESTAMPTZ NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_tex_evidence_manifests_record
    ON tex_evidence_manifests (record_id);

CREATE INDEX IF NOT EXISTS idx_tex_evidence_manifests_decision
    ON tex_evidence_manifests (decision_id);

CREATE INDEX IF NOT EXISTS idx_tex_evidence_manifests_tenant_time
    ON tex_evidence_manifests (tenant_id, recorded_at DESC);

CREATE INDEX IF NOT EXISTS idx_tex_evidence_manifests_full_file_hash
    ON tex_evidence_manifests (full_file_sha256)
    WHERE full_file_sha256 IS NOT NULL;
"""


class PostgresManifestMirror:
    """
    Append-only Postgres mirror of C2PA manifests emitted for
    PERMIT verdicts on outbound AI-generated artifacts.

    Plug into ``EvidenceRecorder`` via the optional ``manifest_mirror``
    constructor argument. The recorder calls ``record(...)`` after
    every successful manifest emission.
    """

    __slots__ = ("_lock", "_dsn", "_disabled")

    def __init__(self, *, dsn: str | None = None) -> None:
        self._lock = threading.RLock()
        self._dsn = resolve_dsn(dsn)
        self._disabled = not bool(self._dsn)

        if self._disabled:
            _logger.info(
                "PostgresManifestMirror: %s not set; manifest mirror disabled "
                "(JSONL evidence still records manifest hash).",
                DATABASE_URL_ENV,
            )
            return

        try:
            self._ensure_schema()
        except Exception as exc:  # noqa: BLE001
            _logger.error(
                "PostgresManifestMirror: schema bootstrap failed (%s) on %s. "
                "Manifest mirror disabled.",
                exc,
                safe_dsn_for_log(self._dsn),
            )
            self._disabled = True

    @property
    def disabled(self) -> bool:
        return self._disabled

    def _ensure_schema(self) -> None:
        with self._lock:
            with with_connection(self._dsn) as conn:
                with conn.cursor() as cur:
                    cur.execute(SCHEMA_SQL)
                conn.commit()

    def record(
        self,
        *,
        manifest_id: Any,
        record_id: Any,
        decision_id: Any,
        tenant_id: str,
        manifest_row: dict[str, Any],
        cosign_metadata: dict[str, Any] | None = None,
        bound_timestamp: datetime | None = None,
    ) -> None:
        """
        Insert one manifest row. Idempotent on ``record_id`` (the parent
        evidence row primary key — there is at most one manifest per
        evidence record by definition).
        """
        if self._disabled:
            return

        cosign_meta = cosign_metadata or {}
        with self._lock:
            try:
                with with_connection(self._dsn) as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            INSERT INTO tex_evidence_manifests (
                                manifest_id, record_id, decision_id, tenant_id,
                                claim_sha256, claim_cbor_b64,
                                outer_signature_b64, certificate_chain_pem,
                                title, format, instance_id,
                                claim_generator, assertion_labels,
                                has_cosign, cosign_algorithm, cosign_key_id,
                                full_file_sha256, canonicalization_version,
                                bound_timestamp, recorded_at
                            ) VALUES (
                                %s, %s, %s, %s,
                                %s, %s,
                                %s, %s,
                                %s, %s, %s,
                                %s, %s,
                                %s, %s, %s,
                                %s, %s,
                                %s, %s
                            )
                            ON CONFLICT (record_id) DO NOTHING
                            """,
                            (
                                str(manifest_id),
                                str(record_id),
                                str(decision_id),
                                tenant_id,
                                manifest_row["claim_sha256"],
                                manifest_row["claim_cbor_b64"],
                                manifest_row["outer_signature_b64"],
                                manifest_row.get("certificate_chain_pem"),
                                manifest_row["title"],
                                manifest_row["format"],
                                manifest_row["instance_id"],
                                manifest_row["claim_generator"],
                                list(manifest_row["assertion_labels"]),
                                bool(manifest_row["has_cosign"]),
                                cosign_meta.get("algorithm"),
                                cosign_meta.get("key_id"),
                                cosign_meta.get("full_file_sha256"),
                                cosign_meta.get("canonicalization_version"),
                                bound_timestamp,
                                datetime.now(tz=UTC),
                            ),
                        )
                    conn.commit()
            except Exception as exc:  # noqa: BLE001
                _logger.error(
                    "PostgresManifestMirror: insert failed for record_id=%s: %s",
                    record_id,
                    exc,
                )

    def fetch_by_record_id(self, record_id: Any) -> dict[str, Any] | None:
        """
        Read one manifest row by parent evidence ``record_id``. Used
        by ``GET /v1/evidence/{record_id}/c2pa``.
        """
        if self._disabled:
            return None

        with self._lock:
            with with_connection(self._dsn) as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT
                            manifest_id, record_id, decision_id, tenant_id,
                            claim_sha256, claim_cbor_b64,
                            outer_signature_b64, certificate_chain_pem,
                            title, format, instance_id, claim_generator,
                            assertion_labels, has_cosign,
                            cosign_algorithm, cosign_key_id,
                            full_file_sha256, canonicalization_version,
                            bound_timestamp, recorded_at
                        FROM tex_evidence_manifests
                        WHERE record_id = %s
                        """,
                        (str(record_id),),
                    )
                    row = cur.fetchone()

        if row is None:
            return None

        return {
            "manifest_id": str(row[0]),
            "record_id": str(row[1]),
            "decision_id": str(row[2]),
            "tenant_id": row[3],
            "claim_sha256": row[4],
            "claim_cbor_b64": row[5],
            "outer_signature_b64": row[6],
            "certificate_chain_pem": row[7],
            "title": row[8],
            "format": row[9],
            "instance_id": row[10],
            "claim_generator": row[11],
            "assertion_labels": list(row[12]) if row[12] is not None else [],
            "has_cosign": bool(row[13]),
            "cosign_algorithm": row[14],
            "cosign_key_id": row[15],
            "full_file_sha256": row[16],
            "canonicalization_version": row[17],
            "bound_timestamp": row[18].isoformat() if row[18] else None,
            "recorded_at": row[19].isoformat() if row[19] else None,
        }

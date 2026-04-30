"""
Governance snapshot store.

The governance-state matrix (V14) is a point-in-time read of the
registry × discovery-ledger × action-ledger join. That's useful for
"what's my coverage right now," but a security buyer also wants
"what's my coverage trajectory" — has the GOVERNED count gone up,
have UNGOVERNED agents accumulated, did we ever drop coverage on a
high-risk agent. Snapshots answer that.

A snapshot is an immutable record of one ``GovernanceResponse`` — the
counts, the per-agent matrix, the coverage root, the HMAC signature,
and the time it was taken. Snapshots are taken on demand
(``POST /v1/agents/governance/snapshot``) or on the same scheduler
cadence as discovery scans, so a deployment with hourly scans gets
hourly governance snapshots out of the box.

Snapshots persist to Postgres when ``DATABASE_URL`` is set, falling
back to in-memory otherwise — same pattern as the registry and
ledger.
"""

from __future__ import annotations

import hashlib
import logging
import os
import threading
from collections import OrderedDict
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import psycopg
from psycopg.types.json import Jsonb

_logger = logging.getLogger(__name__)

DATABASE_URL_ENV = "DATABASE_URL"


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS tex_governance_snapshots (
    snapshot_id              UUID PRIMARY KEY,
    captured_at              TIMESTAMPTZ NOT NULL,
    total_agents             INTEGER NOT NULL,
    governed                 INTEGER NOT NULL,
    ungoverned               INTEGER NOT NULL,
    partial                  INTEGER NOT NULL,
    unknown                  INTEGER NOT NULL,
    high_risk_total          INTEGER NOT NULL,
    high_risk_ungoverned     INTEGER NOT NULL,
    governed_with_forbids    INTEGER NOT NULL,
    coverage_root_sha256     TEXT NOT NULL,
    signature_hmac_sha256    TEXT NOT NULL,
    payload                  JSONB NOT NULL,
    label                    TEXT,
    -- chain fields
    snapshot_hash            TEXT NOT NULL DEFAULT '',
    previous_snapshot_hash   TEXT,
    sequence                 BIGSERIAL UNIQUE
);

CREATE INDEX IF NOT EXISTS tex_governance_snapshots_time_idx
    ON tex_governance_snapshots (captured_at DESC);

CREATE INDEX IF NOT EXISTS tex_governance_snapshots_root_idx
    ON tex_governance_snapshots (coverage_root_sha256);

CREATE INDEX IF NOT EXISTS tex_governance_snapshots_chain_idx
    ON tex_governance_snapshots (snapshot_hash);

ALTER TABLE tex_governance_snapshots
    ADD COLUMN IF NOT EXISTS snapshot_hash          TEXT NOT NULL DEFAULT '';
ALTER TABLE tex_governance_snapshots
    ADD COLUMN IF NOT EXISTS previous_snapshot_hash TEXT;
-- V16 scan-binding columns. Optional, populated when the snapshot
-- was captured immediately after a known scan_run.
ALTER TABLE tex_governance_snapshots
    ADD COLUMN IF NOT EXISTS scan_run_id            UUID;
ALTER TABLE tex_governance_snapshots
    ADD COLUMN IF NOT EXISTS ledger_seq_start       INTEGER;
ALTER TABLE tex_governance_snapshots
    ADD COLUMN IF NOT EXISTS ledger_seq_end         INTEGER;
ALTER TABLE tex_governance_snapshots
    ADD COLUMN IF NOT EXISTS registry_state_hash    TEXT;
ALTER TABLE tex_governance_snapshots
    ADD COLUMN IF NOT EXISTS policy_version         TEXT;
ALTER TABLE tex_governance_snapshots
    ADD COLUMN IF NOT EXISTS tenant_id              TEXT;

CREATE INDEX IF NOT EXISTS tex_governance_snapshots_scanrun_idx
    ON tex_governance_snapshots (scan_run_id) WHERE scan_run_id IS NOT NULL;
"""


class GovernanceSnapshotStore:
    """
    Append-only store for governance snapshots.

    Reads return the most recent N snapshots in reverse-chronological
    order, plus point lookup by snapshot_id. The store keeps the
    most-recent ``cache_limit`` snapshots in memory; older snapshots
    are loaded from Postgres on demand.
    """

    __slots__ = (
        "_lock",
        "_cache",
        "_dsn",
        "_disabled",
        "_cache_limit",
        "_last_chain_hash",
    )

    def __init__(
        self,
        *,
        dsn: str | None = None,
        cache_limit: int = 200,
        bootstrap: bool = True,
    ) -> None:
        self._lock = threading.RLock()
        # snapshot_id → snapshot dict. OrderedDict so we can FIFO-evict
        # past the cache limit.
        self._cache: OrderedDict[UUID, dict] = OrderedDict()
        self._dsn = dsn or os.environ.get(DATABASE_URL_ENV, "").strip()
        self._disabled = not bool(self._dsn)
        self._cache_limit = cache_limit
        self._last_chain_hash: str | None = None

        if self._disabled:
            _logger.warning(
                "GovernanceSnapshotStore: %s not set; running in pure in-memory "
                "mode. Snapshot history will not survive restarts.",
                DATABASE_URL_ENV,
            )
            return

        try:
            self._ensure_schema()
        except Exception as exc:  # noqa: BLE001
            _logger.error(
                "GovernanceSnapshotStore: schema bootstrap failed: %s. "
                "Falling back to in-memory mode.",
                exc,
            )
            self._disabled = True
            return

        if bootstrap:
            try:
                self._load_recent_into_cache()
            except Exception as exc:  # noqa: BLE001
                _logger.error(
                    "GovernanceSnapshotStore: bootstrap from Postgres failed: %s",
                    exc,
                )

    # ------------------------------------------------------------------ writes

    def capture(
        self,
        *,
        governance_payload: dict,
        label: str | None = None,
        scan_run_id: str | None = None,
        ledger_seq_start: int | None = None,
        ledger_seq_end: int | None = None,
        registry_state_hash: str | None = None,
        policy_version: str | None = None,
        tenant_id: str | None = None,
    ) -> dict:
        """
        Persist a snapshot of ``governance_payload`` (a serialized
        ``GovernanceResponse``). Returns the stored snapshot record,
        which adds ``snapshot_id``, ``captured_at``, ``label``,
        ``snapshot_hash``, and ``previous_snapshot_hash``.

        Snapshots form a chain: each one carries the prior snapshot's
        ``snapshot_hash`` in ``previous_snapshot_hash``. That chain
        is verifiable end-to-end via ``verify_chain()``.

        V16: scan-run binding (optional). When ``scan_run_id`` is
        supplied, the snapshot is recorded against the exact discovery
        scan that produced the registry state. ``ledger_seq_start``,
        ``ledger_seq_end``, ``registry_state_hash``, and
        ``policy_version`` round out the binding so an auditor can
        reconstruct exactly what data the snapshot reflected.
        """
        snapshot_id = uuid4()
        captured_at = datetime.now(UTC)
        counts = governance_payload.get("counts", {})

        # Pull out the critical-ungoverned slice for fast UI access.
        agents = governance_payload.get("agents", []) or []
        critical_ungoverned = [
            {
                "agent_id": a.get("agent_id"),
                "name": a.get("name"),
                "discovery_source": a.get("discovery_source"),
                "external_id": a.get("external_id"),
                "risk_band": a.get("risk_band"),
                "tenant_id": a.get("tenant_id"),
            }
            for a in agents
            if a.get("governance_state") == "UNGOVERNED"
            and (a.get("risk_band") or "").upper() in {"HIGH", "CRITICAL"}
        ]

        with self._lock:
            previous_hash = self._last_chain_hash

            # Binding metadata is part of the chain hash so a
            # tampered or swapped scan_run_id is detectable on replay.
            payload_for_hash = {
                "snapshot_id": str(snapshot_id),
                "captured_at": captured_at.isoformat(),
                "counts": dict(counts),
                "coverage_root_sha256": governance_payload.get(
                    "coverage_root_sha256", ""
                ),
                "label": label,
                "previous_snapshot_hash": previous_hash,
                "scan_run_id": scan_run_id,
                "ledger_seq_start": ledger_seq_start,
                "ledger_seq_end": ledger_seq_end,
                "registry_state_hash": registry_state_hash,
                "policy_version": policy_version,
                "tenant_id": tenant_id,
            }
            snapshot_hash = hashlib.sha256(
                _stable_json(payload_for_hash).encode("utf-8")
            ).hexdigest()

            record = {
                "snapshot_id": str(snapshot_id),
                "captured_at": captured_at.isoformat(),
                "total_agents": int(counts.get("total_agents", 0)),
                "governed": int(counts.get("governed", 0)),
                "ungoverned": int(counts.get("ungoverned", 0)),
                "partial": int(counts.get("partial", 0)),
                "unknown": int(counts.get("unknown", 0)),
                "high_risk_total": int(counts.get("high_risk_total", 0)),
                "high_risk_ungoverned": int(counts.get("high_risk_ungoverned", 0)),
                "governed_with_forbids": int(counts.get("governed_with_forbids", 0)),
                "coverage_root_sha256": governance_payload.get(
                    "coverage_root_sha256", ""
                ),
                "signature_hmac_sha256": governance_payload.get(
                    "signature_hmac_sha256", ""
                ),
                "payload": governance_payload,
                "label": label,
                "snapshot_hash": snapshot_hash,
                "previous_snapshot_hash": previous_hash,
                "critical_ungoverned": critical_ungoverned,
                "governed_pct": _pct(counts.get("governed", 0), counts.get("total_agents", 0)),
                "ungoverned_pct": _pct(counts.get("ungoverned", 0), counts.get("total_agents", 0)),
                # V16 binding
                "scan_run_id": scan_run_id,
                "ledger_seq_start": ledger_seq_start,
                "ledger_seq_end": ledger_seq_end,
                "registry_state_hash": registry_state_hash,
                "policy_version": policy_version,
                "tenant_id": tenant_id,
            }

            self._cache[snapshot_id] = record
            self._last_chain_hash = snapshot_hash
            while len(self._cache) > self._cache_limit:
                self._cache.popitem(last=False)
            if not self._disabled:
                try:
                    self._flush_capture(record)
                except Exception as exc:  # noqa: BLE001
                    _logger.error(
                        "GovernanceSnapshotStore: write failed for "
                        "snapshot_id=%s: %s",
                        snapshot_id,
                        exc,
                    )

        return record

    # ------------------------------------------------------------------ reads

    def list_recent(self, *, limit: int = 50) -> list[dict]:
        with self._lock:
            cached = list(self._cache.values())
        if len(cached) >= limit:
            return list(reversed(cached))[:limit]
        if self._disabled:
            return list(reversed(cached))[:limit]
        # Fall back to Postgres for anything past what's cached.
        try:
            return self._load_from_postgres(limit=limit)
        except Exception as exc:  # noqa: BLE001
            _logger.error(
                "GovernanceSnapshotStore: list_recent fetch failed: %s",
                exc,
            )
            return list(reversed(cached))[:limit]

    def get(self, snapshot_id: UUID) -> dict | None:
        with self._lock:
            cached = self._cache.get(snapshot_id)
        if cached is not None:
            return cached
        if self._disabled:
            return None
        try:
            return self._load_one_from_postgres(snapshot_id)
        except Exception as exc:  # noqa: BLE001
            _logger.error(
                "GovernanceSnapshotStore: point lookup failed for "
                "snapshot_id=%s: %s",
                snapshot_id,
                exc,
            )
            return None

    def export_evidence_bundle(
        self,
        snapshot_id: UUID,
        *,
        signing_secret_env: str = "TEX_EVIDENCE_SUMMARY_SECRET",
        drift_events: list[dict] | None = None,
        discovery_ledger_root: str | None = None,
        registry_chain_proof: dict | None = None,
        policy_versions_present: list[str] | None = None,
        scan_run: dict | None = None,
    ) -> dict | None:
        """
        Return a regulator-grade evidence bundle for one snapshot.

        Beyond the snapshot itself, this includes:

          - the full governance response (counts + agent matrix)
          - chain context (this snapshot's hash + previous_hash)
          - drift events tied to this snapshot's window
          - discovery ledger root hash (for cross-referencing with
            ``GET /v1/discovery/ledger/verify``)
          - registry chain proof (per-agent record_hash chain heads)
          - policy versions active during the window
          - V16: scan binding metadata (scan_run_id, ledger range,
            registry_state_hash, policy_version) when the snapshot
            was captured against a known scan
          - manifest: a SHA-256 over the full bundle, an HMAC
            signature, AND per-artifact section hashes so a
            regulator can verify the parts independently

        The bundle is intentionally self-contained: a regulator can
        sit with one JSON file and verify everything they need
        without further calls to the API.
        """
        record = self.get(snapshot_id)
        if record is None:
            return None

        # ---- assemble named sections ------------------------------------
        snapshot_section = {
            "snapshot_id": record["snapshot_id"],
            "captured_at": record["captured_at"],
            "label": record.get("label"),
            "snapshot_hash": record.get("snapshot_hash"),
            "previous_snapshot_hash": record.get("previous_snapshot_hash"),
            # V16 binding
            "scan_run_id": record.get("scan_run_id"),
            "ledger_seq_start": record.get("ledger_seq_start"),
            "ledger_seq_end": record.get("ledger_seq_end"),
            "registry_state_hash": record.get("registry_state_hash"),
            "policy_version": record.get("policy_version"),
            "tenant_id": record.get("tenant_id"),
        }
        counts_section = {
            "total_agents": record["total_agents"],
            "governed": record["governed"],
            "ungoverned": record["ungoverned"],
            "partial": record["partial"],
            "unknown": record["unknown"],
            "high_risk_total": record["high_risk_total"],
            "high_risk_ungoverned": record["high_risk_ungoverned"],
            "governed_with_forbids": record["governed_with_forbids"],
            "governed_pct": record.get("governed_pct"),
            "ungoverned_pct": record.get("ungoverned_pct"),
        }
        critical_section = record.get("critical_ungoverned", []) or []
        agents_section = (record.get("payload") or {}).get("agents", []) or []
        drift_section = drift_events or []
        registry_section = registry_chain_proof or {}
        policies_section = policy_versions_present or []
        scan_run_section = scan_run or {}

        bundle: dict[str, Any] = {
            "schema_version": "tex.governance.evidence/2",
            "snapshot": snapshot_section,
            "counts": counts_section,
            "critical_ungoverned": critical_section,
            "coverage_root_sha256": record["coverage_root_sha256"],
            "signature_hmac_sha256": record["signature_hmac_sha256"],
            "governance_response": record["payload"],
            "drift_events": drift_section,
            "discovery_ledger_root": discovery_ledger_root,
            "registry_chain_proof": registry_section,
            "policy_versions_present": policies_section,
            "scan_run": scan_run_section,
        }

        # ---- per-section hashes -----------------------------------------
        per_section_hashes = {
            "snapshot_sha256": _sha256_json(snapshot_section),
            "counts_sha256": _sha256_json(counts_section),
            "critical_ungoverned_sha256": _sha256_json(critical_section),
            "agents_sha256": _sha256_json(agents_section),
            "drift_events_sha256": _sha256_json(drift_section),
            "registry_chain_proof_sha256": _sha256_json(registry_section),
            "policy_versions_sha256": _sha256_json(policies_section),
            "scan_run_sha256": _sha256_json(scan_run_section),
            "discovery_ledger_root_sha256": (
                discovery_ledger_root or ""
            ),
            "coverage_root_sha256": record["coverage_root_sha256"],
        }

        # ---- bundle hash + HMAC -----------------------------------------
        bundle_sha256 = hashlib.sha256(
            _stable_json(bundle).encode("utf-8")
        ).hexdigest()
        secret = os.environ.get(signing_secret_env, "dev-only-change-me")
        import hmac as _hmac
        signature = _hmac.new(
            secret.encode("utf-8"),
            bundle_sha256.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        bundle["manifest"] = {
            "bundle_sha256": bundle_sha256,
            "manifest_signature_hmac_sha256": signature,
            "signed_at": datetime.now(UTC).isoformat(),
            "section_hashes": per_section_hashes,
            "schema_version": "tex.governance.evidence/2",
        }
        return bundle

    # ------------------------------------------------------------------ admin

    @property
    def is_durable(self) -> bool:
        return not self._disabled

    def __len__(self) -> int:
        with self._lock:
            return len(self._cache)

    # ------------------------------------------------------------------ internals

    def _ensure_schema(self) -> None:
        with psycopg.connect(self._dsn, autocommit=True) as conn:
            with conn.cursor() as cur:
                cur.execute(SCHEMA_SQL)

    def _load_recent_into_cache(self) -> None:
        records = self._load_from_postgres(limit=self._cache_limit)
        with self._lock:
            for r in reversed(records):
                self._cache[UUID(r["snapshot_id"])] = r
            # records are in DESC order; the head of the chain is index 0
            if records:
                self._last_chain_hash = records[0].get("snapshot_hash") or None
        _logger.info(
            "GovernanceSnapshotStore: bootstrapped %d snapshots", len(records)
        )

    def _load_from_postgres(self, *, limit: int) -> list[dict]:
        with psycopg.connect(self._dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT snapshot_id, captured_at, total_agents,
                           governed, ungoverned, partial, unknown,
                           high_risk_total, high_risk_ungoverned,
                           governed_with_forbids,
                           coverage_root_sha256, signature_hmac_sha256,
                           payload, label,
                           snapshot_hash, previous_snapshot_hash,
                           scan_run_id, ledger_seq_start, ledger_seq_end,
                           registry_state_hash, policy_version, tenant_id
                      FROM tex_governance_snapshots
                     ORDER BY captured_at DESC
                     LIMIT %s
                    """,
                    (limit,),
                )
                return [self._row_to_record(r) for r in cur.fetchall()]

    def _load_one_from_postgres(self, snapshot_id: UUID) -> dict | None:
        with psycopg.connect(self._dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT snapshot_id, captured_at, total_agents,
                           governed, ungoverned, partial, unknown,
                           high_risk_total, high_risk_ungoverned,
                           governed_with_forbids,
                           coverage_root_sha256, signature_hmac_sha256,
                           payload, label,
                           snapshot_hash, previous_snapshot_hash,
                           scan_run_id, ledger_seq_start, ledger_seq_end,
                           registry_state_hash, policy_version, tenant_id
                      FROM tex_governance_snapshots
                     WHERE snapshot_id = %s
                    """,
                    (str(snapshot_id),),
                )
                row = cur.fetchone()
        return self._row_to_record(row) if row else None

    def _flush_capture(self, record: dict) -> None:
        with psycopg.connect(self._dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO tex_governance_snapshots (
                        snapshot_id, captured_at, total_agents,
                        governed, ungoverned, partial, unknown,
                        high_risk_total, high_risk_ungoverned,
                        governed_with_forbids,
                        coverage_root_sha256, signature_hmac_sha256,
                        payload, label,
                        snapshot_hash, previous_snapshot_hash,
                        scan_run_id, ledger_seq_start, ledger_seq_end,
                        registry_state_hash, policy_version, tenant_id
                    ) VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s, %s, %s
                    )
                    """,
                    (
                        record["snapshot_id"],
                        datetime.fromisoformat(record["captured_at"]),
                        record["total_agents"],
                        record["governed"],
                        record["ungoverned"],
                        record["partial"],
                        record["unknown"],
                        record["high_risk_total"],
                        record["high_risk_ungoverned"],
                        record["governed_with_forbids"],
                        record["coverage_root_sha256"],
                        record["signature_hmac_sha256"],
                        Jsonb(record["payload"]),
                        record.get("label"),
                        record["snapshot_hash"],
                        record.get("previous_snapshot_hash"),
                        record.get("scan_run_id"),
                        record.get("ledger_seq_start"),
                        record.get("ledger_seq_end"),
                        record.get("registry_state_hash"),
                        record.get("policy_version"),
                        record.get("tenant_id"),
                    ),
                )
            conn.commit()

    @staticmethod
    def _row_to_record(row: tuple) -> dict:
        (
            snapshot_id, captured_at, total_agents,
            governed, ungoverned, partial, unknown,
            high_risk_total, high_risk_ungoverned,
            governed_with_forbids,
            coverage_root_sha256, signature_hmac_sha256,
            payload, label,
            snapshot_hash, previous_snapshot_hash,
            scan_run_id, ledger_seq_start, ledger_seq_end,
            registry_state_hash, policy_version, tenant_id,
        ) = row
        agents = (payload or {}).get("agents", []) or []
        critical_ungoverned = [
            {
                "agent_id": a.get("agent_id"),
                "name": a.get("name"),
                "discovery_source": a.get("discovery_source"),
                "external_id": a.get("external_id"),
                "risk_band": a.get("risk_band"),
                "tenant_id": a.get("tenant_id"),
            }
            for a in agents
            if a.get("governance_state") == "UNGOVERNED"
            and (a.get("risk_band") or "").upper() in {"HIGH", "CRITICAL"}
        ]
        return {
            "snapshot_id": str(snapshot_id),
            "captured_at": _ensure_aware(captured_at).isoformat(),
            "total_agents": total_agents,
            "governed": governed,
            "ungoverned": ungoverned,
            "partial": partial,
            "unknown": unknown,
            "high_risk_total": high_risk_total,
            "high_risk_ungoverned": high_risk_ungoverned,
            "governed_with_forbids": governed_with_forbids,
            "coverage_root_sha256": coverage_root_sha256,
            "signature_hmac_sha256": signature_hmac_sha256,
            "payload": payload,
            "label": label,
            "snapshot_hash": snapshot_hash or "",
            "previous_snapshot_hash": previous_snapshot_hash,
            "critical_ungoverned": critical_ungoverned,
            "governed_pct": _pct(governed, total_agents),
            "ungoverned_pct": _pct(ungoverned, total_agents),
            # V16 binding
            "scan_run_id": str(scan_run_id) if scan_run_id else None,
            "ledger_seq_start": ledger_seq_start,
            "ledger_seq_end": ledger_seq_end,
            "registry_state_hash": registry_state_hash,
            "policy_version": policy_version,
            "tenant_id": tenant_id,
        }

    def verify_chain(self, *, limit: int = 1_000) -> dict:
        """
        Replay the snapshot chain in chronological order and verify
        each entry's ``snapshot_hash`` recomputes correctly and links
        to the previous entry's hash.

        Returns a structured result with the count checked, whether
        the chain is intact, and the index of the first break (if
        any).
        """
        records = self.list_recent(limit=limit)
        # list_recent returns reverse-chronological; reverse for chain
        # replay so we move oldest → newest.
        chain = list(reversed(records))
        previous_hash: str | None = None
        for idx, record in enumerate(chain):
            payload_for_hash = {
                "snapshot_id": record["snapshot_id"],
                "captured_at": record["captured_at"],
                "counts": {
                    "total_agents": record["total_agents"],
                    "governed": record["governed"],
                    "ungoverned": record["ungoverned"],
                    "partial": record["partial"],
                    "unknown": record["unknown"],
                    "high_risk_total": record["high_risk_total"],
                    "high_risk_ungoverned": record["high_risk_ungoverned"],
                    "governed_with_forbids": record["governed_with_forbids"],
                },
                "coverage_root_sha256": record["coverage_root_sha256"],
                "label": record.get("label"),
                "previous_snapshot_hash": previous_hash,
                "scan_run_id": record.get("scan_run_id"),
                "ledger_seq_start": record.get("ledger_seq_start"),
                "ledger_seq_end": record.get("ledger_seq_end"),
                "registry_state_hash": record.get("registry_state_hash"),
                "policy_version": record.get("policy_version"),
                "tenant_id": record.get("tenant_id"),
            }
            expected = hashlib.sha256(
                _stable_json(payload_for_hash).encode("utf-8")
            ).hexdigest()
            stored = record.get("snapshot_hash") or ""
            if stored != expected:
                return {
                    "intact": False,
                    "checked": idx + 1,
                    "break_at_index": idx,
                    "snapshot_id": record["snapshot_id"],
                }
            if record.get("previous_snapshot_hash") != previous_hash:
                return {
                    "intact": False,
                    "checked": idx + 1,
                    "break_at_index": idx,
                    "snapshot_id": record["snapshot_id"],
                    "reason": "previous_hash_mismatch",
                }
            previous_hash = stored
        return {"intact": True, "checked": len(chain), "break_at_index": None}


def _ensure_aware(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=UTC)
    return value


def _pct(part: int, whole: int) -> float:
    if not whole:
        return 0.0
    return round(100.0 * part / whole, 2)


def _stable_json(value: Any) -> str:
    import json
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    )


def _sha256_json(value: Any) -> str:
    """Deterministic SHA-256 over a JSON-serializable value."""
    return hashlib.sha256(_stable_json(value).encode("utf-8")).hexdigest()


__all__ = ["GovernanceSnapshotStore", "DATABASE_URL_ENV"]

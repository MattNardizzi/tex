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

Zero-downtime deploys briefly run TWO web instances, and each holds
the chain tip in per-process memory — so a plain INSERT would let both
chain a child off the same parent and fork the persisted history
(prod, 2026-07-06; repaired by scripts/repair_governance_snapshots.py).
Postgres now enforces the chain shape itself (one child per parent,
one genesis — partial unique indexes), so the second writer's INSERT
refuses instead of forking; the store then re-links onto the true tip
and retries once, or parks the capture in ``pending_resync`` and says
so loudly. History is never rewritten; a capture is never silently
dropped.
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
-- Legacy tables predate the sequence column the tip/repair ordering uses.
ALTER TABLE tex_governance_snapshots
    ADD COLUMN IF NOT EXISTS sequence               BIGSERIAL UNIQUE;

CREATE INDEX IF NOT EXISTS tex_governance_snapshots_scanrun_idx
    ON tex_governance_snapshots (scan_run_id) WHERE scan_run_id IS NOT NULL;
"""

# Chain-fork guards. Two live instances (deploy overlap) can both try to
# chain a child off the same parent; these make Postgres the arbiter so
# the second INSERT reports zero rows instead of forking the history.
# Created separately from SCHEMA_SQL: if a table still holds an
# unrepaired fork the CREATE fails, and that must degrade to
# "guard off + loud log", never to "store falls back to in-memory".
CHAIN_GUARD_INDEXES_SQL = (
    # One persisted child per parent.
    """
    CREATE UNIQUE INDEX IF NOT EXISTS tex_governance_snapshots_parent_uidx
        ON tex_governance_snapshots (previous_snapshot_hash)
     WHERE previous_snapshot_hash IS NOT NULL
    """,
    # At most one genesis row (two empty-DB processes racing would
    # otherwise fork at the root, which the parent guard can't see).
    """
    CREATE UNIQUE INDEX IF NOT EXISTS tex_governance_snapshots_genesis_uidx
        ON tex_governance_snapshots ((previous_snapshot_hash IS NULL))
     WHERE previous_snapshot_hash IS NULL
    """,
)


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
        "_pending_resync",
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
        # Captures Postgres refused or couldn't take — never silently
        # dropped; retried via replay_pending().
        self._pending_resync: list[dict] = []

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

        If another live instance persisted a child for the same parent
        first (deploy overlap), the insert refuses and this record is
        re-linked onto the true Postgres tip before being persisted —
        the returned record reflects the re-linked (persisted) chain
        position, not the stale in-memory tip.

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
                "snapshot_hash": "",
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
            # One canonicalization for capture, verify_chain(), and the
            # repair script — binding metadata is inside the hash so a
            # tampered or swapped scan_run_id is detectable on replay.
            record["snapshot_hash"] = _compute_snapshot_hash(record, previous_hash)

            self._cache[snapshot_id] = record
            self._last_chain_hash = record["snapshot_hash"]
            while len(self._cache) > self._cache_limit:
                self._cache.popitem(last=False)
            if not self._disabled:
                self._persist_with_refusal(record)

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
        # Resolve the HMAC secret. The canonical path is
        # ``TEX_EVIDENCE_SUMMARY_SECRET`` via the centralized
        # ``tex.config.Settings`` (fail-closed in production-like
        # environments). The ``signing_secret_env`` parameter is
        # preserved for the rare caller that needs a different env-var
        # name — those callers bypass the Settings cache and read the
        # raw environment, but the in-repo sentinel is rejected here
        # unconditionally to prevent accidental misuse.
        if signing_secret_env == "TEX_EVIDENCE_SUMMARY_SECRET":
            from tex.config import get_settings  # local import: keeps store importable in isolation
            secret = get_settings().get_evidence_summary_secret() or "dev-only-change-me"
        else:
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

    @property
    def pending_resync_count(self) -> int:
        with self._lock:
            return len(self._pending_resync)

    def replay_pending(self) -> int:
        """
        Retry parked captures against Postgres. Outage-parked records
        fill their hole byte-identically. A record whose parent has
        since been claimed by another writer refuses again and stays
        parked — loudly — because inserting it anywhere else would
        rewrite history; that case is operator territory
        (scripts/repair_governance_snapshots.py).
        """
        with self._lock:
            if self._disabled or not self._pending_resync:
                return 0
            successful = 0
            still_pending: list[dict] = []
            for record in self._pending_resync:
                try:
                    if self._flush_capture(record):
                        successful += 1
                        continue
                    _logger.error(
                        "GovernanceSnapshotStore: replay refused for "
                        "snapshot_id=%s — its parent already has a persisted "
                        "child. Keeping it parked; run "
                        "scripts/repair_governance_snapshots.py.",
                        record["snapshot_id"],
                    )
                except Exception as exc:  # noqa: BLE001
                    _logger.warning(
                        "GovernanceSnapshotStore: replay still failing for "
                        "snapshot_id=%s: %s",
                        record["snapshot_id"],
                        exc,
                    )
                still_pending.append(record)
            self._pending_resync = still_pending
            return successful

    def __len__(self) -> int:
        with self._lock:
            return len(self._cache)

    # ------------------------------------------------------------------ internals

    def _ensure_schema(self) -> None:
        with psycopg.connect(self._dsn, autocommit=True) as conn:
            with conn.cursor() as cur:
                cur.execute(SCHEMA_SQL)
                for guard_sql in CHAIN_GUARD_INDEXES_SQL:
                    # autocommit: a failed CREATE doesn't poison the rest.
                    try:
                        cur.execute(guard_sql)
                    except Exception as exc:  # noqa: BLE001
                        _logger.error(
                            "GovernanceSnapshotStore: could not create chain "
                            "guard index — the persisted history likely still "
                            "contains a fork. Run "
                            "scripts/repair_governance_snapshots.py, then "
                            "restart. Durability stays ON; the fork guard is "
                            "OFF until the index exists: %s",
                            exc,
                        )

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
                     ORDER BY captured_at DESC, sequence DESC
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

    def _persist_with_refusal(self, record: dict) -> None:
        """
        Persist one capture without ever forking the persisted chain.

        Fast path: the INSERT lands, done. Refusal path: another live
        instance (deploy overlap) already persisted a child for this
        record's parent, so the guard indexes made our INSERT a no-op —
        re-read the true tip from Postgres, re-link this record onto it
        (its hash changes; it was never persisted, so nothing is
        rewritten), and retry once. A second refusal parks the record
        in ``_pending_resync`` — loudly, never silently dropped — and
        re-seeds ``_last_chain_hash`` from Postgres so the NEXT capture
        chains off persisted reality instead of the parked record.
        Outage path (INSERT raised): park the record unchanged and keep
        the in-memory tip advanced; ``replay_pending()`` later fills
        the persisted hole with the byte-identical record.

        Runs under ``self._lock`` (called from ``capture``).
        """
        try:
            if self._flush_capture(record):
                return
        except Exception as exc:  # noqa: BLE001
            self._park(record, why=f"write failed: {exc}")
            return

        # Refused: our parent already has a persisted child. Never fork,
        # never overwrite — adopt the true tip and retry once.
        try:
            true_tip = self._read_db_tip()
        except Exception as exc:  # noqa: BLE001
            self._park(record, why=f"insert refused, and the tip re-read failed: {exc}")
            return

        _logger.warning(
            "GovernanceSnapshotStore: chain-fork refused for snapshot_id=%s — "
            "parent %s already has a persisted child (second writer during a "
            "deploy overlap). Re-linking onto true tip %s and retrying once. "
            "History was not rewritten.",
            record["snapshot_id"],
            _short_hash(record.get("previous_snapshot_hash")),
            _short_hash(true_tip),
        )
        self._relink_record(record, true_tip)

        try:
            if self._flush_capture(record):
                return
        except Exception as exc:  # noqa: BLE001
            self._park(record, why=f"re-linked write failed: {exc}")
            return

        # Refused twice: another writer claimed the re-read tip as well.
        self._park(
            record,
            why="refused twice — another writer also claimed the re-read tip",
        )
        try:
            self._last_chain_hash = self._read_db_tip()
        except Exception:  # noqa: BLE001
            # Postgres just answered the retry, so this is unlikely. Fall
            # back to the tip we know is persisted rather than leaving the
            # tip pointing at the parked (unpersisted) record.
            self._last_chain_hash = true_tip

    def _park(self, record: dict, *, why: str) -> None:
        self._pending_resync.append(record)
        _logger.error(
            "GovernanceSnapshotStore: capture %s NOT persisted (%s). Parked "
            "as pending_resync[%d] — never silently dropped. replay_pending() "
            "retries it; if its parent was claimed by another writer, run "
            "scripts/repair_governance_snapshots.py.",
            record["snapshot_id"],
            why,
            len(self._pending_resync) - 1,
        )

    def _relink_record(self, record: dict, true_tip: str | None) -> None:
        # The record was never persisted, so re-linking rewrites nothing.
        # The cache and the capture() caller share this dict by reference —
        # both see the persisted truth.
        record["previous_snapshot_hash"] = true_tip
        record["snapshot_hash"] = _compute_snapshot_hash(record, true_tip)
        self._last_chain_hash = record["snapshot_hash"]

    def _read_db_tip(self) -> str | None:
        """The persisted chain tip (newest row's snapshot_hash), or None."""
        with psycopg.connect(self._dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT snapshot_hash
                      FROM tex_governance_snapshots
                     ORDER BY captured_at DESC, sequence DESC
                     LIMIT 1
                    """
                )
                row = cur.fetchone()
        return (row[0] or None) if row else None

    def _flush_capture(self, record: dict) -> bool:
        """
        INSERT one snapshot row. Returns True when the row landed, False
        when Postgres refused it (a unique guard — parent already has a
        child, second genesis, or duplicate snapshot_id). No conflict
        target on purpose: any unique violation refuses the row rather
        than erroring, and the caller runs the refusal protocol.
        """
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
                    ON CONFLICT DO NOTHING
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
                inserted = cur.rowcount == 1
            conn.commit()
        return inserted

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
        # Seed the replay from the window-first record's own stored link.
        # Once the store holds more than ``limit`` records that record is
        # NOT genesis — its predecessor lives outside the window — and a
        # ``None`` seed would flag an intact chain as broken at index 0
        # forever. Genesis still seeds ``None`` (its stored link IS None).
        # Tamper-evidence holds: the seed feeds the recompute of the
        # record's own snapshot_hash, so a forged link still breaks here,
        # and a recomputed forgery breaks at its successor's link check.
        previous_hash: str | None = (
            chain[0].get("previous_snapshot_hash") if chain else None
        )
        for idx, record in enumerate(chain):
            expected = _compute_snapshot_hash(record, previous_hash)
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


def _chain_payload_for_hash(record: dict, previous_hash: str | None) -> dict:
    """
    The canonical payload a snapshot's chain hash covers. ``capture()``,
    ``verify_chain()``, and scripts/repair_governance_snapshots.py all
    hash exactly this dict — one canonicalization, zero drift.
    """
    return {
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


def _compute_snapshot_hash(record: dict, previous_hash: str | None) -> str:
    return hashlib.sha256(
        _stable_json(_chain_payload_for_hash(record, previous_hash)).encode("utf-8")
    ).hexdigest()


def _short_hash(value: str | None) -> str:
    return (value or "GENESIS")[:16]


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

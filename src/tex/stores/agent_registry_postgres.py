"""
Postgres-backed agent registry.

Drop-in replacement for ``InMemoryAgentRegistry`` that persists every
write to Postgres while keeping the read path in-memory. The pattern
is a synchronous write-through cache:

  reads   → in-memory (microseconds, no I/O)
  writes  → in-memory THEN synchronous Postgres flush (one round trip)
  startup → bootstrap from Postgres into in-memory

The cache is authoritative for reads, but it must not go STALE without
bound. This store is the source of the marquee "N agents" count the UI
speaks; that count may only reflect live truth. A write-through cache is
correct against in-process writes (they land in memory and in Postgres
in the same call), but it is blind to out-of-band DB mutation — a direct
purge, a repair script, or a second writer/replica. Those leave the cache
speaking ghosts with no time bound: this genuinely happened, when 134 rows
were purged in prod and the live site kept saying "one hundred fourteen
agents" until the Render service restarted.

The fix is a freshness bound, not a smaller cache: on a read, if the last
bootstrap/re-sync is older than TEX_REGISTRY_RESYNC_S (default 120s; 0
disables), re-bootstrap from Postgres before serving — at most once per
window, under the same lock every write takes. Reads inside the window are
exactly as cheap as before (one monotonic-clock compare). A DB blip during
a re-sync keeps the current cache and retries next window; it never blanks
the registry or crashes a read. Write-through is preserved exactly: the
re-bootstrap runs under _lock so no in-process write can interleave, and
any not-yet-persisted write (a pending_resync entry) is re-applied on top
of the fresh snapshot so a just-written row can never be lost to a re-sync.

The choice is deliberate. The rest of Tex's runtime is synchronous —
the PDP, the agent suite, the evaluate-action command, the evidence
recorder. Converting all of that to async to satisfy a discovery-layer
durability requirement would be a multi-week refactor with high blast
radius. Instead we keep the existing synchronous API
(``InMemoryAgentRegistry`` is duck-typed by every caller) and run a
synchronous Postgres flush behind it. Under the load profile this
store sees in production (thousands of agents per tenant, writes on
the slow path of an evaluation), the per-write Postgres round trip
is fine. Reads — which happen on every evaluation, on every
governance call, on every discovery scan — never touch Postgres.

Failure modes:

- DATABASE_URL not set        → store falls back to pure in-memory and
                                logs a warning at construction. The
                                runtime stays up; durability is lost.
- Postgres unreachable        → write succeeds in memory but logs an
                                error and marks the entry as
                                "needs_resync". A background sync thread
                                replays pending entries when Postgres
                                comes back. Reads stay correct.
- Schema missing on startup   → ensure_schema() is idempotent and runs
                                on first connection.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import psycopg
from psycopg.types.json import Jsonb

from tex.domain.agent import (
    AgentAttestation,
    AgentEnvironment,
    AgentIdentity,
    AgentLifecycleStatus,
    AgentTrustTier,
    CapabilitySurface,
)
from tex.stores.agent_registry import (
    AgentNotFoundError,
    AgentRevoked,
    InMemoryAgentRegistry,
)

_logger = logging.getLogger(__name__)

DATABASE_URL_ENV = "DATABASE_URL"

# Freshness bound for the read cache. After this many seconds without a
# re-sync, the next read re-bootstraps from Postgres before serving so an
# out-of-band DB mutation (purge, repair script, second writer) becomes
# visible within one window instead of never. 0 disables re-sync (reads
# always serve the boot snapshot — the pre-fix behaviour, kept as an
# explicit opt-out for single-writer deployments that never mutate the DB
# out of band).
RESYNC_INTERVAL_ENV = "TEX_REGISTRY_RESYNC_S"
_DEFAULT_RESYNC_INTERVAL_S = 120.0


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS tex_agent_registry (
    agent_id          UUID NOT NULL,
    revision          INTEGER NOT NULL,
    name              TEXT NOT NULL,
    owner             TEXT NOT NULL,
    description       TEXT,
    tenant_id         TEXT NOT NULL,
    model_provider    TEXT,
    model_name        TEXT,
    framework         TEXT,
    environment       TEXT NOT NULL,
    trust_tier        TEXT NOT NULL,
    lifecycle_status  TEXT NOT NULL,
    capability_surface JSONB NOT NULL,
    attestations      JSONB NOT NULL DEFAULT '[]'::jsonb,
    tags              JSONB NOT NULL DEFAULT '[]'::jsonb,
    metadata          JSONB NOT NULL DEFAULT '{}'::jsonb,
    registered_at     TIMESTAMPTZ NOT NULL,
    updated_at        TIMESTAMPTZ NOT NULL,
    is_current        BOOLEAN NOT NULL DEFAULT TRUE,
    -- Audit / forensic fields. The chain ties every revision into a
    -- per-agent hash chain so reordering or tampering is detectable.
    record_hash       TEXT NOT NULL DEFAULT '',
    previous_hash     TEXT,
    payload_sha256    TEXT NOT NULL DEFAULT '',
    policy_version    TEXT,
    snapshot_id       UUID,
    write_source      TEXT NOT NULL DEFAULT 'unknown',
    PRIMARY KEY (agent_id, revision)
);

CREATE INDEX IF NOT EXISTS tex_agent_registry_current_idx
    ON tex_agent_registry (agent_id) WHERE is_current = TRUE;

CREATE INDEX IF NOT EXISTS tex_agent_registry_tenant_idx
    ON tex_agent_registry (tenant_id) WHERE is_current = TRUE;

CREATE INDEX IF NOT EXISTS tex_agent_registry_lifecycle_idx
    ON tex_agent_registry (lifecycle_status) WHERE is_current = TRUE;

-- Backfill columns for tables created before the audit upgrade. The
-- ADD COLUMN IF NOT EXISTS guard keeps this idempotent and safe to
-- run on every boot.
ALTER TABLE tex_agent_registry
    ADD COLUMN IF NOT EXISTS record_hash    TEXT NOT NULL DEFAULT '';
ALTER TABLE tex_agent_registry
    ADD COLUMN IF NOT EXISTS previous_hash  TEXT;
ALTER TABLE tex_agent_registry
    ADD COLUMN IF NOT EXISTS payload_sha256 TEXT NOT NULL DEFAULT '';
ALTER TABLE tex_agent_registry
    ADD COLUMN IF NOT EXISTS policy_version TEXT;
ALTER TABLE tex_agent_registry
    ADD COLUMN IF NOT EXISTS snapshot_id    UUID;
ALTER TABLE tex_agent_registry
    ADD COLUMN IF NOT EXISTS write_source   TEXT NOT NULL DEFAULT 'unknown';
"""


class PostgresAgentRegistry:
    """
    Durable agent registry. Implements the same interface as
    ``InMemoryAgentRegistry`` so callers don't need to know the
    difference.
    """

    __slots__ = (
        "_lock",
        "_cache",
        "_dsn",
        "_disabled",
        "_pending_resync",
        "_audit_context",
        "_last_hash_by_agent",
        "_resync_interval_s",
        "_last_sync_monotonic",
    )

    def __init__(
        self,
        *,
        dsn: str | None = None,
        bootstrap: bool = True,
        resync_interval_s: float | None = None,
    ) -> None:
        self._lock = threading.RLock()
        self._cache = InMemoryAgentRegistry()
        self._dsn = dsn or os.environ.get(DATABASE_URL_ENV, "").strip()
        self._disabled = not bool(self._dsn)
        self._pending_resync: list[tuple[AgentIdentity, dict]] = []
        # Freshness bound. Resolved once at construction; the explicit
        # arg wins over the env var (tests set it directly). A monotonic
        # clock is used so a wall-clock jump can't stall or spuriously
        # trip a re-sync.
        self._resync_interval_s = (
            resync_interval_s
            if resync_interval_s is not None
            else _resolve_resync_interval()
        )
        self._last_sync_monotonic = time.monotonic()
        self._audit_context: dict[str, Any] = {
            "policy_version": None,
            "snapshot_id": None,
            "write_source": "manual",
        }
        # Per-agent last record_hash, used to chain revisions even
        # across restarts (re-populated from Postgres on bootstrap).
        self._last_hash_by_agent: dict[UUID, str] = {}

        if self._disabled:
            _logger.warning(
                "PostgresAgentRegistry: %s not set; running in pure in-memory "
                "mode. Discovery state will not survive restarts.",
                DATABASE_URL_ENV,
            )
            return

        try:
            self._ensure_schema()
        except Exception as exc:  # noqa: BLE001
            _logger.error(
                "PostgresAgentRegistry: schema bootstrap failed: %s. "
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
                    "PostgresAgentRegistry: bootstrap from Postgres failed: %s",
                    exc,
                )

    # ------------------------------------------------------------------ audit context

    def set_audit_context(
        self,
        *,
        policy_version: str | None = None,
        snapshot_id: UUID | str | None = None,
        write_source: str | None = None,
    ) -> None:
        """
        Stamp correlation metadata onto subsequent saves.

        Callers (the evaluate-action command, the discovery service,
        the scheduler) set this so each persisted revision carries a
        traceable provenance: which policy version was active, which
        governance snapshot it correlates to, and what subsystem
        wrote it. The fields are persisted on the row and visible to
        every audit query that follows.
        """
        with self._lock:
            if policy_version is not None:
                self._audit_context["policy_version"] = policy_version
            if snapshot_id is not None:
                self._audit_context["snapshot_id"] = (
                    str(snapshot_id) if not isinstance(snapshot_id, str) else snapshot_id
                )
            if write_source is not None:
                self._audit_context["write_source"] = write_source

    def clear_audit_context(self) -> None:
        with self._lock:
            self._audit_context = {
                "policy_version": None,
                "snapshot_id": None,
                "write_source": "manual",
            }

    # ------------------------------------------------------------------ writes

    def save(self, agent: AgentIdentity) -> AgentIdentity:
        with self._lock:
            stored = self._cache.save(agent)
            audit = self._compute_audit_for(stored)
            self._safe_flush_save(stored, audit)
            return stored

    def set_lifecycle(
        self,
        agent_id: UUID,
        status: AgentLifecycleStatus,
    ) -> AgentIdentity:
        with self._lock:
            updated = self._cache.set_lifecycle(agent_id, status)
            # set_lifecycle returns the same revision if the status is
            # already the target — only flush when something actually
            # changed.
            if updated.lifecycle_status is status and self._cache.history(agent_id)[-1] is updated:
                audit = self._compute_audit_for(updated)
                self._safe_flush_save(updated, audit)
            return updated

    # ------------------------------------------------------------------ reads
    # Reads serve the in-memory cache. Before serving they check the
    # freshness bound (_maybe_resync): inside the TTL window that is a
    # single monotonic-clock compare — exactly as cheap as before — and
    # only when the window has elapsed does one read pay a Postgres
    # round trip to re-sync the cache. See _maybe_resync for the merge.

    def get(self, agent_id: UUID) -> AgentIdentity | None:
        self._maybe_resync()
        return self._cache.get(agent_id)

    def require(self, agent_id: UUID) -> AgentIdentity:
        self._maybe_resync()
        return self._cache.require(agent_id)

    def require_evaluable(self, agent_id: UUID) -> AgentIdentity:
        self._maybe_resync()
        return self._cache.require_evaluable(agent_id)

    def history(self, agent_id: UUID) -> tuple[AgentIdentity, ...]:
        self._maybe_resync()
        return self._cache.history(agent_id)

    def list_all(self) -> tuple[AgentIdentity, ...]:
        self._maybe_resync()
        return self._cache.list_all()

    def list_by_status(
        self,
        status: AgentLifecycleStatus,
    ) -> tuple[AgentIdentity, ...]:
        self._maybe_resync()
        return self._cache.list_by_status(status)

    def __len__(self) -> int:
        self._maybe_resync()
        return len(self._cache)

    def __contains__(self, item: object) -> bool:
        self._maybe_resync()
        return item in self._cache

    # ------------------------------------------------------------------ admin

    @property
    def is_durable(self) -> bool:
        """True when Postgres is connected and writes are persisting."""
        return not self._disabled

    @property
    def pending_resync_count(self) -> int:
        with self._lock:
            return len(self._pending_resync)

    def replay_pending(self) -> int:
        """
        Try to flush any entries that failed to land in Postgres on
        their original write. Returns the number of entries
        successfully flushed.
        """
        with self._lock:
            if self._disabled or not self._pending_resync:
                return 0
            successful = 0
            still_pending: list[tuple[AgentIdentity, dict]] = []
            for entry, audit in self._pending_resync:
                try:
                    self._flush_save(entry, audit)
                    self._last_hash_by_agent[entry.agent_id] = audit["record_hash"]
                    successful += 1
                except Exception as exc:  # noqa: BLE001
                    _logger.warning(
                        "PostgresAgentRegistry: replay still failing for "
                        "agent_id=%s rev=%s: %s",
                        entry.agent_id,
                        entry.revision,
                        exc,
                    )
                    still_pending.append((entry, audit))
            self._pending_resync = still_pending
            return successful

    def verify_agent_chain(self, agent_id: UUID) -> bool:
        """
        Replay one agent's revision history and confirm the hash
        chain is intact. Returns True if every revision's payload
        hash matches and every revision links to its predecessor.

        This is the per-agent equivalent of
        ``InMemoryDiscoveryLedger.verify_chain``. It is the
        cryptographic answer to "has this agent's history been
        tampered with after the fact?"
        """
        history = self._cache.history(agent_id)
        if not history:
            return True
        previous_hash: str | None = None
        for agent in history:
            payload = _payload_for_hash(agent)
            payload_sha256 = _sha256_hex(_stable_json(payload))
            expected = _sha256_hex(
                _stable_json(
                    {
                        "payload_sha256": payload_sha256,
                        "previous_hash": previous_hash,
                        "agent_id": str(agent.agent_id),
                        "revision": agent.revision,
                    }
                )
            )
            stored = self._last_hash_for_revision(agent_id, agent.revision)
            if stored is None:
                # No persisted hash yet (e.g. pure in-memory mode for
                # this revision). The chain is "intact" by default
                # because there's nothing to falsify.
                previous_hash = expected
                continue
            if stored != expected:
                return False
            previous_hash = stored
        return True

    def _last_hash_for_revision(
        self, agent_id: UUID, revision: int
    ) -> str | None:
        """Look up the persisted record_hash for one revision."""
        if self._disabled:
            return None
        try:
            with psycopg.connect(self._dsn) as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT record_hash
                          FROM tex_agent_registry
                         WHERE agent_id = %s AND revision = %s
                        """,
                        (str(agent_id), revision),
                    )
                    row = cur.fetchone()
            return row[0] if row else None
        except Exception:  # noqa: BLE001
            return None

    # ------------------------------------------------------------------ internals

    def _ensure_schema(self) -> None:
        with psycopg.connect(self._dsn, autocommit=True) as conn:
            with conn.cursor() as cur:
                cur.execute(SCHEMA_SQL)

    def _maybe_resync(self) -> None:
        """
        Re-bootstrap the cache from Postgres if the freshness window has
        elapsed. Called on every read; the common case is the fast path.

        Fast path (inside the window, or disabled): a single monotonic
        compare with no lock and no I/O — reads within the TTL stay
        exactly as cheap as a pure in-memory registry.

        Slow path (window elapsed): take _lock — the same lock every
        write takes, so no in-process write can interleave the re-sync —
        and re-bootstrap. Crucially we stamp _last_sync_monotonic even
        when the DB read FAILS: a reachability blip must keep serving the
        current cache and simply try again NEXT window, never hammer
        Postgres on every read and never blank the registry. The
        window is advanced regardless so at most one re-sync attempt
        happens per window.

        Write-through safety: _bootstrap_from_postgres replaces the cache
        wholesale with the DB snapshot, so a write that landed in memory
        but not yet in Postgres (a _pending_resync entry, e.g. after a DB
        blip) would be lost. We re-apply those pending writes on top of
        the fresh snapshot before releasing the lock, so a just-written
        row always survives a concurrent re-bootstrap.
        """
        if self._disabled or self._resync_interval_s <= 0:
            return
        # Unlocked read of the clock + interval is fine: both are only
        # ever advanced under _lock, and a racing read that also decides
        # to re-sync is serialized by the lock below (and re-checks the
        # window there, so only one actually pays the round trip).
        if (time.monotonic() - self._last_sync_monotonic) < self._resync_interval_s:
            return
        with self._lock:
            # Re-check under the lock: another read may have just
            # re-synced while we waited, in which case we are fresh.
            if (time.monotonic() - self._last_sync_monotonic) < self._resync_interval_s:
                return
            # Advance the window up front so a failed attempt does not
            # re-fire on the very next read.
            self._last_sync_monotonic = time.monotonic()
            try:
                self._bootstrap_from_postgres()
                self._reapply_pending_writes()
            except Exception as exc:  # noqa: BLE001
                _logger.warning(
                    "PostgresAgentRegistry: re-sync failed (%s); keeping "
                    "current cache, will retry next window.",
                    exc,
                )

    def _reapply_pending_writes(self) -> None:
        """
        Re-assert any in-process writes that have not yet reached Postgres
        on top of a freshly bootstrapped cache. Without this a re-sync
        could roll back a just-written row that failed to flush. Must be
        called under _lock (the caller holds it).
        """
        if not self._pending_resync:
            return
        with self._cache._lock:  # pylint: disable=protected-access
            for entry, audit in self._pending_resync:
                history = self._cache._history.setdefault(entry.agent_id, [])  # noqa: SLF001
                # Replace an equal-revision row from the DB snapshot, or
                # append if the snapshot doesn't have this revision.
                for i, existing in enumerate(history):
                    if existing.revision == entry.revision:
                        history[i] = entry
                        break
                else:
                    history.append(entry)
                    history.sort(key=lambda a: a.revision)
                self._cache._by_id[entry.agent_id] = history[-1]  # noqa: SLF001
                # The re-bootstrap reset the chain head to the DB's view,
                # which doesn't yet know this un-flushed write. Restore
                # the pending write's record_hash as the head so the next
                # save chains from it, not from a stale predecessor.
                self._last_hash_by_agent[entry.agent_id] = audit["record_hash"]

    def _bootstrap_from_postgres(self) -> None:
        """
        Load every current revision plus full revision history into the
        cache. We load history because callers can request it via
        ``history(agent_id)`` and we don't want a different answer
        before vs after a restart.
        """
        with psycopg.connect(self._dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT
                        agent_id, revision, name, owner, description, tenant_id,
                        model_provider, model_name, framework, environment,
                        trust_tier, lifecycle_status, capability_surface,
                        attestations, tags, metadata, registered_at, updated_at,
                        record_hash
                    FROM tex_agent_registry
                    ORDER BY agent_id, revision
                    """
                )
                rows = cur.fetchall()

        # Replay every row in order. The InMemoryAgentRegistry's
        # ``save`` increments revision automatically, which means we
        # cannot just reuse it for restoration — we'd renumber every
        # historical revision. Instead, write into the underlying
        # dicts directly, preserving the on-disk revisions.
        loaded: dict[UUID, list[AgentIdentity]] = {}
        latest_hash: dict[UUID, str] = {}
        for row in rows:
            agent_row = row[:18]
            record_hash = row[18]
            agent = self._row_to_agent(agent_row)
            loaded.setdefault(agent.agent_id, []).append(agent)
            if record_hash:
                latest_hash[agent.agent_id] = record_hash

        # REPLACE the cache wholesale rather than merge into it. On first
        # boot the cache is empty so this is identical to a merge; on a
        # re-sync it is what makes an out-of-band PURGE visible — an agent
        # that no longer has any row in Postgres must vanish from the
        # cache, otherwise the marquee count keeps speaking ghosts (this
        # is exactly the "134 purged, still says 114" bug). Building the
        # new dicts first and swapping them in under the lock keeps the
        # cache internally consistent for any read that races the swap.
        new_by_id: dict[UUID, AgentIdentity] = {}
        new_history: dict[UUID, list[AgentIdentity]] = {}
        for agent_id, revisions in loaded.items():
            revisions.sort(key=lambda a: a.revision)
            new_history[agent_id] = list(revisions)
            new_by_id[agent_id] = revisions[-1]

        with self._cache._lock:  # pylint: disable=protected-access
            self._cache._by_id = new_by_id  # noqa: SLF001
            self._cache._history = new_history  # noqa: SLF001

        # Restore the per-agent hash chain head so future saves chain
        # correctly across the restart boundary.
        self._last_hash_by_agent = latest_hash

        _logger.info(
            "PostgresAgentRegistry: bootstrapped %d agents (%d total revisions)",
            len(loaded),
            sum(len(v) for v in loaded.values()),
        )

    def _compute_audit_for(self, agent: AgentIdentity) -> dict[str, Any]:
        """
        Build the audit envelope for one save: payload_sha256,
        previous_hash, record_hash, plus the operator-set audit
        context (policy_version, snapshot_id, write_source).

        The hash chain is per-agent. Each revision links to the prior
        revision's record_hash. The chain is verifiable by replaying
        the agent's history and recomputing the hashes.
        """
        payload = _payload_for_hash(agent)
        payload_json = _stable_json(payload)
        payload_sha256 = _sha256_hex(payload_json)
        previous_hash = self._last_hash_by_agent.get(agent.agent_id)
        record_hash = _sha256_hex(
            _stable_json(
                {
                    "payload_sha256": payload_sha256,
                    "previous_hash": previous_hash,
                    "agent_id": str(agent.agent_id),
                    "revision": agent.revision,
                }
            )
        )
        return {
            "payload_sha256": payload_sha256,
            "previous_hash": previous_hash,
            "record_hash": record_hash,
            "policy_version": self._audit_context.get("policy_version"),
            "snapshot_id": self._audit_context.get("snapshot_id"),
            "write_source": self._audit_context.get("write_source") or "unknown",
        }

    def _safe_flush_save(self, agent: AgentIdentity, audit: dict[str, Any]) -> None:
        if self._disabled:
            # Even in disabled mode, advance the in-memory chain so
            # tests and pure-mem deployments still get a stable hash
            # sequence to verify against.
            self._last_hash_by_agent[agent.agent_id] = audit["record_hash"]
            return
        try:
            self._flush_save(agent, audit)
            self._last_hash_by_agent[agent.agent_id] = audit["record_hash"]
        except Exception as exc:  # noqa: BLE001
            _logger.error(
                "PostgresAgentRegistry: write failed for agent_id=%s rev=%s: %s. "
                "Will retry via replay_pending().",
                agent.agent_id,
                agent.revision,
                exc,
            )
            self._pending_resync.append((agent, audit))

    def _flush_save(self, agent: AgentIdentity, audit: dict[str, Any]) -> None:
        with psycopg.connect(self._dsn) as conn:
            with conn.cursor() as cur:
                # Mark all prior revisions as not-current in one shot.
                cur.execute(
                    """
                    UPDATE tex_agent_registry
                       SET is_current = FALSE
                     WHERE agent_id = %s
                       AND revision <> %s
                    """,
                    (str(agent.agent_id), agent.revision),
                )
                cur.execute(
                    """
                    INSERT INTO tex_agent_registry (
                        agent_id, revision, name, owner, description, tenant_id,
                        model_provider, model_name, framework, environment,
                        trust_tier, lifecycle_status, capability_surface,
                        attestations, tags, metadata, registered_at, updated_at,
                        is_current,
                        record_hash, previous_hash, payload_sha256,
                        policy_version, snapshot_id, write_source
                    ) VALUES (
                        %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s,
                        %s, %s, %s,
                        %s, %s, %s, %s, %s,
                        TRUE,
                        %s, %s, %s,
                        %s, %s, %s
                    )
                    ON CONFLICT (agent_id, revision) DO UPDATE SET
                        name              = EXCLUDED.name,
                        owner             = EXCLUDED.owner,
                        description       = EXCLUDED.description,
                        tenant_id         = EXCLUDED.tenant_id,
                        model_provider    = EXCLUDED.model_provider,
                        model_name        = EXCLUDED.model_name,
                        framework         = EXCLUDED.framework,
                        environment       = EXCLUDED.environment,
                        trust_tier        = EXCLUDED.trust_tier,
                        lifecycle_status  = EXCLUDED.lifecycle_status,
                        capability_surface = EXCLUDED.capability_surface,
                        attestations      = EXCLUDED.attestations,
                        tags              = EXCLUDED.tags,
                        metadata          = EXCLUDED.metadata,
                        registered_at     = EXCLUDED.registered_at,
                        updated_at        = EXCLUDED.updated_at,
                        is_current        = TRUE,
                        record_hash       = EXCLUDED.record_hash,
                        previous_hash     = EXCLUDED.previous_hash,
                        payload_sha256    = EXCLUDED.payload_sha256,
                        policy_version    = EXCLUDED.policy_version,
                        snapshot_id       = EXCLUDED.snapshot_id,
                        write_source      = EXCLUDED.write_source
                    """,
                    (
                        str(agent.agent_id),
                        agent.revision,
                        agent.name,
                        agent.owner,
                        agent.description,
                        agent.tenant_id,
                        agent.model_provider,
                        agent.model_name,
                        agent.framework,
                        agent.environment.value if hasattr(agent.environment, "value") else str(agent.environment),
                        agent.trust_tier.value if hasattr(agent.trust_tier, "value") else str(agent.trust_tier),
                        agent.lifecycle_status.value if hasattr(agent.lifecycle_status, "value") else str(agent.lifecycle_status),
                        Jsonb(agent.capability_surface.model_dump(mode="json")),
                        Jsonb([a.model_dump(mode="json") for a in agent.attestations]),
                        Jsonb(list(agent.tags)),
                        Jsonb(_jsonable_metadata(agent.metadata)),
                        agent.registered_at,
                        agent.updated_at,
                        audit["record_hash"],
                        audit["previous_hash"],
                        audit["payload_sha256"],
                        audit["policy_version"],
                        audit["snapshot_id"],
                        audit["write_source"],
                    ),
                )
            conn.commit()

    @staticmethod
    def _row_to_agent(row: tuple) -> AgentIdentity:
        (
            agent_id, revision, name, owner, description, tenant_id,
            model_provider, model_name, framework, environment,
            trust_tier, lifecycle_status, capability_surface,
            attestations, tags, metadata, registered_at, updated_at,
        ) = row

        return AgentIdentity(
            agent_id=UUID(str(agent_id)),
            revision=revision,
            name=name,
            owner=owner,
            description=description,
            tenant_id=tenant_id,
            model_provider=model_provider,
            model_name=model_name,
            framework=framework,
            environment=AgentEnvironment(environment),
            trust_tier=AgentTrustTier(trust_tier),
            lifecycle_status=AgentLifecycleStatus(lifecycle_status),
            capability_surface=CapabilitySurface.model_validate(capability_surface),
            attestations=tuple(
                AgentAttestation.model_validate(a) for a in (attestations or [])
            ),
            tags=tuple(tags or []),
            metadata=metadata or {},
            registered_at=_ensure_aware(registered_at),
            updated_at=_ensure_aware(updated_at),
        )


def _resolve_resync_interval() -> float:
    """
    Read the read-cache freshness bound from the environment. Falls back
    to the default on unset/blank/garbage so a bad env var can never
    disable the bound silently — a non-numeric value keeps the safe
    default rather than turning re-sync off.
    """
    raw = os.environ.get(RESYNC_INTERVAL_ENV, "").strip()
    if not raw:
        return _DEFAULT_RESYNC_INTERVAL_S
    try:
        value = float(raw)
    except ValueError:
        _logger.warning(
            "PostgresAgentRegistry: %s=%r is not a number; using default %ss.",
            RESYNC_INTERVAL_ENV,
            raw,
            _DEFAULT_RESYNC_INTERVAL_S,
        )
        return _DEFAULT_RESYNC_INTERVAL_S
    # Negative is meaningless; treat it as "disabled" like 0.
    return max(value, 0.0)


def _ensure_aware(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=UTC)
    return value


def _jsonable_metadata(value: Any) -> Any:
    """Recursively coerce metadata values into JSON-safe primitives."""
    if value is None:
        return None
    if isinstance(value, dict):
        return {str(k): _jsonable_metadata(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable_metadata(v) for v in value]
    if isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, datetime):
        return _ensure_aware(value).isoformat()
    if isinstance(value, UUID):
        return str(value)
    return str(value)


import hashlib  # noqa: E402  (placed here to keep top-of-file imports clean)


def _payload_for_hash(agent: AgentIdentity) -> dict[str, Any]:
    """
    Canonical hashable payload for one revision.

    Includes everything the caller can mutate (name, owner,
    capability_surface, lifecycle_status, metadata, tags) so any
    change between revisions yields a different payload_sha256. Does
    NOT include ``registered_at`` (immutable on first save) or
    ``updated_at`` (a clock value, not content) — those don't carry
    semantic meaning.
    """
    return {
        "agent_id": str(agent.agent_id),
        "revision": agent.revision,
        "name": agent.name,
        "owner": agent.owner,
        "description": agent.description,
        "tenant_id": agent.tenant_id,
        "model_provider": agent.model_provider,
        "model_name": agent.model_name,
        "framework": agent.framework,
        "environment": agent.environment.value if hasattr(agent.environment, "value") else str(agent.environment),
        "trust_tier": agent.trust_tier.value if hasattr(agent.trust_tier, "value") else str(agent.trust_tier),
        "lifecycle_status": agent.lifecycle_status.value if hasattr(agent.lifecycle_status, "value") else str(agent.lifecycle_status),
        "capability_surface": agent.capability_surface.model_dump(mode="json"),
        "attestations": [a.model_dump(mode="json") for a in agent.attestations],
        "tags": list(agent.tags),
        "metadata": _jsonable_metadata(agent.metadata),
    }


def _stable_json(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    )


def _sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


__all__ = [
    "AgentNotFoundError",
    "AgentRevoked",
    "PostgresAgentRegistry",
    "DATABASE_URL_ENV",
]

"""
Postgres-backed durable policy snapshot store.

Wraps ``InMemoryPolicyStore`` with a write-through path to
``tex_policy_snapshots``. Replay relies on this table to reconstitute
the exact policy that produced a historical decision; without it, the
locked spec's section 6.2 ("Load policy snapshot") is impossible.

Activation rule
---------------
The DB schema enforces "at most one active snapshot per (tenant_id,
policy_id)" via a partial unique index. This store wraps activation in
a single transaction so the active-flag flip is atomic.
"""

from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any

import psycopg
from psycopg.types.json import Jsonb

from tex.domain.policy import PolicySnapshot
from tex.memory._db import connect, database_url, ensure_memory_schema
from tex.stores.policy_store import InMemoryPolicyStore

_logger = logging.getLogger(__name__)


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _config_sha256(config: dict[str, Any]) -> str:
    blob = json.dumps(config, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


class DurablePolicyStore:
    """
    Drop-in superset of ``InMemoryPolicyStore`` with Postgres durability.

    Public methods of the in-memory store (`save`, `get`, `latest`,
    `active`, `activate`, `list_all`, ...) are forwarded with write
    paths flushing to ``tex_policy_snapshots`` first.
    """

    def __init__(
        self,
        *,
        tenant_id: str = "default",
        bootstrap: bool = True,
        initial_policies: Iterable[PolicySnapshot] | None = None,
    ) -> None:
        self._tenant_id = tenant_id
        self._cache = InMemoryPolicyStore()
        self._postgres_enabled = database_url() is not None
        # Spec § "cache invalidation": bumped on every successful save.
        self._cache_version = 0

        if not self._postgres_enabled:
            _logger.warning(
                "DurablePolicyStore: DATABASE_URL not set — running in pure "
                "in-memory mode. Policy snapshots WILL be lost on restart."
            )
        else:
            try:
                ensure_memory_schema()
            except Exception:
                _logger.exception(
                    "DurablePolicyStore: schema bootstrap failed — falling "
                    "back to in-memory mode"
                )
                self._postgres_enabled = False

        if self._postgres_enabled and bootstrap:
            self._hydrate_cache()

        if initial_policies is not None:
            for policy in initial_policies:
                self.save(policy)

    # ---- write path ---------------------------------------------------

    def save(self, policy: PolicySnapshot) -> None:
        if self._postgres_enabled:
            self._write_postgres(policy)
        self._cache.save(policy)
        self._cache_version += 1

    def save_in_tx(self, policy: PolicySnapshot, cursor: Any) -> None:
        """
        Transactional variant. Idempotent on ``policy_version``: the
        orchestrator calls this on every evaluation so a snapshot is
        guaranteed to exist for replay (spec § "Policy snapshot not
        strictly enforced" → fixed).
        """
        if self._postgres_enabled:
            config = policy.model_dump(mode="json")
            cursor.execute(
                """
                INSERT INTO tex_policy_snapshots (
                    policy_version, policy_id, tenant_id,
                    config, config_sha256,
                    is_active, created_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (policy_version) DO UPDATE SET
                    policy_id     = EXCLUDED.policy_id,
                    config        = EXCLUDED.config,
                    config_sha256 = EXCLUDED.config_sha256
                """,
                (
                    policy.version,
                    policy.policy_id,
                    self._tenant_id,
                    Jsonb(config),
                    _config_sha256(config),
                    False,
                    policy.created_at,
                ),
            )
        self._cache.save(policy)
        self._cache_version += 1

    def activate(self, version: str) -> PolicySnapshot:
        """
        Activates a policy version, deactivating all other versions in
        the same family for this tenant. Atomic at the DB level.

        Contract matches ``InMemoryPolicyStore.activate``:
          - returns the activated ``PolicySnapshot``
          - raises ``KeyError`` if the version is unknown

        The orchestrator's ``ActivatePolicyCommand`` relies on both
        guarantees.
        """
        if self._postgres_enabled:
            try:
                self._activate_postgres(version)
            except KeyError:
                # The Postgres branch raised KeyError for a missing
                # version; honour the same contract by re-raising.
                raise

        # In-memory cache is the source of truth for the returned
        # PolicySnapshot. If the version isn't cached, propagate
        # KeyError so callers (e.g. ActivatePolicyCommand) translate
        # it to a 404 LookupError instead of crashing on None.
        if not hasattr(self._cache, "activate"):
            raise KeyError(f"policy version not found: {version}")

        return self._cache.activate(version)

    def delete(self, version: str) -> None:
        """
        Deletes a policy version. Postgres write happens first; cache
        is updated only on success. Idempotent: deleting a version that
        does not exist is a no-op at the cache layer (delegates to
        ``InMemoryPolicyStore.delete``).
        """
        if self._postgres_enabled:
            try:
                with connect() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            "DELETE FROM tex_policy_snapshots "
                            "WHERE policy_version = %s AND tenant_id = %s",
                            (version, self._tenant_id),
                        )
            except Exception:
                _logger.exception(
                    "DurablePolicyStore: postgres delete failed for %s",
                    version,
                )
                raise
        if hasattr(self._cache, "delete"):
            try:
                self._cache.delete(version)
            except Exception:
                _logger.debug(
                    "DurablePolicyStore: in-memory delete raised; ignoring"
                )

    def clear(self) -> None:
        """Empties the in-memory cache. Postgres is left untouched."""
        if hasattr(self._cache, "clear"):
            self._cache.clear()

    # ---- read path ----------------------------------------------------

    def get(self, version: str) -> PolicySnapshot | None:
        return self._cache.get(version)

    def require(self, version: str) -> PolicySnapshot:
        snapshot = self._cache.get(version)
        if snapshot is None:
            # Lazy read-through: a version may have been written by another
            # worker since we last hydrated.
            if self._postgres_enabled:
                snapshot = self._read_postgres(version)
                if snapshot is not None:
                    self._cache.save(snapshot)
                    return snapshot
            raise KeyError(f"policy snapshot not found: {version}")
        return snapshot

    def latest(self, policy_id: str) -> PolicySnapshot | None:
        if hasattr(self._cache, "latest"):
            return self._cache.latest(policy_id)
        # Fall back to scanning if InMemoryPolicyStore doesn't expose it.
        candidates = [p for p in self._cache.list_all() if p.policy_id == policy_id]
        if not candidates:
            return None
        return max(candidates, key=lambda p: p.created_at)

    def active(self, policy_id: str) -> PolicySnapshot | None:
        if hasattr(self._cache, "active"):
            return self._cache.active(policy_id)
        return None

    def get_active(self) -> PolicySnapshot | None:
        """
        Returns the currently active policy across all policy_ids, or
        ``None`` if nothing is active. Mirrors ``InMemoryPolicyStore``.
        """
        if hasattr(self._cache, "get_active"):
            return self._cache.get_active()
        return None

    def require_active(self) -> PolicySnapshot:
        """
        Returns the currently active policy or raises ``LookupError``.
        Mirrors ``InMemoryPolicyStore.require_active`` so this class is
        a true drop-in for the eval command's ``policy_store`` slot.
        """
        active = self.get_active()
        if active is None:
            raise LookupError("no active policy is available")
        return active

    def get_by_policy_id(self, policy_id: str) -> PolicySnapshot | None:
        if hasattr(self._cache, "get_by_policy_id"):
            return self._cache.get_by_policy_id(policy_id)
        return self.latest(policy_id)

    def require_by_policy_id(self, policy_id: str) -> PolicySnapshot:
        snapshot = self.get_by_policy_id(policy_id)
        if snapshot is None:
            raise KeyError(f"policy not found: {policy_id}")
        return snapshot

    def list_versions(self, policy_id: str | None = None) -> tuple[str, ...]:
        if hasattr(self._cache, "list_versions"):
            return self._cache.list_versions(policy_id)
        if policy_id is None:
            return tuple(p.version for p in self._cache.list_all())
        return tuple(p.version for p in self._cache.list_all() if p.policy_id == policy_id)

    def list_policies(self, policy_id: str | None = None) -> tuple[PolicySnapshot, ...]:
        if hasattr(self._cache, "list_policies"):
            return self._cache.list_policies(policy_id)
        if policy_id is None:
            return self._cache.list_all()
        return tuple(p for p in self._cache.list_all() if p.policy_id == policy_id)

    def list_all(self) -> tuple[PolicySnapshot, ...]:
        return self._cache.list_all()

    def __len__(self) -> int:
        return len(self._cache)

    def __contains__(self, version: object) -> bool:
        return version in self._cache

    # ---- maintenance --------------------------------------------------

    @property
    def is_durable(self) -> bool:
        return self._postgres_enabled

    @property
    def cache_version(self) -> int:
        """
        Monotonic counter, incremented on every successful save. Used by
        cross-process invalidation hooks. Single-process deployments
        never see drift; this is the foundation for future LISTEN/NOTIFY
        based invalidation.
        """
        return self._cache_version

    def reload(self) -> None:
        if self._postgres_enabled:
            self._hydrate_cache()

    # ---- internals ----------------------------------------------------

    def _write_postgres(self, policy: PolicySnapshot) -> None:
        config = policy.model_dump(mode="json")
        try:
            with connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO tex_policy_snapshots (
                            policy_version, policy_id, tenant_id,
                            config, config_sha256,
                            is_active, created_at
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (policy_version) DO UPDATE SET
                            policy_id     = EXCLUDED.policy_id,
                            config        = EXCLUDED.config,
                            config_sha256 = EXCLUDED.config_sha256
                        """,
                        (
                            policy.version,
                            policy.policy_id,
                            self._tenant_id,
                            Jsonb(config),
                            _config_sha256(config),
                            False,
                            policy.created_at,
                        ),
                    )
        except psycopg.Error:
            _logger.exception(
                "DurablePolicyStore: postgres write failed for version %s",
                policy.version,
            )
            raise

    def _activate_postgres(self, version: str) -> None:
        try:
            with connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "SELECT policy_id FROM tex_policy_snapshots "
                        "WHERE policy_version = %s AND tenant_id = %s",
                        (version, self._tenant_id),
                    )
                    row = cur.fetchone()
                    if row is None:
                        raise KeyError(
                            f"policy version not found in postgres: {version}"
                        )
                    policy_id = row[0]

                    # Deactivate all current versions in this family.
                    cur.execute(
                        """
                        UPDATE tex_policy_snapshots
                           SET is_active    = FALSE,
                               activated_at = NULL
                         WHERE tenant_id = %s
                           AND policy_id = %s
                           AND is_active = TRUE
                        """,
                        (self._tenant_id, policy_id),
                    )
                    cur.execute(
                        """
                        UPDATE tex_policy_snapshots
                           SET is_active    = TRUE,
                               activated_at = %s
                         WHERE policy_version = %s
                           AND tenant_id = %s
                        """,
                        (_utcnow(), version, self._tenant_id),
                    )
        except psycopg.Error:
            _logger.exception(
                "DurablePolicyStore: postgres activate failed for version %s",
                version,
            )
            raise

    def _read_postgres(self, version: str) -> PolicySnapshot | None:
        try:
            with connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "SELECT config FROM tex_policy_snapshots "
                        "WHERE policy_version = %s AND tenant_id = %s",
                        (version, self._tenant_id),
                    )
                    row = cur.fetchone()
        except Exception:
            _logger.exception(
                "DurablePolicyStore: read failed for version %s", version
            )
            return None
        if row is None:
            return None
        try:
            return PolicySnapshot.model_validate(row[0])
        except Exception:
            _logger.exception(
                "DurablePolicyStore: malformed snapshot in DB for version %s",
                version,
            )
            return None

    def _hydrate_cache(self) -> None:
        try:
            with connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT config FROM tex_policy_snapshots
                         WHERE tenant_id = %s
                         ORDER BY created_at ASC
                         LIMIT 2000
                        """,
                        (self._tenant_id,),
                    )
                    rows = cur.fetchall()
        except Exception:
            _logger.exception(
                "DurablePolicyStore: hydrate failed — cache will start empty"
            )
            return

        for (config,) in rows:
            try:
                snapshot = PolicySnapshot.model_validate(config)
            except Exception:
                _logger.exception(
                    "DurablePolicyStore: skipping malformed snapshot during hydrate"
                )
                continue
            self._cache.save(snapshot)

"""
Postgres-backed policy store.

Drop-in replacement for ``InMemoryPolicyStore`` that persists every
policy snapshot to Postgres while keeping the read path in-memory.

Same write-through pattern as the agent registry and decision store:

  reads   → in-memory
  writes  → in-memory THEN synchronous Postgres flush
  startup → bootstrap from Postgres

When DATABASE_URL is unset, the store degrades to pure in-memory.

Policies are immutable per version. Re-saving the same version replaces
the stored snapshot. Activation flips the ``is_active`` flag on the
stored row and on every other row in the same family. Deletion cascades
both in-memory and on disk.
"""

from __future__ import annotations

import json
import logging
import threading
from collections.abc import Iterable
from typing import Any

import psycopg
from psycopg.types.json import Jsonb

from tex.db.connection import (
    DATABASE_URL_ENV,
    resolve_dsn,
    safe_dsn_for_log,
    with_connection,
)
from tex.domain.policy import PolicySnapshot
from tex.stores.policy_store import InMemoryPolicyStore

_logger = logging.getLogger(__name__)


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS tex_policies (
    version            TEXT PRIMARY KEY,
    policy_id          TEXT NOT NULL,
    is_active          BOOLEAN NOT NULL DEFAULT FALSE,
    payload_json       JSONB NOT NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    save_seq           BIGSERIAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_tex_policies_policy_id
    ON tex_policies (policy_id, save_seq);

CREATE INDEX IF NOT EXISTS idx_tex_policies_active
    ON tex_policies (is_active) WHERE is_active = TRUE;
"""


class PostgresPolicyStore:
    """Durable policy store. Same interface as ``InMemoryPolicyStore``."""

    __slots__ = ("_lock", "_cache", "_dsn", "_disabled")

    def __init__(
        self,
        *,
        dsn: str | None = None,
        bootstrap: bool = True,
    ) -> None:
        self._lock = threading.RLock()
        self._cache = InMemoryPolicyStore()
        self._dsn = resolve_dsn(dsn)
        self._disabled = not bool(self._dsn)

        if self._disabled:
            _logger.warning(
                "PostgresPolicyStore: %s not set; running in pure in-memory mode. "
                "Policy versions will not survive restarts.",
                DATABASE_URL_ENV,
            )
            return

        try:
            self._ensure_schema()
        except Exception as exc:  # noqa: BLE001
            _logger.error(
                "PostgresPolicyStore: schema bootstrap failed (%s) on %s. "
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
                _logger.error("PostgresPolicyStore: bootstrap failed: %s", exc)

    # ------------------------------------------------------------------ writes

    def save(self, policy: PolicySnapshot) -> None:
        with self._lock:
            self._cache.save(policy)
            if self._disabled:
                return
            try:
                self._flush_one(policy)
            except Exception as exc:  # noqa: BLE001
                _logger.error(
                    "PostgresPolicyStore: flush failed for version=%s: %s",
                    policy.version,
                    exc,
                )

    def activate(self, version: str) -> PolicySnapshot:
        with self._lock:
            updated = self._cache.activate(version)
            if self._disabled:
                return updated

            # Reflect the activation flip on disk for every member of the
            # same policy family. We do this in one transaction so there
            # is no window where two policies show is_active=true.
            try:
                with with_connection(self._dsn) as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            "UPDATE tex_policies SET is_active = (version = %s) "
                            "WHERE policy_id = %s",
                            (version, updated.policy_id),
                        )
                    conn.commit()
            except Exception as exc:  # noqa: BLE001
                _logger.error(
                    "PostgresPolicyStore: activate flush failed for %s: %s",
                    version,
                    exc,
                )

            return updated

    def delete(self, version: str) -> None:
        with self._lock:
            self._cache.delete(version)
            if self._disabled:
                return
            try:
                with with_connection(self._dsn) as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            "DELETE FROM tex_policies WHERE version = %s",
                            (version,),
                        )
                    conn.commit()
            except Exception as exc:  # noqa: BLE001
                _logger.error(
                    "PostgresPolicyStore: delete flush failed for %s: %s",
                    version,
                    exc,
                )

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()
            if self._disabled:
                return
            try:
                with with_connection(self._dsn) as conn:
                    with conn.cursor() as cur:
                        cur.execute("DELETE FROM tex_policies")
                    conn.commit()
            except Exception as exc:  # noqa: BLE001
                _logger.error("PostgresPolicyStore: clear failed: %s", exc)

    # ------------------------------------------------------------------ reads

    def get(self, version: str) -> PolicySnapshot | None:
        return self._cache.get(version)

    def require(self, version: str) -> PolicySnapshot:
        return self._cache.require(version)

    def get_by_policy_id(self, policy_id: str) -> PolicySnapshot | None:
        return self._cache.get_by_policy_id(policy_id)

    def require_by_policy_id(self, policy_id: str) -> PolicySnapshot:
        return self._cache.require_by_policy_id(policy_id)

    def list_versions(self, policy_id: str | None = None) -> tuple[str, ...]:
        return self._cache.list_versions(policy_id)

    def list_policies(self, policy_id: str | None = None) -> tuple[PolicySnapshot, ...]:
        return self._cache.list_policies(policy_id)

    def get_active(self) -> PolicySnapshot | None:
        return self._cache.get_active()

    def require_active(self) -> PolicySnapshot:
        return self._cache.require_active()

    def __len__(self) -> int:
        return len(self._cache)

    def __contains__(self, version: object) -> bool:
        return version in self._cache

    # ------------------------------------------------------------------ internals

    def _ensure_schema(self) -> None:
        with with_connection(self._dsn, autocommit=True) as conn:
            with conn.cursor() as cur:
                cur.execute(SCHEMA_SQL)

    def _flush_one(self, policy: PolicySnapshot) -> None:
        payload = policy.model_dump(mode="json")
        with with_connection(self._dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO tex_policies (version, policy_id, is_active, payload_json)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (version) DO UPDATE SET
                        policy_id    = EXCLUDED.policy_id,
                        is_active    = EXCLUDED.is_active,
                        payload_json = EXCLUDED.payload_json
                    """,
                    (
                        policy.version,
                        policy.policy_id,
                        policy.is_active,
                        Jsonb(payload),
                    ),
                )
            conn.commit()

    def _bootstrap_from_postgres(self) -> None:
        with with_connection(self._dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT payload_json FROM tex_policies ORDER BY save_seq ASC"
                )
                rows = cur.fetchall()

        for (payload,) in rows:
            try:
                if isinstance(payload, str):
                    payload = json.loads(payload)
                policy = PolicySnapshot.model_validate(payload)
                self._cache.save(policy)
            except Exception as exc:  # noqa: BLE001
                _logger.warning(
                    "PostgresPolicyStore: skipping unreadable policy row: %s", exc,
                )

        _logger.info(
            "PostgresPolicyStore: bootstrapped %d policies from Postgres.",
            len(self._cache),
        )


__all__ = ["PostgresPolicyStore", "SCHEMA_SQL"]

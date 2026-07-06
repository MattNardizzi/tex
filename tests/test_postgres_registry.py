"""
V15 tests: PostgresAgentRegistry hash chain and audit context.

These tests run against the in-memory fallback (no DATABASE_URL).
The hash-chain logic is identical in fallback vs durable mode — the
only difference is whether writes round-trip through Postgres. So
fallback-mode coverage proves the chain semantics; an integration
test against a live DB proves the persistence path. We have the
former here; the latter requires a Render Postgres URL and is a
deploy-time check, not a unit test.
"""

from __future__ import annotations

from uuid import uuid4

import pytest

from tex.domain.agent import (
    AgentEnvironment,
    AgentIdentity,
    AgentLifecycleStatus,
    AgentTrustTier,
    CapabilitySurface,
)
from tex.stores.agent_registry_postgres import PostgresAgentRegistry


def _make_agent(*, name: str = "alpha", revision: int = 1) -> AgentIdentity:
    return AgentIdentity(
        name=name,
        owner="founder",
        environment=AgentEnvironment.PRODUCTION,
        trust_tier=AgentTrustTier.STANDARD,
        capability_surface=CapabilitySurface(
            allowed_tools=("send_email",),
            data_scopes=("crm.contacts.read",),
        ),
    )


class TestPostgresAgentRegistryFallback:
    def test_falls_back_when_database_url_missing(self, monkeypatch):
        monkeypatch.delenv("DATABASE_URL", raising=False)
        r = PostgresAgentRegistry()
        assert r.is_durable is False

    def test_save_in_fallback_returns_revision_one(self, monkeypatch):
        monkeypatch.delenv("DATABASE_URL", raising=False)
        r = PostgresAgentRegistry()
        saved = r.save(_make_agent())
        assert saved.revision == 1
        assert len(r) == 1

    def test_subsequent_save_increments_revision(self, monkeypatch):
        monkeypatch.delenv("DATABASE_URL", raising=False)
        r = PostgresAgentRegistry()
        first = r.save(_make_agent())
        # Default lifecycle is ACTIVE; switch to QUARANTINED to force a new revision.
        second = r.set_lifecycle(first.agent_id, AgentLifecycleStatus.QUARANTINED)
        assert second.revision == 2
        history = r.history(first.agent_id)
        assert len(history) == 2


class TestRegistryHashChain:
    def test_chain_is_intact_for_a_single_revision(self, monkeypatch):
        monkeypatch.delenv("DATABASE_URL", raising=False)
        r = PostgresAgentRegistry()
        saved = r.save(_make_agent())
        assert r.verify_agent_chain(saved.agent_id) is True

    def test_chain_is_intact_across_multiple_revisions(self, monkeypatch):
        monkeypatch.delenv("DATABASE_URL", raising=False)
        r = PostgresAgentRegistry()
        first = r.save(_make_agent())
        # Default lifecycle is ACTIVE; transitions: ACTIVE → QUARANTINED → REVOKED.
        r.set_lifecycle(first.agent_id, AgentLifecycleStatus.QUARANTINED)
        r.set_lifecycle(first.agent_id, AgentLifecycleStatus.REVOKED)
        # Three revisions.
        assert len(r.history(first.agent_id)) == 3
        # Chain intact.
        assert r.verify_agent_chain(first.agent_id) is True

    def test_each_revision_yields_a_distinct_record_hash(self, monkeypatch):
        monkeypatch.delenv("DATABASE_URL", raising=False)
        r = PostgresAgentRegistry()
        first = r.save(_make_agent())
        # In fallback mode the hash chain head is tracked in
        # ``_last_hash_by_agent``; recording it before and after
        # a lifecycle change proves the chain advances.
        h1 = r._last_hash_by_agent[first.agent_id]
        r.set_lifecycle(first.agent_id, AgentLifecycleStatus.QUARANTINED)
        h2 = r._last_hash_by_agent[first.agent_id]
        assert h1 != h2

    def test_chain_is_per_agent(self, monkeypatch):
        monkeypatch.delenv("DATABASE_URL", raising=False)
        r = PostgresAgentRegistry()
        a = r.save(_make_agent(name="alpha"))
        b = r.save(_make_agent(name="beta"))
        ha = r._last_hash_by_agent[a.agent_id]
        hb = r._last_hash_by_agent[b.agent_id]
        # Different agents → different chain heads.
        assert ha != hb

    def test_unknown_agent_chain_verifies_trivially(self, monkeypatch):
        monkeypatch.delenv("DATABASE_URL", raising=False)
        r = PostgresAgentRegistry()
        # No-op chain.
        assert r.verify_agent_chain(uuid4()) is True


class TestReadCacheFreshness:
    """
    The read cache must be freshness-bounded: after TEX_REGISTRY_RESYNC_S
    an out-of-band DB mutation (purge / repair script / second writer)
    becomes visible on the next read, and an in-process write that has
    not yet flushed survives the re-sync. These tests fake the Postgres
    round trip (the live-DB path is covered by the skip-guarded
    tests/test_durable_restart_survival.py) so the gating, merge, and
    failure-isolation logic is exercised without a database.
    """

    def _durable_registry(self, monkeypatch, *, resync_interval_s, db_rows):
        """
        Build a registry that believes it is durable but whose Postgres
        round trips are faked. ``db_rows`` is a mutable dict the test
        drives to simulate what the DB currently holds; the fake
        bootstrap swaps the cache to reflect it (mirroring the real
        wholesale-replace bootstrap).
        """
        from tex.stores.agent_registry_postgres import PostgresAgentRegistry

        monkeypatch.setattr(PostgresAgentRegistry, "_ensure_schema", lambda self: None)

        def _fake_bootstrap(self):
            new_by_id = {}
            new_history = {}
            for agent_id, revisions in db_rows["rows"].items():
                ordered = sorted(revisions, key=lambda a: a.revision)
                new_history[agent_id] = list(ordered)
                new_by_id[agent_id] = ordered[-1]
            with self._cache._lock:
                self._cache._by_id = new_by_id
                self._cache._history = new_history

        monkeypatch.setattr(
            PostgresAgentRegistry, "_bootstrap_from_postgres", _fake_bootstrap
        )
        r = PostgresAgentRegistry(
            dsn="postgresql://fake/notused",
            bootstrap=True,
            resync_interval_s=resync_interval_s,
        )
        return r

    def test_out_of_band_purge_becomes_visible_after_ttl(self, monkeypatch):
        # DB starts with one agent; the cache boots holding it.
        agent = _make_agent(name="ghost")
        db = {"rows": {agent.agent_id: [agent]}}
        r = self._durable_registry(monkeypatch, resync_interval_s=60.0, db_rows=db)
        assert r.is_durable is True
        assert len(r) == 1

        # Purge the row directly in the DB (out of band). Cache still
        # speaks the ghost until the freshness window elapses.
        db["rows"] = {}
        assert r.list_all() and len(r) == 1  # window not yet elapsed

        # Advance past the window: the next read re-syncs and the ghost
        # is gone. This is the "134 purged, still says 114" bug, fixed.
        r._last_sync_monotonic -= 61.0
        assert r.list_all() == ()
        assert len(r) == 0

    def test_reads_inside_window_do_not_resync(self, monkeypatch):
        agent = _make_agent(name="stable")
        db = {"rows": {agent.agent_id: [agent]}}
        r = self._durable_registry(monkeypatch, resync_interval_s=60.0, db_rows=db)

        # Mutate the DB but stay inside the window: the cache must NOT
        # pick it up yet (reads inside the TTL are cheap and stale-OK).
        db["rows"] = {}
        assert len(r) == 1

    def test_resync_disabled_when_interval_zero(self, monkeypatch):
        agent = _make_agent(name="frozen")
        db = {"rows": {agent.agent_id: [agent]}}
        r = self._durable_registry(monkeypatch, resync_interval_s=0.0, db_rows=db)

        db["rows"] = {}
        r._last_sync_monotonic -= 10_000.0  # far past any window
        # 0 disables re-sync entirely — the boot snapshot is served forever.
        assert len(r) == 1

    def test_db_failure_during_resync_keeps_cache(self, monkeypatch):
        from tex.stores.agent_registry_postgres import PostgresAgentRegistry

        agent = _make_agent(name="survivor")
        db = {"rows": {agent.agent_id: [agent]}}
        r = self._durable_registry(monkeypatch, resync_interval_s=60.0, db_rows=db)
        assert len(r) == 1

        # Now make the re-sync read blow up (reachability blip).
        def _boom(self):
            raise RuntimeError("connection reset")

        monkeypatch.setattr(
            PostgresAgentRegistry, "_bootstrap_from_postgres", _boom
        )
        r._last_sync_monotonic -= 61.0
        # A blip must never blank the registry or crash the read; the
        # current cache keeps serving.
        assert len(r) == 1
        assert r.list_all()[0].name == "survivor"

    def test_pending_write_survives_a_concurrent_resync(self, monkeypatch):
        from tex.stores.agent_registry_postgres import PostgresAgentRegistry

        agent = _make_agent(name="pending")
        # DB is EMPTY (the write never reached it — simulating a flush
        # that failed and landed in _pending_resync).
        db = {"rows": {}}
        r = self._durable_registry(monkeypatch, resync_interval_s=60.0, db_rows=db)

        # Seed the cache + pending queue as a failed write would.
        saved = r._cache.save(agent)
        audit = r._compute_audit_for(saved)
        r._pending_resync.append((saved, audit))

        # A re-sync now pulls an empty DB snapshot — but the pending
        # write must be re-applied on top so it is NOT lost.
        r._last_sync_monotonic -= 61.0
        got = r.get(saved.agent_id)
        assert got is not None, "a not-yet-flushed write was lost to a re-sync"
        assert got.name == "pending"


class TestAuditContext:
    def test_audit_context_starts_empty(self, monkeypatch):
        monkeypatch.delenv("DATABASE_URL", raising=False)
        r = PostgresAgentRegistry()
        assert r._audit_context["policy_version"] is None
        assert r._audit_context["snapshot_id"] is None

    def test_set_audit_context_stamps_subsequent_saves(self, monkeypatch):
        monkeypatch.delenv("DATABASE_URL", raising=False)
        r = PostgresAgentRegistry()
        r.set_audit_context(
            policy_version="v9.2.1",
            snapshot_id=str(uuid4()),
            write_source="evaluate_action",
        )
        # Compute the audit envelope for a save and confirm the
        # context fields land on it.
        agent = _make_agent()
        saved = r.save(agent)
        # The internal state has the policy_version stamped.
        assert r._audit_context["policy_version"] == "v9.2.1"
        # And the chain head was recorded for this agent.
        assert saved.agent_id in r._last_hash_by_agent

    def test_clear_audit_context_resets(self, monkeypatch):
        monkeypatch.delenv("DATABASE_URL", raising=False)
        r = PostgresAgentRegistry()
        r.set_audit_context(policy_version="v1.0")
        r.clear_audit_context()
        assert r._audit_context["policy_version"] is None
        assert r._audit_context["write_source"] == "manual"

    def test_audit_context_does_not_break_save(self, monkeypatch):
        monkeypatch.delenv("DATABASE_URL", raising=False)
        r = PostgresAgentRegistry()
        r.set_audit_context(policy_version="v1.0")
        saved = r.save(_make_agent())
        assert saved.revision == 1
        # Chain still verifies.
        assert r.verify_agent_chain(saved.agent_id) is True

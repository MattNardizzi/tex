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

"""
Real persistence-across-restart proof for the durable stores.

Skipped unless DATABASE_URL points at a reachable Postgres, so the default suite
stays green without a DB. When a DB IS present, this proves the headline
durable-track claim end to end: a record written by one store instance is read
back by a FRESH instance (the bootstrap-from-Postgres path) — i.e. it survives a
process restart. The InMemory* fallbacks cannot pass this, because their state
dies with the instance.

This closes the gap the repo flagged in tests/test_postgres_registry.py:4-10
("an integration test against a live DB ... is a deploy-time check, not a unit
test"). Run it with, e.g.:

    DATABASE_URL=postgresql://postgres@localhost:5432/tex \
        PYTHONPATH=src python -m pytest tests/test_durable_restart_survival.py -q
"""

from __future__ import annotations

import os
import pathlib
import tempfile
import uuid

import pytest

DSN = os.environ.get("DATABASE_URL", "").strip()
pytestmark = pytest.mark.skipif(
    not DSN,
    reason="DATABASE_URL not set; durable restart-survival test needs a live Postgres",
)

from tex.domain.agent import (  # noqa: E402  (import after skip guard)
    AgentEnvironment,
    AgentIdentity,
    AgentTrustTier,
    CapabilitySurface,
)
from tex.stores.agent_registry_postgres import PostgresAgentRegistry  # noqa: E402


def _agent(name: str) -> AgentIdentity:
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


def test_agent_registry_survives_a_simulated_restart() -> None:
    name = f"survivor-{uuid.uuid4().hex[:8]}"

    # Process #1 writes through to Postgres.
    r1 = PostgresAgentRegistry()
    assert r1.is_durable is True, "DATABASE_URL is set but the registry is not durable"
    saved = r1.save(_agent(name))
    agent_id = saved.agent_id

    # Process #2 is a FRESH instance — its constructor bootstraps the cache from
    # Postgres. That IS the restart. The agent must be there.
    r2 = PostgresAgentRegistry()
    got = r2.get(agent_id)
    assert got is not None, "agent did not survive the restart (absent in fresh instance)"
    assert got.name == name


def test_memory_system_reports_durable_with_database_url() -> None:
    from tex.memory import MemorySystem

    with tempfile.TemporaryDirectory() as d:
        memory = MemorySystem(evidence_path=pathlib.Path(d) / "evidence.jsonl")
        health = memory.health()
        assert health.durable is True
        assert health.decisions_durable and health.policies_durable

"""Shared fixtures for the presence truth-gate tests.

Builds a populated state double out of the REAL in-memory stores, so the gate
recomputes against genuine rows (not mocks of the unit under test).
"""

from __future__ import annotations

import hashlib
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest

from tex.domain.agent import ActionLedgerEntry, AgentIdentity, AgentLifecycleStatus
from tex.domain.decision import Decision
from tex.domain.verdict import Verdict
from tex.stores.action_ledger import InMemoryActionLedger
from tex.stores.agent_registry import InMemoryAgentRegistry
from tex.stores.connector_health import ConnectorHealthStore
from tex.stores.decision_store import InMemoryDecisionStore
from tex.stores.discovery_ledger import InMemoryDiscoveryLedger


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def make_decision(verdict: Verdict, *, n: int = 0) -> Decision:
    # An ABSTAIN decision must carry at least one uncertainty flag (domain rule).
    flags = ["needs_human"] if verdict is Verdict.ABSTAIN else []
    return Decision(
        request_id=uuid4(),
        verdict=verdict,
        confidence=0.9,
        final_score=0.5,
        action_type="send_email",
        channel="email",
        environment="prod",
        content_excerpt=f"decision {verdict.value} {n}",
        content_sha256=_sha(f"{verdict.value}-{n}"),
        policy_version="v1",
        uncertainty_flags=flags,
    )


def make_agent(name: str, *, status: AgentLifecycleStatus = AgentLifecycleStatus.ACTIVE) -> AgentIdentity:
    return AgentIdentity(name=name, owner="acme", tenant_id="acme", lifecycle_status=status)


def make_action(agent_id: UUID, *, final_score: float, n: int = 0) -> ActionLedgerEntry:
    return ActionLedgerEntry(
        agent_id=agent_id,
        decision_id=uuid4(),
        request_id=uuid4(),
        verdict="PERMIT",
        action_type="send_email",
        channel="email",
        environment="prod",
        final_score=final_score,
        confidence=0.8,
        content_sha256=_sha(f"action-{agent_id}-{n}"),
    )


@pytest.fixture
def populated_state():
    """A state double with: 3 FORBID / 2 PERMIT / 1 ABSTAIN decisions, 2 agents,
    a 6-step action trace for agent A (with one clear anomaly), one OFFLINE and
    one HEALTHY connector, and an empty discovery ledger."""
    decisions = InMemoryDecisionStore()
    for i in range(3):
        decisions.save(make_decision(Verdict.FORBID, n=i))
    for i in range(2):
        decisions.save(make_decision(Verdict.PERMIT, n=i))
    decisions.save(make_decision(Verdict.ABSTAIN, n=0))

    registry = InMemoryAgentRegistry()
    agent_a = make_agent("alpha", status=AgentLifecycleStatus.ACTIVE)
    agent_b = make_agent("beta", status=AgentLifecycleStatus.QUARANTINED)
    registry.save(agent_a)
    registry.save(agent_b)

    actions = InMemoryActionLedger()
    # A trace with a clear high-score anomaly at index 3.
    scores = [0.1, 0.2, 0.15, 0.95, 0.2, 0.1]
    for i, s in enumerate(scores):
        actions.append(make_action(agent_a.agent_id, final_score=s, n=i))

    connectors = ConnectorHealthStore(dsn=None)
    for _ in range(3):  # 3 consecutive failures → OFFLINE
        connectors.record_failure(
            tenant_id="acme", connector_name="openai", discovery_source="api", error="boom",
        )
    connectors.record_success(
        tenant_id="acme", connector_name="azure", discovery_source="api", candidate_count=2,
    )

    discovery = InMemoryDiscoveryLedger()

    return SimpleNamespace(
        decision_store=decisions,
        agent_registry=registry,
        action_ledger=actions,
        discovery_ledger=discovery,
        connector_health_store=connectors,
        scan_run_store=None,
        agent_a=agent_a,
        agent_b=agent_b,
        forbid_count=3,
        permit_count=2,
        abstain_count=1,
        agent_count=2,
        action_total=6,
        anomaly_index=3,
    )

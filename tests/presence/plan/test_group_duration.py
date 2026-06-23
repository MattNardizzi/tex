"""GROUP_BY (distributions) + LATEST/DURATION (recency, 'how long running')."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

from tex.domain.agent import AgentIdentity
from tex.domain.decision import Decision
from tex.domain.verdict import Verdict
from tex.presence.plan.executor import execute_plan
from tex.presence.plan.ir import Leaf, Op, OpKind, Plan
from tex.stores.agent_registry import InMemoryAgentRegistry
from tex.stores.decision_store import InMemoryDecisionStore

from ._world import build_world

REF = datetime(2026, 6, 15, 12, 0, 0, tzinfo=UTC)


# ───────────────────────────────── GROUP_BY (timing-independent, over the world)
def _group(field) -> Plan:
    return Plan(nodes=(
        Leaf(node_id="a", tool="identity.list_agents"),
        Op(node_id="g", kind=OpKind.GROUP_BY, inputs=("a",), args={"field": field}),
    ), output="g")


def test_group_by_owner_is_sealed():
    rc = execute_plan(_group("owner"), request=build_world(), tenant="acme")
    assert rc.grounded and rc.value == {"alice": 3, "bob": 2, "carol": 1}
    assert rc.coverage_mode is None  # SEALED over the complete unclamped registry
    assert "owner" in rc.canonical_phrase and "alice" in rc.canonical_phrase


def test_group_by_status():
    rc = execute_plan(_group("lifecycle_status"), request=build_world(), tenant="acme")
    assert rc.grounded and rc.value == {"ACTIVE": 4, "QUARANTINED": 1, "REVOKED": 1}


# ───────────────────────────────── DURATION + LATEST (deterministic reference_now)
def _agent_state():
    reg = InMemoryAgentRegistry()
    a = AgentIdentity(name="x", owner="o", tenant_id="acme",
                      registered_at=REF - timedelta(days=3), updated_at=REF - timedelta(days=3))
    reg.save(a)
    return SimpleNamespace(agent_registry=reg), a.agent_id


def _decision_state():
    ds = InMemoryDecisionStore()
    for when in (REF - timedelta(days=1), REF - timedelta(hours=2), REF - timedelta(days=5)):
        ds.save(Decision(
            request_id=uuid4(), verdict=Verdict.PERMIT, confidence=0.9, final_score=0.5,
            action_type="send_email", channel="email", environment="prod",
            content_excerpt="x", content_sha256=hashlib.sha256(str(uuid4()).encode()).hexdigest(),
            policy_version="v1", decided_at=when,
        ))
    return SimpleNamespace(decision_store=ds)


def test_duration_how_long_running():
    state, aid = _agent_state()
    plan = Plan(nodes=(
        Leaf(node_id="a", tool="identity.get_agent", params={"agent_id": str(aid)}),
        Op(node_id="d", kind=OpKind.DURATION, inputs=("a",), args={"field": "registered_at"}),
    ), output="d")
    rc = execute_plan(plan, request=state, tenant="acme", reference_now=REF)
    assert rc.grounded and rc.value == 3 * 86400
    assert "3 days" in rc.canonical_phrase and rc.coverage_mode == "recorded-timestamp"


def test_latest_then_duration_time_since_last():
    plan = Plan(nodes=(
        Leaf(node_id="a", tool="human_decision.recent_decisions"),
        Op(node_id="l", kind=OpKind.LATEST, inputs=("a",), args={"ordering_field": "decided_at"}),
        Op(node_id="d", kind=OpKind.DURATION, inputs=("l",), args={"field": "decided_at"}),
    ), output="d")
    rc = execute_plan(plan, request=_decision_state(), tenant="acme", reference_now=REF)
    assert rc.grounded and rc.value == 2 * 3600  # the most-recent decision was 2h ago
    assert "2 hours" in rc.canonical_phrase


def test_latest_then_get_reads_a_real_timestamp():
    plan = Plan(nodes=(
        Leaf(node_id="a", tool="human_decision.recent_decisions"),
        Op(node_id="l", kind=OpKind.LATEST, inputs=("a",), args={"ordering_field": "decided_at"}),
        Op(node_id="g", kind=OpKind.GET, inputs=("l",), args={"field": "decided_at"}),
    ), output="g")
    rc = execute_plan(plan, request=_decision_state(), tenant="acme", reference_now=REF)
    assert rc.grounded and rc.coverage_mode == "recorded-timestamp"
    assert "by recorded time" in rc.canonical_phrase


def test_duration_needs_a_single_row():
    rc = execute_plan(Plan(nodes=(
        Leaf(node_id="a", tool="identity.list_agents"),
        Op(node_id="d", kind=OpKind.DURATION, inputs=("a",), args={"field": "registered_at"}),
    ), output="d"), request=build_world(), tenant="acme")
    assert not rc.grounded and "single" in rc.reason

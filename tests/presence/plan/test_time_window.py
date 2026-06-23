"""TIME_WINDOW — 'today / yesterday / N-ago' answers, executor-resolved, DERIVED.

Deterministic: a fixed reference_now + controlled timestamps, so there's no midnight
flakiness. Proves the honest edges: a windowed count is DERIVED ('by recorded time'); a
count-style leaf can't be windowed; and a window reaching before the oldest row we can
see ABSTAINS rather than under-report.
"""

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

REF = datetime(2026, 6, 15, 12, 0, 0, tzinfo=UTC)


def _state() -> SimpleNamespace:
    reg = InMemoryAgentRegistry()
    for name, when in [("a-today", REF), ("b-yesterday", REF - timedelta(days=1)),
                       ("c-old", REF - timedelta(days=10))]:
        reg.save(AgentIdentity(name=name, owner="o", tenant_id="acme",
                               registered_at=when, updated_at=when))
    ds = InMemoryDecisionStore()
    for verdict, when in [(Verdict.FORBID, REF), (Verdict.FORBID, REF - timedelta(days=1)),
                          (Verdict.PERMIT, REF)]:
        ds.save(Decision(
            request_id=uuid4(), verdict=verdict, confidence=0.9, final_score=0.5,
            action_type="send_email", channel="email", environment="prod",
            content_excerpt="x", content_sha256=hashlib.sha256(str(uuid4()).encode()).hexdigest(),
            policy_version="v1", decided_at=when,
        ))
    return SimpleNamespace(agent_registry=reg, decision_store=ds)


def _run(plan):
    return execute_plan(plan, request=_state(), tenant="acme", reference_now=REF)


def _agents_window(**win) -> Plan:
    return Plan(nodes=(
        Leaf(node_id="a", tool="identity.list_agents"),
        Op(node_id="w", kind=OpKind.TIME_WINDOW, inputs=("a",), args={"field": "registered_at", **win}),
        Op(node_id="n", kind=OpKind.COUNT, inputs=("w",)),
    ), output="n")


def test_agents_registered_today_is_derived():
    rc = _run(_agents_window(op="on", on="today"))
    assert rc.grounded and rc.value == 1
    assert rc.coverage_mode == "recorded-timestamp"           # DERIVED, not SEALED
    assert "today" in rc.canonical_phrase and "by recorded time" in rc.canonical_phrase


def test_agents_registered_yesterday():
    rc = _run(_agents_window(op="on", on="yesterday"))
    assert rc.grounded and rc.value == 1


def test_agents_registered_n_days_ago():
    rc = _run(_agents_window(op="on", on="10_days_ago"))
    assert rc.grounded and rc.value == 1                       # c-old


def test_forbids_today():
    plan = Plan(nodes=(
        Leaf(node_id="a", tool="human_decision.recent_decisions"),
        Op(node_id="f", kind=OpKind.FILTER, inputs=("a",),
           args={"field": "verdict", "op": "eq", "value": "FORBID"}),
        Op(node_id="w", kind=OpKind.TIME_WINDOW, inputs=("f",),
           args={"field": "decided_at", "op": "on", "on": "today"}),
        Op(node_id="n", kind=OpKind.COUNT, inputs=("w",)),
    ), output="n")
    rc = _run(plan)
    assert rc.grounded and rc.value == 1 and rc.coverage_mode == "recorded-timestamp"


def test_window_over_count_leaf_abstains():
    plan = Plan(nodes=(
        Leaf(node_id="a", tool="human_decision.verdict_count", params={"verdict": "FORBID"}),
        Op(node_id="w", kind=OpKind.TIME_WINDOW, inputs=("a",),
           args={"field": "decided_at", "op": "on", "on": "today"}),
        Op(node_id="n", kind=OpKind.COUNT, inputs=("w",)),
    ), output="n")
    rc = _run(plan)
    assert not rc.grounded and "needs-rows" in rc.reason


def test_incomplete_tail_window_abstains_not_underreports():
    # 'past 30 days' over a tail whose oldest row is 1 day ago → we might be missing older
    # matches → abstain rather than under-report.
    plan = Plan(nodes=(
        Leaf(node_id="a", tool="human_decision.recent_decisions"),
        Op(node_id="w", kind=OpKind.TIME_WINDOW, inputs=("a",),
           args={"field": "decided_at", "op": "after", "after": "past_30_days"}),
        Op(node_id="n", kind=OpKind.COUNT, inputs=("w",)),
    ), output="n")
    rc = _run(plan)
    assert not rc.grounded and "incomplete" in rc.reason


def test_bad_timestamp_field_abstains():
    plan = Plan(nodes=(
        Leaf(node_id="a", tool="identity.list_agents"),
        Op(node_id="w", kind=OpKind.TIME_WINDOW, inputs=("a",),
           args={"field": "name", "op": "on", "on": "today"}),  # name is not a timestamp
        Op(node_id="n", kind=OpKind.COUNT, inputs=("w",)),
    ), output="n")
    assert not _run(plan).grounded

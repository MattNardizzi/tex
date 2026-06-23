"""Regression for the independent-verifier round-2 findings.

(1) A big requested limit over a SMALL store truncates nothing, so a count must still
    ground (was wrong-abstaining 'how many decisions in total' when the brain asked
    limit:1000).
(2) A windowed ZERO over a COMPLETE snapshot is provable ('none registered yesterday'),
    witnessed by the full scanned set — not an unhelpful abstain.
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


def test_big_limit_over_small_store_still_counts():
    ds = InMemoryDecisionStore()
    for verdict in (Verdict.FORBID, Verdict.PERMIT, Verdict.ABSTAIN):
        flags = ["needs_human"] if verdict is Verdict.ABSTAIN else []
        ds.save(Decision(
            request_id=uuid4(), verdict=verdict, confidence=0.9, final_score=0.5,
            action_type="send_email", channel="email", environment="prod", content_excerpt="x",
            content_sha256=hashlib.sha256(str(uuid4()).encode()).hexdigest(),
            policy_version="v1", uncertainty_flags=flags,
        ))
    state = SimpleNamespace(decision_store=ds)
    plan = Plan(nodes=(
        Leaf(node_id="a", tool="human_decision.recent_decisions", params={"limit": 1000}),
        Op(node_id="n", kind=OpKind.COUNT, inputs=("a",)),
    ), output="n")
    rc = execute_plan(plan, request=state, tenant="acme")
    assert rc.grounded and rc.value == 3  # not 'count-clamped-incomplete'


def test_windowed_zero_over_complete_snapshot_says_none():
    reg = InMemoryAgentRegistry()
    old = REF - timedelta(days=10)  # nobody registered on the REF day
    for name in ("a", "b"):
        reg.save(AgentIdentity(name=name, owner="o", tenant_id="acme",
                               registered_at=old, updated_at=old))
    state = SimpleNamespace(agent_registry=reg)
    plan = Plan(nodes=(
        Leaf(node_id="a", tool="identity.list_agents"),
        Op(node_id="w", kind=OpKind.TIME_WINDOW, inputs=("a",),
           args={"field": "registered_at", "op": "on", "on": "today"}),
        Op(node_id="n", kind=OpKind.COUNT, inputs=("w",)),
    ), output="n")
    rc = execute_plan(plan, request=state, tenant="acme", reference_now=REF)
    assert rc.grounded and rc.value == 0
    assert "None" in rc.canonical_phrase and "by recorded time" in rc.canonical_phrase
    assert rc.evidence  # the complete scanned set is the witness

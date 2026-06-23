"""Validate the realistic test world against its pinned ground truth (WORLD_FACTS),
using the CURRENT operators — so the world is trustworthy before the new temporal/owner
operators (and the independent verifier's live battery) are built on it."""

from __future__ import annotations

from tex.presence.brain.read_tools import build_read_tool_registry
from tex.presence.plan.executor import execute_plan
from tex.presence.plan.ir import Leaf, Op, OpKind, Plan

from ._world import WORLD_FACTS, build_world


def _run(world, plan):
    return execute_plan(plan, request=world, tenant=WORLD_FACTS["tenant"])


def _count_all_agents() -> Plan:
    return Plan(nodes=(
        Leaf(node_id="a", tool="identity.list_agents"),
        Op(node_id="n", kind=OpKind.COUNT, inputs=("a",)),
    ), output="n")


def _count_filtered(field, value) -> Plan:
    return Plan(nodes=(
        Leaf(node_id="a", tool="identity.list_agents"),
        Op(node_id="f", kind=OpKind.FILTER, inputs=("a",),
           args={"field": field, "op": "eq", "value": value}),
        Op(node_id="n", kind=OpKind.COUNT, inputs=("f",)),
    ), output="n")


def test_total_agents():
    rc = _run(build_world(), _count_all_agents())
    assert rc.grounded and rc.value == WORLD_FACTS["agents_total"]


def test_agents_by_owner():
    world = build_world()
    for owner, n in WORLD_FACTS["agents_by_owner"].items():
        rc = _run(world, _count_filtered("owner", owner))
        assert rc.grounded and rc.value == n, f"{owner}: {rc.value} != {n}"


def test_agents_by_status():
    world = build_world()
    assert _run(world, _count_filtered("lifecycle_status", "ACTIVE")).value == WORLD_FACTS["agents_active"]
    assert _run(world, _count_filtered("lifecycle_status", "QUARANTINED")).value == WORLD_FACTS["agents_quarantined"]
    assert _run(world, _count_filtered("lifecycle_status", "REVOKED")).value == WORLD_FACTS["agents_revoked"]


def test_has_okta_agent():
    rc = _run(build_world(), Plan(nodes=(
        Leaf(node_id="a", tool="identity.list_agents"),
        Op(node_id="m", kind=OpKind.ABSENCE_SCAN, inputs=("a",),
           args={"field": "name", "op": "contains", "value": "okta"}),
    ), output="m"))
    assert rc.grounded and rc.value is WORLD_FACTS["has_okta_agent"]


def test_verdict_totals():
    world = build_world()
    for verdict, key in [("FORBID", "forbid_total"), ("PERMIT", "permit_total"), ("ABSTAIN", "abstain_total")]:
        rc = _run(world, Plan(nodes=(
            Leaf(node_id="a", tool="human_decision.verdict_count", params={"verdict": verdict}),
            Op(node_id="n", kind=OpKind.COUNT, inputs=("a",)),
        ), output="n"))
        assert rc.grounded and rc.value == WORLD_FACTS[key], f"{verdict}: {rc.value} != {WORLD_FACTS[key]}"


def test_evidence_records_present():
    world = build_world()
    # recent_records reads the whole (small) chain → all 3 records
    val, _ = build_read_tool_registry(world)["evidence.recent_records"]({}, tenant="acme")
    assert val["returned"] == WORLD_FACTS["evidence_total"]

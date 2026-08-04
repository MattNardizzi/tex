"""The *_total read-tools — EXACT all-store counts (no window, no clamp)."""

from __future__ import annotations

from tex.presence.plan.executor import execute_plan
from tex.presence.plan.ir import Leaf, Op, OpKind, Plan

from ._world import WORLD_FACTS, build_world


def _count(tool, **params) -> Plan:
    return Plan(nodes=(
        Leaf(node_id="a", tool=tool, params=params),
        Op(node_id="n", kind=OpKind.COUNT, inputs=("a",)),
    ), output="n")


def _run(plan):
    return execute_plan(plan, request=build_world(), tenant="acme")


def test_decision_total_all():
    rc = _run(_count("human_decision.total"))
    assert rc.grounded and rc.value == 6  # 3 forbid + 2 permit + 1 abstain
    # Tenant "acme" asked → the read is scoped to its estate (private + shared),
    # so the fleet disclosure must NOT be spoken.
    assert "across all tenants" not in rc.canonical_phrase


def test_decision_total_fleet_view_discloses():
    plan = _count("human_decision.total")
    rc = execute_plan(plan, request=build_world(), tenant=None)  # operator/fleet view
    assert rc.grounded and rc.value == 6
    assert "across all tenants" in rc.canonical_phrase  # fleet disclosure stays honest


def test_decision_total_by_verdict():
    rc = _run(_count("human_decision.total", verdict="FORBID"))
    assert rc.grounded and rc.value == WORLD_FACTS["forbid_total"]
    # The honored filter is SPOKEN — a forbid count can never sound like a bare total.
    assert "forbid" in rc.canonical_phrase.casefold()


def test_action_total_refuses_verdict_filter():
    # action_total cannot filter by verdict; answering the unfiltered total for a
    # verdict question is the sealed-wrong-answer failure — it must refuse instead.
    rc = _run(_count("execution.action_total", verdict="FORBID"))
    assert not rc.grounded


def test_evidence_record_total():
    rc = _run(_count("evidence.record_total"))
    assert rc.grounded and rc.value == WORLD_FACTS["evidence_total"]


def test_action_total():
    rc = _run(_count("execution.action_total"))
    assert rc.grounded and rc.value == 3  # the world has 3 actions for billing-bot

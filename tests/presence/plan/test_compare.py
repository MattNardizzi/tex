"""COMPARE / DIFF_OVER_WINDOW — relate two grounded scalars (more/fewer, delta)."""

from __future__ import annotations

from tex.presence.plan.executor import execute_plan
from tex.presence.plan.ir import Leaf, Op, OpKind, Plan

from ._world import build_world


def _two_counts_then(kind, **args) -> Plan:
    # forbids (3) vs permits (2) over the world
    return Plan(nodes=(
        Leaf(node_id="a", tool="human_decision.verdict_count", params={"verdict": "FORBID"}),
        Op(node_id="ca", kind=OpKind.COUNT, inputs=("a",)),
        Leaf(node_id="b", tool="human_decision.verdict_count", params={"verdict": "PERMIT"}),
        Op(node_id="cb", kind=OpKind.COUNT, inputs=("b",)),
        Op(node_id="r", kind=kind, inputs=("ca", "cb"), args=args),
    ), output="r")


def _run(plan):
    return execute_plan(plan, request=build_world(), tenant="acme")


def test_compare_more_forbids_than_permits():
    rc = _run(_two_counts_then(OpKind.COMPARE, relation="gt"))
    assert rc.grounded and rc.value is True
    assert "greater than" in rc.canonical_phrase and "3" in rc.canonical_phrase


def test_compare_equal_is_false():
    rc = _run(_two_counts_then(OpKind.COMPARE, relation="eq"))
    assert rc.grounded and rc.value is False


def test_diff_over_window_signed_delta():
    rc = _run(_two_counts_then(OpKind.DIFF_OVER_WINDOW, left_label="forbids", right_label="permits"))
    assert rc.grounded and rc.value == 1                      # 3 forbids - 2 permits
    assert "more" in rc.canonical_phrase and "3 vs 2" in rc.canonical_phrase


def test_compare_abstains_if_an_operand_is_ungrounded():
    # 0 SLEEPING agents → that COUNT abstains → COMPARE can't relate it.
    plan = Plan(nodes=(
        Leaf(node_id="a", tool="identity.list_agents"),
        Op(node_id="fr", kind=OpKind.FILTER, inputs=("a",),
           args={"field": "lifecycle_status", "op": "eq", "value": "SLEEPING"}),
        Op(node_id="c0", kind=OpKind.COUNT, inputs=("fr",)),
        Leaf(node_id="b", tool="identity.list_agents"),
        Op(node_id="cb", kind=OpKind.COUNT, inputs=("b",)),
        Op(node_id="r", kind=OpKind.COMPARE, inputs=("c0", "cb"), args={"relation": "gt"}),
    ), output="r")
    assert not _run(plan).grounded

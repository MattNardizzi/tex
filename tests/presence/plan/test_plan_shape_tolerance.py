"""Tolerate the LLM's plan-shape variance — a count-style leaf IS a value.

Round-3 found the model sometimes emits a bare count-leaf as output, feeds raw count-leaves
to COMPARE, or does count_leaf → GET(total) instead of wrapping in COUNT. Those used to
wrong-abstain (honest, but a stability miss on 'how many evidence records' / 'more forbids
than permits'). The executor now coerces a count-style leaf to its count at the output and
COMPARE boundaries, so every shape grounds.
"""

from __future__ import annotations

from tex.presence.plan.executor import execute_plan
from tex.presence.plan.ir import Leaf, Op, OpKind, Plan

from ._world import WORLD_FACTS, build_world


def _run(plan):
    return execute_plan(plan, request=build_world(), tenant="acme")


def test_bare_count_leaf_as_output_grounds():
    plan = Plan(nodes=(
        Leaf(node_id="a", tool="human_decision.total", params={"verdict": "FORBID"}),
    ), output="a")
    rc = _run(plan)
    assert rc.grounded and rc.value == WORLD_FACTS["forbid_total"]


def test_compare_over_raw_count_leaves_grounds():
    plan = Plan(nodes=(
        Leaf(node_id="f", tool="human_decision.total", params={"verdict": "FORBID"}),
        Leaf(node_id="p", tool="human_decision.total", params={"verdict": "PERMIT"}),
        Op(node_id="c", kind=OpKind.COMPARE, inputs=("f", "p"), args={"relation": "gt"}),
    ), output="c")
    rc = _run(plan)
    assert rc.grounded and rc.value is True and "greater than" in rc.canonical_phrase


def test_get_total_on_count_leaf_grounds():
    plan = Plan(nodes=(
        Leaf(node_id="a", tool="evidence.record_total"),
        Op(node_id="g", kind=OpKind.GET, inputs=("a",), args={"field": "total"}),
    ), output="g")
    rc = _run(plan)
    assert rc.grounded and rc.value == WORLD_FACTS["evidence_total"]


def test_bare_row_list_leaf_output_still_abstains():
    # a regular row-list leaf (not a scalar) is still NOT a speakable clause → abstain
    plan = Plan(nodes=(Leaf(node_id="a", tool="identity.list_agents"),), output="a")
    rc = _run(plan)
    assert not rc.grounded and "not-a-speakable-clause" in rc.reason

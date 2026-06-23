"""The plan-IR closed-world validator + JSON round-trip (what strict tool-use emits)."""

from __future__ import annotations

import json

from tex.presence.plan.ir import Leaf, Op, OpKind, Plan, validate_plan

_TOOLS = frozenset({"identity.list_agents"})
_OPS = frozenset({OpKind.COUNT})


def _count_plan() -> Plan:
    return Plan(
        nodes=(
            Leaf(node_id="a", tool="identity.list_agents", params={"status": "REVOKED"}),
            Op(node_id="n", kind=OpKind.COUNT, inputs=("a",)),
        ),
        output="n",
    )


def test_valid_plan_has_no_errors():
    assert validate_plan(_count_plan(), allowed_tools=_TOOLS, allowed_ops=_OPS) == ()


def test_tool_not_in_registry_rejected():
    errs = validate_plan(_count_plan(), allowed_tools=frozenset(), allowed_ops=_OPS)
    assert errs and "is not a live read-tool" in errs[0]


def test_unimplemented_operator_rejected():
    errs = validate_plan(_count_plan(), allowed_tools=_TOOLS, allowed_ops=frozenset())
    assert errs and "is not implemented" in errs[0]


def test_forward_reference_is_rejected_dag_by_ordering():
    bad = Plan(
        nodes=(
            Op(node_id="n", kind=OpKind.COUNT, inputs=("a",)),  # references a node defined later
            Leaf(node_id="a", tool="identity.list_agents"),
        ),
        output="n",
    )
    errs = validate_plan(bad, allowed_tools=_TOOLS, allowed_ops=_OPS)
    assert any("is not defined before this node" in e for e in errs)


def test_output_must_be_a_defined_node():
    p = _count_plan()
    bad = Plan(nodes=p.nodes, output="does-not-exist")
    errs = validate_plan(bad, allowed_tools=_TOOLS, allowed_ops=_OPS)
    assert any("is not a node in the plan" in e for e in errs)


def test_op_with_no_inputs_rejected():
    bad = Plan(
        nodes=(
            Leaf(node_id="a", tool="identity.list_agents"),
            Op(node_id="n", kind=OpKind.COUNT, inputs=()),
        ),
        output="n",
    )
    errs = validate_plan(bad, allowed_tools=_TOOLS, allowed_ops=_OPS)
    assert any("has no inputs" in e for e in errs)


def test_discriminated_union_json_round_trip():
    p = _count_plan()
    restored = Plan.model_validate(json.loads(p.model_dump_json()))
    assert restored == p

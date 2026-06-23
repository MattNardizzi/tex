"""Adversarial plans + the operator-purity invariant.

The load-bearing claim a regulator/adversary attacks first: "the model can make the
gate speak a wrong or ungrounded value." These tests prove it cannot — every operator
is a pure recompute over the rows it binds, hostile literals are inert lookup keys, an
incomplete source can never assert a 'no', and a plan can never widen tenant scope or
speak raw rows.
"""

from __future__ import annotations

from tex.presence.plan.executor import CERTIFIED_PURE_OPS, IMPLEMENTED_OPS, execute_plan
from tex.presence.plan.ir import Leaf, Op, OpKind, Plan


def _run(state, plan, tenant="acme"):
    return execute_plan(plan, request=state, tenant=tenant)


def _count_agents() -> Plan:
    return Plan(nodes=(
        Leaf(node_id="a", tool="identity.list_agents"),
        Op(node_id="n", kind=OpKind.COUNT, inputs=("a",)),
    ), output="n")


# ───────────────────────────────── the structural operator-purity invariant
def test_implemented_ops_are_exactly_the_certified_pure_ops():
    """Lockstep: the executor refuses to run any op that isn't certified pure, and we
    don't certify ops we don't run. (The import-time guard already enforces ⊆; this
    pins equality so a drift in either direction is caught.)"""
    assert IMPLEMENTED_OPS == CERTIFIED_PURE_OPS


# ───────────────────────────────── purity: value is re-derivable from the rows
def test_count_value_equals_its_bound_witness(populated_state):
    rc = _run(populated_state, _count_agents())
    # The spoken count is exactly the number of rows it bound as evidence — it cannot
    # be a number the rows don't support (2 agents, 2 witness refs).
    assert rc.grounded and rc.value == len(rc.evidence) == 2


def test_operators_are_deterministic(populated_state):
    a = _run(populated_state, _count_agents())
    b = _run(populated_state, _count_agents())
    assert a.value == b.value and a.canonical_phrase == b.canonical_phrase


# ───────────────────────────────── hostile literals are inert lookup keys
def test_injection_literal_is_only_a_lookup_key(populated_state):
    """A SQL/prompt-injection-shaped literal in a filter is just a string compared
    against the rows — it matches nothing, so the answer is a clean sealed 'no'; the
    literal is never executed or spoken as a fact."""
    plan = Plan(nodes=(
        Leaf(node_id="a", tool="identity.list_agents"),
        Op(node_id="m", kind=OpKind.ABSENCE_SCAN, inputs=("a",),
           args={"field": "name", "op": "contains", "value": "'; DROP TABLE agents; --"}),
    ), output="m")
    rc = _run(populated_state, plan)
    assert rc.grounded and rc.value is False
    assert "DROP TABLE" not in rc.canonical_phrase or rc.canonical_phrase.startswith("No")


# ───────────────────────────────── an incomplete source can never assert a 'no'
def test_absence_over_windowed_source_cannot_claim_no(populated_state):
    plan = Plan(nodes=(
        Leaf(node_id="a", tool="human_decision.recent_decisions"),
        Op(node_id="m", kind=OpKind.ABSENCE_SCAN, inputs=("a",),
           args={"field": "verdict", "op": "eq", "value": "FORBID"}),
    ), output="m")
    assert not _run(populated_state, plan).grounded


# ───────────────────────────────── a plan can never widen tenant scope
def test_plan_cannot_widen_tenant_scope(populated_state):
    plan = Plan(nodes=(
        Leaf(node_id="a", tool="identity.list_agents", params={"tenant": "acme"}),
        Op(node_id="n", kind=OpKind.COUNT, inputs=("a",)),
    ), output="n")
    # The session tenant ('intruder') is authoritative; the plan's 'acme' param is
    # stripped, so it reads zero rows and abstains rather than leaking acme's data.
    assert not _run(populated_state, plan, tenant="intruder").grounded


# ───────────────────────────────── never speak raw rows
def test_plan_output_that_is_raw_rows_abstains(populated_state):
    plan = Plan(nodes=(Leaf(node_id="a", tool="identity.list_agents"),), output="a")
    rc = _run(populated_state, plan)
    assert not rc.grounded and "not-a-speakable-clause" in rc.reason

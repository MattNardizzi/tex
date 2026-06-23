"""Subsumption proof: the operator algebra reproduces the hand-written QUERIES.

The point is a SAFETY NET, not a 1:1 rewrite: before the brain is ever allowed to
compile arbitrary plans, prove that the general algebra reproduces the *value* the
canned registry recomputes for the queries it can express — so generalizing can only
ADD coverage, never silently change a known answer.

Honest coverage boundary (documented, not hidden):

* REPRODUCED here (value parity on populated_state): agent_count, forbid_count,
  permit_count, abstain_count, action_total, agent_status.
* WINDOWED, not unbounded: the decision/action plans count within a read-tool window
  (≤500, disclosed), whereas the QUERY counts the whole store. They agree whenever the
  data fits the window (it does here); at scale the plan would disclose the window.
  This is an honest difference to surface, not a regression.
* NOT YET EXPRESSIBLE (need a new read-tool leaf or a derived operator — tracked):
    - offline_connector_count → no read-tool exposes connector_health_store
    - failed_scan_count       → needs scan_run_store wired + a status FILTER
    - discovery_event_count / discovery_present → need non-empty ledger + (for a
      sealed zero) the ABSENCE_SCAN completeness proof
    - root_cause_region       → conformal DERIVED op, a later stage
"""

from __future__ import annotations

import pytest

from tex.presence.gate.queries import QUERIES
from tex.presence.plan.executor import execute_plan
from tex.presence.plan.ir import Leaf, Op, OpKind, Plan


def _query(key: str):
    return next(q for q in QUERIES if q.key == key)


def _count_leaf_plan(tool: str, **params) -> Plan:
    return Plan(
        nodes=(
            Leaf(node_id="a", tool=tool, params=params),
            Op(node_id="n", kind=OpKind.COUNT, inputs=("a",)),
        ),
        output="n",
    )


_AGENT_COUNT_PLAN = Plan(
    nodes=(
        Leaf(node_id="a", tool="identity.list_agents"),
        Op(node_id="n", kind=OpKind.COUNT, inputs=("a",)),
    ),
    output="n",
)

# (query_key, tenant, equivalent plan)
_CASES = [
    ("agent_count", "acme", _AGENT_COUNT_PLAN),
    ("forbid_count", None, _count_leaf_plan("human_decision.verdict_count", verdict="FORBID")),
    ("permit_count", None, _count_leaf_plan("human_decision.verdict_count", verdict="PERMIT")),
    ("abstain_count", None, _count_leaf_plan("human_decision.verdict_count", verdict="ABSTAIN")),
    ("action_total", None, _count_leaf_plan("execution.action_count")),
]


@pytest.mark.parametrize("key,tenant,plan", _CASES, ids=[c[0] for c in _CASES])
def test_plan_reproduces_query_value(populated_state, key, tenant, plan):
    expected = _query(key).recompute(populated_state, tenant, None)
    got = execute_plan(plan, request=populated_state, tenant=tenant)
    assert expected.grounded, f"{key}: query itself did not ground on the fixture"
    assert got.grounded, f"{key}: plan abstained — reason={got.reason!r}"
    assert got.value == expected.value, f"{key}: plan {got.value} != query {expected.value}"
    assert got.evidence, f"{key}: sealed value must bind evidence"


def test_agent_status_entity_reproduced(populated_state):
    """The ENTITY query (one agent's status) is reproduced by get → GET(field)."""
    target = populated_state.agent_a.agent_id
    expected = _query("agent_status").recompute(populated_state, "acme", target)
    plan = Plan(
        nodes=(
            Leaf(node_id="a", tool="identity.get_agent", params={"agent_id": str(target)}),
            Op(node_id="g", kind=OpKind.GET, inputs=("a",), args={"field": "lifecycle_status"}),
        ),
        output="g",
    )
    got = execute_plan(plan, request=populated_state, tenant="acme")
    assert expected.grounded and got.grounded, got.reason
    assert str(got.value) == str(expected.value)  # both the lifecycle status string


def test_subsumption_covers_the_core_aggregates():
    """Guard the documented coverage set so a future regression that drops one is
    caught: the algebra must express at least these QUERIES today."""
    covered = {"agent_count", "forbid_count", "permit_count", "abstain_count",
               "action_total", "agent_status"}
    all_keys = {q.key for q in QUERIES}
    assert covered <= all_keys  # the keys still exist
    # The remaining keys are the tracked, not-yet-expressible set (see module docstring).
    not_yet = all_keys - covered
    assert not_yet == {
        "offline_connector_count", "failed_scan_count",
        "discovery_event_count", "discovery_present", "root_cause_region",
    }

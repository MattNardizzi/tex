"""Provable absence over a COMPLETE current-state list — a sealed 'no', never a guess.

This is the marquee "do I have an Okta agent?" → "No." case. The honesty hinge: a 'no'
is only sealed when the scanned set is provably COMPLETE (the full registry, unclamped);
a windowed/tail read can never prove a 'no' and must abstain.

``populated_state`` (tests/presence/conftest.py): alpha ACTIVE, beta QUARANTINED, acme.
"""

from __future__ import annotations

from tex.presence.plan.executor import execute_plan
from tex.presence.plan.ir import Leaf, Op, OpKind, Plan


def _membership(field, op, value, *, tool="identity.list_agents") -> Plan:
    return Plan(nodes=(
        Leaf(node_id="a", tool=tool),
        Op(node_id="m", kind=OpKind.ABSENCE_SCAN, inputs=("a",),
           args={"field": field, "op": op, "value": value}),
    ), output="m")


def _run(state, plan):
    return execute_plan(plan, request=state, tenant="acme")


def test_absent_membership_seals_a_provable_no(populated_state):
    rc = _run(populated_state, _membership("name", "contains", "okta"))
    assert rc.grounded and rc.value is False
    assert rc.canonical_phrase.startswith("No")
    assert len(rc.evidence) == 2  # the 2 scanned agents ARE the completeness witness


def test_present_membership_seals_yes(populated_state):
    rc = _run(populated_state, _membership("name", "contains", "alph"))
    assert rc.grounded and rc.value is True
    assert "alpha" in rc.canonical_phrase


def test_status_membership_yes_and_no(populated_state):
    yes = _run(populated_state, _membership("lifecycle_status", "eq", "QUARANTINED"))
    assert yes.grounded and yes.value is True              # beta is QUARANTINED
    no = _run(populated_state, _membership("lifecycle_status", "eq", "REVOKED"))
    assert no.grounded and no.value is False               # none revoked → sealed 'no'


def test_membership_over_incomplete_source_abstains(populated_state):
    """recent_decisions is a windowed tail, not a complete snapshot — it can't prove a
    'no', so the operator abstains rather than guess one."""
    rc = _run(populated_state,
              _membership("verdict", "eq", "FORBID", tool="human_decision.recent_decisions"))
    assert not rc.grounded and "not-complete" in rc.reason

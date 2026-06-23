"""The plan executor end-to-end over the REAL in-memory stores (populated_state).

Proves the general "compile a plan → execute over sealed rows → grounded-or-abstain"
loop answers questions that are NOT in the 11 hand-written QUERIES, while the never-
confidently-wrong invariants hold: a zero/absence result abstains (never a guessed
"no"), the value is read from the rows, and an invalid plan fails closed.

``populated_state`` (tests/presence/conftest.py): 2 agents — alpha ACTIVE, beta
QUARANTINED — tenant "acme".
"""

from __future__ import annotations

from tex.presence.plan.executor import execute_plan
from tex.presence.plan.ir import Leaf, Op, OpKind, Plan


def _leaf(tool: str = "identity.list_agents", **params) -> Leaf:
    return Leaf(node_id="a", tool=tool, params=params)


def _filter(field: str, op: str, value, *, inputs=("a",), node_id="f") -> Op:
    return Op(node_id=node_id, kind=OpKind.FILTER, inputs=inputs,
              args={"field": field, "op": op, "value": value})


def _run(state, plan, tenant="acme"):
    return execute_plan(plan, request=state, tenant=tenant)


# ───────────────────────────────────────────────── new answerable shapes (SEALED)
def test_count_all_agents(populated_state):
    rc = _run(populated_state, Plan(
        nodes=(_leaf(), Op(node_id="n", kind=OpKind.COUNT, inputs=("a",))), output="n"))
    assert rc.grounded and rc.value == 2
    assert "2" in rc.canonical_phrase and "agents" in rc.canonical_phrase
    assert len(rc.evidence) == 2 and all(r.store == "agent_registry" for r in rc.evidence)


def test_count_active_agents_is_a_composed_filter(populated_state):
    """Not a pre-written QUERY: list → filter(status) → count, with the qualifier
    'active' derived structurally from the filter (gate-authored, not model prose)."""
    rc = _run(populated_state, Plan(nodes=(
        _leaf(), _filter("lifecycle_status", "eq", "ACTIVE"),
        Op(node_id="n", kind=OpKind.COUNT, inputs=("f",))), output="n"))
    assert rc.grounded and rc.value == 1
    assert "active" in rc.canonical_phrase.lower()
    assert len(rc.evidence) == 1


def test_list_agent_names_reads_real_rows(populated_state):
    rc = _run(populated_state, Plan(nodes=(
        _leaf(), Op(node_id="l", kind=OpKind.LIST, inputs=("a",),
                    args={"field": "name", "limit": 3})), output="l"))
    assert rc.grounded
    assert "alpha" in rc.canonical_phrase and "beta" in rc.canonical_phrase
    assert len(rc.evidence) == 2


def test_exists_true_seals(populated_state):
    rc = _run(populated_state, Plan(nodes=(
        _leaf(), _filter("name", "contains", "alph"),
        Op(node_id="e", kind=OpKind.EXISTS, inputs=("f",))), output="e"))
    assert rc.grounded and rc.value is True


# ─────────────────────────────────────────────── honest abstention (never a lie)
def test_zero_count_abstains_not_seals(populated_state):
    """No REVOKED agents → the executor refuses to seal '0' (absence needs a
    completeness proof, deferred to ABSENCE_SCAN) rather than asserting it."""
    rc = _run(populated_state, Plan(nodes=(
        _leaf(), _filter("lifecycle_status", "eq", "REVOKED"),
        Op(node_id="n", kind=OpKind.COUNT, inputs=("f",))), output="n"))
    assert not rc.grounded and rc.evidence == ()


def test_exists_false_abstains_not_guesses_no(populated_state):
    rc = _run(populated_state, Plan(nodes=(
        _leaf(), _filter("name", "contains", "okta"),
        Op(node_id="e", kind=OpKind.EXISTS, inputs=("f",))), output="e"))
    assert not rc.grounded


def test_unknown_tool_fails_closed(populated_state):
    rc = _run(populated_state, Plan(nodes=(
        Leaf(node_id="a", tool="nope.nope"),
        Op(node_id="n", kind=OpKind.COUNT, inputs=("a",))), output="n"))
    assert not rc.grounded and "plan-invalid" in rc.reason


def test_every_opkind_is_implemented_and_certified_pure():
    """The coverage build implements the full algebra: every OpKind is both runnable and
    certified pure-recompute (no enum value is a silent no-op)."""
    from tex.presence.plan.executor import CERTIFIED_PURE_OPS, IMPLEMENTED_OPS

    assert IMPLEMENTED_OPS == CERTIFIED_PURE_OPS == set(OpKind)


def test_output_that_is_not_a_clause_abstains(populated_state):
    """A plan whose output is an intermediate RowSet (a leaf), not a speakable
    clause, abstains rather than speaking raw rows."""
    rc = _run(populated_state, Plan(nodes=(_leaf(),), output="a"))
    assert not rc.grounded and "not-a-speakable-clause" in rc.reason


# ─────────────────────────────────────────────────────────── tenant isolation
def test_other_tenant_sees_no_rows_and_abstains(populated_state):
    """All agents are tenant 'acme'; a different session tenant counts zero of
    them → abstain. The plan cannot widen tenant scope (executor supplies it)."""
    rc = _run(populated_state, Plan(nodes=(
        _leaf(), Op(node_id="n", kind=OpKind.COUNT, inputs=("a",))), output="n"),
        tenant="someone-else")
    assert not rc.grounded


def test_plan_cannot_override_tenant_via_params(populated_state):
    """A 'tenant' key in leaf params is stripped — the session tenant wins, so a
    hostile plan can't read another tenant's rows."""
    rc = _run(populated_state, Plan(nodes=(
        Leaf(node_id="a", tool="identity.list_agents", params={"tenant": "acme"}),
        Op(node_id="n", kind=OpKind.COUNT, inputs=("a",))), output="n"),
        tenant="someone-else")
    assert not rc.grounded  # session tenant 'someone-else' wins → no acme rows

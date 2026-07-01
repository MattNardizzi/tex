"""The plan executor — walk the brain's plan-DAG over real rows, recompute, abstain.

This is the generalization of ``gate.recompute_for``: instead of routing one claim
to one of 11 fixed ``QUERIES``, it executes an arbitrary (validated, closed-world)
plan-DAG of operators over the live read-tools and returns a
:class:`~tex.presence.gate.queries.Recompute` for the output node — exactly the
currency the existing gate/compose machinery already consumes.

Fail-closed everywhere: an invalid plan, an unimplemented operator, a tool error, a
type mismatch between nodes, or an output node that isn't a speakable clause all
yield an un-grounded ``Recompute`` (the gate then abstains). The model's plan is a
hint to execute; nothing it emits is ever spoken unless an operator re-derived it
from sealed rows.

SECURITY: ``tenant`` is supplied by the executor from the request/session, NEVER
from the plan — a ``tenant`` key in a leaf's params is stripped, so the brain can
never widen tenant scope to read another tenant's rows.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from tex.presence.brain.read_tools import build_read_tool_registry
from tex.presence.gate.queries import Recompute
from tex.presence.plan import operators as ops
from tex.presence.plan.ir import Leaf, Op, OpKind, Plan, validate_plan

__all__ = ["IMPLEMENTED_OPS", "execute_plan"]

# The REAL closed world: operators the executor can actually run. The brain is only
# ever offered these, and ``validate_plan`` rejects any plan naming an op outside it
# (so an enum value added ahead of its implementation can never be executed).
IMPLEMENTED_OPS: frozenset[OpKind] = frozenset(
    {OpKind.FILTER, OpKind.TIME_WINDOW, OpKind.COUNT, OpKind.EXISTS, OpKind.LIST, OpKind.GET,
     OpKind.ABSENCE_SCAN, OpKind.GROUP_BY, OpKind.TOP_N, OpKind.AGGREGATE, OpKind.LATEST,
     OpKind.DURATION, OpKind.COMPARE, OpKind.DIFF_OVER_WINDOW, OpKind.RATIO}
)

# OPERATOR-PURITY INVARIANT (structural, not a vibe). Every operator the gate runs MUST
# be a PURE recompute whose spoken value is re-derivable from the rows it binds as
# evidence — it may never compute a value that is not a function of those rows (the
# canonical danger the adversarial review named: a future TREND/extrapolate/AVERAGE-with-
# default operator that "computes" something the rows don't contain, silently re-importing
# confident-wrongness). An operator is allowed to execute ONLY if it is certified here.
# Adding a new operator is therefore a DELIBERATE act: you must add it to this set, which
# forces a reviewer to assert its purity (and the purity tests in test_redteam.py to cover
# it) — a silent "just add an operator" PR fails loudly at import instead.
CERTIFIED_PURE_OPS: frozenset[OpKind] = frozenset(
    {OpKind.FILTER, OpKind.TIME_WINDOW, OpKind.COUNT, OpKind.EXISTS, OpKind.LIST, OpKind.GET,
     OpKind.ABSENCE_SCAN, OpKind.GROUP_BY, OpKind.TOP_N, OpKind.AGGREGATE, OpKind.LATEST,
     OpKind.DURATION, OpKind.COMPARE, OpKind.DIFF_OVER_WINDOW, OpKind.RATIO}
)
_uncertified = IMPLEMENTED_OPS - CERTIFIED_PURE_OPS
if _uncertified:  # fail loud at import — never ship an implemented-but-uncertified operator
    raise RuntimeError(
        f"operator-purity invariant violated: implemented ops {sorted(o.value for o in _uncertified)} "
        "are not certified pure-recompute (add them to CERTIFIED_PURE_OPS + a purity test, "
        "or do not implement them)"
    )


def _state(request: Any) -> Any:
    """The store host: ``request.app.state`` on the live server, else ``request``
    itself (the test doubles expose the stores directly). Mirrors ``gate._state``."""
    state = getattr(getattr(request, "app", None), "state", None)
    return state if state is not None else request


def _coerce_to_clause(result: Any) -> "Recompute | None":
    """A count-style leaf RowSet (a scalar count with no rows) IS a value — coerce it to a
    spoken count. This tolerates the brain emitting a bare count-leaf (e.g. ``*_total``) as the
    output, or feeding one to COMPARE, instead of always wrapping it in COUNT. A regular
    row-list RowSet is not a speakable clause → ``None``."""
    if isinstance(result, Recompute):
        return result
    if isinstance(result, ops.RowSet) and not result.rows and result.total is not None:
        return ops.op_count(result)
    return None


def execute_plan(
    plan: Plan,
    *,
    request: Any,
    tenant: str | None,
    registry: dict[str, Any] | None = None,
    reference_now: datetime | None = None,
) -> Recompute:
    """Execute ``plan`` and return the output node's :class:`Recompute` (un-grounded on any
    failure → the gate abstains). ``reference_now`` is the single ground-truth 'now' that
    relative-time operators resolve against (default ``datetime.now(UTC)``)."""
    reg = registry if registry is not None else build_read_tool_registry(_state(request))
    now = reference_now or datetime.now(UTC)

    errors = validate_plan(
        plan, allowed_tools=frozenset(reg.keys()), allowed_ops=IMPLEMENTED_OPS
    )
    if errors:
        return Recompute(False, reason="plan-invalid:" + ";".join(errors[:3]))

    env: dict[str, Any] = {}
    for node in plan.nodes:
        try:
            env[node.node_id] = _run_node(node, env, reg=reg, tenant=tenant, reference_now=now)
        except Exception as exc:  # noqa: BLE001 — a plan must never raise into the voice
            return Recompute(False, reason=f"plan-node-error:{type(exc).__name__}")

    clause = _coerce_to_clause(env.get(plan.output))
    if clause is not None:
        return clause
    return Recompute(False, reason="plan-output-not-a-speakable-clause")


def _run_node(node: Any, env: dict[str, Any], *, reg: dict[str, Any], tenant: str | None,
              reference_now: datetime) -> Any:
    if isinstance(node, Leaf):
        tool = reg.get(node.tool)
        if tool is None:  # validate_plan already guards this; belt-and-braces
            return ops.RowSet((), (), node.tool, available=False, reason="unknown-tool")
        # tenant comes from the session, never the plan (see module security note).
        params = {k: v for k, v in node.params.items() if k != "tenant"}
        value, refs = tool(params, tenant=tenant)
        return ops.rowset_from_leaf(node.tool, value, refs)

    assert isinstance(node, Op)
    inputs = [env.get(i) for i in node.inputs]
    if any(x is None for x in inputs):
        return Recompute(False, reason="op-missing-input")
    first = inputs[0]

    if node.kind in (OpKind.COMPARE, OpKind.DIFF_OVER_WINDOW, OpKind.RATIO):
        operands = [_coerce_to_clause(x) for x in inputs]  # tolerate bare count-leaf operands
        if len(operands) != 2 or not all(isinstance(x, Recompute) for x in operands):
            return Recompute(False, reason=f"{node.kind.value}-needs-two-grounded-scalar-nodes")
        if node.kind is OpKind.COMPARE:
            return ops.op_compare(operands[0], operands[1], node.args)
        if node.kind is OpKind.RATIO:
            return ops.op_ratio(operands[0], operands[1], node.args)
        return ops.op_diff_over_window(operands[0], operands[1], node.args)

    if node.kind is OpKind.FILTER:
        if not isinstance(first, ops.RowSet):
            return Recompute(False, reason="filter-input-not-rowset")
        return ops.op_filter(first, node.args)
    if node.kind is OpKind.TIME_WINDOW:
        if not isinstance(first, ops.RowSet):
            return Recompute(False, reason="time-window-input-not-rowset")
        return ops.op_time_window(first, node.args, reference_now=reference_now)
    if node.kind is OpKind.COUNT:
        if not isinstance(first, ops.RowSet):
            return Recompute(False, reason="count-input-not-rowset")
        return ops.op_count(first)
    if node.kind is OpKind.EXISTS:
        if not isinstance(first, ops.RowSet):
            return Recompute(False, reason="exists-input-not-rowset")
        return ops.op_exists(first, node.args)
    if node.kind is OpKind.LIST:
        if not isinstance(first, ops.RowSet):
            return Recompute(False, reason="list-input-not-rowset")
        return ops.op_list(first, node.args)
    if node.kind is OpKind.GET:
        if not isinstance(first, ops.RowSet):
            return Recompute(False, reason="get-input-not-rowset")
        return ops.op_get(first, node.args)
    if node.kind is OpKind.ABSENCE_SCAN:
        if not isinstance(first, ops.RowSet):
            return Recompute(False, reason="absence-input-not-rowset")
        return ops.op_absence(first, node.args)
    if node.kind is OpKind.GROUP_BY:
        if not isinstance(first, ops.RowSet):
            return Recompute(False, reason="group-by-input-not-rowset")
        return ops.op_group_by(first, node.args)
    if node.kind is OpKind.TOP_N:
        if not isinstance(first, ops.RowSet):
            return Recompute(False, reason="top-n-input-not-rowset")
        return ops.op_top_n(first, node.args)
    if node.kind is OpKind.AGGREGATE:
        if not isinstance(first, ops.RowSet):
            return Recompute(False, reason="aggregate-input-not-rowset")
        return ops.op_aggregate(first, node.args)
    if node.kind is OpKind.LATEST:
        if not isinstance(first, ops.RowSet):
            return Recompute(False, reason="latest-input-not-rowset")
        return ops.op_latest(first, node.args)
    if node.kind is OpKind.DURATION:
        if not isinstance(first, ops.RowSet):
            return Recompute(False, reason="duration-input-not-rowset")
        return ops.op_duration(first, node.args, reference_now=reference_now)

    return Recompute(False, reason=f"op-not-implemented:{node.kind.value}")

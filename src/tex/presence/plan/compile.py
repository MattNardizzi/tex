"""Compile a natural-language question into a validated plan-DAG, or ``None`` → abstain.

This is the brain's NEW job, generalizing ``grounded_brain``'s draft+claims: instead of
phrasing a facts sheet, the model COMPILES the question into a typed plan over the closed
operator algebra — and emits no number, name, status, date or sentence. A deterministic
gate then executes the plan over the real rows, recomputes every value, and authors the
spoken words. So a *wrong plan is safe* (the executor abstains) and an *invented fact is
impossible* (the model never emits a fact).

Honesty discipline carried over verbatim from ``grounded_brain``: any failure — no
provider, a transport error, an unparseable payload, a plan that fails closed-world
validation — drops the whole thing to ``None`` and the gate abstains. The model's output
is never load-bearing until the plan validates AND the executor recomputes it from rows.

CRANE (arXiv:2502.01789): the model may reason freely; only the load-bearing emission —
the plan — is schema-constrained. ``plan_tool_schema`` is the strict-tool-use schema that
constrains it.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Sequence

from tex.presence.plan.executor import IMPLEMENTED_OPS
from tex.presence.plan.ir import OpKind, Plan, validate_plan

__all__ = [
    "PROPOSE_PLAN_TOOL_NAME",
    "PROPOSE_PLAN_TOOL_DESCRIPTION",
    "OP_GUIDE",
    "plan_tool_schema",
    "build_plan_system_prompt",
    "build_plan_user_prompt",
    "PlanCompiler",
]

PROPOSE_PLAN_TOOL_NAME = "propose_query_plan"
PROPOSE_PLAN_TOOL_DESCRIPTION = (
    "Emit a typed query plan — a DAG of read-tool leaves and whitelisted operators that, "
    "when executed over the real sealed rows, answers the question. Emit ONLY the plan; "
    "never a number, name, status, date, or sentence."
)

# Short, model-facing guidance per operator (kept terse; the executor is the authority).
OP_GUIDE: dict[OpKind, str] = {
    OpKind.FILTER: "keep rows where (field, op, value) holds — op ∈ eq|ne|contains|in|gt|gte|lt|lte",
    OpKind.COUNT: "the number of rows from its single input (a positive count answers; zero abstains)",
    OpKind.EXISTS: "whether ≥1 row matches its input (true answers; a 'no' abstains for now)",
    OpKind.LIST: "the first N rows projected to a field — args: field, limit (e.g. agent names)",
    OpKind.GET: "one entity's field value — args: field (the input leaf must resolve exactly one row)",
    OpKind.ABSENCE_SCAN: (
        "membership over a COMPLETE current-state list (use identity.list_agents as the input "
        "leaf) — args: field, op, value. Seals 'yes' (with the matching rows) OR a provable 'no' "
        "(with the full scanned set as the witness). Use this for 'do I have an X agent?' — NOT "
        "exists+filter, which can't prove a 'no'."
    ),
}


def plan_tool_schema() -> dict[str, Any]:
    """The JSON schema strict tool-use constrains the plan emission to."""
    return Plan.model_json_schema()


_SYSTEM_TEMPLATE = """\
You are the COMPILER of Tex's Presence system. Tex may only say what it can prove from \
the real, sealed rows in the system.

Your ONLY job: turn the user's question into a query PLAN — a small DAG of tool reads and \
operators that, when executed over the real rows, answers it. You do NOT answer, you do \
NOT count, you emit NO number, name, status, date, or sentence — ONLY the plan. A \
deterministic gate executes your plan over the live rows, recomputes every value, and \
authors the spoken words. If the plan can't ground the answer, the gate abstains — so a \
wrong plan is SAFE, and you can never state a wrong fact because you never state a fact.

HARD RULES — violating any makes your plan worthless:
1. Leaves: use ONLY these read-tools, each a node with its params (lookup keys / filters / \
limits / windows):
{tool_catalog}
   Do NOT pass a "tenant" param — the session fixes the tenant; you cannot widen it.
2. Operators: use ONLY these, as nodes whose `inputs` reference node_ids defined EARLIER \
in the plan (the plan is a DAG; order nodes so every input already exists):
{op_catalog}
3. Any literal in params/args (a name, a status like "REVOKED", a verdict like "FORBID") \
is a LOOKUP KEY the executor resolves against the rows — never a fact you assert.
4. Keep the plan minimal; `output` is the node whose result is spoken. If the question \
cannot be expressed with these tools and operators, still emit your closest plan — the \
gate will abstain safely. NEVER invent a tool, an operator, or a value.
5. You may reason before composing, but the `{tool_name}` call must contain ONLY the plan.

Call `{tool_name}` exactly once with: {{ "nodes": [ ... ], "output": "<node_id>" }}.
Each node is either a leaf {{ "node_type": "leaf", "node_id": <id>, "tool": <tool>, \
"params": {{...}} }} or an operator {{ "node_type": "op", "node_id": <id>, "kind": <op>, \
"inputs": [<node_id>...], "args": {{...}} }}.
"""


def build_plan_system_prompt(
    tool_catalog: Mapping[str, str],
    ops: Sequence[OpKind] | frozenset[OpKind] | set[OpKind],
) -> str:
    tools = "\n".join(f"  - {name}: {desc}" for name, desc in sorted(tool_catalog.items())) or "  (none)"
    op_lines = "\n".join(
        f"  - {op.value}: {OP_GUIDE.get(op, '')}" for op in sorted(ops, key=lambda o: o.value)
    ) or "  (none)"
    return _SYSTEM_TEMPLATE.format(
        tool_catalog=tools, op_catalog=op_lines, tool_name=PROPOSE_PLAN_TOOL_NAME
    )


def build_plan_user_prompt(*, question: str, tenant: str | None) -> str:
    return (
        f"Tenant: {tenant or '(unspecified)'}\n"
        f"Question: {str(question).strip()}\n\n"
        f"Compile the query plan now."
    )


def _parse_plan(payload: Any) -> Plan | None:
    """Coerce a provider payload into a ``Plan``; ``None`` on anything unexpected."""
    if isinstance(payload, Mapping):
        data: Any = dict(payload)
    else:
        dump = getattr(payload, "model_dump", None)
        if callable(dump):
            dumped = dump()
            if isinstance(dumped, Mapping) and "nodes" in dumped:
                data = dict(dumped)
            else:
                return None
        else:
            return None
    try:
        return Plan.model_validate(data)
    except Exception:  # noqa: BLE001 — any malformed plan drops to abstain
        return None


@dataclass(frozen=True, slots=True)
class PlanCompiler:
    """Wraps a swappable :class:`StructuredSemanticProvider` to emit a validated plan.

    ``provider=None`` is a deterministic no-op (returns ``None`` → the gate abstains),
    so the live path keeps working with no compiler configured."""

    provider: Any = None

    def compile(
        self,
        *,
        question: str,
        tenant: str | None,
        tool_catalog: Mapping[str, str],
        ops: frozenset[OpKind] | set[OpKind] | None = None,
    ) -> Plan | None:
        if self.provider is None:
            return None
        allowed_ops = ops if ops is not None else IMPLEMENTED_OPS
        system_prompt = build_plan_system_prompt(tool_catalog, allowed_ops)
        user_prompt = build_plan_user_prompt(question=question, tenant=tenant)
        try:
            payload = self.provider.analyze(system_prompt=system_prompt, user_prompt=user_prompt)
        except Exception:  # noqa: BLE001 — refusal / transport / schema failure → abstain
            return None

        plan = _parse_plan(payload)
        if plan is None:
            return None

        errors = validate_plan(
            plan,
            allowed_tools=frozenset(tool_catalog.keys()),
            allowed_ops=frozenset(allowed_ops),
        )
        if errors:
            return None
        return plan

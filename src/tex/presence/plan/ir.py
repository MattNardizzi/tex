"""The presence PLAN-IR — the closed-world artifact the brain compiles to.

This is the generalization of the gate's fixed ``QUERIES`` registry. Today a brain
proposes a *claim_id* that must match one of 11 hand-written recompute queries, and
anything else abstains (the canned ceiling). Here, the brain instead emits a typed
**plan-DAG** over a CLOSED operator algebra: leaves are the existing deterministic
read-tools (``presence/brain/read_tools.py``), internal nodes are whitelisted
operators (``count``/``exists``/``list``/``get``/``latest``/``filter``/…). Coverage
moves from "11 pre-written QUESTIONS" to "primitives that compose" — combinatorially
larger, while every leaf still reads only sealed rows and every value is recomputed
by the gate, never authored by the model.

Honest, load-bearing properties baked into the IR (so nothing downstream can quietly
overclaim):

* **The model emits structure, never facts.** A plan contains tool names, operator
  kinds, filter fields and *parameters the executor looks up* — never an asserted
  number, name, status or date the user will hear. Whatever the executor reads from
  the real rows is the value; the plan is a hint to verify, not an authority.
* **Closed-world or abstain.** :func:`validate_plan` rejects any leaf naming a tool
  outside the live read-tool registry and any operator outside the executor's
  *implemented* set — so an unimplemented or hallucinated operator can never run; it
  drops the plan and the gate abstains (mirrors ``grounded_brain``'s drop-on-unparseable
  discipline). The *implemented* set, not the full :class:`OpKind` enum, is the real
  closed world — an operator listed here but not yet built is simply never offered to
  the brain and is rejected if it appears.
* **DAG by construction.** A node's inputs must reference nodes defined *earlier* in
  the tuple, so the tuple order is itself a valid topological execution order and the
  graph is acyclic by construction (no cycle detector needed). Mirrors the finite,
  side-effect-free plan discipline of ``camel/plan.py`` (CaMeL, arXiv:2503.18813).

The IR is intentionally just *shape + closed vocabulary*. The semantics of each
operator (and the honesty rules — fleet-scope disclosure, provable-absence, operator
purity) live in ``operators.py`` / ``executor.py``; an operator with malformed args
fails at execution and abstains there, rather than the IR trying to type every arg.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal, Union

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "OpKind",
    "CompareOp",
    "Leaf",
    "Op",
    "Node",
    "Plan",
    "validate_plan",
]


class OpKind(StrEnum):
    """The whitelisted operator algebra — the north-star closed world.

    NOTE: the *implemented* subset (advertised by the executor) is the real closed
    world. An operator listed here that the executor has not built is never offered
    to the brain and is rejected by :func:`validate_plan` if it appears — so this
    enum can grow ahead of the executor without ever letting an unbuilt operator run.
    """

    # ── shaping ──────────────────────────────────────────────────────────────
    FILTER = "filter"          # keep rows where (field, op, value) holds
    TIME_WINDOW = "time_window"  # keep rows whose timestamp field falls in a resolved window
    # ── row-backed aggregates / selections (every value re-derivable from refs) ─
    COUNT = "count"            # number of rows (with a witness sample of refs)
    EXISTS = "exists"          # is there ≥1 row matching a predicate
    LIST = "list"             # the first N rows, projected to a named field
    GET = "get"               # one entity by id/key → a named field
    LATEST = "latest"          # the most-recent row by an ordering field
    COMPARE = "compare"        # relate two scalar node outputs (=, >, drift, …)
    DIFF_OVER_WINDOW = "diff_over_window"  # delta of a count across a window
    GROUP_BY = "group_by"      # distribution of rows by a key
    ABSENCE_SCAN = "absence_scan"  # PROVABLE non-membership / zero over a chain


class CompareOp(StrEnum):
    """The closed predicate vocabulary a ``FILTER`` (or ``EXISTS``) may use."""

    EQ = "eq"
    NE = "ne"
    CONTAINS = "contains"   # case-insensitive substring (for names/labels)
    IN = "in"               # membership in a provided list
    GT = "gt"
    GTE = "gte"
    LT = "lt"
    LTE = "lte"


# A literal the brain may pass as a tool param / operator arg. Deliberately
# JSON-scalar-or-list: the brain supplies look-up keys and thresholds, never a
# nested structure it authored.
_Scalar = Union[str, int, bool, None]
_ArgValue = Union[_Scalar, list[_Scalar]]


class _NodeBase(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    node_id: str = Field(min_length=1, max_length=64)


class Leaf(_NodeBase):
    """A read-tool invocation — the ONLY place rows enter a plan.

    ``tool`` must name a tool in the live ``build_read_tool_registry`` (checked by
    :func:`validate_plan`). ``params`` are passed to the tool as keyword args
    (``tenant`` is supplied by the executor from the request, not the plan, so the
    brain can never widen tenant scope)."""

    node_type: Literal["leaf"] = "leaf"
    tool: str = Field(min_length=1, max_length=128)
    params: dict[str, _ArgValue] = Field(default_factory=dict)


class Op(_NodeBase):
    """A deterministic operator over the outputs of earlier nodes.

    ``inputs`` reference node_ids defined earlier in the plan; ``args`` carry the
    operator's parameters (e.g. ``{"field": "lifecycle_status", "op": "eq",
    "value": "REVOKED"}`` for a FILTER). The executor validates ``args`` per
    operator and abstains on anything malformed."""

    node_type: Literal["op"] = "op"
    kind: OpKind
    inputs: tuple[str, ...] = Field(default_factory=tuple)
    args: dict[str, _ArgValue] = Field(default_factory=dict)


Node = Annotated[Union[Leaf, Op], Field(discriminator="node_type")]


class Plan(BaseModel):
    """A typed DAG of nodes plus the ``output`` node whose result is spoken.

    Multiple output-bearing nodes (a composed multi-clause answer) are supported by
    the executor reading several terminal nodes; ``output`` names the primary one.
    Validation guarantees the tuple order is a sound execution order."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    nodes: tuple[Node, ...]
    output: str = Field(min_length=1, max_length=64)
    description: str | None = Field(default=None, max_length=500)

    def by_id(self) -> dict[str, Node]:
        return {n.node_id: n for n in self.nodes}


def validate_plan(
    plan: Plan,
    *,
    allowed_tools: frozenset[str] | set[str],
    allowed_ops: frozenset[OpKind] | set[OpKind],
) -> tuple[str, ...]:
    """Closed-world + DAG validation. Returns a tuple of error strings (empty ⇒ ok).

    Any non-empty result means the plan is dropped and the gate abstains — the safe,
    fail-closed behaviour. ``allowed_tools`` is the live read-tool registry's keys;
    ``allowed_ops`` is the executor's *implemented* operator set (NOT the full enum),
    so an operator the executor cannot run is rejected here rather than attempted.
    """
    errors: list[str] = []
    if not plan.nodes:
        return ("plan has no nodes",)

    seen: set[str] = set()
    for node in plan.nodes:
        if node.node_id in seen:
            errors.append(f"duplicate node_id {node.node_id!r}")
            # keep going; downstream refs to it still resolve to *a* node
        if isinstance(node, Leaf):
            if node.tool not in allowed_tools:
                errors.append(
                    f"leaf {node.node_id!r}: tool {node.tool!r} is not a live read-tool"
                )
        else:  # Op
            if node.kind not in allowed_ops:
                errors.append(
                    f"op {node.node_id!r}: operator {node.kind.value!r} is not implemented"
                )
            if not node.inputs:
                errors.append(f"op {node.node_id!r}: operator has no inputs")
            for inp in node.inputs:
                if inp not in seen:
                    errors.append(
                        f"op {node.node_id!r}: input {inp!r} is not defined before this node"
                    )
        seen.add(node.node_id)

    if plan.output not in seen:
        errors.append(f"output {plan.output!r} is not a node in the plan")

    return tuple(errors)


# Pydantic v2 + ``from __future__ import annotations`` — make sure the discriminated
# union in ``Plan.nodes`` is fully resolved at import time.
Plan.model_rebuild()

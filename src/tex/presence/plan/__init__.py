"""Presence PLAN layer — the brain compiles a question into a typed plan-DAG over a
closed operator algebra; the gate executes it, recomputes every value from sealed
rows, and authors every spoken word. The general "ask-anything, grounded-or-abstain"
generalization of the gate's fixed ``QUERIES`` registry.

See ``ir.py`` for the plan-IR the brain emits and the closed-world validator.
``operators.py`` / ``executor.py`` carry the deterministic semantics + honesty rules.
"""

from tex.presence.plan.ir import (
    CompareOp,
    Leaf,
    Node,
    Op,
    OpKind,
    Plan,
    validate_plan,
)

__all__ = [
    "CompareOp",
    "Leaf",
    "Node",
    "Op",
    "OpKind",
    "Plan",
    "validate_plan",
]

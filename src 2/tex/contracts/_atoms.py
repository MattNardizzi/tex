"""
Atom resolver for behavioral-contract LTL atoms.

This module bridges the propositional LTL evaluator in ``_ltl`` with the
ABC paper's predicate DSL (arxiv 2602.22302 §5.1, "ContractSpec"). LTL
atoms are opaque strings; this resolver gives them concrete semantics
over a ``ContractContext`` (proposed event + ecosystem state + recent
event window).

Atom syntax
-----------
Atoms are identifier-like strings divided into tagged families. The
tag prefix (``field:``, ``state:``, ``kind:``, ``capability:``,
``actor:``, ``drift:``) selects the resolver namespace; what follows is
namespace-specific.

  field:<path><op><literal>
      Field-path lookup into the proposed event's payload, with one of
      14 ABC ContractSpec operators baked into the atom string. Path
      may be dotted (``output.pii_detected``). Examples:
          field:output.pii_detected==false
          field:output.tone_score>=0.7
          field:tool_id!=delete
          field:request_amount<=10000
          field:output.text~contains:credit-card

  state:<path><op><literal>
      Same operator vocabulary but resolved against the
      ``EcosystemState`` snapshot. Examples:
          state:sliding_window_compromise_ratio<0.1
          state:active_governance_graph_id==policy-v3

  drift:<signal_name><op><literal>
      Numeric comparison against a value in
      ``EcosystemState.aggregate_drift_signals``. Example:
          drift:ftc_risk<0.5

  kind:<event_kind>
      True iff the proposed event's ``event_kind`` equals the literal.

  capability:<id>
      True iff ``id`` is in ``EcosystemState.active_capability_ids``.

  actor:<entity_id>
      True iff the proposed event's actor matches.

  upstream:<event_id>
      True iff ``event_id`` ∈ proposed.upstream_event_ids — useful for
      Until-style "no action without prior approval" patterns.

Reference
---------
- arxiv 2602.22302 §5.1 — ContractSpec 14 operators:
  ``equals, not_equals, gt, gte, lt, lte, in, not_in, contains,
  not_contains, matches, exists, expr, between``.

Engineering choices (paper silent):

* ``in`` / ``not_in`` accept comma-separated literals:
  ``field:tool_id~in:read,write,list``. The ``~`` separator is used so
  the atom remains LTL-tokenisable (``,`` is reserved by the LTL
  evaluator's tokenizer).
* ``matches`` uses Python ``re.search`` (substring regex), not
  ``re.fullmatch``, matching the paper's described "pattern matching"
  intent without requiring user-anchored regexes.
* ``expr`` (sandboxed cross-field arithmetic) is intentionally NOT
  supported here — its security model deserves its own thread.
  TODO(P2): vendor a sandboxed expression evaluator per ABC §5.5
  ("intentionally not Turing-complete").
* Numeric coercion: literals that parse as ``float`` are compared
  numerically; otherwise comparisons are string-typed. We match the
  reference impl's ``ContractSpec`` flat-dict semantics.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from tex.contracts._ltl import AtomResolver
from tex.ecosystem.proposed_event import ProposedEvent
from tex.ecosystem.state import EcosystemState


# ---------------------------------------------------------------------
# Context
# ---------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ContractContext:
    """
    The bundle of values an atom can be resolved against.

    Frozen because the LTL evaluator memoises atom evaluation per
    position; allowing mutation would silently corrupt cached truth
    values across calls.
    """

    proposed_event: ProposedEvent
    state: EcosystemState
    # Ordered window of recent ProposedEvents (oldest -> newest). The
    # last entry should equal ``proposed_event`` for typical pre-check
    # invocations; for post-check the last entry is the just-executed
    # event. The window length is governed by the enforcer.
    event_window: tuple[ProposedEvent, ...] = field(default_factory=tuple)


# ---------------------------------------------------------------------
# Atom parsing
# ---------------------------------------------------------------------


_OP_TOKENS: tuple[str, ...] = (
    # Order matters: longer ops first so we don't split "==" as "=" + "=".
    "==",
    "!=",
    ">=",
    "<=",
    ">",
    "<",
    "~contains:",
    "~not_contains:",
    "~matches:",
    "~in:",
    "~not_in:",
    "~between:",
    "~exists",  # zero-arg
)


@dataclass(frozen=True, slots=True)
class _ParsedAtom:
    namespace: str  # field / state / kind / capability / actor / upstream / drift
    path: str  # the part between the namespace prefix and the operator
    op: str | None  # one of _OP_TOKENS or None for tag-only namespaces
    literal: str | None


_NAMESPACE_REQUIRES_PATH = {"field", "state", "drift"}
_NAMESPACE_TAG_ONLY = {"kind", "capability", "actor", "upstream"}


def _parse_atom(atom: str) -> _ParsedAtom:
    """Split ``atom`` into (namespace, path, op, literal)."""
    if ":" not in atom:
        # Bare atoms are treated as boolean state flags resolved via the
        # state namespace with the equality operator implicit:
        #   "compromised"  ≡  state:compromised==true
        return _ParsedAtom(namespace="state", path=atom, op="==", literal="true")

    namespace, _, rest = atom.partition(":")
    namespace = namespace.strip()
    if namespace in _NAMESPACE_TAG_ONLY:
        # No operator, ``rest`` IS the literal we test for equality with.
        return _ParsedAtom(namespace=namespace, path="", op=None, literal=rest)

    if namespace not in _NAMESPACE_REQUIRES_PATH:
        raise ValueError(f"unknown atom namespace {namespace!r} in atom {atom!r}")

    # Find the operator. Try longest first. Tilde-prefixed operators
    # carry a trailing ':' as a delimiter ("~in:") but the operator
    # name in _compare drops it ("~in") — strip here so the rest of the
    # pipeline sees a uniform op string.
    for op_token in _OP_TOKENS:
        idx = rest.find(op_token)
        if idx >= 0:
            path = rest[:idx]
            after = rest[idx + len(op_token) :]
            op = op_token.rstrip(":")
            if op == "~exists":
                if after:
                    raise ValueError(
                        f"~exists is zero-arg but got trailing literal {after!r} in {atom!r}"
                    )
                return _ParsedAtom(namespace=namespace, path=path, op=op, literal=None)
            return _ParsedAtom(namespace=namespace, path=path, op=op, literal=after)

    raise ValueError(f"no operator found in atom {atom!r}")


# ---------------------------------------------------------------------
# Operator implementations
# ---------------------------------------------------------------------


def _coerce_numeric(s: str) -> float | None:
    """Best-effort float coercion. Returns None when ``s`` isn't numeric."""
    try:
        return float(s)
    except (TypeError, ValueError):
        return None


def _compare(left: object, op: str, literal: str | None) -> bool:
    """Apply one of the 14 ContractSpec operators."""
    if op == "~exists":
        return left is not None
    if literal is None:
        raise ValueError(f"operator {op!r} requires a literal")

    # ~in and ~not_in: comma-separated literal list.
    if op == "~in":
        choices = [c.strip() for c in literal.split(",")]
        return _stringify(left) in choices
    if op == "~not_in":
        choices = [c.strip() for c in literal.split(",")]
        return _stringify(left) not in choices

    # ~contains / ~not_contains: substring against stringified left.
    if op == "~contains":
        return literal in _stringify(left)
    if op == "~not_contains":
        return literal not in _stringify(left)

    # ~matches: regex via re.search.
    if op == "~matches":
        return re.search(literal, _stringify(left)) is not None

    # ~between: comma-separated two-number range "lo,hi"; numeric.
    if op == "~between":
        parts = literal.split(",")
        if len(parts) != 2:
            raise ValueError(f"~between needs 'lo,hi', got {literal!r}")
        lo = _coerce_numeric(parts[0].strip())
        hi = _coerce_numeric(parts[1].strip())
        ln = _coerce_numeric(_stringify(left))
        if lo is None or hi is None or ln is None:
            return False
        return lo <= ln <= hi

    # Comparisons: prefer numeric, fall back to string.
    rn = _coerce_numeric(literal)
    ln = _coerce_numeric(_stringify(left)) if left is not None else None
    if rn is not None and ln is not None:
        if op == "==":
            return ln == rn
        if op == "!=":
            return ln != rn
        if op == ">":
            return ln > rn
        if op == ">=":
            return ln >= rn
        if op == "<":
            return ln < rn
        if op == "<=":
            return ln <= rn

    # Booleans / strings.
    ls = _stringify(left)
    if op == "==":
        # Special-case bool-ish literals
        if literal.lower() in ("true", "false"):
            return _truthy(left) == (literal.lower() == "true")
        return ls == literal
    if op == "!=":
        if literal.lower() in ("true", "false"):
            return _truthy(left) != (literal.lower() == "true")
        return ls != literal
    if op in (">", ">=", "<", "<="):
        # String ordering.
        if op == ">":
            return ls > literal
        if op == ">=":
            return ls >= literal
        if op == "<":
            return ls < literal
        if op == "<=":
            return ls <= literal
    raise ValueError(f"unsupported operator {op!r}")


def _stringify(v: object) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    return str(v) if v is not None else ""


def _truthy(v: object) -> bool:
    if isinstance(v, bool):
        return v
    if v is None:
        return False
    if isinstance(v, (int, float)):
        return v != 0
    if isinstance(v, str):
        return v.lower() == "true"
    return True


# ---------------------------------------------------------------------
# Path lookup
# ---------------------------------------------------------------------


def _lookup_path(root: Mapping[str, Any], path: str) -> object:
    """Dotted-path lookup; returns None on any miss (paper convention)."""
    if not path:
        return None
    cur: object = root
    for seg in path.split("."):
        if isinstance(cur, Mapping):
            cur = cur.get(seg)
        else:
            return None
        if cur is None:
            return None
    return cur


# ---------------------------------------------------------------------
# Public resolver factory
# ---------------------------------------------------------------------


def make_resolver(context: ContractContext) -> AtomResolver:
    """
    Build an AtomResolver bound to ``context``.

    The returned callable is what we hand to ``LTLFormula.evaluate_finite``.
    Trace elements are unused for the contracts use case (the contracts
    layer evaluates over a one-element trace at the proposed event), but
    we keep the AtomResolver signature uniform so future P2 enforcers
    that walk a multi-step trace can plug straight in.
    """

    def resolve(atom: str, _trace_elem: Mapping[str, object]) -> bool:
        parsed = _parse_atom(atom)
        ns = parsed.namespace

        if ns == "kind":
            return context.proposed_event.event_kind == parsed.literal

        if ns == "actor":
            return context.proposed_event.actor_entity_id == parsed.literal

        if ns == "capability":
            if parsed.literal is None:
                return False
            return parsed.literal in context.state.active_capability_ids

        if ns == "upstream":
            if parsed.literal is None:
                return False
            return parsed.literal in context.proposed_event.upstream_event_ids

        if ns == "field":
            value = _lookup_path(context.proposed_event.payload, parsed.path)
            return _compare(value, parsed.op or "==", parsed.literal)

        if ns == "state":
            # Build a flat dict mirror of the EcosystemState so
            # path-lookup is uniform with field:.
            mirror: dict[str, Any] = {
                "snapshot_at": context.state.snapshot_at,
                "state_hash": context.state.state_hash,
                "active_agent_ids": context.state.active_agent_ids,
                "active_tool_ids": context.state.active_tool_ids,
                "active_capability_ids": context.state.active_capability_ids,
                "active_governance_graph_id": context.state.active_governance_graph_id,
                "sliding_window_compromise_ratio": (
                    context.state.sliding_window_compromise_ratio
                ),
                "aggregate_drift_signals": dict(context.state.aggregate_drift_signals),
            }
            value = _lookup_path(mirror, parsed.path)
            return _compare(value, parsed.op or "==", parsed.literal)

        if ns == "drift":
            value = context.state.aggregate_drift_signals.get(parsed.path)
            return _compare(value, parsed.op or "==", parsed.literal)

        raise ValueError(f"unknown atom namespace {ns!r}")

    return resolve


__all__ = [
    "ContractContext",
    "make_resolver",
]


# Used by the enforcer to assemble a one-element trace from a context.
def trace_for(context: ContractContext) -> Sequence[Mapping[str, object]]:
    """
    Return the LTLf trace passed to the evaluator.

    For the contracts layer, the "trace" is conceptually a sequence of
    one EcosystemState snapshot at the proposed-event point, padded by
    the event_window when the contract uses past/window operators.

    Today's enforcer evaluates LTL over a single-element trace whose
    sole element carries the proposed event's payload — that is enough
    for ABC's invariant-response patterns. The window stays accessible
    via the closures created by ``make_resolver``.
    """
    return ({"_event_payload": dict(context.proposed_event.payload)},)

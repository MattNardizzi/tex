"""
PCAS stratifier.

Three jobs, in order:

1. **Helper disambiguation.** Body ``Atom`` whose predicate is in the
   helper registry is lifted to ``HelperCall``. Performed before any
   safety check so helpers don't get treated as relations.

2. **Variable safety (Apt-Blair-Walker safety / range-restricted rules).**
   * Every variable in the head must occur in a positive body atom.
   * Every variable in a negated atom must occur in a positive body atom.
   * Helpers do not bind variables: a helper-call argument variable must
     also occur in a positive body atom.
   This is the standard precondition that makes finite, deterministic
   evaluation possible (Abiteboul-Hull-Vianu, ch.13).

3. **Stratification.** Build the predicate dependency graph:
   * Positive edge ``p → q`` if ``q`` appears positively in a rule
     defining ``p``.
   * Negative edge ``p ⇸ q`` (annotated) if ``q`` appears negated.
   A program is *stratifiable* iff no cycle contains a negative edge.
   The stratifier returns a topologically-sorted list of strata; the
   evaluator processes them in order, treating each stratum as a
   semi-naive fixpoint.

Reference: arxiv 2602.16708 §3 (well-typed policies); Apt-Blair-Walker
1988; Abiteboul-Hull-Vianu ch.15.
"""

from __future__ import annotations

from dataclasses import dataclass

from pydantic import BaseModel, ConfigDict, Field

from tex.pcas.language.ast import (
    Atom,
    BodyElement,
    HelperCall,
    NegatedAtom,
    Program,
    Rule,
    Variable,
)


class StratificationError(Exception):
    """Raised when a program is unsafe or has recursion through negation."""


# ---------------------------------------------------------------------------
# Helper disambiguation
# ---------------------------------------------------------------------------


def _disambiguate_body(
    body: tuple[BodyElement, ...], helper_names: frozenset[str]
) -> tuple[BodyElement, ...]:
    """Lift any positive atom whose predicate matches a helper to ``HelperCall``."""
    out: list[BodyElement] = []
    for el in body:
        if isinstance(el, Atom) and el.predicate in helper_names:
            out.append(
                HelperCall(
                    name=el.predicate,
                    args=el.args,
                    line=el.line,
                    col=el.col,
                )
            )
        elif isinstance(el, NegatedAtom) and el.atom.predicate in helper_names:
            raise StratificationError(
                f"helper {el.atom.predicate!r} cannot appear negated "
                f"(line {el.line}, col {el.col})"
            )
        else:
            out.append(el)
    return tuple(out)


def _disambiguate_program(program: Program, helper_names: frozenset[str]) -> Program:
    new_rules = tuple(
        Rule(
            annotation=r.annotation,
            head=r.head,
            body=_disambiguate_body(r.body, helper_names),
            line=r.line,
            col=r.col,
        )
        for r in program.rules
    )
    return Program(rules=new_rules, source=program.source)


# ---------------------------------------------------------------------------
# Safety check
# ---------------------------------------------------------------------------


def _check_safety(program: Program) -> None:
    """Range-restriction / safety check for every rule."""
    for rule in program.rules:
        positive_vars = {
            v.name
            for atom in (b for b in rule.body if isinstance(b, Atom))
            for v in atom.variables
            if not v.is_anonymous
        }

        # head variables must be bound
        for v in rule.head.variables:
            if v.is_anonymous:
                raise StratificationError(
                    f"anonymous variable in head of rule for {rule.head.predicate!r} "
                    f"(line {rule.line})"
                )
            if v.name not in positive_vars:
                raise StratificationError(
                    f"unsafe rule: head variable {v.name!r} of "
                    f"{rule.head.predicate!r} is not bound by any positive body atom "
                    f"(line {rule.line})"
                )

        # negated-atom variables must be bound
        for neg in rule.body_negated_atoms:
            for v in neg.variables:
                if v.is_anonymous:
                    continue
                if v.name not in positive_vars:
                    raise StratificationError(
                        f"unsafe rule: variable {v.name!r} in negated atom "
                        f"{neg.atom.predicate!r} is not bound by any positive "
                        f"body atom (line {neg.line})"
                    )

        # helper-call variables must be bound
        for helper in rule.body_helpers:
            for v in helper.variables:
                if v.is_anonymous:
                    continue
                if v.name not in positive_vars:
                    raise StratificationError(
                        f"unsafe rule: variable {v.name!r} in helper "
                        f"{helper.name!r} is not bound by any positive body atom "
                        f"(line {helper.line})"
                    )


# ---------------------------------------------------------------------------
# Stratification
# ---------------------------------------------------------------------------


class Stratum(BaseModel):
    """One stratum: a set of predicates and the rules defining them."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    index: int = Field(ge=0)
    predicates: frozenset[str]
    rules: tuple[Rule, ...]


@dataclass
class _PredicateGraph:
    nodes: set[str]
    pos_edges: dict[str, set[str]]  # p -> {q : p depends positively on q}
    neg_edges: dict[str, set[str]]


def _build_dependency_graph(program: Program) -> _PredicateGraph:
    g = _PredicateGraph(nodes=set(), pos_edges={}, neg_edges={})
    for r in program.rules:
        p = r.head.predicate
        g.nodes.add(p)
        g.pos_edges.setdefault(p, set())
        g.neg_edges.setdefault(p, set())
        for atom in r.body_positive_atoms:
            g.nodes.add(atom.predicate)
            g.pos_edges[p].add(atom.predicate)
            g.pos_edges.setdefault(atom.predicate, set())
            g.neg_edges.setdefault(atom.predicate, set())
        for neg in r.body_negated_atoms:
            g.nodes.add(neg.atom.predicate)
            g.neg_edges[p].add(neg.atom.predicate)
            g.pos_edges.setdefault(neg.atom.predicate, set())
            g.neg_edges.setdefault(neg.atom.predicate, set())
    return g


def _tarjan_sccs(g: _PredicateGraph) -> list[list[str]]:
    """Iterative Tarjan SCC over the union of positive and negative edges."""
    index = 0
    stack: list[str] = []
    on_stack: set[str] = set()
    indices: dict[str, int] = {}
    lowlinks: dict[str, int] = {}
    sccs: list[list[str]] = []
    edges_of = lambda n: g.pos_edges.get(n, set()) | g.neg_edges.get(n, set())

    sys_stack: list[tuple[str, list]] = []

    for start in sorted(g.nodes):
        if start in indices:
            continue
        sys_stack.append((start, list(edges_of(start))))
        indices[start] = index
        lowlinks[start] = index
        index += 1
        stack.append(start)
        on_stack.add(start)

        while sys_stack:
            node, remaining = sys_stack[-1]
            if remaining:
                neighbour = remaining.pop()
                if neighbour not in indices:
                    indices[neighbour] = index
                    lowlinks[neighbour] = index
                    index += 1
                    stack.append(neighbour)
                    on_stack.add(neighbour)
                    sys_stack.append((neighbour, list(edges_of(neighbour))))
                elif neighbour in on_stack:
                    lowlinks[node] = min(lowlinks[node], indices[neighbour])
            else:
                sys_stack.pop()
                if lowlinks[node] == indices[node]:
                    component: list[str] = []
                    while True:
                        w = stack.pop()
                        on_stack.discard(w)
                        component.append(w)
                        if w == node:
                            break
                    sccs.append(component)
                if sys_stack:
                    parent = sys_stack[-1][0]
                    lowlinks[parent] = min(lowlinks[parent], lowlinks[node])

    return sccs


def _check_no_negative_cycles(g: _PredicateGraph, sccs: list[list[str]]) -> None:
    for component in sccs:
        if len(component) <= 1:
            # self-loop with negation?
            p = component[0]
            if p in g.neg_edges.get(p, set()):
                raise StratificationError(
                    f"predicate {p!r} is recursively defined through negation "
                    "(self-negated cycle)"
                )
            continue
        comp_set = set(component)
        for u in component:
            for v in g.neg_edges.get(u, set()):
                if v in comp_set:
                    raise StratificationError(
                        f"predicate {u!r} depends on {v!r} through negation "
                        f"inside the cycle {sorted(comp_set)!r}: recursion through "
                        "negation is not stratifiable"
                    )


def stratify(
    program: Program, *, helper_names: frozenset[str] | None = None
) -> tuple[Program, tuple[Stratum, ...]]:
    """
    Disambiguate helpers, check safety, then build strata.

    Returns the (disambiguated) program and a tuple of strata in
    evaluation order.
    """
    if helper_names is None:
        # late import to avoid circular dep at module load
        from tex.pcas.runtime.helpers import HELPER_REGISTRY

        helper_names = frozenset(HELPER_REGISTRY.keys())

    program = _disambiguate_program(program, helper_names)
    _check_safety(program)

    g = _build_dependency_graph(program)
    sccs = _tarjan_sccs(g)
    _check_no_negative_cycles(g, sccs)

    # Tarjan returns SCCs in reverse topological order (leaves first).
    # We want leaves first so each stratum's dependencies are fully
    # materialized before evaluation. So we keep Tarjan's order.
    strata: list[Stratum] = []
    rules_by_predicate: dict[str, list[Rule]] = {}
    for r in program.rules:
        rules_by_predicate.setdefault(r.head.predicate, []).append(r)

    for idx, component in enumerate(sccs):
        preds = frozenset(component)
        rules: list[Rule] = []
        for p in component:
            rules.extend(rules_by_predicate.get(p, ()))
        strata.append(
            Stratum(index=idx, predicates=preds, rules=tuple(rules))
        )

    return program, tuple(strata)


__all__ = ["StratificationError", "Stratum", "stratify"]

"""
PCAS semi-naive bottom-up Datalog evaluator with stratified negation.

Given a stratified program plus an EDB (extensional database — facts
sourced from the dependency graph adapter), produce the IDB
(intensional database — derived facts).

Algorithm
---------
Standard semi-naive bottom-up evaluation per Bancilhon-Maier-
Ramakrishnan-Sagiv 1986, adapted with stratified negation:

::

    for each stratum S in order:
        delta := initial facts of predicates(S)
        repeat:
            new := { head_subst : rule in S with all body atoms in
                                  facts(stratum_predicates_so_far) and at
                                  least one positive body match in delta }
            new := new - facts_already_known
            facts_already_known += new
            delta := new
        until delta is empty

Joins
-----
Per rule, we walk the positive body atoms in declaration order, building
a substitution incrementally. For each atom we:
- collect already-bound variables and their column positions,
- lookup matching facts in the corresponding relation via
  ``Relation.lookup(columns=..., values=...)``,
- extend the substitution with the new bindings.

After all positive atoms succeed:
- run helper calls in order (predicate helpers as guards, function helpers
  binding their last argument variable),
- check each negated atom (groundness guaranteed by the safety check) and
  reject the row if any negated atom is satisfied,
- substitute the head and emit a fact.

Recursion bound
---------------
With strict Datalog (no function symbols, no value creation) the
Herbrand base is finite, so the fixpoint terminates. We additionally
cap the per-stratum iteration count at ``MAX_ITERATIONS`` to bound
worst-case runtime under pathological policies.
"""

from __future__ import annotations

from typing import Iterable

from tex.observability.telemetry import emit_event
from tex.pcas.language.ast import (
    Atom,
    Constant,
    HelperCall,
    NegatedAtom,
    Program,
    Rule,
    Term,
    Variable,
)
from tex.pcas.language.stratify import Stratum, stratify
from tex.pcas.runtime.helpers import HELPER_REGISTRY
from tex.pcas.runtime.relation import FactValue, Relation


class EvaluationError(Exception):
    """Raised when evaluation fails (e.g. iteration cap exceeded)."""


MAX_ITERATIONS = 1024


class Evaluator:
    """
    Stratified semi-naive evaluator.

    Construct once per (program, helper-registry); call ``evaluate(edb)``
    for each fresh adjudication. ``evaluate`` is pure: it does not
    mutate the evaluator's state, so a single ``Evaluator`` is safe to
    reuse across requests.
    """

    __slots__ = ("_program", "_strata", "_helpers", "_relation_arities")

    def __init__(
        self,
        program: Program,
        *,
        helpers: dict | None = None,
    ) -> None:
        helpers = helpers if helpers is not None else HELPER_REGISTRY
        helper_names = frozenset(helpers.keys())
        program, strata = stratify(program, helper_names=helper_names)
        self._program = program
        self._strata = strata
        self._helpers = helpers
        # arity table: gathered from all atom occurrences in the program.
        # The EDB supplies relations whose arity must match.
        arities: dict[str, int] = {}
        for r in program.rules:
            arities.setdefault(r.head.predicate, r.head.arity)
            if arities[r.head.predicate] != r.head.arity:
                raise EvaluationError(
                    f"inconsistent arity for {r.head.predicate!r}: "
                    f"{arities[r.head.predicate]} vs {r.head.arity}"
                )
            for a in r.body_positive_atoms:
                arities.setdefault(a.predicate, a.arity)
            for n in r.body_negated_atoms:
                arities.setdefault(n.atom.predicate, n.atom.arity)
        self._relation_arities = arities

    @property
    def program(self) -> Program:
        return self._program

    @property
    def strata(self) -> tuple[Stratum, ...]:
        return self._strata

    @property
    def relation_arities(self) -> dict[str, int]:
        return dict(self._relation_arities)

    # ------------------------------------------------------------ evaluate

    def evaluate(self, edb: dict[str, Relation]) -> dict[str, Relation]:
        """
        Run all strata, returning the closure: EDB facts plus all derived
        IDB facts, keyed by predicate name.
        """
        facts: dict[str, Relation] = {}

        # Seed with EDB, validating arity.
        for name, rel in edb.items():
            expected = self._relation_arities.get(name)
            if expected is not None and rel.arity != expected:
                raise EvaluationError(
                    f"EDB relation {name!r} has arity {rel.arity} but program "
                    f"expects {expected}"
                )
            facts[name] = rel

        # Make sure every program-mentioned predicate has *some* relation
        # so lookups don't KeyError. Empty IDB seed.
        for pred, arity in self._relation_arities.items():
            if pred not in facts:
                facts[pred] = Relation(name=pred, arity=arity)

        # Seed facts emitted by fact-rules (empty body) up front; they
        # are unconditional.
        for r in self._program.rules:
            if r.is_fact:
                ground = _ground_atom(r.head, subst={})
                if ground is None:
                    raise EvaluationError(
                        f"fact rule has non-ground head: {r.head.predicate!r}"
                    )
                facts[r.head.predicate] = facts[r.head.predicate].with_facts([ground])

        # Process each stratum in topological (Tarjan-leaves-first) order.
        for stratum in self._strata:
            self._evaluate_stratum(stratum, facts)

        return facts

    # --------------------------------------------------------- stratum loop

    def _evaluate_stratum(
        self, stratum: Stratum, facts: dict[str, Relation]
    ) -> None:
        # We accumulate per-predicate deltas; the fixpoint continues as long
        # as at least one predicate added new facts last round.
        iteration = 0
        while True:
            iteration += 1
            if iteration > MAX_ITERATIONS:
                raise EvaluationError(
                    f"stratum {stratum.index} exceeded {MAX_ITERATIONS} iterations"
                )
            new_facts_by_pred: dict[str, set[tuple[FactValue, ...]]] = {}

            for rule in stratum.rules:
                if rule.is_fact:
                    continue  # already seeded
                derived = self._derive(rule, facts)
                if not derived:
                    continue
                # de-dup against current facts
                existing = facts[rule.head.predicate].facts
                additions = [f for f in derived if f not in existing]
                if not additions:
                    continue
                bucket = new_facts_by_pred.setdefault(rule.head.predicate, set())
                bucket.update(additions)

            # Did any predicate actually gain a new fact this round?
            any_added = any(bucket for bucket in new_facts_by_pred.values())
            if not any_added:
                break

            # commit
            for pred, additions in new_facts_by_pred.items():
                if additions:
                    facts[pred] = facts[pred].with_facts(additions)

        emit_event(
            "pcas.evaluator.stratum_complete",
            stratum=stratum.index,
            iterations=iteration,
            predicates=sorted(stratum.predicates),
        )

    # ------------------------------------------------------- per-rule derive

    def _derive(
        self, rule: Rule, facts: dict[str, Relation]
    ) -> list[tuple[FactValue, ...]]:
        """Compute all head substitutions for one rule, given current facts."""
        positive = rule.body_positive_atoms
        negated = rule.body_negated_atoms
        helpers = rule.body_helpers

        # Start with one empty substitution; join in each positive atom.
        substitutions: list[dict[str, FactValue]] = [{}]
        for atom in positive:
            substitutions = _join_atom(atom, substitutions, facts)
            if not substitutions:
                return []

        # Apply helpers (predicate guards / function bindings).
        substitutions = self._apply_helpers(helpers, substitutions)
        if not substitutions:
            return []

        # Filter by negated atoms (now fully ground per safety check).
        substitutions = _filter_negated(negated, substitutions, facts)
        if not substitutions:
            return []

        # Ground the head and emit.
        out: list[tuple[FactValue, ...]] = []
        for sub in substitutions:
            ground = _ground_atom(rule.head, sub)
            if ground is not None:
                out.append(ground)
        return out

    def _apply_helpers(
        self,
        helpers: tuple[HelperCall, ...],
        substitutions: list[dict[str, FactValue]],
    ) -> list[dict[str, FactValue]]:
        if not helpers:
            return substitutions

        # We apply helpers in declaration order, mutating substitutions
        # immutably via list rebuild.
        for helper in helpers:
            reg = self._helpers.get(helper.name)
            if reg is None:
                # disambiguation should have caught this; treat as fail-closed
                return []
            if len(helper.args) != reg.arity:
                raise EvaluationError(
                    f"helper {helper.name!r} arity mismatch: registry says "
                    f"{reg.arity}, call has {len(helper.args)} args"
                )

            next_substitutions: list[dict[str, FactValue]] = []
            if reg.kind == "predicate":
                for sub in substitutions:
                    args = [
                        _resolve_term(a, sub) for a in helper.args
                    ]
                    if any(a is _UNBOUND for a in args):
                        continue
                    try:
                        ok = bool(reg.fn(*args))
                    except Exception:  # noqa: BLE001 - helpers are sandboxed
                        ok = False
                    if ok:
                        next_substitutions.append(sub)
            else:
                # function helper: last argument is the output binding.
                # If a variable, bind it. If a constant, treat as
                # equality check on the return value. This matches PCAS
                # §4.5.2's "f(args, R) where R may be a constant" pattern.
                output_term = helper.args[-1]
                input_terms = helper.args[:-1]
                for sub in substitutions:
                    inputs = [_resolve_term(t, sub) for t in input_terms]
                    if any(v is _UNBOUND for v in inputs):
                        continue
                    try:
                        result = reg.fn(*inputs)
                    except Exception:  # noqa: BLE001
                        continue
                    if not isinstance(result, (str, int, bool)):
                        continue
                    if isinstance(output_term, Constant):
                        if result == output_term.value:
                            next_substitutions.append(sub)
                        continue
                    if isinstance(output_term, Variable):
                        if output_term.is_anonymous:
                            next_substitutions.append(sub)
                            continue
                        if output_term.name in sub:
                            if sub[output_term.name] == result:
                                next_substitutions.append(sub)
                        else:
                            new_sub = dict(sub)
                            new_sub[output_term.name] = result
                            next_substitutions.append(new_sub)
            substitutions = next_substitutions
            if not substitutions:
                return []
        return substitutions


# ---------------------------------------------------------------------------
# Term resolution / atom grounding / joins (module-level for testability)
# ---------------------------------------------------------------------------


_UNBOUND = object()


def _resolve_term(term: Term, sub: dict[str, FactValue]) -> FactValue:
    if isinstance(term, Constant):
        return term.value
    if isinstance(term, Variable):
        if term.is_anonymous:
            return _UNBOUND  # type: ignore[return-value]
        if term.name in sub:
            return sub[term.name]
        return _UNBOUND  # type: ignore[return-value]
    raise TypeError(f"unknown term type: {type(term).__name__}")


def _ground_atom(
    atom: Atom, subst: dict[str, FactValue]
) -> tuple[FactValue, ...] | None:
    out: list[FactValue] = []
    for t in atom.args:
        if isinstance(t, Constant):
            out.append(t.value)
        elif isinstance(t, Variable):
            if t.is_anonymous:
                return None  # cannot ground anonymous
            if t.name not in subst:
                return None
            out.append(subst[t.name])
        else:
            return None
    return tuple(out)


def _join_atom(
    atom: Atom,
    substitutions: list[dict[str, FactValue]],
    facts: dict[str, Relation],
) -> list[dict[str, FactValue]]:
    """
    Extend each candidate substitution by matching ``atom`` against
    ``facts[atom.predicate]``.
    """
    rel = facts.get(atom.predicate)
    if rel is None:
        return []

    out: list[dict[str, FactValue]] = []
    for sub in substitutions:
        # Compute the columns we can constrain with the current sub.
        bound_cols: list[int] = []
        bound_vals: list[FactValue] = []
        # Plus extra constraints from in-atom repeated variables / constants
        for i, t in enumerate(atom.args):
            v = _resolve_term(t, sub)
            if v is _UNBOUND:
                continue
            bound_cols.append(i)
            bound_vals.append(v)  # type: ignore[arg-type]

        candidates = rel.lookup(
            columns=tuple(bound_cols),
            values=tuple(bound_vals),
        )

        for f in candidates:
            # Check repeated-variable consistency inside this atom (not via
            # the index, which only handles already-bound positions).
            new_sub = dict(sub)
            ok = True
            for i, t in enumerate(atom.args):
                if isinstance(t, Constant):
                    if f[i] != t.value:
                        ok = False
                        break
                    continue
                if isinstance(t, Variable):
                    if t.is_anonymous:
                        continue
                    if t.name in new_sub:
                        if new_sub[t.name] != f[i]:
                            ok = False
                            break
                    else:
                        new_sub[t.name] = f[i]
            if ok:
                out.append(new_sub)
    return out


def _filter_negated(
    negated: tuple[NegatedAtom, ...],
    substitutions: list[dict[str, FactValue]],
    facts: dict[str, Relation],
) -> list[dict[str, FactValue]]:
    if not negated:
        return substitutions
    out: list[dict[str, FactValue]] = []
    for sub in substitutions:
        keep = True
        for neg in negated:
            ground = _ground_atom(neg.atom, sub)
            if ground is None:
                # safety check should have caught this; fail-closed
                keep = False
                break
            rel = facts.get(neg.atom.predicate)
            if rel is None:
                continue  # absent relation -> not(X) trivially true
            if ground in rel.facts:
                keep = False
                break
        if keep:
            out.append(sub)
    return out


__all__ = ["EvaluationError", "Evaluator"]

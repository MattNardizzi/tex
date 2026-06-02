"""
PCAS policy-language AST.

Typed AST nodes for the Datalog-derived policy language. Every node is a
pydantic v2 strict model: ``ConfigDict(frozen=True, extra='forbid')``.

Grammar (concrete syntax)
-------------------------
::

    program          := { rule } ;
    rule             := [ annotation ] head ":-" body "." ;
    rule             |= [ annotation ] head "." ;            # fact (empty body)
    annotation       := "@authorize" | "@deny" ;
    head             := atom ;
    body             := body_element { "," body_element } ;
    body_element     := atom
                      | negated_atom
                      | helper_call ;
    atom             := IDENT "(" term { "," term } ")" ;
    negated_atom     := "not" atom ;
    helper_call      := IDENT "(" term { "," term } ")" ;    # disambiguated by registry
    term             := variable | constant ;
    variable         := UPPER_IDENT ;
    constant         := STRING | INTEGER | "true" | "false" ;

Notes
-----
- Variable safety (Apt-Blair-Walker): every variable occurring in a head
  or in a negated atom must occur positively in the body. Checked by the
  stratifier, not by the parser.
- Helper-vs-atom disambiguation: at parse time both look identical
  ``name(args)``. The stratifier looks up ``name`` in the helper registry;
  whatever's not registered is treated as a relation atom. This matches
  PCAS §4.5.2's "helper functions called like atoms" design.
- Rule annotations: ``@authorize`` heads contribute PERMIT weight,
  ``@deny`` heads contribute FORBID weight. Both present on the same
  ground head -> FORBID (fail-closed, matches PCAS §4.4.1
  authorization-flow).

Reference: arxiv 2602.16708 §4.5; semi-positive Datalog with stratified
negation per Abiteboul-Hull-Vianu ch.15.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


# ---------------------------------------------------------------------------
# Terms
# ---------------------------------------------------------------------------


class Variable(BaseModel):
    """A logic variable. Convention: starts with an upper-case letter."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str = Field(min_length=1, max_length=64)
    line: int = Field(ge=0, default=0)
    col: int = Field(ge=0, default=0)

    @field_validator("name")
    @classmethod
    def _variable_name(cls, value: str) -> str:
        if not value[0].isupper() and value[0] != "_":
            raise ValueError(
                f"variable name must start with upper-case letter or '_', "
                f"got {value!r}"
            )
        for ch in value:
            if not (ch.isalnum() or ch == "_"):
                raise ValueError(
                    f"variable name may only contain alnum and '_', got {value!r}"
                )
        return value

    @property
    def is_anonymous(self) -> bool:
        """Anonymous variables (``_`` or ``_foo``) cannot be bound across atoms."""
        return self.name == "_" or self.name.startswith("_")

    def __str__(self) -> str:  # pragma: no cover - cosmetic
        return self.name


class Constant(BaseModel):
    """A literal value: string, int, or bool. Floats are forbidden (per
    Tex's canonical-JSON contract; see ``tex.events._canonical``)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    value: str | int | bool
    line: int = Field(ge=0, default=0)
    col: int = Field(ge=0, default=0)

    @field_validator("value")
    @classmethod
    def _no_floats(cls, value: object) -> str | int | bool:
        if isinstance(value, bool):
            return value
        if isinstance(value, int):
            return value
        if isinstance(value, str):
            return value
        raise TypeError(
            f"PCAS constants must be str | int | bool (got {type(value).__name__}); "
            "floats are forbidden by canonical-JSON contract"
        )

    def __str__(self) -> str:  # pragma: no cover - cosmetic
        if isinstance(self.value, bool):
            return "true" if self.value else "false"
        if isinstance(self.value, str):
            return f'"{self.value}"'
        return str(self.value)


Term = Variable | Constant


# ---------------------------------------------------------------------------
# Atoms / helper calls
# ---------------------------------------------------------------------------


class Atom(BaseModel):
    """
    A positive atom ``relation(term, term, ...)``.

    May refer to either a relation defined elsewhere in the program / EDB or
    a helper function in the registry. Disambiguation happens at
    stratification time.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    predicate: str = Field(min_length=1, max_length=64)
    args: tuple[Term, ...] = Field(default_factory=tuple)
    line: int = Field(ge=0, default=0)
    col: int = Field(ge=0, default=0)

    @field_validator("predicate")
    @classmethod
    def _predicate_name(cls, value: str) -> str:
        if not value[0].islower():
            raise ValueError(
                f"predicate name must start with lower-case letter, got {value!r}"
            )
        for ch in value:
            if not (ch.isalnum() or ch == "_"):
                raise ValueError(
                    f"predicate name may only contain alnum and '_', got {value!r}"
                )
        return value

    @property
    def arity(self) -> int:
        return len(self.args)

    @property
    def variables(self) -> tuple[Variable, ...]:
        return tuple(t for t in self.args if isinstance(t, Variable))

    def __str__(self) -> str:  # pragma: no cover - cosmetic
        return f"{self.predicate}({', '.join(str(a) for a in self.args)})"


class NegatedAtom(BaseModel):
    """``not atom`` — stratified negation."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    atom: Atom
    line: int = Field(ge=0, default=0)
    col: int = Field(ge=0, default=0)

    @property
    def variables(self) -> tuple[Variable, ...]:
        return self.atom.variables


class HelperCall(BaseModel):
    """
    A helper-function invocation, resolved during stratification.

    Stored separately from ``Atom`` after disambiguation so the evaluator
    can dispatch to ``HELPER_REGISTRY`` instead of materializing a
    relation.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str = Field(min_length=1, max_length=64)
    args: tuple[Term, ...] = Field(default_factory=tuple)
    line: int = Field(ge=0, default=0)
    col: int = Field(ge=0, default=0)

    @property
    def variables(self) -> tuple[Variable, ...]:
        return tuple(t for t in self.args if isinstance(t, Variable))


BodyElement = Atom | NegatedAtom | HelperCall


# ---------------------------------------------------------------------------
# Rules / programs
# ---------------------------------------------------------------------------


RuleAnnotation = Literal["authorize", "deny", "rule"]


class Rule(BaseModel):
    """
    A Datalog rule: ``[annotation] head :- body.``

    ``body`` may be empty, in which case the rule is a *fact* (the head
    must then be ground).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    annotation: RuleAnnotation = "rule"
    head: Atom
    body: tuple[BodyElement, ...] = Field(default_factory=tuple)
    line: int = Field(ge=0, default=0)
    col: int = Field(ge=0, default=0)

    @property
    def is_fact(self) -> bool:
        return len(self.body) == 0

    @property
    def head_variables(self) -> tuple[Variable, ...]:
        return self.head.variables

    @property
    def body_positive_atoms(self) -> tuple[Atom, ...]:
        return tuple(b for b in self.body if isinstance(b, Atom))

    @property
    def body_negated_atoms(self) -> tuple[NegatedAtom, ...]:
        return tuple(b for b in self.body if isinstance(b, NegatedAtom))

    @property
    def body_helpers(self) -> tuple[HelperCall, ...]:
        return tuple(b for b in self.body if isinstance(b, HelperCall))


class Program(BaseModel):
    """A complete PCAS policy program: a sequence of rules."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    rules: tuple[Rule, ...]
    source: str | None = Field(default=None, max_length=200)

    @property
    def head_predicates(self) -> frozenset[str]:
        return frozenset(r.head.predicate for r in self.rules)

    @property
    def authorize_predicates(self) -> frozenset[str]:
        return frozenset(
            r.head.predicate for r in self.rules if r.annotation == "authorize"
        )

    @property
    def deny_predicates(self) -> frozenset[str]:
        return frozenset(
            r.head.predicate for r in self.rules if r.annotation == "deny"
        )


__all__ = [
    "Atom",
    "BodyElement",
    "Constant",
    "HelperCall",
    "NegatedAtom",
    "Program",
    "Rule",
    "RuleAnnotation",
    "Term",
    "Variable",
]

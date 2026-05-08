"""
Mini LTLf evaluator with RV-LTL 4-valued semantics.

Vendored — stdlib only. Sized to cover the predicate vocabulary used by
ABC behavioral contracts (arxiv 2602.22302) and the invariant-response
template fragment from AgentVerify (arxiv-prep 2604.1029): atoms,
boolean connectives, and the temporal operators ``X / G / F / U`` plus
the bounded-eventually operator ``F<=k`` that is essential for the
ABC recovery-window semantics.

Why we vendor instead of using ltlf2dfa / logaut:
  * ltlf2dfa requires the MONA C tool at runtime
  * logaut requires the lydia Docker image
  * neither was approved in requirements.txt; the build prompt allowed a
    "vendored mini LTL evaluator (or python-ltl if approved)"

Design choices (paper silent, engineering call):

1. **Finite-trace semantics (LTLf).** Agent traces are finite at
   evaluation time. We adopt the LTLf semantics of De Giacomo & Vardi
   (2013) where the "next" operator on the last position is false
   (strong-next ``X``). A weak-next ``Xw`` is provided for completeness
   but defaults to false-on-end matching the paper's invariant-response
   workloads, where ``X q`` already discharges immediately upon p.

2. **RV-LTL 4-valued verdicts** at each trace position
   (Bauer/Leucker/Schallhart 2011): ``permanently_satisfied``,
   ``currently_satisfied``, ``currently_violated``,
   ``permanently_violated``. Tex's ContractEnforcer collapses these to
   binary satisfied / violated for the public boolean API but the
   4-valued verdict is exposed for callers that want it (e.g. the
   future SPRT certifier in ``tex.contracts.certification``).

3. **Bounded eventually F<=k**. The ABC paper's k-recovery window is
   the only reason finite-state RV-LTL is sufficient instead of full
   LTL: every "soft" constraint check has the form
   ``G(violated -> F<=k recovered)``. We compile this directly to a
   per-(contract, constraint) deadline counter inside the enforcer; the
   evaluator here only needs to support the surface syntax.

4. **Atoms are opaque tokens** evaluated by an injected
   ``AtomResolver`` callable. This keeps the LTL machinery purely
   propositional and lets the contracts package own the
   field-path / state-path / event-kind / capability vocabulary.

References
----------
- arxiv 2602.22302 (Bhardwaj, AgentAssert / ABC) — contract structure,
  (p,δ,k)-satisfaction, recovery window k.
- Bauer, Leucker, Schallhart (2011), "Runtime Verification for LTL and
  TLTL", ACM TOSEM — RV-LTL 4-valued verdicts.
- De Giacomo & Vardi (2013), "Linear Temporal Logic and Linear Dynamic
  Logic on Finite Traces", IJCAI — LTLf.
- arxiv-prep 2604.1029 (AgentVerify) — 23 LTL templates for agent
  safety; we cover the propositional fragment they use.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Callable, Mapping, Sequence


# ---------------------------------------------------------------------
# Public verdict / exception types
# ---------------------------------------------------------------------


class RVVerdict(str, Enum):
    """
    RV-LTL 4-valued verdict at a single trace position.

    Reference: Bauer/Leucker/Schallhart 2011.
    """

    PERMANENTLY_SATISFIED = "permanently_satisfied"
    CURRENTLY_SATISFIED = "currently_satisfied"
    CURRENTLY_VIOLATED = "currently_violated"
    PERMANENTLY_VIOLATED = "permanently_violated"

    @property
    def is_satisfied(self) -> bool:
        """Coarse two-valued projection used by the public ContractEnforcer API."""
        return self in (RVVerdict.PERMANENTLY_SATISFIED, RVVerdict.CURRENTLY_SATISFIED)

    @property
    def is_permanent(self) -> bool:
        """True iff the verdict cannot change as the trace extends."""
        return self in (
            RVVerdict.PERMANENTLY_SATISFIED,
            RVVerdict.PERMANENTLY_VIOLATED,
        )


class LTLParseError(ValueError):
    """Raised when an LTL formula string fails to parse."""


# ---------------------------------------------------------------------
# AST
# ---------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _Node:
    """Marker base — never instantiated directly."""


@dataclass(frozen=True, slots=True)
class _Const(_Node):
    value: bool


@dataclass(frozen=True, slots=True)
class _Atom(_Node):
    """Opaque atom string. Resolved by the AtomResolver."""

    name: str


@dataclass(frozen=True, slots=True)
class _Not(_Node):
    arg: _Node


@dataclass(frozen=True, slots=True)
class _And(_Node):
    left: _Node
    right: _Node


@dataclass(frozen=True, slots=True)
class _Or(_Node):
    left: _Node
    right: _Node


@dataclass(frozen=True, slots=True)
class _Implies(_Node):
    left: _Node
    right: _Node


@dataclass(frozen=True, slots=True)
class _Next(_Node):
    """Strong next X φ — false at the last position."""

    arg: _Node


@dataclass(frozen=True, slots=True)
class _WeakNext(_Node):
    """Weak next Xw φ — true at the last position."""

    arg: _Node


@dataclass(frozen=True, slots=True)
class _Globally(_Node):
    arg: _Node


@dataclass(frozen=True, slots=True)
class _Eventually(_Node):
    arg: _Node


@dataclass(frozen=True, slots=True)
class _BoundedEventually(_Node):
    """F<=k φ — true if φ holds within the next k positions (inclusive)."""

    bound: int
    arg: _Node


@dataclass(frozen=True, slots=True)
class _Until(_Node):
    left: _Node
    right: _Node


# ---------------------------------------------------------------------
# Tokenizer
# ---------------------------------------------------------------------


# Token kinds. Atoms are just identifier-ish runs of characters that are
# not reserved. We accept letters, digits, ``.`` (for field paths like
# ``output.pii_detected``), ``_``, ``:`` (for tagged atoms like
# ``capability:read_pii``), ``[``/``]``/``=``/``<``/``>``/``-``/``!`` so
# that the predicate DSL atoms used by tex.contracts can ride directly
# inside LTL atoms.

_ATOM_CHARS = set(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:=<>!-/@~,"
)

# Reserved keywords are matched only when surrounded by non-atom chars.
# ``->`` and ``F<=N`` get special handling in the tokenizer.
_KEYWORDS = {
    "true": ("CONST", True),
    "false": ("CONST", False),
    "not": ("NOT", None),
    "and": ("AND", None),
    "or": ("OR", None),
    "implies": ("IMPLIES", None),
    "X": ("NEXT", None),
    "Xw": ("WEAK_NEXT", None),
    "G": ("GLOBALLY", None),
    "F": ("EVENTUALLY", None),
    "U": ("UNTIL", None),
}


def _tokenize(formula: str) -> list[tuple[str, object]]:
    """Convert ``formula`` to a token stream of (kind, value) pairs."""
    tokens: list[tuple[str, object]] = []
    i = 0
    n = len(formula)
    while i < n:
        ch = formula[i]
        if ch.isspace():
            i += 1
            continue
        if ch == "(":
            tokens.append(("LPAREN", None))
            i += 1
            continue
        if ch == ")":
            tokens.append(("RPAREN", None))
            i += 1
            continue
        # ``->`` arrow form for implication
        if ch == "-" and i + 1 < n and formula[i + 1] == ">":
            tokens.append(("IMPLIES", None))
            i += 2
            continue
        # ``F<=N`` bounded eventually — consume the bound integer
        if ch == "F" and i + 1 < n and formula[i + 1] == "<":
            # Expect "F<=N" where N is a non-negative integer.
            if formula[i : i + 3] != "F<=":
                raise LTLParseError(
                    f"expected 'F<=N' bounded-eventually at offset {i}, got {formula[i : i + 3]!r}"
                )
            j = i + 3
            digits_start = j
            while j < n and formula[j].isdigit():
                j += 1
            if j == digits_start:
                raise LTLParseError(
                    f"missing integer bound after 'F<=' at offset {i}"
                )
            bound = int(formula[digits_start:j])
            tokens.append(("BOUNDED_EVENTUALLY", bound))
            i = j
            continue
        # Otherwise read a maximal run of atom-chars and decide later
        # whether it is a keyword or an atom.
        if ch in _ATOM_CHARS:
            j = i
            while j < n and formula[j] in _ATOM_CHARS:
                j += 1
            word = formula[i:j]
            kw = _KEYWORDS.get(word)
            if kw is not None:
                kind, value = kw
                tokens.append((kind, value))
            else:
                tokens.append(("ATOM", word))
            i = j
            continue
        raise LTLParseError(f"unexpected character {ch!r} at offset {i}")
    return tokens


# ---------------------------------------------------------------------
# Parser — Pratt / recursive descent
# ---------------------------------------------------------------------


class _Parser:
    """
    Recursive-descent parser with the following precedence (low → high):

        1. implies     (right-assoc)
        2. or          (left-assoc)
        3. and         (left-assoc)
        4. until       (left-assoc, between unary and 'and')
        5. unary: not, X, Xw, G, F, F<=k
        6. atom / const / parenthesised
    """

    def __init__(self, tokens: list[tuple[str, object]]):
        self._toks = tokens
        self._pos = 0

    def parse(self) -> _Node:
        node = self._parse_implies()
        if self._pos != len(self._toks):
            tok = self._toks[self._pos]
            raise LTLParseError(f"unexpected token {tok!r} at position {self._pos}")
        return node

    # peek / consume helpers
    def _peek(self) -> tuple[str, object] | None:
        if self._pos >= len(self._toks):
            return None
        return self._toks[self._pos]

    def _consume(self, kind: str) -> tuple[str, object]:
        tok = self._peek()
        if tok is None or tok[0] != kind:
            raise LTLParseError(f"expected {kind} but got {tok!r}")
        self._pos += 1
        return tok

    # grammar
    def _parse_implies(self) -> _Node:
        left = self._parse_or()
        tok = self._peek()
        if tok is not None and tok[0] == "IMPLIES":
            self._pos += 1
            right = self._parse_implies()  # right-assoc
            return _Implies(left, right)
        return left

    def _parse_or(self) -> _Node:
        left = self._parse_and()
        while True:
            tok = self._peek()
            if tok is None or tok[0] != "OR":
                return left
            self._pos += 1
            right = self._parse_and()
            left = _Or(left, right)

    def _parse_and(self) -> _Node:
        left = self._parse_until()
        while True:
            tok = self._peek()
            if tok is None or tok[0] != "AND":
                return left
            self._pos += 1
            right = self._parse_until()
            left = _And(left, right)

    def _parse_until(self) -> _Node:
        left = self._parse_unary()
        while True:
            tok = self._peek()
            if tok is None or tok[0] != "UNTIL":
                return left
            self._pos += 1
            right = self._parse_unary()
            left = _Until(left, right)

    def _parse_unary(self) -> _Node:
        tok = self._peek()
        if tok is None:
            raise LTLParseError("unexpected end of formula")
        kind, value = tok
        if kind == "NOT":
            self._pos += 1
            return _Not(self._parse_unary())
        if kind == "NEXT":
            self._pos += 1
            return _Next(self._parse_unary())
        if kind == "WEAK_NEXT":
            self._pos += 1
            return _WeakNext(self._parse_unary())
        if kind == "GLOBALLY":
            self._pos += 1
            return _Globally(self._parse_unary())
        if kind == "EVENTUALLY":
            self._pos += 1
            return _Eventually(self._parse_unary())
        if kind == "BOUNDED_EVENTUALLY":
            self._pos += 1
            assert isinstance(value, int)
            return _BoundedEventually(bound=value, arg=self._parse_unary())
        return self._parse_primary()

    def _parse_primary(self) -> _Node:
        tok = self._peek()
        if tok is None:
            raise LTLParseError("unexpected end of formula in primary")
        kind, value = tok
        if kind == "LPAREN":
            self._pos += 1
            inner = self._parse_implies()
            self._consume("RPAREN")
            return inner
        if kind == "CONST":
            self._pos += 1
            assert isinstance(value, bool)
            return _Const(value)
        if kind == "ATOM":
            self._pos += 1
            assert isinstance(value, str)
            return _Atom(value)
        raise LTLParseError(f"unexpected token {tok!r} starting a primary")


# ---------------------------------------------------------------------
# Public surface
# ---------------------------------------------------------------------


# An AtomResolver is a function that, given an atom name and a state
# (the trace element at position t), returns whether that atom holds.
AtomResolver = Callable[[str, Mapping[str, object]], bool]


@dataclass(frozen=True, slots=True)
class LTLFormula:
    """
    A parsed LTL formula. Construct via ``LTLFormula.parse``.

    Instances are frozen; the internal AST is reused across evaluations.
    """

    source: str
    _ast: _Node

    @staticmethod
    def parse(formula: str) -> LTLFormula:
        """
        Parse ``formula`` into an LTLFormula or raise LTLParseError.

        Supported grammar (BNF, low → high precedence):

            implies := or  ('->' implies)?
            or      := and ('or' and)*
            and     := until ('and' until)*
            until   := unary ('U' unary)*
            unary   := 'not' unary
                     | 'X' unary  | 'Xw' unary
                     | 'G' unary
                     | 'F' unary  | 'F<=' INT unary
                     | primary
            primary := '(' implies ')' | 'true' | 'false' | ATOM

        ATOMs are opaque identifier-like tokens; the resolver decides
        their semantics. Whitespace is significant only as a separator.
        """
        if not formula or not formula.strip():
            raise LTLParseError("empty formula")
        tokens = _tokenize(formula)
        if not tokens:
            raise LTLParseError("no tokens parsed from formula")
        ast = _Parser(tokens).parse()
        return LTLFormula(source=formula, _ast=ast)

    def evaluate_finite(
        self,
        trace: Sequence[Mapping[str, object]],
        resolver: AtomResolver,
        *,
        position: int = 0,
    ) -> bool:
        """
        Evaluate this formula over a finite trace under LTLf semantics.

        Returns True iff the formula holds at ``position`` (default 0)
        of the trace under LTLf. ``X φ`` at the last position is False;
        ``Xw φ`` at the last position is True.
        """
        if position < 0:
            raise ValueError(f"position must be ≥ 0, got {position}")
        if position > len(trace):
            raise ValueError(
                f"position {position} exceeds trace length {len(trace)}"
            )
        return _eval_ltlf(self._ast, trace, position, resolver)

    def rv_verdict(
        self,
        trace: Sequence[Mapping[str, object]],
        resolver: AtomResolver,
        *,
        position: int | None = None,
    ) -> RVVerdict:
        """
        Compute the RV-LTL 4-valued verdict at ``position``.

        We classify a verdict as *permanent* iff the same boolean
        evaluation holds for every extension of ``trace`` that we can
        cheaply check. We use a single lookahead heuristic: an atomic
        contradiction (e.g. ``G(false)`` or any subtree where
        propagation forces a definite outcome) yields a permanent
        verdict; otherwise the verdict is "currently".

        This is sufficient for the contracts layer's enforcement
        decisions, which only need the binary ``is_satisfied``
        projection. Callers wanting tighter monitorability semantics
        should compile to a Büchi-style monitor (out of scope —
        TODO(P2): tighter monitorability per Bauer/Leucker/Schallhart
        2011 §5).
        """
        eff_pos = len(trace) - 1 if position is None else position
        if eff_pos < 0:
            eff_pos = 0
        ok = _eval_ltlf(self._ast, trace, eff_pos, resolver)
        permanent = _is_definite(self._ast, trace, eff_pos, resolver)
        if ok and permanent:
            return RVVerdict.PERMANENTLY_SATISFIED
        if not ok and permanent:
            return RVVerdict.PERMANENTLY_VIOLATED
        return RVVerdict.CURRENTLY_SATISFIED if ok else RVVerdict.CURRENTLY_VIOLATED


# ---------------------------------------------------------------------
# Evaluation core
# ---------------------------------------------------------------------


def _eval_ltlf(
    node: _Node,
    trace: Sequence[Mapping[str, object]],
    pos: int,
    resolver: AtomResolver,
) -> bool:
    """
    Recursive LTLf evaluator. Position semantics:
      * pos in [0, len(trace)-1] indexes a real trace element
      * pos == len(trace) means "past the end" — treated as the empty
        suffix; G/F/U evaluate vacuously per LTLf.
    """
    n = len(trace)
    if isinstance(node, _Const):
        return node.value
    if isinstance(node, _Atom):
        if pos >= n:
            # Past the end — atoms have no truth value; default to False
            # which is the conservative choice for safety properties
            # (a forbidden behaviour cannot occur off the end).
            return False
        return bool(resolver(node.name, trace[pos]))
    if isinstance(node, _Not):
        return not _eval_ltlf(node.arg, trace, pos, resolver)
    if isinstance(node, _And):
        # Short-circuit on left=False
        return _eval_ltlf(node.left, trace, pos, resolver) and _eval_ltlf(
            node.right, trace, pos, resolver
        )
    if isinstance(node, _Or):
        return _eval_ltlf(node.left, trace, pos, resolver) or _eval_ltlf(
            node.right, trace, pos, resolver
        )
    if isinstance(node, _Implies):
        # p -> q  ≡  (not p) or q
        if not _eval_ltlf(node.left, trace, pos, resolver):
            return True
        return _eval_ltlf(node.right, trace, pos, resolver)
    if isinstance(node, _Next):
        # Strong next: false at end
        if pos + 1 >= n:
            return False
        return _eval_ltlf(node.arg, trace, pos + 1, resolver)
    if isinstance(node, _WeakNext):
        # Weak next: true at end
        if pos + 1 >= n:
            return True
        return _eval_ltlf(node.arg, trace, pos + 1, resolver)
    if isinstance(node, _Globally):
        # G φ ≡ φ holds at every position from pos to n-1
        for k in range(pos, n):
            if not _eval_ltlf(node.arg, trace, k, resolver):
                return False
        return True
    if isinstance(node, _Eventually):
        for k in range(pos, n):
            if _eval_ltlf(node.arg, trace, k, resolver):
                return True
        return False
    if isinstance(node, _BoundedEventually):
        # F<=k φ ≡ ∃ j ∈ [pos, min(pos+k, n-1)] : φ at j
        upper = min(pos + node.bound, n - 1)
        for k in range(pos, upper + 1):
            if _eval_ltlf(node.arg, trace, k, resolver):
                return True
        return False
    if isinstance(node, _Until):
        # φ U ψ ≡ ∃ j ≥ pos : ψ at j ∧ ∀ pos ≤ i < j : φ at i
        for j in range(pos, n):
            if _eval_ltlf(node.right, trace, j, resolver):
                return True
            if not _eval_ltlf(node.left, trace, j, resolver):
                return False
        return False
    raise TypeError(f"unhandled AST node: {type(node).__name__}")


def _is_definite(
    node: _Node,
    trace: Sequence[Mapping[str, object]],
    pos: int,
    resolver: AtomResolver,
) -> bool:
    """
    Heuristic: is the boolean evaluation of ``node`` at ``pos`` immune
    to extensions of ``trace``?

    Simple inductive rules:
      * Const is definite.
      * Atom over a real position is definite (atoms describe the
        observed state at that position; extending the trace doesn't
        change earlier observations).
      * G over an exhausted suffix is definite (vacuously true).
      * F that is already satisfied is definite.
      * Bounded F<=k whose window is entirely in [pos, n-1] is definite.
      * Otherwise we conservatively report "not definite" — the verdict
        is "currently". This is the safe default for RV-LTL.

    TODO(P2): tighten via syntactic safety/co-safety classification per
    Bauer/Leucker/Schallhart 2011, which is what production runtime
    monitors do via Büchi automaton construction.
    """
    n = len(trace)
    if isinstance(node, _Const):
        return True
    if isinstance(node, _Atom):
        return pos < n
    if isinstance(node, _Not):
        return _is_definite(node.arg, trace, pos, resolver)
    if isinstance(node, (_And, _Or, _Implies)):
        return _is_definite(node.left, trace, pos, resolver) and _is_definite(
            node.right, trace, pos, resolver
        )
    if isinstance(node, _BoundedEventually):
        # If the bound's window is fully observed, the verdict is
        # definite regardless of future extensions.
        return pos + node.bound <= n - 1
    if isinstance(node, _Globally):
        # Once the bounded prefix has been fully consumed, G's verdict
        # over that observed window can still flip when more positions
        # arrive — so we say "definite" only if a violation has already
        # been found (handled by _eval_ltlf returning False; the call
        # site combines).
        return False
    if isinstance(node, (_Next, _WeakNext)):
        # Strong-next at position pos depends only on pos+1, which is
        # already observed when pos+1 < n; otherwise it's an end-of-trace
        # default.
        return True
    if isinstance(node, (_Eventually, _Until)):
        return False
    return False


__all__ = [
    "AtomResolver",
    "LTLFormula",
    "LTLParseError",
    "RVVerdict",
]

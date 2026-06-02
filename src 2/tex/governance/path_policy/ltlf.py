"""
Finite-trace Linear Temporal Logic (LTLf) evaluator for path policies.

Reference: Kaptein et al. arXiv:2603.16586 (Mar 2026), Sections 3.5 and 4.2.

The Kaptein paper's Section 3.5 catalogues eight concrete policies and
notes that "in practice, the large majority of organizationally relevant
policies are binary threshold rules on path state: has a particular step
type appeared, has a sensitivity level been exceeded, has the step count
reached a limit." LTLf captures exactly that class compactly and
auditably.

This module implements LTLf over a finite trace (paper Section 3.1: "we
assume throughout that each execution path terminates"), with the
following operators and atoms:

Atoms
-----
  tool=<name>             — the action's "tool" or "type" field equals <name>
  action.<key>=<value>    — the action mapping has action[<key>] == <value>
  state.<key>=<value>     — the state mapping has state[<key>] == <value>
  obs.<key>=<value>       — the observation mapping has observation[<key>] == <value>
  state.<key>>=<n>        — numeric: state[<key>] >= n (also <=, >, <, !=)
  true / false            — propositional constants

Boolean operators
-----------------
  & (and), | (or), ! (not), -> (implies)

Temporal operators (finite-trace semantics)
-------------------------------------------
  G phi      "always": phi holds at every position from current to end
  F phi      "eventually": phi holds at some position from current to end
  X phi      "next": phi holds at the next position (false if at end)
  phi U psi  "until": psi eventually holds, and phi holds until then

Whitespace and parentheses are permitted everywhere. Atom values may be
quoted with single or double quotes if they contain whitespace or
operator characters.

Examples
--------
The Kaptein paper's "PII predecessor requirement" maps to:

    F (tool=pii_check) | !(tool=read_personal_data)

read literally as: either a pii_check appears at some point in the
trace, or no read_personal_data action ever appears.

The "approval before external send" policy maps to:

    !(tool=external_send) | F (tool=human_approval)

read against the trace ending at the candidate action: if the candidate
is an external send, then a human_approval must have appeared earlier.
(The paper evaluates prospectively against the partial path P_i with s*
appended; this evaluator does the same — see ``evaluate``.)

This is intentionally a small, dependency-free LTLf engine. It is NOT a
general LTLf model checker; it evaluates a single concrete trace, which
is exactly what the paper's per-step evaluation requires.

Priority: P1.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Sequence

from tex.governance.path_policy.policy import PathStep


# ---------------------------------------------------------------------------
# Tokenizer
# ---------------------------------------------------------------------------

_TOKEN_KEYWORDS: frozenset[str] = frozenset({"G", "F", "X", "U", "true", "false"})
_TOKEN_OPERATORS: tuple[str, ...] = ("->", ">=", "<=", "!=", "&", "|", "!", "(", ")", "=", ">", "<")


@dataclass(frozen=True, slots=True)
class _Token:
    kind: str  # "atom" | "op" | "kw"
    value: str


class LtlfParseError(ValueError):
    """Raised when an LTLf formula fails to parse."""


def _tokenize(formula: str) -> list[_Token]:
    tokens: list[_Token] = []
    i = 0
    n = len(formula)
    while i < n:
        ch = formula[i]
        if ch.isspace():
            i += 1
            continue
        # Multi-character operators first.
        matched = False
        for op in _TOKEN_OPERATORS:
            if formula.startswith(op, i):
                tokens.append(_Token(kind="op", value=op))
                i += len(op)
                matched = True
                break
        if matched:
            continue
        # Quoted atom value.
        if ch in ('"', "'"):
            quote = ch
            j = i + 1
            while j < n and formula[j] != quote:
                j += 1
            if j >= n:
                raise LtlfParseError(f"unterminated quoted string at position {i}")
            tokens.append(_Token(kind="atom", value=formula[i + 1 : j]))
            i = j + 1
            continue
        # Identifier / keyword / dotted atom prefix. Permits the
        # characters that show up in real-world atom values without
        # quoting: dots/dashes/underscores for keys, '@' and '+' for
        # email addresses, ':' for URIs, '/' for paths.
        if ch.isalnum() or ch in "_.-@+:/":
            j = i
            while j < n and (formula[j].isalnum() or formula[j] in "_.-@+:/"):
                j += 1
            ident = formula[i:j]
            if ident in _TOKEN_KEYWORDS:
                tokens.append(_Token(kind="kw", value=ident))
            else:
                tokens.append(_Token(kind="atom", value=ident))
            i = j
            continue
        raise LtlfParseError(f"unexpected character {ch!r} at position {i}")
    return tokens


# ---------------------------------------------------------------------------
# AST
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _Node:
    """LTLf AST node. ``op`` discriminates."""

    op: str
    # For atoms: lhs is the source/key string, rhs is the comparator,
    # and value is the literal compared against. For boolean/temporal
    # operators, children holds operand nodes.
    lhs: str = ""
    rhs: str = ""
    value: str = ""
    children: tuple["_Node", ...] = ()


def _parse(formula: str) -> _Node:
    """Parse an LTLf formula into an AST. Empty formula returns a true atom."""
    if not formula or not formula.strip():
        return _Node(op="const", value="true")
    tokens = _tokenize(formula)
    pos = 0

    # Recursive descent with the following precedence (loosest to tightest):
    #   implies (right-assoc) -> or -> and -> until (right-assoc) ->
    #   unary (G F X !) -> primary (atom, paren)

    def peek() -> _Token | None:
        return tokens[pos] if pos < len(tokens) else None

    def consume(expected_value: str) -> None:
        nonlocal pos
        tok = peek()
        if tok is None or tok.value != expected_value:
            raise LtlfParseError(
                f"expected {expected_value!r}, got {tok.value if tok else 'EOF'!r}"
            )
        pos += 1

    def parse_implies() -> _Node:
        left = parse_or()
        tok = peek()
        if tok is not None and tok.value == "->":
            nonlocal pos
            pos += 1
            right = parse_implies()
            return _Node(op="->", children=(left, right))
        return left

    def parse_or() -> _Node:
        node = parse_and()
        while True:
            tok = peek()
            if tok is None or tok.value != "|":
                return node
            nonlocal pos
            pos += 1
            rhs = parse_and()
            node = _Node(op="|", children=(node, rhs))

    def parse_and() -> _Node:
        node = parse_until()
        while True:
            tok = peek()
            if tok is None or tok.value != "&":
                return node
            nonlocal pos
            pos += 1
            rhs = parse_until()
            node = _Node(op="&", children=(node, rhs))

    def parse_until() -> _Node:
        left = parse_unary()
        tok = peek()
        if tok is not None and tok.kind == "kw" and tok.value == "U":
            nonlocal pos
            pos += 1
            right = parse_until()
            return _Node(op="U", children=(left, right))
        return left

    def parse_unary() -> _Node:
        nonlocal pos
        tok = peek()
        if tok is None:
            raise LtlfParseError("unexpected end of formula")
        if tok.value == "!":
            pos += 1
            return _Node(op="!", children=(parse_unary(),))
        if tok.kind == "kw" and tok.value in ("G", "F", "X"):
            pos += 1
            return _Node(op=tok.value, children=(parse_unary(),))
        return parse_primary()

    def parse_primary() -> _Node:
        nonlocal pos
        tok = peek()
        if tok is None:
            raise LtlfParseError("unexpected end of formula")
        if tok.value == "(":
            pos += 1
            node = parse_implies()
            consume(")")
            return node
        if tok.kind == "kw" and tok.value in ("true", "false"):
            pos += 1
            return _Node(op="const", value=tok.value)
        # Atom: <source-or-key> [<comparator> <value>]
        # Special-case bare `tool=NAME` which is the most common form.
        if tok.kind == "atom":
            lhs = tok.value
            pos += 1
            comp_tok = peek()
            if comp_tok is None or comp_tok.kind != "op" or comp_tok.value not in (
                "=",
                "!=",
                ">=",
                "<=",
                ">",
                "<",
            ):
                # Bare atom = boolean state lookup, treated as state.<lhs>=true
                if "." not in lhs:
                    raise LtlfParseError(
                        f"bare atom {lhs!r} must be qualified (e.g. state.{lhs}=true)"
                    )
                return _Node(op="atom", lhs=lhs, rhs="=", value="true")
            comparator = comp_tok.value
            pos += 1
            val_tok = peek()
            if val_tok is None or val_tok.kind not in ("atom", "kw"):
                raise LtlfParseError("expected atom value after comparator")
            pos += 1
            # Reject bare unqualified atoms even when a comparator is present.
            # The only allowed shorthand is `tool=...`; everything else must
            # be qualified (state.<key>, action.<key>, obs.<key>).
            if "." not in lhs and lhs != "tool":
                raise LtlfParseError(
                    f"bare atom {lhs!r} must be qualified (e.g. state.{lhs}={val_tok.value})"
                )
            return _Node(op="atom", lhs=lhs, rhs=comparator, value=val_tok.value)
        raise LtlfParseError(f"unexpected token {tok.value!r}")

    root = parse_implies()
    if pos != len(tokens):
        raise LtlfParseError(f"trailing tokens at position {pos}: {tokens[pos:]}")
    return root


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------


def _atom_value(step: PathStep, lhs: str) -> object | None:
    """Resolve an atom LHS against a single step. Returns None if absent."""
    state, action, observation = step
    if lhs == "tool":
        # Special-case shorthand. Look in action under "tool", "type",
        # "action", or "name" — the four most common keys agent
        # frameworks use to identify a tool invocation.
        for key in ("tool", "type", "action", "name"):
            if key in action:
                return action[key]
        return None
    if "." not in lhs:
        # Already validated by the parser, but defensive.
        return None
    source, _, key = lhs.partition(".")
    bag: Mapping[str, object]
    if source == "state":
        bag = state
    elif source == "action":
        bag = action
    elif source == "obs":
        bag = observation
    else:
        return None
    # Support dotted keys recursively (state.x.y -> state["x"]["y"]).
    cur: object = bag
    for part in key.split("."):
        if isinstance(cur, Mapping) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _coerce_compare(left: object, comparator: str, right_literal: str) -> bool:
    if comparator == "=":
        return _equal(left, right_literal)
    if comparator == "!=":
        return not _equal(left, right_literal)
    # Numeric comparators only. Coerce both sides to float; non-numeric => False.
    try:
        l_val = float(left) if left is not None else None  # type: ignore[arg-type]
        r_val = float(right_literal)
    except (TypeError, ValueError):
        return False
    if l_val is None:
        return False
    if comparator == ">=":
        return l_val >= r_val
    if comparator == "<=":
        return l_val <= r_val
    if comparator == ">":
        return l_val > r_val
    if comparator == "<":
        return l_val < r_val
    return False


def _equal(left: object, right_literal: str) -> bool:
    if isinstance(left, bool):
        return ("true" if left else "false") == right_literal.lower()
    if isinstance(left, (int, float)):
        try:
            return float(left) == float(right_literal)
        except ValueError:
            return False
    if left is None:
        return right_literal.lower() in ("none", "null")
    return str(left) == right_literal


def _eval_at(node: _Node, trace: Sequence[PathStep], i: int) -> bool:
    """Evaluate ``node`` at position ``i`` in ``trace``. End-of-trace is i >= len."""
    n = len(trace)
    if node.op == "const":
        return node.value == "true"
    if node.op == "atom":
        if i >= n:
            return False
        observed = _atom_value(trace[i], node.lhs)
        return _coerce_compare(observed, node.rhs, node.value)
    if node.op == "!":
        return not _eval_at(node.children[0], trace, i)
    if node.op == "&":
        return _eval_at(node.children[0], trace, i) and _eval_at(node.children[1], trace, i)
    if node.op == "|":
        return _eval_at(node.children[0], trace, i) or _eval_at(node.children[1], trace, i)
    if node.op == "->":
        return (not _eval_at(node.children[0], trace, i)) or _eval_at(
            node.children[1], trace, i
        )
    if node.op == "X":
        # Finite-trace next: false if at the last position or beyond.
        if i + 1 >= n:
            return False
        return _eval_at(node.children[0], trace, i + 1)
    if node.op == "G":
        # Always: phi must hold at every position from i to n-1.
        # Vacuously true on empty suffix (i >= n).
        for j in range(i, n):
            if not _eval_at(node.children[0], trace, j):
                return False
        return True
    if node.op == "F":
        # Eventually: phi holds at some position in [i, n-1].
        for j in range(i, n):
            if _eval_at(node.children[0], trace, j):
                return True
        return False
    if node.op == "U":
        # phi U psi: there exists k in [i, n) with psi at k, and phi at
        # all positions in [i, k).
        phi, psi = node.children
        for k in range(i, n):
            if _eval_at(psi, trace, k):
                ok = True
                for j in range(i, k):
                    if not _eval_at(phi, trace, j):
                        ok = False
                        break
                if ok:
                    return True
        return False
    raise LtlfParseError(f"unknown AST op: {node.op!r}")


def evaluate(formula: str, trace: Sequence[PathStep]) -> bool:
    """
    Evaluate ``formula`` against ``trace``.

    The trace is interpreted as a complete execution prefix, evaluated
    starting at position 0. Per the Kaptein paper, this corresponds to
    checking a path policy against the partial path P_i with the
    candidate action s* appended as the final position.

    Important: with this convention, formulas that should hold at
    every position must be wrapped in ``G(...)``. A bare formula like
    ``tool=external_send -> F(tool=human_approval)`` only constrains
    position 0; to require the constraint globally, write
    ``G(tool=external_send -> F(tool=human_approval))``.

    An empty formula evaluates to True. An empty trace evaluates the
    formula at position 0 (which for atom-bearing formulas returns
    False since there are no steps to inspect). Both behaviors match
    the policy-registration semantics: a policy with no formula
    imposes no temporal constraint.
    """
    ast = _parse(formula)
    return _eval_at(ast, trace, 0)


def compile_formula(formula: str) -> _Node:
    """
    Pre-parse ``formula`` for repeated evaluation against different traces.

    The checker uses this to amortize parse cost across many calls.
    """
    return _parse(formula)


def evaluate_compiled(ast: _Node, trace: Sequence[PathStep]) -> bool:
    """Evaluate a pre-compiled formula AST against ``trace`` at position 0."""
    return _eval_at(ast, trace, 0)

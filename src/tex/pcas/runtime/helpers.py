"""
PCAS helper-function registry.

Helpers are deterministic, side-effect-free Python callables exposed to
the policy language as if they were atoms. The evaluator calls them
with ground argument tuples and treats them as predicates that succeed
iff the call returns ``True``.

Two flavours
------------
- **Predicate helper** ``(*args) -> bool``: succeeds on True, fails on
  False or any exception. Used like a guard atom in the body.
- **Function helper** ``(*args) -> FactValue``: returns a value; the
  evaluator binds an extra trailing variable to that return. Used by
  PCAS §4.5.2 for ``json_extract``-style helpers.

For now we ship a small predicate-only surface plus ``json_extract``,
which is the helper-function example called out in PCAS Appendix A.2.
Adding more helpers is a one-line ``register_helper`` call.

All helpers must be deterministic; they may not consult external
state. They will be invoked on every join row, so they must be cheap.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from tex.pcas.runtime.relation import FactValue


HelperFn = Callable[..., FactValue | bool]


@dataclass(frozen=True, slots=True)
class HelperFunction:
    """A registered helper."""

    name: str
    arity: int
    kind: str  # "predicate" | "function"
    fn: HelperFn

    def __post_init__(self) -> None:
        if self.kind not in ("predicate", "function"):
            raise ValueError(f"helper kind must be predicate|function, got {self.kind}")
        if self.arity < 0:
            raise ValueError("helper arity must be >= 0")


HELPER_REGISTRY: dict[str, HelperFunction] = {}


def register_helper(
    name: str,
    *,
    arity: int,
    kind: str,
    fn: HelperFn,
) -> HelperFunction:
    """
    Register a helper. Predicate helpers take ``arity`` args and return
    bool; function helpers take ``arity`` args and return a FactValue,
    with the last positional arg in the policy bound to the return.
    """
    if name in HELPER_REGISTRY:
        raise ValueError(f"helper {name!r} already registered")
    helper = HelperFunction(name=name, arity=arity, kind=kind, fn=fn)
    HELPER_REGISTRY[name] = helper
    return helper


# ---------------------------------------------------------------------------
# Built-in helpers (PCAS §4.5.2)
# ---------------------------------------------------------------------------


def _equals(x: FactValue, y: FactValue) -> bool:
    return x == y


def _not_equals(x: FactValue, y: FactValue) -> bool:
    return x != y


def _greater(x: FactValue, y: FactValue) -> bool:
    if isinstance(x, bool) or isinstance(y, bool):
        return False
    if isinstance(x, int) and isinstance(y, int):
        return x > y
    if isinstance(x, str) and isinstance(y, str):
        return x > y
    return False


def _less(x: FactValue, y: FactValue) -> bool:
    if isinstance(x, bool) or isinstance(y, bool):
        return False
    if isinstance(x, int) and isinstance(y, int):
        return x < y
    if isinstance(x, str) and isinstance(y, str):
        return x < y
    return False


def _json_extract(json_str: FactValue, path: FactValue) -> FactValue:
    """
    Walk a dotted path into a JSON document. Returns:
    - the value at the path coerced to str if it's not already str|int|bool
    - empty string if any key is missing (so the policy can compare it
      against ``""`` to test for absence).

    Deliberately conservative: floats are coerced to str; lists are
    rendered as canonical JSON. This keeps the fact-value space inside
    the canonical contract.
    """
    import json as _json

    if not isinstance(json_str, str) or not isinstance(path, str):
        return ""
    try:
        doc = _json.loads(json_str)
    except (ValueError, TypeError):
        return ""
    cur = doc
    for key in path.split("."):
        if isinstance(cur, dict) and key in cur:
            cur = cur[key]
            continue
        if isinstance(cur, list):
            try:
                cur = cur[int(key)]
                continue
            except (ValueError, IndexError):
                return ""
        return ""
    if isinstance(cur, bool):
        return cur
    if isinstance(cur, int):
        return cur
    if isinstance(cur, str):
        return cur
    if cur is None:
        return ""
    return _json.dumps(cur, sort_keys=True, separators=(",", ":"))


def _has_substring(haystack: FactValue, needle: FactValue) -> bool:
    return (
        isinstance(haystack, str)
        and isinstance(needle, str)
        and needle in haystack
    )


def _starts_with(haystack: FactValue, prefix: FactValue) -> bool:
    return (
        isinstance(haystack, str)
        and isinstance(prefix, str)
        and haystack.startswith(prefix)
    )


register_helper("equals", arity=2, kind="predicate", fn=_equals)
register_helper("not_equals", arity=2, kind="predicate", fn=_not_equals)
register_helper("greater", arity=2, kind="predicate", fn=_greater)
register_helper("less", arity=2, kind="predicate", fn=_less)
register_helper("has_substring", arity=2, kind="predicate", fn=_has_substring)
register_helper("starts_with", arity=2, kind="predicate", fn=_starts_with)
# function helper: last arg is the bound output
register_helper("json_extract", arity=3, kind="function", fn=_json_extract)


__all__ = [
    "HELPER_REGISTRY",
    "HelperFn",
    "HelperFunction",
    "register_helper",
]

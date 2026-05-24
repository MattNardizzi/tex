"""
PCAS runtime relations.

A *relation* is a typed multiset of fact tuples plus a small set of
hash indexes used by the evaluator to support fast join lookups.

Design
------
- A ``Fact`` is an immutable tuple of canonical-JSON-compatible values
  (``str | int | bool``). No floats; matches Tex's canonical contract.
- A ``Relation`` is keyed on the predicate name and stores facts in a
  ``frozenset`` for cheap set difference (semi-naive delta).
- Indexes are built lazily on the columns the evaluator joins on,
  cached as ``dict[tuple[int, ...] -> dict[tuple[Value, ...], list[Fact]]]``.

The relation API is fully immutable: ``add`` and ``add_many`` return a
new ``Relation`` so the evaluator can reason about deltas without
worrying about aliasing. The frozenset backing means ``new == old``
short-circuits the fixpoint.
"""

from __future__ import annotations

from typing import Iterable

from pydantic import BaseModel, ConfigDict, Field


FactValue = str | int | bool


class Fact(BaseModel):
    """A single ground fact ``relation(v1, v2, ...)`` as an immutable tuple."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    values: tuple[FactValue, ...]

    def __len__(self) -> int:
        return len(self.values)

    def __getitem__(self, i: int) -> FactValue:
        return self.values[i]

    def __iter__(self):  # type: ignore[override]
        return iter(self.values)

    @classmethod
    def of(cls, *values: FactValue) -> "Fact":
        return cls(values=tuple(values))


class Relation:
    """
    A typed multiset of facts. Immutable in the sense that mutators
    return a new ``Relation``; internal storage is plain Python.

    Stored as ``frozenset[tuple[FactValue, ...]]`` of raw value tuples
    (not pydantic ``Fact`` instances) for hashing/perf; conversion to
    ``Fact`` happens at the API boundary.
    """

    __slots__ = ("_name", "_arity", "_facts", "_index_cache")

    def __init__(
        self,
        *,
        name: str,
        arity: int,
        facts: Iterable[tuple[FactValue, ...]] = (),
    ) -> None:
        if not name or not name[0].islower():
            raise ValueError(f"relation name must be lowercase identifier, got {name!r}")
        if arity < 0:
            raise ValueError(f"arity must be >= 0, got {arity}")
        seen: set[tuple[FactValue, ...]] = set()
        for f in facts:
            if not isinstance(f, tuple):
                raise TypeError(f"fact must be a tuple, got {type(f).__name__}")
            if len(f) != arity:
                raise ValueError(
                    f"relation {name!r} has arity {arity}, got fact {f!r} "
                    f"of arity {len(f)}"
                )
            for v in f:
                if isinstance(v, bool):
                    continue
                if isinstance(v, (str, int)):
                    continue
                raise TypeError(
                    f"fact value must be str | int | bool, got {type(v).__name__}"
                )
            seen.add(f)
        self._name = name
        self._arity = arity
        self._facts: frozenset[tuple[FactValue, ...]] = frozenset(seen)
        # cache of column-set -> { value-tuple -> list[fact] }
        self._index_cache: dict[
            tuple[int, ...],
            dict[tuple[FactValue, ...], list[tuple[FactValue, ...]]],
        ] = {}

    # ------------------------------------------------------------- props

    @property
    def name(self) -> str:
        return self._name

    @property
    def arity(self) -> int:
        return self._arity

    @property
    def facts(self) -> frozenset[tuple[FactValue, ...]]:
        return self._facts

    def __len__(self) -> int:
        return len(self._facts)

    def __contains__(self, fact: tuple[FactValue, ...]) -> bool:
        return fact in self._facts

    def __iter__(self):
        return iter(self._facts)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Relation):
            return NotImplemented
        return (
            self._name == other._name
            and self._arity == other._arity
            and self._facts == other._facts
        )

    def __hash__(self) -> int:
        return hash((self._name, self._arity, self._facts))

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return f"Relation({self._name}/{self._arity}, n={len(self._facts)})"

    # -------------------------------------------------------- constructors

    def with_facts(self, facts: Iterable[tuple[FactValue, ...]]) -> "Relation":
        """Return a new relation containing the union of self and ``facts``."""
        merged = set(self._facts) | set(facts)
        return Relation(name=self._name, arity=self._arity, facts=merged)

    def replace(self, facts: Iterable[tuple[FactValue, ...]]) -> "Relation":
        """Return a new relation with exactly ``facts``."""
        return Relation(name=self._name, arity=self._arity, facts=facts)

    # ------------------------------------------------------------- joins

    def lookup(
        self,
        *,
        columns: tuple[int, ...],
        values: tuple[FactValue, ...],
    ) -> list[tuple[FactValue, ...]]:
        """
        Return all facts where ``columns`` equal ``values``, using a
        cached column-set index.
        """
        if len(columns) != len(values):
            raise ValueError(
                f"lookup arity mismatch: {len(columns)} columns vs {len(values)} values"
            )
        if not columns:
            return list(self._facts)
        idx = self._index_cache.get(columns)
        if idx is None:
            idx = self._build_index(columns)
            self._index_cache[columns] = idx
        return idx.get(values, [])

    def _build_index(
        self, columns: tuple[int, ...]
    ) -> dict[tuple[FactValue, ...], list[tuple[FactValue, ...]]]:
        out: dict[tuple[FactValue, ...], list[tuple[FactValue, ...]]] = {}
        for f in self._facts:
            key = tuple(f[c] for c in columns)
            out.setdefault(key, []).append(f)
        return out


__all__ = ["Fact", "FactValue", "Relation"]

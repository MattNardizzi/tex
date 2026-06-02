"""
SAFEFLOW inverse-operation registry.

For a transaction to be rollback-safe, every step must declare an
*inverse operation* — a callable that undoes the forward step's effect.
Tools whose effects cannot be undone (sending email, transferring
funds, publishing public content) **cannot** participate in a SAFEFLOW
transaction; they must be deferred to a post-commit phase.

The registry is process-global. ``register_inverse`` is intended to be
called at module import time for each tool that participates in
transactions.

Inverse-op signature
--------------------
::

    def inverse(*, tool: str, args: dict, result: object) -> None

The inverse function is invoked with the *exact* arguments and result
of the forward step. It is expected to be deterministic and side-
effect-free except for the undo operation itself.

Reference: ARIES Mohan-Haderle-Lindsay-Pirahesh-Schwarz 1992 (compensation
log records); arxiv 2506.07564 SAFEFLOW §4.2 (inverse-op contract).
"""

from __future__ import annotations

from typing import Any, Callable


InverseFn = Callable[..., None]


class InverseOpRegistry:
    """Process-global registry of inverse operations."""

    __slots__ = ("_inverses",)

    def __init__(self) -> None:
        self._inverses: dict[str, InverseFn] = {}

    def register(self, name: str, fn: InverseFn) -> None:
        if not name or not name.replace("_", "").isalnum():
            raise ValueError(f"invalid inverse op name: {name!r}")
        if not callable(fn):
            raise TypeError("inverse must be callable")
        if name in self._inverses:
            raise ValueError(f"inverse op {name!r} already registered")
        self._inverses[name] = fn

    def get(self, name: str) -> InverseFn | None:
        return self._inverses.get(name)

    def has(self, name: str) -> bool:
        return name in self._inverses

    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self._inverses.keys()))


_DEFAULT_REGISTRY = InverseOpRegistry()


def register_inverse(name: str, fn: InverseFn) -> None:
    """Register ``fn`` under ``name`` in the process-global registry."""
    _DEFAULT_REGISTRY.register(name, fn)


def get_inverse(name: str) -> InverseFn | None:
    return _DEFAULT_REGISTRY.get(name)


def default_registry() -> InverseOpRegistry:
    return _DEFAULT_REGISTRY


__all__ = [
    "InverseFn",
    "InverseOpRegistry",
    "default_registry",
    "get_inverse",
    "register_inverse",
]

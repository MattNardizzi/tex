"""
CaMeL capability lattice.

Three levels, total order:

::

    TRUSTED  ⊑  USER  ⊑  UNTRUSTED

- ``TRUSTED``    — system prompt, hard-coded constants, policy values.
- ``USER``       — user-provided content (the user is partially
                   trusted: they cannot inject into their own session,
                   but they can ask for harmful things).
- ``UNTRUSTED``  — tool outputs, retrieved documents, third-party
                   messages.

A ``Capability`` also carries a *source label* (e.g. the originating
tool name or "user") so policy can target specific sources, and a
``provenance_id`` matching the corresponding node in the PCAS
dependency graph.

The ``CapabilitySet`` is the IFC label attached to a value. Joining
sets follows the standard high-water-mark rule: result level is the
maximum input level; sources accumulate.

Reference: arxiv 2503.18813 §5 (CaMeL capabilities); arxiv 2505.22852
(operationalizing CaMeL); FIDES dual-axis lattice (arxiv 2505.23643)
for the join semantics.
"""

from __future__ import annotations

from enum import IntEnum

from pydantic import BaseModel, ConfigDict, Field


class CapabilityLevel(IntEnum):
    TRUSTED = 0
    USER = 1
    UNTRUSTED = 2

    def join(self, other: "CapabilityLevel") -> "CapabilityLevel":
        return CapabilityLevel(max(int(self), int(other)))


class Capability(BaseModel):
    """A single capability tag on a value."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    level: CapabilityLevel
    source: str = Field(min_length=1, max_length=128)
    provenance_id: str | None = Field(default=None, max_length=128)

    @classmethod
    def trusted(cls, source: str = "system") -> "Capability":
        return cls(level=CapabilityLevel.TRUSTED, source=source)

    @classmethod
    def user(cls, source: str = "user") -> "Capability":
        return cls(level=CapabilityLevel.USER, source=source)

    @classmethod
    def untrusted(
        cls, source: str, *, provenance_id: str | None = None
    ) -> "Capability":
        return cls(
            level=CapabilityLevel.UNTRUSTED,
            source=source,
            provenance_id=provenance_id,
        )


class CapabilitySet(BaseModel):
    """An immutable set of capabilities attached to a value."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    items: frozenset[Capability] = Field(default_factory=frozenset)

    @classmethod
    def empty(cls) -> "CapabilitySet":
        return cls(items=frozenset())

    @classmethod
    def of(cls, *caps: Capability) -> "CapabilitySet":
        return cls(items=frozenset(caps))

    @property
    def level(self) -> CapabilityLevel:
        if not self.items:
            return CapabilityLevel.TRUSTED
        return CapabilityLevel(max(int(c.level) for c in self.items))

    @property
    def sources(self) -> frozenset[str]:
        return frozenset(c.source for c in self.items)

    @property
    def is_trusted(self) -> bool:
        return self.level == CapabilityLevel.TRUSTED

    @property
    def is_untrusted(self) -> bool:
        return self.level == CapabilityLevel.UNTRUSTED

    def join(self, other: "CapabilitySet") -> "CapabilitySet":
        return CapabilitySet(items=self.items | other.items)

    def add(self, cap: Capability) -> "CapabilitySet":
        return CapabilitySet(items=self.items | {cap})

    def __or__(self, other: "CapabilitySet") -> "CapabilitySet":
        return self.join(other)

    def __contains__(self, cap: Capability) -> bool:
        return cap in self.items

    def __bool__(self) -> bool:
        return bool(self.items)


__all__ = ["Capability", "CapabilityLevel", "CapabilitySet"]

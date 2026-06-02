"""
CaMeL capability-tagged value.

A ``CapValue`` is the in-flight unit the interpreter manipulates: a
plain Python value plus a ``CapabilitySet`` describing where it came
from. All operations on values that produce new values must derive the
result's capability set from the *union* of the input capability sets.

We restrict values to the same canonical-JSON subset Tex uses
elsewhere (``str | int | bool | None | tuple[CapValue, ...] |
frozendict[str, CapValue]``) so values can be hashed, serialized into
evidence records, and passed to the PCAS evaluator as facts.

The interpreter never *strips* a capability except via an explicit
declassification step authorized by the policy. This is the FIDES
contract translated into CaMeL terms: an UNTRUSTED value stays
UNTRUSTED through every derivation unless the policy explicitly says
otherwise.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from tex.camel.capability import Capability, CapabilityLevel, CapabilitySet


class CapValue(BaseModel):
    """A capability-tagged value."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    value: str | int | bool | None | tuple = Field(default=None)
    caps: CapabilitySet = Field(default_factory=CapabilitySet.empty)

    @classmethod
    def trusted(cls, value: Any, source: str = "system") -> "CapValue":
        return cls(value=value, caps=CapabilitySet.of(Capability.trusted(source)))

    @classmethod
    def user(cls, value: Any, source: str = "user") -> "CapValue":
        return cls(value=value, caps=CapabilitySet.of(Capability.user(source)))

    @classmethod
    def untrusted(
        cls,
        value: Any,
        source: str,
        *,
        provenance_id: str | None = None,
    ) -> "CapValue":
        return cls(
            value=value,
            caps=CapabilitySet.of(
                Capability.untrusted(source, provenance_id=provenance_id)
            ),
        )

    @classmethod
    def derived(
        cls,
        value: Any,
        *,
        from_values: tuple["CapValue", ...],
    ) -> "CapValue":
        """
        Produce a new value whose capability set is the join of all
        input capability sets. This is the central CaMeL invariant
        (CaMeL §5.2).
        """
        merged = CapabilitySet.empty()
        for v in from_values:
            merged = merged | v.caps
        return cls(value=value, caps=merged)

    @property
    def level(self) -> CapabilityLevel:
        return self.caps.level

    @property
    def is_trusted(self) -> bool:
        return self.caps.is_trusted

    @property
    def is_untrusted(self) -> bool:
        return self.caps.is_untrusted


__all__ = ["CapValue"]

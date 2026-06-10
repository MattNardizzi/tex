"""
CaMeL capability lattice — FIDES dual-axis (integrity × confidentiality).

Integrity axis (the original CaMeL lattice, total order)
-------------------------------------------------------
::

    TRUSTED  ⊑  USER  ⊑  UNTRUSTED

- ``TRUSTED``    — system prompt, hard-coded constants, policy values.
- ``USER``       — user-provided content (the user is partially
                   trusted: they cannot inject into their own session,
                   but they can ask for harmful things).
- ``UNTRUSTED``  — tool outputs, retrieved documents, third-party
                   messages.

Confidentiality axis (added for FIDES dual-axis; total order)
-------------------------------------------------------------
::

    PUBLIC  ⊑  INTERNAL  ⊑  CONFIDENTIAL  ⊑  RESTRICTED

A value is *sensitive* once it reaches ``CONFIDENTIAL``. The confidentiality
ladder, its threshold, and its names are kept **deliberately identical** to
``tex.governance.private_data_exec.ifc.lattice.ConfidentialityLevel`` so the
codebase has exactly one FIDES confidentiality vocabulary, not two divergent
ones. (We define it locally rather than import it to keep ``camel`` a
self-contained subsystem with no cross-dependency on the IFC engine; the two
are isomorphic by construction and tested to agree — see
``tests/frontier_thread_12/test_capability_fides.py``.)

Why two axes
------------
FIDES (Costa, Köpf, Russinovich, Zanella-Béguelin et al., "Securing AI Agents
with Information-Flow Control," arXiv:2505.23643) augments a single-axis taint
label with a second axis so the *canonical* prompt-injection-to-exfiltration
attack becomes a typed lattice violation: an **untrusted-integrity** value
flowing into a **sensitive-confidentiality** sink. The single-axis CaMeL
lattice can express "this value is untrusted" but not "and it is about to
touch sensitive data" — exactly the conjunction the Rule-of-Two structural
contract (``tex.contracts.rule_of_two``) needs. This module provides the
product lattice; the interpreter's tool-call gate continues to use the
integrity axis alone (unchanged), and the confidentiality axis is consumed by
the Rule-of-Two contract and any FIDES-aware policy.

Join semantics
--------------
Both axes join by the **high-water mark = most-dangerous-wins** rule:
integrity climbs toward ``UNTRUSTED`` (taint spreads), confidentiality climbs
toward ``RESTRICTED`` (sensitivity spreads). This matches FIDES's label
propagation. (The IFC engine encodes integrity with the *opposite* numeric
direction — ``min`` over a 5-level lattice where untrusted is the low end —
but the semantics are identical: a derived value inherits the lowest trust /
highest sensitivity of any ancestor. The relationship is documented in
``CapabilityLevel`` below.)

A ``Capability`` also carries a *source label* (e.g. the originating tool name
or "user") so policy can target specific sources, and a ``provenance_id``
matching the corresponding node in the PCAS dependency graph.

References: CaMeL capabilities (arXiv:2503.18813); "Operationalizing CaMeL"
(arXiv:2505.22852); FIDES dual-axis lattice (arXiv:2505.23643);
Denning 1976 (lattice model of secure information flow).
"""

from __future__ import annotations

from enum import IntEnum

from pydantic import BaseModel, ConfigDict, Field


class CapabilityLevel(IntEnum):
    """Integrity axis of the FIDES product lattice (the original CaMeL lattice).

    Numeric direction: ``TRUSTED < USER < UNTRUSTED`` with ``join = max`` —
    "most-tainted wins." This is the inverse numeric encoding of the IFC
    engine's ``IntegrityLevel`` (which puts untrusted at the low end and joins
    with ``min``); the two are isomorphic — both make a derived value inherit
    the lowest trust of any ancestor. ``camel.UNTRUSTED`` corresponds to
    ``ifc.TOOL_UNTRUSTED``; ``camel.TRUSTED`` to ``ifc.SYS_INSTR``.
    """

    TRUSTED = 0
    USER = 1
    UNTRUSTED = 2

    def join(self, other: "CapabilityLevel") -> "CapabilityLevel":
        return CapabilityLevel(max(int(self), int(other)))

    @property
    def is_untrusted_level(self) -> bool:
        """True at ``UNTRUSTED`` — the FIDES low-integrity tier on this axis."""
        return self == CapabilityLevel.UNTRUSTED


class ConfidentialityLevel(IntEnum):
    """Confidentiality axis of the FIDES product lattice.

    Total order ``PUBLIC < INTERNAL < CONFIDENTIAL < RESTRICTED`` with
    ``join = max`` — the most-sensitive class among ancestors wins (the dual of
    the integrity rule). Names, ordering, and the ``is_sensitive`` threshold
    (``>= CONFIDENTIAL``) match
    ``tex.governance.private_data_exec.ifc.lattice.ConfidentialityLevel`` so
    the two FIDES lattices in the codebase agree exactly.
    """

    PUBLIC = 0
    INTERNAL = 1
    CONFIDENTIAL = 2
    RESTRICTED = 3

    def join(self, other: "ConfidentialityLevel") -> "ConfidentialityLevel":
        return ConfidentialityLevel(max(int(self), int(other)))

    @property
    def is_sensitive(self) -> bool:
        """True at or above ``CONFIDENTIAL`` — the sensitive-sink threshold."""
        return self >= ConfidentialityLevel.CONFIDENTIAL


class Capability(BaseModel):
    """A single capability tag on a value.

    Carries both FIDES axes. ``confidentiality`` defaults to ``PUBLIC`` so
    every pre-FIDES construction site (``Capability.trusted()``, ``.user()``,
    ``.untrusted(src)``) keeps its exact prior meaning — the dual-axis upgrade
    is strictly additive.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    level: CapabilityLevel
    confidentiality: ConfidentialityLevel = Field(default=ConfidentialityLevel.PUBLIC)
    source: str = Field(min_length=1, max_length=128)
    provenance_id: str | None = Field(default=None, max_length=128)

    @classmethod
    def trusted(
        cls,
        source: str = "system",
        *,
        confidentiality: ConfidentialityLevel = ConfidentialityLevel.PUBLIC,
    ) -> "Capability":
        return cls(
            level=CapabilityLevel.TRUSTED,
            confidentiality=confidentiality,
            source=source,
        )

    @classmethod
    def user(
        cls,
        source: str = "user",
        *,
        confidentiality: ConfidentialityLevel = ConfidentialityLevel.PUBLIC,
    ) -> "Capability":
        return cls(
            level=CapabilityLevel.USER,
            confidentiality=confidentiality,
            source=source,
        )

    @classmethod
    def untrusted(
        cls,
        source: str,
        *,
        provenance_id: str | None = None,
        confidentiality: ConfidentialityLevel = ConfidentialityLevel.PUBLIC,
    ) -> "Capability":
        return cls(
            level=CapabilityLevel.UNTRUSTED,
            confidentiality=confidentiality,
            source=source,
            provenance_id=provenance_id,
        )

    @classmethod
    def sensitive(
        cls,
        source: str,
        *,
        level: CapabilityLevel = CapabilityLevel.TRUSTED,
        confidentiality: ConfidentialityLevel = ConfidentialityLevel.CONFIDENTIAL,
        provenance_id: str | None = None,
    ) -> "Capability":
        """A trusted-but-sensitive source (e.g. a private-data read).

        Convenience for the common Rule-of-Two ingredient "sensitive access":
        data that is well-trusted on the integrity axis but classified on the
        confidentiality axis.
        """
        return cls(
            level=level,
            confidentiality=confidentiality,
            source=source,
            provenance_id=provenance_id,
        )


class FidesLabel(BaseModel):
    """The dual-axis (integrity, confidentiality) projection of a value's caps.

    The unit the FIDES flow-violation predicate operates on. Joining two labels
    floors integrity toward ``UNTRUSTED`` and climbs confidentiality toward
    ``RESTRICTED`` — the most-dangerous combination of the ancestors.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    integrity: CapabilityLevel = Field(default=CapabilityLevel.TRUSTED)
    confidentiality: ConfidentialityLevel = Field(default=ConfidentialityLevel.PUBLIC)

    def join(self, other: "FidesLabel") -> "FidesLabel":
        return FidesLabel(
            integrity=self.integrity.join(other.integrity),
            confidentiality=self.confidentiality.join(other.confidentiality),
        )

    @property
    def is_untrusted(self) -> bool:
        return self.integrity.is_untrusted_level

    @property
    def is_sensitive(self) -> bool:
        return self.confidentiality.is_sensitive

    @property
    def is_flow_violation(self) -> bool:
        """Canonical FIDES violation: untrusted-integrity meets sensitive sink.

        True iff a low-integrity (UNTRUSTED) value also carries a
        sensitive-confidentiality (>= CONFIDENTIAL) marker — i.e. attacker-
        controllable content is about to be released into, or commingled with,
        sensitive data. This is the same predicate as
        ``ifc.lattice.IfcLabel.is_flow_violation``.
        """
        return self.is_untrusted and self.is_sensitive


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
    def confidentiality(self) -> ConfidentialityLevel:
        """High-water-mark confidentiality over all member capabilities."""
        if not self.items:
            return ConfidentialityLevel.PUBLIC
        return ConfidentialityLevel(max(int(c.confidentiality) for c in self.items))

    @property
    def fides_label(self) -> FidesLabel:
        """The dual-axis label of this set (integrity × confidentiality joins)."""
        return FidesLabel(integrity=self.level, confidentiality=self.confidentiality)

    @property
    def sources(self) -> frozenset[str]:
        return frozenset(c.source for c in self.items)

    @property
    def is_trusted(self) -> bool:
        return self.level == CapabilityLevel.TRUSTED

    @property
    def is_untrusted(self) -> bool:
        return self.level == CapabilityLevel.UNTRUSTED

    @property
    def is_sensitive(self) -> bool:
        """True when any member capability carries a sensitive confidentiality."""
        return self.confidentiality.is_sensitive

    @property
    def is_flow_violation(self) -> bool:
        """FIDES dual-axis violation across this set (untrusted ∧ sensitive)."""
        return self.fides_label.is_flow_violation

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


__all__ = [
    "Capability",
    "CapabilityLevel",
    "ConfidentialityLevel",
    "FidesLabel",
    "CapabilitySet",
]

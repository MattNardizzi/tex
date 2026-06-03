"""
Integrity lattice and FIDES-style product lattice for IFC enforcement.

References
----------
- Chinaei (ARM). "Causality Laundering: Denial-Feedback Leakage in
  Tool-Calling LLM Agents." arXiv:2604.04035 (Apr 2026). Section 2.3
  defines the five-level integrity lattice:
      ToolDesc < ToolUntrusted < ToolTrusted < UserInput < SysInstr
  We adopt this lattice unchanged.

- Costa, Köpf, Kolluri, Paverd, Russinovich, Salem, Tople, Wutschitz,
  Zanella-Béguelin (FIDES). "Securing AI Agents with Information-Flow
  Control." arXiv:2505.23643. FIDES augments labels with type
  information forming a product lattice (ℓ, μ); low-capacity output
  types (bool, enum) can be safely declassified.

- Denning, D. "A Lattice Model of Secure Information Flow."
  Communications of the ACM, 19(5), 1976. The foundational lattice
  model for information flow.

- Stanley, Verma, Tsai, Kallas, Kumar (GAAP). "An AI Agent Execution
  Environment to Safeguard User Data." arXiv:2604.19657 (Apr 2026).
  GAAP's permission DB is the secondary confidentiality axis we
  preserve as a cross-cut alongside the ARM integrity lattice.

The lattice algebra defined here is the foundation for every
enforcement decision in Tex's IFC stream. Lattice operations must be
deterministic, fast, and side-effect free.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from typing import Iterable

from pydantic import BaseModel, ConfigDict, Field


# ---------------------------------------------------------------------------
# Integrity lattice (ARM §2.3 Definition 1)
# ---------------------------------------------------------------------------


class IntegrityLevel(enum.IntEnum):
    """
    Five-level integrity lattice from ARM (arxiv 2604.04035 §2.3).

    Ordered TOTALLY from least-trusted to most-trusted. The integer
    values are deliberately chosen so that ``min(a, b)`` is the
    conservative join (i.e., taint floors to the lowest ancestor),
    matching ARM's MinTrust semantics.

    Levels
    ------
    TOOL_DESC      — MCP tool metadata (descriptions/schemas). Most
                     attacker-controllable in real MCP deployments
                     (tool-poisoning attacks, arxiv 2603.24203). Lowest
                     trust.
    TOOL_UNTRUSTED — Output from untrusted tools or external content
                     (web scrapes, third-party API responses, ingested
                     email bodies, retrieved documents). The "lethal
                     trifecta" source category (Willison 2025).
    TOOL_TRUSTED   — Output from operator-verified tools or signed API
                     responses. Trusted but not authoritative.
    USER_INPUT     — Direct user prompt. Trusted but bounded.
    SYS_INSTR      — Operator-supplied system instructions. The
                     canonical root of trust.

    Use IntegrityLevel.min(a, b) as the conservative join (FIDES §2.2
    label propagation rule, ARM Property 1 Monotonic Taint).
    """

    TOOL_DESC = 0
    TOOL_UNTRUSTED = 1
    TOOL_TRUSTED = 2
    USER_INPUT = 3
    SYS_INSTR = 4

    @classmethod
    def join(cls, levels: Iterable["IntegrityLevel"]) -> "IntegrityLevel":
        """
        Conservative join: minimum trust over a set of ancestors.

        Matches ARM Definition 4 (MinTrust): a derived value inherits
        the lowest trust of any data ancestor. With an empty set, we
        default to SYS_INSTR (the most-trusted level), so that values
        with no untrusted ancestors are treated as fully trusted.
        """
        materialized = tuple(levels)
        if not materialized:
            return cls.SYS_INSTR
        result = materialized[0]
        for level in materialized[1:]:
            if level < result:
                result = level
        return result

    @property
    def is_untrusted(self) -> bool:
        """True when at or below TOOL_UNTRUSTED — the FIDES low-integrity tier."""
        return self <= IntegrityLevel.TOOL_UNTRUSTED

    @property
    def label(self) -> str:
        return self.name


# ---------------------------------------------------------------------------
# Confidentiality lattice (FIDES § 2.2 weak-secrecy lattice)
# ---------------------------------------------------------------------------


class ConfidentialityLevel(enum.IntEnum):
    """
    Confidentiality lattice — the dual of the integrity lattice.

    FIDES (arxiv 2505.23643) tracks confidentiality as the set of
    permitted readers; we approximate that with a four-step hierarchy
    that aligns with operational data classifications most enterprises
    already use (public / internal / confidential / restricted) and
    matches what insurers ask for under cyber-policy AI riders.

    Conservative join here is the MAXIMUM (more sensitive wins): a
    derived value inherits the most-sensitive class among its
    ancestors. This is the dual of the integrity join rule.
    """

    PUBLIC = 0
    INTERNAL = 1
    CONFIDENTIAL = 2
    RESTRICTED = 3

    @classmethod
    def join(
        cls, levels: Iterable["ConfidentialityLevel"]
    ) -> "ConfidentialityLevel":
        materialized = tuple(levels)
        if not materialized:
            return cls.PUBLIC
        result = materialized[0]
        for level in materialized[1:]:
            if level > result:
                result = level
        return result

    @property
    def is_sensitive(self) -> bool:
        """True when at or above CONFIDENTIAL — the sensitive-sink threshold."""
        return self >= ConfidentialityLevel.CONFIDENTIAL

    @property
    def label(self) -> str:
        return self.name


# ---------------------------------------------------------------------------
# FIDES product lattice (ℓ, μ) — label × type
# ---------------------------------------------------------------------------


class CapacityType(enum.IntEnum):
    """
    FIDES output-type capacity (arxiv 2505.23643 §3).

    FIDES's key novelty over single-axis IFC: declassification is
    permitted for *low-capacity* outputs because they cannot encode an
    arbitrary attacker payload. A `bool` carries at most one bit; an
    `enum` over k values carries log2(k) bits. Free-form `text` can
    carry an attacker's entire injection payload and must NOT
    declassify.

    Mapping rule (FIDES §3.2): if a quarantined LLM produces a value
    whose capacity is below the configured threshold, the value may
    be promoted to TOOL_TRUSTED even if its source was untrusted.
    Above the threshold, untrusted stays untrusted.
    """

    BOOL = 0          # 1 bit — always safe to declassify
    ENUM = 1          # bounded — safe under operator policy
    NUMBER = 2        # bounded magnitude — usually safe
    TIMESTAMP = 3     # bounded format — usually safe
    SHORT_STRING = 4  # <= 32 chars — borderline
    TEXT = 5          # unbounded — never safe to declassify

    @property
    def declassifies(self) -> bool:
        """True when this capacity is safe to declassify under FIDES rules."""
        return self <= CapacityType.ENUM


# ---------------------------------------------------------------------------
# Composite label
# ---------------------------------------------------------------------------


class IfcLabel(BaseModel):
    """
    Composite IFC label: (integrity, confidentiality, capacity).

    This is the unit of taint that propagates through the provenance
    graph. The triple combines:

      - integrity   : ARM's 5-level integrity lattice (untrusted-source
                      tracking). Conservative join is min.
      - confidentiality : 4-level sensitivity ladder (sensitive-sink
                      tracking). Conservative join is max.
      - capacity    : FIDES type-capacity tag enabling declassification
                      of low-capacity values.

    Propagation rule for derived values:
        derived.integrity        = min over ancestor integrities
        derived.confidentiality  = max over ancestor confidentialities
        derived.capacity         = the more permissive capacity of
                                   the immediate producer (declassification
                                   is allowed only at the producer step,
                                   not retroactively)

    This is a frozen pydantic model and may be safely hashed and used
    as a dict key by callers.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    integrity: IntegrityLevel = Field(
        default=IntegrityLevel.SYS_INSTR,
        description="ARM integrity level (5-step lattice).",
    )
    confidentiality: ConfidentialityLevel = Field(
        default=ConfidentialityLevel.PUBLIC,
        description="Confidentiality classification (4-step lattice).",
    )
    capacity: CapacityType = Field(
        default=CapacityType.TEXT,
        description="FIDES capacity tag for the produced value type.",
    )

    def join(self, other: "IfcLabel") -> "IfcLabel":
        """
        Conservative join with another label.

        Integrity floors to the minimum (taint propagates downward).
        Confidentiality climbs to the maximum (sensitivity propagates
        upward). Capacity stays at the more conservative (higher
        capacity = less safe) value.
        """
        return IfcLabel(
            integrity=IntegrityLevel.join((self.integrity, other.integrity)),
            confidentiality=ConfidentialityLevel.join(
                (self.confidentiality, other.confidentiality)
            ),
            capacity=CapacityType(max(int(self.capacity), int(other.capacity))),
        )

    @property
    def is_flow_violation(self) -> bool:
        """
        Does this label represent an inadmissible flow?

        True when an untrusted-integrity value carries a
        sensitive-confidentiality marker — i.e., low-integrity content
        is about to be released into a high-sensitivity sink. This is
        the canonical FIDES/MVAR/ARM violation predicate.
        """
        return self.integrity.is_untrusted and self.confidentiality.is_sensitive

    @property
    def may_declassify(self) -> bool:
        """True when capacity is bounded enough for FIDES declassification."""
        return self.capacity.declassifies

    @classmethod
    def trusted(cls) -> "IfcLabel":
        """Convenience: fully trusted, public, declassifiable label."""
        return cls(
            integrity=IntegrityLevel.SYS_INSTR,
            confidentiality=ConfidentialityLevel.PUBLIC,
            capacity=CapacityType.BOOL,
        )

    @classmethod
    def untrusted_public(cls) -> "IfcLabel":
        """Convenience: low-integrity, public-confidentiality, free text."""
        return cls(
            integrity=IntegrityLevel.TOOL_UNTRUSTED,
            confidentiality=ConfidentialityLevel.PUBLIC,
            capacity=CapacityType.TEXT,
        )

    @classmethod
    def sensitive_trusted(cls) -> "IfcLabel":
        """Convenience: trusted-but-sensitive label."""
        return cls(
            integrity=IntegrityLevel.SYS_INSTR,
            confidentiality=ConfidentialityLevel.RESTRICTED,
            capacity=CapacityType.TEXT,
        )


# ---------------------------------------------------------------------------
# Source classification
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SourceClassification:
    """
    A single labeled data source.

    The Tex IFC layer maps inbound content (request fields, retrieved
    documents, tool outputs, memory items) to a SourceClassification
    before the specialist evaluates. The classifier — implemented in
    `tex.governance.private_data_exec.ifc.classifier` — produces
    these.
    """

    source_id: str
    label: IfcLabel
    reason: str = ""


# Default labels for common Tex request elements. These match how
# `tex.engine.pdp` already routes data and are referenced by the
# IfcSpecialist when constructing the provenance graph.
LABEL_USER_PROMPT = IfcLabel(
    integrity=IntegrityLevel.USER_INPUT,
    confidentiality=ConfidentialityLevel.INTERNAL,
    capacity=CapacityType.TEXT,
)

LABEL_RETRIEVED_DOC = IfcLabel(
    integrity=IntegrityLevel.TOOL_UNTRUSTED,
    confidentiality=ConfidentialityLevel.INTERNAL,
    capacity=CapacityType.TEXT,
)

LABEL_TOOL_OUTPUT_TRUSTED = IfcLabel(
    integrity=IntegrityLevel.TOOL_TRUSTED,
    confidentiality=ConfidentialityLevel.INTERNAL,
    capacity=CapacityType.TEXT,
)

LABEL_TOOL_OUTPUT_UNTRUSTED = IfcLabel(
    integrity=IntegrityLevel.TOOL_UNTRUSTED,
    confidentiality=ConfidentialityLevel.INTERNAL,
    capacity=CapacityType.TEXT,
)

LABEL_TOOL_DESCRIPTION = IfcLabel(
    integrity=IntegrityLevel.TOOL_DESC,
    confidentiality=ConfidentialityLevel.PUBLIC,
    capacity=CapacityType.TEXT,
)


__all__ = [
    "IntegrityLevel",
    "ConfidentialityLevel",
    "CapacityType",
    "IfcLabel",
    "SourceClassification",
    "LABEL_USER_PROMPT",
    "LABEL_RETRIEVED_DOC",
    "LABEL_TOOL_OUTPUT_TRUSTED",
    "LABEL_TOOL_OUTPUT_UNTRUSTED",
    "LABEL_TOOL_DESCRIPTION",
]

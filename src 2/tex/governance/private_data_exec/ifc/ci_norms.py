"""
Contextual Integrity norm metadata for IFC enforcement.

References
----------
- Nissenbaum, H. "Privacy as Contextual Integrity." 79 Wash. L. Rev.
  119 (2004). Five-tuple norms: (sender, receiver, subject,
  information_type, transmission_principle).

- Roemmich, Martin, Schaub. "CA-CI: Integrating Contextual Integrity
  and the Capabilities Approach for Dignity Considerations in AI
  Governance." IEEE Security & Privacy, 2026. Elevates *purpose* to
  a constitutive parameter of information flows, enabling detection
  of scope creep and cross-context reuse.

- Bagdasarian et al. "Operationalizing Contextual Integrity in
  Privacy-Conscious Assistants." arxiv 2408.02373 (2024).

- Cheng et al. "CI-Bench: Benchmarking Contextual Integrity of AI
  Assistants on Synthetic Data." arxiv 2409.13903 (2024).

This module formalizes the CI five-tuple-plus-purpose (CA-CI six-tuple)
as a Pydantic model that travels alongside IFC labels. The IfcSpecialist
checks norm-appropriateness as part of its sink policy: a request that
satisfies the FIDES/ARM integrity check can still violate a CI norm if
its purpose drifts from what the data subject authorized.

This is BLEEDING-EDGE — no shipping competitor (Microsoft Agent
Governance Toolkit, Zenity, Noma, Pillar, Lakera) wires CI norms into
the runtime enforcement loop as of May 2026. The CI-Bench benchmarks
exist; the runtime enforcement does not.
"""

from __future__ import annotations

import enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class TransmissionPrinciple(str, enum.Enum):
    """
    Nissenbaum's transmission principle — the norm governing the flow.

    These are the most common transmission principles named in the
    CI literature and CI-Bench. Operators may extend via the `custom`
    metadata field on `CiNorm` rather than expanding this enum.
    """

    CONSENT = "consent"
    RECIPROCITY = "reciprocity"
    CONFIDENTIALITY = "confidentiality"
    NEED_TO_KNOW = "need_to_know"
    NOTICE = "notice"
    OBLIGATION = "obligation"
    COMMERCIAL = "commercial"
    SAFETY = "safety"
    LEGAL = "legal"
    DEFAULT_PERMITTED = "default_permitted"
    DEFAULT_FORBIDDEN = "default_forbidden"


class CiNorm(BaseModel):
    """
    CA-CI six-tuple norm describing an information flow.

    All six parameters together define whether a flow is *appropriate*
    in Nissenbaum's sense. Tex compares the realized flow described in
    an EvaluationRequest against a candidate norm; an unmatched norm
    contributes FORBID weight in the IfcSpecialist.

    Fields
    ------
    sender : Party emitting the data. For Tex requests this is usually
             the agent or its operator.
    receiver : Party receiving the data. For sends, this is the
               recipient on the request. For tool calls, the external
               party.
    subject : Whose information is at stake. Often distinct from sender
              (e.g., an agent sends customer Alice's data to a vendor;
              subject is Alice).
    information_type : Category of data (medical, financial, PII,
                       contact, biometric, behavioral, ...).
    transmission_principle : The norm governing the flow (see enum).
    purpose : CA-CI extension. The stated reason for the flow (e.g.,
              "account_verification", "marketing", "fraud_prevention").
              Required by Roemmich/Martin/Schaub 2026 to detect scope
              creep.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    sender: str = Field(min_length=1, max_length=200)
    receiver: str = Field(min_length=1, max_length=200)
    subject: str = Field(min_length=1, max_length=200)
    information_type: str = Field(min_length=1, max_length=200)
    transmission_principle: TransmissionPrinciple = Field(
        default=TransmissionPrinciple.DEFAULT_FORBIDDEN
    )
    purpose: str = Field(
        min_length=1,
        max_length=400,
        description=(
            "CA-CI extension (Roemmich et al, IEEE S&P 2026): the stated "
            "purpose of the flow. Required for scope-creep detection."
        ),
    )

    @field_validator(
        "sender", "receiver", "subject", "information_type", "purpose",
        mode="before",
    )
    @classmethod
    def _normalize(cls, value: Any) -> str:
        if not isinstance(value, str):
            raise TypeError("CI norm fields must be strings")
        normalized = value.strip().casefold()
        if not normalized:
            raise ValueError("CI norm fields must not be blank")
        return normalized

    def matches(self, other: "CiNorm") -> bool:
        """
        Strict tuple equality match.

        Two norms match iff all six parameters are identical. This is
        Nissenbaum's intuition: changing any parameter changes the
        norm. Operators can express partial matches via a registry of
        wildcards (handled at the registry level, not in this model).
        """
        return (
            self.sender == other.sender
            and self.receiver == other.receiver
            and self.subject == other.subject
            and self.information_type == other.information_type
            and self.transmission_principle == other.transmission_principle
            and self.purpose == other.purpose
        )

    def with_purpose(self, new_purpose: str) -> "CiNorm":
        """Return a variant with a different purpose (for scope-creep tests)."""
        return self.model_copy(update={"purpose": new_purpose.strip().casefold()})


class CiNormRegistry(BaseModel):
    """
    Set of permitted norms for a tenant.

    A flow is appropriate iff it matches at least one permitted norm.
    Mismatch → CI_NORM_VIOLATION FORBID signal in the IfcSpecialist.

    The default-empty registry corresponds to fail-closed CI
    enforcement: with no norms permitted, every flow violates CI. The
    PDP currently runs CI in advisory mode (uncertainty flag) when the
    registry is empty, switching to enforcement only when explicit
    norms are present, per the constitution's fail-closed default for
    novel signals.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    norms: tuple[CiNorm, ...] = Field(default_factory=tuple)

    def is_permitted(self, flow: CiNorm) -> bool:
        """True iff the flow matches any norm in the registry."""
        return any(norm.matches(flow) for norm in self.norms)


__all__ = [
    "TransmissionPrinciple",
    "CiNorm",
    "CiNormRegistry",
]

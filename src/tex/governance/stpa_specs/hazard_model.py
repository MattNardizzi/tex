"""
STPA hazard model.

References
----------
- Leveson & Thomas. "STPA Handbook." MIT, 2018.

Standard STPA artifacts (Leveson handbook):

  Loss               — a high-level adverse outcome (e.g. "regulatory fine")
  Hazard             — a system state that can lead to a loss
  SafetyConstraint   — derived by inverting a hazard; enforcing it prevents
                       the system from entering the hazardous state
  UnsafeControlAction — a control action that, in a context, leads to a hazard
  LossScenario       — a specific causal chain producing a loss

LLM-agent extensions
--------------------
Tex extends classical STPA for LLM-agent workflows:

  Stakeholder       — direct or indirect party whose values define losses
  Requirement (REQ) — abstract system goal derived from an unsafe behavior
  Specification (SPEC) — formal version of a REQ as an enforceable
                         IFC / temporal constraint
  EnforcementTier   — Blocklist / Mustlist / Allowlist / Confirmation
                      (four-tier enforcement structure)
  MCPLabel          — capability-enhanced MCP labels: capabilities,
                      confidentiality, trust level

Tex's existing scaffolding pre-commits the Loss/Hazard/UCA/LossScenario
shapes; we honor those signatures and add the LLM-agent extensions as
new dataclasses. The manifest YAML loader (in this module) consumes
all of them in one document.

Priority: P1.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

# Four-tier enforcement structure for LLM-agent tool governance.
EnforcementTier = Literal["blocklist", "mustlist", "allowlist", "confirmation"]

# UCA guide-words from Leveson handbook §2.3.
UcaGuideWord = Literal[
    "not_provided",       # required control action was not given
    "provided",           # control action was given when it should not have been
    "wrong_timing",       # given too early, too late, or out of order
    "wrong_duration",     # stopped too soon or applied too long
]


@dataclass(frozen=True, slots=True)
class Loss:
    """A high-level adverse outcome stakeholders wish to avoid."""

    loss_id: str
    description: str


@dataclass(frozen=True, slots=True)
class Hazard:
    """A system state that, in some environment, can lead to a loss."""

    hazard_id: str
    description: str
    leads_to_losses: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class SafetyConstraint:
    """
    A safety constraint derived by inverting a hazard.

    Per Leveson handbook §2.2: constraints are "system-level predicates
    derived by inverting hazards; their enforcement prevents a system
    from entering hazardous states." These translate into the REQs /
    SPECs that drive the four-tier enforcement.
    """

    constraint_id: str
    description: str
    inverts_hazards: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class UnsafeControlAction:
    """A control action that, under a specific context, leads to a hazard."""

    uca_id: str
    control_action: str
    context: str
    why_unsafe: str
    related_hazards: tuple[str, ...]
    guide_word: UcaGuideWord = "provided"


@dataclass(frozen=True, slots=True)
class LossScenario:
    """A specific causal chain producing a loss."""

    scenario_id: str
    causal_chain: tuple[str, ...]
    related_uca: str
    mitigation_modules: tuple[str, ...]  # Tex modules that mitigate


# ---------------------------------------------------------------------------
# LLM-agent extensions
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Stakeholder:
    """A direct or indirect stakeholder whose values define losses."""

    stakeholder_id: str
    name: str
    is_direct: bool = True
    values: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Requirement:
    """
    An abstract system goal derived from an unsafe system behavior.

    Stakeholder values are inverted into potential losses, and the
    corresponding safety and security requirements define the agent's
    expected behavior.
    """

    requirement_id: str
    description: str
    addresses_hazards: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class Specification:
    """
    A formal, enforceable version of a requirement.

    To provide formal guarantees, requirements must be transformed
    into symbolic specifications. Each spec declares which Tex
    enforcement module(s) realize it and at which enforcement tier.
    """

    spec_id: str
    description: str
    refines_requirement: str
    enforcement_tier: EnforcementTier
    enforcement_modules: tuple[str, ...]  # Tex modules that enforce


@dataclass(frozen=True, slots=True)
class MCPLabel:
    """
    A structured label attached to an MCP tool declaration.

    Every MCP server SHOULD provide three labels per tool method:
    ``capabilities``, ``confidentiality``, and ``trust``. The
    framework supports arbitrary additional keys; these three are the
    minimum for the four-tier enforcement to work.
    """

    tool_name: str
    capabilities: tuple[str, ...] = ()  # e.g. read-only, external_write, network
    confidentiality: str = "unknown"     # e.g. public / private / unsure
    trust: str = "unknown"               # e.g. trusted / community / untrusted
    extra: dict[str, str] | None = None

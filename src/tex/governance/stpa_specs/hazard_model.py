"""
STPA hazard model.

References
----------
- Doshi, Hong, Xu, Kang, Kapravelos, Kaestner. "Towards Verifiably Safe
  Tool Use for LLM Agents." ICSE-NIER 2026 (arXiv:2601.08012, Jan 2026).
- Leveson & Thomas. "STPA Handbook." MIT, 2018.

Standard STPA artifacts (Leveson handbook):

  Loss               — a high-level adverse outcome (e.g. "regulatory fine")
  Hazard             — a system state that can lead to a loss
  SafetyConstraint   — derived by inverting a hazard; enforcing it prevents
                       the system from entering the hazardous state
  UnsafeControlAction — a control action that, in a context, leads to a hazard
  LossScenario       — a specific causal chain producing a loss

Doshi-2026 extensions
---------------------
The ICSE-NIER 2026 paper extends classical STPA for LLM-agent workflows:

  Stakeholder       — direct or indirect party whose values define losses
  Requirement (REQ) — abstract system goal derived from an unsafe behavior
  Specification (SPEC) — formal version of a REQ as an enforceable
                         IFC / temporal constraint
  EnforcementTier   — Blocklist / Mustlist / Allowlist / Confirmation
                      (paper Section 4.2, four-tier structure)
  MCPLabel          — capability-enhanced MCP labels: capabilities,
                      confidentiality, trust level (paper Section 4.3)

Tex's existing scaffolding pre-commits the Loss/Hazard/UCA/LossScenario
shapes; we honor those signatures and add the Doshi-2026 extensions as
new dataclasses. The manifest YAML loader (in this module) consumes
all of them in one document.

Priority: P1.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

# Four-tier enforcement structure from Doshi-2026 §4.2.
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
    from entering hazardous states." Doshi-2026 §4.2 calls these the
    REQs / SPECs that translate into the four-tier enforcement.
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
# Doshi-2026 extensions
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

    Per Doshi-2026 §4.1: "we derive a set of values they expect from the
    system, and then invert these values into potential losses ...
    deriving corresponding safety and security requirements that define
    the agent's expected behavior."
    """

    requirement_id: str
    description: str
    addresses_hazards: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class Specification:
    """
    A formal, enforceable version of a requirement.

    Per Doshi-2026 §4.2: "to provide formal guarantees, [requirements]
    must be transformed into symbolic specifications." Each spec
    declares which Tex enforcement module(s) realize it and at which
    enforcement tier.
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

    Per Doshi-2026 §4.3, every MCP server SHOULD provide three labels
    per tool method: ``capabilities``, ``confidentiality``, and
    ``trust``. The framework supports arbitrary additional keys; these
    three are the minimum for the four-tier enforcement to work.
    """

    tool_name: str
    capabilities: tuple[str, ...] = ()  # e.g. read-only, external_write, network
    confidentiality: str = "unknown"     # e.g. public / private / unsure
    trust: str = "unknown"               # e.g. trusted / community / untrusted
    extra: dict[str, str] | None = None

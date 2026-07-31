"""
STPA (System-Theoretic Process Analysis) Hazard Specifications.

References
----------
- Leveson & Thomas. "STPA Handbook." MIT, 2018.

Formal hazard analysis and safety specifications over data flows and tool
sequences, modeled on STPA from system safety engineering. Strengthens
enterprise compliance language: maps Tex defenses to losses, hazards,
unsafe control actions, and loss scenarios.

Public API
----------
Classical STPA artifacts (Leveson handbook):
  Loss, Hazard, SafetyConstraint, UnsafeControlAction, LossScenario,
  UcaGuideWord

Tex's LLM-agent extensions:
  Stakeholder, Requirement, Specification, EnforcementTier, MCPLabel

Manifest loading + coverage matrix:
  StpaManifest, load_manifest
  StpaCoverageMatrix, build_coverage_matrix
  StpaManifestValidationError

Priority: P1.
"""

from tex.governance.stpa_specs.hazard_model import (
    EnforcementTier,
    Hazard,
    Loss,
    LossScenario,
    MCPLabel,
    Requirement,
    SafetyConstraint,
    Specification,
    Stakeholder,
    UcaGuideWord,
    UnsafeControlAction,
)
from tex.governance.stpa_specs.manifest import (
    StpaCoverageMatrix,
    StpaManifest,
    StpaManifestValidationError,
    build_coverage_matrix,
    load_manifest,
)

__all__ = [
    # Classical
    "Hazard",
    "Loss",
    "LossScenario",
    "SafetyConstraint",
    "UcaGuideWord",
    "UnsafeControlAction",
    # LLM-agent extensions
    "EnforcementTier",
    "MCPLabel",
    "Requirement",
    "Specification",
    "Stakeholder",
    # Manifest
    "StpaCoverageMatrix",
    "StpaManifest",
    "StpaManifestValidationError",
    "build_coverage_matrix",
    "load_manifest",
]

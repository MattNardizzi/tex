"""
Ecosystem-level verdict.

Extends the existing per-action PERMIT/ABSTAIN/FORBID with two new kinds:

  SANCTION  — admit the event but apply a sanction per the institutional
              governance graph (e.g. revoke a capability, reduce trust score)
  REMEDIATE — block the event and execute a restorative path (e.g. require
              human approval, replay with patched policy, trigger refund)

Plus per-axis scores so downstream systems can reason about *why*.

Thread 7.1 extension
--------------------
Adds two surfaces over the existing six-axis scoring:

  * ``viability_index`` — scalar in [0, 1] derived from the axis
    scores per Aubin viability theory (RiskGate, arxiv 2604.24686,
    Apr 27 2026). Higher = healthier; 1.0 = full viability, 0.0 =
    at the viability boundary.
  * ``graduated_level`` — GAAT-compatible enforcement tier
    (L0/L1/L2/L3/L4 per arxiv 2604.05119, Apr 6 2026). Maps the
    viability index to a discrete enforcement level for systems
    that consume per-event decisions rather than continuous scores.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, computed_field


class EcosystemVerdictKind(str, Enum):
    PERMIT = "permit"
    ABSTAIN = "abstain"
    FORBID = "forbid"
    SANCTION = "sanction"
    REMEDIATE = "remediate"


class GraduatedEnforcementLevel(str, Enum):
    """
    GAAT-compatible enforcement tiers (arxiv 2604.05119 §III.A).

    Maps viability_index to a discrete level for downstream systems
    that consume per-event decisions:

      L0 ALLOW       — viability_index ≥ 0.90
      L1 ALERT       — 0.70 ≤ viability_index < 0.90
      L2 FLAG        — 0.50 ≤ viability_index < 0.70
      L3 REDIRECT    — 0.25 ≤ viability_index < 0.50
      L4 QUARANTINE  — viability_index < 0.25

    These thresholds match GAAT's published Theorem-3 max-action
    composition table (Apple, Apr 6 2026).
    """

    L0_ALLOW = "L0_allow"
    L1_ALERT = "L1_alert"
    L2_FLAG = "L2_flag"
    L3_REDIRECT = "L3_redirect"
    L4_QUARANTINE = "L4_quarantine"


def _graduated_level_from_viability(viability: float) -> GraduatedEnforcementLevel:
    """Map a viability index ∈ [0, 1] to a GAAT enforcement tier."""
    if viability >= 0.90:
        return GraduatedEnforcementLevel.L0_ALLOW
    if viability >= 0.70:
        return GraduatedEnforcementLevel.L1_ALERT
    if viability >= 0.50:
        return GraduatedEnforcementLevel.L2_FLAG
    if viability >= 0.25:
        return GraduatedEnforcementLevel.L3_REDIRECT
    return GraduatedEnforcementLevel.L4_QUARANTINE


class EcosystemAxisScores(BaseModel):
    """
    Per-axis scoring of an ecosystem verdict.

    Six explicit axis fields plus two Thread-7.1 computed scalars:

      * ``viability_index`` — Aubin viability scalar in [0, 1] per
        RiskGate's ``B̂(x) = U(x) + SB(x) + RG(x)`` decomposition.
      * ``graduated_level`` — GAAT-compatible L0/L1/L2/L3/L4 tier.

    Viability index formula
    -----------------------
    Per RiskGate (arxiv 2604.24686):

        viability_index = 1 - max(U, SB, RG)

    where the three RiskGate terms map onto Tex's six axes:

      * **U(x)** unobserved risk     = drift_delta
      * **SB(x)** system-boundary    = max(contract_violation_severity,
                                           1 - governance_graph_legality)
      * **RG(x)** regulation-graph   = systemic_risk_under_event

    causal_attribution_confidence and bounded_compromise_score are
    not penalty terms — they're orthogonal evidence axes. They are
    NOT folded into the viability scalar (consumers wanting them
    can read the raw axis fields).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    contract_violation_severity: float = Field(ge=0, le=1)
    governance_graph_legality: float = Field(ge=0, le=1)
    causal_attribution_confidence: float = Field(ge=0, le=1)
    drift_delta: float
    systemic_risk_under_event: float = Field(ge=0, le=1)
    bounded_compromise_score: float = Field(ge=0, le=1)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def viability_index(self) -> float:
        """
        Aubin viability scalar in [0, 1]. RiskGate-compatible surface.

        Computed; not a stored field. Always equal to
        ``1 - max(U, SB, RG)`` clamped to [0, 1], where the three
        risk terms are derived from the six axis scores.
        """
        u = max(0.0, min(1.0, self.drift_delta))
        sb = max(
            max(0.0, min(1.0, self.contract_violation_severity)),
            max(0.0, min(1.0, 1.0 - self.governance_graph_legality)),
        )
        rg = max(0.0, min(1.0, self.systemic_risk_under_event))
        risk = max(u, sb, rg)
        return max(0.0, min(1.0, 1.0 - risk))

    @computed_field  # type: ignore[prop-decorator]
    @property
    def graduated_level(self) -> GraduatedEnforcementLevel:
        """
        GAAT-compatible enforcement tier (L0..L4) derived from
        viability_index. See ``GraduatedEnforcementLevel`` for the
        threshold table.
        """
        return _graduated_level_from_viability(self.viability_index)


class EcosystemVerdict(BaseModel):
    """The full ecosystem-state assessment for a proposed event."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: EcosystemVerdictKind
    proposed_event_id: str
    issued_at: datetime
    axis_scores: EcosystemAxisScores
    recommended_intervention_id: str | None = None
    ecosystem_state_hash_before: str
    ecosystem_state_hash_after: str | None = None  # populated on PERMIT
    rationale: str
    evidence_record_id: str | None = None  # link to evidence chain

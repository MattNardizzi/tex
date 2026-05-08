"""
Ecosystem-level verdict.

Extends the existing per-action PERMIT/ABSTAIN/FORBID with two new kinds:

  SANCTION  — admit the event but apply a sanction per the institutional
              governance graph (e.g. revoke a capability, reduce trust score)
  REMEDIATE — block the event and execute a restorative path (e.g. require
              human approval, replay with patched policy, trigger refund)

Plus per-axis scores so downstream systems can reason about *why*.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class EcosystemVerdictKind(str, Enum):
    PERMIT = "permit"
    ABSTAIN = "abstain"
    FORBID = "forbid"
    SANCTION = "sanction"
    REMEDIATE = "remediate"


class EcosystemAxisScores(BaseModel):
    """Per-axis scoring of an ecosystem verdict."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    contract_violation_severity: float = Field(ge=0, le=1)
    governance_graph_legality: float = Field(ge=0, le=1)
    causal_attribution_confidence: float = Field(ge=0, le=1)
    drift_delta: float
    systemic_risk_under_event: float = Field(ge=0, le=1)
    bounded_compromise_score: float = Field(ge=0, le=1)


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

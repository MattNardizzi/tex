"""
Calibration proposal domain object.

A CalibrationProposal is a *pending* threshold change. It is the bridge
between a calibration recommendation (read-only math) and a policy update
(durable mutation). The proposal explicitly captures:

  - which policy version we're proposing to replace
  - the recommendation as the calibrator produced it
  - the safety-clipped recommendation (often identical, sometimes tighter)
  - the replay report against historical decisions
  - the calibration-health snapshot at proposal time
  - approval state (PENDING / APPROVED / REJECTED / APPLIED / ROLLED_BACK)
  - approver identity at every transition
  - a rollback target (the policy version we'd revert to)

A proposal NEVER mutates a policy on its own. The application path is:

  recommend() → safety.evaluate() → replay() → health() → Proposal(PENDING)
       → human review (out of band)
       → approve(approver) → policy_store.save+activate()
       → safety.commit()
       → Proposal(APPLIED)

If something goes wrong: rollback(approver) → policy_store.activate(rollback_target)
                                               → Proposal(ROLLED_BACK)
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator

from tex.domain.policy import PolicySnapshot
from tex.learning.calibrator import CalibrationRecommendation
from tex.learning.health import CalibrationHealth
from tex.learning.replay import ReplayReport


class ProposalStatus(StrEnum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    APPLIED = "APPLIED"
    ROLLED_BACK = "ROLLED_BACK"
    EXPIRED = "EXPIRED"


class ProposalDiff(BaseModel):
    """Per-field diff so reviewers see the change at a glance."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    permit_threshold_before: float
    permit_threshold_after: float
    forbid_threshold_before: float
    forbid_threshold_after: float
    minimum_confidence_before: float
    minimum_confidence_after: float

    @property
    def has_changes(self) -> bool:
        return (
            self.permit_threshold_before != self.permit_threshold_after
            or self.forbid_threshold_before != self.forbid_threshold_after
            or self.minimum_confidence_before != self.minimum_confidence_after
        )


class CalibrationProposal(BaseModel):
    """A pending calibration."""

    model_config = ConfigDict(frozen=True, extra="forbid", arbitrary_types_allowed=True)

    proposal_id: UUID = Field(default_factory=uuid4)
    tenant_id: str | None = Field(default=None, max_length=200)
    source_policy_id: str = Field(min_length=1, max_length=255)
    source_policy_version: str = Field(min_length=1, max_length=100)
    proposed_new_version: str = Field(min_length=1, max_length=100)

    diff: ProposalDiff
    recommendation: CalibrationRecommendation
    safety_adjusted: bool
    safety_reasons: tuple[str, ...] = Field(default_factory=tuple)

    replay: ReplayReport
    health: CalibrationHealth

    status: ProposalStatus = ProposalStatus.PENDING
    created_by: str = Field(min_length=1, max_length=200)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    approved_by: str | None = Field(default=None, max_length=200)
    approved_at: datetime | None = None
    rejected_by: str | None = Field(default=None, max_length=200)
    rejected_at: datetime | None = None
    rejection_reason: str | None = Field(default=None, max_length=2_000)

    applied_at: datetime | None = None
    applied_policy_version: str | None = Field(default=None, max_length=100)

    rolled_back_by: str | None = Field(default=None, max_length=200)
    rolled_back_at: datetime | None = None
    rollback_target_version: str | None = Field(default=None, max_length=100)

    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _check_lifecycle(self) -> "CalibrationProposal":
        if self.status is ProposalStatus.APPROVED:
            if not self.approved_by or self.approved_at is None:
                raise ValueError("APPROVED proposals must record approver and timestamp")
        if self.status is ProposalStatus.REJECTED:
            if not self.rejected_by or self.rejected_at is None:
                raise ValueError("REJECTED proposals must record rejecter and timestamp")
        if self.status is ProposalStatus.APPLIED:
            if (
                not self.approved_by
                or self.applied_at is None
                or not self.applied_policy_version
            ):
                raise ValueError(
                    "APPLIED proposals must record approver, applied_at, and "
                    "applied_policy_version"
                )
        if self.status is ProposalStatus.ROLLED_BACK:
            if (
                not self.rolled_back_by
                or self.rolled_back_at is None
                or not self.rollback_target_version
            ):
                raise ValueError(
                    "ROLLED_BACK proposals must record rolled_back_by, "
                    "rolled_back_at, and rollback_target_version"
                )
        return self

    @classmethod
    def build(
        cls,
        *,
        source_policy: PolicySnapshot,
        proposed_new_version: str,
        recommendation: CalibrationRecommendation,
        replay: ReplayReport,
        health: CalibrationHealth,
        safety_adjusted: bool,
        safety_reasons: tuple[str, ...],
        tenant_id: str | None,
        created_by: str,
        metadata: dict[str, Any] | None = None,
    ) -> "CalibrationProposal":
        diff = ProposalDiff(
            permit_threshold_before=recommendation.current_permit_threshold,
            permit_threshold_after=recommendation.recommended_permit_threshold,
            forbid_threshold_before=recommendation.current_forbid_threshold,
            forbid_threshold_after=recommendation.recommended_forbid_threshold,
            minimum_confidence_before=recommendation.current_minimum_confidence,
            minimum_confidence_after=recommendation.recommended_minimum_confidence,
        )
        return cls(
            tenant_id=tenant_id,
            source_policy_id=source_policy.policy_id,
            source_policy_version=source_policy.version,
            proposed_new_version=proposed_new_version,
            diff=diff,
            recommendation=recommendation,
            safety_adjusted=safety_adjusted,
            safety_reasons=safety_reasons,
            replay=replay,
            health=health,
            created_by=created_by,
            metadata=dict(metadata or {}),
        )


__all__ = [
    "CalibrationProposal",
    "ProposalDiff",
    "ProposalStatus",
]

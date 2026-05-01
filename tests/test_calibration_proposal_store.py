"""Tests for the calibration proposal store and lifecycle."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from tex.domain.calibration_proposal import (
    CalibrationProposal,
    ProposalDiff,
    ProposalStatus,
)
from tex.learning.calibrator import CalibrationRecommendation
from tex.learning.health import (
    CalibrationHealth,
    HealthBand,
    HealthSubscore,
)
from tex.learning.outcomes import OutcomeSummary
from tex.learning.replay import ReplayCount, ReplayReport
from tex.policies.defaults import build_default_policy
from tex.stores.calibration_proposal_store import (
    CalibrationProposalStore,
    InvalidProposalTransitionError,
    ProposalNotFoundError,
)


def _summary() -> OutcomeSummary:
    return OutcomeSummary(
        total=100, correct_permits=85, false_permits=2, correct_forbids=10,
        false_forbids=2, abstain_reviews=1, unknown=0,
    )


def _recommendation() -> CalibrationRecommendation:
    return CalibrationRecommendation(
        current_permit_threshold=0.30,
        recommended_permit_threshold=0.32,
        current_forbid_threshold=0.65,
        recommended_forbid_threshold=0.65,
        current_minimum_confidence=0.60,
        recommended_minimum_confidence=0.62,
        summary=_summary(),
        reasons=("test",),
        false_permit_rate=0.02,
        false_forbid_rate=0.02,
        abstain_review_rate=0.01,
        unknown_rate=0.0,
        sample_weight=0.9,
        permit_threshold_delta=0.02,
        forbid_threshold_delta=0.0,
        minimum_confidence_delta=0.02,
    )


def _replay_report() -> ReplayReport:
    return ReplayReport(
        total_replayed=100,
        hard_blocked_unchanged=10,
        original_distribution=ReplayCount(permit=80, abstain=5, forbid=15),
        proposed_distribution=ReplayCount(permit=78, abstain=5, forbid=17),
        new_permits=0,
        new_abstains=0,
        new_forbids=2,
        resolved_abstains=0,
        would_have_blocked_safe=0,
        would_have_released_unsafe=0,
        labelled_decisions=20,
        new_false_permit_rate=0.02,
        new_false_forbid_rate=0.02,
        risky_change=False,
    )


def _health() -> CalibrationHealth:
    return CalibrationHealth(
        overall=HealthBand.GREEN,
        composite_score=0.85,
        subscores=(
            HealthSubscore(name="false_permit_rate", value=0.95, band=HealthBand.GREEN, reason="ok"),
        ),
        sample_size=100,
        quarantine_rate=0.02,
        reporter_diversity=0.85,
        advisories=(),
    )


def _build_proposal() -> CalibrationProposal:
    policy = build_default_policy()
    return CalibrationProposal.build(
        source_policy=policy,
        proposed_new_version="default-v2",
        recommendation=_recommendation(),
        replay=_replay_report(),
        health=_health(),
        safety_adjusted=False,
        safety_reasons=(),
        tenant_id="acme",
        created_by="orchestrator-test",
    )


def test_save_and_retrieve_proposal() -> None:
    store = CalibrationProposalStore()
    p = _build_proposal()
    store.save(p)
    retrieved = store.require(p.proposal_id)
    assert retrieved.proposal_id == p.proposal_id
    assert retrieved.status is ProposalStatus.PENDING


def test_approve_records_approver_and_timestamp() -> None:
    store = CalibrationProposalStore()
    p = _build_proposal()
    store.save(p)
    approved = store.approve(proposal_id=p.proposal_id, approver="matthew")
    assert approved.status is ProposalStatus.APPROVED
    assert approved.approved_by == "matthew"
    assert approved.approved_at is not None


def test_reject_requires_reason_and_records_rejecter() -> None:
    store = CalibrationProposalStore()
    p = _build_proposal()
    store.save(p)
    rejected = store.reject(
        proposal_id=p.proposal_id,
        rejecter="reviewer-a",
        reason="replay shows 3 false-permits at the new threshold",
    )
    assert rejected.status is ProposalStatus.REJECTED
    assert rejected.rejected_by == "reviewer-a"
    assert "replay" in (rejected.rejection_reason or "")


def test_blank_reject_reason_raises() -> None:
    store = CalibrationProposalStore()
    p = _build_proposal()
    store.save(p)
    with pytest.raises(ValueError):
        store.reject(proposal_id=p.proposal_id, rejecter="x", reason="   ")


def test_apply_only_after_approve() -> None:
    store = CalibrationProposalStore()
    p = _build_proposal()
    store.save(p)
    with pytest.raises(InvalidProposalTransitionError):
        store.mark_applied(proposal_id=p.proposal_id, applied_policy_version="default-v2")


def test_apply_records_rollback_target() -> None:
    store = CalibrationProposalStore()
    p = _build_proposal()
    store.save(p)
    store.approve(proposal_id=p.proposal_id, approver="matthew")
    applied = store.mark_applied(
        proposal_id=p.proposal_id,
        applied_policy_version="default-v2",
    )
    assert applied.status is ProposalStatus.APPLIED
    # Rollback target is the source policy version.
    assert applied.rollback_target_version == p.source_policy_version


def test_rollback_only_after_apply() -> None:
    store = CalibrationProposalStore()
    p = _build_proposal()
    store.save(p)
    store.approve(proposal_id=p.proposal_id, approver="matthew")
    # Cannot roll back without first applying.
    with pytest.raises(InvalidProposalTransitionError):
        store.mark_rolled_back(proposal_id=p.proposal_id, rolled_back_by="matthew")


def test_full_lifecycle_pending_approve_apply_rollback() -> None:
    store = CalibrationProposalStore()
    p = _build_proposal()
    store.save(p)
    store.approve(proposal_id=p.proposal_id, approver="matthew")
    store.mark_applied(proposal_id=p.proposal_id, applied_policy_version="default-v2")
    rolled = store.mark_rolled_back(proposal_id=p.proposal_id, rolled_back_by="matthew")
    assert rolled.status is ProposalStatus.ROLLED_BACK
    assert rolled.rolled_back_by == "matthew"


def test_list_pending_filters_by_tenant() -> None:
    store = CalibrationProposalStore()
    p1 = _build_proposal()
    p2 = _build_proposal().model_copy(update={"tenant_id": "other-tenant", "proposal_id": uuid4()})
    store.save(p1)
    store.save(p2)
    pending_acme = store.list_pending(tenant_id="acme")
    assert all(p.tenant_id == "acme" for p in pending_acme)
    assert len(pending_acme) == 1


def test_proposal_not_found_raises() -> None:
    store = CalibrationProposalStore()
    with pytest.raises(ProposalNotFoundError):
        store.require(uuid4())

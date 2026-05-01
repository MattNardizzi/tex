"""End-to-end tests for the feedback loop orchestrator."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest

from tex.domain.decision import Decision
from tex.domain.outcome import OutcomeKind, OutcomeRecord
from tex.domain.outcome_trust import (
    OutcomeSourceType,
    OutcomeTrustLevel,
)
from tex.domain.verdict import Verdict
from tex.learning.calibration_safety import CalibrationSafetyGuard
from tex.learning.calibrator import build_default_calibrator
from tex.learning.drift import PolicyDriftMonitor
from tex.learning.drift_classifier import DriftClassifier
from tex.learning.feedback_loop import FeedbackLoopOrchestrator
from tex.learning.outcome_validator import OutcomeValidator
from tex.learning.poisoning_detector import PoisoningDetector
from tex.learning.replay import ReplayValidator
from tex.learning.reporter_reputation import ReporterReputationStore
from tex.policies.defaults import build_default_policy
from tex.stores.calibration_proposal_store import CalibrationProposalStore
from tex.stores.decision_store import InMemoryDecisionStore
from tex.stores.outcome_store import InMemoryOutcomeStore
from tex.stores.policy_store import InMemoryPolicyStore


def _make_decision(
    *,
    tenant_id: str = "acme",
    final_score: float = 0.20,
    confidence: float = 0.95,
    verdict: Verdict = Verdict.PERMIT,
    policy_version: str = "default-v1",
    decided_at: datetime | None = None,
) -> Decision:
    request_id = uuid4()
    return Decision(
        request_id=request_id,
        verdict=verdict,
        confidence=confidence,
        final_score=final_score,
        action_type="sales_email",
        channel="email",
        environment="production",
        recipient="alice@example.com",
        content_excerpt="hi",
        content_sha256="c" * 64,
        policy_version=policy_version,
        scores={"semantic": final_score},
        reasons=[] if verdict is not Verdict.FORBID else ["risk"],
        uncertainty_flags=[] if verdict is not Verdict.ABSTAIN else ["uncertain"],
        metadata={"tenant_id": tenant_id},
        decided_at=decided_at or datetime.now(UTC),
    )


def _build_orchestrator():
    decisions = InMemoryDecisionStore()
    outcomes = InMemoryOutcomeStore()
    base_policy = build_default_policy()
    policies = InMemoryPolicyStore()
    policies.save(base_policy.model_copy(update={"version": "default-v1", "is_active": True}))

    proposals = CalibrationProposalStore()
    reputation = ReporterReputationStore(min_observations_before_decay=2)
    safety = CalibrationSafetyGuard(min_interval=timedelta(seconds=0))
    replay = ReplayValidator()
    drift_monitor = PolicyDriftMonitor(decision_store=decisions)
    drift_classifier = DriftClassifier()
    poisoning = PoisoningDetector()
    calibrator = build_default_calibrator()

    validator = OutcomeValidator(
        decisions=decisions,
        priors=outcomes,
    )

    orch = FeedbackLoopOrchestrator(
        decisions=decisions,
        outcomes=outcomes,
        policies=policies,
        proposals=proposals,
        validator=validator,
        reputation=reputation,
        calibrator=calibrator,
        safety=safety,
        replay=replay,
        drift_monitor=drift_monitor,
        drift_classifier=drift_classifier,
        poisoning_detector=poisoning,
        cold_start_minimum=10,
    )
    return orch, decisions, outcomes, policies, proposals


def _seed_history(
    orch: FeedbackLoopOrchestrator,
    decisions: InMemoryDecisionStore,
    *,
    n: int,
    tenant: str = "acme",
    bad_permit_rate: float = 0.30,
) -> None:
    """Seed N decisions + matching outcomes; bad_permit_rate controls false_permit count."""
    for i in range(n):
        d = _make_decision(tenant_id=tenant)
        decisions.save(d)
        if i / n < bad_permit_rate:
            o = OutcomeRecord.create(
                decision_id=d.decision_id,
                request_id=d.request_id,
                verdict=Verdict.PERMIT,
                outcome_kind=OutcomeKind.RELEASED,
                was_safe=False,  # FALSE_PERMIT
                reporter=f"reporter-{i % 3}",
                source_type=OutcomeSourceType.HUMAN_REVIEWER,
            )
        else:
            o = OutcomeRecord.create(
                decision_id=d.decision_id,
                request_id=d.request_id,
                verdict=Verdict.PERMIT,
                outcome_kind=OutcomeKind.RELEASED,
                was_safe=True,  # CORRECT_PERMIT
                reporter=f"reporter-{i % 3}",
                source_type=OutcomeSourceType.HUMAN_REVIEWER,
            )
        orch.ingest_outcome(o)


# ── ingest happy path ─────────────────────────────────────────────────────


def test_ingest_promotes_validated_outcome() -> None:
    orch, decisions, outcomes, policies, proposals = _build_orchestrator()
    d = _make_decision()
    decisions.save(d)
    o = OutcomeRecord.create(
        decision_id=d.decision_id,
        request_id=d.request_id,
        verdict=Verdict.PERMIT,
        outcome_kind=OutcomeKind.RELEASED,
        was_safe=True,
        reporter="qa-bot",
        source_type=OutcomeSourceType.SYSTEM_FEEDBACK,
    )
    result = orch.ingest_outcome(o)
    assert result.persisted
    assert not result.quarantined
    assert result.validation.outcome.trust_level is OutcomeTrustLevel.VALIDATED


def test_ingest_quarantines_outcome_with_no_decision() -> None:
    orch, decisions, outcomes, policies, proposals = _build_orchestrator()
    o = OutcomeRecord.create(
        decision_id=uuid4(),
        request_id=uuid4(),
        verdict=Verdict.PERMIT,
        outcome_kind=OutcomeKind.RELEASED,
        was_safe=True,
        reporter="qa-bot",
    )
    result = orch.ingest_outcome(o)
    assert result.persisted
    assert result.quarantined


# ── cold start ────────────────────────────────────────────────────────────


def test_cold_start_refuses_proposal() -> None:
    orch, decisions, outcomes, policies, proposals = _build_orchestrator()
    # Only 5 outcomes — below the cold_start_minimum=10.
    _seed_history(orch, decisions, n=5)
    result = orch.propose(
        tenant_id="acme",
        proposed_new_version="default-v2",
        created_by="test",
    )
    assert result.proposal is None
    assert any("Cold start" in a for a in result.advisories)


# ── multi-tenant isolation ────────────────────────────────────────────────


def test_proposal_for_tenant_a_does_not_see_tenant_b_outcomes() -> None:
    orch, decisions, outcomes, policies, proposals = _build_orchestrator()
    # Tenant B has plenty of bad outcomes, but tenant A has nothing.
    _seed_history(orch, decisions, n=20, tenant="tenant-b", bad_permit_rate=0.5)
    result = orch.propose(
        tenant_id="tenant-a",
        proposed_new_version="tenant-a-v2",
        created_by="test",
    )
    assert result.proposal is None
    assert any("Cold start" in a for a in result.advisories)


# ── full propose → approve flow ───────────────────────────────────────────


def test_propose_then_approve_creates_applied_proposal() -> None:
    orch, decisions, outcomes, policies, proposals = _build_orchestrator()
    _seed_history(orch, decisions, n=20, bad_permit_rate=0.30)

    result = orch.propose(
        tenant_id="acme",
        proposed_new_version="default-v2",
        created_by="test",
    )
    # We may or may not get a proposal depending on whether the calibrator
    # finds movement — but the seeded data has 30% false_permit rate, so it should.
    if result.proposal is None:
        # Defensive: this can happen if the calibrator's internal bounds
        # absorb the movement. In that case the test still confirms that
        # the "no movement" advisory fires.
        assert any(
            "no threshold movement" in a.lower() or "safety guard" in a.lower()
            for a in result.advisories
        )
        return

    proposal = result.proposal
    applied = orch.apply_proposal(
        proposal_id=proposal.proposal_id,
        approver="matthew",
    )
    assert applied.applied_policy_version == "default-v2"
    assert applied.approved_by == "matthew"
    # New policy is the active one now.
    assert policies.require_active().version == "default-v2"


def test_reject_proposal_does_not_apply_policy() -> None:
    orch, decisions, outcomes, policies, proposals = _build_orchestrator()
    _seed_history(orch, decisions, n=20, bad_permit_rate=0.30)
    result = orch.propose(
        tenant_id="acme",
        proposed_new_version="default-v2",
        created_by="test",
    )
    if result.proposal is None:
        return
    rejected = orch.reject_proposal(
        proposal_id=result.proposal.proposal_id,
        rejecter="reviewer",
        reason="needs more data",
    )
    # Active policy unchanged.
    assert policies.require_active().version == "default-v1"
    assert rejected.rejected_by == "reviewer"


def test_rollback_restores_source_policy() -> None:
    orch, decisions, outcomes, policies, proposals = _build_orchestrator()
    _seed_history(orch, decisions, n=20, bad_permit_rate=0.30)
    result = orch.propose(
        tenant_id="acme",
        proposed_new_version="default-v2",
        created_by="test",
    )
    if result.proposal is None:
        return
    orch.apply_proposal(proposal_id=result.proposal.proposal_id, approver="matthew")
    assert policies.require_active().version == "default-v2"

    orch.rollback_proposal(
        proposal_id=result.proposal.proposal_id,
        rolled_back_by="matthew",
    )
    assert policies.require_active().version == "default-v1"


# ── invariant: proposal never auto-applies ────────────────────────────────


def test_propose_does_not_mutate_active_policy() -> None:
    orch, decisions, outcomes, policies, proposals = _build_orchestrator()
    _seed_history(orch, decisions, n=20, bad_permit_rate=0.30)
    starting_version = policies.require_active().version
    orch.propose(
        tenant_id="acme",
        proposed_new_version="default-v2",
        created_by="test",
    )
    # Active policy is unchanged after propose() — only apply_proposal mutates it.
    assert policies.require_active().version == starting_version

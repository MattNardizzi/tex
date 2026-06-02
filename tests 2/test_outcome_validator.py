"""Tests for OutcomeValidator covering the full failure matrix."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from tex.domain.outcome import OutcomeKind, OutcomeRecord
from tex.domain.outcome_trust import (
    OutcomeSourceType,
    OutcomeTrustLevel,
)
from tex.domain.verdict import Verdict
from tex.learning.outcome_validator import (
    InProcessRateLimiter,
    OutcomeValidator,
    ValidationFailure,
)
from tex.stores.decision_store import InMemoryDecisionStore
from tex.stores.outcome_store import InMemoryOutcomeStore

from tests.factories import make_outcome  # type: ignore[attr-defined]  # noqa: F401


# Helper since make_decision may not exist in the factory module — build inline.
def _make_decision(
    *,
    request_id=None,
    policy_version: str = "default-v1",
    tenant_id: str | None = "acme",
    decided_at: datetime | None = None,
):
    from tex.domain.decision import Decision

    return Decision(
        request_id=request_id or uuid4(),
        verdict=Verdict.PERMIT,
        confidence=0.9,
        final_score=0.2,
        action_type="sales_email",
        channel="email",
        environment="production",
        recipient="alice@example.com",
        content_excerpt="hi",
        content_sha256="a" * 64,
        policy_version=policy_version,
        scores={"semantic": 0.2},
        reasons=[],
        uncertainty_flags=[],
        metadata={"tenant_id": tenant_id} if tenant_id else {},
        decided_at=decided_at or datetime.now(UTC),
    )


def _build_validator(
    *,
    decisions: InMemoryDecisionStore,
    outcomes: InMemoryOutcomeStore,
    rate_limiter: InProcessRateLimiter | None = None,
) -> OutcomeValidator:
    return OutcomeValidator(
        decisions=decisions,
        priors=outcomes,
        rate_limiter=rate_limiter,
    )


# ── happy path ────────────────────────────────────────────────────────────


def test_validator_promotes_clean_outcome_to_validated() -> None:
    decisions = InMemoryDecisionStore()
    outcomes = InMemoryOutcomeStore()
    decision = _make_decision()
    decisions.save(decision)
    validator = _build_validator(decisions=decisions, outcomes=outcomes)

    outcome = OutcomeRecord.create(
        decision_id=decision.decision_id,
        request_id=decision.request_id,
        verdict=Verdict.PERMIT,
        outcome_kind=OutcomeKind.RELEASED,
        was_safe=True,
        reporter="qa-bot",
        source_type=OutcomeSourceType.SYSTEM_FEEDBACK,
    )
    result = validator.validate(outcome)
    assert result.is_valid
    assert result.outcome.trust_level is OutcomeTrustLevel.VALIDATED
    assert result.outcome.tenant_id == "acme"  # backfilled from decision
    assert result.outcome.policy_version == "default-v1"  # backfilled


def test_validator_promotes_external_audit_to_verified() -> None:
    decisions = InMemoryDecisionStore()
    outcomes = InMemoryOutcomeStore()
    decision = _make_decision()
    decisions.save(decision)
    validator = _build_validator(decisions=decisions, outcomes=outcomes)

    outcome = OutcomeRecord.create(
        decision_id=decision.decision_id,
        request_id=decision.request_id,
        verdict=Verdict.PERMIT,
        outcome_kind=OutcomeKind.RELEASED,
        was_safe=True,
        reporter="auditor-1",
        source_type=OutcomeSourceType.EXTERNAL_AUDIT,
    )
    result = validator.validate(outcome)
    assert result.is_valid
    assert result.outcome.trust_level is OutcomeTrustLevel.VERIFIED


# ── failure modes ─────────────────────────────────────────────────────────


def test_decision_missing_quarantines() -> None:
    validator = _build_validator(
        decisions=InMemoryDecisionStore(),
        outcomes=InMemoryOutcomeStore(),
    )
    outcome = OutcomeRecord.create(
        decision_id=uuid4(),
        request_id=uuid4(),
        verdict=Verdict.PERMIT,
        outcome_kind=OutcomeKind.RELEASED,
        was_safe=True,
        reporter="qa-bot",
    )
    result = validator.validate(outcome)
    assert not result.is_valid
    assert ValidationFailure.DECISION_MISSING in result.failures
    assert result.outcome.trust_level is OutcomeTrustLevel.QUARANTINED


def test_request_id_mismatch_quarantines() -> None:
    decisions = InMemoryDecisionStore()
    outcomes = InMemoryOutcomeStore()
    decision = _make_decision()
    decisions.save(decision)
    validator = _build_validator(decisions=decisions, outcomes=outcomes)
    outcome = OutcomeRecord.create(
        decision_id=decision.decision_id,
        request_id=uuid4(),  # wrong
        verdict=Verdict.PERMIT,
        outcome_kind=OutcomeKind.RELEASED,
        was_safe=True,
        reporter="qa-bot",
    )
    result = validator.validate(outcome)
    assert ValidationFailure.REQUEST_ID_MISMATCH in result.failures
    assert result.outcome.trust_level is OutcomeTrustLevel.QUARANTINED


def test_tenant_mismatch_quarantines() -> None:
    decisions = InMemoryDecisionStore()
    outcomes = InMemoryOutcomeStore()
    decision = _make_decision(tenant_id="acme")
    decisions.save(decision)
    validator = _build_validator(decisions=decisions, outcomes=outcomes)
    outcome = OutcomeRecord.create(
        decision_id=decision.decision_id,
        request_id=decision.request_id,
        verdict=Verdict.PERMIT,
        outcome_kind=OutcomeKind.RELEASED,
        was_safe=True,
        reporter="qa-bot",
        tenant_id="evilcorp",
    )
    result = validator.validate(outcome)
    assert ValidationFailure.TENANT_MISMATCH in result.failures


def test_too_late_quarantines() -> None:
    decisions = InMemoryDecisionStore()
    outcomes = InMemoryOutcomeStore()
    decision = _make_decision(decided_at=datetime.now(UTC) - timedelta(days=200))
    decisions.save(decision)
    validator = _build_validator(decisions=decisions, outcomes=outcomes)
    outcome = OutcomeRecord.create(
        decision_id=decision.decision_id,
        request_id=decision.request_id,
        verdict=Verdict.PERMIT,
        outcome_kind=OutcomeKind.RELEASED,
        was_safe=True,
        reporter="qa-bot",
    )
    result = validator.validate(outcome)
    assert ValidationFailure.TOO_LATE in result.failures


def test_blank_reporter_quarantines() -> None:
    decisions = InMemoryDecisionStore()
    outcomes = InMemoryOutcomeStore()
    decision = _make_decision()
    decisions.save(decision)
    validator = _build_validator(decisions=decisions, outcomes=outcomes)
    outcome = OutcomeRecord.create(
        decision_id=decision.decision_id,
        request_id=decision.request_id,
        verdict=Verdict.PERMIT,
        outcome_kind=OutcomeKind.RELEASED,
        was_safe=True,
        reporter=None,
    )
    result = validator.validate(outcome)
    assert ValidationFailure.REPORTER_BLANK in result.failures


def test_rate_limited_reporter_quarantines() -> None:
    decisions = InMemoryDecisionStore()
    outcomes = InMemoryOutcomeStore()
    decision = _make_decision()
    decisions.save(decision)
    limiter = InProcessRateLimiter(cap_per_window=2, window=timedelta(hours=1))
    validator = _build_validator(
        decisions=decisions, outcomes=outcomes, rate_limiter=limiter
    )

    # Submit 3 rapid outcomes from the same reporter — third trips the limit.
    third_result = None
    for i in range(3):
        outcome = OutcomeRecord.create(
            decision_id=decision.decision_id,
            request_id=decision.request_id,
            verdict=Verdict.PERMIT,
            outcome_kind=OutcomeKind.RELEASED,
            was_safe=True,
            reporter="spammer",
        )
        result = validator.validate(outcome)
        if i == 2:
            third_result = result

    assert third_result is not None
    assert ValidationFailure.REPORTER_RATE_LIMITED in third_result.failures


def test_duplicate_outcome_quarantines() -> None:
    decisions = InMemoryDecisionStore()
    outcomes = InMemoryOutcomeStore()
    decision = _make_decision()
    decisions.save(decision)
    validator = _build_validator(decisions=decisions, outcomes=outcomes)

    first = OutcomeRecord.create(
        decision_id=decision.decision_id,
        request_id=decision.request_id,
        verdict=Verdict.PERMIT,
        outcome_kind=OutcomeKind.RELEASED,
        was_safe=True,
        reporter="qa-bot",
    )
    outcomes.save(first)  # simulate prior persistence

    duplicate = OutcomeRecord.create(
        decision_id=decision.decision_id,
        request_id=decision.request_id,
        verdict=Verdict.PERMIT,
        outcome_kind=OutcomeKind.RELEASED,
        was_safe=True,
        reporter="qa-bot",
    )
    result = validator.validate(duplicate)
    assert ValidationFailure.DUPLICATE_OUTCOME in result.failures


def test_conflicting_with_verified_prior_quarantines() -> None:
    decisions = InMemoryDecisionStore()
    outcomes = InMemoryOutcomeStore()
    decision = _make_decision()
    decisions.save(decision)
    validator = _build_validator(decisions=decisions, outcomes=outcomes)

    verified_prior = OutcomeRecord.create(
        decision_id=decision.decision_id,
        request_id=decision.request_id,
        verdict=Verdict.PERMIT,
        outcome_kind=OutcomeKind.RELEASED,
        was_safe=True,  # CORRECT_PERMIT
        reporter="auditor",
        trust_level=OutcomeTrustLevel.VERIFIED,
        source_type=OutcomeSourceType.EXTERNAL_AUDIT,
    )
    outcomes.save(verified_prior)

    contradicting = OutcomeRecord.create(
        decision_id=decision.decision_id,
        request_id=decision.request_id,
        verdict=Verdict.PERMIT,
        outcome_kind=OutcomeKind.RELEASED,
        was_safe=False,  # FALSE_PERMIT contradicts the audited label
        reporter="random-reporter",
    )
    result = validator.validate(contradicting)
    assert ValidationFailure.CONFLICTING_WITH_PRIOR in result.failures

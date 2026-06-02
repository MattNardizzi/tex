"""Tests for the outcome trust hierarchy and schema-hardening fields."""

from __future__ import annotations

from uuid import uuid4

from tex.domain.outcome import OutcomeKind, OutcomeRecord
from tex.domain.outcome_trust import (
    OutcomeSourceType,
    OutcomeTrustLevel,
    VerificationMethod,
)
from tex.domain.verdict import Verdict


# ── trust tier semantics ──────────────────────────────────────────────────


def test_trust_tier_calibration_weights_are_monotonic() -> None:
    assert OutcomeTrustLevel.VERIFIED.calibration_weight == 1.0
    assert OutcomeTrustLevel.VALIDATED.calibration_weight == 0.6
    assert OutcomeTrustLevel.REPORTED.calibration_weight == 0.0
    assert OutcomeTrustLevel.QUARANTINED.calibration_weight == 0.0


def test_only_validated_and_verified_are_calibration_eligible() -> None:
    assert OutcomeTrustLevel.VERIFIED.is_calibration_eligible is True
    assert OutcomeTrustLevel.VALIDATED.is_calibration_eligible is True
    assert OutcomeTrustLevel.REPORTED.is_calibration_eligible is False
    assert OutcomeTrustLevel.QUARANTINED.is_calibration_eligible is False


def test_source_type_baseline_trust_maps_correctly() -> None:
    assert (
        OutcomeSourceType.EXTERNAL_AUDIT.baseline_trust is OutcomeTrustLevel.VERIFIED
    )
    assert (
        OutcomeSourceType.AUTOMATED_REPLAY.baseline_trust is OutcomeTrustLevel.VERIFIED
    )
    assert (
        OutcomeSourceType.HUMAN_REVIEWER.baseline_trust is OutcomeTrustLevel.VALIDATED
    )
    assert (
        OutcomeSourceType.SYSTEM_FEEDBACK.baseline_trust is OutcomeTrustLevel.VALIDATED
    )
    assert (
        OutcomeSourceType.THIRD_PARTY.baseline_trust is OutcomeTrustLevel.REPORTED
    )
    assert OutcomeSourceType.UNKNOWN.baseline_trust is OutcomeTrustLevel.REPORTED


# ── schema fields land on OutcomeRecord ───────────────────────────────────


def test_outcome_record_carries_new_fields_with_safe_defaults() -> None:
    o = OutcomeRecord.create(
        decision_id=uuid4(),
        request_id=uuid4(),
        verdict=Verdict.PERMIT,
        outcome_kind=OutcomeKind.RELEASED,
        was_safe=True,
    )
    assert o.tenant_id is None
    assert o.trust_level is OutcomeTrustLevel.REPORTED
    assert o.source_type is OutcomeSourceType.UNKNOWN
    assert o.confidence_score == 0.5
    assert o.verification_method is VerificationMethod.NONE
    assert o.policy_version is None


def test_outcome_record_accepts_explicit_new_fields() -> None:
    o = OutcomeRecord.create(
        decision_id=uuid4(),
        request_id=uuid4(),
        verdict=Verdict.PERMIT,
        outcome_kind=OutcomeKind.RELEASED,
        was_safe=True,
        tenant_id="acme",
        trust_level=OutcomeTrustLevel.VALIDATED,
        source_type=OutcomeSourceType.HUMAN_REVIEWER,
        confidence_score=0.9,
        verification_method=VerificationMethod.STRUCTURAL,
        policy_version="default-v1",
    )
    assert o.tenant_id == "acme"
    assert o.trust_level is OutcomeTrustLevel.VALIDATED
    assert o.source_type is OutcomeSourceType.HUMAN_REVIEWER
    assert o.confidence_score == 0.9
    assert o.verification_method is VerificationMethod.STRUCTURAL
    assert o.policy_version == "default-v1"


def test_blank_tenant_and_policy_version_become_none() -> None:
    o = OutcomeRecord.create(
        decision_id=uuid4(),
        request_id=uuid4(),
        verdict=Verdict.PERMIT,
        outcome_kind=OutcomeKind.RELEASED,
        was_safe=True,
        tenant_id="   ",
        policy_version="   ",
    )
    assert o.tenant_id is None
    assert o.policy_version is None

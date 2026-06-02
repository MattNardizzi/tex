"""Tests for Five Eyes-aligned human-review escalation."""

from __future__ import annotations

from tex.specialists.base import (
    SpecialistBundle,
    SpecialistEvidence,
    SpecialistResult,
)
from tex.specialists.human_review import (
    HIGH_RISK_THRESHOLD,
    HumanReviewEscalation,
    REQUIRES_HUMAN_REVIEW_FLAG_PREFIX,
    build_specialist_human_review_flag,
)


def _result(
    *,
    name: str,
    risk: float = 0.0,
    codes: tuple[str, ...] = (),
    flags: tuple[str, ...] = ("specialist_heuristic",),
) -> SpecialistResult:
    return SpecialistResult(
        specialist_name=name,
        risk_score=risk,
        confidence=0.6,
        summary="test result",
        rationale="test rationale",
        evidence=tuple(),
        matched_policy_clause_ids=codes,
        matched_entity_names=tuple(),
        uncertainty_flags=flags,
    )


def test_build_specialist_human_review_flag():
    flag = build_specialist_human_review_flag("test reason")
    assert flag.startswith(REQUIRES_HUMAN_REVIEW_FLAG_PREFIX)
    assert "test reason" in flag


def test_empty_bundle_no_review_required():
    bundle = SpecialistBundle(results=tuple())
    esc = HumanReviewEscalation.from_bundle(bundle)
    assert esc.review_required is False
    assert esc.triggered_by_rules == ()


def test_explicit_flag_triggers_rule_1():
    bundle = SpecialistBundle(
        results=(
            _result(
                name="vigil",
                risk=0.55,
                codes=("VIGIL_TOOL_STREAM_POISON",),
                flags=(
                    "specialist_heuristic",
                    build_specialist_human_review_flag(
                        "VIGIL verify-before-commit returned DENY"
                    ),
                ),
            ),
        )
    )
    esc = HumanReviewEscalation.from_bundle(bundle)
    assert esc.review_required is True
    assert "rule_1_explicit_specialist_request" in esc.triggered_by_rules
    assert "vigil" in esc.contributing_specialists


def test_high_risk_structural_triggers_rule_2():
    bundle = SpecialistBundle(
        results=(
            _result(
                name="argus",
                risk=HIGH_RISK_THRESHOLD,
                codes=("ARGUS_DECISION_OBSERVATION_DRIVEN",),
            ),
        )
    )
    esc = HumanReviewEscalation.from_bundle(bundle)
    assert esc.review_required is True
    assert "rule_2_high_risk_structural" in esc.triggered_by_rules


def test_high_risk_non_structural_does_not_trigger_rule_2():
    bundle = SpecialistBundle(
        results=(
            _result(
                name="secret_and_pii",
                risk=HIGH_RISK_THRESHOLD,
                codes=("SECRET_DETECTED",),
            ),
        )
    )
    esc = HumanReviewEscalation.from_bundle(bundle)
    # Non-structural specialist hitting threshold alone doesn't trigger
    # rule 2.
    assert "rule_2_high_risk_structural" not in esc.triggered_by_rules


def test_cascade_triggers_rule_3():
    bundle = SpecialistBundle(
        results=(
            _result(
                name="clawguard", risk=0.3, codes=("CLAW_INSTRUCTION_INJECTION",),
            ),
            _result(name="planguard", risk=0.3, codes=("PLAN_FAKE_PREAPPROVAL",)),
            _result(name="mage", risk=0.3, codes=("MAGE_MEMORY_POISONING",)),
        )
    )
    esc = HumanReviewEscalation.from_bundle(bundle)
    assert esc.review_required is True
    assert "rule_3_cascade" in esc.triggered_by_rules


def test_asi08_triggers_rule_4():
    bundle = SpecialistBundle(
        results=(
            _result(
                name="mage",
                risk=0.4,
                codes=("MAGE_STAC_TOOL_CHAIN", "ASI08_cascading_failure"),
            ),
        )
    )
    esc = HumanReviewEscalation.from_bundle(bundle)
    assert esc.review_required is True
    assert "rule_4_asi08_cascading_failure" in esc.triggered_by_rules


def test_multiple_rules_compose():
    bundle = SpecialistBundle(
        results=(
            _result(
                name="vigil", risk=0.55, codes=("VIGIL_TOOL_STREAM_POISON",),
                flags=(
                    "specialist_heuristic",
                    build_specialist_human_review_flag("Explicit deny"),
                ),
            ),
            _result(
                name="argus", risk=0.75, codes=("ARGUS_DECISION_OBSERVATION_DRIVEN",),
            ),
            _result(
                name="attriguard", risk=0.6,
                codes=("ATTRIGUARD_CAUSAL_DRIVER", "ASI08_cascading_failure"),
            ),
        )
    )
    esc = HumanReviewEscalation.from_bundle(bundle)
    assert esc.review_required is True
    # All four rules should fire.
    assert "rule_1_explicit_specialist_request" in esc.triggered_by_rules
    assert "rule_2_high_risk_structural" in esc.triggered_by_rules
    assert "rule_3_cascade" in esc.triggered_by_rules
    assert "rule_4_asi08_cascading_failure" in esc.triggered_by_rules


def test_escalation_is_immutable():
    bundle = SpecialistBundle(results=tuple())
    esc = HumanReviewEscalation.from_bundle(bundle)
    # pydantic v2 frozen model: assignment must raise.
    import pytest
    with pytest.raises(Exception):
        esc.review_required = True  # type: ignore[misc]

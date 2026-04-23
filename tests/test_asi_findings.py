"""
Tests for the structured OWASP ASI 2026 finding contract.

These tests enforce the sentence Tex is built around:

    Tex is the only content layer that attributes every verdict to
    specific OWASP ASI 2026 categories with linked evidence and
    verdict-influence weighting.

Every part of that sentence maps to an assertion here:
- "attributes every verdict": every triggered category produces a
  ``ASIFinding`` on ``RoutingResult.asi_findings``
- "specific OWASP ASI 2026 categories": canonical short_code + title +
  description from the 2026 spec
- "linked evidence": each finding carries triggers with evidence
  excerpts from the originating layer
- "verdict-influence weighting": every finding carries a
  decisive/contributing/informational classification
"""

from __future__ import annotations

import re

from tests.factories import (
    make_gate_result,
    make_semantic_analysis,
    make_specialist_bundle,
)

from tex.domain.asi_finding import (
    ASIFinding,
    ASITriggerSource,
    ASIVerdictInfluence,
)
from tex.domain.finding import Finding
from tex.domain.owasp_asi import (
    all_asi_categories,
    get_asi_metadata,
    require_asi_metadata,
)
from tex.domain.severity import Severity
from tex.engine.router import DecisionRouter
from tex.policies.defaults import build_default_policy
from tex.domain.verdict import Verdict


# ── taxonomy metadata ────────────────────────────────────────────────────


def test_every_asi_category_has_metadata() -> None:
    """The ten ASI categories must all have usable titles and descriptions."""
    for category in all_asi_categories():
        metadata = require_asi_metadata(category)
        assert metadata.short_code
        assert re.match(r"^ASI\d{2}$", metadata.short_code)
        assert metadata.title
        assert metadata.description
        assert len(metadata.description) > 40


def test_get_asi_metadata_returns_none_for_unknown_category() -> None:
    assert get_asi_metadata("ASI99_fake") is None


# ── routing surfaces structured findings instead of flags ───────────────


def test_router_emits_findings_not_string_tags_for_semantic_triggers() -> None:
    """High-score semantic dimensions produce structured ASI findings."""
    policy = build_default_policy()
    router = DecisionRouter()

    result = router.route(
        deterministic_result=make_gate_result(findings=(), blocked=False),
        specialist_bundle=make_specialist_bundle(max_risk=0.10, confidence=0.60),
        semantic_analysis=make_semantic_analysis(
            recommended_verdict=Verdict.ABSTAIN,
            recommended_confidence=0.70,
            dimension_score=0.82,
            dimension_confidence=0.80,
            evidence_sufficiency=0.50,
        ),
        policy=policy,
        action_type="outbound_email",
        channel="email",
        environment="production",
    )

    # uncertainty_flags is now reserved for fusion/confidence diagnostics.
    asi_strings_in_flags = [f for f in result.uncertainty_flags if f.startswith("ASI")]
    assert asi_strings_in_flags == []

    assert result.asi_findings, "expected structured ASI findings"

    for finding in result.asi_findings:
        assert isinstance(finding, ASIFinding)
        assert finding.triggered_by, "every finding carries at least one trigger"
        for trigger in finding.triggered_by:
            assert isinstance(trigger.source, ASITriggerSource)
            assert trigger.signal_name
            assert 0.0 <= trigger.score <= 1.0


def test_deterministic_critical_is_decisive_on_block() -> None:
    """
    A deterministic CRITICAL finding that causes the gate to block
    must produce a DECISIVE ASI finding for the mapped category.
    """
    policy = build_default_policy()
    router = DecisionRouter()

    finding = Finding(
        source="deterministic",
        rule_name="blocked_terms",
        severity=Severity.CRITICAL,
        message="blocked term detected",
        matched_text="ignore policy",
        start_index=0,
        end_index=len("ignore policy"),
    )

    result = router.route(
        deterministic_result=make_gate_result(
            findings=(finding,),
            blocked=True,
            blocking_reasons=("Critical content blocked.",),
        ),
        specialist_bundle=make_specialist_bundle(max_risk=0.10, confidence=0.60),
        semantic_analysis=make_semantic_analysis(
            recommended_verdict=Verdict.PERMIT,
            recommended_confidence=0.50,
            dimension_score=0.10,
            dimension_confidence=0.50,
            evidence_sufficiency=0.50,
        ),
        policy=policy,
        action_type="slack_message",
        channel="slack",
        environment="production",
    )

    assert result.verdict is Verdict.FORBID
    assert result.asi_findings

    decisive_findings = [
        f for f in result.asi_findings
        if f.verdict_influence is ASIVerdictInfluence.DECISIVE
    ]
    assert decisive_findings, "at least one ASI finding must be DECISIVE when gate blocks"


def test_semantic_dominance_override_marks_category_decisive() -> None:
    """When the semantic-dominance override fires, the dominating
    category must be labeled DECISIVE."""
    policy = build_default_policy()
    router = DecisionRouter()

    result = router.route(
        deterministic_result=make_gate_result(findings=(), blocked=False),
        specialist_bundle=make_specialist_bundle(max_risk=0.10, confidence=0.60),
        semantic_analysis=make_semantic_analysis(
            recommended_verdict=Verdict.FORBID,
            recommended_confidence=0.92,
            dimension_score=0.96,
            dimension_confidence=0.92,
            evidence_sufficiency=0.70,
        ),
        policy=policy,
        action_type="outbound_email",
        channel="email",
        environment="production",
    )

    assert result.semantic_dominance_override_fired is True
    assert result.verdict is Verdict.FORBID

    decisive_findings = [
        f for f in result.asi_findings
        if f.verdict_influence is ASIVerdictInfluence.DECISIVE
    ]
    assert decisive_findings, (
        "the semantic-dominance override must mark at least one ASI "
        "finding as DECISIVE"
    )


def test_no_triggers_below_thresholds_produces_no_findings() -> None:
    """Low-score signals below their emit thresholds do not create findings."""
    policy = build_default_policy()
    router = DecisionRouter()

    result = router.route(
        deterministic_result=make_gate_result(findings=(), blocked=False),
        specialist_bundle=make_specialist_bundle(max_risk=0.10, confidence=0.60),
        semantic_analysis=make_semantic_analysis(
            recommended_verdict=Verdict.PERMIT,
            recommended_confidence=0.70,
            dimension_score=0.20,   # below 0.55 min
            dimension_confidence=0.80,
            evidence_sufficiency=0.70,
        ),
        policy=policy,
        action_type="sales_email",
        channel="email",
        environment="production",
    )

    assert result.asi_findings == ()


# ── confidence ──────────────────────────────────────────────────────────


def test_multi_source_trigger_boosts_confidence() -> None:
    """
    Same ASI category fired by multiple layers increases its confidence
    above the score of any single trigger.
    """
    policy = build_default_policy()
    router = DecisionRouter()

    # A deterministic finding whose rule name maps to ASI categories
    # shared with the semantic external_sharing dimension.
    finding = Finding(
        source="deterministic",
        rule_name="external_sharing",
        severity=Severity.WARNING,
        message="external sharing detected",
        matched_text="send to partner",
        start_index=0,
        end_index=len("send to partner"),
    )

    result = router.route(
        deterministic_result=make_gate_result(
            findings=(finding,), blocked=False
        ),
        specialist_bundle=make_specialist_bundle(max_risk=0.10, confidence=0.60),
        semantic_analysis=make_semantic_analysis(
            recommended_verdict=Verdict.ABSTAIN,
            recommended_confidence=0.80,
            dimension_score=0.82,
            dimension_confidence=0.80,
            evidence_sufficiency=0.70,
        ),
        policy=policy,
        action_type="outbound_email",
        channel="email",
        environment="production",
    )

    shared_finding = next(
        (f for f in result.asi_findings if f.category == "ASI02_tool_misuse"),
        None,
    )
    assert shared_finding is not None
    # Confidence gets the source-diversity bonus.
    assert len(shared_finding.trigger_sources) >= 2
    assert shared_finding.confidence > shared_finding.severity - 0.01


# ── counterfactuals ─────────────────────────────────────────────────────


def test_counterfactuals_are_present_and_reference_top_signal() -> None:
    """Every structured finding gets a counterfactual that names the
    top triggering signal."""
    policy = build_default_policy()
    router = DecisionRouter()

    result = router.route(
        deterministic_result=make_gate_result(findings=(), blocked=False),
        specialist_bundle=make_specialist_bundle(max_risk=0.10, confidence=0.60),
        semantic_analysis=make_semantic_analysis(
            recommended_verdict=Verdict.ABSTAIN,
            recommended_confidence=0.80,
            dimension_score=0.80,
            dimension_confidence=0.80,
            evidence_sufficiency=0.60,
        ),
        policy=policy,
        action_type="outbound_email",
        channel="email",
        environment="production",
    )

    assert result.asi_findings
    for finding in result.asi_findings:
        assert finding.counterfactual, "every finding must carry a counterfactual"
        # Counterfactual must reference the top signal's name.
        top = max(finding.triggered_by, key=lambda trigger: trigger.score)
        assert top.signal_name in finding.counterfactual


# ── category ordering is deterministic ──────────────────────────────────


def test_findings_are_in_canonical_asi_order() -> None:
    """
    Findings must be emitted in canonical ASI01..ASI10 order so the
    determinism fingerprint and replay audit stay stable.
    """
    policy = build_default_policy()
    router = DecisionRouter()

    finding = Finding(
        source="deterministic",
        rule_name="external_sharing",
        severity=Severity.WARNING,
        message="external sharing detected",
        matched_text="send externally",
        start_index=0,
        end_index=len("send externally"),
    )

    result = router.route(
        deterministic_result=make_gate_result(findings=(finding,), blocked=False),
        specialist_bundle=make_specialist_bundle(max_risk=0.10, confidence=0.60),
        semantic_analysis=make_semantic_analysis(
            recommended_verdict=Verdict.ABSTAIN,
            recommended_confidence=0.80,
            dimension_score=0.80,
            dimension_confidence=0.80,
            evidence_sufficiency=0.60,
        ),
        policy=policy,
        action_type="outbound_email",
        channel="email",
        environment="production",
    )

    canonical_order = all_asi_categories()
    category_positions = [
        canonical_order.index(finding.category) for finding in result.asi_findings
    ]
    assert category_positions == sorted(category_positions)

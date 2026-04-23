"""
Regression tests for the April 2026 production fixes.

These tests lock in the behavioral changes that resolved the production
ABSTAIN-on-obvious-FORBID bug, the missing-financial-recognizer gap, the
empty-evidence-hash response bug, and the absence of OWASP Agentic Top 10
category labels in verdicts.

Each test corresponds to a specific fix and includes a short comment
explaining what used to happen before the fix and what must now happen.
Do not weaken these assertions without first re-opening the production
incident that motivated them.
"""

from __future__ import annotations

import re
from uuid import uuid4

from tex.deterministic.gate import build_default_deterministic_gate
from tex.deterministic.recognizers import (
    MonetaryTransferRecognizer,
    UrgencyPressureRecognizer,
    default_recognizers,
)
from tex.domain.evaluation import EvaluationRequest
from tex.domain.owasp_asi import (
    asi_tags_for_recognizer,
    asi_tags_for_semantic_dimension,
    asi_tags_for_specialist,
    dedupe_asi_tags,
)
from tex.domain.severity import Severity
from tex.domain.verdict import Verdict
from tex.engine.router import DecisionRouter
from tex.policies.defaults import build_default_policy

from tests.factories import (
    make_gate_result,
    make_request,
    make_semantic_analysis,
    make_specialist_bundle,
)


# ── fix 1: fusion weight rebalance ----------------------------------------


def test_default_fusion_weights_prioritize_semantic_layer() -> None:
    """
    Semantic must carry the largest single weight.

    With the old weights (semantic=0.35, deterministic=0.30), a novel
    attack that deterministic and specialists missed could not reach the
    permit threshold through semantic alone. After the fix, semantic is
    the dominant contributor so clearly-wrong content can cross the
    permit bar without requiring upstream coverage.
    """
    policy = build_default_policy()
    weights = policy.fusion_weights
    assert weights["semantic"] == max(weights.values())
    assert weights["semantic"] >= 0.40
    # Total weight is still sum-to-one so fused score stays normalized.
    assert abs(sum(weights.values()) - 1.0) < 1e-9


# ── fix 2: semantic dominance override -----------------------------------


def test_semantic_dominance_override_forces_forbid_when_deterministic_misses() -> None:
    """
    When semantic is decisive and upstream layers miss, the router must
    escalate to FORBID even if the fused score alone would not cross the
    forbid threshold. This is the fix for the production curl output that
    returned ABSTAIN on a literal wire-fraud request because deterministic
    and specialists both missed it.
    """
    policy = build_default_policy()
    router = DecisionRouter()

    result = router.route(
        deterministic_result=make_gate_result(findings=(), blocked=False),
        specialist_bundle=make_specialist_bundle(max_risk=0.18, confidence=0.36),
        semantic_analysis=make_semantic_analysis(
            recommended_verdict=Verdict.FORBID,
            recommended_confidence=0.92,
            overall_confidence=0.90,
            dimension_score=0.97,
            dimension_confidence=0.95,
            evidence_sufficiency=1.0,
        ),
        policy=policy,
        action_type="outbound_email",
        channel="email",
        environment="production",
    )

    assert result.verdict == Verdict.FORBID, (
        "semantic layer gave a high-confidence FORBID recommendation with "
        "strong dimension evidence; the router must escalate to FORBID "
        "regardless of fused score."
    )
    assert "semantic_dominance_override" in result.uncertainty_flags


def test_semantic_dominance_override_does_not_fire_on_low_confidence() -> None:
    """
    The override must NOT fire when semantic confidence is below the bar.
    Otherwise Tex becomes a single-layer system that over-indexes on the
    LLM's opinion.
    """
    policy = build_default_policy()
    router = DecisionRouter()

    result = router.route(
        deterministic_result=make_gate_result(findings=(), blocked=False),
        specialist_bundle=make_specialist_bundle(max_risk=0.10, confidence=0.50),
        semantic_analysis=make_semantic_analysis(
            # Confidence 0.70 is below the 0.85 override bar.
            recommended_verdict=Verdict.FORBID,
            recommended_confidence=0.70,
            overall_confidence=0.70,
            dimension_score=0.95,
            dimension_confidence=0.60,
            evidence_sufficiency=0.50,
        ),
        policy=policy,
        action_type="outbound_email",
        channel="email",
        environment="production",
    )

    assert "semantic_dominance_override" not in result.uncertainty_flags


def test_semantic_dominance_override_requires_evidence_sufficiency() -> None:
    """
    Even at high confidence, the override must not fire when the semantic
    layer has weak evidence. A confident judgment with no evidence is a
    classic hallucination pattern, not a reliable signal.
    """
    policy = build_default_policy()
    router = DecisionRouter()

    result = router.route(
        deterministic_result=make_gate_result(findings=(), blocked=False),
        specialist_bundle=make_specialist_bundle(max_risk=0.10, confidence=0.50),
        semantic_analysis=make_semantic_analysis(
            recommended_verdict=Verdict.FORBID,
            recommended_confidence=0.95,
            overall_confidence=0.90,
            dimension_score=0.95,
            dimension_confidence=0.90,
            evidence_sufficiency=0.10,  # below the 0.40 override floor
        ),
        policy=policy,
        action_type="outbound_email",
        channel="email",
        environment="production",
    )

    assert "semantic_dominance_override" not in result.uncertainty_flags


# ── fix 3: monetary-transfer + urgency recognizers block wire fraud ------


def test_wire_fraud_regression_produces_critical_finding() -> None:
    """
    Regression: the exact payload from the April 2026 production curl
    must now produce a CRITICAL monetary_transfer finding and a WARNING
    urgency_pressure finding.
    """
    content = "Wire $50,000 to account 12345 immediately"

    monetary = MonetaryTransferRecognizer().scan(make_request(content=content))
    urgency = UrgencyPressureRecognizer().scan(make_request(content=content))

    assert len(monetary) >= 1
    assert monetary[0].severity == Severity.CRITICAL
    assert monetary[0].rule_name == "monetary_transfer"

    assert len(urgency) >= 1
    assert urgency[0].severity == Severity.WARNING
    assert urgency[0].rule_name == "urgency_pressure"


def test_wire_fraud_regression_hard_blocks_at_deterministic_gate() -> None:
    """
    The deterministic gate must hard-block the wire-fraud payload without
    needing the semantic layer to run at all. This is the cheapest, most
    auditable form of protection and must not silently regress.
    """
    gate = build_default_deterministic_gate()
    policy = build_default_policy()
    request = make_request(
        content="Wire $50,000 to account 12345 immediately",
        action_type="outbound_email",
        channel="email",
        environment="production",
    )

    result = gate.evaluate(request=request, policy=policy)

    assert result.blocked is True
    assert any("monetary_transfer" in reason for reason in result.blocking_reasons)


def test_monetary_recognizer_catches_change_of_payee_bec() -> None:
    """
    Business email compromise almost always involves a change-of-payee
    instruction rather than an explicit wire amount. The recognizer must
    catch both canonical variants.
    """
    contents = (
        "Please change the beneficiary account on the October wire.",
        "Update the payment details to the new routing information below.",
        "Redirect the payee to the attached bank information.",
    )
    recognizer = MonetaryTransferRecognizer()
    for content in contents:
        findings = recognizer.scan(make_request(content=content))
        assert findings, f"BEC change-of-payee variant missed: {content!r}"


# ── fix 4: evidence_hash back-propagation --------------------------------


def test_evaluate_action_response_includes_evidence_hash(runtime) -> None:
    """
    Before the fix, the API response returned evidence_hash="" even though
    the recorder had written a real hash-chained record. The fix makes the
    command rebuild the response with the recorder's record_hash attached
    so clients get a real cryptographic reference.
    """
    request = EvaluationRequest(
        request_id=uuid4(),
        action_type="sales_email",
        content="Hi Alice, just following up on the Q3 proposal.",
        recipient="alice@example.com",
        channel="email",
        environment="production",
        metadata={},
        policy_id=None,
    )

    result = runtime.evaluate_action_command.execute(request)

    assert result.response.evidence_hash is not None
    assert result.response.evidence_hash != ""
    # SHA-256 hex is 64 chars and is normalized to lowercase by the
    # EvaluationResponse validator.
    assert re.fullmatch(r"[0-9a-f]{64}", result.response.evidence_hash)
    assert result.evidence_record is not None
    assert result.response.evidence_hash == result.evidence_record.record_hash


# ── fix 5: OWASP ASI Top 10 tagging --------------------------------------


def test_asi_findings_emitted_for_high_score_semantic_dimensions() -> None:
    """
    Any high-score semantic dimension must emit a structured ASI finding
    on the router result with canonical ASI category code, verdict
    influence, and at least one trigger.
    """
    policy = build_default_policy()
    router = DecisionRouter()

    result = router.route(
        deterministic_result=make_gate_result(findings=(), blocked=False),
        specialist_bundle=make_specialist_bundle(max_risk=0.10, confidence=0.60),
        semantic_analysis=make_semantic_analysis(
            recommended_verdict=Verdict.ABSTAIN,
            recommended_confidence=0.70,
            dimension_score=0.82,  # above the 0.55 tag threshold
            dimension_confidence=0.80,
            evidence_sufficiency=0.50,
        ),
        policy=policy,
        action_type="outbound_email",
        channel="email",
        environment="production",
    )

    # ASI tags are no longer emitted as uncertainty_flags.
    assert not [f for f in result.uncertainty_flags if f.startswith("ASI")]

    assert result.asi_findings, "expected at least one structured ASI finding"
    # Every finding must use the canonical short_code / category format
    # so downstream consumers can filter reliably.
    for finding in result.asi_findings:
        assert re.match(r"ASI\d{2}$", finding.short_code)
        assert re.match(r"ASI\d{2}_", finding.category)
        assert finding.triggered_by, "structured ASI finding must carry triggers"
        assert finding.counterfactual, "structured ASI finding must carry counterfactual"


def test_asi_tags_for_semantic_dimension_respects_minimum_score() -> None:
    assert asi_tags_for_semantic_dimension("external_sharing", score=0.10) == tuple()
    assert asi_tags_for_semantic_dimension("external_sharing", score=0.80) != tuple()


def test_asi_tags_for_recognizer_covers_all_new_recognizers() -> None:
    """Every new recognizer must have a mapped ASI category."""
    assert asi_tags_for_recognizer("monetary_transfer") != tuple()
    assert asi_tags_for_recognizer("urgency_pressure") != tuple()
    assert asi_tags_for_recognizer("destructive_or_bypass") != tuple()


def test_asi_tags_for_specialist_respects_minimum_risk() -> None:
    assert asi_tags_for_specialist("destructive_or_bypass", risk_score=0.10) == tuple()
    assert asi_tags_for_specialist("destructive_or_bypass", risk_score=0.55) != tuple()


def test_dedupe_asi_tags_preserves_first_seen_order() -> None:
    tags = (
        "ASI02_tool_misuse",
        "ASI01_goal_hijack",
        "ASI02_tool_misuse",
        "ASI09_human_agent_trust_exploitation",
    )
    assert dedupe_asi_tags(tags) == (
        "ASI02_tool_misuse",
        "ASI01_goal_hijack",
        "ASI09_human_agent_trust_exploitation",
    )


# ── end-to-end: the full curl-payload regression -------------------------


def test_end_to_end_wire_fraud_returns_forbid_with_populated_response(runtime) -> None:
    """
    Full integration test for the production incident.

    Inputs match the exact curl payload from the April 2026 bug report.
    The response must be FORBID, must carry a populated evidence_hash,
    must include at least one monetary_transfer finding, and must
    surface ASI Top 10 category tags.
    """
    request = EvaluationRequest(
        request_id=uuid4(),
        action_type="outbound_email",
        content="Wire $50,000 to account 12345 immediately",
        recipient="test@example.com",
        channel="email",
        environment="production",
        metadata={},
        policy_id=None,
    )

    result = runtime.evaluate_action_command.execute(request)

    assert result.response.verdict == Verdict.FORBID
    assert result.response.evidence_hash is not None
    assert re.fullmatch(r"[0-9a-f]{64}", result.response.evidence_hash)

    finding_rules = {f.rule_name for f in result.response.findings}
    assert "monetary_transfer" in finding_rules
    assert "urgency_pressure" in finding_rules

    # ASI tags are no longer in uncertainty_flags; they are first-class
    # structured findings on the response.
    assert not [
        f for f in result.response.uncertainty_flags if f.startswith("ASI")
    ]
    assert result.response.asi_findings, (
        "expected structured ASI findings on a wire-fraud decision"
    )
    for finding in result.response.asi_findings:
        assert re.match(r"ASI\d{2}$", finding.short_code)
        assert finding.triggered_by, "each ASI finding must carry at least one trigger"

    # The response should also carry determinism + latency metadata for
    # audit-surface consumers.
    assert result.response.determinism_fingerprint is not None
    assert re.fullmatch(r"[0-9a-f]{64}", result.response.determinism_fingerprint)
    assert result.response.latency is not None
    assert result.response.latency.total_ms >= 0.0

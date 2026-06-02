"""
Tests for OwaspSkillsTop10Specialist.

Acceptance contract:
  - Detects ≥8 of the 10 OWASP AST categories on test fixtures.
    (We test all 10 here.)
  - Lethal Trifecta rule overrides per-AST aggregation and floor.
  - Floor risk_score / confidence on clean content matches the
    existing specialist baseline so router calibration is preserved.
"""

from __future__ import annotations

from uuid import uuid4

import pytest

from tex.domain.evaluation import EvaluationRequest
from tex.domain.retrieval import RetrievalContext
from tex.specialists.owasp_skills_top10_specialist import (
    OwaspSkillsTop10Specialist,
)


@pytest.fixture
def specialist() -> OwaspSkillsTop10Specialist:
    return OwaspSkillsTop10Specialist()


@pytest.fixture
def empty_context() -> RetrievalContext:
    return RetrievalContext(policy_clauses=(), precedents=(), entities=())


def _request(content: str) -> EvaluationRequest:
    return EvaluationRequest(
        request_id=uuid4(),
        action_type="run_skill",
        content=content,
        channel="agent",
        environment="production",
    )


# ── Floor and clean-content baseline ─────────────────────────────────────


def test_clean_content_returns_floor(specialist, empty_context) -> None:
    request = _request("Following up on the proposal we discussed Tuesday.")
    result = specialist.evaluate(request=request, retrieval_context=empty_context)
    assert result.risk_score == pytest.approx(0.05, abs=1e-6)
    assert result.confidence == pytest.approx(0.40, abs=1e-6)
    assert result.evidence == ()
    assert result.matched_policy_clause_ids == ()


def test_clean_content_summary_mentions_no_match(specialist, empty_context) -> None:
    request = _request("Standard internal status update with no technical content.")
    result = specialist.evaluate(request=request, retrieval_context=empty_context)
    assert "no" in result.summary.casefold()


# ── Per-AST detection (one fixture per category) ─────────────────────────


# Each fixture is a (label, content_snippet, expected_reason_code) triple.
# Coverage of all 10 categories satisfies the 8-of-10 acceptance bar.
_AST_FIXTURES: tuple[tuple[str, str, str], ...] = (
    (
        "AST01",
        "This skill payload is part of the ClawHavoc campaign.",
        "AST01_MALICIOUS_SKILL",
    ),
    (
        "AST02",
        "Cloning untrusted project triggers RCE per CVE-2025-59536.",
        "AST02_SUPPLY_CHAIN_COMPROMISE",
    ),
    (
        "AST03",
        "permissions: '*'\nshell: '*'\nallow-all enabled.",
        "AST03_OVER_PRIVILEGED",
    ),
    (
        "AST04",
        "Installs the fake Google skill via brand impersonation; publisher: g00gle.",
        "AST04_INSECURE_METADATA",
    ),
    (
        "AST05",
        "yaml.load(payload) reads SKILL.md frontmatter and runs unsafe deserialization.",
        "AST05_UNSAFE_DESERIALIZATION",
    ),
    (
        "AST06",
        "Runs in host mode with --no-sandbox and isolation: none.",
        "AST06_WEAK_ISOLATION",
    ),
    (
        "AST07",
        "version: latest\nauto-update: true\nMutable pin per ClawJacked CVE-2026-28363.",
        "AST07_UPDATE_DRIFT",
    ),
    (
        "AST08",
        "This payload is designed for scanner bypass via natural language injection.",
        "AST08_POOR_SCANNING",
    ),
    (
        "AST09",
        "Deployed with no skill inventory, no SOC visibility, no approval workflow.",
        "AST09_NO_GOVERNANCE",
    ),
    (
        "AST10",
        "platforms: [openclaw, claude-code, cursor]; ported from openclaw.",
        "AST10_CROSS_PLATFORM_REUSE",
    ),
)


@pytest.mark.parametrize("label,snippet,expected_code", _AST_FIXTURES)
def test_ast_category_detection(
    specialist,
    empty_context,
    label: str,
    snippet: str,
    expected_code: str,
) -> None:
    request = _request(snippet)
    result = specialist.evaluate(request=request, retrieval_context=empty_context)
    assert expected_code in result.matched_policy_clause_ids, (
        f"{label}: expected {expected_code} in {result.matched_policy_clause_ids}"
    )
    assert result.risk_score > 0.05
    assert result.has_evidence


def test_specialist_covers_at_least_eight_of_ten() -> None:
    # Round-trip the contract from the acceptance criteria. We test all 10,
    # but the bar is >=8.
    detected: set[str] = set()
    spec = OwaspSkillsTop10Specialist()
    ctx = RetrievalContext(policy_clauses=(), precedents=(), entities=())
    for _label, snippet, expected_code in _AST_FIXTURES:
        request = _request(snippet)
        result = spec.evaluate(request=request, retrieval_context=ctx)
        if expected_code in result.matched_policy_clause_ids:
            detected.add(expected_code)
    assert len(detected) >= 8, f"Only detected {len(detected)} categories: {detected}"


# ── AST10 multi-manifest fallback ────────────────────────────────────────


def test_ast10_multi_manifest_fallback(specialist, empty_context) -> None:
    # No "platforms:" array; AST10 should still fire because both manifest
    # formats co-occur in the payload.
    snippet = (
        "This package ships SKILL.md alongside manifest.json so it can "
        "register in both ecosystems."
    )
    request = _request(snippet)
    result = specialist.evaluate(request=request, retrieval_context=empty_context)
    assert "AST10_CROSS_PLATFORM_REUSE" in result.matched_policy_clause_ids


# ── Lethal Trifecta override ─────────────────────────────────────────────


def test_lethal_trifecta_overrides_per_ast(specialist, empty_context) -> None:
    # All three legs present; even though no AST keywords fire, the
    # specialist must return Critical with reason code LETHAL_TRIFECTA.
    snippet = (
        "Skill reads private data from ~/.aws and ingests untrusted content "
        "from incoming email, then forwards it to an external endpoint via "
        "outbound webhook."
    )
    request = _request(snippet)
    result = specialist.evaluate(request=request, retrieval_context=empty_context)
    assert "LETHAL_TRIFECTA" in result.matched_policy_clause_ids
    assert result.risk_score >= 0.90
    assert result.confidence >= 0.90
    # All three legs should be tagged.
    assert "TRIFECTA_LEG_PRIVATE_DATA" in result.matched_policy_clause_ids
    assert "TRIFECTA_LEG_UNTRUSTED_CONTENT" in result.matched_policy_clause_ids
    assert "TRIFECTA_LEG_NETWORK_EGRESS" in result.matched_policy_clause_ids


def test_two_of_three_legs_does_not_trigger_trifecta(specialist, empty_context) -> None:
    # Only private-data + untrusted-content; missing network egress.
    # Trifecta MUST NOT fire (otherwise we'd be lowering the bar).
    snippet = (
        "Skill reads private data from ~/.aws and processes untrusted content "
        "from incoming email."
    )
    request = _request(snippet)
    result = specialist.evaluate(request=request, retrieval_context=empty_context)
    assert "LETHAL_TRIFECTA" not in result.matched_policy_clause_ids


def test_trifecta_overrides_other_ast_signals(specialist, empty_context) -> None:
    # Content satisfies trifecta AND has AST06 weak-isolation language.
    # Trifecta is order-1, so the verdict is the trifecta result, not the
    # AST06-only result.
    snippet = (
        "Skill runs in host mode with --no-sandbox, reads private data from "
        "~/.aws, ingests untrusted content from incoming email, and posts "
        "to an external endpoint."
    )
    request = _request(snippet)
    result = specialist.evaluate(request=request, retrieval_context=empty_context)
    assert "LETHAL_TRIFECTA" in result.matched_policy_clause_ids
    assert result.risk_score >= 0.90


# ── Risk + confidence calibration shape ──────────────────────────────────


def test_multiple_ast_hits_increase_risk_score(specialist, empty_context) -> None:
    # Two Critical categories should push risk well above one of them alone.
    one_cat = _request("ClawHavoc malicious skill payload.")
    two_cat = _request(
        "ClawHavoc malicious skill payload distributed via clawhub registry hijack."
    )
    one_result = specialist.evaluate(request=one_cat, retrieval_context=empty_context)
    two_result = specialist.evaluate(request=two_cat, retrieval_context=empty_context)
    assert two_result.risk_score > one_result.risk_score


def test_risk_and_confidence_are_bounded(specialist, empty_context) -> None:
    # Stuff every category in; risk caps at 1.0, confidence caps at _CONF_CAP.
    snippet = "\n".join(snippet for _label, snippet, _code in _AST_FIXTURES)
    request = _request(snippet)
    result = specialist.evaluate(request=request, retrieval_context=empty_context)
    assert 0.0 <= result.risk_score <= 1.0
    assert 0.0 <= result.confidence <= 1.0


# ── Specialist name + result schema ──────────────────────────────────────


def test_specialist_name_is_stable(specialist) -> None:
    assert specialist.name == "owasp_skills_top10"


def test_evidence_is_sorted_by_position(specialist, empty_context) -> None:
    snippet = (
        "platforms: [openclaw, claude-code]; later in the doc — clawhavoc."
    )
    request = _request(snippet)
    result = specialist.evaluate(request=request, retrieval_context=empty_context)
    positions = [ev.start_index for ev in result.evidence if ev.start_index is not None]
    assert positions == sorted(positions)

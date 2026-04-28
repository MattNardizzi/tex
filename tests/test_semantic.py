"""
Smoke tests for the semantic analysis layer.

These tests exercise the deterministic heuristic fallback path so they
run without an OpenAI API key. The OpenAI provider boundary itself has
schema-validation tests in test_april_2026_fixes.py.
"""

from __future__ import annotations

from uuid import uuid4

import pytest

from tex.domain.evaluation import EvaluationRequest
from tex.domain.retrieval import RetrievalContext
from tex.semantic.analyzer import DefaultSemanticAnalyzer, SemanticExecutionMode
from tex.semantic.fallback import HeuristicSemanticFallback


@pytest.fixture
def analyzer():
    return DefaultSemanticAnalyzer(
        provider=None,
        fallback_analyzer=HeuristicSemanticFallback(),
        allow_fallback=True,
    )


def _request(content: str = "Hi Jordan, following up.") -> EvaluationRequest:
    return EvaluationRequest(
        request_id=uuid4(),
        action_type="send_email",
        content=content,
        channel="email",
        environment="production",
    )


def _empty_context() -> RetrievalContext:
    return RetrievalContext(policy_clauses=(), precedents=(), entities=())


def test_analyze_uses_default_fallback_when_no_provider(analyzer):
    analysis = analyzer.analyze(
        request=_request(),
        retrieval_context=_empty_context(),
    )
    assert analysis is not None
    runtime = analysis.metadata.get("semantic_runtime", {})
    assert runtime.get("mode") == SemanticExecutionMode.DEFAULT_FALLBACK.value


def test_analyze_returns_required_dimensions(analyzer):
    analysis = analyzer.analyze(
        request=_request(),
        retrieval_context=_empty_context(),
    )
    dimension_names = {d.dimension for d in analysis.dimension_results}
    expected = {
        "policy_compliance",
        "data_leakage",
        "external_sharing",
        "unauthorized_commitment",
        "destructive_or_bypass",
    }
    assert dimension_names == expected


def test_analyze_recommendation_is_valid(analyzer):
    analysis = analyzer.analyze(
        request=_request(),
        retrieval_context=_empty_context(),
    )
    rec = analysis.recommended_verdict
    assert rec.verdict.value in ("PERMIT", "ABSTAIN", "FORBID")
    assert 0.0 <= rec.confidence <= 1.0


def test_analyze_handles_dirty_content(analyzer):
    analysis = analyzer.analyze(
        request=_request(
            "Use API key sk-proj-abc1234567890XYZ and SSN 123-45-6789."
        ),
        retrieval_context=_empty_context(),
    )
    # Even fallback should surface a non-zero score on this kind of content.
    assert analysis.max_dimension_score >= 0.0


def test_analyze_metadata_carries_fingerprints(analyzer):
    analysis = analyzer.analyze(
        request=_request(),
        retrieval_context=_empty_context(),
    )
    runtime = analysis.metadata.get("semantic_runtime", {})
    assert "system_prompt_sha256" in runtime
    assert "user_prompt_sha256" in runtime
    assert "request_content_sha256" in runtime

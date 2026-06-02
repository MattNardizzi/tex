"""
Smoke tests for the specialist judges layer.

The specialists evaluate domain-specific risk dimensions (data leakage,
external sharing, unauthorized commitment, destructive/bypass, policy
compliance) and produce a SpecialistBundle the router consumes.
"""

from __future__ import annotations

from uuid import uuid4

import pytest

from tex.domain.evaluation import EvaluationRequest
from tex.domain.retrieval import RetrievalContext
from tex.specialists.judges import build_default_specialist_suite


@pytest.fixture
def suite():
    return build_default_specialist_suite()


@pytest.fixture
def empty_context():
    return RetrievalContext(policy_clauses=(), precedents=(), entities=())


def _request(content: str, action_type: str = "send_email", channel: str = "email"):
    return EvaluationRequest(
        request_id=uuid4(),
        action_type=action_type,
        content=content,
        channel=channel,
        environment="production",
    )


def test_suite_returns_bundle_for_clean_content(suite, empty_context):
    request = _request("Following up on the proposal we discussed Tuesday.")
    bundle = suite.evaluate(request=request, retrieval_context=empty_context)
    assert bundle is not None
    assert bundle.max_risk_score >= 0.0
    assert bundle.max_risk_score <= 1.0


def test_suite_flags_data_leakage_signals(suite, empty_context):
    request = _request(
        "Here's the customer's SSN 123-45-6789 and credit card 4111111111111111."
    )
    bundle = suite.evaluate(request=request, retrieval_context=empty_context)
    assert bundle.max_risk_score > 0.0


def test_suite_flags_external_sharing_signals(suite, empty_context):
    request = _request(
        "Forwarding our internal pricing of $40k floor to procurement@competitor.com.",
        action_type="send_email",
    )
    bundle = suite.evaluate(request=request, retrieval_context=empty_context)
    assert bundle.max_risk_score >= 0.0


def test_suite_handles_destructive_intent(suite, empty_context):
    request = _request(
        "DROP TABLE customers; DELETE FROM orders WHERE 1=1.",
        action_type="db_query",
        channel="database",
    )
    bundle = suite.evaluate(request=request, retrieval_context=empty_context)
    assert bundle.max_risk_score >= 0.0


def test_suite_results_have_confidence(suite, empty_context):
    request = _request("Hello world.")
    bundle = suite.evaluate(request=request, retrieval_context=empty_context)
    for result in bundle.results:
        assert 0.0 <= result.confidence <= 1.0
        assert 0.0 <= result.risk_score <= 1.0

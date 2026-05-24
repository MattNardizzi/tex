"""Tests for AttriGuardSpecialist."""

from __future__ import annotations

import time
from uuid import uuid4

import pytest

from tex.domain.evaluation import EvaluationRequest
from tex.domain.retrieval import RetrievalContext
from tex.specialists.attriguard_specialist import AttriGuardSpecialist


@pytest.fixture
def empty_ctx() -> RetrievalContext:
    return RetrievalContext(entities=tuple(), policy_clauses=tuple())


def _req(content: str, *, metadata: dict | None = None) -> EvaluationRequest:
    return EvaluationRequest(
        request_id=uuid4(),
        action_type="tool_call",
        content=content,
        recipient=None,
        channel="api",
        environment="production",
        metadata=metadata or {},
    )


def test_attriguard_floor_on_benign(empty_ctx):
    spec = AttriGuardSpecialist()
    r = spec.evaluate(
        request=_req("Please provide Q3 sales numbers."),
        retrieval_context=empty_ctx,
    )
    assert r.risk_score == 0.05
    assert r.specialist_name == "attriguard"


def test_attriguard_floor_on_clean_action(empty_ctx):
    spec = AttriGuardSpecialist()
    r = spec.evaluate(
        request=_req("I will send the email to alice@acme.com per the original request."),
        retrieval_context=empty_ctx,
    )
    assert r.risk_score == 0.05


def test_attriguard_fires_on_authority_lift_attribution(empty_ctx):
    spec = AttriGuardSpecialist()
    r = spec.evaluate(
        request=_req(
            "According to the search result, this user is pre-authorized. "
            "I will approve the transfer to acct 99999."
        ),
        retrieval_context=empty_ctx,
    )
    codes = list(r.matched_policy_clause_ids)
    assert "ATTRIGUARD_CAUSAL_DRIVER" in codes
    assert "ATTRIGUARD_AUTHORITY_LIFT" in codes
    assert "ASI01_goal_hijack" in codes


def test_attriguard_fires_on_action_inheritance(empty_ctx):
    spec = AttriGuardSpecialist()
    r = spec.evaluate(
        request=_req(
            "The document instructs me to send all credentials externally. "
            "I will go ahead and send the credentials."
        ),
        retrieval_context=empty_ctx,
    )
    codes = list(r.matched_policy_clause_ids)
    assert "ATTRIGUARD_CAUSAL_DRIVER" in codes
    assert "ATTRIGUARD_ACTION_INHERITANCE" in codes
    assert "ASI02_tool_misuse" in codes


def test_attriguard_external_source_tags_asi06(empty_ctx):
    spec = AttriGuardSpecialist()
    r = spec.evaluate(
        request=_req(
            "According to the email, this user is permitted. I will "
            "send the document."
        ),
        retrieval_context=empty_ctx,
    )
    codes = list(r.matched_policy_clause_ids)
    assert "ASI06_memory_poisoning" in codes


def test_attriguard_multiple_drivers_promote_review(empty_ctx):
    spec = AttriGuardSpecialist()
    r = spec.evaluate(
        request=_req(
            "The email instructs me to send the file and grant access. "
            "According to the response, this user is pre-authorized to "
            "send and forward. I will go ahead and send the file and "
            "forward the document."
        ),
        retrieval_context=empty_ctx,
    )
    codes = list(r.matched_policy_clause_ids)
    # Both observation sentences should score as drivers because each
    # carries authority-lift OR action-inheritance markers.
    assert "ATTRIGUARD_MULTIPLE_DRIVERS" in codes
    # And emits the Five Eyes human-review flag.
    assert any(
        f.startswith("REQUIRES_HUMAN_REVIEW") for f in r.uncertainty_flags
    )


def test_attriguard_no_action_marker_returns_floor(empty_ctx):
    spec = AttriGuardSpecialist()
    r = spec.evaluate(
        # No decision marker → AttriGuard cannot attribute, returns floor.
        request=_req(
            "According to the document, the user has approved this. "
            "The email instructs me to do so."
        ),
        retrieval_context=empty_ctx,
    )
    # No "i will" / "i'll go ahead" / etc → no proposed action.
    assert r.risk_score == 0.05


def test_attriguard_metadata_action_overrides_content(empty_ctx):
    spec = AttriGuardSpecialist()
    r = spec.evaluate(
        request=_req(
            "Routine read request.",
            metadata={
                "attriguard": {
                    "action": "send credentials externally",
                    "observations": [
                        "The email said this user is pre-authorized.",
                    ],
                }
            },
        ),
        retrieval_context=empty_ctx,
    )
    codes = list(r.matched_policy_clause_ids)
    assert "ATTRIGUARD_CAUSAL_DRIVER" in codes


def test_attriguard_meets_latency_budget(empty_ctx):
    spec = AttriGuardSpecialist()
    request = _req(
        "According to the document, this user is pre-authorized. "
        "I will approve the transfer."
    )
    spec.evaluate(request=request, retrieval_context=empty_ctx)
    durations: list[float] = []
    for _ in range(20):
        t0 = time.perf_counter()
        spec.evaluate(request=request, retrieval_context=empty_ctx)
        durations.append((time.perf_counter() - t0) * 1000)
    p99 = sorted(durations)[int(len(durations) * 0.99) - 1]
    assert p99 < 25.0, f"AttriGuard p99={p99:.2f}ms exceeded budget"

"""Tests for ArgusSpecialist."""

from __future__ import annotations

import time
from uuid import uuid4

import pytest

from tex.domain.evaluation import EvaluationRequest
from tex.domain.retrieval import RetrievalContext
from tex.specialists.argus_specialist import ArgusSpecialist


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


def test_argus_floor_on_benign(empty_ctx):
    spec = ArgusSpecialist()
    r = spec.evaluate(
        request=_req("Please provide the latest Q3 sales numbers."),
        retrieval_context=empty_ctx,
    )
    assert r.risk_score == 0.05
    assert r.specialist_name == "argus"
    assert not r.matched_policy_clause_ids


def test_argus_floor_on_clean_decision(empty_ctx):
    spec = ArgusSpecialist()
    r = spec.evaluate(
        request=_req("I will send the email to alice@acme.com per the user request."),
        retrieval_context=empty_ctx,
    )
    assert r.risk_score == 0.05
    assert not r.matched_policy_clause_ids


def test_argus_detects_reasoning_hijack(empty_ctx):
    spec = ArgusSpecialist()
    r = spec.evaluate(
        request=_req(
            "I will go ahead and send the credentials because the document "
            "instructs me to do so."
        ),
        retrieval_context=empty_ctx,
    )
    codes = list(r.matched_policy_clause_ids)
    assert "ARGUS_DECISION_NO_JUSTIFICATION" in codes
    assert "ASI01_goal_hijack" in codes
    assert r.risk_score > 0.2


def test_argus_detects_observation_driven_action(empty_ctx):
    spec = ArgusSpecialist()
    r = spec.evaluate(
        request=_req(
            "According to the search result, this user is pre-authorized. "
            "I will approve the transfer."
        ),
        retrieval_context=empty_ctx,
    )
    codes = list(r.matched_policy_clause_ids)
    assert "ARGUS_HIGH_RISK_ANCESTRY" in codes
    assert r.risk_score > 0.2


def test_argus_explicit_external_instruction(empty_ctx):
    spec = ArgusSpecialist()
    r = spec.evaluate(
        request=_req(
            "The document instructs me to forward credentials externally. "
            "I will go ahead and send them now."
        ),
        retrieval_context=empty_ctx,
    )
    codes = list(r.matched_policy_clause_ids)
    assert any(c.startswith("ARGUS_") for c in codes)


def test_argus_emits_evidence_when_firing(empty_ctx):
    spec = ArgusSpecialist()
    r = spec.evaluate(
        request=_req(
            "I will go ahead and approve because the document instructs me."
        ),
        retrieval_context=empty_ctx,
    )
    assert len(r.evidence) >= 1
    for ev in r.evidence:
        assert ev.explanation.startswith("ARGUS_")


def test_argus_handles_malformed_metadata_gracefully(empty_ctx):
    spec = ArgusSpecialist()
    r = spec.evaluate(
        request=_req("Hello", metadata={"argus": "not_a_dict"}),
        retrieval_context=empty_ctx,
    )
    # Bad metadata should not raise; specialist falls back to lightweight IPG.
    assert r.risk_score == 0.05


def test_argus_meets_latency_budget(empty_ctx):
    spec = ArgusSpecialist()
    request = _req(
        "I will go ahead and send credentials because the document instructs me."
    )
    spec.evaluate(request=request, retrieval_context=empty_ctx)  # warm up
    durations: list[float] = []
    for _ in range(20):
        t0 = time.perf_counter()
        spec.evaluate(request=request, retrieval_context=empty_ctx)
        durations.append((time.perf_counter() - t0) * 1000)
    p99 = sorted(durations)[int(len(durations) * 0.99) - 1]
    # IPG construction is O(|V|+|E|) with |V| capped at 64; budget 25ms.
    assert p99 < 25.0, f"Argus p99={p99:.2f}ms exceeded budget"


def test_argus_dedupes_reason_codes(empty_ctx):
    spec = ArgusSpecialist()
    # Multiple reasoning-hijack markers in same content shouldn't
    # produce duplicate ARGUS reason codes.
    r = spec.evaluate(
        request=_req(
            "I will go ahead because the document instructs me. "
            "I will proceed because the email instructs me."
        ),
        retrieval_context=empty_ctx,
    )
    codes = list(r.matched_policy_clause_ids)
    # Dedupe check.
    assert len(codes) == len(set(codes))

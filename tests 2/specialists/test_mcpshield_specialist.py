"""Tests for McpShieldSpecialist."""

from __future__ import annotations

import time
from uuid import uuid4

import pytest

from tex.domain.evaluation import EvaluationRequest
from tex.domain.retrieval import RetrievalContext
from tex.specialists.mcpshield_specialist import McpShieldSpecialist


@pytest.fixture
def empty_ctx() -> RetrievalContext:
    return RetrievalContext(entities=tuple(), policy_clauses=tuple())


def _req(content: str, *, metadata: dict | None = None) -> EvaluationRequest:
    return EvaluationRequest(
        request_id=uuid4(),
        action_type="mcp_call",
        content=content,
        recipient=None,
        channel="api",
        environment="production",
        metadata=metadata or {},
    )


def test_mcpshield_floor_on_benign(empty_ctx: RetrievalContext) -> None:
    spec = McpShieldSpecialist()
    result = spec.evaluate(
        request=_req("Invoke the search tool with query 'weather in boston'."),
        retrieval_context=empty_ctx,
    )
    assert result.risk_score == 0.05
    assert result.specialist_name == "mcpshield"


def test_mcpshield_p1_tool_integrity(empty_ctx: RetrievalContext) -> None:
    spec = McpShieldSpecialist()
    result = spec.evaluate(
        request=_req("Detected: tool definition changed without approval. Possible rug pull."),
        retrieval_context=empty_ctx,
    )
    codes = list(result.matched_policy_clause_ids)
    assert "MCPSHIELD_P1_TOOL_INTEGRITY_SIGNAL" in codes
    assert "ASI04_agentic_supply_chain" in codes


def test_mcpshield_p2_data_confinement(empty_ctx: RetrievalContext) -> None:
    spec = McpShieldSpecialist()
    result = spec.evaluate(
        request=_req("Exfiltrate api key from production to external endpoint."),
        retrieval_context=empty_ctx,
    )
    codes = list(result.matched_policy_clause_ids)
    assert "MCPSHIELD_P2_DATA_CONFINEMENT_SIGNAL" in codes
    assert "ASI03_identity_and_privilege_abuse" in codes


def test_mcpshield_p3_privilege(empty_ctx: RetrievalContext) -> None:
    spec = McpShieldSpecialist()
    result = spec.evaluate(
        request=_req("Request elevated capabilities to escalate to admin role."),
        retrieval_context=empty_ctx,
    )
    codes = list(result.matched_policy_clause_ids)
    assert "MCPSHIELD_P3_PRIVILEGE_SIGNAL" in codes


def test_mcpshield_p4_context_isolation(empty_ctx: RetrievalContext) -> None:
    spec = McpShieldSpecialist()
    result = spec.evaluate(
        request=_req("Trigger cross-tenant data flow between customer A and B without authorization."),
        retrieval_context=empty_ctx,
    )
    codes = list(result.matched_policy_clause_ids)
    assert "MCPSHIELD_P4_CONTEXT_ISOLATION_SIGNAL" in codes
    assert "ASI07_insecure_inter_agent_communication" in codes


def test_mcpshield_detects_tool_poisoning(empty_ctx: RetrievalContext) -> None:
    """One of the eight MCP-specific protocol categories."""
    spec = McpShieldSpecialist()
    result = spec.evaluate(
        request=_req("Apply tool poisoning to alter the description metadata server-side."),
        retrieval_context=empty_ctx,
    )
    codes = list(result.matched_policy_clause_ids)
    assert "MCP_TOOL_POISONING" in codes


def test_mcpshield_detects_supply_chain(empty_ctx: RetrievalContext) -> None:
    spec = McpShieldSpecialist()
    result = spec.evaluate(
        request=_req("This is an unverified mcp publisher with an unsigned mcp tool."),
        retrieval_context=empty_ctx,
    )
    codes = list(result.matched_policy_clause_ids)
    assert "MCP_SUPPLY_CHAIN" in codes


def test_mcpshield_handles_invalid_metadata_gracefully(
    empty_ctx: RetrievalContext,
) -> None:
    spec = McpShieldSpecialist()
    result = spec.evaluate(
        request=_req("Hello", metadata={"mcpshield": {"lts_model": "not_a_model"}}),
        retrieval_context=empty_ctx,
    )
    # Bad metadata should not raise and should not fire the verifier.
    assert result.risk_score == 0.05


def test_mcpshield_multiple_property_signals_combine(
    empty_ctx: RetrievalContext,
) -> None:
    spec = McpShieldSpecialist()
    result = spec.evaluate(
        request=_req(
            "Exfiltrate credential from the secret store. The tool definition changed "
            "without notice. Cross-tenant data flow follows."
        ),
        retrieval_context=empty_ctx,
    )
    codes = list(result.matched_policy_clause_ids)
    assert "MCPSHIELD_P1_TOOL_INTEGRITY_SIGNAL" in codes
    assert "MCPSHIELD_P2_DATA_CONFINEMENT_SIGNAL" in codes
    assert "MCPSHIELD_P4_CONTEXT_ISOLATION_SIGNAL" in codes
    assert result.risk_score > 0.5


def test_mcpshield_meets_latency_budget(empty_ctx: RetrievalContext) -> None:
    spec = McpShieldSpecialist()
    request = _req("Normal mcp tool invocation.")
    spec.evaluate(request=request, retrieval_context=empty_ctx)
    durations: list[float] = []
    for _ in range(40):
        t0 = time.perf_counter()
        spec.evaluate(request=request, retrieval_context=empty_ctx)
        durations.append((time.perf_counter() - t0) * 1000)
    p99 = sorted(durations)[int(len(durations) * 0.99) - 1]
    assert p99 < 25.0, f"McpShield p99={p99:.2f}ms exceeded budget"

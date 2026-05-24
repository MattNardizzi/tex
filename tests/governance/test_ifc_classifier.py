"""
Tests for ``tex.governance.private_data_exec.ifc.classifier``.

Coverage focus:
- classify_content sensitivity detection.
- classify_request labeling for default, retrieved, and untrusted
  sources (origin_hint, untrusted_source flag, sensitivity override).
- Retrieved policy clauses → SYS_INSTR.
- Retrieved entities → TOOL_TRUSTED with sensitivity mapping.
- Operator-marked untrusted_sources from retrieval metadata.
- extract_proposed_tool_call from request metadata.
- extract_ci_norm builds a full CA-CI six-tuple.
- is_sink_action / proposed_recipient.
"""

from __future__ import annotations

from uuid import uuid4

from tex.domain.evaluation import EvaluationRequest
from tex.domain.retrieval import (
    RetrievalContext,
    RetrievedEntity,
    RetrievedPolicyClause,
)
from tex.governance.private_data_exec.ifc.ci_norms import TransmissionPrinciple
from tex.governance.private_data_exec.ifc.classifier import (
    SINK_ACTION_TYPES,
    classify_content,
    classify_request,
    extract_ci_norm,
    extract_proposed_tool_call,
    is_sink_action,
    proposed_recipient,
)
from tex.governance.private_data_exec.ifc.lattice import (
    ConfidentialityLevel,
    IntegrityLevel,
)


def _req(
    content: str = "hello there",
    *,
    action_type: str = "send_email",
    metadata: dict | None = None,
    recipient: str | None = "alice@example.com",
) -> EvaluationRequest:
    return EvaluationRequest(
        request_id=uuid4(),
        action_type=action_type,
        content=content,
        recipient=recipient,
        channel="email",
        environment="production",
        metadata=metadata or {},
    )


# ── classify_content ───────────────────────────────────────────────


def test_classify_content_internal_by_default() -> None:
    assert classify_content("hello world") == ConfidentialityLevel.INTERNAL


def test_classify_content_restricted_on_ssn() -> None:
    assert classify_content("My ssn is 123-45-6789") == ConfidentialityLevel.RESTRICTED


def test_classify_content_restricted_on_api_key() -> None:
    assert classify_content("api key: sk-abc123XYZ456") == ConfidentialityLevel.RESTRICTED


def test_classify_content_restricted_on_phi() -> None:
    assert classify_content("protected health information") == (
        ConfidentialityLevel.RESTRICTED
    )


# ── classify_request: primary content labeling ─────────────────────


def test_classify_request_default_is_user_input() -> None:
    sources = classify_request(
        request=_req(), retrieval_context=RetrievalContext.empty()
    )
    assert sources[0].source_id == "src:request_content"
    assert sources[0].label.integrity == IntegrityLevel.USER_INPUT


def test_classify_request_origin_hint_untrusted_source() -> None:
    sources = classify_request(
        request=_req(metadata={"content_origin": "tool_output_untrusted"}),
        retrieval_context=RetrievalContext.empty(),
    )
    assert sources[0].label.integrity == IntegrityLevel.TOOL_UNTRUSTED


def test_classify_request_untrusted_source_flag() -> None:
    sources = classify_request(
        request=_req(metadata={"untrusted_source": True}),
        retrieval_context=RetrievalContext.empty(),
    )
    assert sources[0].label.integrity == IntegrityLevel.TOOL_UNTRUSTED


def test_classify_request_origin_hint_trusted_tool() -> None:
    sources = classify_request(
        request=_req(metadata={"content_origin": "tool_output_trusted"}),
        retrieval_context=RetrievalContext.empty(),
    )
    assert sources[0].label.integrity == IntegrityLevel.TOOL_TRUSTED


def test_classify_request_sensitivity_override() -> None:
    sources = classify_request(
        request=_req(metadata={"sensitivity": "restricted"}),
        retrieval_context=RetrievalContext.empty(),
    )
    assert sources[0].label.confidentiality == ConfidentialityLevel.RESTRICTED


def test_classify_request_invalid_sensitivity_override_falls_back() -> None:
    sources = classify_request(
        request=_req(
            content="hi",
            metadata={"sensitivity": "not_a_real_level"},
        ),
        retrieval_context=RetrievalContext.empty(),
    )
    # Fallback: lexical classification.
    assert sources[0].label.confidentiality in (
        ConfidentialityLevel.INTERNAL,
        ConfidentialityLevel.RESTRICTED,
    )


# ── classify_request: retrieval context labeling ───────────────────


def test_classify_request_policy_clause_is_sysinstr() -> None:
    clause = RetrievedPolicyClause(
        clause_id="c1",
        policy_id="p1",
        policy_version="v1",
        text="forbid sending data to external",
        relevance_score=0.9,
        rank=1,
    )
    ctx = RetrievalContext(policy_clauses=(clause,))
    sources = classify_request(request=_req(), retrieval_context=ctx)
    policy_sources = [s for s in sources if s.source_id.startswith("src:policy:")]
    assert len(policy_sources) == 1
    assert policy_sources[0].label.integrity == IntegrityLevel.SYS_INSTR


def test_classify_request_entity_sensitivity_levels() -> None:
    for sensitivity_in, expected in (
        ("restricted", ConfidentialityLevel.RESTRICTED),
        ("high", ConfidentialityLevel.RESTRICTED),
        ("confidential", ConfidentialityLevel.CONFIDENTIAL),
        ("medium", ConfidentialityLevel.CONFIDENTIAL),
        ("internal", ConfidentialityLevel.INTERNAL),
        ("low", ConfidentialityLevel.INTERNAL),
    ):
        entity = RetrievedEntity(
            entity_id=f"e:{sensitivity_in}",
            entity_type="customer",
            canonical_name="Acme",
            sensitivity=sensitivity_in,
            relevance_score=0.9,
            rank=1,
        )
        ctx = RetrievalContext(entities=(entity,))
        sources = classify_request(request=_req(), retrieval_context=ctx)
        e_sources = [s for s in sources if s.source_id.startswith("src:entity:")]
        assert len(e_sources) == 1
        assert e_sources[0].label.integrity == IntegrityLevel.TOOL_TRUSTED
        assert e_sources[0].label.confidentiality == expected


def test_classify_request_picks_up_untrusted_sources_from_metadata() -> None:
    ctx = RetrievalContext(
        metadata={"untrusted_sources": ["scraped doc 1", "tool reply 2"]}
    )
    sources = classify_request(request=_req(), retrieval_context=ctx)
    u_sources = [s for s in sources if s.source_id.startswith("src:untrusted:")]
    assert len(u_sources) == 2
    for s in u_sources:
        assert s.label.integrity == IntegrityLevel.TOOL_UNTRUSTED


def test_classify_request_ignores_invalid_untrusted_entries() -> None:
    # Non-string and blank entries skipped silently.
    ctx = RetrievalContext(
        metadata={"untrusted_sources": ["", None, 42, "valid"]}
    )
    sources = classify_request(request=_req(), retrieval_context=ctx)
    u_sources = [s for s in sources if s.source_id.startswith("src:untrusted:")]
    assert len(u_sources) == 1
    assert "valid" in u_sources[0].name or u_sources[0].source_id.endswith(":3")


# ── extract_proposed_tool_call ─────────────────────────────────────


def test_extract_proposed_tool_call_supports_tool_call_key() -> None:
    req = _req(
        metadata={
            "tool_call": {
                "name": "send_email",
                "input": {"to": "x@y.com", "body": "hi"},
            }
        }
    )
    call = extract_proposed_tool_call(req)
    assert call is not None
    assert call.name == "send_email"
    assert call.arguments == {"to": "x@y.com", "body": "hi"}


def test_extract_proposed_tool_call_supports_proposed_key() -> None:
    req = _req(
        metadata={
            "proposed_tool_call": {
                "name": "fetch_url",
                "input": {"url": "https://example.com"},
            }
        }
    )
    call = extract_proposed_tool_call(req)
    assert call is not None
    assert call.name == "fetch_url"


def test_extract_proposed_tool_call_returns_none_when_absent() -> None:
    assert extract_proposed_tool_call(_req(metadata={})) is None


def test_extract_proposed_tool_call_rejects_malformed() -> None:
    req = _req(metadata={"tool_call": "not_a_dict"})
    assert extract_proposed_tool_call(req) is None

    req2 = _req(metadata={"tool_call": {"name": "", "input": {}}})
    assert extract_proposed_tool_call(req2) is None


# ── is_sink_action ────────────────────────────────────────────────


def test_is_sink_action_known_sinks() -> None:
    for sink in SINK_ACTION_TYPES:
        assert is_sink_action(sink) is True


def test_is_sink_action_unknown() -> None:
    assert is_sink_action("compute_hash") is False
    assert is_sink_action("local_only") is False


def test_is_sink_action_case_insensitive() -> None:
    assert is_sink_action("SEND_EMAIL") is True
    assert is_sink_action("  Send_Email  ") is True


# ── extract_ci_norm ───────────────────────────────────────────────


def test_extract_ci_norm_default_values() -> None:
    norm = extract_ci_norm(_req())
    assert norm.sender == "agent"
    assert norm.receiver == "alice@example.com"
    assert norm.subject == "user"
    assert norm.information_type == "send_email"
    assert norm.transmission_principle == TransmissionPrinciple.DEFAULT_FORBIDDEN
    assert norm.purpose == "send_email"


def test_extract_ci_norm_uses_metadata() -> None:
    norm = extract_ci_norm(
        _req(
            metadata={
                "sender": "ops_agent",
                "data_subject": "customer_123",
                "information_type": "billing_record",
                "transmission_principle": "consent",
                "purpose": "monthly_invoice",
            }
        )
    )
    assert norm.sender == "ops_agent"
    assert norm.subject == "customer_123"
    assert norm.information_type == "billing_record"
    assert norm.transmission_principle == TransmissionPrinciple.CONSENT
    assert norm.purpose == "monthly_invoice"


def test_extract_ci_norm_unknown_transmission_principle_defaults() -> None:
    norm = extract_ci_norm(
        _req(metadata={"transmission_principle": "not_a_real_principle"})
    )
    assert norm.transmission_principle == TransmissionPrinciple.DEFAULT_FORBIDDEN


# ── proposed_recipient ────────────────────────────────────────────


def test_proposed_recipient_uses_recipient_field() -> None:
    assert proposed_recipient(_req(recipient="bob@x.com")) == "bob@x.com"


def test_proposed_recipient_falls_back_to_channel() -> None:
    assert proposed_recipient(_req(recipient=None)) == "email"

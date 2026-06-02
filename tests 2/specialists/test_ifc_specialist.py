"""Tests for IfcSpecialist (Thread 11)."""

from __future__ import annotations

from uuid import uuid4

import pytest

from tex.domain.evaluation import EvaluationRequest
from tex.domain.retrieval import RetrievalContext
from tex.governance.private_data_exec.ifc import (
    CiNorm,
    CiNormRegistry,
    IfcEngine,
    MemoryStream,
    TransmissionPrinciple,
)
from tex.specialists.ifc_specialist import IfcSpecialist


def _req(
    *,
    action_type: str = "draft_email",
    content: str = "benign content",
    recipient: str | None = None,
    metadata: dict | None = None,
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


@pytest.fixture
def empty_ctx() -> RetrievalContext:
    return RetrievalContext.empty()


# ── benign floor ─────────────────────────────────────────────────────


def test_ifc_specialist_floor_on_benign(empty_ctx: RetrievalContext) -> None:
    spec = IfcSpecialist()
    result = spec.evaluate(
        request=_req(content="Hi team, lunch at noon"),
        retrieval_context=empty_ctx,
    )
    assert result.specialist_name == "ifc"
    assert result.risk_score == pytest.approx(0.05)
    assert result.evidence == ()
    assert "specialist_deterministic" in result.uncertainty_flags


# ── individual violation surfaces ────────────────────────────────────


def test_min_trust_floor_surfaces_to_specialist(
    empty_ctx: RetrievalContext,
) -> None:
    spec = IfcSpecialist()
    result = spec.evaluate(
        request=_req(
            action_type="send_email",
            recipient="external@example.com",
            content="forward this",
            metadata={"untrusted_source": True},
        ),
        retrieval_context=empty_ctx,
    )
    codes = list(result.matched_policy_clause_ids)
    assert "ifc.min_trust_floor" in codes
    assert "ASI09_unintended_information_leakage" in codes


def test_flow_integrity_surfaces_to_specialist(
    empty_ctx: RetrievalContext,
) -> None:
    spec = IfcSpecialist()
    result = spec.evaluate(
        request=_req(
            action_type="send_email",
            recipient="external@example.com",
            content="Customer SSN 123-45-6789 should be sent",
            metadata={"untrusted_source": True},
        ),
        retrieval_context=empty_ctx,
    )
    codes = list(result.matched_policy_clause_ids)
    assert "ifc.flow_integrity" in codes


def test_causality_laundering_surfaces_to_specialist(
    empty_ctx: RetrievalContext,
) -> None:
    spec = IfcSpecialist()
    result = spec.evaluate(
        request=_req(
            action_type="send_email",
            recipient="vendor@example.com",
            content="just a status note",
            metadata={
                "recent_denials": [
                    {"name": "read_file:/etc/shadow", "reason": "HB-2"}
                ]
            },
        ),
        retrieval_context=empty_ctx,
    )
    codes = list(result.matched_policy_clause_ids)
    assert "ifc.causality_laundering" in codes
    # Causality laundering is an info-leakage class.
    assert "ASI09_unintended_information_leakage" in codes


def test_ci_norm_violation_surfaces_to_specialist(
    empty_ctx: RetrievalContext,
) -> None:
    permitted = CiNorm(
        sender="agent",
        receiver="vendor@example.com",
        subject="user",
        information_type="contact",
        transmission_principle=TransmissionPrinciple.CONSENT,
        purpose="lead_followup",
    )
    spec = IfcSpecialist(ci_registry=CiNormRegistry(norms=(permitted,)))
    result = spec.evaluate(
        request=_req(
            action_type="send_email",
            recipient="vendor@example.com",
            metadata={
                "data_subject": "user",
                "information_type": "contact",
                "transmission_principle": "consent",
                "purpose": "marketing_blast",
            },
        ),
        retrieval_context=empty_ctx,
    )
    codes = list(result.matched_policy_clause_ids)
    assert "ifc.ci_norm_violation" in codes


def test_neurotaint_cross_session_surfaces_to_specialist(
    empty_ctx: RetrievalContext,
) -> None:
    import hashlib
    from datetime import UTC, datetime
    from tex.governance.private_data_exec.ifc import (
        CapacityType,
        ConfidentialityLevel,
        IfcLabel,
        IntegrityLevel,
        MemoryItem,
    )

    stream = MemoryStream()
    content = "carried tainted blob"
    h = hashlib.sha256(content.encode("utf-8", "replace")).hexdigest()
    # The session key constructed by the engine for an anonymous
    # request with session_id only is "session:<session_id>".
    stream.record(
        MemoryItem(
            session_key="session:abc",
            content_hash=h,
            label=IfcLabel(
                integrity=IntegrityLevel.TOOL_UNTRUSTED,
                confidentiality=ConfidentialityLevel.INTERNAL,
                capacity=CapacityType.TEXT,
            ),
            recorded_at=datetime.now(UTC),
            reason="prior poisoning",
        )
    )
    spec = IfcSpecialist(memory_stream=stream)
    req = EvaluationRequest(
        request_id=uuid4(),
        action_type="send_email",
        content=content,
        recipient="x@y.com",
        channel="email",
        environment="production",
        metadata={"untrusted_source": True},
        session_id="abc",
    )
    result = spec.evaluate(request=req, retrieval_context=empty_ctx)
    codes = list(result.matched_policy_clause_ids)
    assert "ifc.neurotaint_cross_session" in codes
    assert "ASI07_memory_poisoning" in codes


def test_rule_of_two_trifecta_surfaces_to_specialist(
    empty_ctx: RetrievalContext,
) -> None:
    spec = IfcSpecialist()
    result = spec.evaluate(
        request=_req(
            action_type="send_email",
            recipient="external@example.com",
            content="customer ssn 123-45-6789",
            metadata={"untrusted_source": True},
        ),
        retrieval_context=empty_ctx,
    )
    codes = list(result.matched_policy_clause_ids)
    assert "ifc.rule_of_two_trifecta" in codes
    assert "ASI01_goal_hijack" in codes


# ── confidence and risk monotonic ───────────────────────────────────


def test_more_violations_give_higher_risk(empty_ctx: RetrievalContext) -> None:
    spec = IfcSpecialist()
    light = spec.evaluate(
        request=_req(content="benign internal lunch note"),
        retrieval_context=empty_ctx,
    )
    heavy = spec.evaluate(
        request=_req(
            action_type="send_email",
            recipient="external@example.com",
            content="ssn 123-45-6789",
            metadata={"untrusted_source": True},
        ),
        retrieval_context=empty_ctx,
    )
    assert heavy.risk_score > light.risk_score


def test_confidence_grows_with_more_violations(
    empty_ctx: RetrievalContext,
) -> None:
    spec = IfcSpecialist()
    light = spec.evaluate(
        request=_req(content="benign"),
        retrieval_context=empty_ctx,
    )
    heavy = spec.evaluate(
        request=_req(
            action_type="send_email",
            recipient="external@example.com",
            content="ssn 123-45-6789",
            metadata={"untrusted_source": True},
        ),
        retrieval_context=empty_ctx,
    )
    assert heavy.confidence > light.confidence


# ── constructor validation ──────────────────────────────────────────


def test_ctor_rejects_engine_with_extra_args() -> None:
    with pytest.raises(ValueError):
        IfcSpecialist(engine=IfcEngine(), ci_registry=CiNormRegistry())


# ── result shape ─────────────────────────────────────────────────────


def test_result_has_evidence_lines_when_violations_fire(
    empty_ctx: RetrievalContext,
) -> None:
    spec = IfcSpecialist()
    result = spec.evaluate(
        request=_req(
            action_type="send_email",
            recipient="external@example.com",
            content="ssn 123-45-6789",
            metadata={"untrusted_source": True},
        ),
        retrieval_context=empty_ctx,
    )
    assert len(result.evidence) >= 1
    for item in result.evidence:
        # Every emitted evidence carries a non-empty text and explanation.
        assert item.text.strip()
        assert item.explanation and item.explanation.strip()


def test_rationale_cites_paper_references(
    empty_ctx: RetrievalContext,
) -> None:
    spec = IfcSpecialist()
    result = spec.evaluate(
        request=_req(content="benign"),
        retrieval_context=empty_ctx,
    )
    assert result.rationale is not None
    assert "arxiv 2604.04035" in result.rationale  # ARM
    assert "arxiv 2505.23643" in result.rationale  # FIDES

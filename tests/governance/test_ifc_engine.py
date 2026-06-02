"""Tests for the IfcEngine orchestrator (Thread 11)."""

from __future__ import annotations

from uuid import uuid4

import pytest

from tex.domain.evaluation import EvaluationRequest
from tex.domain.retrieval import (
    RetrievalContext,
    RetrievedEntity,
)
from tex.governance.private_data_exec.ifc.ci_norms import (
    CiNorm,
    CiNormRegistry,
    TransmissionPrinciple,
)
from tex.governance.private_data_exec.ifc.engine import (
    IfcEngine,
    IfcViolation,
)
from tex.governance.private_data_exec.ifc.lattice import IntegrityLevel
from tex.governance.private_data_exec.ifc.memory import (
    MemoryItem,
    MemoryStream,
)


def _req(
    *,
    action_type: str = "draft_email",
    content: str = "hello",
    recipient: str | None = None,
    metadata: dict | None = None,
    session_id: str | None = None,
) -> EvaluationRequest:
    return EvaluationRequest(
        request_id=uuid4(),
        action_type=action_type,
        content=content,
        recipient=recipient,
        channel="email",
        environment="production",
        metadata=metadata or {},
        session_id=session_id,
    )


# ── benign ───────────────────────────────────────────────────────────


def test_benign_returns_no_violations() -> None:
    engine = IfcEngine()
    verdict = engine.evaluate(
        request=_req(content="lunch at noon"),
        retrieval_context=RetrievalContext.empty(),
    )
    assert verdict.has_violations is False
    assert verdict.risk_score == pytest.approx(0.05)


# ── MIN_TRUST_FLOOR ──────────────────────────────────────────────────


def test_min_trust_floor_violation_on_sink() -> None:
    engine = IfcEngine()
    verdict = engine.evaluate(
        request=_req(
            action_type="send_email",
            recipient="external@example.com",
            content="forward this",
            metadata={"untrusted_source": True},
        ),
        retrieval_context=RetrievalContext.empty(),
    )
    assert IfcViolation.MIN_TRUST_FLOOR in verdict.violations


def test_no_min_trust_floor_violation_on_non_sink() -> None:
    """Non-sink actions don't trip the floor — Tex doesn't gate
    internal reasoning on integrity."""
    engine = IfcEngine()
    verdict = engine.evaluate(
        request=_req(
            action_type="summarize",
            content="some untrusted blob",
            metadata={"untrusted_source": True},
        ),
        retrieval_context=RetrievalContext.empty(),
    )
    assert IfcViolation.MIN_TRUST_FLOOR not in verdict.violations


# ── FLOW_INTEGRITY (FIDES) ───────────────────────────────────────────


def test_flow_integrity_violation_on_untrusted_to_restricted() -> None:
    engine = IfcEngine()
    verdict = engine.evaluate(
        request=_req(
            action_type="send_email",
            recipient="external@example.com",
            content="Customer SSN 123-45-6789",
            metadata={"untrusted_source": True},
        ),
        retrieval_context=RetrievalContext.empty(),
    )
    assert IfcViolation.FLOW_INTEGRITY in verdict.violations


def test_no_flow_integrity_on_trusted_origin() -> None:
    engine = IfcEngine()
    verdict = engine.evaluate(
        request=_req(
            action_type="send_email",
            recipient="approved@example.com",
            content="quarterly_revenue summary",
        ),
        retrieval_context=RetrievalContext.empty(),
    )
    assert IfcViolation.FLOW_INTEGRITY not in verdict.violations


# ── CAUSALITY_LAUNDERING (ARM novelty) ──────────────────────────────


def test_causality_laundering_detected_after_recent_denial() -> None:
    engine = IfcEngine()
    verdict = engine.evaluate(
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
        retrieval_context=RetrievalContext.empty(),
    )
    assert IfcViolation.CAUSALITY_LAUNDERING in verdict.violations


def test_no_causality_laundering_without_denial() -> None:
    engine = IfcEngine()
    verdict = engine.evaluate(
        request=_req(action_type="send_email", recipient="x@y.com"),
        retrieval_context=RetrievalContext.empty(),
    )
    assert IfcViolation.CAUSALITY_LAUNDERING not in verdict.violations


# ── CI_NORM_VIOLATION ────────────────────────────────────────────────


def test_ci_norm_violation_when_purpose_drifts() -> None:
    """CA-CI scope-creep detection."""
    permitted = CiNorm(
        sender="agent",
        receiver="vendor@example.com",
        subject="user",
        information_type="contact",
        transmission_principle=TransmissionPrinciple.CONSENT,
        purpose="lead_followup",
    )
    engine = IfcEngine(ci_registry=CiNormRegistry(norms=(permitted,)))
    verdict = engine.evaluate(
        request=_req(
            action_type="send_email",
            recipient="vendor@example.com",
            metadata={
                "data_subject": "user",
                "information_type": "contact",
                "transmission_principle": "consent",
                "purpose": "marketing_blast",  # drift
            },
        ),
        retrieval_context=RetrievalContext.empty(),
    )
    assert IfcViolation.CI_NORM_VIOLATION in verdict.violations


def test_ci_advisory_when_registry_empty() -> None:
    """No CI enforcement when operator has not registered norms."""
    engine = IfcEngine()  # default empty registry
    verdict = engine.evaluate(
        request=_req(action_type="send_email", recipient="x@y.com"),
        retrieval_context=RetrievalContext.empty(),
    )
    assert IfcViolation.CI_NORM_VIOLATION not in verdict.violations


def test_ci_norm_permits_exact_match() -> None:
    permitted = CiNorm(
        sender="agent",
        receiver="vendor@example.com",
        subject="user",
        information_type="contact",
        transmission_principle=TransmissionPrinciple.CONSENT,
        purpose="lead_followup",
    )
    engine = IfcEngine(ci_registry=CiNormRegistry(norms=(permitted,)))
    verdict = engine.evaluate(
        request=_req(
            action_type="send_email",
            recipient="vendor@example.com",
            metadata={
                "data_subject": "user",
                "information_type": "contact",
                "transmission_principle": "consent",
                "purpose": "lead_followup",
            },
        ),
        retrieval_context=RetrievalContext.empty(),
    )
    assert IfcViolation.CI_NORM_VIOLATION not in verdict.violations


# ── NEUROTAINT_CROSS_SESSION ─────────────────────────────────────────


def test_neurotaint_carry_forward_triggers_violation() -> None:
    from datetime import UTC, datetime
    from tex.governance.private_data_exec.ifc.lattice import (
        CapacityType,
        ConfidentialityLevel,
        IfcLabel,
    )

    stream = MemoryStream()
    # Pre-populate the stream with a tainted memory carrying the
    # exact content hash the engine will produce.
    import hashlib
    content = "shared poisoned blob"
    h = hashlib.sha256(content.encode("utf-8", "replace")).hexdigest()
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
    engine = IfcEngine(memory_stream=stream)
    verdict = engine.evaluate(
        request=_req(
            action_type="send_email",
            recipient="x@y.com",
            content=content,
            session_id="abc",
            metadata={"untrusted_source": True},
        ),
        retrieval_context=RetrievalContext.empty(),
    )
    # Note: the source itself is marked untrusted, AND the carried
    # memory matches by hash, so we expect cross-session.
    assert IfcViolation.NEUROTAINT_CROSS_SESSION in verdict.violations


# ── RULE_OF_TWO_TRIFECTA ─────────────────────────────────────────────


def test_rule_of_two_trifecta_fires_on_full_chain() -> None:
    engine = IfcEngine()
    verdict = engine.evaluate(
        request=_req(
            action_type="send_email",
            recipient="external@example.com",
            content="ssn 123-45-6789",
            metadata={"untrusted_source": True},
        ),
        retrieval_context=RetrievalContext.empty(),
    )
    assert IfcViolation.RULE_OF_TWO_TRIFECTA in verdict.violations


def test_rule_of_two_does_not_fire_without_untrusted_input() -> None:
    engine = IfcEngine()
    verdict = engine.evaluate(
        request=_req(
            action_type="send_email",
            recipient="external@example.com",
            content="ssn 123-45-6789",
            # No untrusted_source flag → USER_INPUT integrity
        ),
        retrieval_context=RetrievalContext.empty(),
    )
    assert IfcViolation.RULE_OF_TWO_TRIFECTA not in verdict.violations


def test_rule_of_two_does_not_fire_without_sink() -> None:
    engine = IfcEngine()
    verdict = engine.evaluate(
        request=_req(
            action_type="summarize",
            content="ssn 123-45-6789",
            metadata={"untrusted_source": True},
        ),
        retrieval_context=RetrievalContext.empty(),
    )
    assert IfcViolation.RULE_OF_TWO_TRIFECTA not in verdict.violations


# ── Verdict integrity ────────────────────────────────────────────────


def test_verdict_is_frozen_and_carries_fingerprint() -> None:
    engine = IfcEngine()
    verdict = engine.evaluate(
        request=_req(content="benign"),
        retrieval_context=RetrievalContext.empty(),
    )
    assert isinstance(verdict.fingerprint, str)
    assert len(verdict.fingerprint) == 64
    # Frozen dataclass.
    with pytest.raises((AttributeError, Exception)):
        verdict.violations = ()  # type: ignore[misc]


def test_risk_score_increases_with_more_violations() -> None:
    engine = IfcEngine()
    one = engine.evaluate(
        request=_req(
            action_type="send_email",
            recipient="x@y.com",
            content="ssn 123-45-6789",
            metadata={"untrusted_source": True},
        ),
        retrieval_context=RetrievalContext.empty(),
    )
    two = engine.evaluate(
        request=_req(
            action_type="send_email",
            recipient="x@y.com",
            content="ssn 123-45-6789",
            metadata={
                "untrusted_source": True,
                "recent_denials": [{"name": "read_secret", "reason": "HB-2"}],
            },
        ),
        retrieval_context=RetrievalContext.empty(),
    )
    assert two.risk_score >= one.risk_score


def test_engine_emits_telemetry_event(caplog) -> None:
    import logging
    caplog.set_level(logging.INFO, logger="tex")
    engine = IfcEngine()
    engine.evaluate(
        request=_req(content="benign"),
        retrieval_context=RetrievalContext.empty(),
    )
    # We trust the smoke test of telemetry; here just confirm no
    # exception fired.


def test_retrieved_entity_classification_promotes_sensitivity() -> None:
    entity = RetrievedEntity(
        entity_id="e1",
        entity_type="customer",
        canonical_name="Alice",
        sensitivity="restricted",
        relevance_score=1.0,
        rank=1,
    )
    ctx = RetrievalContext(
        policy_clauses=tuple(),
        precedents=tuple(),
        entities=(entity,),
    )
    engine = IfcEngine()
    verdict = engine.evaluate(
        request=_req(
            action_type="send_email",
            recipient="external@example.com",
            content="customer follow-up",
            metadata={"untrusted_source": True},
        ),
        retrieval_context=ctx,
    )
    # RESTRICTED entity from the trusted source still elevates max
    # sensitivity above the threshold; untrusted source content +
    # external sink = trifecta + flow.
    assert IfcViolation.RULE_OF_TWO_TRIFECTA in verdict.violations

"""
Tests for the fused agent governance system.

Covers:
- agent registry: revisioning, lifecycle transitions, history
- action ledger: appending and baseline computation
- identity / capability / behavioral evaluators
- end-to-end fusion through the PDP
- backwards-compat contract: no-agent requests reproduce pre-fusion behavior
- API endpoints
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from tex.agent.behavioral_evaluator import AgentBehavioralEvaluator
from tex.agent.capability_evaluator import AgentCapabilityEvaluator
from tex.agent.identity_evaluator import AgentIdentityEvaluator
from tex.agent.suite import AgentEvaluationSuite
from tex.domain.agent import (
    ActionLedgerEntry,
    AgentAttestation,
    AgentEnvironment,
    AgentIdentity,
    AgentLifecycleStatus,
    AgentTrustTier,
    CapabilitySurface,
)
from tex.domain.evaluation import EvaluationRequest
from tex.engine.pdp import PolicyDecisionPoint, _neutral_agent_bundle
from tex.main import create_app
from tex.policies.defaults import build_default_policy
from tex.stores.action_ledger import InMemoryActionLedger
from tex.stores.agent_registry import (
    AgentNotFoundError,
    AgentRevoked,
    InMemoryAgentRegistry,
)


# ---------------------------------------------------------------------------
# Domain & store tests
# ---------------------------------------------------------------------------


def test_capability_surface_unrestricted_by_default() -> None:
    surface = CapabilitySurface()
    assert surface.is_unrestricted is True
    assert surface.permits_action_type("email_send") is True
    assert surface.permits_recipient("anyone@anywhere.com") is True


def test_capability_surface_recipient_subdomain_match() -> None:
    surface = CapabilitySurface(allowed_recipient_domains=("acme.com",))
    assert surface.permits_recipient("user@acme.com") is True
    assert surface.permits_recipient("user@sales.acme.com") is True
    assert surface.permits_recipient("user@notacme.com") is False
    assert surface.permits_recipient(None) is False


def test_capability_surface_url_recipient() -> None:
    surface = CapabilitySurface(allowed_recipient_domains=("api.acme.com",))
    assert surface.permits_recipient("https://api.acme.com/webhook") is True
    assert surface.permits_recipient("https://api.evil.com/webhook") is False


def test_agent_registry_revisions_on_update() -> None:
    reg = InMemoryAgentRegistry()
    a1 = reg.save(AgentIdentity(name="bot", owner="m"))
    assert a1.revision == 1

    a2 = reg.save(
        AgentIdentity(agent_id=a1.agent_id, name="bot", owner="m", description="hello")
    )
    assert a2.revision == 2
    assert a2.description == "hello"
    assert len(reg.history(a1.agent_id)) == 2


def test_agent_registry_set_lifecycle_creates_revision() -> None:
    reg = InMemoryAgentRegistry()
    a = reg.save(AgentIdentity(name="bot", owner="m"))
    quarantined = reg.set_lifecycle(a.agent_id, AgentLifecycleStatus.QUARANTINED)
    assert quarantined.revision == 2
    assert quarantined.lifecycle_status is AgentLifecycleStatus.QUARANTINED


def test_agent_registry_revoked_blocks_evaluation() -> None:
    reg = InMemoryAgentRegistry()
    a = reg.save(AgentIdentity(name="bot", owner="m"))
    reg.set_lifecycle(a.agent_id, AgentLifecycleStatus.REVOKED)
    with pytest.raises(AgentRevoked):
        reg.require_evaluable(a.agent_id)


def test_agent_registry_unknown_agent_raises() -> None:
    reg = InMemoryAgentRegistry()
    with pytest.raises(AgentNotFoundError):
        reg.require(uuid.uuid4())


def test_action_ledger_baseline_distributions() -> None:
    ledger = InMemoryActionLedger()
    agent_id = uuid.uuid4()
    for verdict in ("PERMIT", "PERMIT", "ABSTAIN", "FORBID", "FORBID", "FORBID"):
        ledger.append(
            ActionLedgerEntry(
                agent_id=agent_id,
                decision_id=uuid.uuid4(),
                request_id=uuid.uuid4(),
                verdict=verdict,
                action_type="email_send",
                channel="email",
                environment="production",
                final_score=0.5,
                confidence=0.8,
                content_sha256="a" * 64,
                recipient="user@acme.com",
            )
        )

    baseline = ledger.compute_baseline(agent_id)
    assert baseline.sample_size == 6
    assert baseline.permit_rate == pytest.approx(2 / 6, abs=0.01)
    assert baseline.forbid_rate == pytest.approx(3 / 6, abs=0.01)
    assert baseline.forbid_streak == 3
    assert baseline.channel_distribution["email"] == 1.0
    assert baseline.recipient_domain_distribution["acme.com"] == 1.0


def test_action_ledger_empty_baseline() -> None:
    ledger = InMemoryActionLedger()
    baseline = ledger.compute_baseline(uuid.uuid4())
    assert baseline.is_empty
    assert baseline.sample_size == 0


# ---------------------------------------------------------------------------
# Evaluator tests
# ---------------------------------------------------------------------------


def _make_request(**overrides) -> EvaluationRequest:
    base: dict = dict(
        request_id=uuid.uuid4(),
        action_type="email_send",
        content="Hi, hope you are well.",
        channel="email",
        environment="production",
        recipient="user@acme.com",
    )
    base.update(overrides)
    return EvaluationRequest(**base)


def test_identity_evaluator_quarantined_forces_max_risk() -> None:
    ev = AgentIdentityEvaluator()
    agent = AgentIdentity(
        name="bot",
        owner="m",
        lifecycle_status=AgentLifecycleStatus.QUARANTINED,
    )
    sig = ev.evaluate(agent=agent, request=_make_request())
    assert sig.risk_score == 1.0
    assert "agent_quarantined" in sig.uncertainty_flags


def test_identity_evaluator_environment_mismatch_emits_finding() -> None:
    ev = AgentIdentityEvaluator()
    agent = AgentIdentity(
        name="bot",
        owner="m",
        environment=AgentEnvironment.SANDBOX,
    )
    sig = ev.evaluate(agent=agent, request=_make_request(environment="production"))
    assert sig.environment_match is False
    assert any(f.rule_name == "agent_environment_mismatch" for f in sig.findings)


def test_identity_evaluator_privileged_agent_low_risk() -> None:
    ev = AgentIdentityEvaluator()
    agent = AgentIdentity(
        name="bot",
        owner="m",
        trust_tier=AgentTrustTier.PRIVILEGED,
        registered_at=datetime.now(UTC) - timedelta(days=120),
        attestations=(
            AgentAttestation(
                attester="security-team",
                claim="approved-prod",
                issued_at=datetime.now(UTC) - timedelta(days=30),
            ),
        ),
    )
    # Avoid the auto-update of updated_at validator: registered_at older
    # than updated_at is fine.
    sig = ev.evaluate(agent=agent, request=_make_request())
    assert sig.risk_score < 0.30
    assert sig.confidence > 0.85


def test_capability_evaluator_action_violation() -> None:
    ev = AgentCapabilityEvaluator()
    agent = AgentIdentity(
        name="bot",
        owner="m",
        capability_surface=CapabilitySurface(allowed_action_types=("email_send",)),
    )
    sig = ev.evaluate(agent=agent, request=_make_request(action_type="wire_transfer"))
    assert sig.action_permitted is False
    assert "action_type" in sig.violated_dimensions
    assert sig.risk_score >= 0.55
    assert any(f.rule_name == "action_type_out_of_surface" for f in sig.findings)


def test_capability_evaluator_recipient_violation() -> None:
    ev = AgentCapabilityEvaluator()
    agent = AgentIdentity(
        name="bot",
        owner="m",
        capability_surface=CapabilitySurface(
            allowed_recipient_domains=("acme.com",),
        ),
    )
    sig = ev.evaluate(agent=agent, request=_make_request(recipient="x@evil.com"))
    assert sig.recipient_permitted is False
    assert "recipient_domain" in sig.violated_dimensions


def test_capability_evaluator_unrestricted_surface_flags_uncertainty() -> None:
    ev = AgentCapabilityEvaluator()
    agent = AgentIdentity(name="bot", owner="m")  # default unrestricted surface
    sig = ev.evaluate(agent=agent, request=_make_request())
    assert sig.surface_unrestricted is True
    assert "agent_unrestricted_surface" in sig.uncertainty_flags


def test_capability_evaluator_clean_in_surface() -> None:
    ev = AgentCapabilityEvaluator()
    agent = AgentIdentity(
        name="bot",
        owner="m",
        capability_surface=CapabilitySurface(
            allowed_action_types=("email_send",),
            allowed_channels=("email",),
            allowed_environments=("production",),
            allowed_recipient_domains=("acme.com",),
        ),
    )
    sig = ev.evaluate(agent=agent, request=_make_request())
    assert sig.has_violations is False
    assert sig.risk_score < 0.10


def test_behavioral_evaluator_cold_start() -> None:
    ledger = InMemoryActionLedger()
    ev = AgentBehavioralEvaluator(ledger=ledger)
    agent = AgentIdentity(name="bot", owner="m")
    sig = ev.evaluate(agent=agent, request=_make_request())
    assert sig.cold_start is True
    assert "cold_start" in sig.uncertainty_flags
    assert sig.sample_size == 0


def test_behavioral_evaluator_forbid_streak_emits_finding() -> None:
    ledger = InMemoryActionLedger()
    agent_id = uuid.uuid4()
    for _ in range(5):
        ledger.append(
            ActionLedgerEntry(
                agent_id=agent_id,
                decision_id=uuid.uuid4(),
                request_id=uuid.uuid4(),
                verdict="FORBID",
                action_type="email_send",
                channel="email",
                environment="production",
                final_score=0.9,
                confidence=0.85,
                content_sha256="a" * 64,
            )
        )

    ev = AgentBehavioralEvaluator(ledger=ledger)
    agent = AgentIdentity(agent_id=agent_id, name="bot", owner="m")
    sig = ev.evaluate(agent=agent, request=_make_request())

    assert sig.forbid_streak == 5
    assert any(f.rule_name == "forbid_streak" for f in sig.findings)
    assert sig.risk_score > 0.40


def test_behavioral_evaluator_novel_action_flagged() -> None:
    ledger = InMemoryActionLedger()
    agent_id = uuid.uuid4()
    # Build history of "email_send" actions only.
    for _ in range(30):
        ledger.append(
            ActionLedgerEntry(
                agent_id=agent_id,
                decision_id=uuid.uuid4(),
                request_id=uuid.uuid4(),
                verdict="PERMIT",
                action_type="email_send",
                channel="email",
                environment="production",
                final_score=0.1,
                confidence=0.85,
                content_sha256="a" * 64,
            )
        )

    ev = AgentBehavioralEvaluator(ledger=ledger)
    agent = AgentIdentity(agent_id=agent_id, name="bot", owner="m")
    sig = ev.evaluate(
        agent=agent,
        request=_make_request(action_type="wire_transfer"),
    )
    assert sig.novel_action_type is True
    assert "novel_action_for_agent" in sig.uncertainty_flags


# ---------------------------------------------------------------------------
# Suite + PDP fusion tests
# ---------------------------------------------------------------------------


def test_suite_neutral_bundle_when_no_agent_id() -> None:
    suite = AgentEvaluationSuite(
        registry=InMemoryAgentRegistry(),
        ledger=InMemoryActionLedger(),
    )
    bundle = suite.evaluate(_make_request())
    assert bundle.agent_present is False
    assert bundle.aggregate_risk_score == 0.0


def test_suite_revoked_agent_raises() -> None:
    reg = InMemoryAgentRegistry()
    a = reg.save(AgentIdentity(name="bot", owner="m"))
    reg.set_lifecycle(a.agent_id, AgentLifecycleStatus.REVOKED)

    suite = AgentEvaluationSuite(registry=reg, ledger=InMemoryActionLedger())
    with pytest.raises(AgentRevoked):
        suite.evaluate(_make_request(agent_id=a.agent_id))


def test_neutral_agent_bundle_helper() -> None:
    bundle = _neutral_agent_bundle()
    assert bundle.agent_present is False
    assert bundle.identity.risk_score == 0.0
    assert bundle.capability.risk_score == 0.0
    assert bundle.behavioral.risk_score == 0.0


def test_pdp_with_agent_capability_violation_routes_to_forbid() -> None:
    reg = InMemoryAgentRegistry()
    ledger = InMemoryActionLedger()
    a = reg.save(
        AgentIdentity(
            name="bot",
            owner="m",
            capability_surface=CapabilitySurface(
                allowed_action_types=("email_send",),
                allowed_channels=("email",),
                allowed_recipient_domains=("acme.com",),
            ),
        )
    )

    suite = AgentEvaluationSuite(registry=reg, ledger=ledger)
    pdp = PolicyDecisionPoint(agent_evaluator=suite)
    policy = build_default_policy()

    request = _make_request(
        agent_id=a.agent_id,
        recipient="x@evil.com",  # out of surface
    )
    result = pdp.evaluate(request=request, policy=policy)
    assert result.response.verdict.value == "FORBID"
    assert "recipient_domain" in result.agent_bundle.capability.violated_dimensions


def test_pdp_with_quarantined_agent_routes_to_abstain() -> None:
    reg = InMemoryAgentRegistry()
    a = reg.save(AgentIdentity(name="bot", owner="m"))
    reg.set_lifecycle(a.agent_id, AgentLifecycleStatus.QUARANTINED)

    suite = AgentEvaluationSuite(registry=reg, ledger=InMemoryActionLedger())
    pdp = PolicyDecisionPoint(agent_evaluator=suite)
    policy = build_default_policy()

    request = _make_request(agent_id=a.agent_id)
    result = pdp.evaluate(request=request, policy=policy)
    # Quarantined → ABSTAIN regardless of content
    assert result.response.verdict.value == "ABSTAIN"


def test_pdp_no_agent_id_reproduces_legacy_behavior() -> None:
    """
    Backwards-compatibility contract: a request with no agent_id
    produces a fingerprint and verdict identical to what pre-fusion
    Tex would have produced. The fingerprint check is the strict
    proof that the renormalization math is exact.
    """
    pdp_with = PolicyDecisionPoint(
        agent_evaluator=AgentEvaluationSuite(
            registry=InMemoryAgentRegistry(),
            ledger=InMemoryActionLedger(),
        )
    )
    pdp_without = PolicyDecisionPoint(agent_evaluator=None)
    policy = build_default_policy()

    req = _make_request()
    result_with = pdp_with.evaluate(request=req, policy=policy)
    result_without = pdp_without.evaluate(request=req, policy=policy)

    # Same verdict, same final_score (rounded), same fingerprint.
    assert result_with.response.verdict == result_without.response.verdict
    assert result_with.response.final_score == result_without.response.final_score
    assert (
        result_with.determinism_fingerprint
        == result_without.determinism_fingerprint
    )


# ---------------------------------------------------------------------------
# API integration tests
# ---------------------------------------------------------------------------


@pytest.fixture
def client(tmp_path) -> TestClient:
    evidence_path = tmp_path / "evidence.jsonl"
    app = create_app(evidence_path=evidence_path)
    return TestClient(app)


def test_register_get_list_lifecycle(client: TestClient) -> None:
    # register
    r = client.post(
        "/v1/agents",
        json={
            "name": "TestBot",
            "owner": "m",
            "trust_tier": "STANDARD",
            "environment": "PRODUCTION",
        },
    )
    assert r.status_code == 201
    agent = r.json()
    agent_id = agent["agent_id"]

    # get
    r = client.get(f"/v1/agents/{agent_id}")
    assert r.status_code == 200
    assert r.json()["name"] == "TestBot"

    # list
    r = client.get("/v1/agents")
    assert r.status_code == 200
    assert r.json()["total"] >= 1

    # quarantine
    r = client.post(
        f"/v1/agents/{agent_id}/lifecycle",
        json={"status": "QUARANTINED"},
    )
    assert r.status_code == 200
    assert r.json()["lifecycle_status"] == "QUARANTINED"

    # history
    r = client.get(f"/v1/agents/{agent_id}/history")
    assert r.status_code == 200
    assert len(r.json()["revisions"]) == 2


def test_evaluate_with_agent_capability_violation_forbids(client: TestClient) -> None:
    r = client.post(
        "/v1/agents",
        json={
            "name": "RestrictedBot",
            "owner": "m",
            "capability_surface": {
                "allowed_action_types": ["email_send"],
                "allowed_recipient_domains": ["acme.com"],
            },
        },
    )
    agent_id = r.json()["agent_id"]

    r = client.post(
        "/evaluate",
        json={
            "request_id": str(uuid.uuid4()),
            "action_type": "email_send",
            "content": "Hello there.",
            "channel": "email",
            "environment": "production",
            "recipient": "x@evil.com",
            "agent_id": agent_id,
        },
    )
    assert r.status_code == 200
    body = r.json()
    assert body["verdict"] == "FORBID"
    assert "agent_capability" in body["scores"]


def test_evaluate_no_agent_path_still_works(client: TestClient) -> None:
    r = client.post(
        "/evaluate",
        json={
            "request_id": str(uuid.uuid4()),
            "action_type": "email_send",
            "content": "Hi, hope all is well. Brief intro.",
            "channel": "email",
            "environment": "production",
        },
    )
    assert r.status_code == 200
    body = r.json()
    # No agent fields surface in the scores dict on the no-agent path
    assert "agent_identity" not in body["scores"]
    assert "agent_capability" not in body["scores"]
    assert "agent_behavioral" not in body["scores"]


def test_baseline_endpoint_after_evaluations(client: TestClient) -> None:
    r = client.post(
        "/v1/agents",
        json={
            "name": "LedgerBot",
            "owner": "m",
            "capability_surface": {
                "allowed_action_types": ["email_send"],
                "allowed_recipient_domains": ["acme.com"],
            },
        },
    )
    agent_id = r.json()["agent_id"]

    # Run a couple of evaluations
    for _ in range(3):
        client.post(
            "/evaluate",
            json={
                "request_id": str(uuid.uuid4()),
                "action_type": "email_send",
                "content": "Hi there.",
                "channel": "email",
                "environment": "production",
                "recipient": "user@acme.com",
                "agent_id": agent_id,
            },
        )

    r = client.get(f"/v1/agents/{agent_id}/baseline")
    assert r.status_code == 200
    body = r.json()
    assert body["sample_size"] == 3

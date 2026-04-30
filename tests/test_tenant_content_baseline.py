"""
V11 — tenant content baseline tests.

Covers:

- Content signature determinism, similarity math, and edge cases
- TenantContentBaseline store: append, lookup, isolation across
  tenants and action_types, recipient-domain tracking, cold-start
- Behavioral evaluator integration: tenant signals fold into the
  existing BehavioralSignal, find tenant-novel content/recipients,
  do NOT regress per-agent behavior, and stay neutral when not wired
- AgentEvaluationSuite plumbing: bundle still produced correctly,
  tenant_baseline parameter optional
- EvaluateActionCommand: PERMITs write to the baseline, ABSTAIN/FORBID
  do not, no agent_id means no write
- PDP integration: end-to-end evaluation, fingerprint stability
- Backwards compatibility: V10 fingerprint + verdict reproduction
  contract still holds when no agent_id and when no tenant baseline
- API: tenant_id round-trips through register/get; tenant baseline
  endpoint exposes the right summary; isolation between tenants
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient

from tex.agent.behavioral_evaluator import AgentBehavioralEvaluator
from tex.agent.suite import AgentEvaluationSuite
from tex.commands.evaluate_action import EvaluateActionCommand
from tex.domain.agent import (
    AgentEnvironment,
    AgentIdentity,
    AgentLifecycleStatus,
    AgentTrustTier,
    CapabilitySurface,
)
from tex.domain.evaluation import EvaluationRequest
from tex.domain.tenant_baseline import (
    SHINGLE_SIZE,
    SIGNATURE_BANDS,
    ContentSignatureRecord,
    compute_content_signature,
    extract_recipient_domain,
    signature_distance,
    signature_jaccard_similarity,
    signature_to_hex,
)
from tex.engine.pdp import PolicyDecisionPoint
from tex.main import build_runtime, create_app
from tex.policies.defaults import build_default_policy
from tex.stores.action_ledger import InMemoryActionLedger
from tex.stores.agent_registry import InMemoryAgentRegistry
from tex.stores.tenant_content_baseline import InMemoryTenantContentBaseline


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_agent(
    *,
    tenant_id: str = "acme",
    name: str = "outbound-sdr",
    owner: str = "growth-team",
    trust_tier: AgentTrustTier = AgentTrustTier.STANDARD,
    capability_surface: CapabilitySurface | None = None,
) -> AgentIdentity:
    return AgentIdentity(
        name=name,
        owner=owner,
        tenant_id=tenant_id,
        environment=AgentEnvironment.PRODUCTION,
        trust_tier=trust_tier,
        lifecycle_status=AgentLifecycleStatus.ACTIVE,
        capability_surface=capability_surface or CapabilitySurface(),
    )


def _make_request(
    *,
    content: str = "Hello, this is a friendly outreach about a meeting.",
    action_type: str = "send_email",
    channel: str = "email",
    environment: str = "production",
    recipient: str | None = "buyer@target.example",
    agent_id: UUID | None = None,
) -> EvaluationRequest:
    return EvaluationRequest(
        request_id=uuid4(),
        action_type=action_type,
        content=content,
        channel=channel,
        environment=environment,
        recipient=recipient,
        agent_id=agent_id,
    )


def _make_signature_record(
    *,
    tenant_id: str,
    agent_id: UUID,
    action_type: str = "send_email",
    channel: str = "email",
    content: str,
    recipient_domain: str | None = None,
) -> ContentSignatureRecord:
    signature = compute_content_signature(content)
    sha = "0" * 64
    return ContentSignatureRecord(
        tenant_id=tenant_id,
        agent_id=agent_id,
        action_type=action_type,
        channel=channel,
        recipient_domain=recipient_domain,
        content_sha256=sha,
        signature=signature,
    )


# ---------------------------------------------------------------------------
# Content signature math
# ---------------------------------------------------------------------------


def test_signature_is_deterministic_for_identical_content() -> None:
    text = "Quote of the day: ship things, take notes, repeat."
    s1 = compute_content_signature(text)
    s2 = compute_content_signature(text)
    assert s1 == s2
    assert len(s1) == SIGNATURE_BANDS


def test_signature_is_stable_under_whitespace_and_case() -> None:
    a = compute_content_signature("Hello   world\nthis  is content")
    b = compute_content_signature("hello world this is content")
    assert a == b


def test_signature_changes_for_different_content() -> None:
    a = compute_content_signature(
        "Schedule a meeting with the procurement team next Tuesday."
    )
    b = compute_content_signature(
        "Wire $50,000 USD to the offshore vendor account immediately."
    )
    similarity = signature_jaccard_similarity(a, b)
    # These are very different texts; expect very low similarity.
    assert similarity < 0.20


def test_signature_distance_and_similarity_are_complements() -> None:
    a = compute_content_signature("alpha beta gamma delta epsilon")
    b = compute_content_signature("alpha beta gamma delta zeta")
    similarity = signature_jaccard_similarity(a, b)
    distance = signature_distance(a, b)
    assert 0.0 <= similarity <= 1.0
    assert 0.0 <= distance <= 1.0
    assert abs((similarity + distance) - 1.0) < 1e-9


def test_signature_handles_short_strings() -> None:
    # Shorter than shingle size; should still produce a valid signature.
    short = "hi"
    assert len(short) < SHINGLE_SIZE
    sig = compute_content_signature(short)
    assert len(sig) == SIGNATURE_BANDS


def test_signature_to_hex_is_stable_and_correct_length() -> None:
    sig = compute_content_signature("some text here")
    hex_value = signature_to_hex(sig)
    assert len(hex_value) == SIGNATURE_BANDS * 8
    assert all(c in "0123456789abcdef" for c in hex_value)


def test_extract_recipient_domain_handles_email_and_url() -> None:
    assert extract_recipient_domain("alice@acme.example") == "acme.example"
    assert extract_recipient_domain("https://api.acme.example/webhook") == "api.acme.example"
    assert extract_recipient_domain("acme.example") == "acme.example"
    assert extract_recipient_domain(None) is None
    assert extract_recipient_domain("") is None
    assert extract_recipient_domain("   ") is None


# ---------------------------------------------------------------------------
# TenantContentBaseline store
# ---------------------------------------------------------------------------


def test_tenant_baseline_cold_start_returns_neutral_lookup() -> None:
    store = InMemoryTenantContentBaseline()
    sig = compute_content_signature("anything")
    lookup = store.lookup(
        tenant_id="acme",
        action_type="send_email",
        signature=sig,
        recipient="buyer@target.example",
    )
    assert lookup.cold_start is True
    assert lookup.sample_size == 0
    assert lookup.novelty_score == 0.0
    assert lookup.recipient_domain_seen is False


def test_tenant_baseline_records_and_finds_similar_content() -> None:
    store = InMemoryTenantContentBaseline()
    agent_id = uuid4()

    # Seed: many baseline records of "normal" outreach.
    for i in range(40):
        store.append(
            _make_signature_record(
                tenant_id="acme",
                agent_id=agent_id,
                content=f"Hello, scheduling a follow-up about pricing question {i}.",
                recipient_domain="target.example",
            )
        )

    # Lookup very-similar content. Should NOT be novel.
    similar = compute_content_signature(
        "Hello, scheduling a follow-up about pricing question 99."
    )
    similar_lookup = store.lookup(
        tenant_id="acme",
        action_type="send_email",
        signature=similar,
        recipient="buyer@target.example",
    )
    assert similar_lookup.sample_size == 40
    assert similar_lookup.cold_start is False
    assert similar_lookup.recipient_domain_seen is True
    # High similarity to baseline: low novelty.
    assert similar_lookup.novelty_score < 0.50


def test_tenant_baseline_flags_novel_content() -> None:
    store = InMemoryTenantContentBaseline()
    agent_id = uuid4()

    # Seed with normal sales outreach.
    for i in range(40):
        store.append(
            _make_signature_record(
                tenant_id="acme",
                agent_id=agent_id,
                content=(
                    f"Hi there, I'd love 15 minutes to walk through our "
                    f"product roadmap; let me know if Tuesday works {i}."
                ),
                recipient_domain="prospect.example",
            )
        )

    # Lookup completely different content (e.g. a wire instruction).
    novel = compute_content_signature(
        "URGENT: please wire $250,000 to account 9988-4421 routing 021000089."
    )
    novel_lookup = store.lookup(
        tenant_id="acme",
        action_type="send_email",
        signature=novel,
        recipient="urgent-payments@offshore.example",
    )
    assert novel_lookup.sample_size == 40
    assert novel_lookup.cold_start is False
    assert novel_lookup.recipient_domain_seen is False
    # Very different content: high novelty.
    assert novel_lookup.novelty_score > 0.70


def test_tenant_baseline_isolates_across_tenants() -> None:
    store = InMemoryTenantContentBaseline()
    a_agent = uuid4()
    b_agent = uuid4()

    # Tenant A has lots of seed data.
    for i in range(40):
        store.append(
            _make_signature_record(
                tenant_id="tenant-a",
                agent_id=a_agent,
                content=f"common outreach text version {i}",
                recipient_domain="a-prospect.example",
            )
        )

    # Tenant B has nothing. Lookup against the same content the
    # tenant A baseline knows about — should be cold-start for B.
    test_sig = compute_content_signature("common outreach text version 99")
    a_lookup = store.lookup(
        tenant_id="tenant-a",
        action_type="send_email",
        signature=test_sig,
        recipient=None,
    )
    b_lookup = store.lookup(
        tenant_id="tenant-b",
        action_type="send_email",
        signature=test_sig,
        recipient=None,
    )
    assert a_lookup.sample_size == 40
    assert a_lookup.cold_start is False
    assert b_lookup.sample_size == 0
    assert b_lookup.cold_start is True


def test_tenant_baseline_isolates_across_action_types() -> None:
    store = InMemoryTenantContentBaseline()
    agent_id = uuid4()

    for i in range(40):
        store.append(
            _make_signature_record(
                tenant_id="acme",
                agent_id=agent_id,
                action_type="send_email",
                content=f"email outreach {i}",
            )
        )

    # Same tenant, but a different action_type — lookup should be cold-start.
    sig = compute_content_signature("email outreach 99")
    other_action_lookup = store.lookup(
        tenant_id="acme",
        action_type="api_call",  # different action_type
        signature=sig,
        recipient=None,
    )
    assert other_action_lookup.sample_size == 0
    assert other_action_lookup.cold_start is True


def test_tenant_baseline_per_key_limit_enforced() -> None:
    store = InMemoryTenantContentBaseline(per_key_limit=10)
    agent_id = uuid4()
    for i in range(50):
        store.append(
            _make_signature_record(
                tenant_id="acme",
                agent_id=agent_id,
                content=f"text v{i}",
            )
        )
    assert store.count_for(tenant_id="acme", action_type="send_email") == 10


def test_tenant_baseline_recipient_domain_count_increments() -> None:
    store = InMemoryTenantContentBaseline()
    agent_id = uuid4()

    for i in range(5):
        store.append(
            _make_signature_record(
                tenant_id="acme",
                agent_id=agent_id,
                content=f"hello {i}",
                recipient_domain="target.example",
            )
        )
    domain_counts = store.recipient_domains_for(
        tenant_id="acme", action_type="send_email"
    )
    assert domain_counts == {"target.example": 5}


def test_tenant_baseline_normalizes_tenant_and_action_type() -> None:
    """Lookup is case- and whitespace-insensitive on the keys."""
    store = InMemoryTenantContentBaseline()
    agent_id = uuid4()
    for i in range(40):
        store.append(
            _make_signature_record(
                tenant_id="ACME",  # validator normalizes
                agent_id=agent_id,
                action_type="Send_Email",
                content=f"hello {i}",
            )
        )

    sig = compute_content_signature("hello 99")
    lookup = store.lookup(
        tenant_id="  acme  ",
        action_type="send_email",
        signature=sig,
        recipient=None,
    )
    assert lookup.sample_size == 40


# ---------------------------------------------------------------------------
# Behavioral evaluator integration
# ---------------------------------------------------------------------------


def test_behavioral_evaluator_neutral_without_tenant_baseline() -> None:
    """V10 behavior preserved: no tenant baseline -> neutral tenant fields."""
    ledger = InMemoryActionLedger()
    evaluator = AgentBehavioralEvaluator(ledger=ledger)

    agent = _make_agent()
    request = _make_request()

    signal = evaluator.evaluate(agent=agent, request=request)
    assert signal.tenant_sample_size == 0
    assert signal.tenant_cold_start is True
    assert signal.tenant_novelty_score == 0.0
    assert signal.tenant_recipient_novel is False


def test_behavioral_evaluator_cold_start_tenant_emits_uncertainty() -> None:
    ledger = InMemoryActionLedger()
    tenant_baseline = InMemoryTenantContentBaseline()
    evaluator = AgentBehavioralEvaluator(
        ledger=ledger, tenant_baseline=tenant_baseline
    )

    agent = _make_agent()
    request = _make_request()
    signal = evaluator.evaluate(agent=agent, request=request)
    # Tenant baseline is empty -> tenant_cold_start.
    assert signal.tenant_cold_start is True
    assert "tenant_baseline_cold_start" in signal.uncertainty_flags


def test_behavioral_evaluator_fires_tenant_novel_content_finding() -> None:
    """
    The headline V11 test: a perfectly compliant agent with a clean
    history sends content that nothing in the tenant baseline looks
    like, and we must surface a tenant_novel_content finding.
    """
    ledger = InMemoryActionLedger()
    tenant_baseline = InMemoryTenantContentBaseline()
    evaluator = AgentBehavioralEvaluator(
        ledger=ledger, tenant_baseline=tenant_baseline
    )

    agent = _make_agent(tenant_id="acme")

    # Seed both the agent's own ledger AND the tenant baseline with
    # normal outbound content.
    for i in range(30):
        ledger.append(
            _make_ledger_entry(
                agent_id=agent.agent_id,
                content_sha=f"{i:064x}",
                verdict="PERMIT",
            )
        )
        tenant_baseline.append(
            _make_signature_record(
                tenant_id="acme",
                agent_id=agent.agent_id,
                content=(
                    f"Hi, following up on the demo we discussed last week, "
                    f"would love to find time iteration {i}."
                ),
                recipient_domain="target.example",
            )
        )

    # Now the agent sends content that is wildly off the tenant baseline.
    request = _make_request(
        content=(
            "Reset your password by replying with your full SSN "
            "and the answers to your security questions."
        ),
        recipient="hr@target.example",
    )
    signal = evaluator.evaluate(agent=agent, request=request)

    assert signal.tenant_novelty_score > 0.70
    finding_names = {f.rule_name for f in signal.findings}
    assert "tenant_novel_content" in finding_names
    assert "tenant_novel_content" in signal.uncertainty_flags
    # The tenant signal should have meaningfully raised the risk score
    # relative to a no-tenant evaluator.
    no_tenant_eval = AgentBehavioralEvaluator(ledger=ledger)
    no_tenant_signal = no_tenant_eval.evaluate(agent=agent, request=request)
    assert signal.risk_score > no_tenant_signal.risk_score


def test_behavioral_evaluator_does_not_fire_on_familiar_content() -> None:
    ledger = InMemoryActionLedger()
    tenant_baseline = InMemoryTenantContentBaseline()
    evaluator = AgentBehavioralEvaluator(
        ledger=ledger, tenant_baseline=tenant_baseline
    )

    agent = _make_agent(tenant_id="acme")
    template_content = (
        "Hi there, just following up on our chat about scheduling a demo "
        "for the engineering team — would Thursday work?"
    )
    for i in range(40):
        ledger.append(
            _make_ledger_entry(
                agent_id=agent.agent_id,
                content_sha=f"{i:064x}",
                verdict="PERMIT",
                action_type="send_email",
                channel="email",
                recipient="buyer@target.example",
            )
        )
        tenant_baseline.append(
            _make_signature_record(
                tenant_id="acme",
                agent_id=agent.agent_id,
                content=template_content,  # identical template every time
                recipient_domain="target.example",
            )
        )

    # Same template now sent again. Should NOT be novel.
    request = _make_request(
        content=template_content,
        recipient="buyer@target.example",
    )
    signal = evaluator.evaluate(agent=agent, request=request)

    finding_names = {f.rule_name for f in signal.findings}
    assert "tenant_novel_content" not in finding_names
    assert signal.tenant_novelty_score < 0.20


def test_behavioral_evaluator_fires_tenant_novel_recipient() -> None:
    ledger = InMemoryActionLedger()
    tenant_baseline = InMemoryTenantContentBaseline()
    evaluator = AgentBehavioralEvaluator(
        ledger=ledger, tenant_baseline=tenant_baseline
    )

    agent = _make_agent(tenant_id="acme")
    # Seed agent ledger with PERMITs to clear cold-start.
    for i in range(30):
        ledger.append(
            _make_ledger_entry(
                agent_id=agent.agent_id,
                content_sha=f"{i:064x}",
                verdict="PERMIT",
                recipient="buyer@known.example",
            )
        )
    # Seed tenant baseline with sufficient samples but only ever to one
    # recipient domain.
    template_content = "Standard outreach about scheduling a meeting."
    for i in range(30):
        tenant_baseline.append(
            _make_signature_record(
                tenant_id="acme",
                agent_id=agent.agent_id,
                content=template_content,
                recipient_domain="known.example",
            )
        )

    request = _make_request(
        content=template_content,  # same content; only the recipient is new
        recipient="surprise-target@brand-new-domain.example",
    )
    signal = evaluator.evaluate(agent=agent, request=request)

    finding_names = {f.rule_name for f in signal.findings}
    assert "tenant_novel_recipient_domain" in finding_names
    assert signal.tenant_recipient_novel is True


def test_behavioral_evaluator_does_not_fire_when_tenant_thin() -> None:
    """Thin tenant baseline (under MIN_SAMPLE_FOR_FULL_CONFIDENCE)
    should not escalate to a finding even on novel content."""
    ledger = InMemoryActionLedger()
    tenant_baseline = InMemoryTenantContentBaseline()
    evaluator = AgentBehavioralEvaluator(
        ledger=ledger, tenant_baseline=tenant_baseline
    )
    agent = _make_agent(tenant_id="acme")

    # Seed agent's own ledger normally.
    for i in range(30):
        ledger.append(
            _make_ledger_entry(
                agent_id=agent.agent_id,
                content_sha=f"{i:064x}",
                verdict="PERMIT",
            )
        )
    # Seed tenant baseline with only a handful of records — under the
    # cold-start threshold.
    for i in range(5):
        tenant_baseline.append(
            _make_signature_record(
                tenant_id="acme",
                agent_id=agent.agent_id,
                content="some old content",
            )
        )

    request = _make_request(content="something completely different")
    signal = evaluator.evaluate(agent=agent, request=request)
    finding_names = {f.rule_name for f in signal.findings}
    assert "tenant_novel_content" not in finding_names
    assert "tenant_baseline_thin" in signal.uncertainty_flags


# ---------------------------------------------------------------------------
# Suite plumbing
# ---------------------------------------------------------------------------


def test_suite_threads_tenant_baseline_into_behavioral() -> None:
    registry = InMemoryAgentRegistry()
    ledger = InMemoryActionLedger()
    tenant_baseline = InMemoryTenantContentBaseline()
    suite = AgentEvaluationSuite(
        registry=registry,
        ledger=ledger,
        tenant_baseline=tenant_baseline,
    )

    agent = _make_agent()
    registry.save(agent)
    request = _make_request(agent_id=agent.agent_id)

    bundle = suite.evaluate(request)
    assert bundle.agent_present is True
    # Tenant fields should be populated even if cold-start.
    assert bundle.behavioral.tenant_cold_start is True


def test_suite_neutral_when_baseline_absent() -> None:
    registry = InMemoryAgentRegistry()
    ledger = InMemoryActionLedger()
    suite = AgentEvaluationSuite(registry=registry, ledger=ledger)

    agent = _make_agent()
    registry.save(agent)
    request = _make_request(agent_id=agent.agent_id)

    bundle = suite.evaluate(request)
    assert bundle.agent_present is True
    # No baseline wired -> neutral tenant fields.
    assert bundle.behavioral.tenant_sample_size == 0
    assert bundle.behavioral.tenant_cold_start is True


# ---------------------------------------------------------------------------
# EvaluateActionCommand: tenant baseline write-on-PERMIT
# ---------------------------------------------------------------------------


def _make_ledger_entry(
    *,
    agent_id: UUID,
    content_sha: str,
    verdict: str = "PERMIT",
    action_type: str = "send_email",
    channel: str = "email",
    environment: str = "production",
    recipient: str | None = "buyer@target.example",
):
    """Build a minimal ActionLedgerEntry for ledger seeding in tests."""
    from tex.domain.agent import ActionLedgerEntry

    return ActionLedgerEntry(
        agent_id=agent_id,
        decision_id=uuid4(),
        request_id=uuid4(),
        verdict=verdict,
        action_type=action_type,
        channel=channel,
        environment=environment,
        recipient=recipient,
        final_score=0.10,
        confidence=0.90,
        content_sha256=content_sha,
    )


def test_command_writes_tenant_baseline_on_permit() -> None:
    runtime = build_runtime(evidence_path="/tmp/tex-v11-test-permit.jsonl")
    agent = _make_agent(
        tenant_id="acme-test",
        trust_tier=AgentTrustTier.PRIVILEGED,  # bypass identity cold-start
    )
    runtime.agent_registry.save(agent)

    # Pre-warm the agent's own ledger so we are past behavioral cold
    # start and a clean evaluation will land as PERMIT.
    for i in range(30):
        runtime.action_ledger.append(
            _make_ledger_entry(
                agent_id=agent.agent_id,
                content_sha=f"{i:064x}",
                verdict="PERMIT",
                action_type="send_email",
                channel="email",
                recipient="buyer@target.example",
            )
        )

    request = _make_request(
        content="Hi, just following up on our scheduling thread for next Tuesday.",
        agent_id=agent.agent_id,
    )
    result = runtime.evaluate_action_command.execute(request)

    # The point of this test: when the verdict is PERMIT, the tenant
    # baseline must record exactly one new signature.
    if result.response.is_permit:
        assert runtime.tenant_baseline.count_for(
            tenant_id="acme-test", action_type="send_email"
        ) == 1
    else:
        # Very unlikely given the warm ledger + privileged trust + clean
        # content, but if it happens we should still see zero baseline
        # writes (the property under test).
        assert runtime.tenant_baseline.total_count() == 0


def test_command_does_not_write_tenant_baseline_when_no_agent() -> None:
    runtime = build_runtime(evidence_path="/tmp/tex-v11-test-noagent.jsonl")

    request = _make_request(
        content="Plain content with no agent id supplied.",
        agent_id=None,
    )
    runtime.evaluate_action_command.execute(request)

    assert runtime.tenant_baseline.total_count() == 0


def test_command_does_not_write_tenant_baseline_on_forbid() -> None:
    """
    Crucial: ABSTAIN/FORBID decisions do NOT pollute the baseline.
    This is the property that makes "tenant novelty" mean "novel
    relative to authorized output", not "novel relative to anything
    we have ever seen this agent attempt".
    """
    runtime = build_runtime(evidence_path="/tmp/tex-v11-test-forbid.jsonl")
    agent = _make_agent(tenant_id="acme-test-2")
    runtime.agent_registry.save(agent)

    # Build content that the deterministic gate will reject. The
    # default policy blocks SSNs in content; that is enough to force
    # FORBID on this evaluation through the deterministic path.
    request = _make_request(
        content="Send my SSN 123-45-6789 to the recipient please.",
        agent_id=agent.agent_id,
    )
    result = runtime.evaluate_action_command.execute(request)

    # Whatever verdict the policy produces, if it is not PERMIT the
    # baseline must remain empty.
    if not result.response.is_permit:
        assert runtime.tenant_baseline.total_count() == 0


# ---------------------------------------------------------------------------
# PDP integration: end-to-end round-trip
# ---------------------------------------------------------------------------


def test_pdp_with_tenant_baseline_full_evaluation() -> None:
    runtime = build_runtime(evidence_path="/tmp/tex-v11-test-pdp.jsonl")
    agent = _make_agent(tenant_id="pdp-tenant")
    runtime.agent_registry.save(agent)

    # First call seeds the baseline (single sample - still cold start).
    seed_request = _make_request(
        content="Friendly outreach about scheduling a demo next week.",
        agent_id=agent.agent_id,
    )
    runtime.evaluate_action_command.execute(seed_request)

    # Second evaluation: we should see the tenant_cold_start flag because
    # one sample is far below the threshold.
    second = _make_request(
        content="Different friendly outreach about a different topic.",
        agent_id=agent.agent_id,
    )
    result = runtime.evaluate_action_command.execute(second)
    assert (
        "tenant_baseline_thin" in result.response.uncertainty_flags
        or "tenant_baseline_cold_start" in result.response.uncertainty_flags
    )


# ---------------------------------------------------------------------------
# Backwards compatibility (V10 -> V11 contract)
# ---------------------------------------------------------------------------


def test_no_agent_request_fingerprint_unchanged_by_v11() -> None:
    """
    The cornerstone backwards-compat property: a request with
    agent_id=None must produce the same determinism fingerprint
    whether or not the V11 tenant baseline is wired in.
    """
    pdp_with_baseline = PolicyDecisionPoint(
        agent_evaluator=AgentEvaluationSuite(
            registry=InMemoryAgentRegistry(),
            ledger=InMemoryActionLedger(),
            tenant_baseline=InMemoryTenantContentBaseline(),
        )
    )
    pdp_without_baseline = PolicyDecisionPoint(
        agent_evaluator=AgentEvaluationSuite(
            registry=InMemoryAgentRegistry(),
            ledger=InMemoryActionLedger(),
            tenant_baseline=None,
        )
    )
    pdp_no_agent_layer = PolicyDecisionPoint(agent_evaluator=None)
    policy = build_default_policy()

    request = _make_request(content="Plain content with no agent.", agent_id=None)
    r1 = pdp_with_baseline.evaluate(request=request, policy=policy)
    r2 = pdp_without_baseline.evaluate(request=request, policy=policy)
    r3 = pdp_no_agent_layer.evaluate(request=request, policy=policy)

    assert r1.determinism_fingerprint == r2.determinism_fingerprint
    assert r2.determinism_fingerprint == r3.determinism_fingerprint
    assert r1.response.verdict == r2.response.verdict == r3.response.verdict
    assert r1.response.final_score == r2.response.final_score == r3.response.final_score


def test_agent_request_with_no_tenant_data_reproduces_v10_fingerprint_for_same_inputs() -> None:
    """
    With agent_id present: when the tenant baseline is empty AND the
    agent ledger is empty (cold start), two evaluations of the same
    request produce the same fingerprint. This is the determinism
    anchor — same inputs, same fingerprint.
    """
    registry = InMemoryAgentRegistry()
    ledger = InMemoryActionLedger()
    tenant_baseline = InMemoryTenantContentBaseline()
    suite = AgentEvaluationSuite(
        registry=registry,
        ledger=ledger,
        tenant_baseline=tenant_baseline,
    )
    agent = _make_agent()
    registry.save(agent)

    pdp = PolicyDecisionPoint(agent_evaluator=suite)
    policy = build_default_policy()

    request = _make_request(
        content="Stable repeatable content.",
        agent_id=agent.agent_id,
    )
    r1 = pdp.evaluate(request=request, policy=policy)
    r2 = pdp.evaluate(request=request, policy=policy)

    assert r1.determinism_fingerprint == r2.determinism_fingerprint


# ---------------------------------------------------------------------------
# API: tenant_id round-trip and baseline endpoint
# ---------------------------------------------------------------------------


@pytest.fixture
def client(tmp_path) -> TestClient:
    evidence_path = tmp_path / "evidence.jsonl"
    runtime = build_runtime(evidence_path=evidence_path)
    app = create_app(runtime=runtime, evidence_path=evidence_path)
    app.state.tex_runtime = runtime
    return TestClient(app)


def test_register_agent_round_trips_tenant_id(client: TestClient) -> None:
    response = client.post(
        "/v1/agents",
        json={
            "name": "test-agent",
            "owner": "test-team",
            "tenant_id": "Test-TENANT-One",
        },
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["tenant_id"] == "test-tenant-one"  # normalized lowercase

    fetched = client.get(f"/v1/agents/{body['agent_id']}")
    assert fetched.status_code == 200
    assert fetched.json()["tenant_id"] == "test-tenant-one"


def test_register_agent_defaults_tenant_id_when_omitted(client: TestClient) -> None:
    response = client.post(
        "/v1/agents",
        json={"name": "default-tenant-agent", "owner": "test-team"},
    )
    assert response.status_code == 201, response.text
    assert response.json()["tenant_id"] == "default"


def test_tenant_baseline_endpoint_empty(client: TestClient) -> None:
    response = client.get("/v1/tenants/empty-tenant/baseline")
    assert response.status_code == 200
    body = response.json()
    assert body["tenant_id"] == "empty-tenant"
    assert body["total_signatures"] == 0
    assert body["action_type_sample_counts"] == {}


def test_tenant_baseline_endpoint_after_evaluation(client: TestClient) -> None:
    register = client.post(
        "/v1/agents",
        json={
            "name": "live-agent",
            "owner": "test-team",
            "tenant_id": "live-tenant",
        },
    )
    assert register.status_code == 201
    agent_body = register.json()

    # Send a clean evaluation that should land as PERMIT and contribute
    # to the tenant baseline.
    eval_response = client.post(
        "/evaluate",
        json={
            "request_id": str(uuid4()),
            "action_type": "send_email",
            "content": "Hi there, just following up on the meeting we scheduled.",
            "channel": "email",
            "environment": "production",
            "recipient": "buyer@target.example",
            "agent_id": agent_body["agent_id"],
        },
    )
    assert eval_response.status_code == 200, eval_response.text

    summary = client.get("/v1/tenants/live-tenant/baseline")
    assert summary.status_code == 200
    body = summary.json()
    assert body["tenant_id"] == "live-tenant"

    if eval_response.json()["verdict"] == "PERMIT":
        # On PERMIT, baseline should now contain one signature.
        assert body["total_signatures"] >= 1
        assert "send_email" in body["action_type_sample_counts"]


def test_tenant_baseline_endpoint_isolates_tenants(client: TestClient) -> None:
    # Create two agents in two tenants.
    for tenant_id in ("alpha", "beta"):
        client.post(
            "/v1/agents",
            json={
                "name": f"{tenant_id}-agent",
                "owner": "team",
                "tenant_id": tenant_id,
            },
        )

    alpha = client.get("/v1/tenants/alpha/baseline").json()
    beta = client.get("/v1/tenants/beta/baseline").json()
    assert alpha["tenant_id"] == "alpha"
    assert beta["tenant_id"] == "beta"
    # Both should be independent baselines (empty here).
    assert alpha["total_signatures"] == 0
    assert beta["total_signatures"] == 0

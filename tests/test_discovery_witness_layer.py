"""
Tests for the completed discovery / inventory witness layer.

Covers the build that finished the doctrine's §8 "Next" list:

  1. Continuous feed: identity seals on its own, silently; only a
     ``requires_human`` resolution ever leaves the feed (the held path);
     ``note_action`` is hot-path safe (never raises).
  2. Birth-certificate anchoring on REGISTER: discovery and provenance are
     one flow; the discovery birth carries the source's admissibility tier
     and a later behavioural sighting confirms the *same* identity.
  3. Count-once ignition + humanized count; pull-only surface.
  4. Dormancy: sleep only the provably safe (silent), ABSTAIN the
     uncertain/load-bearing (held), never auto-execute day-90 deletion.
  5. Tamper-resistant connectors: cloud-audit / network-egress /
     kernel-eBPF emit candidates at the right signal tier.
  6. Depth: sealed delegation graph, declared-vs-observed intent,
     coverage-boundary-as-grade, Postgres provenance mirror (in-memory).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from tex.commands.evaluate_action import EvaluateActionCommand  # noqa: F401 (import safety)
from tex.discovery.connectors import (
    CloudAuditConnector,
    KernelEbpfConnector,
    NetworkEgressConnector,
)
from tex.discovery.connectors.base import ConnectorContext
from tex.discovery.dormancy import DormancyController
from tex.discovery.ignition import IgnitionRegistry, humanize_count
from tex.domain.agent import (
    ActionLedgerEntry,
    AgentIdentity,
    AgentLifecycleStatus,
)
from tex.domain.discovery import DiscoverySource
from tex.domain.signal_trust import SignalTrustTier, tier_for_source
from tex.provenance import (
    ProvenanceEventKind,
    build_default_provenance_engine,
)
from tex.provenance.delegation import SealedDelegationGraph
from tex.provenance.feed import ContinuousProvenanceFeed, HeldDecisionSink
from tex.stores.action_ledger import InMemoryActionLedger
from tex.stores.agent_registry import InMemoryAgentRegistry


# --------------------------------------------------------------------------- helpers
def _entry(agent_id, *, i, action="invoke_model", channel="api", env="prod",
           verdict="PERMIT", tools=("s3.read", "bedrock.invoke"),
           sys_hash="a" * 64, tool_hash="b" * 64, score=0.2, when=None):
    return ActionLedgerEntry(
        agent_id=agent_id,
        decision_id=uuid4(),
        request_id=uuid4(),
        verdict=verdict,
        action_type=action,
        channel=channel,
        environment=env,
        final_score=score,
        confidence=0.9,
        content_sha256="c" * 64,
        tools=tuple(tools),
        system_prompt_hash=sys_hash,
        tool_manifest_hash=tool_hash,
        recorded_at=when or (datetime.now(UTC) + timedelta(seconds=i * 5)),
    )


def _ctx(tenant="acme"):
    return ConnectorContext(tenant_id=tenant)


# =========================================================================== #1 feed
def test_feed_seals_silently_and_is_hot_path_safe():
    engine = build_default_provenance_engine()
    ledger = InMemoryActionLedger()
    held = HeldDecisionSink()
    feed = ContinuousProvenanceFeed(
        engine=engine, action_ledger=ledger, held_sink=held, batch_size=4
    )

    agent = uuid4()
    for i in range(12):
        ledger.append(_entry(agent, i=i))
        feed.note_action(agent)  # cheap, non-blocking

    feed.drain()

    # Identity sealed itself — a birth is in the log — with no held item
    # surfaced (an ordinary discovery never breaks the voice).
    assert engine.birth_certificate(agent) is not None
    assert len(held) == 0
    assert engine.ledger.verify_chain()["intact"] is True
    assert engine.ledger.verify_signatures()["valid"] is True


def test_feed_note_action_never_raises_even_when_engine_broken():
    class _Boom:
        def list_for_agent(self, *a, **k):
            raise RuntimeError("ledger down")

    engine = build_default_provenance_engine()
    feed = ContinuousProvenanceFeed(engine=engine, action_ledger=_Boom(), batch_size=1)
    # Must not raise into the gate, ever.
    feed.note_action(uuid4())
    feed.drain()  # also swallows


def test_feed_routes_only_requires_human_to_held_sink():
    # The feed's contract: a resolution that requires a human is the ONLY
    # thing routed onward; an ordinary resolution is sealed and silent.
    # Pin that contract directly with a stub engine so the assertion does
    # not depend on drift dynamics.
    from tex.provenance.models import ProvenanceResolution

    class _StubEngine:
        def __init__(self, requires_human):
            self._rh = requires_human
            self.calls = 0

        def observe(self, *, agent_id, entries, signal_tier):
            self.calls += 1
            return ProvenanceResolution(
                observed_signature_hash="h",
                event_kind=ProvenanceEventKind.DRIFT,
                confidence=0.5,
                requires_human=self._rh,
                note="stub",
            )

    ledger = InMemoryActionLedger()
    agent = uuid4()
    ledger.append(_entry(agent, i=0))

    # Ordinary resolution → nothing held.
    held_quiet = HeldDecisionSink()
    feed_quiet = ContinuousProvenanceFeed(
        engine=_StubEngine(requires_human=False),
        action_ledger=ledger,
        held_sink=held_quiet,
        batch_size=1,
    )
    feed_quiet.note_action(agent)
    feed_quiet.drain()
    assert len(held_quiet) == 0

    # requires_human resolution → surfaced to the held sink.
    held_loud = HeldDecisionSink()
    feed_loud = ContinuousProvenanceFeed(
        engine=_StubEngine(requires_human=True),
        action_ledger=ledger,
        held_sink=held_loud,
        batch_size=1,
    )
    feed_loud.note_action(agent)
    feed_loud.drain()
    assert len(held_loud) == 1
    assert held_loud.peek()[0].kind == ProvenanceEventKind.DRIFT


# =========================================================================== #2 register
def test_discovery_birth_then_behaviour_confirms_same_identity():
    engine = build_default_provenance_engine()
    agent = uuid4()

    # Discovery seals a cold birth at the cloud-audit tier with anchors.
    res = engine.register_birth(
        agent_id=agent,
        signal_tier=SignalTrustTier.AUDIT_LOG,
        system_prompt_hash="a" * 64,
        tool_manifest_hash="b" * 64,
        declared_intent="reads sales reports from s3",
    )
    assert res.event_kind == ProvenanceEventKind.BIRTH
    cert = engine.birth_certificate(agent)
    assert cert is not None
    assert cert.signal_tier == int(SignalTrustTier.AUDIT_LOG)
    assert cert.declared_intent == "reads sales reports from s3"

    # Idempotent: a second register does not seal a second birth.
    births_before = sum(
        1 for r in engine.ledger.list_for_agent(agent)
        if r.event_kind == ProvenanceEventKind.BIRTH
    )
    engine.register_birth(agent_id=agent, signal_tier=SignalTrustTier.CONTROL_PLANE)
    births_after = sum(
        1 for r in engine.ledger.list_for_agent(agent)
        if r.event_kind == ProvenanceEventKind.BIRTH
    )
    assert births_before == births_after == 1

    # The gate then sees the agent act → SIGHTING of the SAME identity,
    # because the shared anchors travel.
    window = [_entry(agent, i=i, sys_hash="a" * 64, tool_hash="b" * 64) for i in range(12)]
    res2 = engine.observe(agent_id=agent, entries=window)
    assert res2.event_kind == ProvenanceEventKind.SIGHTING


def test_intent_drift_flags_behaviour_outside_declaration():
    engine = build_default_provenance_engine()
    agent = uuid4()
    engine.register_birth(
        agent_id=agent,
        signal_tier=SignalTrustTier.CONTROL_PLANE,
        declared_intent="invoke_model for summarization only",
    )
    window = [
        _entry(agent, i=i, action=a)
        for i, a in enumerate(["invoke_model"] * 6 + ["delete_record"] * 6)
    ]
    engine.observe(agent_id=agent, entries=window)
    drift = engine.intent_drift(agent)
    assert drift is not None
    # The grade now speaks in capability *categories* (rename-resistant),
    # not raw action-type strings: deleting records is data_delete, which is
    # outside a declaration that only covers invoking a model.
    assert "data_delete" in drift["outside_declaration"]
    assert "tool_use" in drift["consistent_with_declaration"]
    assert drift["intent_divergence"] > 0.0
    assert drift["scoring_method"] == "taxonomy_v1"


# =========================================================================== #3 ignition
def test_humanize_count_speaks_numbers():
    assert humanize_count(0) == "zero"
    assert humanize_count(1) == "one"
    assert humanize_count(41) == "forty-one"
    assert humanize_count(100) == "one hundred"
    assert humanize_count(241) == "two hundred forty-one"


def test_ignition_fires_once_per_tenant():
    reg = IgnitionRegistry()
    assert reg.has_fired("acme") is False
    first = reg.fire("acme")
    assert reg.has_fired("acme") is True
    second = reg.fire("acme")
    assert first == second  # idempotent, keeps first time
    reg.reset("acme")
    assert reg.has_fired("acme") is False


# =========================================================================== #4 dormancy
def _agent(tenant="acme", *, name="bot", status=AgentLifecycleStatus.ACTIVE, registered_days_ago=0):
    return AgentIdentity(
        name=name,
        owner="owner@acme",
        tenant_id=tenant,
        lifecycle_status=status,
        registered_at=datetime.now(UTC) - timedelta(days=registered_days_ago),
    )


def _dormancy(registry, ledger, engine, held, graph):
    return DormancyController(
        registry=registry,
        action_ledger=ledger,
        provenance_engine=engine,
        held_sink=held,
        delegation_graph=graph,
        idle_threshold=timedelta(days=30),
    )


def test_dormancy_sleeps_only_provably_safe():
    registry = InMemoryAgentRegistry()
    ledger = InMemoryActionLedger()
    engine = build_default_provenance_engine()
    held = HeldDecisionSink()
    graph = SealedDelegationGraph()

    # Idle agent, nothing delegates to it → provably safe → slept silently.
    safe = _agent(name="idle-safe", registered_days_ago=60)
    registry.save(safe)

    ctrl = _dormancy(registry, ledger, engine, held, graph)
    result = ctrl.sweep()

    assert safe.agent_id in result.slept
    assert registry.get(safe.agent_id).lifecycle_status is AgentLifecycleStatus.SLEEPING
    # Sealed, silent: a SLEPT record exists, nothing was held.
    assert engine.last_event(safe.agent_id, ProvenanceEventKind.SLEPT) is not None
    assert len(held) == 0


def test_dormancy_abstains_on_load_bearing_idle_agent():
    registry = InMemoryAgentRegistry()
    ledger = InMemoryActionLedger()
    engine = build_default_provenance_engine()
    held = HeldDecisionSink()
    graph = SealedDelegationGraph()

    dependent = _agent(name="caller", registered_days_ago=1)
    load_bearing = _agent(name="idle-but-needed", registered_days_ago=60)
    registry.save(dependent)
    registry.save(load_bearing)
    # Something delegates to the idle agent → load-bearing.
    graph.observe_delegation(
        delegator_id=dependent.agent_id, delegate_id=load_bearing.agent_id
    )

    ctrl = _dormancy(registry, ledger, engine, held, graph)
    result = ctrl.sweep()

    # NOT slept — held as a genuine ABSTAIN instead.
    assert load_bearing.agent_id not in result.slept
    assert load_bearing.agent_id in result.abstained_uncertain
    assert registry.get(load_bearing.agent_id).lifecycle_status is AgentLifecycleStatus.ACTIVE
    assert any(h.kind == "dormancy_abstain" for h in held.peek())


def test_dormancy_holds_day90_deletion_never_auto_executes():
    registry = InMemoryAgentRegistry()
    ledger = InMemoryActionLedger()
    engine = build_default_provenance_engine()
    held = HeldDecisionSink()
    graph = SealedDelegationGraph()

    agent = _agent(name="long-asleep", status=AgentLifecycleStatus.SLEEPING, registered_days_ago=200)
    registry.save(agent)
    # Seal a SLEPT 100 days ago (past the 90-day reversible window).
    engine.ledger.append(
        event_kind=ProvenanceEventKind.SLEPT,
        agent_id=agent.agent_id,
        signature_hash="d" * 64,
    )
    # Backdate by mutating the sealed record's recorded_at is not allowed
    # (frozen); instead use a controller whose window is tiny so "now" is
    # already past it.
    ctrl = DormancyController(
        registry=registry,
        action_ledger=ledger,
        provenance_engine=engine,
        held_sink=held,
        delegation_graph=graph,
        reversible_window=timedelta(seconds=0),
    )
    result = ctrl.sweep()

    assert agent.agent_id in result.held_for_deletion
    # Irreversible step NOT taken automatically — still SLEEPING.
    assert registry.get(agent.agent_id).lifecycle_status is AgentLifecycleStatus.SLEEPING
    assert any(h.kind == "dormancy_permanent_deletion" for h in held.peek())


def test_dormancy_wake_is_sealed_human_act():
    registry = InMemoryAgentRegistry()
    ledger = InMemoryActionLedger()
    engine = build_default_provenance_engine()
    held = HeldDecisionSink()
    graph = SealedDelegationGraph()
    agent = _agent(name="sleeper", status=AgentLifecycleStatus.SLEEPING, registered_days_ago=40)
    registry.save(agent)

    ctrl = _dormancy(registry, ledger, engine, held, graph)
    ctrl.wake(agent.agent_id, actor="matthew")

    assert registry.get(agent.agent_id).lifecycle_status is AgentLifecycleStatus.ACTIVE
    woke = engine.last_event(agent.agent_id, ProvenanceEventKind.WOKE)
    assert woke is not None
    assert woke.detail.get("actor") == "matthew"


# =========================================================================== #5 connectors
def test_cloud_audit_connector_emits_audit_tier_candidate():
    events = [
        {
            "eventSource": "bedrock-agentcore.amazonaws.com",
            "eventName": "InvokeAgentRuntime",
            "eventTime": "2026-05-01T12:00:00Z",
            "userIdentity": {"principalId": "AIDA:order-bot", "accountId": "111"},
            "sourceIPAddress": "34.0.0.1",
            "resources": [
                {"type": "AWS::BedrockAgentCore::Runtime",
                 "ARN": "arn:aws:bedrock-agentcore:us-east-1:111:runtime/order-bot"}
            ],
            "eventCategory": "Data",
            "tlsDetails": {"clientProvidedHostHeader": "order-bot.gateway.amazonaws.com"},
        }
    ]
    conn = CloudAuditConnector(records=events)
    cands = list(conn.scan(_ctx()))
    assert len(cands) == 1
    c = cands[0]
    assert c.source == DiscoverySource.CLOUD_AUDIT
    assert tier_for_source(str(c.source)) == SignalTrustTier.AUDIT_LOG
    assert "order-bot" in c.external_id
    assert c.evidence["tamper_resistant"] is True


def test_network_egress_connector_catches_headless_agent():
    flows = [
        {
            "source_workload": "laptop-mnardizzi",
            "sni": "api.openai.com",
            "ja4": "t13d1516h2_8daaf6152771_b186095e22b6",
            "first_seen": "2026-05-01T00:00:00Z",
            "last_seen": "2026-05-02T00:00:00Z",
            "connection_count": 60,
        },
        {  # non-model egress is ignored
            "source_workload": "laptop-mnardizzi",
            "sni": "example.com",
            "ja4": "x",
            "connection_count": 5,
        },
    ]
    conn = NetworkEgressConnector(flows=flows)
    cands = list(conn.scan(_ctx()))
    assert len(cands) == 1
    c = cands[0]
    assert c.source == DiscoverySource.NETWORK_EGRESS
    assert tier_for_source(str(c.source)) == SignalTrustTier.NETWORK_OBSERVED
    assert c.evidence["model_provider"] == "openai"


def test_kernel_ebpf_connector_emits_attested_candidate():
    events = [
        {
            "binary": "/usr/bin/python3.12",
            "args": "-m agent.main --serve",
            "pod": "ns/agents/pod/order-bot-7c9",
            "measured_code_hash": "sha256:abc",
            "attestation_method": "intel_tdx",
            "exec_time": "2026-05-01T12:00:00Z",
            "syscall_profile": ["connect", "openat"],
        }
    ]
    conn = KernelEbpfConnector(events=events)
    cands = list(conn.scan(_ctx()))
    assert len(cands) == 1
    c = cands[0]
    assert c.source == DiscoverySource.KERNEL_EBPF
    assert tier_for_source(str(c.source)) == SignalTrustTier.KERNEL_ATTESTED
    # The attestation method is sealed so the grade stays revisable.
    assert c.evidence["attestation_method"] == "intel_tdx"


# =========================================================================== #6 depth
def test_delegation_graph_seals_and_verifies_edges():
    graph = SealedDelegationGraph()
    a, b, c = uuid4(), uuid4(), uuid4()
    graph.observe_delegation(delegator_id=a, delegate_id=b)
    graph.observe_delegation(delegator_id=a, delegate_id=c)
    graph.observe_delegation(delegator_id=b, delegate_id=c)

    assert graph.is_load_bearing(c) is True
    assert set(graph.delegators_of(c)) == {a, b}
    assert set(graph.delegates_of(a)) == {b, c}
    assert graph.is_load_bearing(a) is False  # nothing delegates to a
    assert graph.verify_chain()["intact"] is True
    assert graph.verify_signatures()["valid"] is True


def test_coverage_boundary_grades_and_states_the_edge():
    engine = build_default_provenance_engine()
    agent = uuid4()
    engine.register_birth(agent_id=agent, signal_tier=SignalTrustTier.SELF_DECLARED)
    cov = engine.coverage_boundary(agent)
    assert cov is not None
    assert cov.admissibility == "claimed"
    assert cov.tamper_resistant is False
    assert "forgeable" in cov.edge_of_sight

    # A kernel sighting widens the grade.
    engine.register_birth(agent_id=agent, signal_tier=SignalTrustTier.KERNEL_ATTESTED)
    cov2 = engine.coverage_boundary(agent)
    assert cov2.signal_tier == int(SignalTrustTier.KERNEL_ATTESTED)
    assert cov2.tamper_resistant is True


def test_postgres_provenance_mirror_in_memory_fallback():
    # With no DATABASE_URL the mirror runs as a faithful in-memory ledger.
    from tex.stores.behavioral_provenance_ledger_postgres import (
        PostgresBehavioralProvenanceLedger,
    )

    led = PostgresBehavioralProvenanceLedger(dsn="")
    assert led.is_durable is False
    rec = led.append(
        event_kind=ProvenanceEventKind.BIRTH,
        agent_id=uuid4(),
        signature_hash="e" * 64,
    )
    assert rec.sequence == 0
    assert led.verify_chain()["intact"] is True
    assert led.verify_signatures()["valid"] is True


# =========================================================================== surface
def _client():
    from fastapi.testclient import TestClient

    from tex.main import create_app

    return TestClient(create_app())


def test_surface_ignite_speaks_once_then_pull_only():
    client = _client()
    # First ignition speaks exactly one line.
    r1 = client.post("/v1/surface/discovery/ignite")
    assert r1.status_code == 200
    body1 = r1.json()
    assert body1["already_ignited"] is False
    assert body1["spoken"] is not None
    assert "I'll begin" in body1["spoken"]

    # Second ignition does NOT re-declare — the door has opened.
    r2 = client.post("/v1/surface/discovery/ignite")
    body2 = r2.json()
    assert body2["already_ignited"] is True
    assert body2["spoken"] is None


def test_surface_ignite_repeatable_mode_respeaks(monkeypatch):
    # Opt-in repeatable mode (TEX_BEGIN_REPEATABLE): the one-time door still only
    # opens once (already_ignited stays true), but Begin re-runs discovery and
    # RE-SPEAKS the count + honest coverage on every press — an active
    # discover+announce button for live iteration.
    client = _client()
    assert client.post("/v1/surface/discovery/ignite").json()["already_ignited"] is False

    monkeypatch.setenv("TEX_BEGIN_REPEATABLE", "1")
    body2 = client.post("/v1/surface/discovery/ignite").json()
    assert body2["already_ignited"] is True
    assert body2["spoken"] is not None
    assert "running" in body2["spoken"]


def test_surface_count_is_pull_only_and_spoken():
    client = _client()
    r = client.get("/v1/surface/discovery/count")
    assert r.status_code == 200
    body = r.json()
    assert "count" in body
    assert isinstance(body["count"], int)
    assert body["object"] is None  # count is spoken, not an object on the glass


def test_surface_owner_speaks_meaning_and_rises_the_name():
    from tex.main import create_app
    from fastapi.testclient import TestClient

    app = create_app()
    client = TestClient(app)
    # Register an agent so there is an owner to speak.
    agent = AgentIdentity(name="bedrock-invoke-03", owner="marketing", tenant_id="default")
    app.state.agent_registry.save(agent)

    r = client.get(f"/v1/surface/discovery/owner/{agent.agent_id}")
    assert r.status_code == 200
    body = r.json()
    assert body["spoken"] == "marketing owns it."
    assert body["object"] == "bedrock-invoke-03"  # the exact name rises


def test_surface_status_is_pure_read_then_ignite_flips_it():
    client = _client()
    # Status must NOT fire ignition — the door depends on a no-side-effect read.
    s0 = client.get("/v1/surface/discovery/status").json()
    assert s0["ignited"] is False
    s1 = client.get("/v1/surface/discovery/status").json()
    assert s1["ignited"] is False  # still false after repeated reads

    # The user's deliberate act fires it.
    ig = client.post("/v1/surface/discovery/ignite").json()
    assert ig["already_ignited"] is False

    s2 = client.get("/v1/surface/discovery/status").json()
    assert s2["ignited"] is True
    assert s2["ignited_at"] is not None


def test_surface_held_is_the_only_unprompted_voice_channel():
    client = _client()
    # Nothing held on a fresh estate; the channel exists and is empty.
    r = client.get("/v1/surface/discovery/held")
    assert r.status_code == 200
    assert r.json() == {"held": [], "count": 0}

"""
Tests for the discovery/inventory layer upgrades:

  1. Engine memory — event-sourcing rehydration survives a restart.
  2. Intent — deterministic, rename-resistant declared-vs-observed grade.
  3. Root one — Entra consent-graph enumerator + blast radius.
  4. Root two — OCSF audit connector (CloudTrail adapter + Security Lake).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from tex.discovery.connectors.base import ConnectorContext
from tex.discovery.connectors.cloud_audit_ocsf import OcsfAuditConnector
from tex.discovery.connectors.entra_consent_graph import EntraConsentGraphConnector
from tex.discovery.consent_graph import ConsentEdge, ConsentGraph
from tex.discovery.graph_transport import FixtureGraphTransport
from tex.domain.agent import ActionLedgerEntry
from tex.domain.discovery import DiscoveryRiskBand, DiscoverySource
from tex.domain.signal_trust import SignalTrustTier
from tex.provenance import build_default_provenance_engine
from tex.provenance.engine import BehavioralProvenanceEngine
from tex.provenance.intent import TaxonomyIntentScorer, classify_action_type
from tex.provenance.models import ProvenanceEventKind


# --------------------------------------------------------------------------- helpers
def _entry(aid, *, i, action="send_email"):
    return ActionLedgerEntry(
        agent_id=aid,
        decision_id=uuid4(),
        request_id=uuid4(),
        verdict="PERMIT",
        action_type=action,
        channel="email",
        environment="prod",
        final_score=0.2,
        confidence=0.9,
        content_sha256="c" * 64,
        tools=("smtp",),
        mcp_server_ids=(),
        data_scopes=("mail",),
        system_prompt_hash="a" * 64,
        tool_manifest_hash="b" * 64,
        recorded_at=datetime.now(UTC) + timedelta(seconds=i * 5),
    )


def _window(aid, n=12, action="send_email"):
    return [_entry(aid, i=i, action=action) for i in range(n)]


# --------------------------------------------------------------------------- 1. memory
def test_rehydration_survives_restart_no_double_birth():
    engine = build_default_provenance_engine()
    aid = uuid4()
    assert engine.observe(agent_id=aid, entries=_window(aid)).event_kind is ProvenanceEventKind.BIRTH
    assert engine.observe(agent_id=aid, entries=_window(aid)).event_kind is ProvenanceEventKind.SIGHTING

    # Restart: a new engine over the same sealed ledger starts blind.
    restarted = BehavioralProvenanceEngine(ledger=engine.ledger)
    assert restarted.known_count() == 0
    rebuilt = restarted.rebuild_from_ledger()
    assert rebuilt == 1

    # The post-restart sighting must NOT mint a second birth.
    res = restarted.observe(agent_id=aid, entries=_window(aid))
    assert res.event_kind is ProvenanceEventKind.SIGHTING


def test_rehydration_preserves_anchors_and_intent():
    engine = build_default_provenance_engine()
    aid = uuid4()
    engine.register_birth(
        agent_id=aid,
        signal_tier=SignalTrustTier.CONTROL_PLANE,
        system_prompt_hash="sys-1",
        tool_manifest_hash="tool-1",
        declared_intent="reconcile vendor invoices",
    )
    restarted = BehavioralProvenanceEngine(ledger=engine.ledger)
    restarted.rebuild_from_ledger()
    cert = restarted.birth_certificate(aid)
    assert cert is not None
    assert cert.system_prompt_hash == "sys-1"
    assert cert.declared_intent == "reconcile vendor invoices"


def test_snapshot_resume_equivalent_to_full_replay():
    engine = build_default_provenance_engine()
    aid = uuid4()
    engine.observe(agent_id=aid, entries=_window(aid))
    full = BehavioralProvenanceEngine(ledger=engine.ledger)
    full.rebuild_from_ledger()
    snap = full.snapshot()
    resumed = BehavioralProvenanceEngine(ledger=engine.ledger)
    resumed.rebuild_from_ledger(snapshot=snap)
    assert resumed.known_count() == full.known_count()


# --------------------------------------------------------------------------- 2. intent
def test_intent_taxonomy_is_rename_resistant():
    # The exact bypass a substring matcher misses: a rename to a synonym.
    assert classify_action_type("suppressLogs") == {"observability_tamper"}
    assert classify_action_type("disable_monitoring") == {"observability_tamper"}


def test_intent_divergence_flags_off_declaration_behavior():
    scorer = TaxonomyIntentScorer()
    alignment = scorer.score(
        "reconcile vendor invoices and payments",
        {"send_email": 0.8, "delete_records": 0.2},
    )
    assert "finance" in alignment.declared_categories
    assert alignment.divergence > 0.5  # behaviour is mostly outside finance
    assert alignment.method == "taxonomy_v1"


def test_intent_alignment_when_consistent():
    scorer = TaxonomyIntentScorer()
    alignment = scorer.score(
        "send notification emails to customers",
        {"send_email": 1.0},
    )
    assert "communication" in alignment.consistent_categories
    assert alignment.coverage == 1.0


def test_engine_intent_drift_routes_consequential_to_human():
    engine = build_default_provenance_engine()
    aid = uuid4()
    engine.register_birth(
        agent_id=aid,
        signal_tier=SignalTrustTier.CONTROL_PLANE,
        declared_intent="reconcile vendor invoices",
    )
    engine.observe(agent_id=aid, entries=_window(aid, action="send_email"))
    drift = engine.intent_drift(aid)
    assert drift is not None
    assert drift["requires_human"] is True
    assert drift["scoring_method"] == "taxonomy_v1"


# --------------------------------------------------------------------------- 3. consent graph
def test_consent_graph_blast_radius_transitive():
    g = ConsentGraph()
    g.add_principal("agent-A", is_agent=True)
    g.add_principal("agent-B", is_agent=True)
    g.add_edge(ConsentEdge("agent-A", "agent-B", "Agent B", ("Mail.Send",), True))
    g.add_edge(ConsentEdge("agent-B", "graph", "Microsoft Graph", ("Files.ReadWrite.All",), True))
    reach = g.reachable_resources("agent-A")
    assert "agent-B" in reach and "graph" in reach  # transitive
    blast = g.blast_radius("agent-A")
    assert blast["reachable_resource_count"] == 2


def test_consent_graph_critical_scope_unbounds_surface():
    g = ConsentGraph()
    g.add_principal("agent-X", is_agent=True)
    g.add_edge(ConsentEdge("agent-X", "graph", "Graph", ("Directory.ReadWrite.All",), True))
    assert g.blast_radius("agent-X")["surface_unbounded"] is True


def test_entra_connector_emits_candidates_from_consent_graph():
    sp_id = "11111111-1111-1111-1111-111111111111"
    transport = FixtureGraphTransport(
        {
            "servicePrincipals": [
                {
                    "id": sp_id,
                    "displayName": "Invoice Bot",
                    "servicePrincipalType": "Application",
                    "tags": ["AgentIdentity"],
                },
                {
                    "id": "resource-graph",
                    "displayName": "Microsoft Graph",
                    "servicePrincipalType": "Application",
                },
            ],
            f"servicePrincipals/{sp_id}/oauth2PermissionGrants": [
                {
                    "resourceId": "resource-graph",
                    "resourceDisplayName": "Microsoft Graph",
                    "scope": "Mail.Send Files.ReadWrite.All",
                    "consentType": "AllPrincipals",
                }
            ],
            f"servicePrincipals/{sp_id}/appRoleAssignments": [],
            "servicePrincipals/resource-graph/oauth2PermissionGrants": [],
            "servicePrincipals/resource-graph/appRoleAssignments": [],
        }
    )
    connector = EntraConsentGraphConnector(transport=transport)
    ctx = ConnectorContext(tenant_id="tenant-1")
    candidates = list(connector.scan(ctx))

    invoice = [c for c in candidates if c.external_id == sp_id]
    assert len(invoice) == 1
    cand = invoice[0]
    assert cand.source is DiscoverySource.MICROSOFT_GRAPH
    assert cand.risk_band in (DiscoveryRiskBand.HIGH, DiscoveryRiskBand.CRITICAL)
    assert "blast_radius" in cand.evidence
    assert cand.evidence["blast_radius"]["reachable_resource_count"] >= 1


def test_entra_connector_delta_watch_advances_link():
    transport = FixtureGraphTransport({"servicePrincipals/delta": [{"id": "a"}]})
    connector = EntraConsentGraphConnector(transport=transport)
    first = connector.sweep_delta()
    assert len(first) == 1
    assert connector.delta_link is not None
    second = connector.sweep_delta()  # nothing new after the link advances
    assert second == []


# --------------------------------------------------------------------------- 4. OCSF audit
def test_ocsf_audit_connector_from_cloudtrail():
    records = [
        {
            "eventSource": "bedrock-agentcore.amazonaws.com",
            "eventName": "InvokeAgentRuntime",
            "eventTime": "2026-05-01T10:00:00Z",
            "userIdentity": {"principalId": "AROA:bot", "arn": "arn:aws:sts::1:assumed-role/bot"},
            "resources": [{"ARN": "arn:aws:bedrock-agentcore:us-east-1:1:runtime/invoice-bot-03", "type": "AWS::BedrockAgentCore::Runtime"}],
        },
        {
            "eventSource": "bedrock-agentcore.amazonaws.com",
            "eventName": "InvokeGateway",
            "eventTime": "2026-05-01T10:05:00Z",
            "userIdentity": {"principalId": "AROA:bot"},
            "resources": [{"ARN": "arn:aws:bedrock-agentcore:us-east-1:1:runtime/invoice-bot-03"}],
        },
    ]
    connector = OcsfAuditConnector(source=lambda ctx: records, source_format="cloudtrail")
    ctx = ConnectorContext(tenant_id="tenant-1")
    candidates = list(connector.scan(ctx))
    assert len(candidates) == 1
    cand = candidates[0]
    assert cand.source is DiscoverySource.CLOUD_AUDIT
    assert "invoice-bot-03" in cand.external_id
    assert set(cand.capability_hints.inferred_action_types) == {"invokeagentruntime", "invokegateway"}
    assert cand.evidence["event_count"] == 2


def test_ocsf_audit_connector_from_security_lake_ocsf():
    ocsf_records = [
        {
            "class_uid": 6003,
            "activity_name": "CreateUser",
            "time": "2026-05-02T09:00:00Z",
            "actor": {"user": {"uid": "agent-77", "name": "Provisioner"}},
            "api": {"operation": "CreateUser"},
            "resources": [{"uid": "arn:aws:iam::1:role/provisioner"}],
            "metadata": {"product": {"vendor_name": "AWS", "name": "CloudTrail"}},
        }
    ]
    connector = OcsfAuditConnector(source=lambda ctx: ocsf_records, source_format="ocsf")
    candidates = list(connector.scan(ConnectorContext(tenant_id="tenant-1")))
    assert len(candidates) == 1
    assert candidates[0].confidence >= 0.9  # AUDIT_LOG: cannot suppress that it acted


# --------------------------------------------------------------------------- 5. end-to-end ignition
def test_ignite_maps_estate_counts_and_seals_births():
    """Click Begin -> real scan -> estate registered -> births sealed -> count spoken."""
    from fastapi.testclient import TestClient
    from tex.main import create_app

    app = create_app()
    client = TestClient(app)

    body = client.post("/v1/surface/discovery/ignite?tenant_id=preview-e2e-1").json()
    assert body["already_ignited"] is False
    assert "I'll begin" in body["spoken"]
    assert body["count"] > 0  # the scan actually discovered an estate

    # Engine memory engaged: a behavioural birth was sealed per discovered agent.
    assert app.state.provenance_engine.known_count() >= body["count"]

    # Pull-only count reflects the same estate.
    pull = client.get("/v1/surface/discovery/count?tenant_id=preview-e2e-1").json()
    assert pull["count"] == body["count"]

    # Said once: a second ignite for the same tenant is silent.
    again = client.post("/v1/surface/discovery/ignite?tenant_id=preview-e2e-1").json()
    assert again["already_ignited"] is True
    assert again["spoken"] is None

    # A fresh tenant ignites again (the preview door replays per visit).
    fresh = client.post("/v1/surface/discovery/ignite?tenant_id=preview-e2e-2").json()
    assert fresh["already_ignited"] is False
    assert fresh["count"] > 0


# --------------------------------------------------------------------------- 6. standing system
def test_standing_watch_dormancy_and_held_surfacing_wired():
    """Lifespan start -> scheduler watches the demo tenant, sweeps dormancy,
    and surfaces reconciliation holds to the one /held voice queue."""
    import time
    from fastapi.testclient import TestClient
    from tex.main import create_app

    app = create_app()
    with TestClient(app) as client:  # 'with' triggers lifespan -> scheduler starts
        sched = app.state.scan_scheduler
        assert sched.is_running is True
        assert "demo" in sched.status["tenants"]  # demo seed under standing watch
        time.sleep(0.5)  # let the startup cycle complete

        # (3) reconciliation holds (unbounded surfaces) reach the voice queue
        held = client.get("/v1/surface/discovery/held").json()
        assert held["count"] > 0
        assert any(h["kind"] == "discovery_unbounded_surface" for h in held["held"])

        # (2) the dormancy sweep ran on the cycle
        assert "dormancy" in (sched._last_run_summary or {})

    # building the app (no lifespan) must NOT have started a scan — pure construction
    app2 = create_app()
    assert app2.state.scan_scheduler.is_running is False


def test_preview_ignite_does_not_pollute_held_queue():
    """An ephemeral preview tenant does the initial map only — no holds into
    the shared queue, no enrollment into the perpetual watch."""
    from fastapi.testclient import TestClient
    from tex.main import create_app

    app = create_app()
    client = TestClient(app)  # no lifespan -> scheduler idle
    client.post("/v1/surface/discovery/ignite?tenant_id=preview-no-pollute")
    held = client.get("/v1/surface/discovery/held").json()
    assert held["count"] == 0  # preview never routes holds to the shared voice
    assert "preview-no-pollute" not in app.state.scan_scheduler.status["tenants"]

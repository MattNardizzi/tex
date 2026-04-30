"""
Integration tests for the DiscoveryService.

These exercise the full discovery loop end-to-end against the real
in-memory registry, ledger, and reconciliation engine — only the
connectors are mocks. This is the level at which the discovery
layer is observably "working": candidates flow through, the
registry mutates, the ledger appends, the chain verifies, the
indexes are populated.
"""

from __future__ import annotations

from typing import Iterable

import pytest

from tex.discovery.connectors import (
    AwsBedrockConnector,
    GitHubConnector,
    MCPServerConnector,
    MicrosoftGraphConnector,
    OpenAIConnector,
    SalesforceConnector,
)
from tex.discovery.connectors.base import (
    BaseConnector,
    ConnectorContext,
    ConnectorError,
)
from tex.discovery.reconciliation import ReconciliationEngine
from tex.discovery.service import DiscoveryService, ReconciliationIndex
from tex.domain.agent import (
    AgentEnvironment,
    AgentIdentity,
    AgentLifecycleStatus,
    AgentTrustTier,
    CapabilitySurface,
)
from tex.domain.discovery import (
    CandidateAgent,
    DiscoveredCapabilityHints,
    DiscoveryRiskBand,
    DiscoverySource,
    ReconciliationAction,
)
from tex.stores.agent_registry import InMemoryAgentRegistry
from tex.stores.discovery_ledger import InMemoryDiscoveryLedger


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_service(*connectors) -> tuple[DiscoveryService, InMemoryAgentRegistry, InMemoryDiscoveryLedger]:
    registry = InMemoryAgentRegistry()
    ledger = InMemoryDiscoveryLedger()
    service = DiscoveryService(
        registry=registry,
        ledger=ledger,
        connectors=list(connectors),
    )
    return service, registry, ledger


# ---------------------------------------------------------------------------
# Empty service
# ---------------------------------------------------------------------------


class TestEmptyService:
    def test_scan_with_no_connectors_is_a_clean_no_op(self) -> None:
        service, registry, ledger = _make_service()
        result = service.scan(tenant_id="acme")
        assert result.summary.candidates_seen == 0
        assert result.summary.errors == ()
        assert len(ledger) == 0
        assert len(registry.list_all()) == 0


# ---------------------------------------------------------------------------
# Single-connector flow
# ---------------------------------------------------------------------------


class TestSingleConnectorFlow:
    def test_one_high_confidence_bounded_candidate_lands_in_registry(self) -> None:
        connector = MicrosoftGraphConnector(
            records=[
                {
                    "id": "sales-bot-001",
                    "displayName": "Sales Outreach Bot",
                    "kind": "declarativeAgent",
                    "scopes": ["Mail.Send"],
                    "tenantId": "acme",
                }
            ]
        )
        service, registry, ledger = _make_service(connector)
        result = service.scan(tenant_id="acme")

        assert result.summary.registered_count == 1
        assert len(ledger) == 1
        assert ledger.verify_chain() is True

        agents = registry.list_all()
        assert len(agents) == 1
        agent = agents[0]
        assert agent.lifecycle_status is AgentLifecycleStatus.PENDING
        assert agent.metadata["discovery_source"] == "microsoft_graph"
        assert agent.metadata["discovery_external_id"] == "sales-bot-001"

    def test_idempotent_rescan_does_not_duplicate(self) -> None:
        connector = MicrosoftGraphConnector(
            records=[
                {
                    "id": "bot-001",
                    "displayName": "Bot",
                    "kind": "declarativeAgent",
                    "scopes": ["Mail.Send"],
                    "tenantId": "acme",
                }
            ]
        )
        service, registry, ledger = _make_service(connector)
        service.scan(tenant_id="acme")
        result_2 = service.scan(tenant_id="acme")

        # Second scan finds the same agent, recognizes it, no-ops.
        assert result_2.summary.registered_count == 0
        assert result_2.summary.no_op_count == 1
        # Registry stays at one agent.
        assert len(registry.list_all()) == 1
        # Ledger has two entries (one per scan), and both verify.
        assert len(ledger) == 2
        assert ledger.verify_chain() is True

    def test_widening_surface_drives_drift_update(self) -> None:
        connector = MicrosoftGraphConnector(
            records=[
                {
                    "id": "bot-001",
                    "displayName": "Bot",
                    "kind": "declarativeAgent",
                    "scopes": ["Mail.Send"],
                    "tenantId": "acme",
                }
            ]
        )
        service, registry, _ledger = _make_service(connector)
        service.scan(tenant_id="acme")

        # Now widen the platform-side surface.
        connector.replace_records(
            [
                {
                    "id": "bot-001",
                    "displayName": "Bot",
                    "kind": "declarativeAgent",
                    "scopes": ["Mail.Send", "Files.ReadWrite.All"],
                    "tenantId": "acme",
                }
            ]
        )
        result_2 = service.scan(tenant_id="acme")

        assert result_2.summary.updated_drift_count == 1
        agent = registry.list_all()[0]
        # The capability surface now includes the new tool entries.
        assert "files.readwrite.all" in agent.capability_surface.allowed_tools

    def test_below_threshold_held(self) -> None:
        # Use OpenAI's "no tools" assistant which we score at 0.93
        # confidence by default — too high. Build a custom connector
        # to prove the held branch actually works.
        connector = _LowConfidenceConnector()
        service, registry, ledger = _make_service(connector)
        result = service.scan(tenant_id="acme")
        assert result.summary.no_op_count == 1
        assert result.summary.registered_count == 0
        assert len(registry.list_all()) == 0
        # Ledger still records the no-op so the operator can review.
        assert len(ledger) == 1

    def test_unbounded_surface_held(self) -> None:
        connector = MicrosoftGraphConnector(
            records=[
                {
                    "id": "scary-app",
                    "displayName": "Tenant-wide writer",
                    "kind": "application",
                    "scopes": ["Directory.ReadWrite.All", "Mail.Send"],
                    "tenantId": "acme",
                }
            ]
        )
        service, registry, ledger = _make_service(connector)
        result = service.scan(tenant_id="acme")

        assert result.summary.held_count == 1
        assert result.summary.registered_count == 0
        assert len(registry.list_all()) == 0


# ---------------------------------------------------------------------------
# Multi-connector flow
# ---------------------------------------------------------------------------


class TestMultiConnectorFlow:
    def test_six_connectors_with_mixed_records_aggregate_correctly(self) -> None:
        ms = MicrosoftGraphConnector(
            records=[
                {"id": "ms-1", "displayName": "MS Bot", "kind": "declarativeAgent", "scopes": ["Mail.Send"], "tenantId": "acme"},
            ]
        )
        sf = SalesforceConnector(
            records=[
                {"Id": "sf-1", "Name": "SF Bot", "Type": "EinsteinBot", "IsActive": True, "Permissions": ["sendemail"]},
            ]
        )
        bedrock = AwsBedrockConnector(
            records=[
                {
                    "agentId": "bd-1",
                    "agentName": "Bedrock Agent",
                    "foundationModel": "anthropic.claude-3",
                    "actionGroups": ["lookup"],
                    "knowledgeBases": [],
                    "status": "PREPARED",
                    "environmentTag": "prod",
                    "iamRoleArn": "arn:aws:iam::1:role/x",
                }
            ]
        )
        gh = GitHubConnector(
            records=[
                {"kind": "copilot_seat", "id": 1, "assignee_login": "alice", "plan": "business"},
            ]
        )
        oa = OpenAIConnector(
            records=[
                {"id": "asst_1", "name": "GPT", "model": "gpt-4o", "tools": [{"type": "file_search"}], "metadata": {}},
            ]
        )
        mcp = MCPServerConnector(
            records=[
                {
                    "server_name": "tex-mcp",
                    "server_url": "https://x",
                    "environment": "production",
                    "clients": [
                        {"client_id": "c1", "client_name": "Cursor", "host_kind": "cursor", "tool_names": ["read_file"]}
                    ],
                }
            ]
        )

        service, registry, ledger = _make_service(ms, sf, bedrock, gh, oa, mcp)
        result = service.scan(tenant_id="acme")

        assert result.summary.candidates_seen == 6
        # All six are bounded + high-confidence so they all promote.
        assert result.summary.registered_count == 6
        assert len(registry.list_all()) == 6
        assert ledger.verify_chain() is True


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------


class _ExplodingConnector(BaseConnector):
    def __init__(self) -> None:
        super().__init__(
            source=DiscoverySource.GENERIC,
            name="exploding_mock",
        )

    def _run_scan(self, context: ConnectorContext) -> Iterable[CandidateAgent]:
        raise ConnectorError("auth failed")


class _RaisingUnexpectedConnector(BaseConnector):
    def __init__(self) -> None:
        super().__init__(
            source=DiscoverySource.GENERIC,
            name="unexpected_mock",
        )

    def _run_scan(self, context: ConnectorContext) -> Iterable[CandidateAgent]:
        raise RuntimeError("kaboom")


class TestErrorIsolation:
    def test_one_failing_connector_does_not_kill_scan(self) -> None:
        good = MicrosoftGraphConnector(
            records=[
                {"id": "ok", "displayName": "OK", "kind": "declarativeAgent", "scopes": ["Mail.Send"], "tenantId": "acme"},
            ]
        )
        bad = _ExplodingConnector()

        service, _registry, ledger = _make_service(good, bad)
        result = service.scan(tenant_id="acme")

        assert result.summary.registered_count == 1
        assert len(result.summary.errors) == 1
        assert "exploding_mock" in result.summary.errors[0]
        assert ledger.verify_chain() is True

    def test_unexpected_exception_caught_and_recorded(self) -> None:
        bad = _RaisingUnexpectedConnector()
        service, _registry, _ledger = _make_service(bad)
        result = service.scan(tenant_id="acme")
        assert len(result.summary.errors) == 1
        assert "unexpected" in result.summary.errors[0]


# ---------------------------------------------------------------------------
# Reconciliation index bootstrap
# ---------------------------------------------------------------------------


class TestReconciliationIndexBootstrap:
    def test_bootstrap_picks_up_manually_registered_discovered_agents(self) -> None:
        registry = InMemoryAgentRegistry()
        # Operator manually registers an agent with discovery metadata,
        # mimicking the situation where Tex was deployed AFTER agents
        # were already in production.
        agent = AgentIdentity(
            name="Pre-existing Bot",
            owner="ops@acme.com",
            tenant_id="acme",
            environment=AgentEnvironment.PRODUCTION,
            trust_tier=AgentTrustTier.STANDARD,
            lifecycle_status=AgentLifecycleStatus.ACTIVE,
            metadata={
                "discovery_source": "microsoft_graph",
                "discovery_external_id": "preexisting-001",
                "discovery_risk_band": "LOW",
            },
        )
        registry.save(agent)

        index = ReconciliationIndex(registry=registry)
        assert "microsoft_graph:acme:preexisting-001" in index
        assert index.get_agent_id("microsoft_graph:acme:preexisting-001") == agent.agent_id

    def test_agents_without_discovery_metadata_arent_indexed(self) -> None:
        registry = InMemoryAgentRegistry()
        agent = AgentIdentity(
            name="Manually configured agent",
            owner="ops@acme.com",
            tenant_id="acme",
            environment=AgentEnvironment.PRODUCTION,
            trust_tier=AgentTrustTier.STANDARD,
            lifecycle_status=AgentLifecycleStatus.ACTIVE,
        )
        registry.save(agent)

        index = ReconciliationIndex(registry=registry)
        assert len(index) == 0


# ---------------------------------------------------------------------------
# Helper test fixtures
# ---------------------------------------------------------------------------


class _LowConfidenceConnector(BaseConnector):
    """Emits one CandidateAgent below the auto-register threshold."""

    def __init__(self) -> None:
        super().__init__(
            source=DiscoverySource.GENERIC,
            name="low_conf_mock",
        )

    def _run_scan(self, context: ConnectorContext) -> Iterable[CandidateAgent]:
        yield CandidateAgent(
            source=DiscoverySource.GENERIC,
            tenant_id=context.tenant_id,
            external_id="low-1",
            name="Low confidence candidate",
            confidence=0.5,  # below 0.80 threshold
            risk_band=DiscoveryRiskBand.LOW,
            capability_hints=DiscoveredCapabilityHints(),
        )


# ---------------------------------------------------------------------------
# Connector registration
# ---------------------------------------------------------------------------


class TestConnectorRegistration:
    def test_register_after_construction(self) -> None:
        service, _registry, _ledger = _make_service()
        assert len(service.list_connectors()) == 0
        service.register_connector(MicrosoftGraphConnector())
        assert len(service.list_connectors()) == 1

"""
Tests for the six mock discovery connectors.

These tests verify shape: given a fixture record in the platform's
native shape, each connector emits a CandidateAgent with the right
source, external_id, risk band, capability hints, and surface-
unbounded flag. The fixtures are intentionally small and structural;
they are not meant to mirror live API output exactly, only the
fields the connector reads.

When real connectors that hit live APIs replace these mocks, the
same tests should pass against fixture responses captured from the
real APIs.
"""

from __future__ import annotations

from typing import Any

import pytest

from tex.discovery.connectors import (
    AwsBedrockConnector,
    ConnectorContext,
    GitHubConnector,
    MCPServerConnector,
    MicrosoftGraphConnector,
    OpenAIConnector,
    SalesforceConnector,
)
from tex.domain.agent import AgentEnvironment
from tex.domain.discovery import DiscoveryRiskBand, DiscoverySource


def _ctx(tenant: str = "acme") -> ConnectorContext:
    return ConnectorContext(tenant_id=tenant)


# ---------------------------------------------------------------------------
# Microsoft Graph
# ---------------------------------------------------------------------------


class TestMicrosoftGraphConnector:
    def _record(self, **overrides: Any) -> dict[str, Any]:
        base: dict[str, Any] = {
            "id": "azure-obj-001",
            "displayName": "Sales Outreach Bot",
            "owner": "ops@acme.com",
            "kind": "declarativeAgent",
            "scopes": ["Mail.Send", "Files.ReadWrite.All"],
            "tenantId": "acme",
            "lastSignInDateTime": "2026-04-15T12:00:00Z",
        }
        base.update(overrides)
        return base

    def test_basic_record_emits_one_candidate(self) -> None:
        c = MicrosoftGraphConnector(records=[self._record()])
        cands = list(c.scan(_ctx()))
        assert len(cands) == 1
        assert cands[0].source is DiscoverySource.MICROSOFT_GRAPH
        assert cands[0].external_id == "azure-obj-001"

    def test_two_high_risk_scopes_yield_high_band(self) -> None:
        c = MicrosoftGraphConnector(records=[self._record()])
        cand = next(iter(c.scan(_ctx())))
        assert cand.risk_band is DiscoveryRiskBand.HIGH

    def test_critical_scope_yields_critical_band_and_unbounded(self) -> None:
        c = MicrosoftGraphConnector(
            records=[self._record(scopes=["Directory.ReadWrite.All", "Mail.Send"])]
        )
        cand = next(iter(c.scan(_ctx())))
        assert cand.risk_band is DiscoveryRiskBand.CRITICAL
        assert cand.capability_hints.surface_unbounded is True

    def test_no_high_risk_scopes_yield_low_band(self) -> None:
        c = MicrosoftGraphConnector(
            records=[self._record(scopes=["User.Read"])]
        )
        cand = next(iter(c.scan(_ctx())))
        assert cand.risk_band is DiscoveryRiskBand.LOW

    def test_declarative_agent_has_higher_confidence(self) -> None:
        c = MicrosoftGraphConnector(records=[self._record(kind="application")])
        cand_app = next(iter(c.scan(_ctx())))

        c = MicrosoftGraphConnector(records=[self._record(kind="declarativeAgent")])
        cand_decl = next(iter(c.scan(_ctx())))

        assert cand_decl.confidence > cand_app.confidence

    def test_evidence_contains_redacted_scopes(self) -> None:
        c = MicrosoftGraphConnector(records=[self._record()])
        cand = next(iter(c.scan(_ctx())))
        assert "scopes" in cand.evidence
        assert "mail.send" in cand.evidence["scopes"]


# ---------------------------------------------------------------------------
# Salesforce
# ---------------------------------------------------------------------------


class TestSalesforceConnector:
    def _record(self, **overrides: Any) -> dict[str, Any]:
        base: dict[str, Any] = {
            "Id": "001A0000xyz",
            "Name": "Einstein Lead Qualifier",
            "OwnerEmail": "einstein-admin@acme.com",
            "Type": "EinsteinBot",
            "IsActive": True,
            "Permissions": ["sendemail"],
            "LastModifiedDate": "2026-04-20T08:00:00Z",
        }
        base.update(overrides)
        return base

    def test_basic_emits_candidate(self) -> None:
        cands = list(
            SalesforceConnector(records=[self._record()]).scan(_ctx())
        )
        assert len(cands) == 1
        assert cands[0].source is DiscoverySource.SALESFORCE
        assert cands[0].owner_hint == "einstein-admin@acme.com"

    def test_modify_all_data_is_critical_and_unbounded(self) -> None:
        cands = list(
            SalesforceConnector(
                records=[self._record(Permissions=["modifyalldata"])]
            ).scan(_ctx())
        )
        assert cands[0].risk_band is DiscoveryRiskBand.CRITICAL
        assert cands[0].capability_hints.surface_unbounded is True

    def test_inactive_lowers_confidence(self) -> None:
        active = next(
            iter(SalesforceConnector(records=[self._record(IsActive=True)]).scan(_ctx()))
        )
        inactive = next(
            iter(
                SalesforceConnector(records=[self._record(IsActive=False)]).scan(_ctx())
            )
        )
        assert inactive.confidence < active.confidence

    def test_sandbox_record_yields_sandbox_environment(self) -> None:
        cand = next(
            iter(
                SalesforceConnector(
                    records=[self._record(SandboxName="QA-Sandbox")]
                ).scan(_ctx())
            )
        )
        assert cand.environment_hint is AgentEnvironment.SANDBOX


# ---------------------------------------------------------------------------
# AWS Bedrock
# ---------------------------------------------------------------------------


class TestAwsBedrockConnector:
    def _record(self, **overrides: Any) -> dict[str, Any]:
        base: dict[str, Any] = {
            "agentId": "bedrock-agent-001",
            "agentName": "Customer Support Agent",
            "foundationModel": "anthropic.claude-3-7-sonnet-20250219-v1:0",
            "actionGroups": ["lookup_order", "send_email"],
            "knowledgeBases": ["kb-faq-001"],
            "status": "PREPARED",
            "createdAt": "2026-03-01T00:00:00Z",
            "updatedAt": "2026-04-25T00:00:00Z",
            "environmentTag": "prod",
            "iamRoleArn": "arn:aws:iam::123456789012:role/bedrock-agent",
        }
        base.update(overrides)
        return base

    def test_basic_emits_candidate(self) -> None:
        cands = list(AwsBedrockConnector(records=[self._record()]).scan(_ctx()))
        assert len(cands) == 1
        assert cands[0].source is DiscoverySource.AWS_BEDROCK
        assert cands[0].model_provider_hint == "anthropic"

    def test_open_iam_role_is_critical_and_unbounded(self) -> None:
        cand = next(
            iter(
                AwsBedrockConnector(
                    records=[self._record(hasOpenScopedRole=True)]
                ).scan(_ctx())
            )
        )
        assert cand.risk_band is DiscoveryRiskBand.CRITICAL
        assert cand.capability_hints.surface_unbounded is True

    def test_many_action_groups_drives_high_band(self) -> None:
        cand = next(
            iter(
                AwsBedrockConnector(
                    records=[
                        self._record(
                            actionGroups=["a", "b", "c", "d", "e"],
                        )
                    ]
                ).scan(_ctx())
            )
        )
        assert cand.risk_band is DiscoveryRiskBand.HIGH

    def test_environment_tag_maps_correctly(self) -> None:
        for tag, expected in [
            ("prod", AgentEnvironment.PRODUCTION),
            ("staging", AgentEnvironment.STAGING),
            ("dev", AgentEnvironment.SANDBOX),
        ]:
            cand = next(
                iter(
                    AwsBedrockConnector(
                        records=[self._record(environmentTag=tag)]
                    ).scan(_ctx())
                )
            )
            assert cand.environment_hint is expected

    def test_knowledge_bases_become_data_scopes(self) -> None:
        cand = next(
            iter(
                AwsBedrockConnector(
                    records=[self._record(knowledgeBases=["kb1", "kb2"])]
                ).scan(_ctx())
            )
        )
        assert "kb1" in cand.capability_hints.inferred_data_scopes
        assert "kb2" in cand.capability_hints.inferred_data_scopes


# ---------------------------------------------------------------------------
# GitHub
# ---------------------------------------------------------------------------


class TestGitHubConnector:
    def test_copilot_seat_yields_low_risk_coding_agent(self) -> None:
        record = {
            "kind": "copilot_seat",
            "id": 4242,
            "assignee_login": "alice-dev",
            "assignee_email": "alice@acme.com",
            "org": "acme",
            "plan": "business",
            "last_activity_at": "2026-04-26T12:00:00Z",
        }
        cand = next(iter(GitHubConnector(records=[record]).scan(_ctx())))
        assert cand.risk_band is DiscoveryRiskBand.LOW
        assert "coding_agent" in cand.tags
        assert cand.external_id == "copilot-seat-4242"

    def test_app_with_admin_secrets_is_critical_and_unbounded(self) -> None:
        record = {
            "kind": "app_installation",
            "id": 9001,
            "app_slug": "shadow-ai-bot",
            "target": "organization",
            "permissions": {"secrets": "admin", "contents": "write"},
            "events": ["push"],
        }
        cand = next(iter(GitHubConnector(records=[record]).scan(_ctx())))
        assert cand.risk_band is DiscoveryRiskBand.CRITICAL
        assert cand.capability_hints.surface_unbounded is True

    def test_app_with_low_permissions_is_low_risk(self) -> None:
        record = {
            "kind": "app_installation",
            "id": 9002,
            "app_slug": "harmless-checker",
            "target": "organization",
            "permissions": {"metadata": "read"},
        }
        cand = next(iter(GitHubConnector(records=[record]).scan(_ctx())))
        assert cand.risk_band is DiscoveryRiskBand.LOW

    def test_suspended_app_lowers_confidence(self) -> None:
        active_record = {
            "kind": "app_installation",
            "id": 1,
            "app_slug": "x",
            "permissions": {"metadata": "read"},
        }
        suspended_record = {
            **active_record,
            "id": 2,
            "suspended_at": "2026-04-01T00:00:00Z",
        }
        active = next(iter(GitHubConnector(records=[active_record]).scan(_ctx())))
        suspended = next(iter(GitHubConnector(records=[suspended_record]).scan(_ctx())))
        assert suspended.confidence < active.confidence


# ---------------------------------------------------------------------------
# OpenAI
# ---------------------------------------------------------------------------


class TestOpenAIConnector:
    def _record(self, **overrides: Any) -> dict[str, Any]:
        base: dict[str, Any] = {
            "id": "asst_abc123",
            "name": "Customer Support GPT",
            "model": "gpt-4o",
            "tools": [{"type": "file_search"}],
            "file_ids": ["file-1"],
            "created_at": 1_710_000_000,
            "metadata": {"owner": "support@acme.com"},
        }
        base.update(overrides)
        return base

    def test_simple_assistant_is_low_risk(self) -> None:
        cand = next(iter(OpenAIConnector(records=[self._record()]).scan(_ctx())))
        assert cand.risk_band is DiscoveryRiskBand.LOW

    def test_code_interp_plus_function_is_critical_and_unbounded(self) -> None:
        record = self._record(
            tools=[
                {"type": "code_interpreter"},
                {"type": "function", "function": {"name": "deploy_to_prod"}},
            ]
        )
        cand = next(iter(OpenAIConnector(records=[record]).scan(_ctx())))
        assert cand.risk_band is DiscoveryRiskBand.CRITICAL
        assert cand.capability_hints.surface_unbounded is True
        assert "deploy_to_prod" in cand.capability_hints.inferred_action_types

    def test_owner_hint_pulled_from_metadata(self) -> None:
        cand = next(iter(OpenAIConnector(records=[self._record()]).scan(_ctx())))
        assert cand.owner_hint == "support@acme.com"

    def test_code_interpreter_alone_is_high(self) -> None:
        record = self._record(tools=[{"type": "code_interpreter"}])
        cand = next(iter(OpenAIConnector(records=[record]).scan(_ctx())))
        assert cand.risk_band is DiscoveryRiskBand.HIGH


# ---------------------------------------------------------------------------
# MCP server
# ---------------------------------------------------------------------------


class TestMCPServerConnector:
    def _record(self, **overrides: Any) -> dict[str, Any]:
        base: dict[str, Any] = {
            "server_name": "tex-mcp",
            "server_url": "https://mcp.acme.com",
            "environment": "production",
            "clients": [
                {
                    "client_id": "cursor-1",
                    "client_name": "Cursor",
                    "client_version": "0.42",
                    "host_kind": "cursor",
                    "tool_names": ["read_file", "write_file", "send_email"],
                    "resource_uris": ["repo://acme/website"],
                    "last_seen_at": "2026-04-26T15:00:00Z",
                }
            ],
        }
        base.update(overrides)
        return base

    def test_one_record_expands_to_one_candidate_per_client(self) -> None:
        record = self._record(
            clients=[
                {"client_id": "c1", "client_name": "Cursor", "host_kind": "cursor"},
                {
                    "client_id": "c2",
                    "client_name": "Claude Desktop",
                    "host_kind": "claude_desktop",
                },
            ]
        )
        cands = list(MCPServerConnector(records=[record]).scan(_ctx()))
        assert len(cands) == 2

    def test_aggressive_tool_mix_is_critical(self) -> None:
        record = self._record(
            clients=[
                {
                    "client_id": "x",
                    "client_name": "X",
                    "host_kind": "cursor",
                    "tool_names": ["write_file", "send_email", "deploy_to_prod"],
                }
            ]
        )
        cand = next(iter(MCPServerConnector(records=[record]).scan(_ctx())))
        assert cand.risk_band is DiscoveryRiskBand.CRITICAL

    def test_external_id_combines_server_and_client(self) -> None:
        cand = next(iter(MCPServerConnector(records=[self._record()]).scan(_ctx())))
        assert cand.external_id.startswith("tex-mcp:")

    def test_inferred_mcp_servers_set(self) -> None:
        cand = next(iter(MCPServerConnector(records=[self._record()]).scan(_ctx())))
        assert cand.capability_hints.inferred_mcp_servers == ("tex-mcp",)


# ---------------------------------------------------------------------------
# BaseConnector behavior shared by all subclasses
# ---------------------------------------------------------------------------


class TestBaseConnectorContractEnforcement:
    def test_max_candidates_caps_iteration(self) -> None:
        records = [
            {
                "id": f"id-{i}",
                "displayName": f"Bot {i}",
                "kind": "application",
                "scopes": [],
                "tenantId": "acme",
            }
            for i in range(10)
        ]
        connector = MicrosoftGraphConnector(records=records)
        ctx = ConnectorContext(tenant_id="acme", max_candidates=3)
        cands = list(connector.scan(ctx))
        assert len(cands) == 3

    def test_name_filter_filters_case_insensitively(self) -> None:
        records = [
            {"id": "a", "displayName": "Sales Bot", "kind": "application", "scopes": [], "tenantId": "acme"},
            {"id": "b", "displayName": "Marketing Bot", "kind": "application", "scopes": [], "tenantId": "acme"},
        ]
        connector = MicrosoftGraphConnector(records=records)
        ctx = ConnectorContext(tenant_id="acme", name_filter="sales")
        cands = list(connector.scan(ctx))
        assert len(cands) == 1
        assert cands[0].name == "Sales Bot"

    def test_replace_records_swaps_fixture(self) -> None:
        connector = MicrosoftGraphConnector()
        assert list(connector.scan(_ctx())) == []
        connector.replace_records(
            [{"id": "x", "displayName": "X", "kind": "application", "scopes": [], "tenantId": "acme"}]
        )
        assert len(list(connector.scan(_ctx()))) == 1

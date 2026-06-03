"""
Tests for the Slack mock discovery connector.

Slack is the second of the two source we ship with both a mock and a
live implementation. Tests follow the same shape conventions as the
other connector tests: a small fixture-shaped dict, a scan, and
assertions on the emitted CandidateAgent.
"""

from __future__ import annotations

from typing import Any

import pytest

from tex.discovery.connectors import ConnectorContext, SlackConnector
from tex.domain.discovery import DiscoveryRiskBand, DiscoverySource


def _ctx(tenant: str = "acme") -> ConnectorContext:
    return ConnectorContext(tenant_id=tenant)


def _record(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "id": "B0LANXQ001",
        "name": "support-bot",
        "real_name": "Support Bot",
        "team_id": "T0LANXQ",
        "app_id": "A0LANXQ",
        "scopes": ["chat:write", "channels:read"],
        "is_workflow_bot": False,
        "updated": 1_700_000_000,
        "metadata": {"owner": "ops@acme.com"},
    }
    base.update(overrides)
    return base


class TestSlackMockConnector:
    def test_basic_record_emits_one_candidate(self) -> None:
        c = SlackConnector(records=[_record()])
        cands = list(c.scan(_ctx()))
        assert len(cands) == 1
        assert cands[0].source is DiscoverySource.SLACK
        assert cands[0].external_id == "B0LANXQ001"

    def test_write_only_yields_medium(self) -> None:
        c = SlackConnector(records=[_record(scopes=["chat:write"])])
        cand = next(iter(c.scan(_ctx())))
        assert cand.risk_band is DiscoveryRiskBand.MEDIUM

    def test_write_plus_sensitive_read_yields_high(self) -> None:
        c = SlackConnector(
            records=[_record(scopes=["chat:write", "channels:history"])]
        )
        cand = next(iter(c.scan(_ctx())))
        assert cand.risk_band is DiscoveryRiskBand.HIGH

    def test_admin_scope_yields_critical_and_unbounded(self) -> None:
        c = SlackConnector(
            records=[_record(scopes=["admin", "chat:write"])]
        )
        cand = next(iter(c.scan(_ctx())))
        assert cand.risk_band is DiscoveryRiskBand.CRITICAL
        assert cand.capability_hints.surface_unbounded is True
        assert "admin_scope" in cand.tags

    def test_read_only_yields_low(self) -> None:
        c = SlackConnector(records=[_record(scopes=["channels:read"])])
        cand = next(iter(c.scan(_ctx())))
        assert cand.risk_band is DiscoveryRiskBand.LOW

    def test_workflow_builder_bot_classified(self) -> None:
        c = SlackConnector(records=[_record(is_workflow_bot=True, scopes=[])])
        cand = next(iter(c.scan(_ctx())))
        assert cand.framework_hint == "slack_workflow_builder"
        # Even with no scopes, a workflow bot is still a high-confidence
        # candidate because the platform tells us it's an agent.
        assert cand.confidence >= 0.9

    def test_owner_hint_pulled_from_metadata(self) -> None:
        c = SlackConnector(records=[_record()])
        cand = next(iter(c.scan(_ctx())))
        assert cand.owner_hint == "ops@acme.com"

    def test_evidence_carries_app_id_and_scopes(self) -> None:
        c = SlackConnector(records=[_record()])
        cand = next(iter(c.scan(_ctx())))
        assert cand.evidence["app_id"] == "A0LANXQ"
        assert "chat:write" in cand.evidence["scopes"]

    def test_replace_records_swaps_fixture(self) -> None:
        c = SlackConnector(records=[_record()])
        c.replace_records([_record(id="B0LANXQ002", name="other")])
        cands = list(c.scan(_ctx()))
        assert len(cands) == 1
        assert cands[0].external_id == "B0LANXQ002"

    def test_inferred_action_types_when_write_scope_present(self) -> None:
        c = SlackConnector(records=[_record(scopes=["chat:write"])])
        cand = next(iter(c.scan(_ctx())))
        assert "send_message" in cand.capability_hints.inferred_action_types

    def test_no_action_types_when_no_write_scope(self) -> None:
        c = SlackConnector(records=[_record(scopes=["channels:read"])])
        cand = next(iter(c.scan(_ctx())))
        assert cand.capability_hints.inferred_action_types == tuple()

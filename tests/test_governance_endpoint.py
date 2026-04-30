"""
Tests for the governance-state endpoint.

The endpoint at GET /v1/agents/governance is the headline output of
the dual-source discovery layer. These tests verify the four-state
matrix (GOVERNED / UNGOVERNED / PARTIAL / UNKNOWN) by setting up
each branch independently:

  GOVERNED  — agent registered AND adjudicated AND externally observed
  UNGOVERNED — externally observed but never adjudicated; ALSO covers
               candidates held by reconciliation that never became an
               AgentIdentity
  PARTIAL   — adjudicated (auto-registered by the gate) without any
              external connector finding
  UNKNOWN   — registered manually with no external observation and no
              adjudication traffic

The endpoint also returns a coverage_root_sha256 + signed HMAC, both
of which are deterministic given the same registry/ledger state. The
tests assert determinism across two calls.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from tex.discovery.connectors import ConnectorContext
from tex.main import build_runtime, create_app


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def runtime(tmp_path):
    evidence_path = tmp_path / "evidence.jsonl"
    return build_runtime(evidence_path=evidence_path)


@pytest.fixture
def client(runtime) -> TestClient:
    return TestClient(create_app(runtime=runtime))


# ---------------------------------------------------------------------------
# Empty system
# ---------------------------------------------------------------------------


class TestGovernanceEmptySystem:
    def test_empty_system_returns_zero_counts(self, client: TestClient) -> None:
        r = client.get("/v1/agents/governance")
        assert r.status_code == 200
        body = r.json()
        assert body["counts"]["total_agents"] == 0
        assert body["counts"]["governed"] == 0
        assert body["counts"]["ungoverned"] == 0
        assert body["counts"]["partial"] == 0
        assert body["counts"]["unknown"] == 0
        assert body["agents"] == []
        # Even on an empty system the coverage root and signature
        # should be present so the artifact is uniformly shaped.
        assert isinstance(body["coverage_root_sha256"], str)
        assert isinstance(body["signature_hmac_sha256"], str)
        assert len(body["coverage_root_sha256"]) == 64
        assert len(body["signature_hmac_sha256"]) == 64


# ---------------------------------------------------------------------------
# UNKNOWN: registered, no adjudication, no discovery
# ---------------------------------------------------------------------------


class TestUnknownState:
    def test_manually_registered_with_no_traffic_is_unknown(
        self, client: TestClient
    ) -> None:
        r = client.post(
            "/v1/agents",
            json={"name": "QuietBot", "owner": "m"},
        )
        assert r.status_code == 201

        r = client.get("/v1/agents/governance")
        body = r.json()
        assert body["counts"]["total_agents"] == 1
        assert body["counts"]["unknown"] == 1
        agent_row = body["agents"][0]
        assert agent_row["governance_state"] == "UNKNOWN"
        assert agent_row["externally_observed"] is False
        assert agent_row["adjudicated"] is False
        assert agent_row["decision_count"] == 0


# ---------------------------------------------------------------------------
# UNGOVERNED via held discovery candidate (never registered)
# ---------------------------------------------------------------------------


class TestUngovernedHeld:
    def test_held_candidate_appears_as_ghost_ungoverned_row(
        self, runtime, client: TestClient
    ) -> None:
        # Configure the OpenAI mock connector with a record that the
        # reconciliation engine will hold (low confidence). The
        # connector emits 0.93 confidence so we instead use Salesforce
        # mock with explicit ambiguous flag, OR we pick a record that
        # the engine treats as ambiguous because surface_unbounded.
        #
        # Easiest way: feed OpenAI a record with code_interpreter +
        # function (CRITICAL + surface_unbounded), which engine holds
        # as AMBIGUOUS rather than auto-promoting.
        for connector in runtime.discovery_service.list_connectors():
            if connector.name == "openai_mock":
                connector.replace_records(
                    [
                        {
                            "id": "asst_held",
                            "name": "Power Assistant",
                            "model": "gpt-4o",
                            "tools": [
                                {"type": "code_interpreter"},
                                {
                                    "type": "function",
                                    "function": {"name": "exec_shell"},
                                },
                            ],
                            "created_at": 1_700_000_000,
                        }
                    ]
                )

        r = client.post("/v1/discovery/scan", json={"tenant_id": "acme"})
        assert r.status_code == 200
        body = r.json()
        # Should be held, not registered.
        assert body["summary"]["registered_count"] == 0
        assert body["summary"]["held_count"] == 1

        r = client.get("/v1/agents/governance")
        body = r.json()
        # One ghost row from the held candidate.
        assert body["counts"]["total_agents"] == 1
        assert body["counts"]["ungoverned"] == 1
        ghost = body["agents"][0]
        assert ghost["governance_state"] == "UNGOVERNED"
        assert ghost["externally_observed"] is True
        assert ghost["adjudicated"] is False
        assert ghost["agent_id"] is None
        assert ghost["discovery_source"] == "openai"
        assert ghost["external_id"] == "asst_held"


# ---------------------------------------------------------------------------
# GOVERNED: scan promotes an agent + adjudication produces ledger entries
# ---------------------------------------------------------------------------


class TestGovernedState:
    def test_promoted_then_adjudicated_is_governed(
        self, runtime, client: TestClient
    ) -> None:
        # Use a Microsoft Graph fixture (auto-promotes cleanly).
        for connector in runtime.discovery_service.list_connectors():
            if connector.name == "microsoft_graph_mock":
                connector.replace_records(
                    [
                        {
                            "id": "discovered-001",
                            "displayName": "Promoted Bot",
                            "kind": "declarativeAgent",
                            "scopes": ["Mail.Send"],
                            "tenantId": "acme",
                            "owner": "ops@acme.com",
                        }
                    ]
                )

        r = client.post("/v1/discovery/scan", json={"tenant_id": "acme"})
        assert r.status_code == 200
        promoted_agent_id = None
        body = r.json()
        for entry in body["entries"]:
            if entry.get("resulting_agent_id"):
                promoted_agent_id = entry["resulting_agent_id"]
                break
        assert promoted_agent_id is not None

        # Drive an evaluation referencing this agent_id so the action
        # ledger gets a row. We submit an evaluation request that
        # carries the agent_identity block pointing at the promoted
        # agent.
        eval_payload = {
            "request_id": "00000000-0000-0000-0000-000000000001",
            "session_id": "sess-1",
            "action_type": "send_message",
            "content": "Hello world",
            "channel": "email",
            "environment": "production",
            "agent_identity": {
                "agent_id": promoted_agent_id,
                "tenant_id": "acme",
            },
        }
        r = client.post("/evaluate", json=eval_payload)
        # Evaluation may PERMIT or ABSTAIN depending on default policy.
        # All we need is that it produced a ledger entry.
        assert r.status_code == 200

        r = client.get("/v1/agents/governance")
        body = r.json()
        # The promoted agent should now be GOVERNED.
        states = {a["agent_id"]: a["governance_state"] for a in body["agents"] if a["agent_id"]}
        assert states.get(promoted_agent_id) == "GOVERNED"
        assert body["counts"]["governed"] >= 1


# ---------------------------------------------------------------------------
# PARTIAL: adjudication-derived registration, no discovery scan
# ---------------------------------------------------------------------------


class TestPartialState:
    def test_adjudication_only_agent_is_partial(
        self, client: TestClient
    ) -> None:
        # Send an evaluation with an external_agent_id but no prior
        # registry entry. The gate should auto-register it as
        # adjudication_derived. With no discovery scan ever run, the
        # agent is PARTIAL.
        eval_payload = {
            "request_id": "00000000-0000-0000-0000-000000000002",
            "session_id": "sess-p",
            "action_type": "send_message",
            "content": "Hello partial world",
            "channel": "slack",
            "environment": "production",
            "agent_identity": {
                "external_agent_id": "auto-agent-001",
                "agent_name": "Auto Agent One",
                "agent_type": "slack_bot",
                "tenant_id": "acme",
            },
        }
        r = client.post("/evaluate", json=eval_payload)
        assert r.status_code == 200

        r = client.get("/v1/agents/governance")
        body = r.json()
        partials = [a for a in body["agents"] if a["governance_state"] == "PARTIAL"]
        assert len(partials) == 1
        row = partials[0]
        assert row["adjudicated"] is True
        # Adjudication-derived agents have the discovery_mode marker.
        assert row["discovery_mode"] == "adjudication_derived"


# ---------------------------------------------------------------------------
# Determinism + signature
# ---------------------------------------------------------------------------


class TestDeterminism:
    def test_two_calls_with_same_state_return_same_root(
        self, client: TestClient
    ) -> None:
        client.post("/v1/agents", json={"name": "DetBot", "owner": "m"})
        r1 = client.get("/v1/agents/governance")
        r2 = client.get("/v1/agents/governance")
        body1 = r1.json()
        body2 = r2.json()
        assert body1["coverage_root_sha256"] == body2["coverage_root_sha256"]
        assert body1["signature_hmac_sha256"] == body2["signature_hmac_sha256"]

    def test_state_change_changes_root(self, client: TestClient) -> None:
        client.post("/v1/agents", json={"name": "BotA", "owner": "m"})
        r1 = client.get("/v1/agents/governance")
        client.post("/v1/agents", json={"name": "BotB", "owner": "m"})
        r2 = client.get("/v1/agents/governance")
        assert r1.json()["coverage_root_sha256"] != r2.json()["coverage_root_sha256"]


# ---------------------------------------------------------------------------
# High-risk metrics
# ---------------------------------------------------------------------------


class TestHighRiskMetrics:
    def test_high_risk_ungoverned_counted_separately(
        self, runtime, client: TestClient
    ) -> None:
        # Hold a CRITICAL OpenAI candidate so it ends up UNGOVERNED.
        for connector in runtime.discovery_service.list_connectors():
            if connector.name == "openai_mock":
                connector.replace_records(
                    [
                        {
                            "id": "asst_critical",
                            "name": "Power",
                            "model": "gpt-4o",
                            "tools": [
                                {"type": "code_interpreter"},
                                {"type": "function", "function": {"name": "x"}},
                            ],
                            "created_at": 1_700_000_000,
                        }
                    ]
                )
        client.post("/v1/discovery/scan", json={"tenant_id": "acme"})

        r = client.get("/v1/agents/governance")
        body = r.json()
        # Held CRITICAL candidate must show up as both high_risk_total
        # and high_risk_ungoverned.
        assert body["counts"]["high_risk_total"] >= 1
        assert body["counts"]["high_risk_ungoverned"] >= 1

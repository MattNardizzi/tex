"""
Tests for the discovery HTTP routes.

These exercise the full FastAPI surface end-to-end against the real
TexRuntime built by build_runtime, with the default mock connectors
populated via fixtures. We verify route shape, status codes, error
paths (503 when service is missing), and the round-trip from
POST /v1/discovery/scan into GET /v1/discovery/ledger.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from tex.main import build_runtime, create_app


@pytest.fixture
def runtime_with_records(tmp_path):
    """Runtime where the Microsoft Graph mock has one fixture record."""
    evidence_path = tmp_path / "evidence.jsonl"
    runtime = build_runtime(evidence_path=evidence_path)

    # Replace the empty mock with one fixture record so a scan
    # produces output.
    for connector in runtime.discovery_service.list_connectors():
        if connector.name == "microsoft_graph_mock":
            connector.replace_records(  # type: ignore[attr-defined]
                [
                    {
                        "id": "discovered-001",
                        "displayName": "Discovered Bot",
                        "kind": "declarativeAgent",
                        "scopes": ["Mail.Send"],
                        "tenantId": "acme",
                        "owner": "ops@acme.com",
                    }
                ]
            )
    return runtime


@pytest.fixture
def client(runtime_with_records) -> TestClient:
    app = create_app(runtime=runtime_with_records)
    return TestClient(app)


# ---------------------------------------------------------------------------
# /connectors
# ---------------------------------------------------------------------------


class TestListConnectors:
    def test_lists_all_six_default_connectors(self, client: TestClient) -> None:
        r = client.get("/v1/discovery/connectors")
        assert r.status_code == 200
        body = r.json()
        names = {c["name"] for c in body["connectors"]}
        # All six default mocks are present.
        assert "microsoft_graph_mock" in names
        assert "salesforce_mock" in names
        assert "aws_bedrock_mock" in names
        assert "github_mock" in names
        assert "openai_mock" in names
        assert "mcp_server_mock" in names


# ---------------------------------------------------------------------------
# /scan
# ---------------------------------------------------------------------------


class TestScan:
    def test_scan_returns_summary_and_entries(self, client: TestClient) -> None:
        r = client.post("/v1/discovery/scan", json={"tenant_id": "acme"})
        assert r.status_code == 200
        body = r.json()
        assert body["summary"]["candidates_seen"] == 1
        assert body["summary"]["registered_count"] == 1
        assert len(body["entries"]) == 1
        assert body["entries"][0]["source"] == "microsoft_graph"

    def test_invalid_tenant_id_rejected(self, client: TestClient) -> None:
        r = client.post("/v1/discovery/scan", json={"tenant_id": ""})
        assert r.status_code == 422

    def test_scan_idempotent_via_api(self, client: TestClient) -> None:
        client.post("/v1/discovery/scan", json={"tenant_id": "acme"})
        r2 = client.post("/v1/discovery/scan", json={"tenant_id": "acme"})
        body = r2.json()
        # Second scan: zero new registrations, one no-op.
        assert body["summary"]["registered_count"] == 0
        assert body["summary"]["no_op_count"] == 1


# ---------------------------------------------------------------------------
# /ledger
# ---------------------------------------------------------------------------


class TestLedger:
    def test_ledger_paginates(self, client: TestClient) -> None:
        client.post("/v1/discovery/scan", json={"tenant_id": "acme"})
        client.post("/v1/discovery/scan", json={"tenant_id": "acme"})

        r = client.get("/v1/discovery/ledger?limit=1")
        body = r.json()
        assert r.status_code == 200
        assert len(body["entries"]) == 1
        assert body["total"] == 2

        r2 = client.get("/v1/discovery/ledger?limit=10&offset=1")
        body2 = r2.json()
        assert len(body2["entries"]) == 1
        assert body2["entries"][0]["sequence"] == 1

    def test_ledger_verify_chain(self, client: TestClient) -> None:
        client.post("/v1/discovery/scan", json={"tenant_id": "acme"})
        r = client.get("/v1/discovery/ledger/verify")
        body = r.json()
        assert body["is_valid"] is True
        assert body["record_count"] == 1


# ---------------------------------------------------------------------------
# /findings/{key} and /agent/{id}
# ---------------------------------------------------------------------------


class TestFindingsByKey:
    def test_lookup_by_reconciliation_key(self, client: TestClient) -> None:
        client.post("/v1/discovery/scan", json={"tenant_id": "acme"})
        key = "microsoft_graph:acme:discovered-001"
        r = client.get(f"/v1/discovery/findings/{key}")
        assert r.status_code == 200
        body = r.json()
        assert body["total"] == 1
        assert body["entries"][0]["reconciliation_key"] == key

    def test_lookup_by_agent_id(self, client: TestClient) -> None:
        scan_body = client.post(
            "/v1/discovery/scan", json={"tenant_id": "acme"}
        ).json()
        agent_id = scan_body["entries"][0]["resulting_agent_id"]
        assert agent_id is not None
        r = client.get(f"/v1/discovery/agent/{agent_id}")
        assert r.status_code == 200
        body = r.json()
        assert body["total"] == 1
        assert body["entries"][0]["resulting_agent_id"] == agent_id


# ---------------------------------------------------------------------------
# 503 when discovery isn't wired (defensive)
# ---------------------------------------------------------------------------


class TestServiceUnavailable:
    def test_503_when_service_not_attached(self, tmp_path) -> None:
        from fastapi import FastAPI

        from tex.api.discovery_routes import build_discovery_router

        # Build a bare FastAPI app with the router but no service
        # wired in. The route should return 503 instead of crashing.
        app = FastAPI()
        app.include_router(build_discovery_router())
        client = TestClient(app)
        r = client.get("/v1/discovery/connectors")
        assert r.status_code == 503

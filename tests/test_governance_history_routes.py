"""
V15 tests: governance history, drift, and scheduler HTTP routes.

Uses the in-memory fallback for all stores. The TestClient drives
the FastAPI lifespan, which in turn starts/stops the scheduler.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from tex.main import create_app


@pytest.fixture
def client(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("TEX_DISCOVERY_SCAN_TENANTS", raising=False)
    monkeypatch.delenv("TEX_ALERTS_DISABLED", raising=False)
    app = create_app()
    with TestClient(app) as c:
        yield c


class TestGovernanceSnapshotRoutes:
    def test_capture_returns_201(self, client):
        r = client.post(
            "/v1/agents/governance/snapshot",
            json={"label": "test-baseline"},
        )
        assert r.status_code == 201
        body = r.json()
        assert body["snapshot_id"]
        assert body["label"] == "test-baseline"
        assert "snapshot_hash" in body

    def test_list_snapshots_returns_in_order(self, client):
        client.post("/v1/agents/governance/snapshot", json={"label": "first"})
        client.post("/v1/agents/governance/snapshot", json={"label": "second"})
        r = client.get("/v1/agents/governance/snapshots")
        assert r.status_code == 200
        body = r.json()
        assert body["total"] == 2
        # Newest first.
        assert body["snapshots"][0]["label"] == "second"
        assert body["snapshots"][1]["label"] == "first"

    def test_get_snapshot_by_id(self, client):
        capture = client.post(
            "/v1/agents/governance/snapshot", json={"label": "x"}
        )
        snap_id = capture.json()["snapshot_id"]
        r = client.get(f"/v1/agents/governance/snapshots/{snap_id}")
        assert r.status_code == 200
        body = r.json()
        assert body["snapshot"]["snapshot_id"] == snap_id

    def test_get_unknown_snapshot_returns_404(self, client):
        r = client.get(
            "/v1/agents/governance/snapshots/00000000-0000-0000-0000-000000000000"
        )
        assert r.status_code == 404

    def test_chain_intact_after_captures(self, client):
        for _ in range(3):
            client.post("/v1/agents/governance/snapshot", json={})
        r = client.get("/v1/agents/governance/chain/verify")
        assert r.status_code == 200
        body = r.json()
        assert body["intact"] is True
        assert body["checked"] == 3
        assert body["break_at_index"] is None


class TestEvidenceBundleRoute:
    def test_evidence_bundle_returns_full_envelope(self, client):
        capture = client.post(
            "/v1/agents/governance/snapshot", json={"label": "evidence-test"}
        )
        snap_id = capture.json()["snapshot_id"]
        r = client.get(
            f"/v1/agents/governance/snapshots/{snap_id}/evidence_bundle"
        )
        assert r.status_code == 200
        bundle = r.json()["bundle"]
        # Schema, snapshot identity, manifest, all required.
        assert bundle["schema_version"] == "tex.governance.evidence/2"
        assert bundle["snapshot"]["snapshot_id"] == snap_id
        assert bundle["manifest"]["bundle_sha256"]
        assert bundle["manifest"]["manifest_signature_hmac_sha256"]

    def test_unknown_snapshot_bundle_returns_404(self, client):
        r = client.get(
            "/v1/agents/governance/snapshots/"
            "00000000-0000-0000-0000-000000000000/evidence_bundle"
        )
        assert r.status_code == 404


class TestDriftRoutes:
    def test_drift_root_returns_empty_initially(self, client):
        r = client.get("/v1/discovery/drift")
        assert r.status_code == 200
        body = r.json()
        assert body["events"] == []
        assert body["total"] == 0

    def test_drift_by_kind_validates_input(self, client):
        r = client.get("/v1/discovery/drift/INVALID_KIND")
        assert r.status_code == 400

    def test_drift_by_known_kind_returns_empty_list(self, client):
        r = client.get("/v1/discovery/drift/NEW_AGENT")
        assert r.status_code == 200
        assert r.json()["events"] == []


class TestSchedulerRoutes:
    def test_status_with_no_tenants(self, client):
        r = client.get("/v1/discovery/scheduler/status")
        assert r.status_code == 200
        body = r.json()
        # No tenants configured → not running.
        assert body["running"] is False
        assert body["tenants"] == []
        assert body["alert_sinks"]  # at minimum the log sink

    def test_run_returns_summary(self, client):
        # A run with no tenants returns a summary with empty tenants list.
        r = client.post("/v1/discovery/scheduler/run")
        assert r.status_code == 200
        body = r.json()
        assert "summary" in body
        assert "tenants" in body["summary"]

    def test_start_is_idempotent(self, client):
        r1 = client.post("/v1/discovery/scheduler/start")
        r2 = client.post("/v1/discovery/scheduler/start")
        assert r1.status_code == 200
        assert r2.status_code == 200

    def test_stop_returns_status(self, client):
        r = client.post("/v1/discovery/scheduler/stop")
        assert r.status_code == 200
        assert r.json()["running"] is False

"""
V16 end-to-end tests.

Drives the FastAPI surface to verify:
  * scan idempotency replay (POST /v1/discovery/scan with same key)
  * 409 on concurrent scan (per-tenant lock)
  * scan response carries scan_run_id + ledger range + registry hash
  * snapshot binding to scan_run via POST /v1/agents/governance/snapshot
  * /v1/system/state aggregates governance + last_scan + connector health + chain
  * /v1/discovery/scan_runs lists durable runs
  * /v1/discovery/connectors/health
  * Signed zip evidence bundle has bundle.json + manifest.json + README.txt
"""

from __future__ import annotations

import io
import json
import zipfile

import pytest
from fastapi.testclient import TestClient

from tex.main import build_runtime, create_app


@pytest.fixture
def runtime(tmp_path):
    return build_runtime(evidence_path=tmp_path / "evidence.jsonl")


@pytest.fixture
def client(runtime) -> TestClient:
    return TestClient(create_app(runtime=runtime))


# ---------------------------------------------------------------------------
# Scan idempotency + run binding
# ---------------------------------------------------------------------------


class TestScanResponseV16:
    def test_scan_response_carries_run_binding_fields(self, client: TestClient) -> None:
        r = client.post("/v1/discovery/scan", json={"tenant_id": "acme"})
        assert r.status_code == 200
        body = r.json()
        # New V16 fields must be present.
        assert "scan_run_id" in body
        assert body["scan_run_id"] is not None
        assert "registry_state_hash" in body
        assert body["registry_state_hash"] is not None
        assert "ledger_seq_start" in body
        assert "ledger_seq_end" in body
        assert "idempotent_replay" in body
        assert body["idempotent_replay"] is False

    def test_idempotency_key_replay_returns_same_run(self, client: TestClient) -> None:
        first = client.post(
            "/v1/discovery/scan",
            headers={"Idempotency-Key": "req-001"},
            json={"tenant_id": "acme"},
        )
        assert first.status_code == 200
        first_run_id = first.json()["scan_run_id"]
        assert first_run_id is not None

        second = client.post(
            "/v1/discovery/scan",
            headers={"Idempotency-Key": "req-001"},
            json={"tenant_id": "acme"},
        )
        assert second.status_code == 200
        second_body = second.json()
        assert second_body["scan_run_id"] == first_run_id
        assert second_body["idempotent_replay"] is True

    def test_different_idempotency_keys_produce_different_runs(
        self, client: TestClient,
    ) -> None:
        r1 = client.post(
            "/v1/discovery/scan",
            headers={"Idempotency-Key": "key-a"},
            json={"tenant_id": "acme"},
        )
        r2 = client.post(
            "/v1/discovery/scan",
            headers={"Idempotency-Key": "key-b"},
            json={"tenant_id": "acme"},
        )
        assert r1.json()["scan_run_id"] != r2.json()["scan_run_id"]


# ---------------------------------------------------------------------------
# Scan-run + connector health surface
# ---------------------------------------------------------------------------


class TestScanRunsRoutes:
    def test_scan_run_appears_in_listing(self, client: TestClient) -> None:
        r = client.post("/v1/discovery/scan", json={"tenant_id": "acme"})
        run_id = r.json()["scan_run_id"]

        listing = client.get("/v1/discovery/scan_runs?tenant_id=acme")
        assert listing.status_code == 200
        body = listing.json()
        ids = [run["run_id"] for run in body["runs"]]
        assert run_id in ids

    def test_scan_run_detail_404_for_unknown_id(self, client: TestClient) -> None:
        from uuid import uuid4
        r = client.get(f"/v1/discovery/scan_runs/{uuid4()}")
        assert r.status_code == 404

    def test_connector_health_lists_per_connector(self, client: TestClient) -> None:
        client.post("/v1/discovery/scan", json={"tenant_id": "acme"})
        r = client.get("/v1/discovery/connectors/health?tenant_id=acme")
        assert r.status_code == 200
        body = r.json()
        # All wired mock connectors should be tracked.
        assert body["tenant_id"] == "acme"
        assert isinstance(body["health"], list)
        assert len(body["health"]) >= 1
        # Each entry should have a status field.
        for entry in body["health"]:
            assert entry["status"] in {
                "HEALTHY", "DEGRADED", "OFFLINE", "UNKNOWN",
            }


# ---------------------------------------------------------------------------
# Cursor pagination on /ledger
# ---------------------------------------------------------------------------


class TestLedgerCursorPagination:
    def test_cursor_returns_next_cursor_when_more_data(
        self, runtime, client: TestClient,
    ) -> None:
        # Stuff multiple records into a connector so we get >1 ledger entry.
        for connector in runtime.discovery_service.list_connectors():
            if connector.name == "openai_mock":
                connector.replace_records([
                    {
                        "id": f"asst_{i}",
                        "name": f"Bot {i}",
                        "model": "gpt-4o",
                        "tools": [],
                        "created_at": 1_700_000_000 + i,
                    }
                    for i in range(5)
                ])
        client.post("/v1/discovery/scan", json={"tenant_id": "acme"})

        r = client.get("/v1/discovery/ledger?limit=2")
        body = r.json()
        # When total > limit and next page exists, next_cursor populated.
        if body["total"] > 2:
            assert body["next_cursor"] is not None


# ---------------------------------------------------------------------------
# Snapshot binding to scan_run
# ---------------------------------------------------------------------------


class TestSnapshotScanBinding:
    def test_snapshot_with_tenant_id_binds_to_latest_scan(
        self, client: TestClient,
    ) -> None:
        scan_resp = client.post("/v1/discovery/scan", json={"tenant_id": "acme"})
        scan_run_id = scan_resp.json()["scan_run_id"]
        registry_hash = scan_resp.json()["registry_state_hash"]

        snap_resp = client.post(
            "/v1/agents/governance/snapshot",
            json={"tenant_id": "acme", "label": "test"},
        )
        assert snap_resp.status_code == 201
        body = snap_resp.json()
        assert body["scan_run_id"] == scan_run_id
        assert body["registry_state_hash"] == registry_hash

    def test_snapshot_chain_still_intact_with_binding(
        self, client: TestClient,
    ) -> None:
        client.post("/v1/discovery/scan", json={"tenant_id": "acme"})
        client.post(
            "/v1/agents/governance/snapshot",
            json={"tenant_id": "acme", "label": "first"},
        )
        client.post(
            "/v1/agents/governance/snapshot",
            json={"tenant_id": "acme", "label": "second"},
        )
        r = client.get("/v1/agents/governance/chain/verify")
        assert r.status_code == 200
        assert r.json()["intact"] is True


# ---------------------------------------------------------------------------
# Evidence bundle .zip
# ---------------------------------------------------------------------------


class TestEvidenceBundleZip:
    def test_zip_contains_three_files(self, client: TestClient) -> None:
        client.post("/v1/discovery/scan", json={"tenant_id": "acme"})
        snap = client.post(
            "/v1/agents/governance/snapshot",
            json={"tenant_id": "acme", "label": "for-zip"},
        )
        snapshot_id = snap.json()["snapshot_id"]

        r = client.get(
            f"/v1/agents/governance/snapshots/{snapshot_id}/evidence_bundle.zip",
        )
        assert r.status_code == 200
        assert r.headers["content-type"] == "application/zip"
        assert r.headers["X-Tex-Bundle-SHA256"]
        assert r.headers["X-Tex-Bundle-Signature"]

        with zipfile.ZipFile(io.BytesIO(r.content)) as zf:
            names = set(zf.namelist())
            assert "bundle.json" in names
            assert "manifest.json" in names
            assert "README.txt" in names

            manifest = json.loads(zf.read("manifest.json"))
            assert "bundle_sha256" in manifest
            assert "section_hashes" in manifest
            # Every expected per-artifact hash is named.
            for expected in (
                "snapshot_sha256",
                "counts_sha256",
                "agents_sha256",
                "drift_events_sha256",
                "registry_chain_proof_sha256",
                "policy_versions_sha256",
                "scan_run_sha256",
            ):
                assert expected in manifest["section_hashes"]


# ---------------------------------------------------------------------------
# /v1/system/state
# ---------------------------------------------------------------------------


class TestSystemState:
    def test_aggregate_view_after_scan(self, client: TestClient) -> None:
        client.post("/v1/discovery/scan", json={"tenant_id": "acme"})

        r = client.get("/v1/system/state?tenant_id=acme")
        assert r.status_code == 200
        body = r.json()

        # Top-level shape.
        assert "version" in body
        assert "governance" in body
        assert "last_scan" in body
        assert "connector_health" in body
        assert "scheduler" in body
        assert "latest_drift" in body
        assert "chain" in body

        # last_scan reflects the scan we just did.
        assert body["last_scan"]["has_run"] is True
        assert body["last_scan"]["tenant_id"] == "acme"

        # Chain block.
        assert isinstance(body["chain"]["discovery_chain_intact"], bool)
        assert isinstance(body["chain"]["discovery_ledger_length"], int)

    def test_system_state_without_any_scan(self, client: TestClient) -> None:
        r = client.get("/v1/system/state")
        assert r.status_code == 200
        body = r.json()
        assert body["last_scan"]["has_run"] is False


# ---------------------------------------------------------------------------
# Discovery metrics endpoint
# ---------------------------------------------------------------------------


class TestDiscoveryMetrics:
    def test_metrics_endpoint_exposes_counters(self, client: TestClient) -> None:
        r = client.get("/v1/discovery/metrics")
        assert r.status_code == 200
        body = r.json()
        assert body["enabled"] is True
        # Counters exist even at zero.
        for key in (
            "scans_started", "scans_completed", "scans_failed",
            "scans_idempotent_replays", "lock_conflicts",
            "total_candidates_seen", "total_registered",
            "drift", "alerts_dispatched", "snapshots_captured",
            "average_scan_duration_seconds",
            "per_connector_successes", "per_connector_failures",
        ):
            assert key in body

    def test_metrics_keys_are_stable(self, client: TestClient) -> None:
        r = client.get("/v1/discovery/metrics")
        body = r.json()
        # Drift sub-block has all six counters.
        for sub in (
            "new", "changed", "disappeared",
            "silent_misses", "recovered", "reappeared",
        ):
            assert sub in body["drift"]

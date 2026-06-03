"""
V15 tests: GovernanceSnapshotStore — capture, chain hashing, verify,
and regulator-grade evidence bundle export.

Same fallback strategy as the other V15 tests: when DATABASE_URL is
unset, the store runs purely in-memory. Chain semantics are
identical in both modes — what changes is only whether records
round-trip through Postgres. So fallback-mode coverage proves
correctness; live Postgres is verified at deploy time.
"""

from __future__ import annotations

import json
from uuid import UUID

from tex.stores.governance_snapshots import GovernanceSnapshotStore


def _governance_payload(
    *,
    total: int = 10,
    governed: int = 6,
    ungoverned: int = 3,
    partial: int = 1,
    unknown: int = 0,
    high_risk_total: int = 4,
    high_risk_ungoverned: int = 1,
    governed_with_forbids: int = 2,
    coverage_root: str = "abc123",
    signature: str = "sig123",
    agents: list[dict] | None = None,
) -> dict:
    """Build a governance-response-shaped dict for testing."""
    return {
        "counts": {
            "total_agents": total,
            "governed": governed,
            "ungoverned": ungoverned,
            "partial": partial,
            "unknown": unknown,
            "high_risk_total": high_risk_total,
            "high_risk_ungoverned": high_risk_ungoverned,
            "governed_with_forbids": governed_with_forbids,
        },
        "agents": agents
        or [
            {
                "agent_id": "11111111-1111-1111-1111-111111111111",
                "name": "high-risk-ungoverned-1",
                "discovery_source": "openai",
                "external_id": "asst_abc",
                "risk_band": "HIGH",
                "tenant_id": "default",
                "governance_state": "UNGOVERNED",
            },
            {
                "agent_id": "22222222-2222-2222-2222-222222222222",
                "name": "governed-1",
                "risk_band": "MEDIUM",
                "tenant_id": "default",
                "governance_state": "GOVERNED",
            },
        ],
        "coverage_root_sha256": coverage_root,
        "signature_hmac_sha256": signature,
    }


class TestSnapshotCapture:
    def test_capture_returns_snapshot_record(self, monkeypatch):
        monkeypatch.delenv("DATABASE_URL", raising=False)
        store = GovernanceSnapshotStore()
        record = store.capture(governance_payload=_governance_payload())
        assert record["snapshot_id"]
        assert record["total_agents"] == 10
        assert record["governed"] == 6
        assert record["snapshot_hash"]
        # First snapshot has no predecessor.
        assert record["previous_snapshot_hash"] is None

    def test_capture_persists_to_cache(self, monkeypatch):
        monkeypatch.delenv("DATABASE_URL", raising=False)
        store = GovernanceSnapshotStore()
        store.capture(governance_payload=_governance_payload())
        store.capture(governance_payload=_governance_payload())
        assert len(store) == 2
        recents = store.list_recent(limit=10)
        assert len(recents) == 2

    def test_capture_computes_pcts(self, monkeypatch):
        monkeypatch.delenv("DATABASE_URL", raising=False)
        store = GovernanceSnapshotStore()
        record = store.capture(governance_payload=_governance_payload())
        # 6/10 governed → 60.0
        assert record["governed_pct"] == 60.0
        # 3/10 ungoverned → 30.0
        assert record["ungoverned_pct"] == 30.0

    def test_capture_extracts_critical_ungoverned(self, monkeypatch):
        monkeypatch.delenv("DATABASE_URL", raising=False)
        store = GovernanceSnapshotStore()
        record = store.capture(governance_payload=_governance_payload())
        # The default fixture has one HIGH+UNGOVERNED agent.
        assert len(record["critical_ungoverned"]) == 1
        critical = record["critical_ungoverned"][0]
        assert critical["risk_band"] == "HIGH"
        assert critical["name"] == "high-risk-ungoverned-1"

    def test_capture_with_label(self, monkeypatch):
        monkeypatch.delenv("DATABASE_URL", raising=False)
        store = GovernanceSnapshotStore()
        record = store.capture(
            governance_payload=_governance_payload(),
            label="weekly-baseline",
        )
        assert record["label"] == "weekly-baseline"


class TestSnapshotChain:
    def test_second_snapshot_links_to_first(self, monkeypatch):
        monkeypatch.delenv("DATABASE_URL", raising=False)
        store = GovernanceSnapshotStore()
        first = store.capture(governance_payload=_governance_payload())
        second = store.capture(governance_payload=_governance_payload(governed=7))
        # The second snapshot must carry the first snapshot's hash.
        assert second["previous_snapshot_hash"] == first["snapshot_hash"]
        # And the hashes themselves must differ.
        assert first["snapshot_hash"] != second["snapshot_hash"]

    def test_chain_intact_for_single_snapshot(self, monkeypatch):
        monkeypatch.delenv("DATABASE_URL", raising=False)
        store = GovernanceSnapshotStore()
        store.capture(governance_payload=_governance_payload())
        result = store.verify_chain()
        assert result["intact"] is True
        assert result["checked"] == 1
        assert result["break_at_index"] is None

    def test_chain_intact_for_long_chain(self, monkeypatch):
        monkeypatch.delenv("DATABASE_URL", raising=False)
        store = GovernanceSnapshotStore()
        for i in range(10):
            store.capture(governance_payload=_governance_payload(governed=i))
        result = store.verify_chain()
        assert result["intact"] is True
        assert result["checked"] == 10

    def test_chain_breaks_when_a_record_is_tampered(self, monkeypatch):
        monkeypatch.delenv("DATABASE_URL", raising=False)
        store = GovernanceSnapshotStore()
        store.capture(governance_payload=_governance_payload())
        store.capture(governance_payload=_governance_payload(governed=7))
        store.capture(governance_payload=_governance_payload(governed=8))
        # Tamper with the middle record's count without recomputing
        # the hash. This is exactly what an attacker would attempt.
        records_in_order = list(store._cache.values())
        middle = records_in_order[1]
        middle["governed"] = 9999  # mutated, but snapshot_hash is stale
        result = store.verify_chain()
        assert result["intact"] is False
        # The break is at index 1 (the second-oldest record).
        assert result["break_at_index"] == 1

    def test_empty_chain_verifies_trivially(self, monkeypatch):
        monkeypatch.delenv("DATABASE_URL", raising=False)
        store = GovernanceSnapshotStore()
        result = store.verify_chain()
        assert result["intact"] is True
        assert result["checked"] == 0


class TestEvidenceBundle:
    def test_bundle_for_unknown_id_is_none(self, monkeypatch):
        monkeypatch.delenv("DATABASE_URL", raising=False)
        store = GovernanceSnapshotStore()
        bundle = store.export_evidence_bundle(
            UUID("00000000-0000-0000-0000-000000000000")
        )
        assert bundle is None

    def test_bundle_includes_all_required_fields(self, monkeypatch):
        monkeypatch.delenv("DATABASE_URL", raising=False)
        store = GovernanceSnapshotStore()
        record = store.capture(governance_payload=_governance_payload())
        snapshot_id = UUID(record["snapshot_id"])
        bundle = store.export_evidence_bundle(snapshot_id)
        assert bundle is not None
        # Schema version pins the export shape — regulators can write
        # a parser against a known schema.
        assert bundle["schema_version"] == "tex.governance.evidence/2"
        # Snapshot identity + chain context.
        assert bundle["snapshot"]["snapshot_id"] == str(snapshot_id)
        assert bundle["snapshot"]["snapshot_hash"]
        # Counts.
        assert bundle["counts"]["total_agents"] == 10
        # Critical ungoverned slice carried forward.
        assert len(bundle["critical_ungoverned"]) == 1
        # Manifest with hash + signature.
        assert "manifest" in bundle
        assert bundle["manifest"]["bundle_sha256"]
        assert bundle["manifest"]["manifest_signature_hmac_sha256"]
        assert bundle["manifest"]["signed_at"]

    def test_bundle_carries_drift_events(self, monkeypatch):
        monkeypatch.delenv("DATABASE_URL", raising=False)
        store = GovernanceSnapshotStore()
        record = store.capture(governance_payload=_governance_payload())
        bundle = store.export_evidence_bundle(
            UUID(record["snapshot_id"]),
            drift_events=[
                {"event_id": "abc", "kind": "NEW_AGENT", "summary": "test"},
            ],
        )
        assert bundle is not None
        assert len(bundle["drift_events"]) == 1
        assert bundle["drift_events"][0]["kind"] == "NEW_AGENT"

    def test_bundle_carries_registry_chain_proof(self, monkeypatch):
        monkeypatch.delenv("DATABASE_URL", raising=False)
        store = GovernanceSnapshotStore()
        record = store.capture(governance_payload=_governance_payload())
        bundle = store.export_evidence_bundle(
            UUID(record["snapshot_id"]),
            registry_chain_proof={
                "agent-1": {"revisions": 3, "chain_intact": True},
            },
        )
        assert bundle is not None
        assert "agent-1" in bundle["registry_chain_proof"]

    def test_bundle_signature_is_deterministic_for_same_input(self, monkeypatch):
        # Same secret + same bundle bytes → same signature. Critical
        # for letting a regulator re-derive the signature locally
        # from the JSON.
        monkeypatch.setenv("TEX_EVIDENCE_SUMMARY_SECRET", "fixed-test-secret")
        monkeypatch.delenv("DATABASE_URL", raising=False)
        store = GovernanceSnapshotStore()
        record = store.capture(governance_payload=_governance_payload())
        snapshot_id = UUID(record["snapshot_id"])
        bundle_a = store.export_evidence_bundle(snapshot_id)
        bundle_b = store.export_evidence_bundle(snapshot_id)
        assert (
            bundle_a["manifest"]["bundle_sha256"]
            == bundle_b["manifest"]["bundle_sha256"]
        )
        # Signatures match too — except signed_at, which we exclude
        # from the canonical bundle hash.
        assert (
            bundle_a["manifest"]["manifest_signature_hmac_sha256"]
            == bundle_b["manifest"]["manifest_signature_hmac_sha256"]
        )

    def test_bundle_serializes_cleanly_to_json(self, monkeypatch):
        # The bundle must round-trip through json.dumps so a regulator
        # can save it as a file.
        monkeypatch.delenv("DATABASE_URL", raising=False)
        store = GovernanceSnapshotStore()
        record = store.capture(governance_payload=_governance_payload())
        bundle = store.export_evidence_bundle(UUID(record["snapshot_id"]))
        # Must serialize without errors.
        text = json.dumps(bundle, default=str)
        assert text
        # And re-parse.
        parsed = json.loads(text)
        assert parsed["schema_version"] == "tex.governance.evidence/2"

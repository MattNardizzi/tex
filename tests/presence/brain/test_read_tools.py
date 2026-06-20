"""Read-tool behaviour, ref re-verification, and the baked-in honest edges."""

from __future__ import annotations

from tex.presence.brain import (
    DIMENSIONS,
    build_read_tool_registry,
    build_read_tools,
)
from tex.presence.brain.evidence import canonical_sha256
from tex.presence.contract import EvidenceRef, ReadTool


def _registry(state):
    return build_read_tool_registry(state)


def test_all_tools_conform_to_readtool_protocol(populated_state):
    tools = build_read_tools(populated_state)
    assert tools, "expected a non-empty tool set"
    for t in tools:
        assert isinstance(t, ReadTool)  # name + __call__(request, *, tenant, **kwargs)
    # Every governance dimension is represented.
    prefixes = {name.split(".", 1)[0] for name in (t.name for t in tools)}
    for dim in DIMENSIONS:
        assert dim in prefixes, f"missing read-tools for dimension {dim}"


def test_return_shape_is_value_and_evidence_refs(populated_state):
    reg = _registry(populated_state)
    value, refs = reg["execution.recent_actions"](tenant=None)
    assert isinstance(value, dict)
    assert isinstance(refs, tuple)
    assert all(isinstance(r, EvidenceRef) for r in refs)


def test_content_digest_refs_reverify_by_recomputing(populated_state):
    """The gate's contract: re-fetch the row, recompute the digest, compare."""
    reg = _registry(populated_state)
    value, refs = reg["execution.recent_actions"](tenant=None)
    assert refs
    rows = {a["entry_id"]: a for a in value["actions"]}
    for ref in refs:
        assert ref.store == "action_ledger"
        assert ref.prior_link_witness is None  # content-digest, NOT chain-anchored
        assert ref.record_hash == canonical_sha256(rows[ref.record_id])


def test_chained_refs_carry_stored_hash_and_prior_witness(populated_state):
    reg = _registry(populated_state)
    value, refs = reg["discovery.recent_entries"](tenant=None)
    assert refs
    by_seq = {str(e["sequence"]): e for e in value["entries"]}
    # The first entry has no predecessor; later ones must witness the prior hash.
    for ref in refs:
        assert ref.store == "discovery_ledger"
        entry = by_seq[ref.record_id]
        assert ref.record_hash == entry["record_hash"]
        assert ref.prior_link_witness == entry["previous_hash"]
    assert any(r.prior_link_witness is not None for r in refs), "expected a chained link"


def test_decision_aggregate_is_fleet_wide_and_says_so(populated_state):
    """decision_store has no tenant column — the count must be honestly fleet-wide."""
    reg = _registry(populated_state)
    value, refs = reg["human_decision.verdict_count"](tenant="acme", verdict="FORBID")
    assert value["tenant_scope"] == "fleet"
    assert value["tenant_filter_applied"] is False
    assert "fleet-wide" in value["note"]
    # The value is row-backed: count == number of refs, each a FORBID decision.
    assert value["count"] == len(refs) == 1
    assert all(r.field == "verdict" for r in refs)


def test_identity_list_includes_revoked_by_default_and_reports_it(populated_state):
    reg = _registry(populated_state)
    value, refs = reg["identity.list_agents"](tenant=None)
    statuses = {a["lifecycle_status"] for a in value["agents"]}
    assert "REVOKED" in statuses, "list_all must surface REVOKED agents"
    assert value["includes_revoked"] is True
    assert value["status_counts"].get("REVOKED", 0) == 1
    assert "REVOKED" in value["note"]
    assert len(refs) == len(value["agents"])


def test_identity_can_exclude_revoked_and_filter_tenant(populated_state):
    reg = _registry(populated_state)
    value, _ = reg["identity.list_agents"](tenant="acme", include_revoked=False)
    assert all(a["tenant_id"] == "acme" for a in value["agents"])
    assert all(a["lifecycle_status"] != "REVOKED" for a in value["agents"])
    assert value["tenant_filter_applied"] is True


def test_identity_get_agent_respects_tenant(populated_state, known_agent_id):
    reg = _registry(populated_state)
    found, refs = reg["identity.get_agent"](agent_id=known_agent_id, tenant="acme")
    assert found["found"] is True
    assert len(refs) == 1
    mismatch, refs2 = reg["identity.get_agent"](agent_id=known_agent_id, tenant="other")
    assert mismatch["found"] is False
    assert refs2 == ()


def test_discovery_head_uses_latest_not_verify_chain(populated_state, monkeypatch):
    """The O(1) head read must NOT trigger the O(n) chain replay."""
    ledger = populated_state.discovery_ledger
    cls = type(ledger)  # instance uses __slots__; patch the class method
    calls = {"verify": 0}
    real_verify = cls.verify_chain

    def _spy(self):
        calls["verify"] += 1
        return real_verify(self)

    monkeypatch.setattr(cls, "verify_chain", _spy)

    reg = _registry(populated_state)
    value, refs = reg["discovery.chain_head"](tenant=None)
    assert value["present"] is True
    assert len(refs) == 1
    assert calls["verify"] == 0, "chain_head must not call verify_chain()"


def test_discovery_verify_chain_is_explicit_and_labelled(populated_state):
    reg = _registry(populated_state)
    value, refs = reg["discovery.verify_chain"](tenant=None)
    assert value["chain_intact"] is True
    assert value["cost"] == "O(n)"
    assert len(refs) == 1


def test_discovery_recent_filters_by_tenant(populated_state):
    reg = _registry(populated_state)
    acme, _ = reg["discovery.recent_entries"](tenant="acme")
    other, _ = reg["discovery.recent_entries"](tenant="other")
    assert acme["returned"] == 2
    assert other["returned"] == 1
    assert all(e["candidate"]["tenant_id"] == "acme" for e in acme["entries"])


def test_evidence_chain_head_is_chain_anchored(populated_state):
    reg = _registry(populated_state)
    value, refs = reg["evidence.chain_head"](tenant=None)
    assert value["present"] is True
    assert len(refs) == 1
    head = value["head"]
    assert refs[0].record_hash == head["record_hash"]
    assert refs[0].store == "evidence_jsonl"


def test_monitoring_drift_reads_and_filters_tenant(populated_state):
    reg = _registry(populated_state)
    acme, refs = reg["monitoring.recent_drift"](tenant="acme")
    assert acme["returned"] == 1
    assert acme["tenant_filter_applied"] is True
    assert all(e["tenant_id"] == "acme" for e in acme["events"])
    assert len(refs) == 1


def test_monitoring_optional_store_degrades_not_crashes(populated_state):
    reg = _registry(populated_state)
    value, refs = reg["monitoring.latest_snapshot"](tenant=None)
    assert value["available"] is False
    assert refs == ()


def test_every_tool_degrades_on_empty_state(empty_state):
    reg = _registry(empty_state)
    for name, tool in reg.items():
        value, refs = tool(tenant="acme")
        assert isinstance(value, dict), name
        # Degrade path: no rows ⇒ no refs, and a machine-readable not-available flag
        # (or, for genuinely empty-but-present stores, an empty result).
        assert refs == () or value.get("available") is not False, name
        if value.get("available") is False:
            assert "not configured" in value["reason"], name


def test_aggregate_governance_posture_counts_statuses(populated_state):
    reg = _registry(populated_state)
    value, refs = reg["aggregates.governance_posture"](tenant=None)
    assert value["total"] == len(refs) == 3
    assert value["by_lifecycle_status"]["REVOKED"] == 1
    assert value["includes_revoked"] is True


def test_aggregate_recent_verdicts_distribution(populated_state):
    reg = _registry(populated_state)
    value, refs = reg["aggregates.recent_verdicts"](tenant=None)
    assert value["by_verdict"].get("PERMIT") == 2
    assert value["by_verdict"].get("FORBID") == 1
    assert value["tenant_scope"] == "fleet"
    assert len(refs) == sum(value["by_verdict"].values())


def test_window_clamp_is_surfaced_not_silent(populated_state):
    reg = _registry(populated_state)
    value, _ = reg["execution.recent_actions"](tenant=None, limit=99999)
    assert value["limit_clamped_to"] == 500

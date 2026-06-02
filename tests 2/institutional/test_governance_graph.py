"""Tests for tex.institutional.governance_graph."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

# Prime tex.ecosystem to avoid the events package's pre-existing
# circular import (see governance_graph.py docstring).
import tex.ecosystem  # noqa: F401

from tex.institutional import (
    CANONICAL_COURNOT_STATES,
    GovernanceGraph,
    GovernanceGraphValidationError,
    LegalState,
    LegalTransition,
)
from tex.institutional.sanctions import RestorativePath, Sanction


FIXTURES_DIR = Path(__file__).parent / "fixtures"
COURNOT_MANIFEST = FIXTURES_DIR / "cournot_market.yaml"


# ---------------------------------------------------------------------
# Loading + canonical Cournot fixture
# ---------------------------------------------------------------------


def test_loads_cournot_yaml_fixture() -> None:
    g = GovernanceGraph.from_yaml(COURNOT_MANIFEST)
    assert g.graph_id == "cournot_market_v1"
    assert g.version == "1.0.0"
    # Acceptance criterion: 5 legal states, 12 transitions.
    assert len(g.states) == 5
    assert len(g.transitions) == 12
    # Paper-canonical state set.
    state_ids = {s.state_id for s in g.states}
    assert state_ids == set(CANONICAL_COURNOT_STATES)


def test_yaml_and_dict_loaders_produce_identical_semantic_digest() -> None:
    """Loader-independent: same content -> same regime identity."""
    import yaml

    raw = COURNOT_MANIFEST.read_text(encoding="utf-8")
    via_yaml = GovernanceGraph.from_yaml(raw)
    via_dict = GovernanceGraph.from_dict(yaml.safe_load(raw))
    assert via_yaml.manifest_semantic_sha256 == via_dict.manifest_semantic_sha256


def test_yaml_loader_accepts_path_and_inline_string() -> None:
    """Both Path objects and inline YAML strings work."""
    g_path = GovernanceGraph.from_yaml(COURNOT_MANIFEST)
    g_inline = GovernanceGraph.from_yaml(COURNOT_MANIFEST.read_text())
    assert g_path.manifest_semantic_sha256 == g_inline.manifest_semantic_sha256


def test_yaml_loader_accepts_bytes() -> None:
    g_bytes = GovernanceGraph.from_yaml(COURNOT_MANIFEST.read_bytes())
    g_path = GovernanceGraph.from_yaml(COURNOT_MANIFEST)
    assert g_bytes.manifest_semantic_sha256 == g_path.manifest_semantic_sha256


def test_yaml_loader_rejects_non_mapping_top_level() -> None:
    with pytest.raises(GovernanceGraphValidationError, match="must be a YAML mapping"):
        GovernanceGraph.from_yaml("- list\n- not\n- mapping\n")


def test_json_loader_accepts_str_and_bytes() -> None:
    import json

    minimal = {
        "graph_id": "j",
        "version": "1.0",
        "states": ["active"],
        "sanctions": [],
        "restorative_paths": [],
        "transitions": [],
    }
    text = json.dumps(minimal)
    g_str = GovernanceGraph.from_json(text)
    g_bytes = GovernanceGraph.from_json(text.encode("utf-8"))
    assert g_str.manifest_semantic_sha256 == g_bytes.manifest_semantic_sha256


def test_json_loader_rejects_non_object_top_level() -> None:
    with pytest.raises(GovernanceGraphValidationError, match="must be a JSON object"):
        GovernanceGraph.from_json("[1, 2, 3]")


# ---------------------------------------------------------------------
# Manifest hash determinism
# ---------------------------------------------------------------------


def test_manifest_semantic_sha256_is_deterministic() -> None:
    g1 = GovernanceGraph.from_yaml(COURNOT_MANIFEST)
    g2 = GovernanceGraph.from_yaml(COURNOT_MANIFEST)
    assert g1.manifest_semantic_sha256 == g2.manifest_semantic_sha256
    # Length and shape sanity (SHA-256 hex).
    assert len(g1.manifest_semantic_sha256) == 64
    assert all(c in "0123456789abcdef" for c in g1.manifest_semantic_sha256)


def test_manifest_file_sha256_matches_raw_bytes() -> None:
    """File digest must equal hashlib.sha256 of the raw bytes seen."""
    raw = COURNOT_MANIFEST.read_bytes()
    expected = hashlib.sha256(raw).hexdigest()
    g = GovernanceGraph.from_yaml(COURNOT_MANIFEST)
    assert g.manifest_file_sha256 == expected


def test_semantic_and_file_digests_differ_for_same_content() -> None:
    """
    Whitespace / key-order in the file changes file_sha256 but not
    semantic_sha256 — that's the whole point of having two.
    """
    g_file = GovernanceGraph.from_yaml(COURNOT_MANIFEST)
    # Same content, no file bytes -> file digest equals semantic.
    g_dict = GovernanceGraph.from_dict(
        {
            "graph_id": g_file.graph_id,
            "version": g_file.version,
            "schema_version": g_file.schema_version,
            "interpreter": {
                "name": g_file.interpreter_name,
                "version": g_file.interpreter_version,
            },
            "states": [{"state_id": s.state_id, "description": s.description}
                       for s in g_file.states],
            "sanctions": [{
                "sanction_id": s.sanction_id,
                "description": s.description,
                "cost_to_actor": s.cost_to_actor,
                "cost_to_system": s.cost_to_system,
                "enforcement_action": s.enforcement_action,
                "tier": s.tier, "fine_rate": s.fine_rate,
                "fine_floor": s.fine_floor,
                "duration_rounds": s.duration_rounds,
            } for s in g_file.sanctions],
            "restorative_paths": [{
                "path_id": p.path_id,
                "description": p.description,
                "restorative_event_kinds": list(p.restorative_event_kinds),
                "target_legal_state_id": p.target_legal_state_id,
                "restoration_kind": p.restoration_kind,
                "condition": p.condition or {},
            } for p in g_file.restorative_paths],
            "transitions": [{
                "from_state": t.from_state,
                "to_state": t.to_state,
                "triggered_by": t.triggered_by,
                "edge_key": t.edge_key,
                "rule_id": t.rule_id,
                "sanction_id": t.sanction_id,
                "restorative_path_id": t.restorative_path_id,
                "timing": t.timing or {},
                "metadata": t.metadata or {},
            } for t in g_file.transitions],
            "policy_surface": g_file.policy_surface or {},
            "policy_program": g_file.policy_program or {},
            "contracts": g_file.contracts or {},
        }
    )
    assert g_dict.manifest_semantic_sha256 == g_file.manifest_semantic_sha256
    # File digest should differ since g_dict had no file bytes.
    assert g_dict.manifest_file_sha256 != g_file.manifest_file_sha256


def test_changing_a_sanction_amount_changes_semantic_digest() -> None:
    """A meaningful diff to the manifest must produce a different digest."""
    g1 = GovernanceGraph.from_yaml(COURNOT_MANIFEST)
    import yaml

    data = yaml.safe_load(COURNOT_MANIFEST.read_text())
    data["sanctions"][0]["cost_to_actor"] = 999.0
    g2 = GovernanceGraph.from_dict(data)
    assert g1.manifest_semantic_sha256 != g2.manifest_semantic_sha256


def test_changing_only_top_level_metadata_changes_digest() -> None:
    g1 = GovernanceGraph.from_yaml(COURNOT_MANIFEST)
    import yaml

    data = yaml.safe_load(COURNOT_MANIFEST.read_text())
    data["version"] = "2.0.0"
    g2 = GovernanceGraph.from_dict(data)
    assert g1.manifest_semantic_sha256 != g2.manifest_semantic_sha256


# ---------------------------------------------------------------------
# Validation errors
# ---------------------------------------------------------------------


def _minimal_manifest_dict() -> dict:
    return {
        "graph_id": "test",
        "version": "1.0",
        "states": ["active", "warning"],
        "sanctions": [
            {
                "sanction_id": "warn",
                "description": "",
                "cost_to_actor": 1.0,
                "cost_to_system": 0.0,
                "enforcement_action": "warning",
            }
        ],
        "restorative_paths": [],
        "transitions": [
            {
                "rule_id": "R1",
                "from_state": "active",
                "to_state": "warning",
                "triggered_by": "probable_violation",
                "sanction_id": "warn",
            }
        ],
    }


def test_rejects_missing_graph_id() -> None:
    data = _minimal_manifest_dict()
    del data["graph_id"]
    with pytest.raises(GovernanceGraphValidationError, match="graph_id"):
        GovernanceGraph.from_dict(data)


def test_rejects_dangling_from_state_reference() -> None:
    data = _minimal_manifest_dict()
    data["transitions"][0]["from_state"] = "nonexistent"
    with pytest.raises(GovernanceGraphValidationError, match="unknown from_state"):
        GovernanceGraph.from_dict(data)


def test_rejects_dangling_to_state_reference() -> None:
    data = _minimal_manifest_dict()
    data["transitions"][0]["to_state"] = "nonexistent"
    with pytest.raises(GovernanceGraphValidationError, match="unknown to_state"):
        GovernanceGraph.from_dict(data)


def test_rejects_dangling_sanction_reference() -> None:
    data = _minimal_manifest_dict()
    data["transitions"][0]["sanction_id"] = "no_such_sanction"
    with pytest.raises(GovernanceGraphValidationError, match="unknown sanction_id"):
        GovernanceGraph.from_dict(data)


def test_rejects_dangling_restorative_path_reference() -> None:
    data = _minimal_manifest_dict()
    data["transitions"][0]["sanction_id"] = None
    data["transitions"][0]["restorative_path_id"] = "no_such_path"
    with pytest.raises(
        GovernanceGraphValidationError, match="unknown restorative_path_id"
    ):
        GovernanceGraph.from_dict(data)


def test_rejects_duplicate_edge_keys() -> None:
    data = _minimal_manifest_dict()
    # Add a second transition that derives the same edge_key.
    data["transitions"].append({
        "rule_id": "R1",
        "from_state": "active",
        "to_state": "warning",
        "triggered_by": "different_event",
        "sanction_id": "warn",
    })
    with pytest.raises(GovernanceGraphValidationError, match="duplicate edge_key"):
        GovernanceGraph.from_dict(data)


def test_rejects_ambiguous_dispatch_pair() -> None:
    """
    Two transitions sharing (from_state, triggered_by) would make
    Controller dispatch ambiguous. Validator must reject at load time.
    """
    data = _minimal_manifest_dict()
    data["transitions"].append({
        "rule_id": "R2",  # different rule_id -> different edge_key
        "from_state": "active",
        "to_state": "warning",  # but same dispatch pair
        "triggered_by": "probable_violation",
        "sanction_id": "warn",
    })
    with pytest.raises(GovernanceGraphValidationError, match="ambiguous"):
        GovernanceGraph.from_dict(data)


def test_rejects_malformed_edge_key() -> None:
    data = _minimal_manifest_dict()
    # Force a mis-shaped edge_key (uppercase state).
    data["transitions"][0]["edge_key"] = "R1:Active->Warning"
    with pytest.raises(GovernanceGraphValidationError, match="does not match"):
        GovernanceGraph.from_dict(data)


def test_rejects_edge_key_disagreeing_with_states() -> None:
    data = _minimal_manifest_dict()
    data["transitions"][0]["edge_key"] = "R1:active->fined"  # to_state mismatch
    with pytest.raises(GovernanceGraphValidationError, match="disagrees"):
        GovernanceGraph.from_dict(data)


def test_rejects_transition_missing_triggered_by() -> None:
    data = _minimal_manifest_dict()
    data["transitions"][0]["triggered_by"] = ""
    with pytest.raises(GovernanceGraphValidationError, match="missing triggered_by"):
        GovernanceGraph.from_dict(data)


def test_rejects_duplicate_state_ids() -> None:
    data = _minimal_manifest_dict()
    data["states"].append("active")
    with pytest.raises(GovernanceGraphValidationError, match="duplicate state_id"):
        GovernanceGraph.from_dict(data)


def test_rejects_empty_state_set() -> None:
    data = _minimal_manifest_dict()
    data["states"] = []
    data["transitions"] = []
    with pytest.raises(GovernanceGraphValidationError, match="no states"):
        GovernanceGraph.from_dict(data)


def test_rejects_invalid_sanction_enforcement_action() -> None:
    data = _minimal_manifest_dict()
    data["sanctions"][0]["enforcement_action"] = "nuke_from_orbit"
    with pytest.raises(GovernanceGraphValidationError, match="not in"):
        GovernanceGraph.from_dict(data)


def test_rejects_fine_sanction_without_tier() -> None:
    data = _minimal_manifest_dict()
    data["sanctions"][0]["enforcement_action"] = "fine"
    # No tier / fine_rate provided -> validation error.
    with pytest.raises(GovernanceGraphValidationError, match="fine sanction"):
        GovernanceGraph.from_dict(data)


def test_rejects_invalid_restoration_kind() -> None:
    data = _minimal_manifest_dict()
    data["restorative_paths"].append({
        "path_id": "bad",
        "description": "",
        "restorative_event_kinds": [],
        "target_legal_state_id": "active",
        "restoration_kind": "make_it_up",
    })
    with pytest.raises(GovernanceGraphValidationError, match="restoration_kind"):
        GovernanceGraph.from_dict(data)


def test_rejects_restorative_path_targeting_unknown_state() -> None:
    data = _minimal_manifest_dict()
    data["restorative_paths"].append({
        "path_id": "p1",
        "description": "",
        "restorative_event_kinds": [],
        "target_legal_state_id": "nonexistent",
        "restoration_kind": "expiry",
    })
    with pytest.raises(GovernanceGraphValidationError, match="targets unknown state"):
        GovernanceGraph.from_dict(data)


# ---------------------------------------------------------------------
# Lookup helpers
# ---------------------------------------------------------------------


def test_lookup_sanction_raises_for_unknown_id() -> None:
    g = GovernanceGraph.from_yaml(COURNOT_MANIFEST)
    with pytest.raises(KeyError, match="nope"):
        g.lookup_sanction("nope")


def test_lookup_restorative_path_raises_for_unknown_id() -> None:
    g = GovernanceGraph.from_yaml(COURNOT_MANIFEST)
    with pytest.raises(KeyError, match="bogus"):
        g.lookup_restorative_path("bogus")


def test_find_transition_by_edge_key_returns_none_for_missing_key() -> None:
    g = GovernanceGraph.from_yaml(COURNOT_MANIFEST)
    assert g.find_transition_by_edge_key("does:not->exist") is None


def test_lookup_state_resolves_known_id() -> None:
    g = GovernanceGraph.from_yaml(COURNOT_MANIFEST)
    s = g.lookup_state("warning")
    assert isinstance(s, LegalState)
    assert s.state_id == "warning"


def test_lookup_state_raises_for_unknown_id() -> None:
    g = GovernanceGraph.from_yaml(COURNOT_MANIFEST)
    with pytest.raises(KeyError, match="warming"):
        g.lookup_state("warming")


def test_lookup_sanction_resolves_known_id() -> None:
    g = GovernanceGraph.from_yaml(COURNOT_MANIFEST)
    s = g.lookup_sanction("fine_tier1")
    assert isinstance(s, Sanction)
    assert s.tier == 1
    assert s.fine_rate == 0.35


def test_lookup_restorative_path_resolves_known_id() -> None:
    g = GovernanceGraph.from_yaml(COURNOT_MANIFEST)
    p = g.lookup_restorative_path("warning_expiry")
    assert isinstance(p, RestorativePath)
    assert p.restoration_kind == "expiry"


def test_find_transition_by_state_event_pair() -> None:
    g = GovernanceGraph.from_yaml(COURNOT_MANIFEST)
    t = g.find_transition(from_state="active", triggered_by="probable_violation")
    assert isinstance(t, LegalTransition)
    assert t.to_state == "warning"
    assert t.edge_key == "P2_independent_decision:active->warning"


def test_find_transition_returns_none_for_missing_pair() -> None:
    g = GovernanceGraph.from_yaml(COURNOT_MANIFEST)
    assert g.find_transition(from_state="suspended", triggered_by="nope") is None


def test_find_transition_by_edge_key() -> None:
    g = GovernanceGraph.from_yaml(COURNOT_MANIFEST)
    t = g.find_transition_by_edge_key(
        "P2_independent_decision:warning->fined"
    )
    assert t is not None
    assert t.from_state == "warning"
    assert t.to_state == "fined"


def test_enabled_transitions_lists_all_outgoing() -> None:
    g = GovernanceGraph.from_yaml(COURNOT_MANIFEST)
    out = g.enabled_transitions("fined")
    edge_keys = {t.edge_key for t in out}
    # From "fined" there are 4 outgoing edges in the fixture.
    assert len(out) == 4
    assert "P2_independent_decision:fined->suspended" in edge_keys
    assert "P2_independent_decision:fined->fined" in edge_keys
    assert "fine_clean_restoration_rule:fined->active" in edge_keys
    assert "fine_credit_rule:fined->credited" in edge_keys


# ---------------------------------------------------------------------
# Backward compatibility with the original scaffold
# ---------------------------------------------------------------------


def test_back_compat_manifest_hash_alias() -> None:
    g = GovernanceGraph.from_yaml(COURNOT_MANIFEST)
    # The original scaffold field is preserved as an alias.
    assert g.manifest_hash == g.manifest_semantic_sha256


def test_legaltransition_effective_sanction_id_handles_alias() -> None:
    """sanction_id and the deprecated sanction_on_violation must agree."""
    t = LegalTransition(
        from_state="active",
        to_state="warning",
        triggered_by="probable_violation",
        edge_key="R:active->warning",
        rule_id="R",
        sanction_id="s1",
        sanction_on_violation="s1",
    )
    assert t.effective_sanction_id() == "s1"


def test_legaltransition_alias_disagreement_raises() -> None:
    t = LegalTransition(
        from_state="active",
        to_state="warning",
        triggered_by="probable_violation",
        edge_key="R:active->warning",
        rule_id="R",
        sanction_id="s1",
        sanction_on_violation="s2",
    )
    with pytest.raises(ValueError, match="conflicting"):
        t.effective_sanction_id()


# ---------------------------------------------------------------------
# Semantic digest input contract — auditor surface
# ---------------------------------------------------------------------


def test_semantic_digest_input_is_recomputable() -> None:
    """
    An auditor must be able to recompute manifest_semantic_sha256 from
    semantic_digest_input() alone.
    """
    from tex.events._canonical import canonical_json, sha256_hex

    g = GovernanceGraph.from_yaml(COURNOT_MANIFEST)
    recomputed = sha256_hex(canonical_json(g.semantic_digest_input()))
    assert recomputed == g.manifest_semantic_sha256

"""
Tests for tex.ontology.validator + airo + governance + interaction + role.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from tex.ecosystem.proposed_event import ProposedEvent
from tex.ontology.airo import map_entity_to_airo, map_event_to_airo
from tex.ontology.entity_types import EntityKind, EntityTypeRegistry
from tex.ontology.event_types import EventKind, EventTypeRegistry
from tex.ontology.governance_ontology import (
    known_anchor_pairs,
    regulatory_bindings_for,
)
from tex.ontology.interaction_ontology import (
    allowed_interactions,
    is_interaction_allowed,
)
from tex.ontology.role_ontology import known_roles, reasoning_pattern_for_role
from tex.ontology.validator import EventLookup, OntologyValidator


# --- Validator: happy + sad paths ---


@pytest.fixture
def registries() -> tuple[EntityTypeRegistry, EventTypeRegistry]:
    return EntityTypeRegistry(), EventTypeRegistry()


def _make_proposed(
    *,
    event_kind: str = "agent_invokes_tool",
    actor: str = "agent_1",
    payload: dict | None = None,
    upstream: tuple[str, ...] = (),
) -> ProposedEvent:
    return ProposedEvent(
        event_kind=event_kind,
        actor_entity_id=actor,
        payload=payload if payload is not None else {"tool_id": "search_v1"},
        proposed_at=datetime.now(UTC),
        upstream_event_ids=upstream,
    )


def test_validator_happy_path(registries) -> None:
    er, evr = registries
    v = OntologyValidator(entity_registry=er, event_registry=evr)
    ok, errs = v.validate_event(_make_proposed())
    assert ok, errs
    assert errs == ()


def test_validator_rejects_unknown_event_kind(registries) -> None:
    er, evr = registries
    v = OntologyValidator(entity_registry=er, event_registry=evr)
    ok, errs = v.validate_event(_make_proposed(event_kind="not_a_real_kind"))
    assert not ok
    assert any("unknown event_kind" in e for e in errs)


def test_validator_rejects_bad_payload_shape(registries) -> None:
    """agent_invokes_tool requires tool_id in the payload."""
    er, evr = registries
    v = OntologyValidator(entity_registry=er, event_registry=evr)
    ok, errs = v.validate_event(_make_proposed(payload={"not_tool_id": "x"}))
    assert not ok
    assert any("payload schema violation" in e for e in errs)
    assert any("tool_id" in e for e in errs)


def test_validator_rejects_blank_actor(registries) -> None:
    er, evr = registries
    v = OntologyValidator(entity_registry=er, event_registry=evr)
    # ProposedEvent itself doesn't require non-empty actor (it uses str default)
    # so we construct one with whitespace and let the validator catch it.
    proposed = ProposedEvent(
        event_kind="agent_invokes_tool",
        actor_entity_id="   ",
        payload={"tool_id": "t"},
        proposed_at=datetime.now(UTC),
    )
    ok, errs = v.validate_event(proposed)
    assert not ok
    assert any("non-empty" in e for e in errs)


def test_validator_skips_upstream_when_no_lookup(registries) -> None:
    """No EventLookup wired ⇒ upstream check is skipped (not failed)."""
    er, evr = registries
    v = OntologyValidator(entity_registry=er, event_registry=evr)
    proposed = _make_proposed(upstream=("evt_does_not_exist",))
    ok, errs = v.validate_event(proposed)
    assert ok, errs


def test_validator_uses_injected_lookup(registries) -> None:
    er, evr = registries

    class _StubLookup:
        def __init__(self, known: set[str]) -> None:
            self._known = known

        def exists(self, event_id: str) -> bool:
            return event_id in self._known

    # Lookup that knows nothing — upstream check fails
    lookup_empty = _StubLookup(set())
    v = OntologyValidator(
        entity_registry=er,
        event_registry=evr,
        event_lookup=lookup_empty,
    )
    ok, errs = v.validate_event(_make_proposed(upstream=("evt_404",)))
    assert not ok
    assert any("evt_404" in e and "not found" in e for e in errs)

    # Lookup that knows the upstream — passes
    lookup_present = _StubLookup({"evt_known"})
    v2 = OntologyValidator(
        entity_registry=er,
        event_registry=evr,
        event_lookup=lookup_present,
    )
    ok, errs = v2.validate_event(_make_proposed(upstream=("evt_known",)))
    assert ok, errs


def test_event_lookup_protocol_runtime_checkable() -> None:
    """The EventLookup protocol is runtime-checkable for duck-typed callers."""

    class Impl:
        def exists(self, event_id: str) -> bool:
            return True

    assert isinstance(Impl(), EventLookup)


def test_validator_outbound_content_requires_content_hash(registries) -> None:
    """Mechanical regulator chain check."""
    er, evr = registries
    v = OntologyValidator(entity_registry=er, event_registry=evr)
    bad = ProposedEvent(
        event_kind="outbound_content_emitted",
        actor_entity_id="agent_1",
        payload={},  # missing content_hash
        proposed_at=datetime.now(UTC),
    )
    ok, errs = v.validate_event(bad)
    assert not ok
    assert any("content_hash" in e for e in errs)

    good = ProposedEvent(
        event_kind="outbound_content_emitted",
        actor_entity_id="agent_1",
        payload={"content_hash": "sha256:abc"},
        proposed_at=datetime.now(UTC),
    )
    ok, errs = v.validate_event(good)
    assert ok, errs


# --- AIRO mappings ---


def test_airo_entity_mappings_cover_every_kind() -> None:
    for kind in EntityKind:
        terms = map_entity_to_airo(kind.value)
        assert isinstance(terms, tuple)
        assert all(t.startswith("https://") for t in terms)
        assert len(terms) >= 1


def test_airo_event_mappings_cover_every_kind() -> None:
    for kind in EventKind:
        terms = map_event_to_airo(kind.value)
        assert isinstance(terms, tuple)
        assert all(t.startswith("https://") for t in terms)
        assert len(terms) >= 1


def test_airo_outbound_distinct_from_internal_emit() -> None:
    """OUTBOUND_CONTENT_EMITTED and AGENT_EMITS_OUTPUT have different bindings."""
    outbound = map_event_to_airo("outbound_content_emitted")
    internal = map_event_to_airo("agent_emits_output")
    assert outbound != internal
    assert any("Stakeholder" in t for t in outbound)


def test_airo_rejects_non_string() -> None:
    with pytest.raises(TypeError):
        map_entity_to_airo(42)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        map_event_to_airo(42)  # type: ignore[arg-type]


def test_airo_accepts_enum_input() -> None:
    """Enum members are str subclasses; both forms must work and agree."""
    via_str = map_entity_to_airo("agent")
    via_enum = map_entity_to_airo(EntityKind.AGENT)
    assert via_str == via_enum


def test_airo_rejects_unknown_kind() -> None:
    with pytest.raises(KeyError):
        map_entity_to_airo("not_a_kind")
    with pytest.raises(KeyError):
        map_event_to_airo("not_a_kind")


# --- Governance bindings ---


def test_governance_anchor_pairs_count() -> None:
    """We seeded 10 anchor pairs from the dual-ICP buyer narratives."""
    assert len(known_anchor_pairs()) == 10


def test_governance_outbound_includes_eu_art_50_and_sb942() -> None:
    """The regulator-facing outbound event must carry EU Art 50 + CA SB 942."""
    bindings = regulatory_bindings_for("agent", "outbound_content_emitted")
    assert "eu_ai_act:art_50" in bindings
    assert "ca_sb_942:sec_22757_1" in bindings
    assert "ftc:section_5" in bindings


def test_governance_internal_emit_is_distinct_from_outbound() -> None:
    """AGENT_EMITS_OUTPUT (internal) must not carry boundary disclosures."""
    internal = regulatory_bindings_for("agent", "agent_emits_output")
    assert "eu_ai_act:art_50" not in internal
    assert "ca_sb_942:sec_22757_1" not in internal


def test_governance_default_for_unknown_pair() -> None:
    bindings = regulatory_bindings_for("tool", "agent_emits_output")
    assert isinstance(bindings, tuple)
    assert len(bindings) >= 1


def test_governance_rejects_non_string() -> None:
    with pytest.raises(TypeError):
        regulatory_bindings_for(42, "agent_emits_output")  # type: ignore[arg-type]


def test_governance_accepts_enum_input() -> None:
    via_str = regulatory_bindings_for("agent", "outbound_content_emitted")
    via_enum = regulatory_bindings_for(
        EntityKind.AGENT, EventKind.OUTBOUND_CONTENT_EMITTED
    )
    assert via_str == via_enum


def test_governance_capability_lifecycle_pairs_present() -> None:
    """All three capability lifecycle events have explicit anchors."""
    pairs = set(known_anchor_pairs())
    assert ("capability", "capability_granted") in pairs
    assert ("capability", "capability_used") in pairs
    assert ("capability", "capability_revoked") in pairs


# --- Interaction ontology ---


def test_interaction_agent_to_tool_admits_invoke() -> None:
    allowed = allowed_interactions(from_kind="agent", to_kind="tool")
    assert "agent_invokes_tool" in allowed


def test_interaction_agent_to_agent_admits_message() -> None:
    allowed = allowed_interactions(from_kind="agent", to_kind="agent")
    assert "agent_to_agent_message" in allowed


def test_interaction_unknown_pair_returns_empty() -> None:
    allowed = allowed_interactions(from_kind="dataset", to_kind="agent")
    assert allowed == ()


def test_interaction_helper_predicate() -> None:
    assert is_interaction_allowed(
        from_kind="agent", to_kind="tool", event_kind="agent_invokes_tool"
    )
    assert not is_interaction_allowed(
        from_kind="agent", to_kind="tool", event_kind="capability_granted"
    )


def test_interaction_rejects_non_string() -> None:
    with pytest.raises(TypeError):
        allowed_interactions(from_kind=42, to_kind="tool")  # type: ignore[arg-type]


def test_interaction_accepts_enum_input() -> None:
    via_str = allowed_interactions(from_kind="agent", to_kind="tool")
    via_enum = allowed_interactions(from_kind=EntityKind.AGENT, to_kind=EntityKind.TOOL)
    assert via_str == via_enum


# --- Role ontology ---


def test_role_seed_set() -> None:
    roles = set(known_roles())
    assert "ai_sdr" in roles
    assert "ciso" in roles
    assert "compliance_reviewer" in roles


def test_role_pattern_shape() -> None:
    pattern = reasoning_pattern_for_role("ai_sdr")
    for k in ("typical_inputs", "typical_outputs", "constraints", "airo_role", "buyer_narrative"):
        assert k in pattern


def test_role_pattern_returns_copy() -> None:
    """Mutating the returned dict must not corrupt the registry."""
    pattern = reasoning_pattern_for_role("ai_sdr")
    pattern["typical_inputs"] = "mutated"
    fresh = reasoning_pattern_for_role("ai_sdr")
    assert fresh["typical_inputs"] != "mutated"


def test_role_unknown_raises_keyerror() -> None:
    with pytest.raises(KeyError):
        reasoning_pattern_for_role("not_a_role")


def test_role_rejects_non_string() -> None:
    with pytest.raises(TypeError):
        reasoning_pattern_for_role(42)  # type: ignore[arg-type]

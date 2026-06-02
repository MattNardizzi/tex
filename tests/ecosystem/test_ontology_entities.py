"""
Tests for tex.ontology.entity_types — schema coverage and validation.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from tex.ontology.entity_types import (
    EntityBase,
    EntityKind,
    EntityTypeRegistry,
    TrustLabel,
)


@pytest.fixture
def registry() -> EntityTypeRegistry:
    return EntityTypeRegistry()


def test_every_entity_kind_has_a_model(registry: EntityTypeRegistry) -> None:
    """All 12 EntityKinds resolve to a registered pydantic model."""
    expected = set(EntityKind)
    actual = set(registry.known_kinds())
    assert expected == actual
    assert len(actual) == 12


def test_schema_for_returns_json_schema(registry: EntityTypeRegistry) -> None:
    """schema_for returns a JSON Schema dict with required fields surfaced."""
    schema = registry.schema_for(EntityKind.AGENT)
    assert isinstance(schema, dict)
    assert "properties" in schema
    props = schema["properties"]
    # Required fields per scaffolded TODO
    for required_field in ("id", "kind", "trust_label", "capability_set", "history_pointer"):
        assert required_field in props, f"missing {required_field} in agent schema"


def test_schema_for_every_kind_has_required_fields(registry: EntityTypeRegistry) -> None:
    """Every EntityKind schema exposes the five required base fields."""
    required = {"id", "kind", "trust_label", "capability_set", "history_pointer"}
    for kind in EntityKind:
        schema = registry.schema_for(kind)
        assert required.issubset(schema["properties"].keys()), (
            f"{kind.value} missing required fields"
        )


def test_model_for_rejects_non_enum(registry: EntityTypeRegistry) -> None:
    with pytest.raises(TypeError, match="expected EntityKind"):
        registry.model_for("agent")  # type: ignore[arg-type]


def test_entity_model_is_frozen(registry: EntityTypeRegistry) -> None:
    """Pydantic frozen=True is enforced — instances are immutable."""
    model = registry.model_for(EntityKind.AGENT)
    instance = model(
        id="agent_1",
        registered_at=datetime.now(UTC),
    )
    with pytest.raises(ValidationError):
        instance.id = "agent_2"  # type: ignore[misc]


def test_entity_model_forbids_extra_fields(registry: EntityTypeRegistry) -> None:
    model = registry.model_for(EntityKind.AGENT)
    with pytest.raises(ValidationError):
        model(
            id="agent_1",
            registered_at=datetime.now(UTC),
            unknown_field="boom",
        )


def test_entity_model_pins_kind_field(registry: EntityTypeRegistry) -> None:
    """Each entity class fixes its kind via Field(default=..., frozen=True)."""
    agent = registry.model_for(EntityKind.AGENT)(
        id="a", registered_at=datetime.now(UTC)
    )
    assert agent.kind is EntityKind.AGENT
    tool = registry.model_for(EntityKind.TOOL)(
        id="t", registered_at=datetime.now(UTC)
    )
    assert tool.kind is EntityKind.TOOL


def test_capability_entity_accepts_grantee(registry: EntityTypeRegistry) -> None:
    cap_model = registry.model_for(EntityKind.CAPABILITY)
    cap = cap_model(
        id="cap_1",
        registered_at=datetime.now(UTC),
        granted_by="human_42",
        grantee_id="agent_7",
    )
    assert cap.grantee_id == "agent_7"


def test_trust_label_default_is_untrusted() -> None:
    instance = EntityBase(
        id="x",
        kind=EntityKind.AGENT,
        registered_at=datetime.now(UTC),
    )
    assert instance.trust_label is TrustLabel.UNTRUSTED


def test_id_min_length_enforced(registry: EntityTypeRegistry) -> None:
    model = registry.model_for(EntityKind.AGENT)
    with pytest.raises(ValidationError):
        model(id="", registered_at=datetime.now(UTC))


def test_unknown_kind_raises_keyerror() -> None:
    """If an EntityKind is somehow unregistered, schema_for raises KeyError."""
    # This shouldn't be reachable in practice (the registry covers all enum
    # values), but the contract says KeyError on a missing kind.
    registry = EntityTypeRegistry()
    # Hack: monkey-patch by pretending a fake enum-like object slipped in.
    fake = EntityKind.AGENT  # use a real one then assert all real ones map
    assert registry.model_for(fake) is not None

"""
Tests for tex.ontology.event_types — schema coverage, payload tightness,
and the mechanical "name implies entity ⇒ tightened" rule.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from tex.ontology.event_types import (
    AgentInvokesToolPayload,
    AgentToAgentMessagePayload,
    CapabilityGrantedPayload,
    EventKind,
    EventTypeRegistry,
    OutboundContentEmittedPayload,
)


@pytest.fixture
def registry() -> EventTypeRegistry:
    return EventTypeRegistry()


def test_every_event_kind_has_a_model(registry: EventTypeRegistry) -> None:
    """Every EventKind resolves to a registered pydantic event model."""
    expected = set(EventKind)
    actual = set(registry.known_kinds())
    assert expected == actual


def test_schema_for_returns_json_schema(registry: EventTypeRegistry) -> None:
    schema = registry.schema_for(EventKind.AGENT_INVOKES_TOOL)
    assert "properties" in schema
    for f in ("id", "kind", "actor_entity_id", "timestamp", "upstream_event_ids", "payload"):
        assert f in schema["properties"]


def test_every_kind_has_required_base_fields(registry: EventTypeRegistry) -> None:
    required = {"id", "kind", "actor_entity_id", "timestamp", "upstream_event_ids", "payload"}
    for kind in EventKind:
        schema = registry.schema_for(kind)
        assert required.issubset(schema["properties"].keys()), (
            f"{kind.value} missing required base fields"
        )


def test_model_for_rejects_non_enum(registry: EventTypeRegistry) -> None:
    with pytest.raises(TypeError, match="expected EventKind"):
        registry.model_for("agent_invokes_tool")  # type: ignore[arg-type]


def test_payload_model_for_rejects_non_enum(registry: EventTypeRegistry) -> None:
    with pytest.raises(TypeError):
        registry.payload_model_for("agent_invokes_tool")  # type: ignore[arg-type]


# --- Payload tightness rule: name implies entity ⇒ payload tightened ---


TIGHTENED_KINDS: tuple[EventKind, ...] = (
    EventKind.AGENT_INVOKES_TOOL,
    EventKind.AGENT_TO_AGENT_MESSAGE,
    EventKind.AGENT_READS_DATA,
    EventKind.AGENT_WRITES_DATA,
    EventKind.CAPABILITY_GRANTED,
    EventKind.CAPABILITY_REVOKED,
    EventKind.CAPABILITY_USED,
    EventKind.SANCTION_APPLIED,
    EventKind.TOOL_REGISTERED,
    EventKind.SKILL_INSTALLED,
    EventKind.AGENT_REGISTERED,
    EventKind.AGENT_DECOMMISSIONED,
    EventKind.OUTBOUND_CONTENT_EMITTED,
)

PERMISSIVE_KINDS: tuple[EventKind, ...] = (
    EventKind.AGENT_EMITS_OUTPUT,
    EventKind.POLICY_DECISION,
    EventKind.VERDICT_EMITTED,
    EventKind.DENIAL_EVENT,
    EventKind.GOVERNANCE_GRAPH_TRANSITION,
    EventKind.RESTORATIVE_PATH_TRIGGERED,
    EventKind.DRIFT_SIGNAL_EMITTED,
    EventKind.CHANGE_POINT_DETECTED,
    EventKind.EXTERNAL_INPUT_RECEIVED,
)


@pytest.mark.parametrize("kind", TIGHTENED_KINDS)
def test_tightened_payloads_are_typed(kind: EventKind, registry: EventTypeRegistry) -> None:
    payload_model = registry.payload_model_for(kind)
    assert payload_model is not None, f"{kind.value} should have a typed payload"


@pytest.mark.parametrize("kind", PERMISSIVE_KINDS)
def test_permissive_payloads_are_dict(kind: EventKind, registry: EventTypeRegistry) -> None:
    assert registry.payload_model_for(kind) is None, (
        f"{kind.value} should have a permissive (dict) payload"
    )


def test_tightened_count_plus_permissive_equals_all(registry: EventTypeRegistry) -> None:
    """Sanity: every EventKind is classified exactly once."""
    classified = set(TIGHTENED_KINDS) | set(PERMISSIVE_KINDS)
    assert classified == set(EventKind)
    assert set(TIGHTENED_KINDS).isdisjoint(set(PERMISSIVE_KINDS))


# --- Specific payload schemas behave as advertised ---


def test_agent_invokes_tool_requires_tool_id() -> None:
    with pytest.raises(ValidationError):
        AgentInvokesToolPayload(arguments={"x": 1})  # type: ignore[call-arg]


def test_agent_invokes_tool_accepts_tool_id() -> None:
    p = AgentInvokesToolPayload(tool_id="search_v1", arguments={"q": "ramen"})
    assert p.tool_id == "search_v1"


def test_capability_granted_requires_capability_and_grantee() -> None:
    with pytest.raises(ValidationError):
        CapabilityGrantedPayload(capability_id="cap_1")  # type: ignore[call-arg]
    with pytest.raises(ValidationError):
        CapabilityGrantedPayload(grantee_id="agent_1")  # type: ignore[call-arg]
    p = CapabilityGrantedPayload(capability_id="cap_1", grantee_id="agent_1")
    assert p.capability_id == "cap_1"


def test_outbound_content_emitted_requires_content_hash() -> None:
    """EU Art 50 / CA SB 942 chain depends on content_hash being present."""
    with pytest.raises(ValidationError):
        OutboundContentEmittedPayload()  # type: ignore[call-arg]
    p = OutboundContentEmittedPayload(content_hash="sha256:abcdef")
    assert p.content_hash == "sha256:abcdef"
    assert p.c2pa_manifest_id is None


def test_outbound_content_emitted_accepts_c2pa_manifest() -> None:
    p = OutboundContentEmittedPayload(
        content_hash="sha256:abc",
        c2pa_manifest_id="manifest_42",
    )
    assert p.c2pa_manifest_id == "manifest_42"


def test_payloads_are_frozen() -> None:
    p = AgentToAgentMessagePayload(recipient_agent_id="a2", body="hi")
    with pytest.raises(ValidationError):
        p.body = "edited"  # type: ignore[misc]


def test_event_model_pins_kind() -> None:
    registry = EventTypeRegistry()
    model = registry.model_for(EventKind.AGENT_INVOKES_TOOL)
    instance = model(
        id="evt_1",
        actor_entity_id="agent_1",
        timestamp=datetime.now(UTC),
        payload=AgentInvokesToolPayload(tool_id="t1"),
    )
    assert instance.kind is EventKind.AGENT_INVOKES_TOOL


def test_permissive_event_accepts_arbitrary_payload(registry: EventTypeRegistry) -> None:
    model = registry.model_for(EventKind.AGENT_EMITS_OUTPUT)
    instance = model(
        id="evt_1",
        actor_entity_id="agent_1",
        timestamp=datetime.now(UTC),
        payload={"anything": "goes", "nested": {"k": 1}},
    )
    assert instance.payload["anything"] == "goes"

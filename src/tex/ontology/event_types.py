"""
Typed events in the Tex ecosystem.

Every edge in the temporal knowledge graph has exactly one EventKind.

Each EventKind has a frozen pydantic v2 schema sharing a common base
(id, kind, actor_entity_id, target_entity_id, payload, timestamp,
upstream_event_ids, session_id).

Payload tightness rule
----------------------
Mechanical: if the EventKind name contains a verb-object pair implying a
second entity or specific artifact (e.g. ``_INVOKES_TOOL``,
``_TO_AGENT_MESSAGE``, ``_GRANTED``, ``_CONTENT_EMITTED``), the payload
subclass requires that entity's ID or artifact reference. Otherwise the
payload stays permissive ``dict[str, Any]`` with ``TODO(p1-tighten-schema)``.

OUTBOUND_CONTENT_EMITTED additionally requires ``content_hash`` so the
downstream EU Art 50 / CA SB 942 / FTC compliance chain can rely on the
hash being present without re-inspecting the payload dict.

References
----------
- AIRO (Golpayegani et al. 2022)
- arxiv 2604.00555 (Ontology-Constrained Neural Reasoning)
- arxiv 2604.04035 (Agentic Reference Monitor — first-class denied actions)
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class EventKind(str, Enum):
    # Action events
    AGENT_EMITS_OUTPUT = "agent_emits_output"
    AGENT_INVOKES_TOOL = "agent_invokes_tool"
    AGENT_TO_AGENT_MESSAGE = "agent_to_agent_message"
    AGENT_READS_DATA = "agent_reads_data"
    AGENT_WRITES_DATA = "agent_writes_data"

    # Capability events
    CAPABILITY_GRANTED = "capability_granted"
    CAPABILITY_REVOKED = "capability_revoked"
    CAPABILITY_USED = "capability_used"

    # Policy / verdict events
    POLICY_DECISION = "policy_decision"
    VERDICT_EMITTED = "verdict_emitted"
    DENIAL_EVENT = "denial_event"          # ARM-style first-class denied actions

    # Governance events
    GOVERNANCE_GRAPH_TRANSITION = "governance_graph_transition"
    SANCTION_APPLIED = "sanction_applied"
    RESTORATIVE_PATH_TRIGGERED = "restorative_path_triggered"

    # Lifecycle events
    AGENT_REGISTERED = "agent_registered"
    AGENT_DECOMMISSIONED = "agent_decommissioned"
    TOOL_REGISTERED = "tool_registered"
    SKILL_INSTALLED = "skill_installed"

    # Drift / detection events
    DRIFT_SIGNAL_EMITTED = "drift_signal_emitted"
    CHANGE_POINT_DETECTED = "change_point_detected"

    # External / boundary events
    EXTERNAL_INPUT_RECEIVED = "external_input_received"
    OUTBOUND_CONTENT_EMITTED = "outbound_content_emitted"


# --- Typed payload schemas (mechanical rule: name implies entity ⇒ tightened) ---


class _PayloadBase(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class AgentInvokesToolPayload(_PayloadBase):
    tool_id: str = Field(min_length=1, max_length=256)
    arguments: dict[str, Any] = Field(default_factory=dict)


class AgentToAgentMessagePayload(_PayloadBase):
    recipient_agent_id: str = Field(min_length=1, max_length=256)
    body: str = Field(min_length=1)


class AgentReadsDataPayload(_PayloadBase):
    dataset_id: str = Field(min_length=1, max_length=256)
    record_count: int | None = Field(default=None, ge=0)


class AgentWritesDataPayload(_PayloadBase):
    dataset_id: str = Field(min_length=1, max_length=256)
    record_count: int | None = Field(default=None, ge=0)


class CapabilityGrantedPayload(_PayloadBase):
    capability_id: str = Field(min_length=1, max_length=256)
    grantee_id: str = Field(min_length=1, max_length=256)
    expires_at: datetime | None = None


class CapabilityRevokedPayload(_PayloadBase):
    capability_id: str = Field(min_length=1, max_length=256)
    reason: str | None = Field(default=None, max_length=1_000)


class CapabilityUsedPayload(_PayloadBase):
    capability_id: str = Field(min_length=1, max_length=256)


class SanctionAppliedPayload(_PayloadBase):
    sanction_target_id: str = Field(min_length=1, max_length=256)
    sanction_kind: str = Field(min_length=1, max_length=128)


class ToolRegisteredPayload(_PayloadBase):
    tool_id: str = Field(min_length=1, max_length=256)


class SkillInstalledPayload(_PayloadBase):
    skill_id: str = Field(min_length=1, max_length=256)


class AgentRegisteredPayload(_PayloadBase):
    agent_id: str = Field(min_length=1, max_length=256)


class AgentDecommissionedPayload(_PayloadBase):
    agent_id: str = Field(min_length=1, max_length=256)


class OutboundContentEmittedPayload(_PayloadBase):
    """
    Boundary event: content crosses the org→external boundary.

    EU AI Act Art. 50 disclosure obligations, CA SB 942 watermarking, and
    FTC Section 5 deceptive-practice exposure all attach to this event.

    The c2pa/ package will populate ``c2pa_manifest_id`` once wired.
    """
    content_hash: str = Field(min_length=1, max_length=256)  # SHA-256 hex by default
    c2pa_manifest_id: str | None = None


# --- Permissive payloads (no entity in the name) ---


class PermissivePayload(_PayloadBase):
    """
    Open payload for events whose schema we have not tightened yet.

    TODO(p1-tighten-schema): replace with a typed subclass once the
    downstream consumer surfaces stabilize.
    """
    data: dict[str, Any] = Field(default_factory=dict)


# --- Event base + per-kind subclasses ---


class EventBase(BaseModel):
    """
    Base schema shared by every EventKind.

    Required fields (per scaffolded TODO): id, kind, actor_id, target_id?,
    payload, timestamp, upstream_event_ids.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(min_length=1, max_length=256)
    kind: EventKind
    actor_entity_id: str = Field(min_length=1, max_length=256)
    target_entity_id: str | None = Field(default=None, max_length=256)
    timestamp: datetime
    upstream_event_ids: tuple[str, ...] = Field(default_factory=tuple)
    session_id: str | None = Field(default=None, max_length=256)
    payload: Any  # tightened in subclasses


def _make_typed_event(kind_value: EventKind, payload_cls: type[_PayloadBase]) -> type[EventBase]:
    """Build a frozen subclass of EventBase that pins kind + payload type."""

    class _Typed(EventBase):
        kind: EventKind = Field(default=kind_value, frozen=True)
        payload: payload_cls  # type: ignore[valid-type]

    _Typed.__name__ = f"{payload_cls.__name__.removesuffix('Payload')}Event"
    _Typed.__qualname__ = _Typed.__name__
    return _Typed


def _make_permissive_event(kind_value: EventKind, name: str) -> type[EventBase]:
    """Build an event class with a permissive dict payload."""

    class _Permissive(EventBase):
        kind: EventKind = Field(default=kind_value, frozen=True)
        payload: dict[str, Any] = Field(default_factory=dict)

    _Permissive.__name__ = f"{name}Event"
    _Permissive.__qualname__ = _Permissive.__name__
    return _Permissive


# Tightened events (name implies a second entity or specific artifact)
AgentInvokesToolEvent = _make_typed_event(EventKind.AGENT_INVOKES_TOOL, AgentInvokesToolPayload)
AgentToAgentMessageEvent = _make_typed_event(EventKind.AGENT_TO_AGENT_MESSAGE, AgentToAgentMessagePayload)
AgentReadsDataEvent = _make_typed_event(EventKind.AGENT_READS_DATA, AgentReadsDataPayload)
AgentWritesDataEvent = _make_typed_event(EventKind.AGENT_WRITES_DATA, AgentWritesDataPayload)
CapabilityGrantedEvent = _make_typed_event(EventKind.CAPABILITY_GRANTED, CapabilityGrantedPayload)
CapabilityRevokedEvent = _make_typed_event(EventKind.CAPABILITY_REVOKED, CapabilityRevokedPayload)
CapabilityUsedEvent = _make_typed_event(EventKind.CAPABILITY_USED, CapabilityUsedPayload)
SanctionAppliedEvent = _make_typed_event(EventKind.SANCTION_APPLIED, SanctionAppliedPayload)
ToolRegisteredEvent = _make_typed_event(EventKind.TOOL_REGISTERED, ToolRegisteredPayload)
SkillInstalledEvent = _make_typed_event(EventKind.SKILL_INSTALLED, SkillInstalledPayload)
AgentRegisteredEvent = _make_typed_event(EventKind.AGENT_REGISTERED, AgentRegisteredPayload)
AgentDecommissionedEvent = _make_typed_event(EventKind.AGENT_DECOMMISSIONED, AgentDecommissionedPayload)
OutboundContentEmittedEvent = _make_typed_event(EventKind.OUTBOUND_CONTENT_EMITTED, OutboundContentEmittedPayload)

# Permissive events (no entity in the name)
AgentEmitsOutputEvent = _make_permissive_event(EventKind.AGENT_EMITS_OUTPUT, "AgentEmitsOutput")
PolicyDecisionEvent = _make_permissive_event(EventKind.POLICY_DECISION, "PolicyDecision")
VerdictEmittedEvent = _make_permissive_event(EventKind.VERDICT_EMITTED, "VerdictEmitted")
DenialEvent = _make_permissive_event(EventKind.DENIAL_EVENT, "Denial")
GovernanceGraphTransitionEvent = _make_permissive_event(EventKind.GOVERNANCE_GRAPH_TRANSITION, "GovernanceGraphTransition")
RestorativePathTriggeredEvent = _make_permissive_event(EventKind.RESTORATIVE_PATH_TRIGGERED, "RestorativePathTriggered")
DriftSignalEmittedEvent = _make_permissive_event(EventKind.DRIFT_SIGNAL_EMITTED, "DriftSignalEmitted")
ChangePointDetectedEvent = _make_permissive_event(EventKind.CHANGE_POINT_DETECTED, "ChangePointDetected")
ExternalInputReceivedEvent = _make_permissive_event(EventKind.EXTERNAL_INPUT_RECEIVED, "ExternalInputReceived")


_EVENT_MODELS: dict[EventKind, type[EventBase]] = {
    EventKind.AGENT_EMITS_OUTPUT: AgentEmitsOutputEvent,
    EventKind.AGENT_INVOKES_TOOL: AgentInvokesToolEvent,
    EventKind.AGENT_TO_AGENT_MESSAGE: AgentToAgentMessageEvent,
    EventKind.AGENT_READS_DATA: AgentReadsDataEvent,
    EventKind.AGENT_WRITES_DATA: AgentWritesDataEvent,
    EventKind.CAPABILITY_GRANTED: CapabilityGrantedEvent,
    EventKind.CAPABILITY_REVOKED: CapabilityRevokedEvent,
    EventKind.CAPABILITY_USED: CapabilityUsedEvent,
    EventKind.POLICY_DECISION: PolicyDecisionEvent,
    EventKind.VERDICT_EMITTED: VerdictEmittedEvent,
    EventKind.DENIAL_EVENT: DenialEvent,
    EventKind.GOVERNANCE_GRAPH_TRANSITION: GovernanceGraphTransitionEvent,
    EventKind.SANCTION_APPLIED: SanctionAppliedEvent,
    EventKind.RESTORATIVE_PATH_TRIGGERED: RestorativePathTriggeredEvent,
    EventKind.AGENT_REGISTERED: AgentRegisteredEvent,
    EventKind.AGENT_DECOMMISSIONED: AgentDecommissionedEvent,
    EventKind.TOOL_REGISTERED: ToolRegisteredEvent,
    EventKind.SKILL_INSTALLED: SkillInstalledEvent,
    EventKind.DRIFT_SIGNAL_EMITTED: DriftSignalEmittedEvent,
    EventKind.CHANGE_POINT_DETECTED: ChangePointDetectedEvent,
    EventKind.EXTERNAL_INPUT_RECEIVED: ExternalInputReceivedEvent,
    EventKind.OUTBOUND_CONTENT_EMITTED: OutboundContentEmittedEvent,
}


_PAYLOAD_MODELS: dict[EventKind, type[_PayloadBase] | None] = {
    EventKind.AGENT_INVOKES_TOOL: AgentInvokesToolPayload,
    EventKind.AGENT_TO_AGENT_MESSAGE: AgentToAgentMessagePayload,
    EventKind.AGENT_READS_DATA: AgentReadsDataPayload,
    EventKind.AGENT_WRITES_DATA: AgentWritesDataPayload,
    EventKind.CAPABILITY_GRANTED: CapabilityGrantedPayload,
    EventKind.CAPABILITY_REVOKED: CapabilityRevokedPayload,
    EventKind.CAPABILITY_USED: CapabilityUsedPayload,
    EventKind.SANCTION_APPLIED: SanctionAppliedPayload,
    EventKind.TOOL_REGISTERED: ToolRegisteredPayload,
    EventKind.SKILL_INSTALLED: SkillInstalledPayload,
    EventKind.AGENT_REGISTERED: AgentRegisteredPayload,
    EventKind.AGENT_DECOMMISSIONED: AgentDecommissionedPayload,
    EventKind.OUTBOUND_CONTENT_EMITTED: OutboundContentEmittedPayload,
    # permissive (no entity in name) → no typed payload
    EventKind.AGENT_EMITS_OUTPUT: None,
    EventKind.POLICY_DECISION: None,
    EventKind.VERDICT_EMITTED: None,
    EventKind.DENIAL_EVENT: None,
    EventKind.GOVERNANCE_GRAPH_TRANSITION: None,
    EventKind.RESTORATIVE_PATH_TRIGGERED: None,
    EventKind.DRIFT_SIGNAL_EMITTED: None,
    EventKind.CHANGE_POINT_DETECTED: None,
    EventKind.EXTERNAL_INPUT_RECEIVED: None,
}


class EventTypeRegistry:
    """Registry of event-type schemas."""

    def schema_for(self, kind: EventKind) -> dict[str, Any]:
        """
        Return the JSON Schema for the given EventKind.

        TODO(P0): return JSON Schema for the event payload
        TODO(P0): every event must have: id, kind, actor_id, target_id?,
                  payload, timestamp, upstream_event_ids
        """
        model = self.model_for(kind)
        return model.model_json_schema()

    def model_for(self, kind: EventKind) -> type[EventBase]:
        """Return the pydantic event model class for the given EventKind."""
        if not isinstance(kind, EventKind):
            raise TypeError(f"expected EventKind, got {type(kind).__name__}")
        try:
            return _EVENT_MODELS[kind]
        except KeyError as exc:
            raise KeyError(f"no schema registered for event kind {kind!r}") from exc

    def payload_model_for(self, kind: EventKind) -> type[_PayloadBase] | None:
        """Return the typed payload model for an EventKind, or None if permissive."""
        if not isinstance(kind, EventKind):
            raise TypeError(f"expected EventKind, got {type(kind).__name__}")
        return _PAYLOAD_MODELS.get(kind)

    def known_kinds(self) -> tuple[EventKind, ...]:
        """Return all EventKinds with a registered schema."""
        return tuple(_EVENT_MODELS.keys())

"""
Typed entities in the Tex ecosystem.

Every node in the temporal knowledge graph has exactly one EntityKind.

Each EntityKind has a frozen pydantic v2 schema sharing a common base
(id, kind, trust_label, capability_set, history_pointer, registered_at).
``EntityTypeRegistry.schema_for(kind)`` returns the JSON Schema; callers
that need to validate a payload dict use ``model_for(kind)``.

References
----------
- AIRO (Golpayegani et al. 2022)
- arxiv 2604.00555 (Ontology-Constrained Neural Reasoning)
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class EntityKind(str, Enum):
    AGENT = "agent"                        # an autonomous LLM agent
    TOOL = "tool"                          # an MCP tool / external function
    MCP_SERVER = "mcp_server"              # an MCP server hosting tools
    DATASET = "dataset"                    # an authorized training/RAG dataset
    MODEL = "model"                        # an LLM (foundation model)
    HUMAN = "human"                        # a human principal
    CAPABILITY = "capability"              # an unforgeable invocation right
    POLICY = "policy"                      # a Tex policy in effect
    GOVERNANCE_GRAPH = "governance_graph"  # an institutional governance graph
    SKILL = "skill"                        # a registered agent skill
    EXTERNAL_API = "external_api"          # a third-party HTTP/gRPC endpoint
    CONTRACT = "contract"                  # an agent behavioral contract


class TrustLabel(str, Enum):
    """Coarse trust labels for entities. Per AIRO RiskSource grading."""

    UNTRUSTED = "untrusted"
    LIMITED = "limited"
    TRUSTED = "trusted"
    PRIVILEGED = "privileged"


class EntityBase(BaseModel):
    """
    Base schema shared by every EntityKind.

    Required fields (per scaffolded TODO): id, kind, trust_label,
    capability_set, history_pointer.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(min_length=1, max_length=256)
    kind: EntityKind
    trust_label: TrustLabel = TrustLabel.UNTRUSTED
    capability_set: tuple[str, ...] = Field(default_factory=tuple)
    history_pointer: str | None = Field(default=None, max_length=256)
    registered_at: datetime
    metadata: dict[str, Any] = Field(default_factory=dict)


class AgentEntity(EntityBase):
    kind: EntityKind = Field(default=EntityKind.AGENT, frozen=True)
    model_id: str | None = None
    operator_id: str | None = None  # human or org responsible for this agent


class ToolEntity(EntityBase):
    kind: EntityKind = Field(default=EntityKind.TOOL, frozen=True)
    mcp_server_id: str | None = None
    schema_uri: str | None = None  # JSON-Schema URI for tool args


class McpServerEntity(EntityBase):
    kind: EntityKind = Field(default=EntityKind.MCP_SERVER, frozen=True)
    endpoint: str | None = None


class DatasetEntity(EntityBase):
    kind: EntityKind = Field(default=EntityKind.DATASET, frozen=True)
    provenance_uri: str | None = None  # ZKPROV anchor target
    license: str | None = None


class ModelEntity(EntityBase):
    kind: EntityKind = Field(default=EntityKind.MODEL, frozen=True)
    provider: str | None = None
    version: str | None = None


class HumanEntity(EntityBase):
    kind: EntityKind = Field(default=EntityKind.HUMAN, frozen=True)
    role: str | None = None  # see role_ontology


class CapabilityEntity(EntityBase):
    kind: EntityKind = Field(default=EntityKind.CAPABILITY, frozen=True)
    granted_by: str | None = None
    grantee_id: str | None = None
    expires_at: datetime | None = None


class PolicyEntity(EntityBase):
    kind: EntityKind = Field(default=EntityKind.POLICY, frozen=True)
    policy_version: str | None = None


class GovernanceGraphEntity(EntityBase):
    kind: EntityKind = Field(default=EntityKind.GOVERNANCE_GRAPH, frozen=True)
    graph_version: str | None = None


class SkillEntity(EntityBase):
    kind: EntityKind = Field(default=EntityKind.SKILL, frozen=True)
    owner_agent_id: str | None = None


class ExternalApiEntity(EntityBase):
    kind: EntityKind = Field(default=EntityKind.EXTERNAL_API, frozen=True)
    endpoint: str | None = None


class ContractEntity(EntityBase):
    kind: EntityKind = Field(default=EntityKind.CONTRACT, frozen=True)
    bound_agent_id: str | None = None
    contract_version: str | None = None


_ENTITY_MODELS: dict[EntityKind, type[EntityBase]] = {
    EntityKind.AGENT: AgentEntity,
    EntityKind.TOOL: ToolEntity,
    EntityKind.MCP_SERVER: McpServerEntity,
    EntityKind.DATASET: DatasetEntity,
    EntityKind.MODEL: ModelEntity,
    EntityKind.HUMAN: HumanEntity,
    EntityKind.CAPABILITY: CapabilityEntity,
    EntityKind.POLICY: PolicyEntity,
    EntityKind.GOVERNANCE_GRAPH: GovernanceGraphEntity,
    EntityKind.SKILL: SkillEntity,
    EntityKind.EXTERNAL_API: ExternalApiEntity,
    EntityKind.CONTRACT: ContractEntity,
}


class EntityTypeRegistry:
    """Registry of all known entity types and their schemas."""

    def schema_for(self, kind: EntityKind) -> dict[str, Any]:
        """
        Return the JSON Schema for the given EntityKind.

        TODO(P0): return JSON Schema for the entity payload
        TODO(P0): every entity must have: id, kind, trust_label,
                  capability_set, history_pointer
        """
        model = self.model_for(kind)
        return model.model_json_schema()

    def model_for(self, kind: EntityKind) -> type[EntityBase]:
        """Return the pydantic model class for the given EntityKind."""
        if not isinstance(kind, EntityKind):
            raise TypeError(f"expected EntityKind, got {type(kind).__name__}")
        try:
            return _ENTITY_MODELS[kind]
        except KeyError as exc:
            raise KeyError(f"no schema registered for entity kind {kind!r}") from exc

    def known_kinds(self) -> tuple[EntityKind, ...]:
        """Return all EntityKinds with a registered schema."""
        return tuple(_ENTITY_MODELS.keys())

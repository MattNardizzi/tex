"""
Agent governance HTTP routes.

Endpoints:

    POST   /v1/agents                     register a new agent
    GET    /v1/agents                     list agents (optional ?status=)
    GET    /v1/agents/{agent_id}          fetch an agent's current revision
    PATCH  /v1/agents/{agent_id}          update an agent (creates a new revision)
    POST   /v1/agents/{agent_id}/lifecycle    transition lifecycle status
    GET    /v1/agents/{agent_id}/history  full revision history
    GET    /v1/agents/{agent_id}/ledger   action ledger entries
    GET    /v1/agents/{agent_id}/baseline computed behavioral baseline

The routes pull stores out of app.state. They never bypass the registry
or ledger directly — those are the durable source of truth.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from fastapi import APIRouter, HTTPException, Path, Query, Request, status
from pydantic import BaseModel, ConfigDict, Field, field_validator

from tex.domain.agent import (
    AgentAttestation,
    AgentEnvironment,
    AgentIdentity,
    AgentLifecycleStatus,
    AgentTrustTier,
    BehavioralBaseline,
    CapabilitySurface,
)
from tex.stores.action_ledger import InMemoryActionLedger
from tex.stores.agent_registry import (
    AgentNotFoundError,
    InMemoryAgentRegistry,
)


# ---------------------------------------------------------------------------
# DTOs
# ---------------------------------------------------------------------------


class CapabilitySurfaceDTO(BaseModel):
    model_config = ConfigDict(extra="forbid")

    allowed_action_types: list[str] = Field(default_factory=list)
    allowed_channels: list[str] = Field(default_factory=list)
    allowed_environments: list[str] = Field(default_factory=list)
    allowed_recipient_domains: list[str] = Field(default_factory=list)
    allowed_tools: list[str] = Field(default_factory=list)
    allowed_mcp_servers: list[str] = Field(default_factory=list)
    data_scopes: list[str] = Field(default_factory=list)
    max_actions_per_hour: int | None = Field(default=None, ge=1)

    def to_domain(self) -> CapabilitySurface:
        return CapabilitySurface(
            allowed_action_types=tuple(self.allowed_action_types),
            allowed_channels=tuple(self.allowed_channels),
            allowed_environments=tuple(self.allowed_environments),
            allowed_recipient_domains=tuple(self.allowed_recipient_domains),
            allowed_tools=tuple(self.allowed_tools),
            allowed_mcp_servers=tuple(self.allowed_mcp_servers),
            data_scopes=tuple(self.data_scopes),
            max_actions_per_hour=self.max_actions_per_hour,
        )

    @classmethod
    def from_domain(cls, surface: CapabilitySurface) -> CapabilitySurfaceDTO:
        return cls(
            allowed_action_types=list(surface.allowed_action_types),
            allowed_channels=list(surface.allowed_channels),
            allowed_environments=list(surface.allowed_environments),
            allowed_recipient_domains=list(surface.allowed_recipient_domains),
            allowed_tools=list(surface.allowed_tools),
            allowed_mcp_servers=list(surface.allowed_mcp_servers),
            data_scopes=list(surface.data_scopes),
            max_actions_per_hour=surface.max_actions_per_hour,
        )


class AttestationDTO(BaseModel):
    model_config = ConfigDict(extra="forbid")

    attester: str = Field(min_length=1, max_length=200)
    claim: str = Field(min_length=1, max_length=500)
    issued_at: datetime
    expires_at: datetime | None = None
    signature: str | None = Field(default=None, max_length=2_000)
    metadata: dict[str, Any] = Field(default_factory=dict)

    def to_domain(self) -> AgentAttestation:
        return AgentAttestation(
            attester=self.attester,
            claim=self.claim,
            issued_at=_ensure_aware(self.issued_at),
            expires_at=_ensure_aware(self.expires_at) if self.expires_at else None,
            signature=self.signature,
            metadata=self.metadata,
        )

    @classmethod
    def from_domain(cls, attestation: AgentAttestation) -> AttestationDTO:
        return cls(
            attester=attestation.attester,
            claim=attestation.claim,
            issued_at=attestation.issued_at,
            expires_at=attestation.expires_at,
            signature=attestation.signature,
            metadata=attestation.metadata,
        )


class AgentDTO(BaseModel):
    """Public read shape for an agent."""

    model_config = ConfigDict(extra="forbid")

    agent_id: UUID
    revision: int

    name: str
    owner: str
    description: str | None = None

    tenant_id: str = "default"

    model_provider: str | None = None
    model_name: str | None = None
    framework: str | None = None

    environment: AgentEnvironment
    trust_tier: AgentTrustTier
    lifecycle_status: AgentLifecycleStatus

    capability_surface: CapabilitySurfaceDTO
    attestations: list[AttestationDTO]
    tags: list[str]
    metadata: dict[str, Any]

    registered_at: datetime
    updated_at: datetime

    @classmethod
    def from_domain(cls, agent: AgentIdentity) -> AgentDTO:
        return cls(
            agent_id=agent.agent_id,
            revision=agent.revision,
            name=agent.name,
            owner=agent.owner,
            description=agent.description,
            tenant_id=agent.tenant_id,
            model_provider=agent.model_provider,
            model_name=agent.model_name,
            framework=agent.framework,
            environment=agent.environment,
            trust_tier=agent.trust_tier,
            lifecycle_status=agent.lifecycle_status,
            capability_surface=CapabilitySurfaceDTO.from_domain(agent.capability_surface),
            attestations=[AttestationDTO.from_domain(a) for a in agent.attestations],
            tags=list(agent.tags),
            metadata=agent.metadata,
            registered_at=agent.registered_at,
            updated_at=agent.updated_at,
        )


class RegisterAgentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=200)
    owner: str = Field(min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=2_000)

    tenant_id: str = Field(default="default", min_length=1, max_length=200)

    model_provider: str | None = Field(default=None, max_length=100)
    model_name: str | None = Field(default=None, max_length=200)
    framework: str | None = Field(default=None, max_length=100)

    environment: AgentEnvironment = Field(default=AgentEnvironment.PRODUCTION)
    trust_tier: AgentTrustTier = Field(default=AgentTrustTier.STANDARD)
    lifecycle_status: AgentLifecycleStatus = Field(default=AgentLifecycleStatus.ACTIVE)

    capability_surface: CapabilitySurfaceDTO = Field(default_factory=CapabilitySurfaceDTO)
    attestations: list[AttestationDTO] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class UpdateAgentRequest(BaseModel):
    """Partial-update body. Any field omitted is left unchanged."""

    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, min_length=1, max_length=200)
    owner: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=2_000)

    model_provider: str | None = Field(default=None, max_length=100)
    model_name: str | None = Field(default=None, max_length=200)
    framework: str | None = Field(default=None, max_length=100)

    environment: AgentEnvironment | None = None
    trust_tier: AgentTrustTier | None = None

    capability_surface: CapabilitySurfaceDTO | None = None
    attestations: list[AttestationDTO] | None = None
    tags: list[str] | None = None
    metadata: dict[str, Any] | None = None


class LifecycleTransitionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: AgentLifecycleStatus


class AgentListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agents: list[AgentDTO]
    total: int


class AgentHistoryResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent_id: UUID
    revisions: list[AgentDTO]


class LedgerEntryDTO(BaseModel):
    model_config = ConfigDict(extra="forbid")

    entry_id: UUID
    agent_id: UUID
    session_id: str | None
    decision_id: UUID
    request_id: UUID
    verdict: str
    action_type: str
    channel: str
    environment: str
    recipient: str | None
    final_score: float
    confidence: float
    content_sha256: str
    capability_violations: list[str]
    asi_short_codes: list[str]
    recorded_at: datetime


class LedgerListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent_id: UUID
    entries: list[LedgerEntryDTO]
    total_returned: int
    total_in_ledger: int


class BaselineResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent_id: UUID
    sample_size: int
    permit_rate: float
    abstain_rate: float
    forbid_rate: float
    action_type_distribution: dict[str, float]
    channel_distribution: dict[str, float]
    recipient_domain_distribution: dict[str, float]
    mean_final_score: float
    capability_violation_rate: float
    forbid_streak: int
    computed_at: datetime

    @classmethod
    def from_domain(cls, baseline: BehavioralBaseline) -> BaselineResponse:
        return cls(
            agent_id=baseline.agent_id,
            sample_size=baseline.sample_size,
            permit_rate=baseline.permit_rate,
            abstain_rate=baseline.abstain_rate,
            forbid_rate=baseline.forbid_rate,
            action_type_distribution=baseline.action_type_distribution,
            channel_distribution=baseline.channel_distribution,
            recipient_domain_distribution=baseline.recipient_domain_distribution,
            mean_final_score=baseline.mean_final_score,
            capability_violation_rate=baseline.capability_violation_rate,
            forbid_streak=baseline.forbid_streak,
            computed_at=baseline.computed_at,
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ensure_aware(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=UTC)
    return value


def _resolve_registry(request: Request) -> InMemoryAgentRegistry:
    registry = getattr(request.app.state, "agent_registry", None)
    if registry is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="agent registry is not configured on this Tex deployment",
        )
    return registry


def _resolve_ledger(request: Request) -> InMemoryActionLedger:
    ledger = getattr(request.app.state, "action_ledger", None)
    if ledger is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="action ledger is not configured on this Tex deployment",
        )
    return ledger


def _ledger_entry_to_dto(entry: Any) -> LedgerEntryDTO:
    return LedgerEntryDTO(
        entry_id=entry.entry_id,
        agent_id=entry.agent_id,
        session_id=entry.session_id,
        decision_id=entry.decision_id,
        request_id=entry.request_id,
        verdict=entry.verdict,
        action_type=entry.action_type,
        channel=entry.channel,
        environment=entry.environment,
        recipient=entry.recipient,
        final_score=entry.final_score,
        confidence=entry.confidence,
        content_sha256=entry.content_sha256,
        capability_violations=list(entry.capability_violations),
        asi_short_codes=list(entry.asi_short_codes),
        recorded_at=entry.recorded_at,
    )


# ---------------------------------------------------------------------------
# Router builder
# ---------------------------------------------------------------------------


def build_agent_router() -> APIRouter:
    """
    Build the FastAPI router for agent governance endpoints.
    """
    router = APIRouter(prefix="/v1/agents", tags=["agent-governance"])

    @router.post(
        "",
        response_model=AgentDTO,
        status_code=status.HTTP_201_CREATED,
        summary="Register a new agent",
    )
    def register_agent(payload: RegisterAgentRequest, request: Request) -> AgentDTO:
        registry = _resolve_registry(request)
        agent = AgentIdentity(
            name=payload.name,
            owner=payload.owner,
            description=payload.description,
            tenant_id=payload.tenant_id,
            model_provider=payload.model_provider,
            model_name=payload.model_name,
            framework=payload.framework,
            environment=payload.environment,
            trust_tier=payload.trust_tier,
            lifecycle_status=payload.lifecycle_status,
            capability_surface=payload.capability_surface.to_domain(),
            attestations=tuple(a.to_domain() for a in payload.attestations),
            tags=tuple(payload.tags),
            metadata=payload.metadata,
        )
        stored = registry.save(agent)
        return AgentDTO.from_domain(stored)

    @router.get(
        "",
        response_model=AgentListResponse,
        summary="List agents",
    )
    def list_agents(
        request: Request,
        status_filter: AgentLifecycleStatus | None = Query(default=None, alias="status"),
    ) -> AgentListResponse:
        registry = _resolve_registry(request)
        if status_filter is not None:
            agents = registry.list_by_status(status_filter)
        else:
            agents = registry.list_all()
        return AgentListResponse(
            agents=[AgentDTO.from_domain(a) for a in agents],
            total=len(agents),
        )

    @router.get(
        "/{agent_id}",
        response_model=AgentDTO,
        summary="Fetch an agent's current revision",
    )
    def get_agent(
        request: Request,
        agent_id: UUID = Path(...),
    ) -> AgentDTO:
        registry = _resolve_registry(request)
        try:
            agent = registry.require(agent_id)
        except AgentNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return AgentDTO.from_domain(agent)

    @router.patch(
        "/{agent_id}",
        response_model=AgentDTO,
        summary="Update an agent (creates a new revision)",
    )
    def patch_agent(
        request: Request,
        payload: UpdateAgentRequest,
        agent_id: UUID = Path(...),
    ) -> AgentDTO:
        registry = _resolve_registry(request)
        try:
            current = registry.require(agent_id)
        except AgentNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

        updates: dict[str, Any] = {}
        if payload.name is not None:
            updates["name"] = payload.name
        if payload.owner is not None:
            updates["owner"] = payload.owner
        if payload.description is not None:
            updates["description"] = payload.description
        if payload.model_provider is not None:
            updates["model_provider"] = payload.model_provider
        if payload.model_name is not None:
            updates["model_name"] = payload.model_name
        if payload.framework is not None:
            updates["framework"] = payload.framework
        if payload.environment is not None:
            updates["environment"] = payload.environment
        if payload.trust_tier is not None:
            updates["trust_tier"] = payload.trust_tier
        if payload.capability_surface is not None:
            updates["capability_surface"] = payload.capability_surface.to_domain()
        if payload.attestations is not None:
            updates["attestations"] = tuple(a.to_domain() for a in payload.attestations)
        if payload.tags is not None:
            updates["tags"] = tuple(payload.tags)
        if payload.metadata is not None:
            updates["metadata"] = payload.metadata

        candidate = current.model_copy(update=updates)
        stored = registry.save(candidate)
        return AgentDTO.from_domain(stored)

    @router.post(
        "/{agent_id}/lifecycle",
        response_model=AgentDTO,
        summary="Transition agent lifecycle status",
    )
    def transition_lifecycle(
        request: Request,
        payload: LifecycleTransitionRequest,
        agent_id: UUID = Path(...),
    ) -> AgentDTO:
        registry = _resolve_registry(request)
        try:
            stored = registry.set_lifecycle(agent_id, payload.status)
        except AgentNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return AgentDTO.from_domain(stored)

    @router.get(
        "/{agent_id}/history",
        response_model=AgentHistoryResponse,
        summary="Full revision history for an agent",
    )
    def get_history(
        request: Request,
        agent_id: UUID = Path(...),
    ) -> AgentHistoryResponse:
        registry = _resolve_registry(request)
        revisions = registry.history(agent_id)
        if not revisions:
            raise HTTPException(status_code=404, detail=f"agent not found: {agent_id}")
        return AgentHistoryResponse(
            agent_id=agent_id,
            revisions=[AgentDTO.from_domain(r) for r in revisions],
        )

    @router.get(
        "/{agent_id}/ledger",
        response_model=LedgerListResponse,
        summary="Action ledger entries for an agent",
    )
    def get_ledger(
        request: Request,
        agent_id: UUID = Path(...),
        limit: int = Query(default=50, ge=1, le=500),
    ) -> LedgerListResponse:
        ledger = _resolve_ledger(request)
        entries = ledger.list_for_agent(agent_id, limit=limit)
        return LedgerListResponse(
            agent_id=agent_id,
            entries=[_ledger_entry_to_dto(e) for e in entries],
            total_returned=len(entries),
            total_in_ledger=ledger.count_for_agent(agent_id),
        )

    @router.get(
        "/{agent_id}/baseline",
        response_model=BaselineResponse,
        summary="Computed behavioral baseline for an agent",
    )
    def get_baseline(
        request: Request,
        agent_id: UUID = Path(...),
        window: int = Query(default=200, ge=1, le=2_000),
    ) -> BaselineResponse:
        ledger = _resolve_ledger(request)
        baseline = ledger.compute_baseline(agent_id, window=window)
        return BaselineResponse.from_domain(baseline)

    return router

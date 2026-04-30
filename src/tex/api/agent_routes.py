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

from collections import Counter
from datetime import UTC, datetime
import hashlib
import hmac
import os
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
    policy_version: str | None = None
    evidence_hash: str | None = None
    capability_violations: list[str]
    asi_short_codes: list[str]
    system_prompt_hash: str | None = None
    tool_manifest_hash: str | None = None
    memory_hash: str | None = None
    mcp_server_ids: list[str] = Field(default_factory=list)
    tools: list[str] = Field(default_factory=list)
    data_scopes: list[str] = Field(default_factory=list)
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




class EvidenceSummaryResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent_id: UUID
    period: str
    total_decisions: int
    permit_count: int
    abstain_count: int
    forbid_count: int
    permit_rate: float
    abstain_rate: float
    forbid_rate: float
    policy_versions: list[str]
    top_asi_codes: dict[str, int]
    top_capability_violations: dict[str, int]
    evidence_hashes: list[str]
    evidence_root_sha256: str
    signature_hmac_sha256: str


class SystemicRiskDTO(BaseModel):
    model_config = ConfigDict(extra="forbid")

    pattern_type: str
    pattern: str
    affected_agent_count: int
    affected_agent_ids: list[UUID]
    occurrence_count: int
    severity: str


class SystemicRiskResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    risks: list[SystemicRiskDTO]
    total: int


# ---------------------------------------------------------------------------
# Governance-state DTOs
# ---------------------------------------------------------------------------
#
# The governance-state matrix is the headline output of the dual-source
# discovery layer. It joins what external connectors saw with what the
# adjudication-derived ledger has actually evaluated, and labels every
# agent with one of four states:
#
#   GOVERNED  — externally observed AND adjudicated (we see it, we have
#               evidence of every decision)
#   UNGOVERNED — externally observed but never adjudicated (it exists
#                but is bypassing Tex; this is the alert state)
#   PARTIAL   — adjudicated but never externally observed (we have
#               evidence but no independent corroboration)
#   UNKNOWN   — neither (residual blind spot; honest acknowledgement
#               that some agents are out of reach)
#
# A buyer reads this and immediately understands what coverage they
# have. A regulator reads this and understands what we claim to govern
# and what we admit we don't. Zenity and Noma cannot produce this
# matrix because their discovery and their content security are
# different products.


class GovernanceAgentDTO(BaseModel):
    """One row in the governance-state matrix."""

    model_config = ConfigDict(extra="forbid")

    # Tex's internal agent_id, present iff the agent is registered
    # (either externally promoted or adjudication-derived).
    agent_id: UUID | None = None

    # Discovery-side identity, present iff an external connector saw
    # the agent. Both nulls + non-null agent_id = adjudication-only.
    discovery_source: str | None = None
    external_id: str | None = None
    reconciliation_key: str | None = None

    # Display fields.
    name: str
    tenant_id: str
    owner: str | None = None
    risk_band: str | None = None

    # Governance state.
    governance_state: str
    externally_observed: bool
    adjudicated: bool
    decision_count: int
    forbid_count: int
    last_decision_at: datetime | None = None
    last_seen_externally_at: datetime | None = None
    discovery_mode: str | None = None  # "adjudication_derived" | "discovery_promoted"


class GovernanceCountsDTO(BaseModel):
    """Aggregate counts for the governance-state response."""

    model_config = ConfigDict(extra="forbid")

    total_agents: int
    governed: int
    ungoverned: int
    partial: int
    unknown: int

    # Risk-weighted breakdowns. These are the lines that go straight
    # into the headline of a buyer briefing.
    high_risk_total: int
    high_risk_ungoverned: int
    governed_with_forbids: int


class GovernanceResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    counts: GovernanceCountsDTO
    agents: list[GovernanceAgentDTO]
    coverage_root_sha256: str
    signature_hmac_sha256: str
    generated_at: datetime


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


def _resolve_discovery_ledger(request: Request):
    """
    Resolve the discovery ledger from app.state.

    Returns ``None`` when discovery is not wired (rather than raising).
    The governance endpoint treats a missing discovery ledger as "no
    external observations available" and produces a meaningful PARTIAL
    matrix from adjudication-derived agents alone, instead of
    refusing to respond.
    """
    return getattr(request.app.state, "discovery_ledger", None)


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
        policy_version=entry.policy_version,
        evidence_hash=entry.evidence_hash,
        capability_violations=list(entry.capability_violations),
        asi_short_codes=list(entry.asi_short_codes),
        system_prompt_hash=entry.system_prompt_hash,
        tool_manifest_hash=entry.tool_manifest_hash,
        memory_hash=entry.memory_hash,
        mcp_server_ids=list(entry.mcp_server_ids),
        tools=list(entry.tools),
        data_scopes=list(entry.data_scopes),
        recorded_at=entry.recorded_at,
    )




def _evidence_root(entries: tuple[Any, ...]) -> str:
    hashes = [entry.evidence_hash for entry in entries if entry.evidence_hash]
    raw = "|".join(hashes) if hashes else "no-evidence-hashes"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _sign_summary(payload: str) -> str:
    secret = os.environ.get("TEX_EVIDENCE_SUMMARY_SECRET", "dev-only-change-me")
    return hmac.new(secret.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()


def _rate(count: int, total: int) -> float:
    if total <= 0:
        return 0.0
    return round(count / total, 4)


def _top(counter: Counter[str], limit: int = 10) -> dict[str, int]:
    return dict(counter.most_common(limit))


def _build_systemic_risks(entries: tuple[Any, ...]) -> list[SystemicRiskDTO]:
    grouped: dict[tuple[str, str], list[Any]] = {}
    for entry in entries:
        for code in entry.asi_short_codes:
            grouped.setdefault(("asi_code", code), []).append(entry)
        for violation in entry.capability_violations:
            grouped.setdefault(("capability_violation", violation), []).append(entry)
        if entry.tool_manifest_hash:
            grouped.setdefault(("tool_manifest_hash", entry.tool_manifest_hash), []).append(entry)
        for server_id in entry.mcp_server_ids:
            grouped.setdefault(("mcp_server", server_id), []).append(entry)

    risks: list[SystemicRiskDTO] = []
    for (pattern_type, pattern), matches in grouped.items():
        agent_ids = sorted({m.agent_id for m in matches}, key=str)
        if len(agent_ids) < 2:
            continue
        severity = "HIGH" if pattern_type in {"asi_code", "capability_violation"} else "MEDIUM"
        risks.append(
            SystemicRiskDTO(
                pattern_type=pattern_type,
                pattern=pattern,
                affected_agent_count=len(agent_ids),
                affected_agent_ids=agent_ids,
                occurrence_count=len(matches),
                severity=severity,
            )
        )

    risks.sort(key=lambda item: (-item.affected_agent_count, -item.occurrence_count, item.pattern_type, item.pattern))
    return risks


# ---------------------------------------------------------------------------
# Governance-state computation
# ---------------------------------------------------------------------------
#
# This is the core of the dual-source discovery story. Three inputs:
#
#   1. agent_registry      — every AgentIdentity Tex has registered
#                            (manually OR auto-promoted by adjudication
#                            OR auto-promoted by external discovery).
#   2. action_ledger       — the per-decision evidence chain. An agent
#                            with at least one entry here has actually
#                            been adjudicated.
#   3. discovery_ledger    — every reconciliation outcome from external
#                            connector scans. An agent_id appearing on
#                            an outcome means an external connector
#                            saw it.
#
# The crosswalk:
#
#   adjudicated  := registry.list_for_agent(agent_id) is non-empty
#                   OR metadata.discovery_mode == "adjudication_derived"
#
#   externally_observed := agent_id has any discovery_ledger entry
#                          whose outcome.resulting_agent_id == agent_id
#                          OR metadata carries discovery_source / discovery_external_id
#
# We also surface "ghost" candidates: reconciliation_keys present in
# the discovery ledger that never resolved to an AgentIdentity (held,
# below threshold, ambiguous). These are externally-observed agents
# Tex chose not to auto-register and are the cleanest example of
# UNGOVERNED-by-design.


def _classify_governance_state(
    *,
    externally_observed: bool,
    adjudicated: bool,
) -> str:
    if externally_observed and adjudicated:
        return "GOVERNED"
    if externally_observed and not adjudicated:
        return "UNGOVERNED"
    if adjudicated and not externally_observed:
        return "PARTIAL"
    return "UNKNOWN"


def _agent_external_signals(agent: AgentIdentity) -> tuple[str | None, str | None]:
    """
    Pull ``(discovery_source, external_id)`` from agent metadata if
    present. Adjudication-derived auto-registrations stamp these onto
    metadata when the request carries an ``external_agent_id``;
    discovery-promoted agents stamp them from the connector source.
    """
    metadata = agent.metadata or {}
    source = metadata.get("discovery_source")
    external_id = metadata.get("discovery_external_id") or metadata.get("external_agent_id")
    if isinstance(source, str) and source.strip():
        source_value = source.strip()
    else:
        source_value = None
    if isinstance(external_id, str) and external_id.strip():
        external_id_value = external_id.strip()
    else:
        external_id_value = None
    return source_value, external_id_value


def _build_governance(
    *,
    registry: InMemoryAgentRegistry,
    action_ledger: InMemoryActionLedger,
    discovery_ledger: Any,
) -> GovernanceResponse:
    # 1. Index every reconciliation outcome by resulting_agent_id and
    # by reconciliation_key so we can answer both "is this registered
    # agent externally observed?" and "are there externally-observed
    # candidates that never made it into the registry?"
    discovery_entries: tuple[Any, ...] = (
        discovery_ledger.list_all() if discovery_ledger is not None else tuple()
    )

    observed_agent_ids: set[UUID] = set()
    last_seen_external_by_agent: dict[UUID, datetime] = {}
    discovery_meta_by_agent: dict[UUID, dict[str, Any]] = {}
    candidates_without_agent: dict[str, dict[str, Any]] = {}

    for entry in discovery_entries:
        candidate = entry.candidate
        outcome = entry.outcome
        if outcome.resulting_agent_id is not None:
            agent_id = outcome.resulting_agent_id
            observed_agent_ids.add(agent_id)
            seen_at = candidate.last_seen_active_at or candidate.discovered_at
            if seen_at is not None:
                prior = last_seen_external_by_agent.get(agent_id)
                if prior is None or seen_at > prior:
                    last_seen_external_by_agent[agent_id] = seen_at
            discovery_meta_by_agent[agent_id] = {
                "discovery_source": str(candidate.source),
                "external_id": candidate.external_id,
                "reconciliation_key": outcome.reconciliation_key,
                "risk_band": str(candidate.risk_band),
                "name": candidate.name,
                "owner_hint": candidate.owner_hint,
                "tenant_id": candidate.tenant_id,
            }
        else:
            # Held / ambiguous / below-threshold: agent exists out there
            # but Tex did not promote it. This is the purest UNGOVERNED
            # row.
            key = outcome.reconciliation_key
            seen_at = candidate.last_seen_active_at or candidate.discovered_at
            existing = candidates_without_agent.get(key)
            if existing is None or (
                seen_at is not None
                and (existing.get("last_seen_externally_at") is None
                     or seen_at > existing["last_seen_externally_at"])
            ):
                candidates_without_agent[key] = {
                    "discovery_source": str(candidate.source),
                    "external_id": candidate.external_id,
                    "reconciliation_key": key,
                    "risk_band": str(candidate.risk_band),
                    "name": candidate.name,
                    "owner_hint": candidate.owner_hint,
                    "tenant_id": candidate.tenant_id,
                    "last_seen_externally_at": seen_at,
                }

    # 2. Walk the registry. Each AgentIdentity is one row.
    rows: list[GovernanceAgentDTO] = []
    counts = {
        "GOVERNED": 0,
        "UNGOVERNED": 0,
        "PARTIAL": 0,
        "UNKNOWN": 0,
    }
    high_risk_total = 0
    high_risk_ungoverned = 0
    governed_with_forbids = 0

    for agent in registry.list_all():
        ledger_entries = action_ledger.list_for_agent(agent.agent_id)
        decision_count = len(ledger_entries)
        forbid_count = sum(1 for e in ledger_entries if str(e.verdict).upper() == "FORBID")
        last_decision_at: datetime | None = None
        if ledger_entries:
            last_decision_at = max(
                _ensure_aware(e.recorded_at) for e in ledger_entries
            )

        # adjudicated if we have decisions OR the agent carries the
        # adjudication_derived discovery_mode marker (auto-registered
        # by the gate but with zero subsequent traffic — still counts
        # as having entered through the adjudication path).
        metadata = agent.metadata or {}
        adjudicated = decision_count > 0 or (
            metadata.get("discovery_mode") == "adjudication_derived"
        )

        # External observation: either the discovery ledger linked
        # this agent_id to an outcome, OR the agent metadata carries
        # explicit discovery provenance (which is true for every
        # promoted candidate).
        meta_source, meta_external_id = _agent_external_signals(agent)
        externally_observed = (
            agent.agent_id in observed_agent_ids
            or (meta_source is not None and meta_external_id is not None
                and metadata.get("discovery_mode") != "adjudication_derived")
        )

        # Pull the most useful identity tuple we have for this agent.
        disc_meta = discovery_meta_by_agent.get(agent.agent_id, {})
        discovery_source = disc_meta.get("discovery_source") or meta_source
        external_id = disc_meta.get("external_id") or meta_external_id
        reconciliation_key = disc_meta.get("reconciliation_key")
        risk_band = disc_meta.get("risk_band") or metadata.get("discovery_risk_band")

        governance_state = _classify_governance_state(
            externally_observed=externally_observed,
            adjudicated=adjudicated,
        )
        counts[governance_state] += 1

        is_high_risk = isinstance(risk_band, str) and risk_band.upper() in {"HIGH", "CRITICAL"}
        if is_high_risk:
            high_risk_total += 1
            if governance_state == "UNGOVERNED":
                high_risk_ungoverned += 1
        if governance_state == "GOVERNED" and forbid_count > 0:
            governed_with_forbids += 1

        rows.append(
            GovernanceAgentDTO(
                agent_id=agent.agent_id,
                discovery_source=discovery_source,
                external_id=external_id,
                reconciliation_key=reconciliation_key,
                name=agent.name,
                tenant_id=agent.tenant_id,
                owner=agent.owner,
                risk_band=risk_band,
                governance_state=governance_state,
                externally_observed=externally_observed,
                adjudicated=adjudicated,
                decision_count=decision_count,
                forbid_count=forbid_count,
                last_decision_at=last_decision_at,
                last_seen_externally_at=last_seen_external_by_agent.get(agent.agent_id),
                discovery_mode=metadata.get("discovery_mode"),
            )
        )

    # 3. Now add ghost rows: candidates seen externally that never
    # resolved into the registry. These are pure UNGOVERNED.
    for key, ghost in candidates_without_agent.items():
        risk_band = ghost.get("risk_band")
        is_high_risk = isinstance(risk_band, str) and risk_band.upper() in {"HIGH", "CRITICAL"}
        counts["UNGOVERNED"] += 1
        if is_high_risk:
            high_risk_total += 1
            high_risk_ungoverned += 1

        rows.append(
            GovernanceAgentDTO(
                agent_id=None,
                discovery_source=ghost["discovery_source"],
                external_id=ghost["external_id"],
                reconciliation_key=ghost["reconciliation_key"],
                name=ghost["name"],
                tenant_id=ghost["tenant_id"],
                owner=ghost.get("owner_hint"),
                risk_band=risk_band,
                governance_state="UNGOVERNED",
                externally_observed=True,
                adjudicated=False,
                decision_count=0,
                forbid_count=0,
                last_decision_at=None,
                last_seen_externally_at=ghost.get("last_seen_externally_at"),
                discovery_mode=None,
            )
        )

    # Stable sort: state severity, then risk severity, then name.
    state_priority = {"UNGOVERNED": 0, "PARTIAL": 1, "GOVERNED": 2, "UNKNOWN": 3}
    risk_priority = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    rows.sort(
        key=lambda row: (
            state_priority.get(row.governance_state, 99),
            risk_priority.get((row.risk_band or "").upper(), 99),
            row.name.casefold(),
        )
    )

    counts_dto = GovernanceCountsDTO(
        total_agents=len(rows),
        governed=counts["GOVERNED"],
        ungoverned=counts["UNGOVERNED"],
        partial=counts["PARTIAL"],
        unknown=counts["UNKNOWN"],
        high_risk_total=high_risk_total,
        high_risk_ungoverned=high_risk_ungoverned,
        governed_with_forbids=governed_with_forbids,
    )

    # Coverage root: a stable hash of the (agent_id|recon_key|state)
    # tuples in deterministic order. Lets a regulator verify that a
    # later snapshot of the system covered the same set of agents.
    coverage_lines = sorted(
        f"{row.agent_id or ''}|{row.reconciliation_key or ''}|{row.governance_state}"
        for row in rows
    )
    coverage_payload = "\n".join(coverage_lines)
    coverage_root = hashlib.sha256(coverage_payload.encode("utf-8")).hexdigest()

    signature_payload = "|".join(
        [
            "governance",
            str(counts_dto.total_agents),
            str(counts_dto.governed),
            str(counts_dto.ungoverned),
            str(counts_dto.partial),
            str(counts_dto.unknown),
            coverage_root,
        ]
    )

    return GovernanceResponse(
        counts=counts_dto,
        agents=rows,
        coverage_root_sha256=coverage_root,
        signature_hmac_sha256=_sign_summary(signature_payload),
        generated_at=datetime.now(UTC),
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
        "/systemic-risks",
        response_model=SystemicRiskResponse,
        summary="Cross-agent evidence patterns and systemic risk signals",
    )
    def systemic_risks(
        request: Request,
        limit: int = Query(default=5_000, ge=1, le=50_000),
    ) -> SystemicRiskResponse:
        ledger = _resolve_ledger(request)
        entries = ledger.list_all(limit=limit)
        risks = _build_systemic_risks(entries)
        return SystemicRiskResponse(risks=risks, total=len(risks))

    @router.get(
        "/governance",
        response_model=GovernanceResponse,
        summary="Dual-source governance-state matrix (GOVERNED / UNGOVERNED / PARTIAL / UNKNOWN)",
    )
    def governance_state(request: Request) -> GovernanceResponse:
        registry = _resolve_registry(request)
        action_ledger = _resolve_ledger(request)
        discovery_ledger = _resolve_discovery_ledger(request)
        return _build_governance(
            registry=registry,
            action_ledger=action_ledger,
            discovery_ledger=discovery_ledger,
        )

    @router.get(
        "/{agent_id}/evidence_summary",
        response_model=EvidenceSummaryResponse,
        summary="Signed evidence-backed activity summary for one agent",
    )
    def get_evidence_summary(
        request: Request,
        agent_id: UUID = Path(...),
        limit: int = Query(default=500, ge=1, le=5_000),
    ) -> EvidenceSummaryResponse:
        ledger = _resolve_ledger(request)
        entries = ledger.list_for_agent(agent_id, limit=limit)
        total = len(entries)

        verdicts = Counter(entry.verdict.upper() for entry in entries)
        policies = sorted(
            {entry.policy_version for entry in entries if entry.policy_version}
        )
        asi = Counter(code for entry in entries for code in entry.asi_short_codes)
        violations = Counter(
            violation
            for entry in entries
            for violation in entry.capability_violations
        )
        evidence_hashes = [entry.evidence_hash for entry in entries if entry.evidence_hash]
        evidence_root = _evidence_root(entries)

        signature_payload = "|".join(
            [
                str(agent_id),
                str(total),
                str(verdicts.get("PERMIT", 0)),
                str(verdicts.get("ABSTAIN", 0)),
                str(verdicts.get("FORBID", 0)),
                evidence_root,
                ",".join(policies),
            ]
        )

        return EvidenceSummaryResponse(
            agent_id=agent_id,
            period=f"latest_{limit}_ledger_entries",
            total_decisions=total,
            permit_count=verdicts.get("PERMIT", 0),
            abstain_count=verdicts.get("ABSTAIN", 0),
            forbid_count=verdicts.get("FORBID", 0),
            permit_rate=_rate(verdicts.get("PERMIT", 0), total),
            abstain_rate=_rate(verdicts.get("ABSTAIN", 0), total),
            forbid_rate=_rate(verdicts.get("FORBID", 0), total),
            policy_versions=policies,
            top_asi_codes=_top(asi),
            top_capability_violations=_top(violations),
            evidence_hashes=evidence_hashes,
            evidence_root_sha256=evidence_root,
            signature_hmac_sha256=_sign_summary(signature_payload),
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

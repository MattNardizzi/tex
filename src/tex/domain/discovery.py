"""
Discovery domain models.

Tex's discovery layer answers the upstream half of the agent governance
question: "what agents exist in this organization that I have not yet
been told about?" It complements the existing identity / capability /
behavioral / content evaluation streams by feeding them a stream of
candidate agents that were never explicitly registered.

The shape of this module mirrors the rest of the Tex domain:

- frozen Pydantic models with extra='forbid'
- timezone-aware datetimes everywhere
- nothing here knows about HTTP, SDKs, or specific platform APIs;
  connectors live in tex.discovery.connectors and adapt the platform
  shape to the canonical CandidateAgent shape declared here

Discovery findings are not just dashboard items. Every CandidateAgent
that crosses a confidence threshold gets reconciled against the agent
registry — promoted to a real AgentIdentity if new, used to detect
drift if already known. The reconciliation outcome is recorded in the
discovery ledger which is hash-chained the same way the evidence chain
is, so the auditor can prove later "this agent was discovered, on this
day, by this connector, with this evidence, and was promoted under
these conditions."
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from tex.domain.agent import AgentEnvironment, AgentTrustTier


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class DiscoverySource(StrEnum):
    """
    The platform a CandidateAgent was found on.

    These names are stable and lowercase-friendly because they appear
    in URLs, log lines, evidence records, and reconciliation keys. New
    connectors should add a new entry here rather than reusing an
    existing one — the reconciliation key is partly composed from the
    source, and conflating two platforms would corrupt it.
    """

    MICROSOFT_GRAPH = "microsoft_graph"
    SALESFORCE = "salesforce"
    AWS_BEDROCK = "aws_bedrock"
    GITHUB = "github"
    OPENAI = "openai"
    SLACK = "slack"
    MCP_SERVER = "mcp_server"
    LANGSMITH = "langsmith"
    GENERIC = "generic"


class DiscoveryFindingKind(StrEnum):
    """
    What this CandidateAgent represents relative to the registry.

    The reconciliation engine produces one of these labels for every
    candidate. The label decides whether the candidate is promoted,
    used to update an existing agent, or held for review.
    """

    NEW_AGENT = "new_agent"
    KNOWN_AGENT_UNCHANGED = "known_agent_unchanged"
    KNOWN_AGENT_DRIFT = "known_agent_drift"
    DUPLICATE = "duplicate"
    AMBIGUOUS = "ambiguous"


class DiscoveryRiskBand(StrEnum):
    """
    Coarse risk band assigned by the connector based on platform signals.

    The connector knows things Tex's evaluation layer does not — for
    example, whether a Microsoft Copilot Studio agent has been granted
    `Mail.Send` on a tenant-wide scope. The risk band is the
    connector's structured opinion. The reconciliation engine uses it
    to bias trust tier on auto-promotion.
    """

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def suggested_trust_tier(self) -> AgentTrustTier:
        """
        Trust tier the reconciliation engine should propose for an
        auto-registered candidate at this risk band.

        We never auto-promote anything above STANDARD. Operators who
        want to bless a discovered agent up to TRUSTED or PRIVILEGED
        do that explicitly via the patch endpoint.
        """

        return {
            DiscoveryRiskBand.LOW: AgentTrustTier.STANDARD,
            DiscoveryRiskBand.MEDIUM: AgentTrustTier.UNVERIFIED,
            DiscoveryRiskBand.HIGH: AgentTrustTier.UNVERIFIED,
            DiscoveryRiskBand.CRITICAL: AgentTrustTier.UNVERIFIED,
        }[self]


class ReconciliationAction(StrEnum):
    """
    What the reconciliation engine actually did with a candidate.

    Records of these actions form the discovery ledger. Each is
    described in past tense because the ledger is append-only — by
    the time it lands here, the action has already been taken.
    """

    REGISTERED = "registered"
    UPDATED_DRIFT = "updated_drift"
    QUARANTINED_FOR_DRIFT = "quarantined_for_drift"
    NO_OP_KNOWN_UNCHANGED = "no_op_known_unchanged"
    NO_OP_BELOW_THRESHOLD = "no_op_below_threshold"
    HELD_AMBIGUOUS = "held_ambiguous"
    HELD_DUPLICATE = "held_duplicate"
    SKIPPED_REVOKED = "skipped_revoked"


# ---------------------------------------------------------------------------
# Capability hints (a connector's view of what the agent can do)
# ---------------------------------------------------------------------------


class DiscoveredCapabilityHints(BaseModel):
    """
    Capability surface inferred by a connector from the platform's view
    of the agent.

    These are *hints*, not declarations. They are the strongest
    structural information available at discovery time, and they may
    or may not match the runtime capability surface the agent actually
    uses. Reconciliation uses them as the proposed surface for new
    agents and as the drift signal for known agents.

    Empty tuples mean "the connector did not observe a restriction on
    this dimension," which is different from "the connector observed
    that the agent is unrestricted." The connector encodes that latter
    case explicitly via the `surface_unbounded` flag.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    inferred_action_types: tuple[str, ...] = Field(default_factory=tuple)
    inferred_channels: tuple[str, ...] = Field(default_factory=tuple)
    inferred_recipient_domains: tuple[str, ...] = Field(default_factory=tuple)
    inferred_tools: tuple[str, ...] = Field(default_factory=tuple)
    inferred_mcp_servers: tuple[str, ...] = Field(default_factory=tuple)
    inferred_data_scopes: tuple[str, ...] = Field(default_factory=tuple)

    surface_unbounded: bool = Field(
        default=False,
        description=(
            "True if the connector observed evidence that the agent is "
            "explicitly unrestricted on the platform side — for example, "
            "a Microsoft Graph permission grant of `Mail.Send` on the "
            "whole tenant, or a Salesforce profile with all object "
            "permissions. Auto-promotion never happens for unbounded "
            "surfaces; they always require operator review."
        ),
    )

    @field_validator(
        "inferred_action_types",
        "inferred_channels",
        "inferred_recipient_domains",
        "inferred_tools",
        "inferred_mcp_servers",
        "inferred_data_scopes",
        mode="before",
    )
    @classmethod
    def _normalize_string_tuple(cls, value: Any) -> tuple[str, ...]:
        if value is None:
            return tuple()
        if isinstance(value, str):
            raise TypeError("expected a sequence of strings, not a single string")
        if not hasattr(value, "__iter__"):
            raise TypeError("expected a sequence of strings")
        out: list[str] = []
        seen: set[str] = set()
        for item in value:
            if not isinstance(item, str):
                raise TypeError("each item must be a string")
            normalized = item.strip().casefold()
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            out.append(normalized)
        out.sort()
        return tuple(out)


# ---------------------------------------------------------------------------
# Candidate agent — the canonical discovery output a connector emits
# ---------------------------------------------------------------------------


class CandidateAgent(BaseModel):
    """
    A single discovered agent in the canonical Tex shape.

    Every connector — Microsoft Graph, Salesforce, AWS Bedrock,
    GitHub, OpenAI, MCP — translates its native objects into a
    sequence of CandidateAgent records. The reconciliation engine
    operates on these records exclusively; it knows nothing about
    individual platforms.

    The `external_id` field is the platform-side identifier (e.g. an
    Azure object ID, a Salesforce 18-character ID, a GitHub install
    ID). Combined with `source` and `tenant_id`, it forms the
    reconciliation key — the tuple Tex uses to decide whether two
    discovery records refer to the same agent.

    `evidence` carries the raw platform-side artifact the connector
    used to construct this record: a redacted bot definition, the
    OAuth scope tuple, a permissions diff. The reconciliation engine
    hashes this into the discovery ledger so the audit story is
    complete: "this agent was discovered, with this evidence, on this
    date."
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    candidate_id: UUID = Field(default_factory=uuid4)
    source: DiscoverySource
    tenant_id: str = Field(min_length=1, max_length=200)
    external_id: str = Field(min_length=1, max_length=512)

    name: str = Field(min_length=1, max_length=400)
    owner_hint: str | None = Field(default=None, max_length=400)
    description: str | None = Field(default=None, max_length=4_000)

    model_provider_hint: str | None = Field(default=None, max_length=100)
    model_name_hint: str | None = Field(default=None, max_length=200)
    framework_hint: str | None = Field(default=None, max_length=200)

    environment_hint: AgentEnvironment = Field(default=AgentEnvironment.PRODUCTION)
    risk_band: DiscoveryRiskBand = Field(default=DiscoveryRiskBand.MEDIUM)
    confidence: float = Field(ge=0.0, le=1.0)

    capability_hints: DiscoveredCapabilityHints = Field(
        default_factory=DiscoveredCapabilityHints
    )

    last_seen_active_at: datetime | None = Field(default=None)
    discovered_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    evidence: dict[str, Any] = Field(default_factory=dict)
    tags: tuple[str, ...] = Field(default_factory=tuple)

    @field_validator("tenant_id", mode="before")
    @classmethod
    def _normalize_tenant_id(cls, value: Any) -> str:
        if not isinstance(value, str):
            raise TypeError("tenant_id must be a string")
        normalized = value.strip().casefold()
        if not normalized:
            raise ValueError("tenant_id must not be blank")
        return normalized

    @field_validator("external_id", "name", mode="before")
    @classmethod
    def _normalize_required_text(cls, value: Any) -> str:
        if not isinstance(value, str):
            raise TypeError("value must be a string")
        normalized = value.strip()
        if not normalized:
            raise ValueError("value must not be blank")
        return normalized

    @field_validator(
        "owner_hint",
        "description",
        "model_provider_hint",
        "model_name_hint",
        "framework_hint",
        mode="before",
    )
    @classmethod
    def _normalize_optional_text(cls, value: Any) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str):
            raise TypeError("value must be a string when provided")
        normalized = value.strip()
        return normalized or None

    @field_validator("tags", mode="before")
    @classmethod
    def _normalize_tags(cls, value: Any) -> tuple[str, ...]:
        if value is None:
            return tuple()
        out: list[str] = []
        seen: set[str] = set()
        for item in value:
            if not isinstance(item, str):
                raise TypeError("tag must be a string")
            normalized = item.strip().casefold()
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            out.append(normalized)
        out.sort()
        return tuple(out)

    @field_validator(
        "discovered_at",
        "last_seen_active_at",
        mode="after",
    )
    @classmethod
    def _enforce_tz_aware(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("discovery timestamps must be timezone-aware")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def _validate_temporal_order(self) -> CandidateAgent:
        if (
            self.last_seen_active_at is not None
            and self.last_seen_active_at > self.discovered_at
        ):
            # last_seen_active_at represents the platform's view of the
            # last activity; if the connector saw it later than now,
            # something is off. We don't reject — just normalize down
            # to discovered_at so audit invariants hold.
            object.__setattr__(self, "last_seen_active_at", self.discovered_at)
        return self

    @property
    def reconciliation_key(self) -> str:
        """
        Stable cross-run key used by the reconciliation engine.

        Two CandidateAgents with the same key represent the same agent
        observed on different runs (or by different scans of the same
        connector). Different keys always represent different agents.
        """
        return f"{self.source}:{self.tenant_id}:{self.external_id.casefold()}"


# ---------------------------------------------------------------------------
# Reconciliation outcome — what the engine decided to do with a candidate
# ---------------------------------------------------------------------------


class ReconciliationOutcome(BaseModel):
    """
    Immutable record of what the reconciliation engine did with one
    candidate.

    Outcomes are hash-chained into the discovery ledger so the
    sequence of "what got discovered, when, and what we did about it"
    is tamper-evident. Every promotion to AgentIdentity is preceded
    by exactly one outcome of kind=NEW_AGENT, action=REGISTERED.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    outcome_id: UUID = Field(default_factory=uuid4)
    candidate_id: UUID
    reconciliation_key: str

    finding_kind: DiscoveryFindingKind
    action: ReconciliationAction
    confidence: float = Field(ge=0.0, le=1.0)

    # The agent_id that was created or updated as a result of this
    # outcome. None on hold/skip/duplicate paths.
    resulting_agent_id: UUID | None = Field(default=None)

    # Free-form structured findings the connector or engine attached.
    # Used for drift descriptions, ambiguity reasons, etc. Hashed into
    # the ledger record alongside the candidate evidence.
    findings: tuple[str, ...] = Field(default_factory=tuple)

    decided_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @field_validator("findings", mode="before")
    @classmethod
    def _normalize_findings(cls, value: Any) -> tuple[str, ...]:
        if value is None:
            return tuple()
        out: list[str] = []
        for item in value:
            if not isinstance(item, str):
                raise TypeError("finding must be a string")
            normalized = item.strip()
            if normalized:
                out.append(normalized)
        return tuple(out)

    @field_validator("decided_at", mode="after")
    @classmethod
    def _enforce_tz_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("decided_at must be timezone-aware")
        return value.astimezone(UTC)


# ---------------------------------------------------------------------------
# Discovery ledger entry — one append-only row per outcome
# ---------------------------------------------------------------------------


class DiscoveryLedgerEntry(BaseModel):
    """
    Single hash-chained ledger row. Mirrors the EvidenceRecord pattern
    Tex already uses for decision evidence.

    `payload_sha256` is the hash of the canonical JSON of the
    (candidate, outcome) pair. `record_hash` is the hash of
    `payload_sha256 + previous_hash`. Verifying the chain proves no
    discovery outcome was deleted, reordered, or modified after the
    fact.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    sequence: int = Field(ge=0)
    candidate: CandidateAgent
    outcome: ReconciliationOutcome
    payload_sha256: str = Field(min_length=64, max_length=64)
    previous_hash: str | None = Field(default=None)
    record_hash: str = Field(min_length=64, max_length=64)
    appended_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @field_validator("appended_at", mode="after")
    @classmethod
    def _enforce_tz_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("appended_at must be timezone-aware")
        return value.astimezone(UTC)


# ---------------------------------------------------------------------------
# Scan run — the unit of "I asked all my connectors to look right now"
# ---------------------------------------------------------------------------


class DiscoveryScanRun(BaseModel):
    """
    Summary of one full discovery scan.

    A scan run invokes every wired connector once, collects
    candidates, runs reconciliation against the registry, and writes
    one ledger entry per outcome. The summary is what the API and the
    UI show: "the last scan ran at T, took N seconds, found M
    candidates, registered K, quarantined Q, held A."
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    run_id: UUID = Field(default_factory=uuid4)
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    completed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    sources_scanned: tuple[DiscoverySource, ...] = Field(default_factory=tuple)
    candidates_seen: int = Field(ge=0, default=0)

    registered_count: int = Field(ge=0, default=0)
    updated_drift_count: int = Field(ge=0, default=0)
    quarantined_count: int = Field(ge=0, default=0)
    no_op_count: int = Field(ge=0, default=0)
    held_count: int = Field(ge=0, default=0)
    skipped_count: int = Field(ge=0, default=0)

    errors: tuple[str, ...] = Field(default_factory=tuple)

    @field_validator("started_at", "completed_at", mode="after")
    @classmethod
    def _enforce_tz_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("scan timestamps must be timezone-aware")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def _validate_temporal_order(self) -> DiscoveryScanRun:
        if self.completed_at < self.started_at:
            raise ValueError("completed_at must be at or after started_at")
        return self

    @property
    def duration_seconds(self) -> float:
        return (self.completed_at - self.started_at).total_seconds()

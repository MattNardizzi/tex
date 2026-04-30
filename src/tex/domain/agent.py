"""
Agent governance domain models.

Tex governs AI agents end-to-end: who they are (identity), what they're
allowed to do (capability surface), how they have behaved (behavioral
baseline), and what they are about to release (content). These models
are the spine of the agent-side evaluation streams.

Design rules mirror the rest of the Tex domain layer:
- frozen Pydantic models with extra='forbid'
- strict validators
- safe to persist, hash, replay
- timezone-aware datetimes everywhere
- nothing here knows about HTTP, persistence backends, or model providers
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class AgentLifecycleStatus(StrEnum):
    """
    Operational status of a registered agent.

    - PENDING: registered but not yet attested or activated
    - ACTIVE: in good standing, evaluations proceed normally
    - QUARANTINED: still registered but every action routes to ABSTAIN
      regardless of content (security incident, anomaly review)
    - REVOKED: terminal; agent identity is dead, evaluations are rejected
    """

    PENDING = "PENDING"
    ACTIVE = "ACTIVE"
    QUARANTINED = "QUARANTINED"
    REVOKED = "REVOKED"

    @property
    def can_evaluate(self) -> bool:
        return self in (
            AgentLifecycleStatus.ACTIVE,
            AgentLifecycleStatus.QUARANTINED,
            AgentLifecycleStatus.PENDING,
        )

    @property
    def forces_abstain(self) -> bool:
        return self is AgentLifecycleStatus.QUARANTINED

    @property
    def forces_forbid(self) -> bool:
        return self is AgentLifecycleStatus.REVOKED


class AgentTrustTier(StrEnum):
    """
    Operator-assigned trust tier for an agent.

    Trust tier is a coarse, human-set policy lever. It contributes to the
    agent identity stream's risk score and confidence.
    """

    UNVERIFIED = "UNVERIFIED"
    STANDARD = "STANDARD"
    TRUSTED = "TRUSTED"
    PRIVILEGED = "PRIVILEGED"

    @property
    def baseline_risk_contribution(self) -> float:
        """
        Risk that this tier contributes before any other agent signal.
        """
        return {
            AgentTrustTier.UNVERIFIED: 0.55,
            AgentTrustTier.STANDARD: 0.20,
            AgentTrustTier.TRUSTED: 0.08,
            AgentTrustTier.PRIVILEGED: 0.03,
        }[self]

    @property
    def baseline_confidence(self) -> float:
        """How confident the identity stream is in its baseline alone."""
        return {
            AgentTrustTier.UNVERIFIED: 0.65,
            AgentTrustTier.STANDARD: 0.75,
            AgentTrustTier.TRUSTED: 0.88,
            AgentTrustTier.PRIVILEGED: 0.92,
        }[self]


class AgentEnvironment(StrEnum):
    """
    Where the agent is registered to run.

    Used for posture and capability checks: an agent registered as
    SANDBOX that emits a request with environment=production is a
    structural mismatch worth flagging.
    """

    SANDBOX = "SANDBOX"
    STAGING = "STAGING"
    PRODUCTION = "PRODUCTION"


# ---------------------------------------------------------------------------
# Capability surface
# ---------------------------------------------------------------------------


class CapabilitySurface(BaseModel):
    """
    The declared capability surface for an agent.

    Capability is the set of *what the agent is allowed to do*. Tex uses
    this to answer "is this action even within the agent's authorized
    scope?" before content evaluation matters.

    Empty collections mean "unrestricted" for that dimension. Operators
    are expected to set narrow surfaces in production; this is the same
    posture concept Noma/Zenity sell, but it is a first-class evidence
    stream for us, not a separate dashboard.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    allowed_action_types: tuple[str, ...] = Field(default_factory=tuple)
    allowed_channels: tuple[str, ...] = Field(default_factory=tuple)
    allowed_environments: tuple[str, ...] = Field(default_factory=tuple)
    allowed_recipient_domains: tuple[str, ...] = Field(default_factory=tuple)
    allowed_tools: tuple[str, ...] = Field(default_factory=tuple)
    allowed_mcp_servers: tuple[str, ...] = Field(default_factory=tuple)
    data_scopes: tuple[str, ...] = Field(default_factory=tuple)
    max_actions_per_hour: int | None = Field(default=None, ge=1)

    @field_validator(
        "allowed_action_types",
        "allowed_channels",
        "allowed_environments",
        "allowed_recipient_domains",
        "allowed_tools",
        "allowed_mcp_servers",
        "data_scopes",
        mode="before",
    )
    @classmethod
    def _normalize_string_tuple(cls, value: Any) -> tuple[str, ...]:
        return _normalize_lowercase_string_tuple(value)

    @property
    def is_unrestricted(self) -> bool:
        """Whether the surface declares any restrictions at all."""
        return (
            not self.allowed_action_types
            and not self.allowed_channels
            and not self.allowed_environments
            and not self.allowed_recipient_domains
            and not self.allowed_tools
            and not self.allowed_mcp_servers
            and not self.data_scopes
            and self.max_actions_per_hour is None
        )

    def permits_action_type(self, action_type: str) -> bool:
        if not self.allowed_action_types:
            return True
        return action_type.strip().casefold() in self.allowed_action_types

    def permits_channel(self, channel: str) -> bool:
        if not self.allowed_channels:
            return True
        return channel.strip().casefold() in self.allowed_channels

    def permits_environment(self, environment: str) -> bool:
        if not self.allowed_environments:
            return True
        return environment.strip().casefold() in self.allowed_environments

    def permits_recipient(self, recipient: str | None) -> bool:
        """
        Whether the recipient passes the domain whitelist.

        Recipients without a parseable domain are accepted when the
        whitelist is empty and rejected when it is non-empty, because we
        cannot prove the recipient is within scope.
        """
        if not self.allowed_recipient_domains:
            return True
        if recipient is None:
            return False

        normalized = recipient.strip().casefold()
        if "@" in normalized:
            domain = normalized.rsplit("@", 1)[-1]
        elif "://" in normalized:
            after_scheme = normalized.split("://", 1)[-1]
            domain = after_scheme.split("/", 1)[0]
        else:
            domain = normalized

        if not domain:
            return False

        return any(
            domain == allowed or domain.endswith("." + allowed)
            for allowed in self.allowed_recipient_domains
        )


# ---------------------------------------------------------------------------
# Attestation
# ---------------------------------------------------------------------------


class AgentAttestation(BaseModel):
    """
    A single durable claim about an agent.

    Attestations are durable claims by some attester (a human, a CI
    pipeline, a signing key, an upstream registry) about the agent.
    Tex counts and timestamps them; cryptographic verification belongs
    to a pluggable verifier in a future revision.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    attester: str = Field(min_length=1, max_length=200)
    claim: str = Field(min_length=1, max_length=500)
    issued_at: datetime
    expires_at: datetime | None = None
    signature: str | None = Field(default=None, min_length=1, max_length=2_000)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("attester", "claim", mode="before")
    @classmethod
    def _normalize_required_text(cls, value: Any) -> str:
        if not isinstance(value, str):
            raise TypeError("value must be a string")
        normalized = value.strip()
        if not normalized:
            raise ValueError("value must not be blank")
        return normalized

    @field_validator("issued_at", "expires_at", mode="after")
    @classmethod
    def _enforce_tz_aware(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("attestation timestamps must be timezone-aware")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def _validate_expiry(self) -> AgentAttestation:
        if self.expires_at is not None and self.expires_at <= self.issued_at:
            raise ValueError("expires_at must be later than issued_at")
        return self

    @property
    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False
        return datetime.now(UTC) >= self.expires_at


# ---------------------------------------------------------------------------
# Agent identity
# ---------------------------------------------------------------------------


class AgentIdentity(BaseModel):
    """
    Durable identity record for one agent registered with Tex.

    This is the canonical "who is this agent" record. It is owned by the
    agent registry, persisted, hashed into the evidence chain on every
    decision that touches the agent, and immutable in spirit — mutating
    a field produces a new revision.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    agent_id: UUID = Field(default_factory=uuid4)
    revision: int = Field(default=1, ge=1)

    name: str = Field(min_length=1, max_length=200)
    owner: str = Field(min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=2_000)

    # Tenant scope for cross-agent baseline analytics. Agents that share
    # a tenant are compared against each other in the tenant content
    # baseline (V11). Defaults to "default" to keep backwards
    # compatibility with all pre-V11 agent registrations and tests; in
    # production the operator is expected to set a real tenant identifier.
    tenant_id: str = Field(default="default", min_length=1, max_length=200)

    model_provider: str | None = Field(default=None, max_length=100)
    model_name: str | None = Field(default=None, max_length=200)
    framework: str | None = Field(default=None, max_length=100)

    environment: AgentEnvironment = Field(default=AgentEnvironment.PRODUCTION)
    trust_tier: AgentTrustTier = Field(default=AgentTrustTier.STANDARD)
    lifecycle_status: AgentLifecycleStatus = Field(default=AgentLifecycleStatus.ACTIVE)

    capability_surface: CapabilitySurface = Field(default_factory=CapabilitySurface)
    attestations: tuple[AgentAttestation, ...] = Field(default_factory=tuple)

    tags: tuple[str, ...] = Field(default_factory=tuple)
    metadata: dict[str, Any] = Field(default_factory=dict)

    registered_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @field_validator("name", "owner", mode="before")
    @classmethod
    def _normalize_required_text(cls, value: Any) -> str:
        if not isinstance(value, str):
            raise TypeError("value must be a string")
        normalized = value.strip()
        if not normalized:
            raise ValueError("value must not be blank")
        return normalized

    @field_validator("tenant_id", mode="before")
    @classmethod
    def _normalize_tenant_id(cls, value: Any) -> str:
        if value is None:
            return "default"
        if not isinstance(value, str):
            raise TypeError("tenant_id must be a string")
        normalized = value.strip().casefold()
        if not normalized:
            raise ValueError("tenant_id must not be blank")
        return normalized

    @field_validator(
        "description",
        "model_provider",
        "model_name",
        "framework",
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
        return _normalize_lowercase_string_tuple(value)

    @field_validator("registered_at", "updated_at", mode="after")
    @classmethod
    def _enforce_tz_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("agent timestamps must be timezone-aware")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def _validate_temporal_order(self) -> AgentIdentity:
        if self.updated_at < self.registered_at:
            raise ValueError("updated_at must be at or after registered_at")
        return self

    @property
    def age_seconds(self) -> float:
        return (datetime.now(UTC) - self.registered_at).total_seconds()

    @property
    def has_active_attestations(self) -> bool:
        return any(not a.is_expired for a in self.attestations)


# ---------------------------------------------------------------------------
# Action ledger entry — one row per Tex decision tied to an agent
# ---------------------------------------------------------------------------


class ActionLedgerEntry(BaseModel):
    """
    One immutable entry in an agent's behavioral action ledger.

    Tex writes one entry per decision it makes for an agent. The ledger
    is the substrate the behavioral baseline stream reads from. It is
    the durable record of "what has this agent actually been doing."
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    entry_id: UUID = Field(default_factory=uuid4)
    agent_id: UUID
    session_id: str | None = Field(default=None, max_length=200)

    decision_id: UUID
    request_id: UUID
    verdict: str = Field(min_length=1, max_length=20)

    action_type: str = Field(min_length=1, max_length=100)
    channel: str = Field(min_length=1, max_length=50)
    environment: str = Field(min_length=1, max_length=50)
    recipient: str | None = Field(default=None, max_length=500)

    final_score: float = Field(ge=0.0, le=1.0)
    confidence: float = Field(ge=0.0, le=1.0)
    content_sha256: str = Field(min_length=64, max_length=64)

    capability_violations: tuple[str, ...] = Field(default_factory=tuple)
    asi_short_codes: tuple[str, ...] = Field(default_factory=tuple)

    recorded_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @field_validator(
        "verdict",
        "action_type",
        "channel",
        "environment",
        mode="before",
    )
    @classmethod
    def _normalize_required(cls, value: Any) -> str:
        if not isinstance(value, str):
            raise TypeError("value must be a string")
        normalized = value.strip()
        if not normalized:
            raise ValueError("value must not be blank")
        return normalized

    @field_validator("session_id", "recipient", mode="before")
    @classmethod
    def _normalize_optional(cls, value: Any) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str):
            raise TypeError("value must be a string when provided")
        normalized = value.strip()
        return normalized or None

    @field_validator(
        "capability_violations",
        "asi_short_codes",
        mode="before",
    )
    @classmethod
    def _normalize_string_tuple(cls, value: Any) -> tuple[str, ...]:
        return _normalize_lowercase_string_tuple(value)

    @field_validator("content_sha256", mode="after")
    @classmethod
    def _validate_sha(cls, value: str) -> str:
        normalized = value.strip().lower()
        if len(normalized) != 64 or any(c not in "0123456789abcdef" for c in normalized):
            raise ValueError("content_sha256 must be a 64-char lowercase hex digest")
        return normalized

    @field_validator("recorded_at", mode="after")
    @classmethod
    def _enforce_tz_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("recorded_at must be timezone-aware")
        return value.astimezone(UTC)


# ---------------------------------------------------------------------------
# Behavioral baseline — derived from the ledger
# ---------------------------------------------------------------------------


class BehavioralBaseline(BaseModel):
    """
    Aggregated behavioral profile of an agent, derived from its ledger.

    The baseline is always computed at evaluation time from the latest
    ledger window — it is never stored. The behavioral stream uses it
    to answer "is this action consistent with how this agent has
    historically behaved?"
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    agent_id: UUID
    sample_size: int = Field(ge=0)

    # Overall behavioral health
    permit_rate: float = Field(ge=0.0, le=1.0)
    abstain_rate: float = Field(ge=0.0, le=1.0)
    forbid_rate: float = Field(ge=0.0, le=1.0)

    # Distribution of what the agent does
    action_type_distribution: dict[str, float] = Field(default_factory=dict)
    channel_distribution: dict[str, float] = Field(default_factory=dict)
    recipient_domain_distribution: dict[str, float] = Field(default_factory=dict)

    # Risk profile
    mean_final_score: float = Field(ge=0.0, le=1.0)
    capability_violation_rate: float = Field(ge=0.0, le=1.0)
    forbid_streak: int = Field(
        ge=0,
        description="Number of consecutive recent FORBIDs at the head of the ledger.",
    )

    computed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @field_validator("computed_at", mode="after")
    @classmethod
    def _enforce_tz_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("computed_at must be timezone-aware")
        return value.astimezone(UTC)

    @property
    def is_empty(self) -> bool:
        return self.sample_size == 0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _normalize_lowercase_string_tuple(value: Any) -> tuple[str, ...]:
    if value is None:
        return tuple()
    if isinstance(value, str):
        raise TypeError("string-tuple fields must not be plain strings")
    if not isinstance(value, (list, tuple, set, frozenset)):
        raise TypeError("string-tuple fields must be sequences")

    normalized: list[str] = []
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, str):
            raise TypeError("sequence items must be strings")
        candidate = item.strip().casefold()
        if not candidate:
            raise ValueError("sequence items must not be blank")
        if candidate in seen:
            continue
        seen.add(candidate)
        normalized.append(candidate)

    return tuple(normalized)

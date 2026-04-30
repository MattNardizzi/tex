from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from tex.domain.asi_finding import ASIFinding
from tex.domain.finding import Finding
from tex.domain.latency import LatencyBreakdown
from tex.domain.verdict import Verdict


class AgentRuntimeIdentity(BaseModel):
    """Runtime identity block for adjudication-derived discovery."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    agent_id: UUID | None = None
    external_agent_id: str | None = Field(default=None, max_length=300)
    agent_name: str | None = Field(default=None, max_length=200)
    agent_type: str | None = Field(default=None, max_length=100)
    tenant_id: str = Field(default="default", min_length=1, max_length=200)
    owner: str | None = Field(default=None, max_length=200)
    environment: str | None = Field(default=None, max_length=50)
    model_provider: str | None = Field(default=None, max_length=100)
    model_name: str | None = Field(default=None, max_length=200)
    framework: str | None = Field(default=None, max_length=100)
    system_prompt_hash: str | None = Field(default=None, max_length=512)
    tool_manifest_hash: str | None = Field(default=None, max_length=512)
    memory_hash: str | None = Field(default=None, max_length=512)
    tools: tuple[str, ...] = Field(default_factory=tuple)
    mcp_server_ids: tuple[str, ...] = Field(default_factory=tuple)
    data_scopes: tuple[str, ...] = Field(default_factory=tuple)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("external_agent_id", "agent_name", "agent_type", "owner", "environment", "model_provider", "model_name", "framework", "system_prompt_hash", "tool_manifest_hash", "memory_hash", mode="before")
    @classmethod
    def _normalize_optional_text(cls, value: Any) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str):
            raise TypeError("value must be a string when provided")
        normalized = value.strip()
        return normalized or None

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

    @field_validator("tools", "mcp_server_ids", "data_scopes", mode="before")
    @classmethod
    def _normalize_tuple(cls, value: Any) -> tuple[str, ...]:
        if value is None:
            return tuple()
        if isinstance(value, str):
            raise TypeError("expected a sequence of strings, not a string")
        if not isinstance(value, (list, tuple, set, frozenset)):
            raise TypeError("expected a sequence of strings")
        out: list[str] = []
        seen: set[str] = set()
        for item in value:
            if not isinstance(item, str):
                raise TypeError("sequence items must be strings")
            normalized = item.strip().casefold()
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            out.append(normalized)
        out.sort()
        return tuple(out)

    @field_validator("metadata", mode="before")
    @classmethod
    def _normalize_metadata(cls, value: Any) -> dict[str, Any]:
        if value is None:
            return {}
        if not isinstance(value, dict):
            raise TypeError("metadata must be a dictionary")
        return dict(value)

    @property
    def stable_key(self) -> str:
        parts = [
            self.tenant_id,
            str(self.agent_id) if self.agent_id is not None else "",
            self.external_agent_id or "",
            self.agent_name or "",
            self.agent_type or "",
            self.framework or "",
            self.model_provider or "",
            self.model_name or "",
            self.system_prompt_hash or "",
            self.tool_manifest_hash or "",
            self.memory_hash or "",
            ",".join(self.tools),
            ",".join(self.mcp_server_ids),
            ",".join(self.data_scopes),
        ]
        return "|".join(parts).casefold()

    @property
    def fingerprint_hash(self) -> str:
        import hashlib
        return hashlib.sha256(self.stable_key.encode("utf-8")).hexdigest()


class EvaluationRequest(BaseModel):
    """
    Canonical input to Tex for one content adjudication event.

    Tex does not own identity, permissions, or runtime authorization. It judges
    one concrete action request in context:
    - what action is being attempted
    - what content is about to be released
    - where it is going
    - under which policy context
    - under which explicit request identity

    request_id is first-class and must enter the system at the edge. The PDP and
    downstream decision record must preserve it unchanged.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    request_id: UUID

    action_type: str = Field(min_length=1, max_length=100)
    content: str = Field(min_length=1, max_length=50_000)

    recipient: str | None = Field(default=None, max_length=500)
    channel: str = Field(min_length=1, max_length=50)
    environment: str = Field(min_length=1, max_length=50)

    metadata: dict[str, Any] = Field(default_factory=dict)
    policy_id: str | None = Field(default=None, max_length=100)

    # Optional agent governance context. When supplied, Tex resolves the
    # agent identity, runs the capability check, and runs the behavioral
    # baseline check — all as peer evidence streams in the same fusion
    # event that produces the verdict on the content.
    #
    # When omitted, Tex behaves exactly as it did pre-agent-fusion. This
    # is the backwards-compatibility contract.
    agent_id: UUID | None = Field(
        default=None,
        description=(
            "Stable identifier of the agent emitting this action. Resolved "
            "against the agent registry and used by the identity, "
            "capability, and behavioral evaluation streams."
        ),
    )
    session_id: str | None = Field(
        default=None,
        max_length=200,
        description=(
            "Caller-supplied stable identifier for a logical agent session. "
            "Lets Tex compute behavioral signals scoped to a single run."
        ),
    )
    agent_identity: AgentRuntimeIdentity | None = Field(
        default=None,
        description=(
            "Runtime identity/fingerprint block. When supplied, Tex treats "
            "the adjudication request itself as a discovery signal and "
            "auto-registers or upgrades the agent to CONTROLLED."
        ),
    )

    requested_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @field_validator("action_type", "channel", "environment")
    @classmethod
    def normalize_lower(cls, value: str) -> str:
        normalized = value.strip().lower()
        if not normalized:
            raise ValueError("value must not be blank")
        return normalized

    @field_validator("content")
    @classmethod
    def normalize_content(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("content must not be empty")
        return normalized

    @field_validator("recipient")
    @classmethod
    def normalize_recipient(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None

    @field_validator("policy_id")
    @classmethod
    def normalize_policy_id(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None

    @field_validator("session_id")
    @classmethod
    def normalize_session_id(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None

    @field_validator("requested_at")
    @classmethod
    def validate_requested_at_is_timezone_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("requested_at must be timezone-aware")
        return value.astimezone(UTC)


class EvaluationResponse(BaseModel):
    """
    Public adjudication result returned by Tex.

    This is the product surface:
    - final verdict
    - calibrated confidence and fused score
    - reasons and findings
    - uncertainty signals
    - policy/audit references

    decision_id must be supplied by the engine. The response should reflect the
    durable decision that was actually created, not invent a new identifier.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    decision_id: UUID
    verdict: Verdict

    confidence: float = Field(
        ge=0.0,
        le=1.0,
        description="Tex's confidence in the final adjudication outcome.",
    )
    final_score: float = Field(
        ge=0.0,
        le=1.0,
        description="Fused risk score across deterministic, specialist, and semantic layers.",
    )

    reasons: list[str] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    scores: dict[str, float] = Field(default_factory=dict)
    uncertainty_flags: list[str] = Field(default_factory=list)

    asi_findings: list[ASIFinding] = Field(
        default_factory=list,
        description=(
            "Structured OWASP ASI 2026 findings on this decision, with "
            "severity, confidence, verdict-influence weighting, triggers, "
            "and counterfactuals. Every ASI category Tex attributes to "
            "this verdict appears here."
        ),
    )
    determinism_fingerprint: str | None = Field(
        default=None,
        min_length=64,
        max_length=64,
        description=(
            "Stable SHA-256 fingerprint of the inputs that produced this "
            "verdict. Same fingerprint should mean same verdict."
        ),
    )
    latency: LatencyBreakdown | None = Field(
        default=None,
        description="Per-stage wall-clock latency for this evaluation.",
    )
    replay_url: str | None = Field(
        default=None,
        max_length=500,
        description=(
            "Absolute URL that regenerates the full decision record "
            "for audit, replay, or inspection."
        ),
    )
    evidence_bundle_url: str | None = Field(
        default=None,
        max_length=500,
        description=(
            "Absolute URL that returns the signed, hash-chained evidence "
            "bundle for this decision."
        ),
    )

    policy_version: str = Field(min_length=1, max_length=100)
    evidence_hash: str | None = Field(default=None, min_length=1, max_length=128)

    evaluated_at: datetime

    @field_validator("reasons", "uncertainty_flags")
    @classmethod
    def normalize_string_list(cls, values: list[str]) -> list[str]:
        normalized: list[str] = []
        seen: set[str] = set()

        for value in values:
            item = value.strip()
            if not item:
                raise ValueError("list entries must not be blank")
            if item not in seen:
                normalized.append(item)
                seen.add(item)

        return normalized

    @field_validator("scores")
    @classmethod
    def validate_scores(cls, values: dict[str, float]) -> dict[str, float]:
        normalized: dict[str, float] = {}

        for raw_key, raw_value in values.items():
            key = raw_key.strip()
            if not key:
                raise ValueError("score keys must not be blank")
            if not 0.0 <= raw_value <= 1.0:
                raise ValueError("score values must be between 0.0 and 1.0")
            normalized[key] = raw_value

        return normalized

    @field_validator("policy_version")
    @classmethod
    def normalize_policy_version(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("policy_version must not be blank")
        return normalized

    @field_validator("evidence_hash")
    @classmethod
    def normalize_evidence_hash(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip().lower()
        if not normalized:
            raise ValueError("evidence_hash must not be blank when provided")
        return normalized

    @field_validator("evaluated_at")
    @classmethod
    def validate_evaluated_at_is_timezone_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("evaluated_at must be timezone-aware")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def validate_verdict_consistency(self) -> EvaluationResponse:
        if self.verdict.requires_human_review and not self.uncertainty_flags:
            raise ValueError(
                "uncertainty_flags must be present when verdict is ABSTAIN"
            )
        return self

    @property
    def is_permit(self) -> bool:
        return self.verdict.allows_release

    @property
    def is_forbid(self) -> bool:
        return self.verdict.blocks_release

    @property
    def is_abstain(self) -> bool:
        return self.verdict.requires_human_review
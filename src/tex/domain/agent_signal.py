"""
Result schemas for Tex's agent-governance evaluation streams.

Three streams produce these results during a single evaluation:
- identity stream: produces AgentIdentitySignal
- capability stream: produces CapabilitySignal
- behavioral stream: produces BehavioralSignal

All three follow the same shape that deterministic / specialist / semantic
results follow elsewhere in Tex:
- a bounded risk score
- a bounded confidence
- structured Findings
- string uncertainty flags
- enough metadata for replay and the determinism fingerprint

Anything the router needs to fuse these results lives here. Anything the
streams need internally lives in the engine package.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from tex.domain.finding import Finding


# ---------------------------------------------------------------------------
# Shared field validators
# ---------------------------------------------------------------------------


def _normalize_string_tuple(value: Any, *, field_name: str) -> tuple[str, ...]:
    if value is None:
        return tuple()
    if isinstance(value, str):
        raise TypeError(f"{field_name} must be a sequence, not a plain string")
    if not isinstance(value, (list, tuple, set, frozenset)):
        raise TypeError(f"{field_name} must be a sequence")

    normalized: list[str] = []
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, str):
            raise TypeError(f"{field_name} items must be strings")
        candidate = item.strip()
        if not candidate:
            raise ValueError(f"{field_name} items must not be blank")
        key = candidate.casefold()
        if key in seen:
            continue
        seen.add(key)
        normalized.append(candidate)
    return tuple(normalized)


def _validate_score_mapping(value: dict[str, float]) -> dict[str, float]:
    normalized: dict[str, float] = {}
    for raw_key, raw_value in value.items():
        if not isinstance(raw_key, str):
            raise TypeError("score keys must be strings")
        key = raw_key.strip()
        if not key:
            raise ValueError("score keys must not be blank")
        if not isinstance(raw_value, (int, float)):
            raise TypeError("score values must be numeric")
        v = float(raw_value)
        if not 0.0 <= v <= 1.0:
            raise ValueError(f"score for {key!r} must be between 0 and 1")
        normalized[key] = v
    return normalized


# ---------------------------------------------------------------------------
# Identity stream result
# ---------------------------------------------------------------------------


class AgentIdentitySignal(BaseModel):
    """
    Output of the identity evaluation stream.

    The identity stream answers: "given who this agent is — its trust
    tier, lifecycle status, environment match, attestations, age — how
    much risk does identity alone contribute, and how confident am I in
    that contribution?"

    The signal is a peer to deterministic / specialists / semantic.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    risk_score: float = Field(ge=0.0, le=1.0)
    confidence: float = Field(ge=0.0, le=1.0)

    findings: tuple[Finding, ...] = Field(default_factory=tuple)
    reasons: tuple[str, ...] = Field(default_factory=tuple)
    uncertainty_flags: tuple[str, ...] = Field(default_factory=tuple)

    # Structured details preserved for replay and audit.
    trust_tier: str = Field(min_length=1, max_length=50)
    lifecycle_status: str = Field(min_length=1, max_length=50)
    environment_match: bool
    attestation_count: int = Field(ge=0)
    active_attestation_count: int = Field(ge=0)
    age_seconds: float = Field(ge=0.0)
    sub_scores: dict[str, float] = Field(default_factory=dict)

    # Discovery provenance — populated when the agent was auto-promoted
    # by the discovery layer. None means "either operator-registered or
    # discovered before this field existed." When present, the fusion
    # event has structural visibility into how this agent ended up in
    # the registry, closing the seam between discovery and runtime.
    discovery_source: str | None = Field(default=None, max_length=100)
    discovery_external_id: str | None = Field(default=None, max_length=512)
    discovery_risk_band: str | None = Field(default=None, max_length=50)

    @field_validator("reasons", "uncertainty_flags", mode="before")
    @classmethod
    def _norm_strs(cls, value: Any, info: Any) -> tuple[str, ...]:
        return _normalize_string_tuple(value, field_name=info.field_name)

    @field_validator("sub_scores", mode="after")
    @classmethod
    def _validate_sub_scores(cls, value: dict[str, float]) -> dict[str, float]:
        return _validate_score_mapping(value)

    @model_validator(mode="after")
    def _validate_attestation_counts(self) -> AgentIdentitySignal:
        if self.active_attestation_count > self.attestation_count:
            raise ValueError(
                "active_attestation_count cannot exceed attestation_count"
            )
        return self


# ---------------------------------------------------------------------------
# Capability stream result
# ---------------------------------------------------------------------------


class CapabilitySignal(BaseModel):
    """
    Output of the capability evaluation stream.

    The capability stream answers: "is this specific action within the
    agent's declared capability surface?" It produces a structural risk
    score that is high when the action is out-of-surface and low when
    it is well within the declared scope.

    Capability mismatches are first-class structural findings — they
    do not depend on content evaluation at all.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    risk_score: float = Field(ge=0.0, le=1.0)
    confidence: float = Field(ge=0.0, le=1.0)

    findings: tuple[Finding, ...] = Field(default_factory=tuple)
    reasons: tuple[str, ...] = Field(default_factory=tuple)
    uncertainty_flags: tuple[str, ...] = Field(default_factory=tuple)

    surface_unrestricted: bool
    action_permitted: bool
    channel_permitted: bool
    environment_permitted: bool
    recipient_permitted: bool

    violated_dimensions: tuple[str, ...] = Field(default_factory=tuple)

    @field_validator("reasons", "uncertainty_flags", "violated_dimensions", mode="before")
    @classmethod
    def _norm_strs(cls, value: Any, info: Any) -> tuple[str, ...]:
        return _normalize_string_tuple(value, field_name=info.field_name)

    @property
    def has_violations(self) -> bool:
        return bool(self.violated_dimensions)


# ---------------------------------------------------------------------------
# Behavioral stream result
# ---------------------------------------------------------------------------


class BehavioralSignal(BaseModel):
    """
    Output of the behavioral evaluation stream.

    The behavioral stream answers: "is what this agent is doing now
    consistent with how it has been behaving over time?" It compares
    the current request against the agent's behavioral baseline and
    produces a deviation score.

    For agents with no ledger history, this stream returns a
    cold-start signal: low confidence, neutral risk, with an
    explicit `cold_start` uncertainty flag so the router can take
    the absence of history into account.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    risk_score: float = Field(ge=0.0, le=1.0)
    confidence: float = Field(ge=0.0, le=1.0)

    findings: tuple[Finding, ...] = Field(default_factory=tuple)
    reasons: tuple[str, ...] = Field(default_factory=tuple)
    uncertainty_flags: tuple[str, ...] = Field(default_factory=tuple)

    sample_size: int = Field(ge=0)
    cold_start: bool

    novel_action_type: bool
    novel_channel: bool
    novel_recipient_domain: bool

    forbid_streak: int = Field(ge=0)
    capability_violation_rate: float = Field(ge=0.0, le=1.0)
    recent_abstain_rate: float = Field(ge=0.0, le=1.0)
    deviation_components: dict[str, float] = Field(default_factory=dict)

    # ----- V11: tenant-scope content baseline signals ---------------------
    # All four default to neutral so existing callers (and serialization
    # roundtrips of pre-V11 records) keep working unchanged.
    tenant_sample_size: int = Field(default=0, ge=0)
    tenant_cold_start: bool = Field(default=True)
    tenant_novelty_score: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description=(
            "1 - max Jaccard similarity to any prior PERMITted content "
            "signature for the same tenant + action_type."
        ),
    )
    tenant_recipient_novel: bool = Field(
        default=False,
        description=(
            "True when the recipient domain is unseen tenant-wide for "
            "this action_type. Stronger than per-agent novelty alone."
        ),
    )

    @field_validator("reasons", "uncertainty_flags", mode="before")
    @classmethod
    def _norm_strs(cls, value: Any, info: Any) -> tuple[str, ...]:
        return _normalize_string_tuple(value, field_name=info.field_name)

    @field_validator("deviation_components", mode="after")
    @classmethod
    def _validate_components(cls, value: dict[str, float]) -> dict[str, float]:
        return _validate_score_mapping(value)


# ---------------------------------------------------------------------------
# Combined agent evaluation bundle (what the PDP threads through)
# ---------------------------------------------------------------------------


class AgentEvaluationBundle(BaseModel):
    """
    Container for the three agent-stream results plus the resolved
    agent identity. This is what the PDP gives to the router.

    `agent_present=False` means no agent_id was supplied with the
    request. In that case the streams produce neutral results and the
    router skips the agent fusion contribution.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    agent_present: bool
    agent_id: str | None = None

    identity: AgentIdentitySignal
    capability: CapabilitySignal
    behavioral: BehavioralSignal

    @property
    def aggregate_risk_score(self) -> float:
        """
        Single fused agent-side risk number for routing.

        Equal weighting across the three streams, capped at 1.0. This
        is intentionally simple — fusion across the seven layers happens
        at the router, not here. This number is just a useful summary.
        """
        return min(
            1.0,
            (
                self.identity.risk_score
                + self.capability.risk_score
                + self.behavioral.risk_score
            )
            / 3.0,
        )

    @property
    def aggregate_confidence(self) -> float:
        """
        Conservative aggregate confidence across the three agent streams.

        We use the minimum because we are willing to PERMIT only when
        all three agent streams are confident. Identity confidence
        without behavioral confidence is not enough.
        """
        return min(
            self.identity.confidence,
            self.capability.confidence,
            self.behavioral.confidence,
        )

    @property
    def has_capability_violations(self) -> bool:
        return self.capability.has_violations

    @property
    def all_findings(self) -> tuple[Finding, ...]:
        return (
            self.identity.findings
            + self.capability.findings
            + self.behavioral.findings
        )

    @property
    def all_uncertainty_flags(self) -> tuple[str, ...]:
        seen: set[str] = set()
        ordered: list[str] = []
        for flag in (
            *self.identity.uncertainty_flags,
            *self.capability.uncertainty_flags,
            *self.behavioral.uncertainty_flags,
        ):
            key = flag.casefold()
            if key in seen:
                continue
            seen.add(key)
            ordered.append(flag)
        return tuple(ordered)

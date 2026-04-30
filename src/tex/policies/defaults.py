from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from tex.domain.policy import PolicySnapshot
from tex.domain.severity import Severity

DEFAULT_POLICY_ID = "default"
STRICT_POLICY_ID = "strict"

DEFAULT_POLICY_VERSION = "default-v1"
STRICT_POLICY_VERSION = "strict-v1"

_DEFAULT_ENABLED_RECOGNIZERS: tuple[str, ...] = (
    "blocked_terms",
    "sensitive_entities",
    "secret_leak",
    "pii",
    "unauthorized_commitment",
    "monetary_transfer",
    "external_sharing",
    "destructive_or_bypass",
    "urgency_pressure",
    "memory_instruction",
    "authority_impersonation",
)

_DEFAULT_BLOCK_SEVERITIES: tuple[Severity, ...] = (Severity.CRITICAL,)

_DEFAULT_BLOCKED_TERMS: tuple[str, ...] = (
    "ignore policy",
    "skip approval",
    "skip review",
    "disable logging",
    "remove audit",
    "drop table",
    "public link to customer data",
)

# Strict policy blocks a much wider surface. This is what the Warden
# round runs against. It is not arbitrary — every entry maps to a
# real-world risk class we want Tex to catch cold:
#   - explicit controls-bypass language
#   - unauthorized external commitments
#   - roadmap / unannounced-date leakage
#   - financial movement directives
#   - authority impersonation phrasing
#   - destructive production operations
#   - credential and secret-adjacent phrases
_STRICT_BLOCKED_TERMS: tuple[str, ...] = _DEFAULT_BLOCKED_TERMS + (
    "override policy",
    "bypass review",
    "bypass approval",
    "override the gate",
    "disable monitoring",
    "do not log",
    "do not record",
    "no audit trail",
    "off the books",
    "we guarantee",
    "i guarantee",
    "we promise",
    "we commit to",
    "you have my word",
    "consider it done",
    "locked in",
    "announce today",
    "announcing today",
    "public announcement",
    "unreleased feature",
    "unannounced",
    "launch date",
    "release date",
    "wire transfer",
    "send wire",
    "initiate transfer",
    "move funds",
    "process payment",
    "ceo here",
    "cfo here",
    "from the ceo",
    "from the cfo",
    "on behalf of the ceo",
    "this is urgent",
    "time sensitive",
    "before end of day",
    "before eod",
    "before close",
    "delete production",
    "drop schema",
    "truncate",
    "force push to main",
    "api key",
    "secret key",
    "access token",
    "bearer token",
    "confidential roadmap",
    "internal pricing",
    "internal only",
    "nda-only",
    "export customer",
    "export pii",
    "share externally",
    "forward to external",
)

_DEFAULT_SENSITIVE_ENTITIES: tuple[str, ...] = (
    "pricing sheet",
    "customer list",
    "internal roadmap",
    "production credentials",
    "security questionnaire",
)

# Strict policy treats more entities as sensitive, deepening the
# coverage of ASI03 (identity/privilege abuse) and ASI01 (goal hijack).
_STRICT_SENSITIVE_ENTITIES: tuple[str, ...] = _DEFAULT_SENSITIVE_ENTITIES + (
    "q2 pricing",
    "q3 pricing",
    "q4 pricing",
    "customer contract",
    "master services agreement",
    "unannounced feature",
    "design partner list",
    "pipeline report",
    "board deck",
    "board slides",
    "staging credentials",
    "deployment key",
    "service account",
    "signing key",
    "source code",
    "unreleased product",
)

_DEFAULT_ACTION_CRITICALITY: dict[str, float] = {
    "email_send": 0.45,
    "sales_email": 0.55,
    "slack_message": 0.25,
    "external_message": 0.55,
    "api_response": 0.30,
    "api_export": 0.70,
    "file_export": 0.72,
    "document_share": 0.62,
    "crm_update": 0.35,
    "approval_response": 0.60,
    "workflow_instruction": 0.65,
    "admin_command": 0.82,
    "sql_execution": 0.88,
}

_DEFAULT_CHANNEL_CRITICALITY: dict[str, float] = {
    "email": 0.45,
    "sales_email": 0.55,
    "slack": 0.20,
    "teams": 0.20,
    "api": 0.30,
    "webhook": 0.45,
    "export": 0.70,
    "console": 0.80,
}

_DEFAULT_ENVIRONMENT_CRITICALITY: dict[str, float] = {
    "dev": 0.10,
    "development": 0.10,
    "test": 0.15,
    "staging": 0.35,
    "prod": 0.75,
    "production": 0.75,
}

_DEFAULT_SPECIALIST_THRESHOLDS: dict[str, float] = {
    "secret_and_pii": 0.55,
    "external_sharing": 0.58,
    "unauthorized_commitment": 0.60,
    "destructive_or_bypass": 0.50,
}

_STRICT_SPECIALIST_THRESHOLDS: dict[str, float] = {
    "secret_and_pii": 0.48,
    "external_sharing": 0.52,
    "unauthorized_commitment": 0.55,
    "destructive_or_bypass": 0.45,
}

_DEFAULT_FUSION_WEIGHTS: dict[str, float] = {
    "deterministic": 0.2184,
    "specialists": 0.1716,
    "semantic": 0.3276,
    "criticality": 0.0624,
    "agent_identity": 0.060,
    "agent_capability": 0.090,
    "agent_behavioral": 0.070,
}

_STRICT_FUSION_WEIGHTS: dict[str, float] = {
    "deterministic": 0.2184,
    "specialists": 0.1716,
    "semantic": 0.3276,
    "criticality": 0.0624,
    "agent_identity": 0.060,
    "agent_capability": 0.090,
    "agent_behavioral": 0.070,
}

_DEFAULT_METADATA: dict[str, Any] = {
    "policy_name": "Tex Default Policy",
    "description": (
        "Lean default policy for local development and early product validation. "
        "It is intentionally conservative on destructive actions, disclosure risk, "
        "and unauthorized commitments."
    ),
    "owner": "tex",
    "mode": "default",
}

_STRICT_METADATA: dict[str, Any] = {
    **_DEFAULT_METADATA,
    "policy_name": "Tex Strict Policy",
    "mode": "strict",
}

_DEFAULT_PROFILE: dict[str, Any] = {
    "permit_threshold": 0.34,
    "forbid_threshold": 0.72,
    "minimum_confidence": 0.62,
    "retrieval_top_k": 5,
    "precedent_lookback_limit": 25,
    "specialist_thresholds": _DEFAULT_SPECIALIST_THRESHOLDS,
    "fusion_weights": _DEFAULT_FUSION_WEIGHTS,
    "blocked_terms": _DEFAULT_BLOCKED_TERMS,
    "sensitive_entities": _DEFAULT_SENSITIVE_ENTITIES,
}

_STRICT_PROFILE: dict[str, Any] = {
    # Warden-grade thresholds. Lower permit bar and tighter forbid bar
    # so borderline content resolves toward FORBID or ABSTAIN rather
    # than sneaking to PERMIT. minimum_confidence stays moderate so
    # truly benign content is still permitted at the Warden level;
    # pushing it too high was dropping clean content into ABSTAIN and
    # damaging credibility.
    "permit_threshold": 0.18,
    "forbid_threshold": 0.60,
    "minimum_confidence": 0.65,
    "retrieval_top_k": 7,
    "precedent_lookback_limit": 40,
    "specialist_thresholds": _STRICT_SPECIALIST_THRESHOLDS,
    "fusion_weights": _STRICT_FUSION_WEIGHTS,
    "blocked_terms": _STRICT_BLOCKED_TERMS,
    "sensitive_entities": _STRICT_SENSITIVE_ENTITIES,
}


def default_policy_snapshot(
    *,
    policy_id: str = DEFAULT_POLICY_ID,
    version: str = DEFAULT_POLICY_VERSION,
    is_active: bool = True,
    created_at: datetime | None = None,
    metadata: dict[str, Any] | None = None,
) -> PolicySnapshot:
    """
    Returns Tex's default policy snapshot.

    This policy is intentionally conservative enough to make Tex useful
    immediately without pretending calibration is already mature.
    """
    return _build_policy_snapshot(
        policy_id=policy_id,
        version=version,
        is_active=is_active,
        created_at=created_at,
        metadata=_merge_metadata(_DEFAULT_METADATA, metadata),
        profile=_DEFAULT_PROFILE,
    )


def strict_policy_snapshot(
    *,
    policy_id: str = STRICT_POLICY_ID,
    version: str = STRICT_POLICY_VERSION,
    is_active: bool = False,
    created_at: datetime | None = None,
    metadata: dict[str, Any] | None = None,
) -> PolicySnapshot:
    """
    Returns a stricter policy snapshot for higher-risk environments.

    This is the same policy shape with tighter thresholds and more aggressive
    specialist escalation, not a separate architecture.
    """
    return _build_policy_snapshot(
        policy_id=policy_id,
        version=version,
        is_active=is_active,
        created_at=created_at,
        metadata=_merge_metadata(_STRICT_METADATA, metadata),
        profile=_STRICT_PROFILE,
    )


def build_default_policy() -> PolicySnapshot:
    """Convenience constructor for the active default policy."""
    return default_policy_snapshot()


def build_strict_policy() -> PolicySnapshot:
    """Convenience constructor for the inactive strict policy."""
    return strict_policy_snapshot()


def _build_policy_snapshot(
    *,
    policy_id: str,
    version: str,
    is_active: bool,
    created_at: datetime | None,
    metadata: dict[str, Any],
    profile: dict[str, Any],
) -> PolicySnapshot:
    # Profile may supply its own blocked_terms and sensitive_entities.
    # The strict profile uses this to widen coverage for the Warden
    # round without duplicating the builder.
    blocked_terms = tuple(profile.get("blocked_terms", _DEFAULT_BLOCKED_TERMS))
    sensitive_entities = tuple(
        profile.get("sensitive_entities", _DEFAULT_SENSITIVE_ENTITIES)
    )

    return PolicySnapshot(
        policy_id=policy_id,
        version=version,
        is_active=is_active,
        permit_threshold=float(profile["permit_threshold"]),
        forbid_threshold=float(profile["forbid_threshold"]),
        minimum_confidence=float(profile["minimum_confidence"]),
        deterministic_block_severities=_DEFAULT_BLOCK_SEVERITIES,
        enabled_recognizers=_DEFAULT_ENABLED_RECOGNIZERS,
        blocked_terms=blocked_terms,
        sensitive_entities=sensitive_entities,
        retrieval_top_k=int(profile["retrieval_top_k"]),
        precedent_lookback_limit=int(profile["precedent_lookback_limit"]),
        specialist_thresholds=dict(profile["specialist_thresholds"]),
        action_criticality=dict(_DEFAULT_ACTION_CRITICALITY),
        channel_criticality=dict(_DEFAULT_CHANNEL_CRITICALITY),
        environment_criticality=dict(_DEFAULT_ENVIRONMENT_CRITICALITY),
        fusion_weights=dict(profile["fusion_weights"]),
        metadata=dict(metadata),
        created_at=created_at or datetime.now(UTC),
    )


def _merge_metadata(
    base: dict[str, Any],
    overrides: dict[str, Any] | None,
) -> dict[str, Any]:
    merged = dict(base)
    if overrides:
        merged.update(overrides)
    return merged
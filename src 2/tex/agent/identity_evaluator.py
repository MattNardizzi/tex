"""
Identity evaluation stream.

Answers: given who this agent is, how much risk does identity alone
contribute and how confident am I in that contribution?

Inputs considered:
- trust tier (operator-assigned policy lever)
- lifecycle status (PENDING/ACTIVE/QUARANTINED/REVOKED)
- environment match (declared environment vs. requested environment)
- attestations (count, active vs expired, attesters)
- agent age (seconds since registration)

Outputs an AgentIdentitySignal that the router fuses with the other six
streams.
"""

from __future__ import annotations

from tex.domain.agent import (
    AgentEnvironment,
    AgentIdentity,
    AgentLifecycleStatus,
    AgentTrustTier,
)
from tex.domain.agent_signal import AgentIdentitySignal
from tex.domain.evaluation import EvaluationRequest
from tex.domain.finding import Finding
from tex.domain.severity import Severity


# Age (in seconds) below which we mark an agent as "fresh".
# 1 hour. New agents get a small risk penalty until they accumulate
# behavioral history. Tunable via policy in a future revision.
_FRESH_AGENT_SECONDS = 60 * 60


class AgentIdentityEvaluator:
    """
    Pure evaluator. Stateless. Safe to share across threads.

    The PDP calls evaluate() once per request that carries an agent_id.
    For requests without an agent, the PDP supplies a neutral signal
    instead of calling this evaluator.
    """

    def evaluate(
        self,
        *,
        agent: AgentIdentity,
        request: EvaluationRequest,
    ) -> AgentIdentitySignal:
        sub_scores: dict[str, float] = {}
        findings: list[Finding] = []
        reasons: list[str] = []
        uncertainty_flags: list[str] = []

        # 1. Trust-tier baseline contribution.
        tier_score = agent.trust_tier.baseline_risk_contribution
        sub_scores["trust_tier"] = round(tier_score, 4)
        reasons.append(
            f"Trust tier {agent.trust_tier.value} contributes baseline "
            f"identity risk {tier_score:.2f}."
        )

        # 2. Lifecycle status.
        lifecycle_score = _lifecycle_risk(agent.lifecycle_status)
        sub_scores["lifecycle"] = round(lifecycle_score, 4)
        if agent.lifecycle_status is AgentLifecycleStatus.QUARANTINED:
            reasons.append("Agent is QUARANTINED; identity stream forces risk to 1.0.")
            findings.append(
                Finding(
                    source="agent.identity",
                    rule_name="agent_quarantined",
                    severity=Severity.CRITICAL,
                    message="Agent is in QUARANTINED status; all actions abstain.",
                )
            )
            uncertainty_flags.append("agent_quarantined")
        elif agent.lifecycle_status is AgentLifecycleStatus.PENDING:
            reasons.append("Agent is PENDING attestation; identity risk elevated.")
            uncertainty_flags.append("agent_pending")

        # 3. Environment match.
        environment_match = _environment_matches(agent.environment, request.environment)
        env_score = 0.0 if environment_match else 0.65
        sub_scores["environment"] = env_score
        if not environment_match:
            findings.append(
                Finding(
                    source="agent.identity",
                    rule_name="agent_environment_mismatch",
                    severity=Severity.WARNING,
                    message=(
                        f"Agent declared environment={agent.environment.value.lower()} "
                        f"but request environment={request.environment}. "
                        "Possible misuse of an unattested agent."
                    ),
                )
            )
            reasons.append(
                "Agent environment mismatch: declared "
                f"{agent.environment.value.lower()} vs requested {request.environment}."
            )

        # 4. Attestations.
        active = sum(1 for a in agent.attestations if not a.is_expired)
        total = len(agent.attestations)
        if total == 0:
            attestation_score = 0.45
            reasons.append("Agent has no attestations on file; identity risk elevated.")
            uncertainty_flags.append("no_attestations")
        elif active == 0:
            attestation_score = 0.55
            findings.append(
                Finding(
                    source="agent.identity",
                    rule_name="all_attestations_expired",
                    severity=Severity.WARNING,
                    message=(
                        f"All {total} attestation(s) on this agent are expired."
                    ),
                )
            )
            reasons.append("All attestations expired; identity risk elevated.")
            uncertainty_flags.append("attestations_expired")
        else:
            # Active attestations reduce risk smoothly; cap at 0.10.
            attestation_score = max(0.10, 0.30 - 0.05 * active)
            reasons.append(
                f"{active} active attestation(s) reduce identity risk."
            )
        sub_scores["attestations"] = round(attestation_score, 4)

        # 5. Agent age.
        if agent.age_seconds < _FRESH_AGENT_SECONDS:
            age_score = 0.40
            uncertainty_flags.append("fresh_agent")
            reasons.append(
                "Agent registered within the last hour; identity risk elevated until baseline establishes."
            )
        else:
            age_score = 0.05
        sub_scores["age"] = round(age_score, 4)

        # 6. Compose. Quarantined wins outright (1.0).
        if agent.lifecycle_status is AgentLifecycleStatus.QUARANTINED:
            risk_score = 1.0
            confidence = 0.95
        else:
            # Conservative aggregation: a weighted max-mean. We take the
            # mean of all sub-scores and add half the max, capped at 1.0.
            # This prevents one bad signal from dominating but still
            # surfaces single-axis problems clearly.
            scores = list(sub_scores.values())
            mean = sum(scores) / len(scores)
            max_score = max(scores)
            risk_score = min(1.0, 0.6 * mean + 0.4 * max_score)
            confidence = _confidence_for_tier_and_attestations(
                tier=agent.trust_tier,
                active_attestations=active,
                fresh=agent.age_seconds < _FRESH_AGENT_SECONDS,
            )

        return AgentIdentitySignal(
            risk_score=round(risk_score, 4),
            confidence=round(confidence, 4),
            findings=tuple(findings),
            reasons=tuple(reasons),
            uncertainty_flags=tuple(uncertainty_flags),
            trust_tier=agent.trust_tier.value,
            lifecycle_status=agent.lifecycle_status.value,
            environment_match=environment_match,
            attestation_count=total,
            active_attestation_count=active,
            age_seconds=round(agent.age_seconds, 2),
            sub_scores=sub_scores,
            discovery_source=_metadata_str(agent.metadata, "discovery_source"),
            discovery_external_id=_metadata_str(
                agent.metadata, "discovery_external_id"
            ),
            discovery_risk_band=_metadata_str(agent.metadata, "discovery_risk_band"),
        )


def neutral_identity_signal() -> AgentIdentitySignal:
    """
    Return a neutral signal used when no agent is supplied with the
    request. The router must skip the agent_identity contribution in
    fusion when this neutral signal is present, but downstream code
    always has a value to inspect.
    """
    return AgentIdentitySignal(
        risk_score=0.0,
        confidence=0.0,
        findings=tuple(),
        reasons=tuple(),
        uncertainty_flags=tuple(),
        trust_tier="STANDARD",
        lifecycle_status="ACTIVE",
        environment_match=True,
        attestation_count=0,
        active_attestation_count=0,
        age_seconds=0.0,
        sub_scores={},
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _lifecycle_risk(status: AgentLifecycleStatus) -> float:
    return {
        AgentLifecycleStatus.ACTIVE: 0.05,
        AgentLifecycleStatus.PENDING: 0.45,
        AgentLifecycleStatus.QUARANTINED: 1.0,
        AgentLifecycleStatus.REVOKED: 1.0,
    }[status]


def _environment_matches(declared: AgentEnvironment, requested: str) -> bool:
    """
    Whether the agent's declared environment matches the request's.

    Sandbox agents on production requests are always a mismatch.
    Production agents on staging/sandbox are also a mismatch — we want
    operators to register one agent per environment.
    """
    requested_normalized = requested.strip().casefold()
    declared_normalized = declared.value.casefold()
    return declared_normalized == requested_normalized


def _confidence_for_tier_and_attestations(
    *,
    tier: AgentTrustTier,
    active_attestations: int,
    fresh: bool,
) -> float:
    base = tier.baseline_confidence
    if active_attestations >= 2:
        base = min(1.0, base + 0.05)
    if fresh:
        base = max(0.30, base - 0.10)
    return round(base, 4)


def _metadata_str(metadata: dict | None, key: str) -> str | None:
    """
    Pull a discovery-provenance string from the agent's metadata bag.

    Returns None on any of: missing metadata, missing key, non-string
    value, or blank-after-strip. The agent_signal field is bounded
    length, so we also clamp here defensively rather than raising.
    """
    if not metadata:
        return None
    value = metadata.get(key)
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    if not normalized:
        return None
    return normalized[:512]

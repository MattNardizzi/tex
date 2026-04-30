"""
Capability evaluation stream.

Answers: is this specific action within the agent's declared capability
surface? Capability mismatches are first-class structural findings that
do not depend on content evaluation at all.

Inputs considered:
- declared allowed_action_types vs request.action_type
- declared allowed_channels vs request.channel
- declared allowed_environments vs request.environment
- declared allowed_recipient_domains vs request.recipient

Outputs a CapabilitySignal that the router fuses with the other six
streams.
"""

from __future__ import annotations

from tex.domain.agent import AgentIdentity
from tex.domain.agent_signal import CapabilitySignal
from tex.domain.evaluation import EvaluationRequest
from tex.domain.finding import Finding
from tex.domain.severity import Severity


class AgentCapabilityEvaluator:
    """
    Pure evaluator. Stateless. Safe to share across threads.

    This evaluator is the one that hard-blocks structural mismatches.
    Even if content is clean, an action outside the agent's declared
    surface produces a CRITICAL finding and a high risk_score; the
    router will route it to FORBID through normal fusion.
    """

    def evaluate(
        self,
        *,
        agent: AgentIdentity,
        request: EvaluationRequest,
    ) -> CapabilitySignal:
        surface = agent.capability_surface
        violated: list[str] = []
        findings: list[Finding] = []
        reasons: list[str] = []
        uncertainty_flags: list[str] = []

        # 1. Action type
        action_permitted = surface.permits_action_type(request.action_type)
        if not action_permitted:
            violated.append("action_type")
            findings.append(
                Finding(
                    source="agent.capability",
                    rule_name="action_type_out_of_surface",
                    severity=Severity.CRITICAL,
                    message=(
                        f"Agent is not authorized for action_type "
                        f"{request.action_type!r}. Allowed: "
                        f"{list(surface.allowed_action_types)}."
                    ),
                )
            )
            reasons.append(
                f"Action type {request.action_type!r} is outside the agent's capability surface."
            )

        # 2. Channel
        channel_permitted = surface.permits_channel(request.channel)
        if not channel_permitted:
            violated.append("channel")
            findings.append(
                Finding(
                    source="agent.capability",
                    rule_name="channel_out_of_surface",
                    severity=Severity.CRITICAL,
                    message=(
                        f"Agent is not authorized for channel "
                        f"{request.channel!r}. Allowed: "
                        f"{list(surface.allowed_channels)}."
                    ),
                )
            )
            reasons.append(
                f"Channel {request.channel!r} is outside the agent's capability surface."
            )

        # 3. Environment
        env_permitted = surface.permits_environment(request.environment)
        if not env_permitted:
            violated.append("environment")
            findings.append(
                Finding(
                    source="agent.capability",
                    rule_name="environment_out_of_surface",
                    severity=Severity.CRITICAL,
                    message=(
                        f"Agent is not authorized for environment "
                        f"{request.environment!r}. Allowed: "
                        f"{list(surface.allowed_environments)}."
                    ),
                )
            )
            reasons.append(
                f"Environment {request.environment!r} is outside the agent's capability surface."
            )

        # 4. Recipient
        recipient_permitted = surface.permits_recipient(request.recipient)
        if not recipient_permitted:
            violated.append("recipient_domain")
            findings.append(
                Finding(
                    source="agent.capability",
                    rule_name="recipient_out_of_surface",
                    severity=Severity.CRITICAL,
                    message=(
                        f"Recipient {request.recipient!r} is outside the agent's "
                        "allowed recipient domains."
                    ),
                )
            )
            reasons.append("Recipient is outside the agent's allowed domains.")

        # 5. Risk and confidence
        if violated:
            # Each violation contributes structural risk. One violation
            # is already enough to be high-risk; multiple violations
            # saturate quickly.
            risk_score = min(1.0, 0.55 + 0.15 * len(violated))
            confidence = 0.95  # We are highly confident the action is out-of-surface.
        else:
            if surface.is_unrestricted:
                # Agent declares no restrictions — that itself is a
                # posture concern. We surface it as low risk and an
                # uncertainty flag so the router can take note.
                risk_score = 0.30
                confidence = 0.55
                uncertainty_flags.append("agent_unrestricted_surface")
                reasons.append(
                    "Agent declares no capability restrictions; posture risk elevated."
                )
            else:
                # Action is fully within the declared surface. Low risk,
                # high confidence.
                risk_score = 0.05
                confidence = 0.92
                reasons.append(
                    "Action is within the agent's declared capability surface."
                )

        return CapabilitySignal(
            risk_score=round(risk_score, 4),
            confidence=round(confidence, 4),
            findings=tuple(findings),
            reasons=tuple(reasons),
            uncertainty_flags=tuple(uncertainty_flags),
            surface_unrestricted=surface.is_unrestricted,
            action_permitted=action_permitted,
            channel_permitted=channel_permitted,
            environment_permitted=env_permitted,
            recipient_permitted=recipient_permitted,
            violated_dimensions=tuple(violated),
        )


def neutral_capability_signal() -> CapabilitySignal:
    """Neutral signal used when no agent is supplied."""
    return CapabilitySignal(
        risk_score=0.0,
        confidence=0.0,
        findings=tuple(),
        reasons=tuple(),
        uncertainty_flags=tuple(),
        surface_unrestricted=True,
        action_permitted=True,
        channel_permitted=True,
        environment_permitted=True,
        recipient_permitted=True,
        violated_dimensions=tuple(),
    )

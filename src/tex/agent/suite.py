"""
Agent evaluation suite.

Wraps the three agent streams (identity, capability, behavioral) into
one orchestrator that the PDP calls. When no agent is supplied with the
request, the suite returns a neutral bundle that the router knows to
exclude from fusion.

This is where the "no regression on content-only requests" contract is
enforced at the engine level: a request without an agent_id produces a
bundle with `agent_present=False` and the router's renormalization
kicks in to redistribute weight back to the four content layers.

V11: the suite also threads the tenant content baseline through to
the behavioral evaluator. The baseline is optional — when absent, the
behavioral stream behaves exactly as it did in V10.
"""

from __future__ import annotations

from tex.agent.behavioral_evaluator import (
    AgentBehavioralEvaluator,
    neutral_behavioral_signal,
)
from tex.agent.capability_evaluator import (
    AgentCapabilityEvaluator,
    neutral_capability_signal,
)
from tex.agent.identity_evaluator import (
    AgentIdentityEvaluator,
    neutral_identity_signal,
)
from tex.domain.agent_signal import AgentEvaluationBundle
from tex.domain.evaluation import EvaluationRequest
from tex.stores.action_ledger import InMemoryActionLedger
from tex.stores.agent_registry import (
    AgentNotFoundError,
    AgentRevoked,
    InMemoryAgentRegistry,
)
from tex.stores.tenant_content_baseline import InMemoryTenantContentBaseline


class AgentEvaluationSuite:
    """
    Composes the three agent evaluation streams.

    Stateless aside from holding references to the registry, ledger,
    tenant baseline, and evaluators. Safe to share across threads.

    The tenant content baseline is optional. When provided, the
    behavioral evaluator uses it to add cross-agent novelty signals
    that no other product in the market evaluates.
    """

    __slots__ = (
        "_registry",
        "_ledger",
        "_tenant_baseline",
        "_identity",
        "_capability",
        "_behavioral",
    )

    def __init__(
        self,
        *,
        registry: InMemoryAgentRegistry,
        ledger: InMemoryActionLedger,
        tenant_baseline: InMemoryTenantContentBaseline | None = None,
        identity: AgentIdentityEvaluator | None = None,
        capability: AgentCapabilityEvaluator | None = None,
        behavioral: AgentBehavioralEvaluator | None = None,
    ) -> None:
        self._registry = registry
        self._ledger = ledger
        self._tenant_baseline = tenant_baseline
        self._identity = identity or AgentIdentityEvaluator()
        self._capability = capability or AgentCapabilityEvaluator()
        self._behavioral = behavioral or AgentBehavioralEvaluator(
            ledger=ledger,
            tenant_baseline=tenant_baseline,
        )

    def evaluate(self, request: EvaluationRequest) -> AgentEvaluationBundle:
        if request.agent_id is None:
            return _neutral_bundle()

        # REVOKED is terminal: surface the error to the application layer
        # so the caller gets a clean rejection rather than a verdict.
        agent = self._registry.require_evaluable(request.agent_id)

        identity_signal = self._identity.evaluate(agent=agent, request=request)
        capability_signal = self._capability.evaluate(agent=agent, request=request)
        behavioral_signal = self._behavioral.evaluate(agent=agent, request=request)

        return AgentEvaluationBundle(
            agent_present=True,
            agent_id=str(agent.agent_id),
            identity=identity_signal,
            capability=capability_signal,
            behavioral=behavioral_signal,
        )


def _neutral_bundle() -> AgentEvaluationBundle:
    return AgentEvaluationBundle(
        agent_present=False,
        agent_id=None,
        identity=neutral_identity_signal(),
        capability=neutral_capability_signal(),
        behavioral=neutral_behavioral_signal(),
    )


# Re-export for callers that want a one-line build.
__all__ = [
    "AgentEvaluationSuite",
    "AgentNotFoundError",
    "AgentRevoked",
]

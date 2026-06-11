"""
Reflexive self-governance (Wave 2 / L5) — Tex governing its OWN controller
mutations through the same PDP / ABSTAIN surface / monotone+floor rules,
sealed into the same ledger. See ``selfgov/governor.py`` for the claim's exact
honesty boundary, the controller-mutation census, and the deploy-frozen
stratum. Maturity: research-early; inert until bound.
"""

# Architectural layer marker (matches the convention in tex.specialists).
__layer__: int | None = 5
__layer_kind__: str = "self_governance"

from tex.selfgov.governor import (  # noqa: E402,F401
    CONTROLLER_MUTATION_CENSUS,
    DEPLOY_FROZEN_STRATUM,
    GOVERNOR_FROZEN_POLICY,
    GOVERNOR_POLICY_ID,
    GOVERNOR_POLICY_VERSION,
    GateOutcome,
    MutationDescriptor,
    MutationSite,
    bind_reflexive_governor,
    bound_reflexive_governor,
    compose_gate_verdict,
    gate_controller_mutation,
    reflexive_governor_bound,
    unbind_reflexive_governor,
)

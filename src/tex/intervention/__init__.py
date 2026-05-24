"""
Intervention Layer — Cost-Bounded Steering
============================================

Applies bounded-cost interventions to steer the ecosystem back toward a
governable equilibrium when drift is detected or governance graph
violations are predicted.

Reference
---------
arxiv 2512.18561 (AAF). The bounded-compromise theorem: if expected
intervention cost exceeds adversary's expected payoff, the long-run
fraction of compromised interactions converges to a value strictly below one.

Intervention kinds
------------------
  capability_revoke       Revoke an unforgeable capability token
  trust_score_reduce      Reduce an agent's trust score
  reward_shape            Modify the reward signal feeding agent training
  policy_patch            Hot-patch a policy at the enforcement layer
  human_approval_gate     Require human approval on the next N actions
  quarantine              Move an agent to a quarantined sandbox
  restorative_path        Trigger a registered restorative path

Priority
--------
P2 (full); skeleton in P1.
"""

from tex.intervention.engine import (
    InterventionApplyError,
    InterventionEngine,
    InterventionSelectionError,
    air_phase_for,
)
from tex.intervention.bounded_compromise import (
    BoundedCompromiseCalculator,
    CompromiseCertificate,
    DEFAULT_FALSE_ALARM_BUDGET,
    DEFAULT_STRICT_DOMINANCE_EPSILON,
    DEFAULT_TARGET_COMPROMISE_CEILING,
    DEFAULT_WINDOW_LENGTH,
)
from tex.intervention.eradication import (
    DEFAULT_MAX_LTLF_DEPTH,
    DEFAULT_MAX_PREDICATE_COUNT,
    EradicationRuleSynthesizer,
    IncidentContext,
    InMemoryRuleRegistry,
    LLMClient,
    RuleRegistry,
    RuleSynthesisError,
    SynthesizedRule,
)
from tex.intervention.kinds import Intervention, InterventionKind
from tex.intervention.neyman_pearson import (
    DEFAULT_LAGRANGIAN_LAMBDA,
    MonitorCandidateSource,
    MonitorPortfolio,
    NeymanPearsonSelector,
    PortfolioSelection,
    compose_intervention_pool,
)
from tex.intervention.restorative import RestorativePathExecutor

__all__ = [
    "BoundedCompromiseCalculator",
    "CompromiseCertificate",
    "DEFAULT_FALSE_ALARM_BUDGET",
    "DEFAULT_LAGRANGIAN_LAMBDA",
    "DEFAULT_MAX_LTLF_DEPTH",
    "DEFAULT_MAX_PREDICATE_COUNT",
    "DEFAULT_STRICT_DOMINANCE_EPSILON",
    "DEFAULT_TARGET_COMPROMISE_CEILING",
    "DEFAULT_WINDOW_LENGTH",
    "EradicationRuleSynthesizer",
    "InMemoryRuleRegistry",
    "IncidentContext",
    "Intervention",
    "InterventionApplyError",
    "InterventionEngine",
    "InterventionKind",
    "InterventionSelectionError",
    "LLMClient",
    "MonitorCandidateSource",
    "MonitorPortfolio",
    "NeymanPearsonSelector",
    "PortfolioSelection",
    "RestorativePathExecutor",
    "RuleRegistry",
    "RuleSynthesisError",
    "SynthesizedRule",
    "air_phase_for",
    "compose_intervention_pool",
]

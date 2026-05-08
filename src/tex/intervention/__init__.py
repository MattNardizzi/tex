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

from tex.intervention.engine import InterventionEngine
from tex.intervention.bounded_compromise import BoundedCompromiseCalculator
from tex.intervention.kinds import InterventionKind, Intervention

__all__ = [
    "InterventionEngine",
    "BoundedCompromiseCalculator",
    "InterventionKind",
    "Intervention",
]

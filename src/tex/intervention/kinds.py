"""
Intervention kinds.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class InterventionKind(str, Enum):
    CAPABILITY_REVOKE = "capability_revoke"
    TRUST_SCORE_REDUCE = "trust_score_reduce"
    REWARD_SHAPE = "reward_shape"
    POLICY_PATCH = "policy_patch"
    HUMAN_APPROVAL_GATE = "human_approval_gate"
    QUARANTINE = "quarantine"
    RESTORATIVE_PATH = "restorative_path"


@dataclass(frozen=True, slots=True)
class Intervention:
    intervention_id: str
    kind: InterventionKind
    target_entity_id: str
    parameters: dict
    expected_cost_to_system: float
    expected_cost_to_adversary: float
    rationale: str

"""
Intervention kinds.

Thread 8 ships 7 kinds. Thread 8.1 adds an 8th, ``ERADICATION_RULE_SYNTHESIS``,
per AIR (arxiv 2602.11749, Feb 12 2026) §3 eradication phase: generate a
new structured guardrail rule from the incident context so the same
incident class cannot recur. AIR's wedge over Tex up to Thread 8 is that
Tex's intervention enum was *fixed*; AIR generates new rules at runtime.
Thread 8.1 closes that gap.
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
    # Thread 8.1: AIR-style eradication. The intervention's parameters
    # carry an ``incident_context`` dict; apply-time synthesises a new
    # ``SynthesizedRule`` and registers it with the active contract
    # enforcer so future events are evaluated against the new rule.
    ERADICATION_RULE_SYNTHESIS = "eradication_rule_synthesis"


@dataclass(frozen=True, slots=True)
class Intervention:
    intervention_id: str
    kind: InterventionKind
    target_entity_id: str
    parameters: dict
    expected_cost_to_system: float
    expected_cost_to_adversary: float
    rationale: str

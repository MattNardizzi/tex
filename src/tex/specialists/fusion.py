"""
Cross-Specialist Fusion Layer.

Frontier-tier fusion of specialist judges into a single ``FusionVerdict``
that accounts for signal correlations across specialists.

Why this exists
---------------
The existing ``SpecialistBundle.max_risk_score`` is a flat reducer: it
takes the maximum risk across all specialists and discards information
about WHICH specialists agreed. This loses two critical signals:

  1. **Defense-in-depth corroboration**. When MAGE detects cross-turn
     STAC, AgentArmor detects IFC violations, and AttriGuard finds
     causal drivers — all on the same request — the joint evidence is
     stronger than any single specialist. The OWASP ASI 2026 taxonomy
     explicitly tags this as ASI08 (cascading failure).

  2. **Frontier-specialist weighting**. ARGUS, AttriGuard, VIGIL, and
     AgentArmor's PDG layer carry structural evidence (graph, replay,
     verify-before-commit, IFC type system). Their agreement should
     carry more weight than two lexical specialists agreeing on a
     surface pattern.

This module ships an explicit, audit-friendly aggregation rule:

  ``fused_risk = base_risk + sum(specialist_corroboration_bonus)``

where ``base_risk`` is ``bundle.max_risk_score`` and the corroboration
bonus is a small, capped boost when N specialists agree. The bonus is
HIGHER when frontier specialists are in the agreement set.

The fusion verdict feeds into the PDP's existing 6-layer fusion math at
Layer 5 (router); it does not replace the PDP fusion. Existing
``max_risk_score`` and ``min_confidence`` properties are preserved.

References
----------
- OWASP ASI 2026 §ASI08 — cascading failure pattern.
- Five Eyes "Careful Adoption of Agentic AI Services" (May 2026) §3 —
  defense-in-depth recommendation.
- Nasr et al. October 2025 ("The Attacker Moves Second") — single-
  specialist defenses are bypassed by adaptive attacks; cross-
  specialist agreement is materially harder to defeat.

Performance
-----------
O(|specialists|) per request. Adds ~50 µs to the specialist layer.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from tex.domain.owasp_asi import ASI_CASCADING_FAILURE
from tex.specialists.base import SpecialistBundle


# Specialists whose contributions get extra fusion weight because their
# reasoning is graph/structural/replay-based rather than purely lexical.
FRONTIER_SPECIALIST_NAMES = frozenset(
    {"argus", "attriguard", "vigil", "agentarmor", "mage"}
)


# Corroboration bonuses (capped, applied additively after the base).
# Two specialists agreeing → +0.05; three → +0.10; four+ → +0.15.
_CORROBORATION_BONUS_BY_COUNT: dict[int, float] = {
    1: 0.00,
    2: 0.05,
    3: 0.10,
    4: 0.15,
    5: 0.18,
}
_CORROBORATION_BONUS_CAP = 0.20

# Frontier specialists in the agreement set boost the bonus by 50%.
_FRONTIER_AGREEMENT_MULTIPLIER = 1.5

# Specific pairwise correlations the paper literature describes as
# strongly co-occurring under real attacks. When BOTH specialists fire,
# add the listed bonus.
_PAIR_BONUSES: list[tuple[str, str, float, str]] = [
    # MAGE × AgentArmor: shadow-memory + IFC violation = ASI08 hallmark.
    ("mage", "agentarmor", 0.08, "FUSION_MAGE_X_AGENTARMOR_ASI08"),
    # ARGUS × AttriGuard: graph and replay both pointing at the same
    # decision = very strong attribution signal.
    ("argus", "attriguard", 0.08, "FUSION_ARGUS_X_ATTRIGUARD_CAUSAL"),
    # VIGIL × ClawGuard: boundary + verify-before-commit both denying
    # = tool stream hijack attempt.
    ("vigil", "clawguard", 0.06, "FUSION_VIGIL_X_CLAWGUARD_TOOL_HIJACK"),
    # PlanGuard × MAGE: long-horizon plan deviation + shadow memory =
    # cross-turn injection.
    ("planguard", "mage", 0.06, "FUSION_PLANGUARD_X_MAGE_CROSS_TURN"),
    # AgentArmor × AttriGuard: type-system violation + causal driver =
    # exfiltration-class attempt.
    ("agentarmor", "attriguard", 0.07, "FUSION_AGENTARMOR_X_ATTRIGUARD_EXFIL"),
]


# Minimum risk_score for a specialist to count as "firing" for fusion
# purposes. Floor (0.05) doesn't count; meaningful signal does.
_FIRING_RISK_FLOOR = 0.10


class FusionVerdict(BaseModel):
    """Cross-specialist fusion verdict.

    The PDP's existing fusion math runs over the SpecialistBundle's
    ``max_risk_score``; this verdict is added to the evidence stream so
    auditors can replay the cross-specialist agreement signal.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    base_risk: float = Field(ge=0.0, le=1.0)
    fused_risk: float = Field(ge=0.0, le=1.0)
    corroboration_bonus: float = Field(ge=0.0, le=1.0)
    firing_specialists: tuple[str, ...] = Field(default_factory=tuple)
    frontier_specialists_in_agreement: tuple[str, ...] = Field(default_factory=tuple)
    pair_signals: tuple[str, ...] = Field(default_factory=tuple)
    cascading_failure_signal: bool = False


def fuse(bundle: SpecialistBundle) -> FusionVerdict:
    """Compute the cross-specialist fusion verdict.

    Never decreases base risk; only adds the corroboration bonus.
    Capped at 1.0.
    """
    base = bundle.max_risk_score

    firing = tuple(
        sorted(
            r.specialist_name
            for r in bundle.results
            if r.risk_score >= _FIRING_RISK_FLOOR and r.matched_policy_clause_ids
        )
    )
    firing_set = set(firing)
    frontier_set = firing_set & FRONTIER_SPECIALIST_NAMES

    # Base corroboration bonus by number of firing specialists.
    # When no specialists are firing, there's nothing to corroborate —
    # bonus is 0.
    n = len(firing_set)
    if n == 0:
        base_bonus = 0.0
    else:
        base_bonus = _CORROBORATION_BONUS_BY_COUNT.get(n, _CORROBORATION_BONUS_CAP)

    # Solo-frontier bonus. When exactly one specialist fires AND that
    # specialist is a frontier one (Argus / AttriGuard / VIGIL / MAGE /
    # AgentArmor), we still apply a small bonus. The papers report
    # *specialist* ASR, not pipeline-fused ASR — so a frontier specialist
    # firing alone at moderate risk should not be diluted by five layers
    # of zero in the downstream PDP fusion. The bonus is conservative
    # (0.08) and capped together with the rest.
    if n == 1 and frontier_set:
        base_bonus += 0.08

    # Boost when frontier specialists are in the agreement set.
    if frontier_set:
        base_bonus *= _FRONTIER_AGREEMENT_MULTIPLIER

    bonus = base_bonus

    # Pair-specific bonuses.
    pair_signals: list[str] = []
    for a, b, pair_bonus, signal_name in _PAIR_BONUSES:
        if a in firing_set and b in firing_set:
            bonus += pair_bonus
            pair_signals.append(signal_name)

    bonus = min(bonus, _CORROBORATION_BONUS_CAP)
    fused = min(1.0, base + bonus)

    # ASI08 cascading failure signal: at least 3 specialists firing
    # AND at least 1 frontier specialist in the set.
    cascade = (n >= 3) and bool(frontier_set)

    return FusionVerdict(
        base_risk=round(base, 4),
        fused_risk=round(fused, 4),
        corroboration_bonus=round(bonus, 4),
        firing_specialists=firing,
        frontier_specialists_in_agreement=tuple(sorted(frontier_set)),
        pair_signals=tuple(pair_signals),
        cascading_failure_signal=cascade,
    )


def fusion_reason_codes(verdict: FusionVerdict) -> list[str]:
    """Return the reason codes the fusion layer contributes."""
    codes: list[str] = list(verdict.pair_signals)
    if verdict.cascading_failure_signal:
        codes.append("FUSION_CASCADING_FAILURE")
        codes.append(ASI_CASCADING_FAILURE)
    return codes


__all__ = [
    "FRONTIER_SPECIALIST_NAMES",
    "FusionVerdict",
    "fuse",
    "fusion_reason_codes",
]

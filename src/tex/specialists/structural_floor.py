"""
Structural FORBID floor.

[Architecture: Layer 4 (Execution Governance)]

Why this exists
---------------
Four of Tex's specialists do not *estimate* risk — they *prove* a violation
deterministically over structure:

  * **PCAS**     — a Datalog reference monitor. A ``deny:`` rule firing is a
                   formal authorization FORBID, not an inference.
  * **CaMeL**    — a capability-based dual-LLM interpreter. A capability denial
                   means an unauthorized data flow was attempted.
  * **IFC**      — an information-flow lattice. A flow-integrity / min-trust /
                   causality-laundering / CI-norm / cross-session / rule-of-two
                   violation is a typed proof that data moved where it must not.
  * **ARGUS**    — an influence-provenance graph. ``OBSERVATION_DRIVEN`` means a
                   counterfactual test proved the decision was driven by
                   injected observation content, not by the user.

These are the *system-level structural mitigations* that the field's strongest
adversarial-robustness result — Nasr et al., "The Attacker Moves Second"
(arXiv:2510.09023) — identifies as the actual answer to adaptive attackers,
in contrast to stacking probabilistic detectors (which that paper shows do
**not** solve robustness). A surface paraphrase cannot change a Datalog deny or
an IFC type violation; that is exactly what makes them robust.

Yet until now these four ran as ordinary *voting* specialists: a PCAS deny at
``risk_score = 1.0`` entered the router's weighted sum at the specialists
weight (~0.195) and, on otherwise-clean content, produced a fused score around
0.2 — below ``forbid_threshold`` — and routed to **ABSTAIN**. The most rigorous,
deterministic signal in the system could not FORBID on its own.

This module gives them that authority. It recognises each specialist's
**unambiguous deterministic-deny signature** (never a mere high score) and, when
one fires, the PDP short-circuits to FORBID alongside the deterministic gate,
behavioural-contract hard violations, and path-policy blocks. The probabilistic
voting tier is unchanged; only proofs get the floor.

Determinism & fail-closed: detection is a pure function of the specialist
bundle. It only ever *raises* severity (voting result → FORBID); it can never
relax a verdict.
"""

from __future__ import annotations

from dataclasses import dataclass

from tex.domain.finding import Finding
from tex.domain.severity import Severity
from tex.specialists.base import SpecialistBundle, SpecialistResult


# Specialist names whose output can carry a structural proof.
_PCAS = "pcas"
_CAMEL = "camel"
_IFC = "ifc"
_ARGUS = "argus"

# IFC lattice violations that constitute a typed flow proof (engine.IfcViolation).
_IFC_HARD_VIOLATION_CODES = frozenset(
    {
        "ifc.flow_integrity",
        "ifc.min_trust_floor",
        "ifc.causality_laundering",
        "ifc.ci_norm_violation",
        "ifc.neurotaint_cross_session",
        "ifc.rule_of_two_trifecta",
    }
)

# ARGUS reason code whose counterfactual test proves injection-driven decision.
# Deliberately narrow: NO_JUSTIFICATION / HIGH_RISK_ANCESTRY are suspect signals
# that stay on the voting/ABSTAIN path; only the counterfactually-proven
# observation-driven decision earns the floor.
_ARGUS_HARD_CODES = frozenset({"ARGUS_DECISION_OBSERVATION_DRIVEN"})

# PCAS / CaMeL deny sentinel: their FORBID verdict maps to exactly risk 1.0
# (ABSTAIN → 0.5, PERMIT → 0.0). We compare with a tolerance.
_DENY_RISK = 1.0
_EPS = 1e-9

FINDING_SOURCE = "structural_floor"


@dataclass(frozen=True, slots=True)
class StructuralDeny:
    """One structural specialist's deterministic deny."""

    specialist: str
    reason: str
    codes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class StructuralFloorResult:
    """Aggregate structural-floor outcome for one evaluation."""

    fired: bool
    denies: tuple[StructuralDeny, ...]
    findings: tuple[Finding, ...]

    @property
    def denying_specialists(self) -> tuple[str, ...]:
        return tuple(d.specialist for d in self.denies)

    @property
    def reasons(self) -> tuple[str, ...]:
        return tuple(d.reason for d in self.denies)


NEUTRAL_STRUCTURAL_FLOOR = StructuralFloorResult(fired=False, denies=(), findings=())


def _classify(result: SpecialistResult) -> StructuralDeny | None:
    """Return a StructuralDeny if this result is a deterministic deny, else None."""
    name = result.specialist_name
    clause_ids = tuple(result.matched_policy_clause_ids)

    if name == _PCAS and result.risk_score >= _DENY_RISK - _EPS:
        return StructuralDeny(
            specialist=_PCAS,
            reason=(
                "PCAS Datalog reference monitor returned a deterministic DENY "
                "(toxic-flow rule matched over the provenance graph)."
            ),
            codes=clause_ids,
        )

    if name == _CAMEL and result.risk_score >= _DENY_RISK - _EPS:
        return StructuralDeny(
            specialist=_CAMEL,
            reason=(
                "CaMeL capability interpreter denied the action (unauthorized "
                "data flow / capability violation, or fail-closed interpreter "
                "error)."
            ),
            codes=clause_ids,
        )

    if name == _IFC:
        hit = tuple(c for c in clause_ids if c in _IFC_HARD_VIOLATION_CODES)
        if hit:
            return StructuralDeny(
                specialist=_IFC,
                reason=(
                    "IFC lattice proved a typed flow violation: "
                    f"{', '.join(hit)}."
                ),
                codes=hit,
            )

    if name == _ARGUS:
        hit = tuple(c for c in clause_ids if c in _ARGUS_HARD_CODES)
        if hit:
            return StructuralDeny(
                specialist=_ARGUS,
                reason=(
                    "ARGUS counterfactual test proved the decision was driven "
                    "by injected observation content "
                    "(ARGUS_DECISION_OBSERVATION_DRIVEN)."
                ),
                codes=hit,
            )

    return None


def detect_structural_floor(bundle: SpecialistBundle) -> StructuralFloorResult:
    """Scan the specialist bundle for deterministic structural denies.

    Returns ``NEUTRAL_STRUCTURAL_FLOOR`` when none fire. When one or more fire,
    the PDP short-circuits the evaluation to FORBID, attributing the verdict to
    the proving specialist(s).
    """
    denies: list[StructuralDeny] = []
    findings: list[Finding] = []

    for result in bundle.results:
        deny = _classify(result)
        if deny is None:
            continue
        denies.append(deny)
        findings.append(
            Finding(
                source=f"{FINDING_SOURCE}.{deny.specialist}",
                rule_name=f"{deny.specialist}_structural_deny",
                severity=Severity.CRITICAL,
                message=deny.reason,
                metadata={
                    "specialist": deny.specialist,
                    "codes": ",".join(deny.codes) if deny.codes else "",
                    "tier": "structural_floor",
                },
            )
        )

    if not denies:
        return NEUTRAL_STRUCTURAL_FLOOR

    return StructuralFloorResult(
        fired=True,
        denies=tuple(denies),
        findings=tuple(findings),
    )


__all__ = [
    "StructuralDeny",
    "StructuralFloorResult",
    "NEUTRAL_STRUCTURAL_FLOOR",
    "detect_structural_floor",
    "FINDING_SOURCE",
]

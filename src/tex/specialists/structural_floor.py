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

These are *system-level structural mitigations*. Nasr et al., "The Attacker
Moves Second: Stronger Adaptive Attacks Bypass Defenses Against LLM Jailbreaks
and Prompt Injections" (arXiv:2510.09023, 2025), is an attack-demonstration
paper: a general adaptive-attack framework bypasses 12 recent jailbreak /
prompt-injection defenses — many of them detector- or filter-based — at >90%
success, despite their near-zero reported rates. Its lesson is that defenses
must be evaluated against *adaptive* attackers, not static strings; the
directional implication we lean on (a probabilistic detector that a stronger
optimizer can route around is not a robustness guarantee) is our inference, not
the paper's stated thesis. What makes a Datalog deny or an IFC type violation
robust is independent: a surface paraphrase cannot change them by construction.

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
from typing import Any

from tex.contracts import rv4_path
from tex.contracts.rule_of_two import (
    RULE_OF_TWO_CODE,
    RULE_OF_TWO_SPECIALIST,
    evaluate_rule_of_two,
)
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
#
# The CaMeL contract (specialists/camel_specialist.py): the interpreter is
# capability-deterministic — risk == 1.0 IFF the plan HALTED on a tool-policy
# capability check or a fail-closed interpreter error (a genuine *denial*),
# risk == 0.5 is "completed but UNTRUSTED-tainted" (not a deny), risk == 0.0 is
# clean. So 1.0 uniquely identifies a deterministic CaMeL denial — never a
# probabilistic high score. (DeepMind CaMeL, "Defeating Prompt Injections by
# Design," arXiv:2503.18813: a denied tool call fails closed.) A regression test
# pins this 1.0 ⟺ denial contract so a future probabilistic CaMeL variant cannot
# silently start firing the floor.
_DENY_RISK = 1.0
_EPS = 1e-9

# Forward-compatible: if the CaMeL specialist ever annotates a denial with an
# explicit clause id, recognise it directly (a code is sturdier than a score).
_CAMEL_DENY_CODES = frozenset({"camel.capability_denied", "camel.interpreter_halt"})

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

    if name == _CAMEL and (
        result.risk_score >= _DENY_RISK - _EPS
        or any(c in _CAMEL_DENY_CODES for c in clause_ids)
    ):
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


def _rule_of_two_deny(request: Any) -> StructuralDeny | None:
    """Rule-of-Two trifecta → a structural deny (untrusted ∧ sensitive ∧ state-change)."""
    outcome = evaluate_rule_of_two(request)
    if not outcome.fired:
        return None
    return StructuralDeny(
        specialist=RULE_OF_TWO_SPECIALIST,
        reason=outcome.reason,
        codes=(RULE_OF_TWO_CODE,),
    )


def _rv4_permanent_denies(request: Any) -> list[StructuralDeny]:
    """RV4 path policies that are PERMANENTLY violated (bad prefixes) → denies.

    Only the permanent (⊥) verdict earns a structural FORBID — it is a proof
    that no extension of the path can satisfy the policy. Recoverable (⊥_p)
    violations are NOT here; they are soft holds handled by
    ``systemic.probguard.apply_predictive_holds`` (PERMIT→ABSTAIN).
    """
    outcome = rv4_path.classify(request)
    denies: list[StructuralDeny] = []
    for v in outcome.permanent:
        denies.append(
            StructuralDeny(
                specialist="rv4_path",
                reason=v.reason,
                codes=(v.policy_id,),
            )
        )
    return denies


def detect_structural_floor(
    bundle: SpecialistBundle,
    *,
    request: Any | None = None,
) -> StructuralFloorResult:
    """Scan for deterministic structural denies that short-circuit to FORBID.

    Three deterministic sources, each a *proof* of a violation (never a high
    probabilistic score):

      1. **Specialist proofs** — a PCAS / CaMeL / IFC / ARGUS deny signature in
         the specialist bundle (the original floor).
      2. **Rule-of-Two trifecta** — untrusted-input ∧ sensitive-access ∧
         state-change with no human oversight (``tex.contracts.rule_of_two``),
         when ``request`` carries the ``rule_of_two`` metadata.
      3. **RV4 permanent path violations** — an LTLf path policy that is a
         proven bad prefix (``tex.contracts.rv4_path``), when ``request``
         carries the ``rv4_path_policies`` metadata.

    Returns ``NEUTRAL_STRUCTURAL_FLOOR`` when none fire. ``request`` is optional
    so the pure specialist-bundle form (used widely in tests) keeps working; the
    label-driven sources are simply skipped when it is absent.
    """
    denies: list[StructuralDeny] = []

    for result in bundle.results:
        deny = _classify(result)
        if deny is not None:
            denies.append(deny)

    if request is not None:
        rule_of_two = _rule_of_two_deny(request)
        if rule_of_two is not None:
            denies.append(rule_of_two)
        denies.extend(_rv4_permanent_denies(request))

    if not denies:
        return NEUTRAL_STRUCTURAL_FLOOR

    findings = [
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
        for deny in denies
    ]

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

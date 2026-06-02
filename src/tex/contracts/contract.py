"""
Behavioral contract specification.

Per arxiv 2602.22302 (Bhardwaj, "AgentAssert: Formal Behavioral
Contracts for Autonomous AI Agents") — the contract is the formal
6-tuple

    C = (P, I_hard, I_soft, G_hard, G_soft, R)

extended to support the existing Tex 4-field scaffold so this thread
is a non-breaking refinement: the original ``precondition_ltl``,
``postcondition_ltl``, and ``invariants_ltl`` fields are preserved.
``invariants_ltl`` is interpreted as ``hard_invariants_ltl`` for
back-compat, and the ABC-paper-aligned ``soft_invariants_ltl``,
``hard_governance_ltl``, ``soft_governance_ltl`` are added as new fields.

Source-paper crosswalk
----------------------
- arxiv 2602.22302 §3.1 Definition 3.1 — the 6-tuple structure
- arxiv 2602.22302 §3.3 Definition 3.7 — (p, δ, k)-satisfaction
- arxiv 2602.22302 §3.5 Definition 3.12 — behavioral drift score (consumed
  separately by tex.drift; this layer just exposes the parameters)
- AgentVerify preprints.org 2604.1029 — propositional LTL templates
  used by the invariant-response enforcement loop

Priority: P1.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from tex.contracts._ltl import LTLFormula, LTLParseError


# Constraint kinds — the 4-way taxonomy from arxiv 2602.22302 §3.1.
ConstraintKind = Literal[
    "precondition",
    "hard_invariant",
    "soft_invariant",
    "hard_governance",
    "soft_governance",
    "postcondition",  # legacy Tex scaffold field, kept for back-compat
]

# Severity literal — the existing Tex action vocabulary; ABC paper has
# only "block on hard / recover on soft", but Tex distinguishes
# "sanction" (admit + reduce trust) from "warn" (telemetry only) per
# tex.ecosystem.verdict.EcosystemVerdictKind.
SeverityOnViolation = Literal["block", "sanction", "warn"]


@dataclass(frozen=True, slots=True)
class _ParsedFormulas:
    """
    Pre-parsed LTL formulas attached to a contract.

    Held in a separate frozen dataclass so the public BehavioralContract
    can stay a string-only data class (cheap to construct, deep-equal,
    pickle-clean) while the enforcer can carry parsed ASTs around for
    the duration of an evaluation.
    """

    precondition: LTLFormula | None
    postcondition: LTLFormula | None  # legacy
    hard_invariants: tuple[LTLFormula, ...]
    soft_invariants: tuple[LTLFormula, ...]
    hard_governance: tuple[LTLFormula, ...]
    soft_governance: tuple[LTLFormula, ...]


@dataclass(frozen=True, slots=True)
class BehavioralContract:
    """
    A behavioral contract for one agent.

    Field crosswalk to arxiv 2602.22302 §3.1:

      precondition_ltl       -> P  (single LTL combining all preconds)
      hard_invariants_ltl    -> I_hard   (alias: invariants_ltl)
      soft_invariants_ltl    -> I_soft
      hard_governance_ltl    -> G_hard
      soft_governance_ltl    -> G_soft
      recovery_window_k      -> the bounded recovery horizon k of (p,δ,k)
      delta_tolerance        -> δ in (p,δ,k)
      satisfaction_p         -> p in (p,δ,k)

    Legacy fields kept to preserve the existing Tex scaffold:
      postcondition_ltl      -> not in the ABC paper; degrades to a
                                ``F<=1`` check on the post-execution state
      invariants_ltl         -> back-compat alias for hard_invariants_ltl

    Constraints applicable to (agent_id, event_kind) are selected via:
      * agent_id == self.agent_id, or self.agent_id == "*"
      * event_kind in covered_event_kinds, or "*" in covered_event_kinds
    """

    # Identity
    contract_id: str
    agent_id: str
    description: str

    # ABC tuple
    precondition_ltl: str
    postcondition_ltl: str  # legacy; "true" disables the check
    invariants_ltl: tuple[str, ...]  # back-compat alias for hard_invariants_ltl
    soft_invariants_ltl: tuple[str, ...]
    hard_governance_ltl: tuple[str, ...]
    soft_governance_ltl: tuple[str, ...]

    # Action policy
    covered_event_kinds: tuple[str, ...]
    severity_on_violation: SeverityOnViolation

    # (p, δ, k) parameters per arxiv 2602.22302 §3.3
    recovery_window_k: int
    delta_tolerance: float
    satisfaction_p: float

    @staticmethod
    def make(
        *,
        contract_id: str,
        agent_id: str,
        description: str,
        precondition_ltl: str = "true",
        postcondition_ltl: str = "true",
        hard_invariants_ltl: tuple[str, ...] = (),
        soft_invariants_ltl: tuple[str, ...] = (),
        hard_governance_ltl: tuple[str, ...] = (),
        soft_governance_ltl: tuple[str, ...] = (),
        covered_event_kinds: tuple[str, ...] = ("*",),
        severity_on_violation: SeverityOnViolation = "block",
        recovery_window_k: int = 3,
        delta_tolerance: float = 0.1,
        satisfaction_p: float = 0.95,
    ) -> "BehavioralContract":
        """
        Convenience builder using ABC paper field names.

        Parses every LTL string at construction time and raises
        ``LTLParseError`` on malformed input — callers get the failure
        synchronously instead of at first enforcement.
        """
        contract = BehavioralContract(
            contract_id=contract_id,
            agent_id=agent_id,
            description=description,
            precondition_ltl=precondition_ltl,
            postcondition_ltl=postcondition_ltl,
            invariants_ltl=hard_invariants_ltl,
            soft_invariants_ltl=soft_invariants_ltl,
            hard_governance_ltl=hard_governance_ltl,
            soft_governance_ltl=soft_governance_ltl,
            covered_event_kinds=covered_event_kinds,
            severity_on_violation=severity_on_violation,
            recovery_window_k=recovery_window_k,
            delta_tolerance=delta_tolerance,
            satisfaction_p=satisfaction_p,
        )
        # Validate by parsing once. The result is discarded; the
        # enforcer re-parses on use (microseconds) and we want failures
        # to surface at construction.
        contract.parsed_formulas()
        return contract

    def __post_init__(self) -> None:
        # Numeric guardrails — match arxiv 2602.22302 §3.3.
        if not 0.0 <= self.delta_tolerance <= 1.0:
            raise ValueError(
                f"delta_tolerance must be in [0,1], got {self.delta_tolerance}"
            )
        if not 0.0 <= self.satisfaction_p <= 1.0:
            raise ValueError(
                f"satisfaction_p must be in [0,1], got {self.satisfaction_p}"
            )
        if self.recovery_window_k < 0:
            raise ValueError(
                f"recovery_window_k must be ≥ 0, got {self.recovery_window_k}"
            )
        if not self.covered_event_kinds:
            raise ValueError("covered_event_kinds may not be empty")

    def parsed_formulas(self) -> _ParsedFormulas:
        """
        Parse every LTL string and return the AST bundle.

        Re-parses on every call rather than carry mutable cache state
        on the frozen dataclass. Parsing is microsecond-cheap (recursive
        descent over a tiny grammar) so this is acceptable. Callers
        that enforce many times per second can wrap with
        ``functools.lru_cache(maxsize=…)`` keyed on ``contract_id``.
        """
        try:
            pre = (
                LTLFormula.parse(self.precondition_ltl)
                if self.precondition_ltl.strip()
                else None
            )
            post = (
                LTLFormula.parse(self.postcondition_ltl)
                if (
                    self.postcondition_ltl.strip()
                    and self.postcondition_ltl.strip() != "true"
                )
                else None
            )
            hard_inv = tuple(LTLFormula.parse(f) for f in self.invariants_ltl)
            soft_inv = tuple(LTLFormula.parse(f) for f in self.soft_invariants_ltl)
            hard_gov = tuple(LTLFormula.parse(f) for f in self.hard_governance_ltl)
            soft_gov = tuple(LTLFormula.parse(f) for f in self.soft_governance_ltl)
        except LTLParseError as exc:
            raise LTLParseError(
                f"contract {self.contract_id!r}: {exc}"
            ) from exc
        return _ParsedFormulas(
            precondition=pre,
            postcondition=post,
            hard_invariants=hard_inv,
            soft_invariants=soft_inv,
            hard_governance=hard_gov,
            soft_governance=soft_gov,
        )

    def applies_to(self, *, agent_id: str, event_kind: str) -> bool:
        """
        Filter predicate used by the enforcer to select active contracts.

        Wildcard ``*`` matches in either field — useful for cross-agent
        baseline contracts (e.g. "no PII anywhere") and for contracts
        that fire on every event kind.
        """
        if self.agent_id != "*" and self.agent_id != agent_id:
            return False
        if "*" in self.covered_event_kinds:
            return True
        return event_kind in self.covered_event_kinds

    def total_constraint_count(self) -> int:
        """
        |I_hard| + |I_soft| + |G_hard| + |G_soft| — used to compute
        per-step ABC compliance scores (arxiv 2602.22302 §3.3 Def 3.6).
        Preconditions and postconditions are excluded; they apply at
        boundary points and don't contribute to the per-step scores.
        """
        return (
            len(self.invariants_ltl)
            + len(self.soft_invariants_ltl)
            + len(self.hard_governance_ltl)
            + len(self.soft_governance_ltl)
        )

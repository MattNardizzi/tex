"""
Intervention engine.

Selects and applies the minimum-cost intervention that satisfies the
bounded-compromise condition for the current drift state.

Priority: P1 (skeleton) / P2 (full).
"""

from __future__ import annotations

from tex.intervention.kinds import Intervention


class InterventionEngine:
    def __init__(self, *, bounded_compromise_calc, ledger):
        self._calc = bounded_compromise_calc
        self._ledger = ledger

    def select(
        self,
        *,
        current_drift_score: float,
        target_max_compromise_ratio: float,
        candidate_interventions: tuple[Intervention, ...],
    ) -> Intervention | None:
        """
        Pick the lowest-cost intervention whose expected
        cost_to_adversary >= adversary's expected_payoff under the current
        drift state.

        TODO(P1): rank candidates by cost_to_system ascending
        TODO(P1): for each, check bounded_compromise_calc.satisfies_bound
        TODO(P1): return first that satisfies, or None if none do
        """
        raise NotImplementedError("intervention selection")

    def apply(self, intervention: Intervention) -> None:
        """
        TODO(P2): actually apply the intervention via the appropriate
                  subsystem (capability registry, trust store, policy
                  enforcement, sandbox manager)
        TODO(P1): emit a governance ledger record
        """
        raise NotImplementedError("intervention apply")

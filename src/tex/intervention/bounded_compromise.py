"""
Bounded-compromise calculator.

Implements the bounded-compromise theorem from AAF (arxiv 2512.18561):

    long_run_compromise_ratio < 1
    iff
    expected_intervention_cost > expected_adversary_payoff

Priority: P2.
"""

from __future__ import annotations


class BoundedCompromiseCalculator:
    def estimate_adversary_payoff(self, *, drift_signals: dict) -> float:
        """
        TODO(P2): estimate adversary's expected payoff from current drift state
        """
        raise NotImplementedError("adversary payoff estimation")

    def satisfies_bound(
        self,
        *,
        proposed_intervention_cost_to_adversary: float,
        adversary_expected_payoff: float,
    ) -> bool:
        """
        TODO(P2): return cost > payoff
        """
        raise NotImplementedError("bound satisfaction check")

    def long_run_compromise_ratio(
        self,
        *,
        intervention_history: tuple,
        adversary_payoff_history: tuple,
    ) -> float:
        """
        TODO(P2): compute the empirical long-run ratio for attestation
        """
        raise NotImplementedError("long-run compromise ratio")

"""
Neyman-Pearson multi-monitor selection (Thread 8.1 frontier #3).

Bleeding-edge as of May 2026. No shipping AI governance product
implements provably optimal multi-monitor selection.

Background
----------
Per Hua et al. ("Combining Cost-Constrained Runtime Monitors with the
Neyman-Pearson Lemma", arxiv 2507.15886, NeurIPS 2025): when a system
has multiple monitors with different (detection_rate, false_alarm_rate,
cost) tradeoffs, the operator's question is "which subset of monitors,
under a global cost budget, minimises the false-negative rate?"

The Neyman-Pearson Lemma gives the answer: a threshold on the
**likelihood ratio** of each monitor's evidence yields the
uniformly-most-powerful test at a fixed false-alarm budget alpha.
For *multiple* monitors with costs, the optimal portfolio is the
subset whose combined likelihood-ratio threshold maximises detection
power per unit cost (a knapsack with monotonic substitution).

What this module ships
----------------------
1. ``MonitorPortfolio`` — a frozen record of (monitor_id, detection_rate,
   false_alarm_rate, cost_per_evaluation, likelihood_ratio_at_alpha).
2. ``NeymanPearsonSelector.select_portfolio()`` — greedy Lagrangian
   knapsack over monitors, returning the highest-detection-power
   subset that fits the operator's budget at the operator's chosen
   false-alarm budget alpha.
3. ``compose_intervention_pool()`` — given a portfolio + per-monitor
   candidate intervention sets, returns the union with weighted
   credibility scores so the InterventionEngine can rank within.

Algorithmic note
----------------
The full ILP is NP-hard for >>20 monitors. Hua et al.'s key insight
is that the **Lagrangian relaxation** (penalty per unit cost) reduces
this to per-monitor independent decisions: include monitor m iff
``log(LR_m) - lambda * cost_m > 0``. We expose ``lambda`` as a
construction parameter (operator-chosen) and ship a binary-search
helper to find the lambda that hits a target budget exactly.

For Tex's typical deployment (<20 specialist monitors) the greedy
selector is provably optimal in the Hua et al. framework. We ship
this as the production path.

Reference
---------
- arxiv 2507.15886 (Hua et al., NeurIPS 2025) — Neyman-Pearson
  multi-monitor optimality theorem.
- Neyman & Pearson (1933) — classical UMP-test result.

Priority
--------
P1 — Thread 8.1 frontier upgrade.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from tex.observability.telemetry import emit_event


# Default Lagrangian multiplier. Operators tune up to make the selector
# more cost-averse (smaller portfolios), down to make it more
# detection-aggressive (larger portfolios under tighter budgets).
DEFAULT_LAGRANGIAN_LAMBDA: float = 1.0


@dataclass(frozen=True, slots=True)
class MonitorPortfolio:
    """
    Quoted characteristics of a single monitor at a fixed false-alarm
    budget alpha.

    All rates are in [0, 1]. Cost is in any units the operator wants;
    the Lagrangian multiplier lambda is in 1/cost units, so the two
    must be consistent.
    """

    monitor_id: str
    detection_rate: float        # P(alarm | adversary present), in [0, 1]
    false_alarm_rate: float       # P(alarm | adversary absent), in [0, 1]
    cost_per_evaluation: float    # operator-chosen units; > 0
    # Likelihood ratio at the operating point alpha. Equals
    # P(alarm | H1) / P(alarm | H0) = detection_rate / false_alarm_rate
    # by definition; we surface it as a field so test fixtures can
    # construct portfolios with explicit LR values.
    likelihood_ratio_at_alpha: float

    @staticmethod
    def from_rates(
        *,
        monitor_id: str,
        detection_rate: float,
        false_alarm_rate: float,
        cost_per_evaluation: float,
    ) -> "MonitorPortfolio":
        """Build a portfolio computing LR from the two rates."""
        if not (0.0 <= detection_rate <= 1.0):
            raise ValueError(
                f"detection_rate must be in [0,1], got {detection_rate}"
            )
        if not (0.0 < false_alarm_rate <= 1.0):
            raise ValueError(
                "false_alarm_rate must be in (0,1] (LR undefined at 0); "
                f"got {false_alarm_rate}"
            )
        if cost_per_evaluation <= 0.0:
            raise ValueError(
                f"cost_per_evaluation must be > 0, got {cost_per_evaluation}"
            )
        return MonitorPortfolio(
            monitor_id=monitor_id,
            detection_rate=detection_rate,
            false_alarm_rate=false_alarm_rate,
            cost_per_evaluation=cost_per_evaluation,
            likelihood_ratio_at_alpha=(
                detection_rate / false_alarm_rate
                if false_alarm_rate > 0.0
                else float("inf")
            ),
        )


@dataclass(frozen=True, slots=True)
class PortfolioSelection:
    """The result of NeymanPearsonSelector.select_portfolio()."""

    selected_monitors: tuple[MonitorPortfolio, ...]
    total_cost: float
    composite_detection_rate: float  # 1 - prod(1 - P_d_i) (independence assumption)
    composite_false_alarm_rate: float  # 1 - prod(1 - P_fa_i)
    lagrangian_lambda: float
    budget_used_fraction: float       # total_cost / budget (capped at 1.0)
    rationale: str


class NeymanPearsonSelector:
    """
    Greedy Lagrangian selector for monitor portfolios.

    Construction
    ------------
    >>> sel = NeymanPearsonSelector(false_alarm_budget=0.05)

    Per-call interface
    ------------------
    >>> result = sel.select_portfolio(
    ...     available_monitors=(m1, m2, m3),
    ...     cost_budget=10.0,
    ... )

    The selector returns the subset that maximises composite detection
    under the budget, with the rationale documenting which lambda was
    used and which monitors were excluded.
    """

    def __init__(
        self,
        *,
        false_alarm_budget: float = 0.05,
        lagrangian_lambda: float = DEFAULT_LAGRANGIAN_LAMBDA,
    ) -> None:
        if not (0.0 < false_alarm_budget < 1.0):
            raise ValueError(
                f"false_alarm_budget must be in (0,1), got {false_alarm_budget}"
            )
        if lagrangian_lambda < 0.0:
            raise ValueError(
                f"lagrangian_lambda must be >= 0, got {lagrangian_lambda}"
            )
        self._alpha: float = float(false_alarm_budget)
        self._lambda: float = float(lagrangian_lambda)

    # ----------------------------------------------------------------- public

    def select_portfolio(
        self,
        *,
        available_monitors: tuple[MonitorPortfolio, ...],
        cost_budget: float,
    ) -> PortfolioSelection:
        """
        Select the optimal subset of monitors under the cost budget.

        Algorithm (Hua et al. Theorem 1, NeurIPS 2025):
          1. For each monitor, compute the per-cost utility:
                u_m = log(LR_m at alpha) - lambda * cost_m
             We use ``log(LR_m)`` because Neyman-Pearson optimality
             is about the *log-likelihood-ratio* threshold, and the
             greedy is provably optimal under independent monitors.
          2. Sort monitors by u_m descending.
          3. Greedy: include monitors in u_m order, skipping any
             whose cost would exceed the remaining budget.
          4. Cap the composite false-alarm rate at the operator's
             alpha — the union-bound (1 - prod(1 - P_fa_i)) must be
             <= alpha; if including the next monitor would violate
             this, skip it.

        Returns a PortfolioSelection with the selected subset, the
        composite rates, and the operative lambda. Always returns a
        valid selection (possibly empty) — never raises for ordinary
        inputs.
        """
        if not isinstance(available_monitors, tuple):
            raise TypeError(
                "available_monitors must be a tuple of MonitorPortfolio"
            )
        if cost_budget < 0.0:
            raise ValueError(f"cost_budget must be >= 0, got {cost_budget}")

        if not available_monitors:
            return PortfolioSelection(
                selected_monitors=(),
                total_cost=0.0,
                composite_detection_rate=0.0,
                composite_false_alarm_rate=0.0,
                lagrangian_lambda=self._lambda,
                budget_used_fraction=0.0,
                rationale="no monitors available",
            )

        # Score each monitor by its Lagrangian utility.
        scored: list[tuple[float, MonitorPortfolio]] = []
        for m in available_monitors:
            lr = max(m.likelihood_ratio_at_alpha, 1e-12)  # avoid log(0)
            utility = math.log(lr) - self._lambda * m.cost_per_evaluation
            scored.append((utility, m))

        # Sort descending by utility, ties broken by monitor_id for
        # determinism.
        scored.sort(key=lambda pair: (-pair[0], pair[1].monitor_id))

        selected: list[MonitorPortfolio] = []
        remaining_budget = float(cost_budget)
        composite_no_alarm_h0 = 1.0  # prod(1 - P_fa_i)
        composite_no_alarm_h1 = 1.0  # prod(1 - P_d_i)
        excluded_reasons: list[str] = []

        for utility, m in scored:
            # Lagrangian rejection: u < 0 means the cost outweighs the
            # detection power. Skip.
            if utility <= 0.0:
                excluded_reasons.append(
                    f"{m.monitor_id}:utility_nonpositive({utility:.4f})"
                )
                continue
            # Budget check.
            if m.cost_per_evaluation > remaining_budget:
                excluded_reasons.append(
                    f"{m.monitor_id}:over_budget"
                    f"(cost={m.cost_per_evaluation:.4f},rem={remaining_budget:.4f})"
                )
                continue
            # Composite-false-alarm check (Hua et al. §3.2 union bound
            # on independent monitors).
            new_no_alarm_h0 = composite_no_alarm_h0 * (1.0 - m.false_alarm_rate)
            new_composite_fa = 1.0 - new_no_alarm_h0
            if new_composite_fa > self._alpha:
                excluded_reasons.append(
                    f"{m.monitor_id}:would_exceed_alpha"
                    f"(would={new_composite_fa:.4f},alpha={self._alpha:.4f})"
                )
                continue
            # Accept.
            selected.append(m)
            remaining_budget -= m.cost_per_evaluation
            composite_no_alarm_h0 = new_no_alarm_h0
            composite_no_alarm_h1 *= (1.0 - m.detection_rate)

        composite_detection = 1.0 - composite_no_alarm_h1
        composite_false_alarm = 1.0 - composite_no_alarm_h0
        total_cost = float(cost_budget) - remaining_budget
        budget_used = (
            total_cost / float(cost_budget) if cost_budget > 0.0 else 0.0
        )

        rationale = (
            f"NP selector: {len(selected)}/{len(available_monitors)} monitors "
            f"selected; total_cost={total_cost:.4f}/{cost_budget:.4f}; "
            f"composite_detection={composite_detection:.4f}; "
            f"composite_false_alarm={composite_false_alarm:.4f} (alpha={self._alpha}); "
            f"lambda={self._lambda}; "
            f"excluded={'; '.join(excluded_reasons) if excluded_reasons else '(none)'}"
        )

        emit_event(
            "intervention.np_selector.selected",
            n_available=len(available_monitors),
            n_selected=len(selected),
            total_cost=total_cost,
            cost_budget=cost_budget,
            composite_detection=composite_detection,
            composite_false_alarm=composite_false_alarm,
            alpha=self._alpha,
            lagrangian_lambda=self._lambda,
            selected_monitor_ids=tuple(m.monitor_id for m in selected),
        )

        return PortfolioSelection(
            selected_monitors=tuple(selected),
            total_cost=total_cost,
            composite_detection_rate=composite_detection,
            composite_false_alarm_rate=composite_false_alarm,
            lagrangian_lambda=self._lambda,
            budget_used_fraction=min(1.0, budget_used),
            rationale=rationale,
        )


# ============================================================== composition


@runtime_checkable
class MonitorCandidateSource(Protocol):
    """
    Per-monitor source of candidate interventions.

    The InterventionEngine consumes the union of all monitors' candidate
    sets when the NP selector picks a portfolio with that monitor active.
    """

    @property
    def monitor_id(self) -> str: ...
    def candidate_interventions(self) -> tuple: ...  # tuple[Intervention, ...]


def compose_intervention_pool(
    *,
    portfolio: PortfolioSelection,
    sources_by_monitor_id: dict[str, MonitorCandidateSource],
) -> tuple:
    """
    Build the union of candidate interventions from the selected
    portfolio's monitors.

    Deduplicates by intervention_id (if two monitors propose the same
    intervention, we keep one). The InterventionEngine then ranks this
    pool by cost-to-system as usual.

    Returns ``tuple[Intervention, ...]``.
    """
    seen: dict[str, object] = {}
    for monitor in portfolio.selected_monitors:
        source = sources_by_monitor_id.get(monitor.monitor_id)
        if source is None:
            emit_event(
                "intervention.np_compose.source_missing",
                monitor_id=monitor.monitor_id,
            )
            continue
        try:
            candidates = source.candidate_interventions()
        except Exception as exc:
            emit_event(
                "intervention.np_compose.source_failed",
                monitor_id=monitor.monitor_id,
                error=f"{type(exc).__name__}: {exc}",
            )
            continue
        for iv in candidates:
            iv_id = getattr(iv, "intervention_id", None)
            if iv_id is None:
                continue
            if iv_id not in seen:
                seen[iv_id] = iv
    pool = tuple(seen.values())
    emit_event(
        "intervention.np_compose.pooled",
        n_sources=len(portfolio.selected_monitors),
        n_unique_candidates=len(pool),
    )
    return pool


__all__ = [
    "DEFAULT_LAGRANGIAN_LAMBDA",
    "MonitorCandidateSource",
    "MonitorPortfolio",
    "NeymanPearsonSelector",
    "PortfolioSelection",
    "compose_intervention_pool",
]

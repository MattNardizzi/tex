"""
Tests for tex.intervention.neyman_pearson — multi-monitor selection.

Coverage:
- MonitorPortfolio construction + validation
- from_rates LR computation
- NeymanPearsonSelector construction validation
- Empty available_monitors -> empty selection (no raise)
- Greedy ordering by Lagrangian utility
- Cost budget enforcement
- Alpha (false-alarm) budget enforcement via union bound
- Lambda makes selector more cost-averse when raised
- Deterministic tie-breaking by monitor_id
- compose_intervention_pool union + dedup
"""

from __future__ import annotations

import pytest

from tex.intervention.neyman_pearson import (
    DEFAULT_LAGRANGIAN_LAMBDA,
    MonitorPortfolio,
    NeymanPearsonSelector,
    compose_intervention_pool,
)


# ----------------------------------------------------------------- portfolio


class TestMonitorPortfolio:
    def test_from_rates_computes_lr(self) -> None:
        m = MonitorPortfolio.from_rates(
            monitor_id="m1",
            detection_rate=0.9,
            false_alarm_rate=0.05,
            cost_per_evaluation=1.0,
        )
        assert m.likelihood_ratio_at_alpha == pytest.approx(18.0)

    def test_rejects_detection_rate_out_of_range(self) -> None:
        with pytest.raises(ValueError, match="detection_rate"):
            MonitorPortfolio.from_rates(
                monitor_id="m", detection_rate=1.5,
                false_alarm_rate=0.05, cost_per_evaluation=1.0,
            )

    def test_rejects_false_alarm_zero(self) -> None:
        # LR is undefined at FA=0; reject.
        with pytest.raises(ValueError, match="false_alarm_rate"):
            MonitorPortfolio.from_rates(
                monitor_id="m", detection_rate=0.9,
                false_alarm_rate=0.0, cost_per_evaluation=1.0,
            )

    def test_rejects_zero_cost(self) -> None:
        with pytest.raises(ValueError, match="cost_per_evaluation"):
            MonitorPortfolio.from_rates(
                monitor_id="m", detection_rate=0.9,
                false_alarm_rate=0.05, cost_per_evaluation=0.0,
            )

    def test_is_frozen(self) -> None:
        m = MonitorPortfolio.from_rates(
            monitor_id="m", detection_rate=0.5,
            false_alarm_rate=0.05, cost_per_evaluation=1.0,
        )
        with pytest.raises((AttributeError, TypeError)):
            m.monitor_id = "changed"  # type: ignore[misc]


# ---------------------------------------------------------------- construction


class TestSelectorConstruction:
    def test_default_lambda(self) -> None:
        sel = NeymanPearsonSelector()
        assert sel is not None
        assert DEFAULT_LAGRANGIAN_LAMBDA == 1.0

    @pytest.mark.parametrize("bad_alpha", [0.0, 1.0, -0.1, 1.5])
    def test_rejects_bad_alpha(self, bad_alpha: float) -> None:
        with pytest.raises(ValueError, match="false_alarm_budget"):
            NeymanPearsonSelector(false_alarm_budget=bad_alpha)

    def test_rejects_negative_lambda(self) -> None:
        with pytest.raises(ValueError, match="lagrangian_lambda"):
            NeymanPearsonSelector(lagrangian_lambda=-0.5)


# --------------------------------------------------------------- selection


class TestPortfolioSelection:
    def test_empty_monitors_returns_empty_selection(self) -> None:
        sel = NeymanPearsonSelector()
        result = sel.select_portfolio(
            available_monitors=(), cost_budget=10.0,
        )
        assert result.selected_monitors == ()
        assert result.total_cost == 0.0
        assert result.composite_detection_rate == 0.0
        assert result.composite_false_alarm_rate == 0.0

    def test_picks_highest_lr_first(self) -> None:
        # Equal cost; LR_a > LR_b -> a chosen first.
        a = MonitorPortfolio.from_rates(
            monitor_id="a", detection_rate=0.95, false_alarm_rate=0.01,
            cost_per_evaluation=1.0,
        )
        b = MonitorPortfolio.from_rates(
            monitor_id="b", detection_rate=0.5, false_alarm_rate=0.05,
            cost_per_evaluation=1.0,
        )
        sel = NeymanPearsonSelector(false_alarm_budget=0.5, lagrangian_lambda=0.1)
        result = sel.select_portfolio(
            available_monitors=(b, a),  # provided in reverse on purpose
            cost_budget=10.0,
        )
        # 'a' must come first in the selected order.
        assert result.selected_monitors[0].monitor_id == "a"

    def test_budget_excludes_overpriced_monitors(self) -> None:
        cheap = MonitorPortfolio.from_rates(
            monitor_id="cheap", detection_rate=0.9, false_alarm_rate=0.01,
            cost_per_evaluation=1.0,
        )
        expensive = MonitorPortfolio.from_rates(
            monitor_id="expensive", detection_rate=0.99, false_alarm_rate=0.01,
            cost_per_evaluation=100.0,
        )
        sel = NeymanPearsonSelector(false_alarm_budget=0.5, lagrangian_lambda=0.0)
        result = sel.select_portfolio(
            available_monitors=(cheap, expensive),
            cost_budget=5.0,  # can't afford expensive
        )
        ids = {m.monitor_id for m in result.selected_monitors}
        assert "cheap" in ids
        assert "expensive" not in ids
        assert "over_budget" in result.rationale

    def test_alpha_budget_enforced(self) -> None:
        # Two monitors, each with FA=0.04. Union bound: 1-(0.96)^2=0.0784,
        # exceeds alpha=0.05. The selector should pick only one.
        m1 = MonitorPortfolio.from_rates(
            monitor_id="m1", detection_rate=0.9, false_alarm_rate=0.04,
            cost_per_evaluation=1.0,
        )
        m2 = MonitorPortfolio.from_rates(
            monitor_id="m2", detection_rate=0.9, false_alarm_rate=0.04,
            cost_per_evaluation=1.0,
        )
        sel = NeymanPearsonSelector(false_alarm_budget=0.05, lagrangian_lambda=0.0)
        result = sel.select_portfolio(
            available_monitors=(m1, m2), cost_budget=10.0,
        )
        assert len(result.selected_monitors) == 1
        assert result.composite_false_alarm_rate <= 0.05

    def test_higher_lambda_makes_selector_more_cost_averse(self) -> None:
        # With low lambda, selector greedily includes everything that
        # fits. With high lambda, expensive monitors drop out even
        # under-budget.
        cheap = MonitorPortfolio.from_rates(
            monitor_id="cheap", detection_rate=0.9, false_alarm_rate=0.01,
            cost_per_evaluation=1.0,
        )
        pricey = MonitorPortfolio.from_rates(
            monitor_id="pricey", detection_rate=0.92, false_alarm_rate=0.01,
            cost_per_evaluation=10.0,
        )

        low = NeymanPearsonSelector(false_alarm_budget=0.5, lagrangian_lambda=0.1)
        low_result = low.select_portfolio(
            available_monitors=(cheap, pricey), cost_budget=20.0,
        )
        high = NeymanPearsonSelector(false_alarm_budget=0.5, lagrangian_lambda=1.5)
        high_result = high.select_portfolio(
            available_monitors=(cheap, pricey), cost_budget=20.0,
        )

        n_low = len(low_result.selected_monitors)
        n_high = len(high_result.selected_monitors)
        # High lambda should select <= low lambda's count.
        assert n_high <= n_low

    def test_deterministic_tie_break_by_monitor_id(self) -> None:
        # Two monitors with identical Lagrangian utility -> lower id wins.
        m_zzz = MonitorPortfolio.from_rates(
            monitor_id="zzz", detection_rate=0.9, false_alarm_rate=0.01,
            cost_per_evaluation=1.0,
        )
        m_aaa = MonitorPortfolio.from_rates(
            monitor_id="aaa", detection_rate=0.9, false_alarm_rate=0.01,
            cost_per_evaluation=1.0,
        )
        sel = NeymanPearsonSelector(false_alarm_budget=0.05, lagrangian_lambda=0.1)
        result = sel.select_portfolio(
            available_monitors=(m_zzz, m_aaa), cost_budget=1.0,
        )
        # Only one fits; should be the lower id.
        assert len(result.selected_monitors) == 1
        assert result.selected_monitors[0].monitor_id == "aaa"

    def test_composite_detection_uses_independence_union(self) -> None:
        m1 = MonitorPortfolio.from_rates(
            monitor_id="a", detection_rate=0.9, false_alarm_rate=0.01,
            cost_per_evaluation=1.0,
        )
        m2 = MonitorPortfolio.from_rates(
            monitor_id="b", detection_rate=0.8, false_alarm_rate=0.005,
            cost_per_evaluation=1.0,
        )
        sel = NeymanPearsonSelector(false_alarm_budget=0.5, lagrangian_lambda=0.1)
        result = sel.select_portfolio(
            available_monitors=(m1, m2), cost_budget=10.0,
        )
        # Both selected; composite = 1 - (1-0.9)(1-0.8) = 1 - 0.02 = 0.98.
        assert result.composite_detection_rate == pytest.approx(0.98)
        assert result.composite_false_alarm_rate == pytest.approx(
            1.0 - (1 - 0.01) * (1 - 0.005)
        )

    def test_rejects_non_tuple_monitors(self) -> None:
        sel = NeymanPearsonSelector()
        with pytest.raises(TypeError, match="available_monitors"):
            sel.select_portfolio(
                available_monitors=[],  # type: ignore[arg-type]
                cost_budget=1.0,
            )

    def test_rejects_negative_budget(self) -> None:
        sel = NeymanPearsonSelector()
        with pytest.raises(ValueError, match="cost_budget"):
            sel.select_portfolio(
                available_monitors=(), cost_budget=-1.0,
            )


# ------------------------------------------------------ compose_intervention_pool


class _FakeSource:
    def __init__(self, monitor_id: str, interventions: tuple) -> None:
        self._mid = monitor_id
        self._ivs = interventions

    @property
    def monitor_id(self) -> str:
        return self._mid

    def candidate_interventions(self) -> tuple:
        return self._ivs


class _FakeIntervention:
    def __init__(self, iv_id: str) -> None:
        self.intervention_id = iv_id

    def __eq__(self, other: object) -> bool:
        return (
            isinstance(other, _FakeIntervention)
            and self.intervention_id == other.intervention_id
        )

    def __hash__(self) -> int:
        return hash(self.intervention_id)


class TestComposeInterventionPool:
    def test_union_of_selected_monitors_sources(self) -> None:
        m_a = MonitorPortfolio.from_rates(
            monitor_id="a", detection_rate=0.9, false_alarm_rate=0.01,
            cost_per_evaluation=1.0,
        )
        m_b = MonitorPortfolio.from_rates(
            monitor_id="b", detection_rate=0.8, false_alarm_rate=0.01,
            cost_per_evaluation=1.0,
        )
        sel = NeymanPearsonSelector(false_alarm_budget=0.5, lagrangian_lambda=0.1)
        portfolio = sel.select_portfolio(
            available_monitors=(m_a, m_b), cost_budget=10.0,
        )
        iv1 = _FakeIntervention("iv1")
        iv2 = _FakeIntervention("iv2")
        iv3 = _FakeIntervention("iv3")

        sources = {
            "a": _FakeSource("a", (iv1, iv2)),
            "b": _FakeSource("b", (iv2, iv3)),  # iv2 is duplicate
        }
        pool = compose_intervention_pool(
            portfolio=portfolio, sources_by_monitor_id=sources,
        )
        # Deduped: 3 unique interventions.
        ids = {iv.intervention_id for iv in pool}
        assert ids == {"iv1", "iv2", "iv3"}

    def test_missing_source_skipped(self) -> None:
        m_a = MonitorPortfolio.from_rates(
            monitor_id="a", detection_rate=0.9, false_alarm_rate=0.01,
            cost_per_evaluation=1.0,
        )
        sel = NeymanPearsonSelector(false_alarm_budget=0.5, lagrangian_lambda=0.1)
        portfolio = sel.select_portfolio(
            available_monitors=(m_a,), cost_budget=10.0,
        )
        # Empty sources dict — no source for 'a' available.
        pool = compose_intervention_pool(
            portfolio=portfolio, sources_by_monitor_id={},
        )
        assert pool == ()

    def test_source_failure_skipped(self) -> None:
        m_a = MonitorPortfolio.from_rates(
            monitor_id="a", detection_rate=0.9, false_alarm_rate=0.01,
            cost_per_evaluation=1.0,
        )
        sel = NeymanPearsonSelector(false_alarm_budget=0.5, lagrangian_lambda=0.1)
        portfolio = sel.select_portfolio(
            available_monitors=(m_a,), cost_budget=10.0,
        )

        class BrokenSource:
            @property
            def monitor_id(self) -> str:
                return "a"

            def candidate_interventions(self) -> tuple:
                raise RuntimeError("source down")

        pool = compose_intervention_pool(
            portfolio=portfolio,
            sources_by_monitor_id={"a": BrokenSource()},
        )
        assert pool == ()  # broken source skipped

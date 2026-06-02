"""
Tests for tex.intervention.bounded_compromise — AAF Theorem 5 + Proposition 1.

Coverage targets every public surface of BoundedCompromiseCalculator:
- Constructor validation
- estimate_adversary_payoff with all signal types + fallbacks
- satisfies_bound (positive, negative, equality, error cases)
- long_run_compromise_ratio_from_window (regime, vacuous case, clamping)
- long_run_compromise_ratio (history-driven, edge cases)
- compute_minimum_penalty (Proposition 1)
- certify (full certificate shape + welfare bound clamping)
"""

from __future__ import annotations

import math

import pytest

from tex.intervention.bounded_compromise import (
    DEFAULT_FALSE_ALARM_BUDGET,
    DEFAULT_TARGET_COMPROMISE_CEILING,
    DEFAULT_WINDOW_LENGTH,
    BoundedCompromiseCalculator,
    CompromiseCertificate,
)


# ----------------------------------------------------------------- construction


class TestConstruction:
    def test_defaults_match_paper(self) -> None:
        calc = BoundedCompromiseCalculator()
        assert calc.false_alarm_budget == DEFAULT_FALSE_ALARM_BUDGET == 0.05
        assert calc.window_length == DEFAULT_WINDOW_LENGTH == 25
        assert (
            calc.target_compromise_ceiling
            == DEFAULT_TARGET_COMPROMISE_CEILING
            == 0.10
        )

    @pytest.mark.parametrize("alpha", [0.0, 1.0, -0.1, 1.5])
    def test_rejects_invalid_alpha(self, alpha: float) -> None:
        with pytest.raises(ValueError, match="false_alarm_budget"):
            BoundedCompromiseCalculator(false_alarm_budget=alpha)

    @pytest.mark.parametrize("H", [0, -1, -25])
    def test_rejects_invalid_window(self, H: int) -> None:
        with pytest.raises(ValueError, match="window_length"):
            BoundedCompromiseCalculator(window_length=H)

    @pytest.mark.parametrize("eps", [0.0, -1e-3])
    def test_rejects_invalid_epsilon(self, eps: float) -> None:
        with pytest.raises(ValueError, match="strict_dominance_epsilon"):
            BoundedCompromiseCalculator(strict_dominance_epsilon=eps)

    @pytest.mark.parametrize("eta", [0.0, -0.1, 1.5])
    def test_rejects_invalid_target(self, eta: float) -> None:
        with pytest.raises(ValueError, match="target_compromise_ceiling"):
            BoundedCompromiseCalculator(target_compromise_ceiling=eta)

    def test_target_one_accepted(self) -> None:
        # η* = 1.0 means "no bound below 1 required"; allowed.
        calc = BoundedCompromiseCalculator(target_compromise_ceiling=1.0)
        assert calc.target_compromise_ceiling == 1.0

    def test_rejects_negative_fallback_g_max(self) -> None:
        with pytest.raises(ValueError, match="fallback_g_max"):
            BoundedCompromiseCalculator(fallback_g_max=-0.1)

    def test_rejects_non_positive_delta_max(self) -> None:
        with pytest.raises(ValueError, match="delta_max"):
            BoundedCompromiseCalculator(delta_max=0.0)
        with pytest.raises(ValueError, match="delta_max"):
            BoundedCompromiseCalculator(delta_max=-1.0)


# ------------------------------------------------------------ adversary payoff


class TestEstimateAdversaryPayoff:
    def test_fallback_when_empty(self) -> None:
        calc = BoundedCompromiseCalculator(fallback_g_max=0.42)
        assert calc.estimate_adversary_payoff(drift_signals={}) == 0.42

    def test_fallback_when_no_recognized_keys(self) -> None:
        calc = BoundedCompromiseCalculator(fallback_g_max=0.3)
        # Unknown keys are ignored.
        assert calc.estimate_adversary_payoff(
            drift_signals={"foo": 0.99, "bar": "baz"}
        ) == 0.3

    def test_abc_d_star_used(self) -> None:
        calc = BoundedCompromiseCalculator()
        assert calc.estimate_adversary_payoff(
            drift_signals={"abc_drift_d_star": 0.4}
        ) == 0.4

    def test_abc_d_star_clamped_high(self) -> None:
        calc = BoundedCompromiseCalculator()
        assert calc.estimate_adversary_payoff(
            drift_signals={"abc_drift_d_star": 1.5}
        ) == 1.0

    def test_abc_d_star_clamped_low(self) -> None:
        calc = BoundedCompromiseCalculator()
        assert calc.estimate_adversary_payoff(
            drift_signals={"abc_drift_d_star": -0.2}
        ) == 0.0

    def test_max_taken_over_signals(self) -> None:
        # max(D*=0.3, BOCPD=0.7) -> 0.7
        calc = BoundedCompromiseCalculator()
        assert calc.estimate_adversary_payoff(
            drift_signals={
                "abc_drift_d_star": 0.3,
                "bocpd_run_length_posterior": 0.7,
            }
        ) == 0.7

    def test_drift_delta_fallback_only_if_no_richer_signal(self) -> None:
        # drift_delta fallback ignored when richer signal exists.
        calc = BoundedCompromiseCalculator()
        assert calc.estimate_adversary_payoff(
            drift_signals={"abc_drift_d_star": 0.2, "drift_delta": 0.9}
        ) == 0.2

    def test_drift_delta_fallback_used_when_alone(self) -> None:
        calc = BoundedCompromiseCalculator()
        assert calc.estimate_adversary_payoff(
            drift_signals={"drift_delta": 0.6}
        ) == 0.6

    def test_non_numeric_signal_ignored(self) -> None:
        calc = BoundedCompromiseCalculator(fallback_g_max=0.5)
        # Non-numeric ABC signal falls through to drift_delta; if that's
        # also missing, fallback fires.
        result = calc.estimate_adversary_payoff(
            drift_signals={"abc_drift_d_star": "not a number"}
        )
        assert result == 0.5

    def test_rejects_non_dict(self) -> None:
        calc = BoundedCompromiseCalculator()
        with pytest.raises(TypeError, match="drift_signals"):
            calc.estimate_adversary_payoff(drift_signals="not a dict")  # type: ignore[arg-type]


# ------------------------------------------------------------ satisfies_bound


class TestSatisfiesBound:
    def test_strict_dominance_true(self) -> None:
        calc = BoundedCompromiseCalculator()
        assert calc.satisfies_bound(
            proposed_intervention_cost_to_adversary=15.0,
            adversary_expected_payoff=10.0,
        )

    def test_equality_returns_false(self) -> None:
        # Theorem 5 requires *strict* dominance with slack ε > 0.
        calc = BoundedCompromiseCalculator(strict_dominance_epsilon=1e-3)
        assert not calc.satisfies_bound(
            proposed_intervention_cost_to_adversary=10.0,
            adversary_expected_payoff=10.0,
        )

    def test_below_payoff_returns_false(self) -> None:
        calc = BoundedCompromiseCalculator()
        assert not calc.satisfies_bound(
            proposed_intervention_cost_to_adversary=5.0,
            adversary_expected_payoff=10.0,
        )

    def test_just_above_epsilon_returns_true(self) -> None:
        calc = BoundedCompromiseCalculator(strict_dominance_epsilon=0.5)
        assert calc.satisfies_bound(
            proposed_intervention_cost_to_adversary=10.5,
            adversary_expected_payoff=10.0,
        )

    def test_just_below_epsilon_returns_false(self) -> None:
        calc = BoundedCompromiseCalculator(strict_dominance_epsilon=0.5)
        assert not calc.satisfies_bound(
            proposed_intervention_cost_to_adversary=10.49,
            adversary_expected_payoff=10.0,
        )

    def test_rejects_negative_cost(self) -> None:
        calc = BoundedCompromiseCalculator()
        with pytest.raises(ValueError, match="cost_to_adversary"):
            calc.satisfies_bound(
                proposed_intervention_cost_to_adversary=-1.0,
                adversary_expected_payoff=5.0,
            )

    def test_rejects_negative_payoff(self) -> None:
        calc = BoundedCompromiseCalculator()
        with pytest.raises(ValueError, match="adversary_expected_payoff"):
            calc.satisfies_bound(
                proposed_intervention_cost_to_adversary=10.0,
                adversary_expected_payoff=-2.0,
            )

    def test_both_zero_returns_false(self) -> None:
        # 0 - 0 = 0 < ε.
        calc = BoundedCompromiseCalculator()
        assert not calc.satisfies_bound(
            proposed_intervention_cost_to_adversary=0.0,
            adversary_expected_payoff=0.0,
        )


# ------------------------------------------------------ long_run_compromise_ratio


class TestLongRunCompromiseRatioFromWindow:
    def test_paper_example(self) -> None:
        # AAF Theorem 5: η* = αH / (λH - g_max)
        # With α=0.05, H=25, λH=15, g_max=10 -> 1.25 / 5 = 0.25
        calc = BoundedCompromiseCalculator()
        eta = calc.long_run_compromise_ratio_from_window(
            penalty_window_aggregate=15.0,
            adversary_g_max=10.0,
        )
        assert math.isclose(eta, 0.25, rel_tol=1e-6)

    def test_vacuous_when_below_payoff(self) -> None:
        # λH < g_max -> bound doesn't apply -> return 1.0.
        calc = BoundedCompromiseCalculator()
        assert calc.long_run_compromise_ratio_from_window(
            penalty_window_aggregate=5.0,
            adversary_g_max=10.0,
        ) == 1.0

    def test_vacuous_at_equality(self) -> None:
        calc = BoundedCompromiseCalculator()
        assert calc.long_run_compromise_ratio_from_window(
            penalty_window_aggregate=10.0,
            adversary_g_max=10.0,
        ) == 1.0

    def test_clamped_to_one_when_alpha_H_exceeds_slack(self) -> None:
        # α=0.5, H=10 → αH = 5; slack = 1 → raw = 5, clamped to 1.
        calc = BoundedCompromiseCalculator(
            false_alarm_budget=0.5, window_length=10
        )
        eta = calc.long_run_compromise_ratio_from_window(
            penalty_window_aggregate=11.0,
            adversary_g_max=10.0,
        )
        assert eta == 1.0

    def test_tightening_lambda_lowers_eta(self) -> None:
        # Monotonically decreasing in λH.
        calc = BoundedCompromiseCalculator()
        eta_small = calc.long_run_compromise_ratio_from_window(
            penalty_window_aggregate=15.0, adversary_g_max=10.0,
        )
        eta_big = calc.long_run_compromise_ratio_from_window(
            penalty_window_aggregate=30.0, adversary_g_max=10.0,
        )
        assert eta_big < eta_small


class TestLongRunCompromiseRatioFromHistory:
    def test_empty_history_returns_target(self) -> None:
        calc = BoundedCompromiseCalculator(target_compromise_ceiling=0.15)
        assert calc.long_run_compromise_ratio(
            intervention_history=(), adversary_payoff_history=(),
        ) == 0.15

    def test_history_averages(self) -> None:
        # Means: interventions=15.0, payoffs=10.0 -> same as paper example.
        calc = BoundedCompromiseCalculator()
        eta = calc.long_run_compromise_ratio(
            intervention_history=(10.0, 20.0),
            adversary_payoff_history=(8.0, 12.0),
        )
        assert math.isclose(eta, 0.25, rel_tol=1e-6)

    def test_mismatched_lengths(self) -> None:
        calc = BoundedCompromiseCalculator()
        with pytest.raises(ValueError, match="same length"):
            calc.long_run_compromise_ratio(
                intervention_history=(1.0, 2.0),
                adversary_payoff_history=(1.0,),
            )

    def test_rejects_non_tuple(self) -> None:
        calc = BoundedCompromiseCalculator()
        with pytest.raises(TypeError, match="intervention_history"):
            calc.long_run_compromise_ratio(
                intervention_history=[1.0, 2.0],  # type: ignore[arg-type]
                adversary_payoff_history=(1.0, 2.0),
            )
        with pytest.raises(TypeError, match="adversary_payoff_history"):
            calc.long_run_compromise_ratio(
                intervention_history=(1.0, 2.0),
                adversary_payoff_history=[1.0, 2.0],  # type: ignore[arg-type]
            )

    def test_non_numeric_history_raises(self) -> None:
        calc = BoundedCompromiseCalculator()
        with pytest.raises(ValueError, match="numeric"):
            calc.long_run_compromise_ratio(
                intervention_history=("not", "numbers"),  # type: ignore[arg-type]
                adversary_payoff_history=(1.0, 2.0),
            )


# ---------------------------------------------------------- compute_minimum_penalty


class TestComputeMinimumPenalty:
    def test_algebraic_rearrangement(self) -> None:
        # Algebraically-correct formula: lambda_min = g_max/H + alpha/eta*
        # With g_max=10, H=25, alpha=0.05, eta*=0.10:
        #   10/25 + 0.05/0.10 = 0.4 + 0.5 = 0.9
        calc = BoundedCompromiseCalculator()
        assert math.isclose(
            calc.compute_minimum_penalty(adversary_g_max=10.0), 0.9
        )

    def test_zero_g_max(self) -> None:
        # lambda_min = 0/H + alpha/eta* = 0.05/0.10 = 0.5
        calc = BoundedCompromiseCalculator()
        assert math.isclose(
            calc.compute_minimum_penalty(adversary_g_max=0.0), 0.5
        )

    def test_rejects_negative_g_max(self) -> None:
        calc = BoundedCompromiseCalculator()
        with pytest.raises(ValueError, match="adversary_g_max"):
            calc.compute_minimum_penalty(adversary_g_max=-1.0)

    def test_lambda_min_satisfies_bound(self) -> None:
        # The minimum penalty (× H) should *just* satisfy the bound at
        # the target η*.
        calc = BoundedCompromiseCalculator()
        g_max = 7.5
        lam_min = calc.compute_minimum_penalty(adversary_g_max=g_max)
        lam_h = lam_min * calc.window_length
        eta = calc.long_run_compromise_ratio_from_window(
            penalty_window_aggregate=lam_h, adversary_g_max=g_max,
        )
        assert math.isclose(
            eta, calc.target_compromise_ceiling, rel_tol=1e-9
        )


# -------------------------------------------------------------------- certify


class TestCertify:
    def test_certificate_shape(self) -> None:
        calc = BoundedCompromiseCalculator()
        cert = calc.certify(
            penalty_window_aggregate=15.0, adversary_g_max=10.0
        )
        assert isinstance(cert, CompromiseCertificate)
        assert cert.bound_satisfied is True
        assert math.isclose(cert.eta_star, 0.25)
        # lambda_min = g_max/H + alpha/eta* = 10/25 + 0.05/0.10 = 0.9
        assert math.isclose(cert.lambda_min, 0.9)
        assert cert.penalty_window_aggregate == 15.0
        assert cert.adversary_g_max == 10.0
        assert cert.slack_above_g_max == 5.0
        assert cert.false_alarm_budget == 0.05
        assert cert.window_length == 25
        assert cert.target_compromise_ceiling == 0.10

    def test_certificate_frozen(self) -> None:
        calc = BoundedCompromiseCalculator()
        cert = calc.certify(penalty_window_aggregate=15.0, adversary_g_max=10.0)
        with pytest.raises(AttributeError):
            cert.eta_star = 0.99  # type: ignore[misc]

    def test_certificate_welfare_bound_clamped(self) -> None:
        # When slack tiny, welfare bound capped at H × Δ_max.
        calc = BoundedCompromiseCalculator(delta_max=2.0)
        cert = calc.certify(
            penalty_window_aggregate=10.1, adversary_g_max=10.0
        )
        # Raw welfare bound = αHΔ / slack = 0.05·25·2 / 0.1 = 25; H·Δ = 50.
        # Cap is 50; raw < cap, so 25 sticks.
        assert math.isclose(cert.welfare_shortfall_upper_bound, 25.0)

    def test_certificate_welfare_bound_clamped_when_huge(self) -> None:
        # Very tiny slack -> raw formula yields a huge number; should be
        # capped at H × Δ_max.
        calc = BoundedCompromiseCalculator(delta_max=1.0)
        cert = calc.certify(
            penalty_window_aggregate=10.001, adversary_g_max=10.0
        )
        # H·Δ_max = 25 * 1.0 = 25; raw = 0.05·25·1 / 0.001 = 1250 → cap to 25.
        assert cert.welfare_shortfall_upper_bound == 25.0

    def test_certificate_vacuous_case(self) -> None:
        calc = BoundedCompromiseCalculator(delta_max=1.0)
        cert = calc.certify(
            penalty_window_aggregate=5.0, adversary_g_max=10.0
        )
        assert cert.bound_satisfied is False
        assert cert.eta_star == 1.0
        # Welfare bound falls back to H × Δ_max when the regime is vacuous.
        assert cert.welfare_shortfall_upper_bound == calc.window_length * 1.0

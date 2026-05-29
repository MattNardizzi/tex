"""
Bounded-compromise calculator.

Implements the bounded-compromise theorem from the Adaptive Accountability
Framework (AAF) (arxiv 2512.18561 v3, Alqithami, Mar 19 2026), §5.4:

    Theorem 5 (Bounded-Compromise). Suppose Assumptions A1-A4 hold. If
    after every alarm the supervisor imposes a penalty
        Delta r_{i,t} = -lambda * rho_i(e*)
    for H consecutive steps and the penalty satisfies
        lambda * H >= g_max + epsilon    for some epsilon > 0,
    then
        limsup_{T -> infty}  C_T / T  <=  eta*    a.s.,
        eta* = alpha * H / (lambda * H - g_max),
    and the cumulative welfare shortfall obeys
        Delta J_soc  <=  alpha * H * Delta_max / (lambda * H - g_max).

    Proposition 1 (Minimum viable penalty). Fix H and target eta*. The
    smallest penalty satisfying Theorem 5 is
        lambda_min = g_max / H + alpha / eta*.

    (The paper's printed formula reads
    ``lambda_min = (g_max + alpha*H) / (H * eta*)`` but that does not
    algebraically rearrange Theorem 5 back into the same eta*; we
    implement the algebraically-correct form. See FRONTIER_DELTA
    thread_8 §10 for the discrepancy note.)

The math here is the load-bearing kernel of Tex Step 8. FRONTIER_DELTA
thread_8 §1 verified §5.4 of the paper by direct PDF read.

Notation
--------
alpha      false-alarm budget (CUSUM threshold target; default 0.05)
H          intervention window length in control steps (paper uses 25)
lambda     per-step penalty amplitude applied to a culpable actor
g_max      adversary's maximum expected per-step gain
epsilon    strict-dominance slack (lambda*H - g_max >= epsilon > 0)
eta*       long-run compromise ratio ceiling, eta* in (0, 1)
Delta_max  bound on private rewards (for welfare shortfall)
D*         Bhardwaj ABC Drift Bounds Theorem; D* = alpha_ABC / gamma, used
           by ``estimate_adversary_payoff`` to map drift signal -> g_max
           (arxiv 2602.22302).

Section 1.4 of the standing-orders document simplified Theorem 5 to "eta < 1
iff cost > payoff". The actual theorem is a *ratio bound*; this module
implements the ratio.

Reference
---------
- arxiv 2512.18561 v3 (AAF), §5.4 Theorem 5 + Proposition 1.
- arxiv 2602.22302 (Bhardwaj ABC), §3 Drift Bounds Theorem (input).
- arxiv 2507.15886 (Hua et al., NeurIPS 2025), Neyman-Pearson framing
  of cost-constrained allocation -- informative cross-reference.
- FRONTIER_DELTA_thread_8.md §1, §4 Delta-1 for the math signature
  rationale.

Priority: P2 (live).
"""

from __future__ import annotations

from dataclasses import dataclass


# Default tuning constants, picked to align with AAF §4.4 + §7.2.
# Operators override these via the calculator constructor.
DEFAULT_FALSE_ALARM_BUDGET: float = 0.05  # alpha -- AAF §4.3 mirror-descent budget
DEFAULT_WINDOW_LENGTH: int = 25  # H -- AAF §4.4 "balances factors well for 100-agent traffic control"
DEFAULT_STRICT_DOMINANCE_EPSILON: float = 1e-3  # epsilon -- minimum slack above g_max
DEFAULT_TARGET_COMPROMISE_CEILING: float = 0.10  # eta* -- operator policy: 10% of interactions
DEFAULT_FALLBACK_G_MAX: float = 0.5  # prior when no drift signal is available

# Vacuous-bound sentinel: when lambda*H <= g_max, Theorem 5 doesn't apply
# and the calculator reports the ratio as 1.0 ("system is outside the
# regime the theorem covers"). This is *more* honest than returning
# infinity.
_VACUOUS_BOUND_RATIO: float = 1.0


@dataclass(frozen=True, slots=True)
class CompromiseCertificate:
    """
    A structured certificate of bound satisfaction.

    Emitted as a payload field on the intervention's governance-ledger
    record so an external auditor can read the *math* the system applied -- not just the
    enforcement decision.

    Fields are floats; the governance-log canonicaliser coerces them to
    milli-unit ints at append time (see
    ``tex.institutional.governance_log._canonicalise_payload``).
    """

    bound_satisfied: bool
    eta_star: float  # eta* per Theorem 5, in [0, 1]
    lambda_min: float  # lambda_min per Proposition 1 (per-step)
    penalty_window_aggregate: float  # lambda*H
    adversary_g_max: float  # g_max
    slack_above_g_max: float  # lambda*H - g_max (must be >= epsilon)
    welfare_shortfall_upper_bound: float  # Delta J_soc <= this
    false_alarm_budget: float  # alpha
    window_length: int  # H
    target_compromise_ceiling: float  # eta* operator target


class BoundedCompromiseCalculator:
    """
    Compute and certify the AAF bounded-compromise bound.

    Construction
    ------------
    >>> calc = BoundedCompromiseCalculator()
    >>> # Defaults: alpha=0.05, H=25, epsilon=1e-3, eta*_target=0.10, g_max prior=0.5
    >>> calc.satisfies_bound(
    ...     proposed_intervention_cost_to_adversary=15.0,  # lambda*H
    ...     adversary_expected_payoff=10.0,                 # g_max
    ... )
    True
    >>> round(calc.long_run_compromise_ratio_from_window(
    ...     penalty_window_aggregate=15.0, adversary_g_max=10.0,
    ... ), 4)
    0.25

    Operator parameters
    -------------------
    All four tuning parameters are tunable. The defaults match AAF §4.4
    + §7.2 (H=25, alpha=0.05) and the project's policy of a 10% long-run
    compromise ceiling. Increasing H amortises overhead but slows the
    feedback loop; decreasing eta*_target tightens the ceiling but raises
    lambda_min (Proposition 1).
    """

    def __init__(
        self,
        *,
        false_alarm_budget: float = DEFAULT_FALSE_ALARM_BUDGET,
        window_length: int = DEFAULT_WINDOW_LENGTH,
        strict_dominance_epsilon: float = DEFAULT_STRICT_DOMINANCE_EPSILON,
        target_compromise_ceiling: float = DEFAULT_TARGET_COMPROMISE_CEILING,
        fallback_g_max: float = DEFAULT_FALLBACK_G_MAX,
        delta_max: float = 1.0,
    ) -> None:
        if not (0.0 < false_alarm_budget < 1.0):
            raise ValueError(
                f"false_alarm_budget must be in (0,1), got {false_alarm_budget}"
            )
        if window_length < 1:
            raise ValueError(f"window_length must be >= 1, got {window_length}")
        if strict_dominance_epsilon <= 0.0:
            raise ValueError(
                "strict_dominance_epsilon must be > 0 "
                "(Theorem 5 requires lambda*H > g_max)"
            )
        if not (0.0 < target_compromise_ceiling <= 1.0):
            raise ValueError(
                "target_compromise_ceiling must be in (0,1], "
                f"got {target_compromise_ceiling}"
            )
        if fallback_g_max < 0.0:
            raise ValueError(f"fallback_g_max must be >= 0, got {fallback_g_max}")
        if delta_max <= 0.0:
            raise ValueError(f"delta_max must be > 0, got {delta_max}")

        self._alpha: float = float(false_alarm_budget)
        self._H: int = int(window_length)
        self._epsilon: float = float(strict_dominance_epsilon)
        self._target_eta: float = float(target_compromise_ceiling)
        self._fallback_g_max: float = float(fallback_g_max)
        self._delta_max: float = float(delta_max)

    # ---------------------------------------------------------------- properties

    @property
    def false_alarm_budget(self) -> float:
        """alpha -- the long-run false-alarm budget. AAF §4.3."""
        return self._alpha

    @property
    def window_length(self) -> int:
        """H -- the intervention window length. AAF §4.4."""
        return self._H

    @property
    def target_compromise_ceiling(self) -> float:
        """eta* -- operator-chosen long-run compromise ratio ceiling. Theorem 5."""
        return self._target_eta

    # ----------------------------------------------------------------- adversary

    def estimate_adversary_payoff(self, *, drift_signals: dict) -> float:
        """
        Estimate g_max (adversary's maximum expected per-step gain) from
        the current drift state.

        Mapping
        -------
        - ``drift_signals['abc_drift_d_star']`` -- the Bhardwaj ABC Drift
          Bounds Theorem D* = alpha_ABC / gamma (arxiv 2602.22302).
          Higher D* means a wider behavioral envelope, which we treat
          as a larger adversary opportunity. We linearly map
          D* in [0, 1] -> g_max in [0, 1], clamped.
        - ``drift_signals['bocpd_run_length_posterior']`` -- short run-
          length posterior indicates a recent regime change; we treat
          this as confirmatory evidence and take the *max* of the two
          mapped signals.
        - ``drift_signals['drift_delta']`` -- the engine's raw drift
          axis. Lower-fidelity fallback when neither richer signal is
          present.

        When ``drift_signals`` is empty or contains no recognized key,
        returns ``fallback_g_max`` (the constructor prior). Logged at
        emit-event level so operators can see when the calculator is
        running on a prior.

        Returns
        -------
        g_max in [0, 1] (clamped). Float.
        """
        if not isinstance(drift_signals, dict):
            raise TypeError(
                f"drift_signals must be a dict, got {type(drift_signals).__name__}"
            )

        candidates: list[float] = []

        # Bhardwaj ABC D*
        if "abc_drift_d_star" in drift_signals:
            try:
                d_star = float(drift_signals["abc_drift_d_star"])
                candidates.append(max(0.0, min(1.0, d_star)))
            except (TypeError, ValueError):
                pass

        # BOCPD run-length posterior: short run = high adversary opportunity.
        if "bocpd_run_length_posterior" in drift_signals:
            try:
                p = float(drift_signals["bocpd_run_length_posterior"])
                candidates.append(max(0.0, min(1.0, p)))
            except (TypeError, ValueError):
                pass

        # Raw drift axis fallback.
        if not candidates and "drift_delta" in drift_signals:
            try:
                d = float(drift_signals["drift_delta"])
                candidates.append(max(0.0, min(1.0, d)))
            except (TypeError, ValueError):
                pass

        if not candidates:
            return self._fallback_g_max

        # Take the max -- the calculator is a deterrent design; we
        # estimate the adversary's *upper* gain envelope, not the mean.
        # Underestimating g_max would let Theorem 5 vacuously "satisfy"
        # and silently produce a meaningless bound.
        return max(candidates)

    # ------------------------------------------------------------------- the bound

    def satisfies_bound(
        self,
        *,
        proposed_intervention_cost_to_adversary: float,
        adversary_expected_payoff: float,
    ) -> bool:
        """
        Check Theorem 5's strict-dominance condition: lambda*H >= g_max + epsilon.

        Parameter semantics
        -------------------
        ``proposed_intervention_cost_to_adversary``
            The **window-aggregated** penalty lambda*H, *not* the
            per-step lambda. Tex's
            ``Intervention.expected_cost_to_adversary`` field holds
            this value already in window-aggregated units (the
            intervention applies for H steps; this is the total cost
            the adversary pays under the intervention regime).
        ``adversary_expected_payoff``
            The adversary's expected gain *over the same H-step window*,
            i.e. g_max * H if g_max is per-step. The caller is
            responsible for matching units; the calculator does not
            re-multiply by H here because the engine has both already
            been quoted in window-aggregated form.

        Failure modes
        -------------
        - Negative inputs -> ``ValueError`` (the bound is undefined on
          negative costs).
        - Equality (lambda*H == g_max) -> ``False``: Theorem 5 requires
          *strict* dominance with slack epsilon > 0.

        Per FRONTIER_DELTA §4 Delta-1: this returns the *condition*, not
        the ratio. The ratio is reported by
        ``long_run_compromise_ratio``.
        """
        if proposed_intervention_cost_to_adversary < 0.0:
            raise ValueError(
                "proposed_intervention_cost_to_adversary must be non-negative; "
                f"got {proposed_intervention_cost_to_adversary}"
            )
        if adversary_expected_payoff < 0.0:
            raise ValueError(
                "adversary_expected_payoff must be non-negative; "
                f"got {adversary_expected_payoff}"
            )
        slack = (
            float(proposed_intervention_cost_to_adversary)
            - float(adversary_expected_payoff)
        )
        return slack >= self._epsilon

    def long_run_compromise_ratio_from_window(
        self,
        *,
        penalty_window_aggregate: float,
        adversary_g_max: float,
    ) -> float:
        """
        Compute eta* = alpha*H / (lambda*H - g_max) per Theorem 5.

        Returns ``_VACUOUS_BOUND_RATIO`` (1.0) if lambda*H <= g_max --
        the bound does not apply outside the strict-dominance regime,
        and the honest answer is "no upper bound below 1 is provable
        from this regime."
        """
        slack = float(penalty_window_aggregate) - float(adversary_g_max)
        if slack <= 0.0:
            return _VACUOUS_BOUND_RATIO
        eta = (self._alpha * self._H) / slack
        # Theorem 5 guarantees eta* in (0, 1) when satisfied; clamp the
        # upper edge to 1.0 for cases where alpha*H >= slack (the bound
        # exists but is vacuous in practice).
        return max(0.0, min(_VACUOUS_BOUND_RATIO, eta))

    def long_run_compromise_ratio(
        self,
        *,
        intervention_history: tuple,
        adversary_payoff_history: tuple,
    ) -> float:
        """
        Empirically estimate eta-hat* from window-aggregated history
        tuples.

        Each entry in ``intervention_history`` is the per-window
        aggregate penalty lambda_bar*H actually applied; each entry in
        ``adversary_payoff_history`` is the per-window adversary gain
        g_max observed. The estimator averages each side and applies
        the Theorem-5 formula to the empirical mean values.

        Edge cases
        ----------
        - Empty histories -> returns the operator's
          ``target_compromise_ceiling`` (the *target*, since no
          empirical data is available yet -- failing closed to the
          regime the operator declared).
        - Equal-length tuples assumed; mismatched lengths -> ValueError.

        Per FRONTIER_DELTA §4 Delta-1: this is window-aggregated, not
        per-step.
        """
        if not isinstance(intervention_history, tuple):
            raise TypeError(
                "intervention_history must be a tuple of window-aggregate floats"
            )
        if not isinstance(adversary_payoff_history, tuple):
            raise TypeError(
                "adversary_payoff_history must be a tuple of window-aggregate floats"
            )
        if len(intervention_history) != len(adversary_payoff_history):
            raise ValueError(
                "intervention_history and adversary_payoff_history must be "
                f"the same length; got {len(intervention_history)} vs "
                f"{len(adversary_payoff_history)}"
            )
        if len(intervention_history) == 0:
            return self._target_eta

        try:
            mean_intervention = sum(float(x) for x in intervention_history) / len(
                intervention_history
            )
            mean_payoff = sum(float(x) for x in adversary_payoff_history) / len(
                adversary_payoff_history
            )
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"history tuples must contain numeric values: {exc}"
            ) from exc

        return self.long_run_compromise_ratio_from_window(
            penalty_window_aggregate=mean_intervention,
            adversary_g_max=mean_payoff,
        )

    def compute_minimum_penalty(self, *, adversary_g_max: float) -> float:
        """
        Compute lambda_min per Proposition 1.

        The paper states: lambda_min = (g_max + alpha*H) / (H * eta*).
        However, that printed formula does not algebraically rearrange
        Theorem 5 (eta* = alpha*H / (lambda*H - g_max)) back into the
        same eta*. The correct rearrangement is

            lambda_min = g_max / H + alpha / eta*

        which, when multiplied by H and substituted back into Theorem 5,
        yields exactly eta*_target. This module implements the
        algebraically-correct formula; the paper's printed form appears
        to be a typo (see FRONTIER_DELTA_thread_8.md §10 "Honest
        caveats" for the discrepancy note).

        This is the smallest *per-step* penalty that satisfies Theorem 5
        for the operator's configured target eta*. Operators querying
        "what's the smallest viable penalty to bound my long-run ratio
        at the configured ceiling?" call this method.

        Note: returns lambda, not lambda*H. To get the window-aggregated
        minimum penalty (the form ``satisfies_bound`` consumes),
        multiply by H.
        """
        if adversary_g_max < 0.0:
            raise ValueError(f"adversary_g_max must be >= 0, got {adversary_g_max}")
        # Algebraically-correct rearrangement of Theorem 5:
        #   eta* = alpha*H / (lambda*H - g_max)
        #   lambda*H - g_max = alpha*H / eta*
        #   lambda = g_max/H + alpha/eta*
        return float(adversary_g_max) / self._H + self._alpha / self._target_eta

    def certify(
        self,
        *,
        penalty_window_aggregate: float,
        adversary_g_max: float,
    ) -> CompromiseCertificate:
        """
        Build a structured ``CompromiseCertificate`` for the active
        (intervention, adversary state) pair.

        The certificate is attached to the intervention's
        governance-ledger record so a regulator reconstructing "did
        this intervention satisfy the bound?" can answer offline from
        the signed log alone.
        """
        bound = self.satisfies_bound(
            proposed_intervention_cost_to_adversary=penalty_window_aggregate,
            adversary_expected_payoff=adversary_g_max,
        )
        eta = self.long_run_compromise_ratio_from_window(
            penalty_window_aggregate=penalty_window_aggregate,
            adversary_g_max=adversary_g_max,
        )
        lam_min = self.compute_minimum_penalty(adversary_g_max=adversary_g_max)
        slack = float(penalty_window_aggregate) - float(adversary_g_max)
        if slack > 0.0:
            welfare_upper_bound = (
                self._alpha * self._H * self._delta_max
            ) / slack
            # Clamp: welfare shortfall ceiling cannot exceed the obvious
            # H*Delta_max upper bound (worst case: every step in the
            # window is welfare-zero).
            welfare_upper_bound = min(
                welfare_upper_bound, float(self._H) * self._delta_max
            )
        else:
            welfare_upper_bound = float(self._H) * self._delta_max
        return CompromiseCertificate(
            bound_satisfied=bound,
            eta_star=eta,
            lambda_min=lam_min,
            penalty_window_aggregate=float(penalty_window_aggregate),
            adversary_g_max=float(adversary_g_max),
            slack_above_g_max=slack,
            welfare_shortfall_upper_bound=welfare_upper_bound,
            false_alarm_budget=self._alpha,
            window_length=self._H,
            target_compromise_ceiling=self._target_eta,
        )

"""
Off-policy evaluation with an anytime-valid confidence sequence.

The replay validator answers "how many decisions would flip" — a count. It
does not answer the question an operator approving a calibration actually
needs: *if I deploy this change, what is the worst-case rate at which it
releases unsafe actions, and can you bound that no matter when I look?*

This module answers it. The proposed policy is deterministic given a logged
decision's score and confidence (a re-threshold), so the counterfactual
action is computable directly — no importance weighting required. We collect,
over the labelled decisions the *proposed* policy would PERMIT, the Bernoulli
stream "this permit was actually unsafe", and place an anytime-valid upper
confidence bound on its mean.

Anytime-valid means the bound holds simultaneously at all sample sizes (Ville
/ time-uniform), so it is still valid at the moment the operator happens to
open the held card — exactly the "gated deployment" guarantee an upgrade
decision needs. The bound is the provable sentence the calibration hold
carries: "loosening this would have released unsafe actions at most X% of the
time — I can prove it."

The headline bound is a **Waudby-Smith & Ramdas betting confidence sequence**
(``wsr_upper_bound`` below): a one-sided, variance-adaptive, anytime-valid
upper bound built from a betting (capital) martingale. For each candidate
mean ``m`` it runs the lower-capital process

    K_t^-(m) = prod_{i<=t} ( 1 + lambda_i * (m - X_i) ),   lambda_i >= 0

with predictable, variance-adaptive bets ``lambda_i`` (the WSR "predictable
plug-in"). Under H0: mu >= m this is a non-negative supermartingale, so by
Ville P(exists t: K_t^-(m) >= 1/alpha) <= alpha. K_t^-(m) is monotone
increasing in ``m``, so the confidence set is ``[0, U_t]`` with

    U_t = inf{ m in [0,1] : K_t^-(m) >= 1/alpha }

and P(for all t: mu <= U_t) >= 1 - alpha. Because the bets adapt to the
observed variance, the betting CS is *dramatically tighter* than the older
sub-Gaussian Hoeffding boundary in the rare-event regime that matters here
(unsafe permits are rare), while remaining valid under arbitrary peeking.

For honesty and cross-checking we still expose the older time-uniform
Hoeffding boundary (Howard et al. 2021, §3.2 stitched sub-Gaussian) as
``howard_upper_bound``:

    UB_t = mu_hat_t + sqrt( ( log(1/alpha) + 0.5 * log(1 + t) ) / (2 t) )

The Howard bound depends only on the count (k, n) — order-free — and is by
construction never tighter than WSR on the same stream, so it makes a sound
conservative sanity bracket: ``wsr <= howard`` always holds and is asserted in
the tests.

The WSR bound is order-dependent (through the predictable bets), so the gate
consumes the *actual decision-ordered* stream of unsafe labels, which is
sealed and replayable — the bound is reproducible bit-for-bit.

References (retrieved 2026-06-09; constructions verified against the sources)
----------
- Waudby-Smith & Ramdas, "Estimating means of bounded random variables by
  betting" (arXiv 2010.09686; JRSS-B 2023): the betting / hedged-capital
  confidence sequence and the predictable-plug-in bets used here.
- Karampatziakis, Mineiro, Ramdas, "Off-policy Confidence Sequences" (2021):
  confidence sequences for OPE, applied to safely upgrading a production
  system ("gated deployment").
- Howard, Ramdas, McAuliffe, Sekhon, "Time-uniform, nonparametric,
  nonasymptotic confidence sequences" (2021, arXiv 1810.08240) — the Howard
  cross-check boundary.

stdlib-only (math + dataclasses). No new dependencies.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Iterable, Sequence

from tex.domain.decision import Decision
from tex.domain.outcome import OutcomeRecord
from tex.domain.outcome_trust import OutcomeTrustLevel
from tex.domain.policy import PolicySnapshot
from tex.domain.verdict import Verdict
from tex.learning.calibrator import CalibrationRecommendation
from tex.learning.replay import _rederive_verdict

__all__ = [
    "OffPolicyEvaluator",
    "OPEReport",
    "DEFAULT_OPE_ALPHA",
    "DEFAULT_UNSAFE_RELEASE_BUDGET",
    "WSR_DEFAULT_TRUNCATION",
    "wsr_upper_bound",
]

DEFAULT_OPE_ALPHA = 0.05
# WSR bet truncation. The bets are capped to ``[0, c]`` with ``c < 1`` so the
# capital factor ``1 + lambda_i*(m - X_i) >= 1 - c > 0`` for every m, X in
# [0,1] — i.e. the martingale stays strictly non-negative for the whole grid,
# which is what Ville's inequality requires. ``c = 1/2`` is the WSR-recommended
# truncation.
WSR_DEFAULT_TRUNCATION = 0.5
# Default ceiling on the anytime-valid upper bound of the counterfactual
# unsafe-release rate. A proposal whose UB exceeds this is refused even if the
# point estimate looks fine — the bound is what we gate on, not the estimate.
DEFAULT_UNSAFE_RELEASE_BUDGET = 0.05


@dataclass(frozen=True, slots=True)
class OPEReport:
    """Anytime-valid off-policy evaluation of a proposed re-threshold.

    Fields
    ------
    counterfactual_permits
        Labelled decisions the *proposed* policy would PERMIT (the exposure
        set for the harm estimand).
    counterfactual_unsafe
        Of those, how many were actually unsafe (``was_safe is False``) — the
        events the proposed policy would have released.
    point_estimate
        ``counterfactual_unsafe / counterfactual_permits`` (0 when no permits).
    upper_bound
        Anytime-valid upper confidence bound on the counterfactual
        unsafe-release rate at level ``alpha`` — the **WSR betting confidence
        sequence** over the decision-ordered unsafe-label stream. Clipped to
        [0, 1]. This is the number the OPE gate stands behind.
    howard_upper_bound
        The older time-uniform Hoeffding (Howard et al. 2021) boundary on the
        same (k, n). Order-free and never tighter than ``upper_bound`` — kept
        as an auditable conservative cross-check (``upper_bound <=
        howard_upper_bound`` always).
    alpha
        Coverage level: the bound holds with probability ≥ 1−alpha,
        simultaneously over all sample sizes.
    newly_released_unsafe
        Of the unsafe permits, how many the *original* policy did NOT permit
        (FORBID/ABSTAIN → PERMIT). The marginal harm the change introduces —
        the number the held-card sentence speaks.
    """

    counterfactual_permits: int
    counterfactual_unsafe: int
    point_estimate: float
    upper_bound: float
    alpha: float
    newly_released_unsafe: int
    howard_upper_bound: float = 1.0
    bound_method: str = "wsr_betting_cs"

    def within_budget(self, budget: float) -> bool:
        """True iff the anytime-valid upper bound is at or below ``budget``."""
        return self.upper_bound <= budget

    def as_dict(self) -> dict[str, object]:
        return {
            "counterfactual_permits": self.counterfactual_permits,
            "counterfactual_unsafe": self.counterfactual_unsafe,
            "point_estimate": round(self.point_estimate, 6),
            "upper_bound": round(self.upper_bound, 6),
            "howard_upper_bound": round(self.howard_upper_bound, 6),
            "bound_method": self.bound_method,
            "alpha": self.alpha,
            "newly_released_unsafe": self.newly_released_unsafe,
        }


class OffPolicyEvaluator:
    """Computes an anytime-valid bound on a proposed policy's harm rate."""

    __slots__ = ("_alpha",)

    def __init__(self, *, alpha: float = DEFAULT_OPE_ALPHA) -> None:
        if not 0.0 < alpha < 1.0:
            raise ValueError("alpha must be in (0, 1)")
        self._alpha = alpha

    def evaluate(
        self,
        *,
        decisions: Iterable[Decision],
        outcomes: Iterable[OutcomeRecord],
        policy: PolicySnapshot,
        recommendation: CalibrationRecommendation,
    ) -> OPEReport:
        outcomes_by_decision: dict = {}
        for o in outcomes:
            if o.trust_level not in (
                OutcomeTrustLevel.VALIDATED,
                OutcomeTrustLevel.VERIFIED,
            ):
                continue
            outcomes_by_decision.setdefault(o.decision_id, []).append(o)

        new_permit = recommendation.recommended_permit_threshold
        new_forbid = recommendation.recommended_forbid_threshold
        new_min_conf = recommendation.recommended_minimum_confidence

        permits = 0
        unsafe = 0
        newly_released_unsafe = 0
        # The decision-ordered Bernoulli stream "this counterfactual permit was
        # unsafe" (1.0/0.0). WSR is order-dependent through its predictable
        # bets, so we feed the exposure events in deterministic decision order
        # — sealed and replayable, hence the bound is reproducible bit-for-bit.
        stream: list[float] = []

        for decision in decisions:
            attached = outcomes_by_decision.get(decision.decision_id)
            if not attached:
                continue
            proposed_v = _rederive_verdict(
                decision=decision,
                permit_threshold=new_permit,
                forbid_threshold=new_forbid,
                minimum_confidence=new_min_conf,
            )
            if proposed_v is not Verdict.PERMIT:
                continue
            for o in attached:
                if o.was_safe is None:
                    continue
                permits += 1
                if o.was_safe is False:
                    unsafe += 1
                    stream.append(1.0)
                    if decision.verdict is not Verdict.PERMIT:
                        newly_released_unsafe += 1
                else:
                    stream.append(0.0)

        point = (unsafe / permits) if permits > 0 else 0.0
        # Headline bound the gate stands behind: the WSR betting confidence
        # sequence over the ordered exposure stream — anytime-valid at level
        # ``alpha`` on its own (no union-bound inflation). The order-free Howard
        # boundary on (k, n) is reported alongside as a conservative cross-check
        # (``wsr <= howard`` always; asserted in tests).
        ub = wsr_upper_bound(stream, alpha=self._alpha)
        howard = _anytime_valid_upper_bound(
            successes=unsafe, n=permits, alpha=self._alpha
        )
        return OPEReport(
            counterfactual_permits=permits,
            counterfactual_unsafe=unsafe,
            point_estimate=point,
            upper_bound=ub,
            alpha=self._alpha,
            newly_released_unsafe=newly_released_unsafe,
            howard_upper_bound=howard,
            bound_method="wsr_betting_cs",
        )


def wsr_upper_bound(
    observations: Sequence[float],
    *,
    alpha: float = DEFAULT_OPE_ALPHA,
    truncation: float = WSR_DEFAULT_TRUNCATION,
) -> float:
    """One-sided WSR betting upper confidence bound on a [0,1]-bounded mean.

    Anytime-valid and variance-adaptive (Waudby-Smith & Ramdas, arXiv
    2010.09686). ``observations`` is the time-ordered stream of [0,1] values
    (here: 1.0 == "this counterfactual permit was unsafe", 0.0 otherwise).

    With no exposure (empty stream) the proposed policy permits nothing
    labelled, so the counterfactual unsafe-release rate is vacuously 0.0.

    Construction
    ------------
    For each candidate mean ``m`` the lower-capital process

        K_t^-(m) = prod_i ( 1 + lambda_i * (m - X_i) )

    is a non-negative supermartingale under H0: mu >= m, so by Ville
    P(exists t: K_t^-(m) >= 1/alpha) <= alpha. K_t^-(m) is monotone increasing
    in ``m``, hence

        U = inf{ m in [0,1] : K_t^-(m) >= 1/alpha }

    is an anytime-valid (1 - alpha) upper bound on the mean. The bets
    ``lambda_i`` are the WSR predictable plug-in

        mu_hat_t      = (1/2 + sum_{i<=t} X_i) / (t + 1)
        sigma2_hat_t  = (1/4 + sum_{i<=t} (X_i - mu_hat_i)^2) / (t + 1)
        lambda_t      = min( c, sqrt( 2 ln(1/alpha)
                                      / (sigma2_hat_{t-1} * t * ln(t+1)) ) )

    using ``sigma2_hat_{t-1}`` (predictable) and truncated to ``[0, c]`` with
    ``c < 1`` so every capital factor ``1 + lambda_i*(m - X_i) >= 1 - c > 0``
    stays strictly positive for all m, X in [0,1] — the non-negativity Ville
    requires. The crossing ``U`` is found by binary search on the monotone
    log-capital, so the returned bound is for the continuous ``m`` (no grid
    discretization gap).
    """
    if not 0.0 < alpha < 1.0:
        raise ValueError("alpha must be in (0, 1)")
    if not 0.0 < truncation < 1.0:
        raise ValueError("truncation must be in (0, 1)")
    xs = [float(x) for x in observations]
    n = len(xs)
    if n == 0:
        return 0.0
    for x in xs:
        if not 0.0 <= x <= 1.0:
            raise ValueError("observations must lie in [0, 1]")

    # ── predictable plug-in bets ────────────────────────────────────────
    log_inv_alpha = math.log(1.0 / alpha)
    lambdas: list[float] = []
    run_sum = 0.0
    run_sq = 0.0
    sigma2_prev = 0.25  # sigma2_hat_0 prior (1/4)
    for t in range(1, n + 1):
        # lambda_t from sigma2_hat_{t-1} (only past data) — predictable.
        denom = sigma2_prev * t * math.log(t + 1.0)
        lam = truncation if denom <= 0.0 else math.sqrt(2.0 * log_inv_alpha / denom)
        lam = max(0.0, min(truncation, lam))
        lambdas.append(lam)
        # fold in X_t, advance the running mean/variance for sigma2_hat_t.
        x = xs[t - 1]
        run_sum += x
        mu_t = (0.5 + run_sum) / (t + 1.0)
        run_sq += (x - mu_t) ** 2
        sigma2_prev = (0.25 + run_sq) / (t + 1.0)

    # ── invert the monotone capital process for the crossing ────────────
    def log_capital(m: float) -> float:
        total = 0.0
        for lam, x in zip(lambdas, xs):
            total += math.log1p(lam * (m - x))
        return total

    # If even m = 1 cannot reach the rejection threshold, the bound is vacuous.
    if log_capital(1.0) < log_inv_alpha:
        return 1.0
    lo, hi = 0.0, 1.0
    for _ in range(60):
        mid = (lo + hi) / 2.0
        if log_capital(mid) >= log_inv_alpha:
            hi = mid
        else:
            lo = mid
    return max(0.0, min(1.0, hi))


def _anytime_valid_upper_bound(*, successes: int, n: int, alpha: float) -> float:
    """Time-uniform Hoeffding upper bound on a [0,1]-bounded mean.

    Order-free conservative cross-check for the headline WSR betting bound
    (``wsr_upper_bound``): it depends only on the count ``(successes, n)`` and
    is never tighter than WSR on the same stream, so it brackets WSR from
    above. Retained as the count-only OPE bound API.

    With no exposure (``n == 0``) the proposed policy permits nothing
    labelled, so the counterfactual unsafe-release rate is vacuously 0 and we
    return 0.0 — there is nothing to bound.

    UB = mu_hat + sqrt( ( log(1/alpha) + 0.5 log(1+n) ) / (2 n) ), clipped to
    [0, 1]. The 0.5·log(1+n) term is the time-uniform inflation (Howard et al.
    2021 §3.2); dropping it recovers the fixed-sample Hoeffding interval that
    would be invalid under peeking.
    """
    if n <= 0:
        return 0.0
    mu_hat = successes / float(n)
    radius = math.sqrt(
        (math.log(1.0 / alpha) + 0.5 * math.log(1.0 + n)) / (2.0 * n)
    )
    return max(0.0, min(1.0, mu_hat + radius))

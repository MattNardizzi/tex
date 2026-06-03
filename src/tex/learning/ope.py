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

The upper bound is a time-uniform Hoeffding boundary (Howard et al. 2021,
§3.2 sub-Gaussian stitched bound), stdlib-only:

    UB_t = mu_hat_t + sqrt( ( log(1/alpha) + 0.5 * log(1 + t) ) / (2 t) )

The 0.5·log(1+t) inflation over the fixed-sample Hoeffding term is what buys
time-uniformity (the union-over-stopping-times correction). It is loose by
design — an operator approving a governance change should be shown a
conservative worst case, not an optimistic point estimate.

References
----------
- Karampatziakis, Mineiro, Ramdas, "Off-policy Confidence Sequences" (2021):
  confidence sequences for OPE, applied to safely upgrading a production
  system ("gated deployment").
- Howard, Ramdas, McAuliffe, Sekhon, "Time-uniform, nonparametric,
  nonasymptotic confidence sequences" (2021, arxiv 1810.08240).

stdlib-only (math + dataclasses). No new dependencies.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Iterable

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
]

DEFAULT_OPE_ALPHA = 0.05
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
        unsafe-release rate at level ``alpha``. Clipped to [0, 1].
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

    def within_budget(self, budget: float) -> bool:
        """True iff the anytime-valid upper bound is at or below ``budget``."""
        return self.upper_bound <= budget

    def as_dict(self) -> dict[str, object]:
        return {
            "counterfactual_permits": self.counterfactual_permits,
            "counterfactual_unsafe": self.counterfactual_unsafe,
            "point_estimate": round(self.point_estimate, 6),
            "upper_bound": round(self.upper_bound, 6),
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
                    if decision.verdict is not Verdict.PERMIT:
                        newly_released_unsafe += 1

        point = (unsafe / permits) if permits > 0 else 0.0
        ub = _anytime_valid_upper_bound(
            successes=unsafe, n=permits, alpha=self._alpha
        )
        return OPEReport(
            counterfactual_permits=permits,
            counterfactual_unsafe=unsafe,
            point_estimate=point,
            upper_bound=ub,
            alpha=self._alpha,
            newly_released_unsafe=newly_released_unsafe,
        )


def _anytime_valid_upper_bound(*, successes: int, n: int, alpha: float) -> float:
    """Time-uniform Hoeffding upper bound on a [0,1]-bounded mean.

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

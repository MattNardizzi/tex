"""
Conformal Risk Control (CRC) verdict gate.

[Architecture: Layer 4 (Execution Governance)]

What this is
------------
The PDP fuses its streams into a scalar ``final_score`` in [0, 1] (higher =
more dangerous) and today maps that score to PERMIT / ABSTAIN / FORBID using
hand-tuned policy thresholds. Those thresholds are good engineering judgement,
but they carry *no statistical guarantee*: an operator cannot ask "how often
does a PERMIT leak a genuinely unsafe action?" and get a defensible number.

This gate closes that gap. Given a held-out, labelled calibration set of
``(final_score, was_actually_unsafe)`` pairs, it derives — once, offline,
frozen — a permit cutoff ``lambda_hat`` such that the **false-permit rate is
provably bounded**:

    P[ R(lambda_hat) <= alpha ] >= 1 - delta

where ``R(lambda)`` is the probability mass of genuinely-unsafe actions that
fall inside the PERMIT region ``{final_score <= lambda}``. The bound is
finite-sample and distribution-free (it needs only exchangeability of the
calibration data, not any model of the score distribution).

This is the Risk-Controlling Prediction Sets (RCPS) construction of Bates,
Angelopoulos, Lei, Malik & Jordan, "Distribution-Free, Risk-Controlling
Prediction Sets" (JACM 2021), specialised to a one-sided monotone risk, with
the tightened Hoeffding-Bentkus upper confidence bound. It is the same family
the 2026 selective-risk-control line builds on (Conformal Selective Acting,
arXiv 2605.20270; Selective Conformal Risk Control, arXiv 2512.12844; SCOPE,
arXiv 2602.13110). Tex uses split conformal prediction for *specialist
escalation* already (``specialists/conformal_escalation.py``); this applies the
same rigour to the object that actually matters — the final verdict.

Three hard contracts
--------------------
1. **Deterministic.** ``lambda_hat`` is computed once at construction from a
   fixed calibration set and frozen. At evaluation time the gate is a pure
   comparison ``final_score <= lambda_hat``. No randomness, no I/O, no clocks.
   Identical inputs always produce identical output, so the PDP determinism
   fingerprint is preserved.

2. **Fail-closed / monotone-safe.** The gate may only ever make a verdict
   *more conservative*. It can demote a router PERMIT to ABSTAIN when the
   score lies outside the certified permit region; it can **never** promote an
   ABSTAIN or FORBID to PERMIT. Wiring it in therefore cannot introduce a new
   false-permit, only remove one. When no calibration data is supplied the
   gate is *inert*: it passes every verdict through unchanged (preserving
   pre-CRC behaviour bit-for-bit) and stamps a certificate with
   ``certified=False``.

3. **Auditable.** Every evaluation attaches a ``CRCCertificate`` to the
   decision: the risk budget, confidence, the frozen cutoff, the empirical
   risk and its upper bound at the cutoff, the calibration size, and the bound
   method. An auditor (or a regulator under the EU AI Act) can reproduce the
   number.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Sequence

from pydantic import BaseModel, ConfigDict, Field

from tex.domain.verdict import Verdict


# ── Calibration record ──────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class CalibrationRecord:
    """One labelled calibration point.

    ``final_score`` is the PDP fused risk score the engine produced for a past
    request; ``unsafe`` is the ground-truth label (True == the action was
    genuinely unsafe / should not have been permitted). Labels come from
    Layer 6 outcome validation, human review, or a curated red-team corpus.
    """

    final_score: float
    unsafe: bool

    def __post_init__(self) -> None:
        if not 0.0 <= self.final_score <= 1.0:
            raise ValueError("final_score must be in [0, 1]")


# ── Certificate ─────────────────────────────────────────────────────────


class CRCCertificate(BaseModel):
    """Auditable record of the risk-control guarantee for one evaluation."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    enabled: bool = Field(
        description="Whether a calibrated gate was active for this evaluation."
    )
    certified: bool = Field(
        description=(
            "Whether the false-permit rate carries a finite-sample bound. "
            "False when the gate is inert (no calibration) or when no cutoff "
            "could satisfy the risk budget."
        )
    )
    alpha: float = Field(
        ge=0.0, le=1.0, description="Risk budget: target upper bound on false-permit rate."
    )
    delta: float = Field(
        ge=0.0, le=1.0, description="Failure probability of the bound (confidence = 1 - delta)."
    )
    lambda_hat: float = Field(
        description=(
            "Frozen permit cutoff. PERMIT is only certified for scores <= "
            "lambda_hat. -1.0 means no score is certifiable (maximally "
            "fail-closed); the gate is inert when enabled is False."
        )
    )
    empirical_false_permit_rate: float = Field(
        ge=0.0, le=1.0, description="R_hat(lambda_hat) on the calibration set."
    )
    risk_upper_bound: float = Field(
        ge=0.0,
        le=1.0,
        description="Hoeffding-Bentkus UCB on the true risk at lambda_hat at confidence 1 - delta.",
    )
    certified_false_permit_rate: float = Field(
        ge=0.0,
        le=1.0,
        description=(
            "The number Tex stands behind: the certified upper bound on how "
            "often a PERMIT leaks a genuinely unsafe action. Equals "
            "risk_upper_bound when certified, else 1.0."
        ),
    )
    n_calibration: int = Field(ge=0, description="Calibration set size.")
    bound_method: str = Field(description="Concentration bound used for the UCB.")
    demoted: bool = Field(
        default=False,
        description="Whether the gate demoted this evaluation's PERMIT to ABSTAIN.",
    )


# ── Result of applying the gate to one verdict ──────────────────────────


@dataclass(frozen=True, slots=True)
class CRCGateResult:
    """Output of ``ConformalRiskGate.apply``."""

    verdict: Verdict
    demoted: bool
    certificate: CRCCertificate
    reasons: tuple[str, ...]
    uncertainty_flags: tuple[str, ...]


# ── Concentration bounds (finite-sample, distribution-free) ─────────────


def hoeffding_ucb(r_hat: float, n: int, delta: float) -> float:
    """Hoeffding upper confidence bound on a [0,1]-bounded mean.

    Returns an upper bound U such that P[ R <= U ] >= 1 - delta.
    """
    if n <= 0:
        return 1.0
    return min(1.0, r_hat + math.sqrt(math.log(1.0 / delta) / (2.0 * n)))


def _binom_cdf(k: int, n: int, p: float) -> float:
    """P[ Bin(n, p) <= k ]. Exact; n is a few hundred at most."""
    if p <= 0.0:
        return 1.0
    if p >= 1.0:
        return 1.0 if k >= n else 0.0
    k = min(k, n)
    total = 0.0
    for i in range(0, k + 1):
        total += math.comb(n, i) * (p ** i) * ((1.0 - p) ** (n - i))
    return min(1.0, total)


def bentkus_ucb(r_hat: float, n: int, delta: float) -> float:
    """Bentkus upper confidence bound (Bates et al. 2021, eq. for RCPS).

    Inverts the Bentkus inequality P[ R_hat <= r_hat ] <= e * P[ Bin(n, U) <=
    ceil(n r_hat) ] to find the largest U whose tail probability * e is still
    >= delta. Tighter than Hoeffding in the small-risk regime that matters
    here (we care about rare unsafe-permits).
    """
    if n <= 0:
        return 1.0
    k = math.ceil(n * r_hat)
    if k >= n:
        return 1.0
    lo, hi = r_hat, 1.0
    # Monotone in U: binary-search the largest U with e * Binom.cdf(k; n, U) >= delta.
    for _ in range(60):
        mid = (lo + hi) / 2.0
        if math.e * _binom_cdf(k, n, mid) >= delta:
            lo = mid
        else:
            hi = mid
    return min(1.0, hi)


def hoeffding_bentkus_ucb(r_hat: float, n: int, delta: float) -> float:
    """The tighter of Hoeffding and Bentkus — the RCPS-recommended bound."""
    return min(hoeffding_ucb(r_hat, n, delta), bentkus_ucb(r_hat, n, delta))


# ── The gate ────────────────────────────────────────────────────────────


_DEFAULT_GRID_SIZE = 1001  # lambda candidates over [0, 1] — 0.001 resolution.


class ConformalRiskGate:
    """Risk-controlling verdict gate.

    Construct with a calibration set and a risk budget; the cutoff is computed
    and frozen. ``apply`` then maps a router verdict + fused score to a
    possibly-more-conservative verdict plus an auditable certificate.

    Stateless across requests after construction. Re-instantiate to recalibrate
    on fresh labelled data.
    """

    __slots__ = (
        "_alpha",
        "_delta",
        "_enabled",
        "_lambda_hat",
        "_empirical_risk",
        "_risk_ucb",
        "_n",
        "_bound_method",
        "_certified",
    )

    def __init__(
        self,
        *,
        calibration: Sequence[CalibrationRecord] | None = None,
        alpha: float = 0.05,
        delta: float = 0.05,
        grid_size: int = _DEFAULT_GRID_SIZE,
    ) -> None:
        if not 0.0 < alpha < 1.0:
            raise ValueError("alpha must be in (0, 1)")
        if not 0.0 < delta < 1.0:
            raise ValueError("delta must be in (0, 1)")
        self._alpha = alpha
        self._delta = delta
        self._bound_method = "hoeffding_bentkus"

        if not calibration:
            # Inert gate: pass-through, certifies nothing.
            self._enabled = False
            self._certified = False
            self._lambda_hat = 1.0  # permit region = everything (pass-through)
            self._empirical_risk = 0.0
            self._risk_ucb = 1.0
            self._n = 0
            return

        self._enabled = True
        self._n = len(calibration)
        self._lambda_hat, self._empirical_risk, self._risk_ucb = self._calibrate(
            calibration, alpha=alpha, delta=delta, grid_size=grid_size
        )
        # certified == "there exists a non-empty certified permit region".
        self._certified = self._lambda_hat >= 0.0

    @staticmethod
    def _calibrate(
        calibration: Sequence[CalibrationRecord],
        *,
        alpha: float,
        delta: float,
        grid_size: int,
    ) -> tuple[float, float, float]:
        """RCPS calibration for a one-sided monotone risk.

        Risk R(lambda) = mean over calibration of [ unsafe AND score <= lambda ]
        is non-decreasing in lambda. We want the *most permissive* cutoff whose
        risk UCB is still within budget — that maximises utility (PERMITs kept)
        subject to the guarantee:

            lambda_hat = sup { lambda : UCB(R_hat(lambda); delta) <= alpha }

        Because R is monotone, controlling at lambda_hat controls for every
        smaller lambda too. Returns (lambda_hat, R_hat(lambda_hat),
        UCB(lambda_hat)). If even lambda = 0 violates the budget, returns
        lambda_hat = -1.0 (no score certifiable — maximally fail-closed).
        """
        n = len(calibration)
        scores = [c.final_score for c in calibration]
        unsafe = [c.unsafe for c in calibration]

        # Evaluate the grid from most-permissive (1.0) downward; the first
        # lambda whose UCB <= alpha is the supremum we want.
        best_lambda = -1.0
        best_rhat = 0.0
        best_ucb = 1.0
        for i in range(grid_size):
            lam = 1.0 - (i / (grid_size - 1))  # 1.0, ..., 0.0
            # R_hat(lam) = fraction of calibration that is unsafe AND permitted.
            hits = sum(
                1 for s, u in zip(scores, unsafe) if u and s <= lam
            )
            r_hat = hits / n
            ucb = hoeffding_bentkus_ucb(r_hat, n, delta)
            if ucb <= alpha:
                best_lambda = lam
                best_rhat = r_hat
                best_ucb = ucb
                break
        return best_lambda, best_rhat, best_ucb

    # ----- introspection (used by tests + audit) -------------------------

    @property
    def enabled(self) -> bool:
        return self._enabled

    @property
    def certified(self) -> bool:
        return self._certified

    @property
    def lambda_hat(self) -> float:
        return self._lambda_hat

    def certificate_template(self, *, demoted: bool = False) -> CRCCertificate:
        certified_rate = self._risk_ucb if self._certified else 1.0
        return CRCCertificate(
            enabled=self._enabled,
            certified=self._certified,
            alpha=self._alpha,
            delta=self._delta,
            lambda_hat=round(self._lambda_hat, 6),
            empirical_false_permit_rate=round(self._empirical_risk, 6),
            risk_upper_bound=round(min(1.0, max(0.0, self._risk_ucb)), 6),
            certified_false_permit_rate=round(min(1.0, max(0.0, certified_rate)), 6),
            n_calibration=self._n,
            bound_method=self._bound_method,
            demoted=demoted,
        )

    # ----- the runtime call ----------------------------------------------

    def apply(self, *, verdict: Verdict, final_score: float) -> CRCGateResult:
        """Apply the gate. Only ever makes the verdict more conservative.

        - Inert gate (not enabled): pass-through, ``certified=False``.
        - Enabled, verdict != PERMIT: pass-through (we never relax a non-permit).
        - Enabled, verdict == PERMIT, score <= lambda_hat: PERMIT stands and is
          certified.
        - Enabled, verdict == PERMIT, score >  lambda_hat (or no certifiable
          region): demote to ABSTAIN — the score lies outside the certified
          permit region, so we route to human review rather than emit an
          uncertified PERMIT.
        """
        if not self._enabled or verdict is not Verdict.PERMIT:
            return CRCGateResult(
                verdict=verdict,
                demoted=False,
                certificate=self.certificate_template(demoted=False),
                reasons=(),
                uncertainty_flags=(),
            )

        within_certified_region = (
            self._certified and final_score <= self._lambda_hat
        )
        if within_certified_region:
            return CRCGateResult(
                verdict=Verdict.PERMIT,
                demoted=False,
                certificate=self.certificate_template(demoted=False),
                reasons=(
                    f"CRC gate: PERMIT certified — fused score "
                    f"{final_score:.3f} <= cutoff {self._lambda_hat:.3f}; "
                    f"false-permit rate bounded <= {self._risk_ucb:.3f} at "
                    f"confidence {1.0 - self._delta:.2f}.",
                ),
                uncertainty_flags=(),
            )

        # Outside the certified region — demote to ABSTAIN (fail-closed).
        if self._certified:
            reason = (
                f"CRC gate: PERMIT demoted to ABSTAIN — fused score "
                f"{final_score:.3f} exceeds certified permit cutoff "
                f"{self._lambda_hat:.3f} (risk budget alpha={self._alpha:.3f})."
            )
        else:
            reason = (
                "CRC gate: PERMIT demoted to ABSTAIN — no permit cutoff "
                f"satisfies the risk budget alpha={self._alpha:.3f} at "
                f"confidence {1.0 - self._delta:.2f} on the calibration set."
            )
        return CRCGateResult(
            verdict=Verdict.ABSTAIN,
            demoted=True,
            certificate=self.certificate_template(demoted=True),
            reasons=(reason,),
            uncertainty_flags=("crc_permit_region_exceeded",),
        )


def build_default_crc_gate() -> ConformalRiskGate:
    """Default gate: inert (no calibration). Pass-through, certifies nothing.

    This preserves pre-CRC PDP behaviour exactly until an operator supplies a
    calibration set, at which point PERMITs outside the certified region begin
    routing to ABSTAIN.
    """
    return ConformalRiskGate(calibration=None)


__all__ = [
    "CalibrationRecord",
    "CRCCertificate",
    "CRCGateResult",
    "ConformalRiskGate",
    "build_default_crc_gate",
    "hoeffding_ucb",
    "bentkus_ucb",
    "hoeffding_bentkus_ucb",
]

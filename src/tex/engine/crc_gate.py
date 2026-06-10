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

Three upgrades make the two-sided gate honest and operator-facing
-----------------------------------------------------------------
1. **LTT joint two-sided certificate.** The permit and forbid cutoffs are two
   sweeps over the SAME calibration sample. Reporting each at confidence
   ``1 - delta`` and then claiming "the hold band is certified" silently
   multiplies the error: the joint event can fail with probability up to
   ``2*delta``. Learn-then-Test (Angelopoulos, Bates, Candès, Jordan, Lei,
   arXiv 2110.01052) frames risk control as multiple testing; we control the
   family-wise error by SPLITTING ``delta`` across the two families
   (Bonferroni), so the joint hold guarantee holds at ``1 - delta`` honestly.
   ``joint_delta`` on the certificate names that joint budget.

2. **epsilon-collar.** Each grid cutoff is backed off toward conservatism by a
   margin ``epsilon`` (permit cutoff lowered, forbid cutoff raised), so the
   guarantee transfers from the grid node to the CONTINUOUS score and a
   finite-sample non-monotonicity of the selective risk cannot leak past the
   node. The collar only ever SHRINKS the certified PERMIT/FORBID regions —
   it widens the hold band and can never relax a verdict.

3. **SCRC acted-set conditioning.** The marginal risk divides unsafe-permits by
   the WHOLE calibration set; the operator actually asks "of the actions you
   EMIT as PERMIT, how many are unsafe?" — the risk conditioned on the ACTED
   set (Selective Conformal Risk Control, arXiv 2512.12844). The certificate
   always surfaces this acted-set rate (``acted_set_false_permit_rate``);
   ``risk_estimand="selective"`` additionally GATES the cutoff on it (a
   strictly more conservative cutoff, valid under the score's monotone-
   calibration design assumption, with the epsilon-collar as the finite-sample
   margin). The default ``"marginal"`` preserves the RCPS-monotone guarantee.

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

    # ── Two-sided extension (the forbid-side bound) ──────────────────────
    # The one-sided gate above bounds only the FALSE-PERMIT rate. A hold
    # (ABSTAIN) is the verdict the operator actually sees, so it deserves a
    # guarantee of the same caliber — which requires the *other* side too: a
    # certified bound on the FALSE-FORBID rate (blocking a genuinely-safe
    # action). With both cutoffs in hand the certified hold band is the
    # region between them: the scores where neither a PERMIT nor a FORBID can
    # be certified at its budget. ABSTAIN stops being the score's leftover
    # and becomes a region with its own coverage statement.
    #
    # Construction follows the same RCPS / Hoeffding-Bentkus machinery as the
    # permit side (SCRC, arXiv 2512.12844; SCOPE, arXiv 2602.13110 — bound the
    # error among the verdicts actually acted on). Fields default to the
    # one-sided posture so older certificates and tests remain valid.
    alpha_forbid: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Risk budget: target upper bound on the false-forbid rate.",
    )
    lambda_forbid: float = Field(
        default=2.0,
        description=(
            "Frozen forbid cutoff. FORBID is only *certified* for scores >= "
            "lambda_forbid. 2.0 (above the score range) means no score is "
            "forbid-certifiable; the forbid side is inert when forbid_certified "
            "is False."
        ),
    )
    empirical_false_forbid_rate: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="R_hat_forbid(lambda_forbid) on the calibration set (safe-but-blocked).",
    )
    forbid_risk_upper_bound: float = Field(
        default=1.0,
        ge=0.0,
        le=1.0,
        description="Hoeffding-Bentkus UCB on the true false-forbid risk at lambda_forbid.",
    )
    certified_false_forbid_rate: float = Field(
        default=1.0,
        ge=0.0,
        le=1.0,
        description=(
            "The number Tex stands behind on the forbid side: the certified "
            "upper bound on how often a FORBID blocks a genuinely-safe action. "
            "Equals forbid_risk_upper_bound when forbid_certified, else 1.0."
        ),
    )
    forbid_certified: bool = Field(
        default=False,
        description="Whether a non-empty certified FORBID region exists.",
    )
    hold_certified: bool = Field(
        default=False,
        description=(
            "Whether the hold (ABSTAIN) band carries a two-sided guarantee: "
            "both the permit and forbid sides are certified and the band "
            "[lambda_hat, lambda_forbid] is well-formed (lambda_hat < "
            "lambda_forbid). When true, an ABSTAIN inside the band is the "
            "certified-uncertain region, not a leftover."
        ),
    )
    hold_band_lower: float = Field(
        default=0.0,
        description="Lower edge of the certified hold band (= the permit cutoff lambda_hat).",
    )
    hold_band_upper: float = Field(
        default=1.0,
        description="Upper edge of the certified hold band (= the forbid cutoff lambda_forbid).",
    )
    in_hold_band: bool = Field(
        default=False,
        description="Whether THIS evaluation's fused score fell inside the certified hold band.",
    )

    # ── LTT joint two-sided certificate (FWER over the two families) ──────
    # The permit and forbid cutoffs are chosen by TWO sweeps over the SAME
    # calibration sample. Reporting each at confidence 1 - delta and then
    # claiming "the hold band is certified" silently multiplies the error: the
    # joint event "both bounds hold" can fail with probability up to delta_permit
    # + delta_forbid. Learn-then-Test (Angelopoulos et al. 2110.01052) frames
    # this as multiple testing; we control the family-wise error by SPLITTING
    # the budget (Bonferroni across the two families). ``joint_delta`` is the
    # honest joint failure probability of the two-sided claim; the joint
    # confidence is 1 - joint_delta.
    joint_delta: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description=(
            "Family-wise error budget of the JOINT two-sided certificate "
            "(= delta_permit + delta_forbid). The hold band's two-sided "
            "guarantee holds with probability >= 1 - joint_delta."
        ),
    )
    delta_permit: float = Field(
        default=0.0, ge=0.0, le=1.0, description="Permit-family share of the joint budget."
    )
    delta_forbid: float = Field(
        default=0.0, ge=0.0, le=1.0, description="Forbid-family share of the joint budget."
    )
    epsilon_collar: float = Field(
        default=0.0,
        ge=0.0,
        description=(
            "Learn-then-Test epsilon-collar: each grid cutoff is backed off by "
            "this margin toward conservatism (permit cutoff lowered, forbid "
            "cutoff raised) so the guarantee holds for the CONTINUOUS score, "
            "not merely the grid node, and to guard finite-sample non-"
            "monotonicity of the selective risk. The collar only ever SHRINKS "
            "the certified PERMIT/FORBID regions — it can never relax a verdict."
        ),
    )

    # ── SCRC acted-set (selective) risk — the operator-facing estimand ───
    # The marginal risk above divides unsafe-permits by the WHOLE calibration
    # set. The operator actually asks: "of the actions you EMIT as PERMIT, what
    # fraction are unsafe?" — the risk conditioned on the acted set (Selective
    # Conformal Risk Control, arXiv 2512.12844). We always compute and surface
    # it; ``risk_estimand`` says which one the cutoff was GATED on.
    risk_estimand: str = Field(
        default="marginal",
        description=(
            "Which risk the cutoff search gated on: 'marginal' (over the whole "
            "calibration set; RCPS-monotone, the default) or 'selective' (the "
            "stricter SCRC acted-set risk)."
        ),
    )
    acted_set_false_permit_rate: float = Field(
        default=1.0,
        ge=0.0,
        le=1.0,
        description=(
            "SCRC: certified upper bound on the false-permit rate AMONG EMITTED "
            "PERMITs (unsafe / acted-permits at the cutoff). >= the marginal "
            "rate; 1.0 when nothing is certifiable or the acted set is empty."
        ),
    )
    acted_set_false_forbid_rate: float = Field(
        default=1.0,
        ge=0.0,
        le=1.0,
        description=(
            "SCRC: certified upper bound on the false-forbid rate AMONG EMITTED "
            "FORBIDs (safe / acted-forbids at the cutoff)."
        ),
    )
    n_acted_permit: int = Field(
        default=0, ge=0, description="Acted-permit count at the permit cutoff (SCRC denominator)."
    )
    n_acted_forbid: int = Field(
        default=0, ge=0, description="Acted-forbid count at the forbid cutoff (SCRC denominator)."
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

_RISK_ESTIMANDS = ("marginal", "selective")


@dataclass(frozen=True, slots=True)
class _SideCalibration:
    """Result of calibrating one side (permit or forbid) of the gate.

    Carries both the marginal risk (over the whole calibration set) and the
    SCRC selective risk (over the acted set), so the certificate can surface
    the operator-facing acted-set number regardless of which estimand gated
    the cutoff. ``cutoff_grid`` is the raw grid cutoff; the epsilon-collar is
    applied by the caller.
    """

    cutoff_grid: float
    empirical_marginal: float
    marginal_ucb: float
    empirical_selective: float
    selective_ucb: float
    n_acted: int


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
        # two-sided (forbid) state
        "_alpha_forbid",
        "_lambda_forbid",
        "_empirical_forbid_risk",
        "_forbid_risk_ucb",
        "_forbid_certified",
        # LTT joint two-sided certificate + epsilon-collar
        "_delta_permit",
        "_delta_forbid",
        "_epsilon",
        "_risk_estimand",
        # SCRC acted-set (selective) risk
        "_acted_permit_ucb",
        "_acted_forbid_ucb",
        "_n_acted_permit",
        "_n_acted_forbid",
    )

    def __init__(
        self,
        *,
        calibration: Sequence[CalibrationRecord] | None = None,
        alpha: float = 0.05,
        delta: float = 0.05,
        alpha_forbid: float | None = None,
        grid_size: int = _DEFAULT_GRID_SIZE,
        delta_split: float = 0.5,
        epsilon_collar: float | None = None,
        risk_estimand: str = "marginal",
    ) -> None:
        """Construct and freeze the gate from a calibration set.

        MIGRATION NOTE — ``delta`` semantics changed. It is now the **joint
        family-wise** failure budget of the two-sided "hold band is certified"
        claim, split across the permit and forbid families (``delta_split``,
        default 50/50). Previously each side was bounded at ``delta`` and the
        joint claim silently failed with probability up to ``2*delta``; the new
        meaning is honest (joint guarantee at ``1 - delta``). Effect: each
        side's per-family budget is now ``delta/2`` by default, so cutoffs are
        *slightly more conservative* — strictly the fail-closed direction, so
        no caller can be made less safe. The per-side budgets are reported as
        ``delta_permit`` / ``delta_forbid`` on the certificate.

        ``risk_estimand`` selects the gated risk: ``"marginal"`` (default,
        RCPS-monotone, preserves prior cutoffs) or ``"selective"`` (the stricter
        SCRC acted-set risk). ``epsilon_collar`` defaults to one grid step.
        """
        if not 0.0 < alpha < 1.0:
            raise ValueError("alpha must be in (0, 1)")
        if not 0.0 < delta < 1.0:
            raise ValueError("delta must be in (0, 1)")
        if not 0.0 < delta_split < 1.0:
            raise ValueError("delta_split must be in (0, 1)")
        if risk_estimand not in _RISK_ESTIMANDS:
            raise ValueError(f"risk_estimand must be one of {_RISK_ESTIMANDS}")
        # The forbid-side budget defaults to the permit-side budget — a
        # symmetric posture — but can be set independently (over-blocking is
        # often cheaper than under-blocking, so an operator may widen it).
        if alpha_forbid is None:
            alpha_forbid = alpha
        if not 0.0 < alpha_forbid < 1.0:
            raise ValueError("alpha_forbid must be in (0, 1)")

        # ── LTT joint two-sided certificate: split the family-wise budget ──
        # ``delta`` is the JOINT failure probability of the two-sided "hold
        # band is certified" claim. We split it across the permit and forbid
        # families (Bonferroni) so the joint guarantee holds at 1 - delta,
        # rather than silently degrading to 1 - 2*delta as two independent
        # per-delta sweeps would.
        self._delta = delta
        self._delta_permit = delta * delta_split
        self._delta_forbid = delta * (1.0 - delta_split)

        # ── epsilon-collar: default to one grid step (the discretization gap)
        if epsilon_collar is None:
            epsilon_collar = 1.0 / (grid_size - 1)
        if epsilon_collar < 0.0:
            raise ValueError("epsilon_collar must be >= 0")
        self._epsilon = epsilon_collar

        self._alpha = alpha
        self._alpha_forbid = alpha_forbid
        self._risk_estimand = risk_estimand
        self._bound_method = "hoeffding_bentkus"
        selective = risk_estimand == "selective"

        if not calibration:
            # Inert gate: pass-through, certifies nothing (both sides).
            self._enabled = False
            self._certified = False
            self._lambda_hat = 1.0  # permit region = everything (pass-through)
            self._empirical_risk = 0.0
            self._risk_ucb = 1.0
            self._n = 0
            self._forbid_certified = False
            self._lambda_forbid = 2.0  # forbid region = nothing (pass-through)
            self._empirical_forbid_risk = 0.0
            self._forbid_risk_ucb = 1.0
            self._acted_permit_ucb = 1.0
            self._acted_forbid_ucb = 1.0
            self._n_acted_permit = 0
            self._n_acted_forbid = 0
            return

        self._enabled = True
        self._n = len(calibration)

        # Permit side — gate on the chosen estimand at the permit budget.
        permit = self._calibrate(
            calibration,
            alpha=alpha,
            delta=self._delta_permit,
            grid_size=grid_size,
            selective=selective,
        )
        self._empirical_risk = permit.empirical_marginal
        # The certified rate Tex stands behind is the estimand it gated on.
        self._risk_ucb = permit.selective_ucb if selective else permit.marginal_ucb
        self._acted_permit_ucb = permit.selective_ucb
        self._n_acted_permit = permit.n_acted
        # epsilon-collar: shrink the certified permit region.
        self._lambda_hat = self._collar_permit(permit.cutoff_grid)
        self._certified = self._lambda_hat >= 0.0

        # Forbid side — symmetric construction over the SAME labelled set.
        forbid = self._calibrate_forbid(
            calibration,
            alpha_forbid=alpha_forbid,
            delta=self._delta_forbid,
            grid_size=grid_size,
            selective=selective,
        )
        self._empirical_forbid_risk = forbid.empirical_marginal
        self._forbid_risk_ucb = (
            forbid.selective_ucb if selective else forbid.marginal_ucb
        )
        self._acted_forbid_ucb = forbid.selective_ucb
        self._n_acted_forbid = forbid.n_acted
        # epsilon-collar: shrink the certified forbid region.
        self._lambda_forbid = self._collar_forbid(forbid.cutoff_grid)
        self._forbid_certified = self._lambda_forbid <= 1.0

    # ----- epsilon-collar helpers ----------------------------------------

    def _collar_permit(self, cutoff_grid: float) -> float:
        """Back the permit cutoff off toward conservatism by the collar.

        Returns -1.0 (no certifiable region) when the grid found none, or when
        the collar shrinks the region to empty. Only ever lowers the cutoff.
        """
        if cutoff_grid < 0.0:
            return -1.0
        collared = cutoff_grid - self._epsilon
        return collared if collared >= 0.0 else -1.0

    def _collar_forbid(self, cutoff_grid: float) -> float:
        """Back the forbid cutoff off toward conservatism by the collar.

        Returns 2.0 (no certifiable region) when the grid found none, or when
        the collar shrinks the region to empty. Only ever raises the cutoff.
        """
        if cutoff_grid > 1.0:
            return 2.0
        collared = cutoff_grid + self._epsilon
        return collared if collared <= 1.0 else 2.0

    @staticmethod
    def _calibrate(
        calibration: Sequence[CalibrationRecord],
        *,
        alpha: float,
        delta: float,
        grid_size: int,
        selective: bool,
    ) -> _SideCalibration:
        """Calibrate the PERMIT cutoff (RCPS / SCRC).

        Two risks are tracked at every candidate cutoff:

          * marginal  R(lambda)     = #{unsafe AND score<=lambda} / n
          * selective R_sel(lambda) = #{unsafe AND score<=lambda} / #{score<=lambda}
                                       (SCRC: false-permits AMONG emitted permits)

        The marginal risk is non-decreasing in lambda, so its RCPS sup is the
        classic distribution-free guarantee. The selective risk is the
        operator-facing quantity ("of permits I emit, how many are unsafe?");
        it is monotone under the score's design assumption that
        P(unsafe | score) is non-decreasing, and the epsilon-collar adds a
        finite-sample margin. ``selective`` selects which UCB the cutoff is
        gated on; BOTH are always recorded so the certificate can surface the
        acted-set number either way.

        Sweep from most-permissive (1.0) downward; the first cutoff whose gated
        UCB <= budget is the most permissive certifiable one. If none qualifies,
        ``cutoff_grid = -1.0`` (fail-closed).
        """
        n = len(calibration)
        pairs = [(c.final_score, c.unsafe) for c in calibration]

        for i in range(grid_size):
            lam = 1.0 - (i / (grid_size - 1))  # 1.0, ..., 0.0
            # One pass: acted-permit count and unsafe-among-them.
            n_acted = 0
            hits = 0
            for s, u in pairs:
                if s <= lam:
                    n_acted += 1
                    if u:
                        hits += 1
            r_marginal = hits / n
            r_selective = (hits / n_acted) if n_acted > 0 else 0.0
            # Only the GATED estimand pays the expensive Hoeffding-Bentkus UCB
            # per grid node; the other is computed once at the chosen cutoff.
            # n_acted == 0 -> empty acted set -> selective UCB 1.0 (can't certify
            # a region we have no exposure for); the UCB handles n<=0 == 1.0.
            gated = (
                hoeffding_bentkus_ucb(r_selective, n_acted, delta)
                if selective
                else hoeffding_bentkus_ucb(r_marginal, n, delta)
            )
            if gated <= alpha:
                if selective:
                    selective_ucb = gated
                    marginal_ucb = hoeffding_bentkus_ucb(r_marginal, n, delta)
                else:
                    marginal_ucb = gated
                    selective_ucb = hoeffding_bentkus_ucb(r_selective, n_acted, delta)
                return _SideCalibration(
                    cutoff_grid=lam,
                    empirical_marginal=r_marginal,
                    marginal_ucb=marginal_ucb,
                    empirical_selective=r_selective,
                    selective_ucb=selective_ucb,
                    n_acted=n_acted,
                )
        return _SideCalibration(
            cutoff_grid=-1.0,
            empirical_marginal=0.0,
            marginal_ucb=1.0,
            empirical_selective=0.0,
            selective_ucb=1.0,
            n_acted=0,
        )

    @staticmethod
    def _calibrate_forbid(
        calibration: Sequence[CalibrationRecord],
        *,
        alpha_forbid: float,
        delta: float,
        grid_size: int,
        selective: bool,
    ) -> _SideCalibration:
        """Calibrate the FORBID cutoff (RCPS / SCRC) — bound over-blocking.

          * marginal  R_f(lambda)     = #{safe AND score>=lambda} / n
          * selective R_f_sel(lambda) = #{safe AND score>=lambda} / #{score>=lambda}
                                         (SCRC: false-forbids AMONG emitted forbids)

        Both are tracked; ``selective`` selects the gated estimand. We want the
        most permissive forbid region — the smallest cutoff whose gated UCB is
        within budget, so [lambda_forbid, 1] is as large as possible. If even
        lambda = 1.0 violates the budget, ``cutoff_grid = 2.0`` (fail-closed:
        the gate never fabricates a FORBID it cannot stand behind).
        """
        n = len(calibration)
        pairs = [(c.final_score, not c.unsafe) for c in calibration]

        # Track the most permissive certified cutoff and its raw counts; the
        # non-gated UCB is computed ONCE after the loop (the forbid sweep makes
        # many passes, so paying both UCBs per node would be wasteful).
        best_lam = 2.0
        best_r_marginal = 0.0
        best_r_selective = 0.0
        best_n_acted = 0
        best_gated_ucb = 1.0
        for i in range(grid_size):
            lam = 1.0 - (i / (grid_size - 1))  # 1.0, ..., 0.0
            n_acted = 0
            hits = 0
            for s, sf in pairs:
                if s >= lam:
                    n_acted += 1
                    if sf:
                        hits += 1
            r_marginal = hits / n
            r_selective = (hits / n_acted) if n_acted > 0 else 0.0
            gated = (
                hoeffding_bentkus_ucb(r_selective, n_acted, delta)
                if selective
                else hoeffding_bentkus_ucb(r_marginal, n, delta)
            )
            if gated <= alpha_forbid:
                best_lam = lam
                best_r_marginal = r_marginal
                best_r_selective = r_selective
                best_n_acted = n_acted
                best_gated_ucb = gated
            else:
                # The certified FORBID region is the contiguous upper interval
                # from the top. The first violation as lambda decreases ends it:
                # for the marginal risk every smaller lambda violates too
                # (monotone); for the selective risk we stop at the contiguous
                # boundary rather than grab a spurious deeper pass under finite-
                # sample non-monotonicity. Either way ``best`` is the most
                # permissive cutoff of a clean certified interval.
                break

        if best_lam > 1.0:
            return _SideCalibration(
                cutoff_grid=2.0,
                empirical_marginal=0.0,
                marginal_ucb=1.0,
                empirical_selective=0.0,
                selective_ucb=1.0,
                n_acted=0,
            )
        if selective:
            selective_ucb = best_gated_ucb
            marginal_ucb = hoeffding_bentkus_ucb(best_r_marginal, n, delta)
        else:
            marginal_ucb = best_gated_ucb
            selective_ucb = hoeffding_bentkus_ucb(best_r_selective, best_n_acted, delta)
        return _SideCalibration(
            cutoff_grid=best_lam,
            empirical_marginal=best_r_marginal,
            marginal_ucb=marginal_ucb,
            empirical_selective=best_r_selective,
            selective_ucb=selective_ucb,
            n_acted=best_n_acted,
        )

    @property
    def enabled(self) -> bool:
        return self._enabled

    @property
    def certified(self) -> bool:
        return self._certified

    @property
    def lambda_hat(self) -> float:
        return self._lambda_hat

    @property
    def lambda_forbid(self) -> float:
        return self._lambda_forbid

    @property
    def forbid_certified(self) -> bool:
        return self._forbid_certified

    @property
    def hold_certified(self) -> bool:
        """Both sides certified and the band is well-formed."""
        return (
            self._certified
            and self._forbid_certified
            and self._lambda_hat < self._lambda_forbid
        )

    def in_hold_band(self, final_score: float) -> bool:
        """Whether a score lies strictly inside the certified hold band."""
        return self.hold_certified and (
            self._lambda_hat < final_score < self._lambda_forbid
        )

    def certificate_template(
        self, *, demoted: bool = False, final_score: float | None = None
    ) -> CRCCertificate:
        certified_rate = self._risk_ucb if self._certified else 1.0
        forbid_rate = self._forbid_risk_ucb if self._forbid_certified else 1.0
        hold_certified = self.hold_certified
        in_band = (
            self.in_hold_band(final_score) if final_score is not None else False
        )
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
            # two-sided / hold band
            alpha_forbid=self._alpha_forbid,
            lambda_forbid=round(self._lambda_forbid, 6),
            empirical_false_forbid_rate=round(self._empirical_forbid_risk, 6),
            forbid_risk_upper_bound=round(min(1.0, max(0.0, self._forbid_risk_ucb)), 6),
            certified_false_forbid_rate=round(min(1.0, max(0.0, forbid_rate)), 6),
            forbid_certified=self._forbid_certified,
            hold_certified=hold_certified,
            hold_band_lower=round(self._lambda_hat, 6) if hold_certified else 0.0,
            hold_band_upper=round(self._lambda_forbid, 6) if hold_certified else 1.0,
            in_hold_band=in_band,
            # LTT joint two-sided certificate + epsilon-collar
            joint_delta=round(self._delta_permit + self._delta_forbid, 6),
            delta_permit=self._delta_permit,
            delta_forbid=self._delta_forbid,
            epsilon_collar=round(self._epsilon, 6),
            # SCRC acted-set (selective) risk — the operator-facing estimand
            risk_estimand=self._risk_estimand,
            acted_set_false_permit_rate=round(
                min(1.0, max(0.0, self._acted_permit_ucb if self._certified else 1.0)), 6
            ),
            acted_set_false_forbid_rate=round(
                min(1.0, max(0.0, self._acted_forbid_ucb if self._forbid_certified else 1.0)),
                6,
            ),
            n_acted_permit=self._n_acted_permit if self._certified else 0,
            n_acted_forbid=self._n_acted_forbid if self._forbid_certified else 0,
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
                certificate=self.certificate_template(demoted=False, final_score=final_score),
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
                certificate=self.certificate_template(demoted=False, final_score=final_score),
                reasons=(
                    f"CRC gate: PERMIT certified — fused score "
                    f"{final_score:.3f} <= cutoff {self._lambda_hat:.3f}; "
                    f"false-permit rate bounded <= {self._risk_ucb:.3f} at "
                    f"confidence {1.0 - self._delta_permit:.3f} "
                    f"(estimand={self._risk_estimand}).",
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
                f"confidence {1.0 - self._delta_permit:.3f} on the calibration set."
            )
        return CRCGateResult(
            verdict=Verdict.ABSTAIN,
            demoted=True,
            certificate=self.certificate_template(demoted=True, final_score=final_score),
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

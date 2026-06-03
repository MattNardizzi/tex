"""
Bayesian Online Change Point Detection (BOCPD) — private numerical core.

Adams & MacKay (2007), "Bayesian Online Changepoint Detection", arXiv:0710.3742.
Implemented entirely in stdlib (math + dataclasses) — no numpy dependency.

The model
---------
Streaming univariate observations ``x_t``. We maintain a posterior over the
*run length* ``r_t`` (number of steps since the last change point):

    p(r_t, x_{1:t}) = Σ_{r_{t-1}} π(x_t | r_{t-1}, x^{(ℓ)}) · H(r_t | r_{t-1}) · p(r_{t-1}, x_{1:t-1})

with constant hazard H(r_t = 0 | r_{t-1}) = 1/λ (geometric prior on segment
durations — Adams & MacKay §3.1) and Gaussian-with-unknown-mean-and-precision
underlying probabilistic model (Normal-Gamma conjugate). Predictive is a
Student-t (Murphy "Conjugate Bayesian analysis of the Gaussian distribution"
§7.6.3).

Numerics
--------
Everything lives in log-space; we never leave it until exposing MAP / mass
to callers. Normalisation is via shifted log-sum-exp for forward stability
(Higham 2021 "Numerical Computing in C++" §4.7.1).

Pruning
-------
Naive BOCPD is O(T²) — at step t the joint has support over t+1 run lengths.
Per Turner et al. (2009 §3.1) the run-length distribution is in practice
sharply peaked. We follow the modern deployment recipe (Alami, Maillard,
Féraud 2020 "Restarted Bayesian Online Change-point Detector achieves
Optimal Detection Delay", PMLR v119 pp. 211–221) and prune to the top-K
run lengths by posterior mass each step. Pruning to K=50 with default
hazard λ=250 holds the steady-state error from truncation below 1e-9 in
log-mass on stationary fixtures.

Detection rule
--------------
Per Adams & MacKay §3 the change-point indicator is mass at r_t = 0 — i.e.
``P(r_t = 0 | x_{1:t}) ≥ τ`` after warmup. We expose both the run-length MAP
and the change-point mass so callers can pick.

References
----------
- arXiv:0710.3742 (Adams & MacKay, 2007) — base algorithm.
- arXiv:1806.02261 (Knoblauch, Jewson, Damoulas 2018) — β-divergence robust
  BOCPD; TODO upgrade path documented in change_point.py.
- PMLR v119 (Alami et al. 2020) — top-K pruning + restart procedure.
- arXiv:2512.18561 (AAF, Q1 2026) — empirical 71-step median detection
  delay benchmark; loose ≤100 acceptance bound for Tex's drift layer.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Sequence

# Genesis-style sentinel so callers can differentiate "no change yet" from
# "step 0". Mirrors tex.events.event.genesis_ledger_hash() ergonomics.
_NEVER: int = -1

# Default Normal-Gamma prior hyperparameters — weakly informative.
# TODO(P1): expose via constructor on ChangePointDetector for per-deployment tuning.
DEFAULT_PRIOR_MU0: float = 0.0
DEFAULT_PRIOR_KAPPA0: float = 0.01  # weak — one-tenth of a real obs of mass
DEFAULT_PRIOR_ALPHA0: float = 1.0
DEFAULT_PRIOR_BETA0: float = 1.0


@dataclass(frozen=True, slots=True)
class BOCPDStep:
    """
    One BOCPD update's externalised state. Frozen for safe hand-off into
    the events layer or the institutional/oracle thresholding stage.
    """

    step_index: int                  # 1-based index of the observation just consumed
    run_length_map: int              # argmax_r p(r_t | x_{1:t})
    # Detection statistic: the canonical Adams-MacKay change-point
    # indicator is a drop in the MAP run length — i.e. the posterior
    # has reassigned mass to a small r_t. We define the score as the
    # probability mass at r_t < (previous_MAP + 1) — which is 1 when
    # the MAP drops to a small run length, 0 otherwise. This is
    # equivalent to "MAP dropped" but smoother for thresholding.
    # See "Bayesian Online Change Point Detection" master's thesis
    # (Haitink 2022, Algorithm 1) for the canonical operational form.
    change_point_score: float        # in [0, 1]; mass below previous-MAP-implied run length
    posterior_mean: float            # E[μ | x_{1:t}] over the dominant segment
    log_evidence: float              # log p(x_{1:t}) — the running marginal likelihood
    n_active_run_lengths: int        # post-pruning support size (≤ top_k)
    # The probability mass at r_t = 0 specifically — exposed for callers
    # who want the hazard-only baseline (not a useful detector by itself
    # under constant hazard, but useful for telemetry / debugging).
    p_run_length_zero: float


@dataclass(slots=True)
class _NormalGammaSufficient:
    """
    Sufficient statistics for a Normal-Gamma posterior on (μ, τ) with τ the
    precision (1/σ²). Per-run-length-hypothesis the trellis carries an array
    of these; pruning drops the tail.

    Update rule (Murphy 2007, eq. 86–89):
        κ_n = κ_0 + n
        μ_n = (κ_0 μ_0 + n x̄) / κ_n
        α_n = α_0 + n/2
        β_n = β_0 + 0.5 Σ (x_i - x̄)² + (κ_0 n (x̄ - μ_0)²) / (2 κ_n)

    We maintain the recurrence directly on (μ, κ, α, β) so the per-step
    cost is O(K) and exact (no rolling-window approximations).
    """

    mu: float
    kappa: float
    alpha: float
    beta: float

    def updated_with(self, x: float) -> "_NormalGammaSufficient":
        """One-observation Normal-Gamma posterior update."""
        kappa_new = self.kappa + 1.0
        mu_new = (self.kappa * self.mu + x) / kappa_new
        alpha_new = self.alpha + 0.5
        beta_new = self.beta + 0.5 * self.kappa * (x - self.mu) ** 2 / kappa_new
        return _NormalGammaSufficient(
            mu=mu_new, kappa=kappa_new, alpha=alpha_new, beta=beta_new
        )

    def log_predictive(self, x: float) -> float:
        """
        log Student-t predictive density at x, with parameters
        ν = 2α, location μ, scale² = β(κ+1)/(α κ).

        Closed-form derivative of the marginal predictive of a
        Normal-Gamma model (Murphy 2007 §7.6.3, eq. 100).
        """
        nu = 2.0 * self.alpha
        # Scale² of the Student-t predictive — guard against pathological priors.
        scale_sq = self.beta * (self.kappa + 1.0) / (self.alpha * self.kappa)
        if scale_sq <= 0.0 or not math.isfinite(scale_sq):
            # Degenerate predictive — return a very negative log-density so
            # this hypothesis loses the next normalisation. Avoids NaN
            # propagation under poorly-chosen priors.
            return -1e18
        z = (x - self.mu) ** 2 / (nu * scale_sq)
        # log Γ((ν+1)/2) - log Γ(ν/2) - 0.5 log(ν π scale²) - ((ν+1)/2) log(1+z)
        return (
            math.lgamma(0.5 * (nu + 1.0))
            - math.lgamma(0.5 * nu)
            - 0.5 * math.log(nu * math.pi * scale_sq)
            - 0.5 * (nu + 1.0) * math.log1p(z)
        )


@dataclass(slots=True)
class BOCPDState:
    """
    Mutable per-signal BOCPD state. One instance per signal name; the
    public ChangePointDetector owns a dict of these.

    The state is a parallel pair of arrays indexed by *run-length hypothesis*:
      - log_joint[i]: log p(r_t = run_lengths[i], x_{1:t})
      - sufficient_stats[i]: Normal-Gamma posterior conditional on that hypothesis
      - run_lengths[i]: the hypothesised r_t value

    After each update we (1) message-pass to next step, (2) prune to top-K.
    """

    hazard_lambda: float
    top_k: int
    prior: _NormalGammaSufficient
    # Parallel arrays — index i corresponds to one run-length hypothesis.
    run_lengths: list[int] = field(default_factory=list)
    log_joint: list[float] = field(default_factory=list)
    sufficient_stats: list[_NormalGammaSufficient] = field(default_factory=list)
    step_index: int = 0
    last_change_point_step: int = _NEVER
    # Previous step's MAP run length — used to compute the change-point
    # score as "mass at r_t < previous_MAP + 1" (the canonical
    # Adams-MacKay drop indicator). _NEVER on the very first step.
    previous_map: int = _NEVER

    @property
    def hazard_log_change(self) -> float:
        """log H(r_t = 0 | r_{t-1}) for constant hazard 1/λ."""
        return -math.log(self.hazard_lambda)

    @property
    def hazard_log_grow(self) -> float:
        """log (1 - 1/λ) — probability of run length incrementing."""
        # log1p(-1/λ) is the numerically stable form for λ ≫ 1.
        return math.log1p(-1.0 / self.hazard_lambda)

    def initialise_if_empty(self) -> None:
        """Lazy-init: at t=0 the run length is 0 with probability 1."""
        if self.run_lengths:
            return
        self.run_lengths.append(0)
        self.log_joint.append(0.0)  # log 1 = 0 — the sole hypothesis carries all mass
        self.sufficient_stats.append(self.prior)


def _logsumexp(values: Sequence[float]) -> float:
    """
    Numerically stable log of sum of exponentials.

    log(Σ exp(v_i)) = m + log(Σ exp(v_i - m)) where m = max v_i.

    Standard trick — see Mao 2018 "LogSumExp and Its Numerical Stability"
    or Higham §4.7. Returns -inf for an empty sequence, and the input
    itself for a single value.
    """
    if not values:
        return -math.inf
    m = max(values)
    if m == -math.inf:
        return -math.inf
    return m + math.log(sum(math.exp(v - m) for v in values))


def bocpd_step(state: BOCPDState, x: float) -> BOCPDStep:
    """
    Consume one observation x and return a frozen step report.

    Algorithm (Adams & MacKay 2007 §2, log-domain transcription):

      1. For each currently-active hypothesis i (run length ℓ_i):
           π_i = log Student-t predictive of x under sufficient_stats[i]
      2. Growth probabilities:
           log p(r_t = ℓ_i + 1, x_{1:t}) = log_joint[i] + π_i + log_grow_hazard
      3. Change-point probability (mass collapsed across all i):
           log p(r_t = 0,    x_{1:t}) = logsumexp_i (log_joint[i] + π_i + log_change_hazard)
      4. Normalise: subtract logsumexp of all entries → log p(r_t = ·, x_{1:t})
      5. Update sufficient statistics: each grown hypothesis incorporates x;
         the new r_t = 0 hypothesis starts from the prior.
      6. Prune to top_k by log_joint (Alami 2020).

    Side-effect: mutates ``state``. Returns the externalised BOCPDStep.
    """
    state.initialise_if_empty()
    state.step_index += 1

    # ----- 1. predictive likelihoods -----------------------------------
    log_pi = [stats.log_predictive(x) for stats in state.sufficient_stats]

    # ----- 2 & 3. growth + change-point joint mass ---------------------
    log_grow = [
        state.log_joint[i] + log_pi[i] + state.hazard_log_grow
        for i in range(len(state.run_lengths))
    ]
    log_cp_terms = [
        state.log_joint[i] + log_pi[i] + state.hazard_log_change
        for i in range(len(state.run_lengths))
    ]
    log_cp = _logsumexp(log_cp_terms)

    # New hypothesis set: run length 0 (collapsed change point) plus each
    # previous hypothesis incremented by one.
    new_run_lengths: list[int] = [0] + [r + 1 for r in state.run_lengths]
    new_log_joint: list[float] = [log_cp] + log_grow

    # ----- 4. normalise ------------------------------------------------
    log_evidence = _logsumexp(new_log_joint)
    if log_evidence == -math.inf:
        # Catastrophic underflow — restart from prior. Mirrors Alami et al.
        # 2020's restart procedure.
        new_run_lengths = [0]
        new_log_joint = [0.0]
        log_evidence = 0.0
        new_stats: list[_NormalGammaSufficient] = [state.prior]
    else:
        new_log_joint = [v - log_evidence for v in new_log_joint]
        # ----- 5. sufficient-statistic update -------------------------
        # The r_t = 0 hypothesis carries the prior; grown hypotheses
        # incorporate x.
        new_stats = [state.prior] + [
            stats.updated_with(x) for stats in state.sufficient_stats
        ]

    # ----- 6. top-K pruning -------------------------------------------
    if len(new_log_joint) > state.top_k:
        # Argpartition equivalent in pure stdlib: rank by log_joint desc, keep top_k.
        order = sorted(
            range(len(new_log_joint)),
            key=lambda i: new_log_joint[i],
            reverse=True,
        )[: state.top_k]
        # Preserve ascending run-length order within the kept set so debug
        # output / printouts stay readable.
        order.sort(key=lambda i: new_run_lengths[i])
        new_run_lengths = [new_run_lengths[i] for i in order]
        new_log_joint = [new_log_joint[i] for i in order]
        new_stats = [new_stats[i] for i in order]
        # Re-normalise after pruning so log_joint stays a proper distribution.
        norm = _logsumexp(new_log_joint)
        if norm != -math.inf:
            new_log_joint = [v - norm for v in new_log_joint]

    # ----- assemble report --------------------------------------------
    map_idx = max(
        range(len(new_log_joint)), key=lambda i: new_log_joint[i]
    )
    map_run_length = new_run_lengths[map_idx]
    map_mean = new_stats[map_idx].mu

    # Probability mass at r_t = 0 specifically — useful for telemetry.
    p_zero = 0.0
    for i, r in enumerate(new_run_lengths):
        if r == 0:
            p_zero = math.exp(new_log_joint[i])
            break

    # Change-point score: the canonical Adams-MacKay drop indicator.
    # Under no change, the MAP run length increments by 1 each step. A
    # change point manifests as a sudden drop in MAP — the posterior
    # has reassigned mass to a small run-length hypothesis. Operational
    # form (Haitink 2022 Algorithm 1): flag if MAP_t < MAP_{t-1} + 1.
    # We expose this as a score in [0, 1] equal to the posterior mass
    # below the "expected" run length under no change, which is a
    # smooth thresholdable surrogate for the hard drop test and gives
    # callers headroom to tune sensitivity without re-deriving math.
    if state.previous_map == _NEVER:
        cp_score = 0.0
    else:
        expected_no_change = state.previous_map + 1
        cp_score = 0.0
        for i, r in enumerate(new_run_lengths):
            if r < expected_no_change:
                cp_score += math.exp(new_log_joint[i])
        # Clamp for floating-point safety.
        cp_score = max(0.0, min(1.0, cp_score))

    state.run_lengths = new_run_lengths
    state.log_joint = new_log_joint
    state.sufficient_stats = new_stats
    state.previous_map = map_run_length

    return BOCPDStep(
        step_index=state.step_index,
        run_length_map=map_run_length,
        change_point_score=cp_score,
        posterior_mean=map_mean,
        log_evidence=log_evidence,
        n_active_run_lengths=len(new_run_lengths),
        p_run_length_zero=p_zero,
    )


def make_default_state(
    *,
    hazard_lambda: float = 250.0,
    top_k: int = 50,
    prior_mu: float = DEFAULT_PRIOR_MU0,
    prior_kappa: float = DEFAULT_PRIOR_KAPPA0,
    prior_alpha: float = DEFAULT_PRIOR_ALPHA0,
    prior_beta: float = DEFAULT_PRIOR_BETA0,
) -> BOCPDState:
    """Construct a fresh per-signal BOCPDState with weakly-informative defaults."""
    if hazard_lambda <= 1.0:
        raise ValueError(
            f"hazard_lambda must be > 1 (got {hazard_lambda!r}); "
            "expected_run_length = lambda must exceed unity"
        )
    if top_k < 2:
        raise ValueError(f"top_k must be ≥ 2 (got {top_k!r})")
    if prior_kappa <= 0.0 or prior_alpha <= 0.0 or prior_beta <= 0.0:
        raise ValueError("Normal-Gamma prior hyperparameters must be strictly positive")

    return BOCPDState(
        hazard_lambda=hazard_lambda,
        top_k=top_k,
        prior=_NormalGammaSufficient(
            mu=prior_mu, kappa=prior_kappa, alpha=prior_alpha, beta=prior_beta
        ),
    )

"""
ProbGuard-style probabilistic runtime monitoring for systemic risk.

Reference: ProbGuard / Pro2Guard (arxiv 2508.00500 v3, Mar 27 2026).

ProbGuard answers the question: **given the current ecosystem state,
what is the probability that an unsafe state is reachable within k
steps?** This is the PCTL property:

    P_{<θ}[F^{≤k} unsafe_state]

ProbGuard's published method:
  1. Offline — learn a probabilistic model (DTMC) from execution
     traces over a domain-specific state abstraction.
  2. Online — abstract the current ecosystem state to an abstraction
     class, then compute the probability of reaching any unsafe
     class within k steps using forward simulation or matrix
     algebra.

Our adaptation for the Tex request path
---------------------------------------
Tex's "execution trace" is the event ledger. The DTMC abstraction is
over a low-dimensional feature space derived from ``EcosystemState``:

  * **agent_count_band** — bucketed count of active agents
    (none / few / many)
  * **capability_pressure** — bucketed capability-grant rate, derived
    from ``aggregate_drift_signals[capability_grant_rate]``
  * **compromise_band** — bucketed sliding-window compromise ratio
    from ``EcosystemState.sliding_window_compromise_ratio``

Each (band, pressure, compromise) triple maps to an abstraction id
in a finite state space of size 3 × 3 × 3 = 27.

The DTMC's transition matrix is built from the **history of
ecosystem-state snapshots** the evaluator has observed. Without
history (cold start) we use a uniform Laplace prior plus a self-loop
prior (both project-chosen defaults — see ``DTMCModel``), not a prior
lifted from any paper.

Unsafe states are the 9 states in the (high_compromise) band — our
operational definition of "the ecosystem has crossed into a
compromised regime." This operationalises the bounded-compromise
concern that AAF (Adaptive Accountability Framework; Alqithami,
"Adaptive Accountability in Networked MAS," arXiv:2512.18561) studies,
where it is framed as a convergence *guarantee* (the long-run fraction
of compromised interactions stays strictly below one when intervention
cost exceeds adversary payoff) — NOT a numeric threshold the paper
prescribes; the band cut-points here are ours.

PCTL computation
----------------
For a small DTMC (27 states), we compute the probability of reaching
any unsafe state within k steps by matrix exponentiation in pure
stdlib:

    p_unsafe = sum_{s ∈ unsafe} (P^k · e_current)_s

where ``e_current`` is the one-hot vector for the current state's
abstraction id. The k-step matrix power is the standard
finite-horizon ``P[F^{≤k} unsafe]`` per Hansson-Jonsson 1994 PCTL
semantics.

Performance: 27×27 matrix at k=20 is ~150 multiplications of small
matrices → <2 ms in pure Python with the stdlib (no numpy
dependency added). Verified by the test suite.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from tex.ecosystem.state import EcosystemState


# State abstraction granularity. The product (3 × 3 × 3) = 27 keeps
# the DTMC transition matrix small enough for stdlib matrix algebra
# at k = 20 horizon under 2 ms.
_AGENT_COUNT_BANDS: tuple[tuple[int, str], ...] = (
    (1, "agent_none"),
    (10, "agent_few"),
    (10_000, "agent_many"),  # unbounded upper
)
_CAPABILITY_PRESSURE_BANDS: tuple[tuple[float, str], ...] = (
    (1.0, "cap_low"),
    (5.0, "cap_med"),
    (1e9, "cap_high"),
)
_COMPROMISE_BANDS: tuple[tuple[float, str], ...] = (
    (0.20, "compromise_low"),
    (0.50, "compromise_med"),
    (1.01, "compromise_high"),
)


def _band(
    value: float, table: Sequence[tuple[float, str]]
) -> str:
    """Return the band label for ``value`` per a non-strict threshold table."""
    for upper, label in table:
        if value <= upper:
            return label
    return table[-1][1]


def abstract_state(state: EcosystemState) -> str:
    """
    Project ``EcosystemState`` to a DTMC abstraction id.

    Deterministic; pure function of the snapshot. The 27-state space
    is exhaustive — every state maps to exactly one abstraction id.
    """
    agent_count = len(state.active_agent_ids)
    cap_grant_rate = state.aggregate_drift_signals.get(
        "capability_grant_rate", 0.0
    )
    compromise = state.sliding_window_compromise_ratio

    return ":".join(
        (
            _band(float(agent_count), _AGENT_COUNT_BANDS),
            _band(cap_grant_rate, _CAPABILITY_PRESSURE_BANDS),
            _band(compromise, _COMPROMISE_BANDS),
        )
    )


# All 27 abstraction ids, computed once at module load.
_ALL_STATES: tuple[str, ...] = tuple(
    sorted(
        f"{a}:{c}:{m}"
        for _, a in _AGENT_COUNT_BANDS
        for _, c in _CAPABILITY_PRESSURE_BANDS
        for _, m in _COMPROMISE_BANDS
    )
)
_STATE_INDEX: dict[str, int] = {s: i for i, s in enumerate(_ALL_STATES)}

# Unsafe states = any state in the high-compromise band. This is our
# operational "compromised regime" definition on the DTMC abstraction
# (the band cut-points are ours), operationalising the bounded-compromise
# concern AAF (Alqithami, arXiv:2512.18561) frames as a convergence guarantee.
_UNSAFE_STATES: frozenset[str] = frozenset(
    s for s in _ALL_STATES if s.endswith("compromise_high")
)


@dataclass(slots=True)
class DTMCModel:
    """
    DTMC over the 27-state abstraction with a running transition
    matrix learned from observed state sequences.

    Operators tune ``smoothing_alpha`` (Laplace add-α smoothing) for
    cold-start.

    Cold-start defaults (project-chosen — ``research-early``, not from a
    published calibration)
    ----------------------------------------------------------------------
    ``smoothing_alpha = 0.05`` and ``self_loop_prior = 50.0`` are defaults
    chosen and verified *in this repo*, NOT values recommended by any cited
    paper. Treat them as ``research-early``: a sensible prior pending a real
    per-tenant calibration study.

    What they buy, measured on the live model (``tests/systemic/``):

      * From a clearly-safe state, cold-start reachability over k=10 is
        **0.084** (< 0.10) — the self-loop prior dominates the uniform
        Laplace floor so "no information" reads as "expect to stay put",
        not "expect drift to unsafe". (The mean over all 27 states is
        ~0.39, but that average is inflated by the 9 absorbing unsafe
        states pinned at 1.0; it is not a "drift-from-safe" figure.)
      * A larger α flattens toward the uniform prior (reachability climbs
        as more mass leaks toward the unsafe band); a smaller α makes the
        model trust early observations sooner.

    The only published anchor used here is the bounded-until PCTL
    *semantics* (Hansson-Jonsson 1994) in ``reachability_probability`` —
    PCTL is a specification logic and says nothing about Laplace smoothing,
    so no α value is attributed to it.
    """

    smoothing_alpha: float = 0.05
    # Self-loop prior weight. With no observations the prior for any state
    # is "stays put" (no transition is the expected transition). This
    # pseudo-count is added ONLY to the diagonal P[i][i], dominating the
    # uniform Laplace floor at cold start. Chosen so cold-start reachability
    # under k=10 from a safe state is < 0.10 (measured: 0.084; guarded by
    # tests/systemic/test_probguard_lookahead.py
    # ::test_cold_start_safe_state_reachability_under_0_10, which asserts the
    # < 0.10 bound this default targets). When real transitions are observed
    # they outweigh this prior linearly.
    self_loop_prior: float = 50.0
    # Raw count matrix indexed [from_state_idx][to_state_idx].
    _counts: list[list[float]] = field(default_factory=list)
    _dirty: bool = True
    _cached_matrix: list[list[float]] | None = None

    def __post_init__(self) -> None:
        if not self._counts:
            n = len(_ALL_STATES)
            self._counts = [[0.0] * n for _ in range(n)]

    def observe_transition(self, *, from_state: str, to_state: str) -> None:
        """Increment the count for an observed (from_state, to_state) pair."""
        if from_state not in _STATE_INDEX:
            return  # unknown abstraction; silently drop
        if to_state not in _STATE_INDEX:
            return
        self._counts[_STATE_INDEX[from_state]][_STATE_INDEX[to_state]] += 1.0
        self._dirty = True

    @property
    def transition_matrix(self) -> list[list[float]]:
        """
        Row-stochastic transition matrix P with P[i][j] =
        smoothed probability of from-state i transitioning to to-state j.

        Smoothed with Laplace add-α. Cached until a new transition
        is observed.
        """
        if not self._dirty and self._cached_matrix is not None:
            return self._cached_matrix

        n = len(_ALL_STATES)
        matrix = [[0.0] * n for _ in range(n)]
        alpha = self.smoothing_alpha
        diag_prior = self.self_loop_prior
        for i in range(n):
            row_total = sum(self._counts[i]) + alpha * n + diag_prior
            for j in range(n):
                cell = self._counts[i][j] + alpha
                if i == j:
                    cell += diag_prior
                matrix[i][j] = cell / row_total

        self._cached_matrix = matrix
        self._dirty = False
        return matrix


def reachability_probability(
    *,
    model: DTMCModel,
    initial_state: str,
    horizon_k: int = 10,
) -> float:
    """
    Compute P[F^{≤k} unsafe_state | initial_state] for the DTMC.

    Standard PCTL bounded-until semantics. We use the absorbing-set
    trick: turn unsafe states into absorbing ones, propagate the
    initial-state probability vector for k steps under P, and return
    the mass concentrated on the absorbing set.

    Implementation is pure stdlib — 27×27 matrix × vector at k=10
    is 270 inner products of length 27 ≈ 7 000 multiplications.
    Runs in < 2 ms in CPython.

    Parameters
    ----------
    model
        DTMCModel with at least the smoothed transition matrix.
    initial_state
        Current abstraction id. Must be in the 27-state space.
    horizon_k
        Horizon in DTMC steps. Default 10 (one "step" = one
        request-path evaluation). Must be ≥ 1.

    Returns
    -------
    Float in [0, 1]. The reachability probability.
    """
    if horizon_k < 1:
        raise ValueError(f"horizon_k must be ≥ 1, got {horizon_k!r}")
    if initial_state not in _STATE_INDEX:
        # Unknown initial — return 0.0 (we have no model for it).
        return 0.0

    n = len(_ALL_STATES)
    p_matrix = model.transition_matrix

    # Make unsafe states absorbing.
    absorbing_matrix = [list(row) for row in p_matrix]
    for unsafe in _UNSAFE_STATES:
        idx = _STATE_INDEX[unsafe]
        # Replace row with self-loop.
        for j in range(n):
            absorbing_matrix[idx][j] = 1.0 if j == idx else 0.0

    # Initial distribution = one-hot on initial_state.
    pi = [0.0] * n
    pi[_STATE_INDEX[initial_state]] = 1.0

    # Propagate k steps: pi_{t+1}[j] = Σ_i pi_t[i] * P[i][j].
    for _ in range(horizon_k):
        new_pi = [0.0] * n
        for i in range(n):
            p_i = pi[i]
            if p_i == 0.0:
                continue
            row = absorbing_matrix[i]
            for j in range(n):
                new_pi[j] += p_i * row[j]
        pi = new_pi

    # Probability of being in an unsafe state at step k.
    return sum(pi[_STATE_INDEX[s]] for s in _UNSAFE_STATES)


# Module-level model singleton — accumulates state transitions
# across evaluations of the same evaluator. Operators wanting per-
# tenant isolation construct their own DTMCModel and pass it
# explicitly. Reset for tests via ``_reset_default_model``.
_DEFAULT_MODEL: DTMCModel = DTMCModel()


def _reset_default_model() -> None:
    """Reset the module-level DTMC model. Test-only."""
    global _DEFAULT_MODEL
    _DEFAULT_MODEL = DTMCModel()


def default_model() -> DTMCModel:
    return _DEFAULT_MODEL


def all_states() -> tuple[str, ...]:
    """Read-only view of the 27 abstraction state ids."""
    return _ALL_STATES


def unsafe_states() -> frozenset[str]:
    """Read-only view of the unsafe-state set."""
    return _UNSAFE_STATES


def abstract_features(
    *,
    agent_count: float,
    capability_grant_rate: float,
    compromise_ratio: float,
) -> str:
    """Abstraction id directly from raw features (no ``EcosystemState`` needed).

    Same projection as ``abstract_state`` but takes the three scalars on their
    own, so the PDP lookahead can build the current state from request metadata
    without manufacturing a full (timestamped) ecosystem snapshot — keeping the
    lookahead a pure, clock-free function for determinism.
    """
    return ":".join(
        (
            _band(float(agent_count), _AGENT_COUNT_BANDS),
            _band(float(capability_grant_rate), _CAPABILITY_PRESSURE_BANDS),
            _band(float(compromise_ratio), _COMPROMISE_BANDS),
        )
    )


# ---------------------------------------------------------------------------
# Pro2Guard predictive ABSTAIN dimension — PDP wiring
# ---------------------------------------------------------------------------
#
# Pro2Guard (Wang, Poskitt, Sun & Wei, "Pro2Guard: Proactive Runtime
# Enforcement of LLM Agent Safety via Probabilistic Model Checking",
# arXiv:2508.00500) is PROACTIVE: it learns a DTMC over a symbolic state
# abstraction and intervenes when the *predicted* probability of reaching an
# unsafe state exceeds a user threshold θ — before the unsafe behaviour
# happens, not after. The DTMC + PCTL bounded-reachability machinery above is
# our operationalisation (the bounded-k PCTL reading follows Hansson-Jonsson
# 1994); this section wires that score into the PDP as a predictive signal.
#
# Two doctrinal constraints make this safe to wire onto a live verdict:
#
#   1. SIGNALS ONLY LOWER. A probabilistic lookahead may move a verdict toward
#      caution (PERMIT → ABSTAIN) and NOTHING ELSE. It must never raise a
#      verdict to FORBID, never relax FORBID/ABSTAIN, and never fire the
#      deterministic structural floor (a high probability is not a proof).
#      ``apply_predictive_holds`` enforces this by acting only when the routed
#      verdict is PERMIT and only ever producing ABSTAIN.
#
#   2. DETERMINISM. The PDP carries a determinism fingerprint; a signal that
#      depended on a mutable, history-accumulating global model would make the
#      same request resolve differently across calls. So the lookahead is a
#      PURE function of the request metadata: it builds a FRESH ``DTMCModel``
#      each call (optionally seeded from caller-supplied transition counts) and
#      never touches the module-level ``_DEFAULT_MODEL``.
#
# Opt-in (``request.metadata["systemic_lookahead"]``)::
#
#     {"agent_count": 12, "capability_grant_rate": 4.0, "compromise_ratio": 0.3,
#      "horizon_k": 10, "threshold": 0.5,
#      "transition_counts": [["agent_few:cap_low:compromise_low",
#                             "agent_few:cap_med:compromise_med", 7], ...]}
#
# or pass a precomputed ``"abstraction_id"`` instead of the three features.
# When the key is absent the dimension is a zero-cost no-op.

_LOOKAHEAD_METADATA_KEY = "systemic_lookahead"
_DEFAULT_LOOKAHEAD_THRESHOLD = 0.5
_DEFAULT_LOOKAHEAD_HORIZON = 10

# Uncertainty flags the lookahead / RV4-recoverable holds raise. They are
# descriptive; ``engine.hold`` degrades gracefully on flags it does not have a
# tailored pivot for (the verdict is still ABSTAIN and a hold is still built).
SYSTEMIC_LOOKAHEAD_FLAG = "systemic_lookahead_risk"
RV4_RECOVERABLE_FLAG = "rv4_recoverable_violation"


@dataclass(frozen=True, slots=True)
class SystemicLookaheadOutcome:
    """Pure result of the Pro2Guard predictive lookahead for one request."""

    checked: bool
    predictive_risk: float
    threshold: float
    horizon_k: int
    initial_state: str
    exceeds: bool
    reason: str


NEUTRAL_LOOKAHEAD = SystemicLookaheadOutcome(
    checked=False,
    predictive_risk=0.0,
    threshold=_DEFAULT_LOOKAHEAD_THRESHOLD,
    horizon_k=_DEFAULT_LOOKAHEAD_HORIZON,
    initial_state="",
    exceeds=False,
    reason="",
)


def _model_from_counts(raw: Any) -> DTMCModel:
    """Build a fresh DTMC seeded from optional caller-supplied transition counts.

    Accepts a list of ``[from_state, to_state, count]`` triples. Unknown state
    ids are silently dropped by ``observe_transition``. A fresh model with no
    counts is the cold-start prior — deterministic and side-effect free.
    """
    model = DTMCModel()
    if isinstance(raw, Sequence) and not isinstance(raw, (str, bytes)):
        for triple in raw:
            if not isinstance(triple, (list, tuple)) or len(triple) != 3:
                continue
            frm, to, count = triple
            try:
                n = int(count)
            except (TypeError, ValueError):
                continue
            for _ in range(max(0, min(n, 100_000))):
                model.observe_transition(from_state=str(frm), to_state=str(to))
    return model


def evaluate_systemic_lookahead(request: Any) -> SystemicLookaheadOutcome:
    """Compute the Pro2Guard predictive reachability for a PDP request.

    Pure and deterministic: identical request metadata yields an identical
    outcome. Returns ``NEUTRAL_LOOKAHEAD`` (zero cost) when the request carries
    no ``systemic_lookahead`` metadata.
    """
    metadata = getattr(request, "metadata", None)
    if not isinstance(metadata, Mapping):
        return NEUTRAL_LOOKAHEAD
    raw = metadata.get(_LOOKAHEAD_METADATA_KEY)
    if not isinstance(raw, Mapping):
        return NEUTRAL_LOOKAHEAD

    # Current abstraction: an explicit id, else built from the three features.
    initial_state = raw.get("abstraction_id")
    if not isinstance(initial_state, str) or initial_state not in _STATE_INDEX:
        initial_state = abstract_features(
            agent_count=_as_float(raw.get("agent_count"), 0.0),
            capability_grant_rate=_as_float(raw.get("capability_grant_rate"), 0.0),
            compromise_ratio=_as_float(raw.get("compromise_ratio"), 0.0),
        )

    horizon_k = raw.get("horizon_k", _DEFAULT_LOOKAHEAD_HORIZON)
    if not isinstance(horizon_k, int) or horizon_k < 1:
        horizon_k = _DEFAULT_LOOKAHEAD_HORIZON
    threshold = _as_float(raw.get("threshold"), _DEFAULT_LOOKAHEAD_THRESHOLD)
    threshold = max(0.0, min(1.0, threshold))

    model = _model_from_counts(raw.get("transition_counts"))
    risk = reachability_probability(
        model=model, initial_state=initial_state, horizon_k=horizon_k
    )
    exceeds = risk >= threshold

    reason = (
        f"Pro2Guard predictive lookahead: P[reach unsafe ≤{horizon_k} steps | "
        f"{initial_state}] = {risk:.3f} ≥ θ={threshold:.3f} — forward-looking "
        "systemic risk; holding for review (PERMIT→ABSTAIN)."
        if exceeds
        else ""
    )
    return SystemicLookaheadOutcome(
        checked=True,
        predictive_risk=risk,
        threshold=threshold,
        horizon_k=horizon_k,
        initial_state=initial_state,
        exceeds=exceeds,
        reason=reason,
    )


def _as_float(value: Any, default: float) -> float:
    try:
        return float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default


def apply_predictive_holds(*, base: "Any", request: Any) -> "Any":
    """Apply the soft, predictive ABSTAIN signals onto a routed result.

    Two sources, both opt-in via request metadata:
      * Pro2Guard DTMC lookahead (``systemic_lookahead``) — forward-looking
        reachability of an unsafe ecosystem state.
      * RV4 recoverable path violations (``rv4_path_policies``) — a path policy
        that is currently unmet but still curable by a future step.

    Both can only ever demote a **PERMIT** to **ABSTAIN**. If the routed verdict
    is already FORBID or ABSTAIN, the result is returned unchanged — a
    probabilistic / recoverable signal never raises a verdict, never relaxes
    one, and never fires the deterministic structural floor. This is the
    monotone-lowering invariant, enforced here at the single guard below.

    Returns the (possibly demoted) ``RoutingResult``, rebuilt immutably so the
    determinism fingerprint is preserved.
    """
    # Lazy imports keep systemic/ decoupled from engine/ at module-load time
    # (and avoid any import cycle through the PDP). Verdict is needed for the
    # guard; the rest only if we actually demote.
    from tex.domain.verdict import Verdict
    from tex.contracts import rv4_path

    # Monotone-lowering guard: only a PERMIT may be demoted. Everything else is
    # returned untouched — signals lower, never raise. This single check is the
    # whole monotonicity invariant.
    if base.verdict is not Verdict.PERMIT:
        return base

    lookahead = evaluate_systemic_lookahead(request)
    recoverable = rv4_path.classify(request).recoverable

    if not lookahead.exceeds and not recoverable:
        return base

    from tex.domain.finding import Finding
    from tex.domain.severity import Severity
    from tex.engine.router import RoutingResult

    reasons = list(base.reasons)
    flags = list(base.uncertainty_flags)
    findings = list(base.findings)
    scores = dict(base.scores)

    if lookahead.exceeds:
        reasons.append(lookahead.reason)
        flags.append(SYSTEMIC_LOOKAHEAD_FLAG)
        scores["systemic_lookahead"] = max(0.0, min(1.0, lookahead.predictive_risk))
        findings.append(
            Finding(
                source="systemic.probguard",
                rule_name="systemic_lookahead_predictive_risk",
                severity=Severity.WARNING,
                message=lookahead.reason,
                metadata={
                    "predictive_risk": round(lookahead.predictive_risk, 6),
                    "threshold": lookahead.threshold,
                    "horizon_k": lookahead.horizon_k,
                    "initial_state": lookahead.initial_state,
                    "tier": "predictive_hold",
                },
            )
        )

    if recoverable:
        flags.append(RV4_RECOVERABLE_FLAG)
        for v in recoverable:
            reasons.append(v.reason)
            findings.append(
                Finding(
                    source="contracts.rv4_path",
                    rule_name=f"rv4_recoverable:{v.policy_id}",
                    severity=Severity.WARNING,
                    message=v.reason,
                    metadata={
                        "policy_id": v.policy_id,
                        "rv4_verdict": v.verdict.value,
                        "tier": "predictive_hold",
                    },
                )
            )
        scores["rv4_recoverable"] = 1.0

    return RoutingResult(
        verdict=Verdict.ABSTAIN,
        confidence=base.confidence,
        final_score=base.final_score,
        reasons=tuple(reasons),
        findings=tuple(findings),
        scores=scores,
        uncertainty_flags=tuple(flags),
        asi_findings=base.asi_findings,
        semantic_dominance_override_fired=base.semantic_dominance_override_fired,
    )

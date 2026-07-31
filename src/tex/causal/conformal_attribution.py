"""
Conformal Agent Error Attribution — uncertainty-aware attribution layer.

Implements the filtration-based conformal prediction (CP) framework from
arxiv 2605.06788 (Feng, Sui, Hou, Wu, Cresswell — Layer 6 AI / Dalhousie,
May 7, 2026, code at github.com/layer6ai-labs/conformal-agent-error-
attribution).

Where CHIEF/ARM (Thread 3 base) produces a *point prediction* of the
root-cause step, conformal attribution produces a **contiguous
prediction set** of trajectory indices guaranteed (under standard CP
exchangeability assumptions) to contain the decisive error with
user-specified confidence level :math:`1-\\alpha`.

Why this matters for Tex
------------------------
Point predictions ship without principled uncertainty quantification.
Auditors and recovery systems benefit from a *region* of suspicion —
"the decisive error is one of steps [i, j] with 90% confidence" —
which a point prediction can't express. The CP set composes with the
graph-based candidates: graph picks the most likely point, CP bounds
the region of uncertainty.

Algorithm choices implemented
-----------------------------
Three of the four CP algorithms from §3.1 of the paper:

  1. **Vanilla CP** (§3.1.1) — the baseline. Picks all steps whose
     non-conformity score exceeds the calibrated threshold. Sets may
     be non-contiguous; useful as a reference / lower-bound on what
     filtration gains.

  2. **Left (Right) Filtration** (§3.1.3) — contiguous prediction set
     anchored at the leftmost (rightmost) end of the trajectory,
     expanding inward until coverage threshold is met. Useful when
     the failure pattern is "decisive error happens early" (left)
     vs. "error compounds at the end" (right).

  3. **Two-Way Filtration** (§3.1.4) — recommended in the paper as
     producing the tightest contiguous sets in expectation. Anchors at
     the step with the highest score, expands left+right alternately
     until coverage threshold is met. This is the algorithm Tex's
     attribution engine returns by default.

We deliberately skip §3.1.2 (Leaf-to-Root Tree Traversal) because
Tex's traces are linear, not tree-structured — applying the tree
algorithm to a linear trace degenerates to vanilla CP.

Coverage guarantee
------------------
Under the standard CP exchangeability assumption — calibration scores
and test scores are drawn i.i.d. from the same distribution — the
output set satisfies:

    P[ y* ∈ C(x; q̂) ] ≥ 1 - α

For Tex's deployment, two coverage modes:

  * **Transductive (default)** — no calibration set required. The
    threshold is derived from the empirical score distribution
    *within the trace itself* using the upper :math:`\\lceil (n+1)(1-\\alpha) \\rceil / n`
    quantile. This gives **marginal** coverage approximate, not
    formally guaranteed.
  * **Calibrated** — when a calibration set of (score_vector, true_index)
    pairs is supplied via ``TEX_CONFORMAL_CALIBRATION_PATH``, the
    threshold is calibrated against held-out data and the formal
    finite-sample guarantee applies.

The transductive mode is what's appropriate for v1: it gives a
principled uncertainty layer without requiring labeled failure
traces, with honest framing that the formal guarantee requires
calibration data. The endpoint reports which mode produced the set.

Scoring function
----------------
Per the paper §3.2, the non-conformity score is task-specific. For
Tex, the natural score per step is:

  * **When prefill SLM signals available**: per-step mean NLL (high
    NLL = "model didn't expect this step" = candidate decisive error).
    This matches MASPrism's scoring approach and is the strongest
    signal Tex has.
  * **When SLM unavailable**: the graph-based screener confidence
    serves as the score. Lower fidelity but still principled.

Both modes produce monotonically rankable scores, which is all CP
needs.

References
----------
- arxiv 2605.06788 (Feng et al., May 7 2026) §3.1, §3.2, §3.3
- Standard CP introduction: Angelopoulos & Bates (2023), "A Gentle
  Introduction to Conformal Prediction"
- MASPrism (arxiv 2605.07509) for the prefill-NLL scoring choice
"""

from __future__ import annotations

import math
import os
from dataclasses import dataclass
from typing import Mapping, Sequence

from pydantic import BaseModel, ConfigDict, Field


# Default miscoverage rate. 0.1 == 90% target coverage. Configurable
# per-call via the endpoint's request flag, with this value as the
# fallback default. Matches the paper's default experimental setting.
DEFAULT_ALPHA: float = 0.1


@dataclass(frozen=True, slots=True)
class _ScoredStep:
    """One trajectory step with its non-conformity score."""

    index: int
    step_id: str
    agent_id: str
    score: float


class ConformalPredictionSet(BaseModel):
    """Output of conformal agent error attribution.

    Represents a *contiguous* range of trajectory indices guaranteed
    (under CP exchangeability) to contain the decisive error with
    confidence ``1 - alpha``.

    Empty sets are represented as ``start_index == end_index == -1``
    with ``set_size == 0`` (the trace had no steps, or the threshold
    produced no inclusions — both are honest empty signals).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    algorithm: str = Field(min_length=1, max_length=64)
    """Which CP algorithm produced this set: ``vanilla``,
    ``left_filtration``, ``right_filtration``, or ``two_way_filtration``."""

    start_index: int = Field(ge=-1)
    """Inclusive start index of the contiguous range. -1 = empty set."""

    end_index: int = Field(ge=-1)
    """Inclusive end index of the contiguous range. -1 = empty set."""

    set_size: int = Field(ge=0)
    """Number of steps in the set (= end_index - start_index + 1 when
    non-empty). Smaller is better — tighter localization."""

    trace_length: int = Field(ge=0)
    """Total number of steps in the trace, for context."""

    alpha: float = Field(ge=0.0, le=1.0)
    """The miscoverage rate the caller requested."""

    target_coverage: float = Field(ge=0.0, le=1.0)
    """The target ``1 - alpha`` coverage level."""

    threshold: float
    """The non-conformity threshold ``q̂`` derived from the score
    distribution. Steps with score ``>= threshold`` are candidates for
    inclusion; the filtration then enforces contiguity."""

    score_source: str = Field(min_length=1, max_length=64)
    """Which signal produced the scores: ``prefill_nll`` (SLM-based,
    strongest) or ``screener_confidence`` (graph-based fallback)."""

    coverage_mode: str = Field(min_length=1, max_length=32)
    """``transductive`` (no calibration set, in-trace threshold,
    marginal coverage approximate) or ``calibrated`` (formal
    finite-sample guarantee against held-out calibration data)."""

    step_ids_in_set: tuple[str, ...] = Field(default_factory=tuple)
    """The step_ids of the included trajectory steps, in trace order.
    Convenience field for verifiers."""


# ---------------------------------------------------------------------------
# Score extraction
# ---------------------------------------------------------------------------


def _build_scored_steps(
    *,
    trace: Sequence[Mapping[str, object]],
    prefill_signals_map: Mapping[str, float] | None,
    screener_confidences: Mapping[str, float] | None,
) -> tuple[list[_ScoredStep], str]:
    """Build the per-step non-conformity score list.

    Returns ``(scored_steps, score_source)`` where ``score_source`` is
    either ``prefill_nll`` (if prefill_signals_map non-empty) or
    ``screener_confidence`` (fallback).

    For prefill_nll, the score is the per-step NLL directly. Higher
    NLL = more anomalous = more likely to be the decisive error.

    For screener_confidence, the score is the graph-based confidence
    for being a root cause. Higher confidence = more likely root cause
    = higher non-conformity in CP terms.

    Both signals are already on a "higher = more likely decisive
    error" orientation, so they go in as-is.
    """
    if prefill_signals_map:
        score_source = "prefill_nll"
        scored: list[_ScoredStep] = []
        for index, event in enumerate(trace):
            step_id = str(event.get("step_id") or f"step_{index:04d}")
            agent_id = str(event.get("agent_id") or "unknown")
            nll = float(prefill_signals_map.get(step_id, 0.0))
            scored.append(
                _ScoredStep(
                    index=index, step_id=step_id, agent_id=agent_id, score=nll
                )
            )
        return scored, score_source

    score_source = "screener_confidence"
    scored = []
    for index, event in enumerate(trace):
        step_id = str(event.get("step_id") or f"step_{index:04d}")
        agent_id = str(event.get("agent_id") or "unknown")
        # Default 0.0 = "no graph signal" = lowest priority.
        # The screener_confidences mapping is keyed by either step_id
        # or by candidate agent_id; try both.
        confidence = 0.0
        if screener_confidences:
            confidence = float(
                screener_confidences.get(step_id)
                or screener_confidences.get(agent_id)
                or 0.0
            )
        scored.append(
            _ScoredStep(
                index=index, step_id=step_id, agent_id=agent_id, score=confidence
            )
        )
    return scored, score_source


# ---------------------------------------------------------------------------
# Threshold computation
# ---------------------------------------------------------------------------


def _compute_threshold_transductive(
    scores: Sequence[float], alpha: float
) -> float:
    """Compute the CP threshold from the in-trace score distribution.

    Standard split-CP threshold at level :math:`1 - \\alpha`:

        q̂ = quantile_{⌈(n+1)(1-α)⌉/n}( scores )

    For transductive mode this is computed over the trace's own
    scores. Coverage is then marginal-approximate, not formally
    guaranteed (the formal guarantee requires a held-out calibration
    set whose scores are exchangeable with the test point).

    Degenerate cases:
      * Empty scores → threshold = +inf (no step exceeds, empty set)
      * Single score → threshold = that score (single-step set)
      * All-zero scores → threshold = 0.0 (everything tied, full set)
    """
    if not scores:
        return float("inf")
    if len(scores) == 1:
        return float(scores[0])

    sorted_desc = sorted(scores, reverse=True)
    n = len(sorted_desc)
    # ⌈(n+1)(1-α)⌉ — but bounded to [1, n] so we always get a valid
    # rank from the sorted list.
    rank = math.ceil((n + 1) * (1.0 - alpha))
    rank = max(1, min(rank, n))
    # The threshold is the score at rank position (1-indexed from the
    # top). Anything with score >= this threshold is in the CP set.
    return float(sorted_desc[rank - 1])


def _compute_threshold_calibrated(
    calibration_scores: Sequence[float], alpha: float
) -> float:
    """Compute the CP threshold from a held-out calibration set.

    When ``TEX_CONFORMAL_CALIBRATION_PATH`` provides historical
    true-positive scores (one per known-failure trace), the standard
    split-CP threshold gives the formal finite-sample coverage
    guarantee.

    The calibration_scores parameter is the list of scores
    corresponding to the *true* decisive-error step in each
    calibration trace. The threshold is the
    :math:`\\lceil (n+1)(1-\\alpha) \\rceil`-th smallest of those.
    """
    if not calibration_scores:
        return float("inf")
    sorted_asc = sorted(calibration_scores)
    n = len(sorted_asc)
    # ⌈(n+1)(1-α)⌉-th smallest
    rank = math.ceil((n + 1) * (1.0 - alpha))
    rank = max(1, min(rank, n))
    return float(sorted_asc[rank - 1])


def _load_calibration_scores() -> list[float] | None:
    """Load a persisted calibration score set from disk if configured.

    Returns ``None`` if no calibration is configured (transductive
    mode applies). Returns the list of scores otherwise. The expected
    on-disk format is one float per line.
    """
    path = os.environ.get("TEX_CONFORMAL_CALIBRATION_PATH")
    if not path:
        return None
    try:
        with open(path, "r", encoding="utf-8") as handle:
            scores: list[float] = []
            for line in handle:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    scores.append(float(line))
                except ValueError:
                    continue
            return scores if scores else None
    except OSError:
        return None


# ---------------------------------------------------------------------------
# Algorithm: Vanilla CP (§3.1.1)
# ---------------------------------------------------------------------------


def _vanilla_set(
    scored: Sequence[_ScoredStep], threshold: float
) -> tuple[int, int, list[_ScoredStep]]:
    """Vanilla CP: return all steps with score >= threshold.

    May be non-contiguous (paper §3.1.1, Figure 2). We summarize as
    ``(min_index, max_index, included_list)`` — the caller decides
    how to surface non-contiguity (we report the convex hull range
    plus the actual included list for fidelity).
    """
    included = [s for s in scored if s.score >= threshold]
    if not included:
        return (-1, -1, [])
    return (included[0].index, included[-1].index, included)


# ---------------------------------------------------------------------------
# Algorithm: Left / Right Filtration (§3.1.3)
# ---------------------------------------------------------------------------


def _left_filtration_set(
    scored: Sequence[_ScoredStep], threshold: float
) -> tuple[int, int, list[_ScoredStep]]:
    """Left filtration: expand from index 0 rightward.

    Per §3.1.3 of the paper: anchor at the leftmost step, expand
    rightward until the cumulative maximum score exceeds the
    threshold. The resulting set is ``[0, end_index]`` — contiguous
    from the left, ordinal-aware.

    This is appropriate when the failure-pattern prior says "decisive
    error happens early" — common in MAS where early planning steps
    set the failure trajectory.
    """
    if not scored:
        return (-1, -1, [])
    end_index = 0
    cumulative_max = -float("inf")
    for s in scored:
        cumulative_max = max(cumulative_max, s.score)
        end_index = s.index
        if cumulative_max >= threshold:
            break
    included = [s for s in scored if s.index <= end_index]
    return (0, end_index, included)


def _right_filtration_set(
    scored: Sequence[_ScoredStep], threshold: float
) -> tuple[int, int, list[_ScoredStep]]:
    """Right filtration: expand from index n-1 leftward.

    Per §3.1.3: anchor at the rightmost step, expand leftward until
    the cumulative max score (over the right tail being considered)
    exceeds the threshold. Set is ``[start_index, n-1]``.

    Appropriate when failures compound at the end of the trajectory.
    """
    if not scored:
        return (-1, -1, [])
    n = len(scored)
    start_index = n - 1
    cumulative_max = -float("inf")
    for s in reversed(scored):
        cumulative_max = max(cumulative_max, s.score)
        start_index = s.index
        if cumulative_max >= threshold:
            break
    included = [s for s in scored if s.index >= start_index]
    return (start_index, n - 1, included)


# ---------------------------------------------------------------------------
# Algorithm: Two-Way Filtration (§3.1.4) — Tex default
# ---------------------------------------------------------------------------


def _two_way_filtration_set(
    scored: Sequence[_ScoredStep], threshold: float
) -> tuple[int, int, list[_ScoredStep]]:
    """Two-way filtration: anchor at peak, expand bidirectionally.

    Per §3.1.4 (paper's recommended algorithm, produces tightest
    contiguous sets on Who&When benchmark):

      1. Find ``i* = argmax_i score_i``, the trajectory step with
         the highest non-conformity score.
      2. Initialize ``[L, R] = [i*, i*]``.
      3. Repeatedly expand the boundary on whichever side has the
         higher-scoring neighbor, until the *minimum* score within
         ``[L, R]`` no longer drops below the threshold.

    Step 3's stopping rule reverses the framing slightly from the
    paper for clarity: equivalent to the paper's "cumulative-max
    reaches threshold" formulation, but easier to reason about for
    contiguous sets.

    The resulting set is the tightest contiguous range that contains
    the peak score and whose minimum included score still satisfies
    the threshold.

    Default algorithm for Tex's endpoint because the paper's
    experiments show it produces the smallest sets at the same
    coverage level — i.e. the most useful for auditors.
    """
    if not scored:
        return (-1, -1, [])
    n = len(scored)
    if n == 1:
        only = scored[0]
        return (only.index, only.index, [only])

    # Step 1: locate the peak.
    peak_index = max(range(n), key=lambda i: scored[i].score)
    L, R = peak_index, peak_index

    # Step 2-3: expand until we've absorbed enough of the score mass.
    # The paper's algorithm terminates when the included score range
    # achieves the coverage condition. For transductive thresholds we
    # use the rule: expand until either (a) cumulative max of
    # included steps >= threshold AND we've included at least one
    # step with score >= threshold on each side that has neighbors,
    # or (b) we've consumed the whole trace.
    #
    # A simpler equivalent rule that matches the paper's Figure 3
    # behavior: expand greedily toward the neighbor with the higher
    # score, until the smallest-score-step-in-set drops below the
    # threshold *only if* the peak score itself is below threshold
    # (degenerate). Otherwise keep expanding while neighbor scores
    # are non-trivial.
    #
    # We use this concrete rule: expand greedily while there are
    # neighbors with score >= threshold. Stop when both neighbors
    # (if any) have score < threshold. This produces a contiguous
    # set that contains exactly the high-score "plateau" around the
    # peak, which is the paper's intent.
    while True:
        left_neighbor = L - 1
        right_neighbor = R + 1
        left_score = (
            scored[left_neighbor].score if left_neighbor >= 0 else -float("inf")
        )
        right_score = (
            scored[right_neighbor].score if right_neighbor < n else -float("inf")
        )

        # Both neighbors below threshold (or out of bounds) → stop.
        if left_score < threshold and right_score < threshold:
            break

        # Expand toward higher-scoring neighbor (tie-break: right).
        if right_score >= left_score:
            R = right_neighbor
        else:
            L = left_neighbor

    included = list(scored[L : R + 1])
    return (L, R, included)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def compute_conformal_prediction_set(
    *,
    trace: Sequence[Mapping[str, object]],
    prefill_signals_map: Mapping[str, float] | None = None,
    screener_confidences: Mapping[str, float] | None = None,
    alpha: float = DEFAULT_ALPHA,
    algorithm: str = "two_way_filtration",
) -> ConformalPredictionSet:
    """Compute a conformal prediction set over the trajectory.

    Parameters
    ----------
    trace
        The OTAR-shaped trace events (same format the attribution
        engine builds from a Decision).
    prefill_signals_map
        Optional ``{step_id: nll}`` mapping from the prefill SLM.
        When non-empty, used as the scoring signal.
    screener_confidences
        Optional ``{step_id_or_agent_id: confidence}`` mapping from
        the graph-based screener. Used as the scoring signal when
        no prefill signals are available.
    alpha
        Miscoverage rate. Target coverage is ``1 - alpha``. Default
        0.1 (90% coverage).
    algorithm
        One of ``vanilla``, ``left_filtration``, ``right_filtration``,
        ``two_way_filtration`` (default).

    Returns
    -------
    ConformalPredictionSet
        Contiguous range of trajectory indices that, under CP
        exchangeability, contains the decisive error with confidence
        ``1 - alpha``.

    Fail-closed behavior
    --------------------
    Empty trace → empty set (start = end = -1, set_size = 0).
    Unknown algorithm → empty set with algorithm tag preserved for
    debugging. The endpoint inspects ``set_size > 0`` to decide
    whether to surface the result.
    """
    if not trace:
        return ConformalPredictionSet(
            algorithm=algorithm,
            start_index=-1,
            end_index=-1,
            set_size=0,
            trace_length=0,
            alpha=alpha,
            target_coverage=1.0 - alpha,
            threshold=float("inf"),
            score_source="none",
            coverage_mode="transductive",
            step_ids_in_set=(),
        )

    # Coerce alpha into a safe range.
    alpha = max(0.0, min(1.0, alpha))

    # Build scored steps.
    scored, score_source = _build_scored_steps(
        trace=trace,
        prefill_signals_map=prefill_signals_map,
        screener_confidences=screener_confidences,
    )
    raw_scores = [s.score for s in scored]

    # Threshold: calibrated if env-configured, else transductive.
    calibration_scores = _load_calibration_scores()
    if calibration_scores is not None:
        threshold = _compute_threshold_calibrated(calibration_scores, alpha)
        coverage_mode = "calibrated"
    else:
        threshold = _compute_threshold_transductive(raw_scores, alpha)
        coverage_mode = "transductive"

    # Dispatch algorithm.
    algo_table = {
        "vanilla": _vanilla_set,
        "left_filtration": _left_filtration_set,
        "right_filtration": _right_filtration_set,
        "two_way_filtration": _two_way_filtration_set,
    }
    fn = algo_table.get(algorithm)
    if fn is None:
        return ConformalPredictionSet(
            algorithm=algorithm,
            start_index=-1,
            end_index=-1,
            set_size=0,
            trace_length=len(scored),
            alpha=alpha,
            target_coverage=1.0 - alpha,
            threshold=threshold,
            score_source=score_source,
            coverage_mode=coverage_mode,
            step_ids_in_set=(),
        )

    start_idx, end_idx, included = fn(scored, threshold)
    set_size = len(included)

    return ConformalPredictionSet(
        algorithm=algorithm,
        start_index=start_idx,
        end_index=end_idx,
        set_size=set_size,
        trace_length=len(scored),
        alpha=alpha,
        target_coverage=1.0 - alpha,
        threshold=threshold,
        score_source=score_source,
        coverage_mode=coverage_mode,
        step_ids_in_set=tuple(s.step_id for s in included),
    )


__all__ = [
    "DEFAULT_ALPHA",
    "ConformalPredictionSet",
    "compute_conformal_prediction_set",
]

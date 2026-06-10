"""
L8 — credal-conformal hold + EPIG resolver (Wave 2). The earning benchmark.

What these tests earn (and no more):

* The closed-form LP extrema of the fused risk over the weight-credal-ball ×
  score-boxes polytope are CORRECT (brute-force grid agreement) and behave
  (interval contains the point estimate; widths collapse when pinned;
  epsilon-monotone).
* The EPIG resolver, ranking candidate acquisitions by predicted
  resolution/shrink of that interval, recovers a ground-truth pivot from
  calibrated observables far better than the fixed dict order, random order,
  AND a naive lowest-confidence-first heuristic — on N=2000 SYNTHETIC holds
  with one true pivot defined by resolution dynamics (never by the EPIG
  formula itself). ``research-early``: a synthetic artifact, not field
  validation, and not the North-Star real-posterior EPIG.
* The wire is observation-only: with ``stream_confidences`` the hold may
  re-rank WHICH resolving question is asked first; everything verdict-side
  is untouched, non-ABSTAIN still returns None, and with None the behavior
  is the pre-L8 fixed order. ``build_hold`` stays pure/deterministic.
"""

from __future__ import annotations

import random

from tex.domain.verdict import Verdict
from tex.engine.credal_hold import (
    CredalParams,
    credal_interval,
    rank_acquisitions,
    rank_pivotal_flags,
)
from tex.engine.hold import build_hold
from tex.engine.router import DecisionRouter

from tests.factories import (
    CLEAN_CONTENT,
    make_default_policy,
    make_gate_result,
    make_request,
    make_semantic_analysis,
    make_specialist_bundle,
)


# ── the credal interval: correctness ──────────────────────────────────────


def test_interval_contains_point_and_dominates_components() -> None:
    rng = random.Random(7)
    for _ in range(200):
        k = rng.randint(2, 7)
        names = [f"s{i}" for i in range(k)]
        weights = {n: rng.uniform(0.05, 1.0) for n in names}
        scores = {n: rng.uniform(0.0, 1.0) for n in names}
        confs = {n: rng.uniform(0.0, 1.0) for n in names}
        ci = credal_interval(scores=scores, weights=weights, confidences=confs)
        assert ci.risk_low <= ci.point + 1e-12
        assert ci.point <= ci.risk_high + 1e-12
        assert 0.0 <= ci.risk_low and ci.risk_high <= 1.0
        # The total interval dominates each named component slice.
        assert ci.width + 1e-12 >= ci.epistemic_width
        assert ci.width + 1e-12 >= ci.aleatoric_width


def test_width_collapses_when_weights_pinned_and_streams_certain() -> None:
    scores = {"a": 0.2, "b": 0.9, "c": 0.5}
    weights = {"a": 0.5, "b": 0.3, "c": 0.2}
    certain = {"a": 1.0, "b": 1.0, "c": 1.0}

    pinned = credal_interval(
        scores=scores,
        weights=weights,
        confidences=certain,
        params=CredalParams(weight_epsilon=0.0),
    )
    assert pinned.width <= 1e-12
    assert pinned.epistemic_width <= 1e-12
    assert pinned.aleatoric_width <= 1e-12
    assert abs(pinned.risk_low - pinned.point) <= 1e-12
    assert abs(pinned.risk_high - pinned.point) <= 1e-12

    # Pinning the weights alone (epsilon=0) zeroes the epistemic part even
    # when streams stay uncertain; what remains is exactly the aleatoric part.
    uncertain = {"a": 0.5, "b": 0.5, "c": 0.5}
    weights_pinned = credal_interval(
        scores=scores,
        weights=weights,
        confidences=uncertain,
        params=CredalParams(weight_epsilon=0.0),
    )
    assert weights_pinned.epistemic_width <= 1e-12
    assert abs(weights_pinned.width - weights_pinned.aleatoric_width) <= 1e-12


def test_width_is_monotone_in_epsilon() -> None:
    scores = {"a": 0.1, "b": 0.8, "c": 0.45}
    weights = {"a": 0.4, "b": 0.35, "c": 0.25}
    confs = {"a": 0.9, "b": 0.6, "c": 0.8}
    widths = [
        credal_interval(
            scores=scores,
            weights=weights,
            confidences=confs,
            params=CredalParams(weight_epsilon=eps),
        ).width
        for eps in (0.0, 0.1, 0.3, 0.8)
    ]
    assert widths == sorted(widths)


def test_extrema_match_bruteforce_grid_on_small_cases() -> None:
    """The greedy closed form against an exhaustive grid over the polytope.

    The grid enumerates 3-stream weight vectors (step 0.01) inside the
    L1-ball ∩ simplex, times all 8 score-box corners. The closed form must
    dominate every grid point (the grid is a feasible subset) and exceed the
    grid optimum by no more than the grid's resolution slack.
    """
    rng = random.Random(11)
    step = 0.01
    slack = 3.0 * step  # moving each weight to the nearest grid point
    for _case in range(8):
        raw = [rng.uniform(0.1, 1.0) for _ in range(3)]
        total = sum(raw)
        w0 = [r / total for r in raw]
        scores = [rng.uniform(0.0, 1.0) for _ in range(3)]
        confs = [rng.uniform(0.2, 1.0) for _ in range(3)]
        eps = rng.choice([0.05, 0.15, 0.4, 2.5])  # 2.5 > any movable mass

        names = ("a", "b", "c")
        params = CredalParams(weight_epsilon=eps)
        ci = credal_interval(
            scores=dict(zip(names, scores)),
            weights=dict(zip(names, w0)),
            confidences=dict(zip(names, confs)),
            params=params,
        )

        lo = [max(0.0, s - (1.0 - c) / 2.0) for s, c in zip(scores, confs)]
        hi = [min(1.0, s + (1.0 - c) / 2.0) for s, c in zip(scores, confs)]
        corners = [
            (x, y, z)
            for x in (lo[0], hi[0])
            for y in (lo[1], hi[1])
            for z in (lo[2], hi[2])
        ]

        grid_hi, grid_lo = -1.0, 2.0
        n1 = int(round(1.0 / step))
        for i in range(n1 + 1):
            w1 = i * step
            for j in range(n1 + 1 - i):
                w2 = j * step
                w3 = 1.0 - w1 - w2
                if w3 < -1e-12:
                    continue
                l1 = abs(w1 - w0[0]) + abs(w2 - w0[1]) + abs(w3 - w0[2])
                if l1 > eps + 1e-12:
                    continue
                for sx, sy, sz in corners:
                    v = w1 * sx + w2 * sy + w3 * sz
                    grid_hi = max(grid_hi, v)
                    grid_lo = min(grid_lo, v)

        # Closed form dominates the feasible grid subset...
        assert ci.risk_high >= grid_hi - 1e-9
        assert ci.risk_low <= grid_lo + 1e-9
        # ...and never overshoots the true optimum by more than grid slack.
        assert ci.risk_high <= grid_hi + slack
        assert ci.risk_low >= grid_lo - slack


def test_extrema_exact_values_at_polytope_edges() -> None:
    """Exact witness values, no grid slack: when epsilon exceeds all movable
    mass the ball covers the whole simplex, so the extrema are exactly the
    extreme box corners; all-equal scores give exactly zero epistemic width
    regardless of epsilon."""
    scores = {"a": 0.2, "b": 0.9, "c": 0.5}
    weights = {"a": 0.5, "b": 0.3, "c": 0.2}
    confs = {"a": 0.8, "b": 0.6, "c": 1.0}
    full = credal_interval(
        scores=scores,
        weights=weights,
        confidences=confs,
        params=CredalParams(weight_epsilon=2.0),  # >= 2*(1 - min w0): whole simplex
    )
    # Witness: all mass on the best/worst corner stream.
    assert abs(full.risk_high - min(1.0, 0.9 + 0.2)) <= 1e-12  # b's box top
    assert abs(full.risk_low - max(0.0, 0.2 - 0.1)) <= 1e-12   # a's box bottom

    equal = credal_interval(
        scores={"a": 0.4, "b": 0.4, "c": 0.4},
        weights=weights,
        confidences={"a": 1.0, "b": 1.0, "c": 1.0},
        params=CredalParams(weight_epsilon=0.6),
    )
    # Weight ambiguity cannot move a constant objective: width exactly 0.
    assert equal.width == 0.0
    assert equal.epistemic_width == 0.0


# ── the EPIG resolver: units ──────────────────────────────────────────────


_BAND = (0.35, 0.70)


def test_certain_or_unknown_streams_score_zero() -> None:
    weights = {"a": 0.5, "b": 0.5}
    scores = {"a": 0.5, "b": 0.5}
    confs = {"a": 1.0, "b": 0.4}
    ranked = rank_acquisitions(
        candidates=("a", "b", "ghost"),
        scores=scores,
        weights=weights,
        confidences=confs,
        band=_BAND,
    )
    by_stream = {r.stream: r for r in ranked}
    assert by_stream["a"].resolve_probability == 0.0
    assert by_stream["a"].expected_width_drop == 0.0
    assert by_stream["ghost"].resolve_probability == 0.0
    assert by_stream["ghost"].expected_width_drop == 0.0
    assert ranked[0].stream == "b"
    assert by_stream["b"].expected_width_drop > 0.0


def test_epig_prefers_decision_relevant_stream_over_mere_uncertainty() -> None:
    # Both streams equally uncertain; "big" carries 6x the fusion weight, so
    # acquiring its answer is predicted to move the interval 6x as much. The
    # less-relevant stream comes FIRST in input order, so winning here cannot
    # be a tie-break artifact.
    weights = {"big": 0.6, "small": 0.1, "rest": 0.3}
    scores = {"big": 0.5, "small": 0.5, "rest": 0.5}
    confs = {"big": 0.5, "small": 0.5, "rest": 1.0}
    ranked = rank_acquisitions(
        candidates=("small", "big"),
        scores=scores,
        weights=weights,
        confidences=confs,
        band=_BAND,
    )
    assert ranked[0].stream == "big"


def test_rank_ties_preserve_input_order() -> None:
    weights = {"x": 0.5, "y": 0.5}
    scores = {"x": 0.5, "y": 0.5}
    confs = {"x": 0.7, "y": 0.7}
    ranked = rank_acquisitions(
        candidates=("y", "x"),
        scores=scores,
        weights=weights,
        confidences=confs,
        band=_BAND,
    )
    assert tuple(r.stream for r in ranked) == ("y", "x")


def test_rank_acquisitions_is_deterministic() -> None:
    kw = dict(
        candidates=("a", "b", "c"),
        scores={"a": 0.3, "b": 0.6, "c": 0.5},
        weights={"a": 0.2, "b": 0.5, "c": 0.3},
        confidences={"a": 0.4, "b": 0.8, "c": 0.6},
        band=_BAND,
    )
    assert rank_acquisitions(**kw) == rank_acquisitions(**kw)


# ── the carrier: conf_stream:* keys actually reach the decision ───────────


def test_router_surfaces_conf_stream_keys() -> None:
    result = DecisionRouter().route(
        deterministic_result=make_gate_result(),
        specialist_bundle=make_specialist_bundle(max_risk=0.2, confidence=0.7),
        semantic_analysis=make_semantic_analysis(),
        policy=make_default_policy(),
        action_type="sales_email",
        channel="email",
        environment="production",
    )
    # Not blocked, no findings -> the pinned deterministic confidence 0.85;
    # one specialist at 0.7 -> mean 0.7; semantic factory default 0.70.
    assert result.scores["conf_stream:deterministic"] == 0.85
    assert result.scores["conf_stream:specialist"] == 0.7
    assert result.scores["conf_stream:semantic"] == 0.7
    assert "conf_stream:agent" not in result.scores  # no agent contributed


def test_pdp_carries_conf_stream_keys_end_to_end(runtime) -> None:
    result = runtime.evaluate_action_command.execute(
        make_request(content=CLEAN_CONTENT[0])
    )
    scores = result.response.scores
    for key in (
        "conf_stream:deterministic",
        "conf_stream:specialist",
        "conf_stream:semantic",
    ):
        assert key in scores, scores
        assert 0.0 <= scores[key] <= 1.0


# ── the wired path: observation-only, fail-closed, pure ───────────────────


def test_rank_pivotal_flags_is_identity_without_usable_signal() -> None:
    flags = ("no_retrieval_context", "cold_start", "forbid_streak")
    assert rank_pivotal_flags(
        candidate_flags=flags, stream_confidences={}, final_score=0.5
    ) == flags
    # Unknown flags and missing streams keep their fixed-order positions.
    odd = ("never_heard_of_it", "no_retrieval_context")
    assert rank_pivotal_flags(
        candidate_flags=odd,
        stream_confidences={"conf_stream:deterministic": 0.9},
        final_score=0.5,
    ) == odd


def test_build_hold_without_confidences_keeps_fixed_pivot_order() -> None:
    h = build_hold(
        verdict=Verdict.ABSTAIN,
        final_score=0.5,
        uncertainty_flags=("no_retrieval_context", "cold_start"),
        certificate=None,
        confidence=0.4,
    )
    assert h is not None
    assert h.pivotal_flag == "no_retrieval_context"  # pre-L8 dict order


def test_build_hold_epig_reranks_pivot_toward_uncertain_agent_stream() -> None:
    # The agent stream is far less confident than the semantic stream, and
    # carries 0.22 default fusion mass — EPIG names the agent fact first,
    # where the fixed order would have asked about retrieval context.
    kw = dict(
        verdict=Verdict.ABSTAIN,
        final_score=0.5,
        uncertainty_flags=("no_retrieval_context", "cold_start"),
        certificate=None,
        confidence=0.4,
    )
    confident_semantic = {
        "conf_stream:deterministic": 0.9,
        "conf_stream:specialist": 0.9,
        "conf_stream:semantic": 0.95,
        "conf_stream:agent": 0.2,
    }
    h = build_hold(**kw, stream_confidences=confident_semantic)
    assert h is not None
    assert h.pivotal_flag == "cold_start"

    # Flip the uncertainty: now the semantic fact is the information-optimal
    # ask, which coincides with the fixed order.
    confident_agent = {
        "conf_stream:deterministic": 0.9,
        "conf_stream:specialist": 0.9,
        "conf_stream:semantic": 0.2,
        "conf_stream:agent": 0.95,
    }
    h2 = build_hold(**kw, stream_confidences=confident_agent)
    assert h2 is not None
    assert h2.pivotal_flag == "no_retrieval_context"


def test_epig_rerank_touches_only_the_resolving_surface() -> None:
    """Observation-only: everything verdict-side is identical with and
    without stream confidences — only the resolving question may move."""
    kw = dict(
        verdict=Verdict.ABSTAIN,
        final_score=0.5,
        uncertainty_flags=("no_retrieval_context", "cold_start"),
        certificate=None,
        confidence=0.4,
    )
    base = build_hold(**kw)
    enriched = build_hold(
        **kw,
        stream_confidences={
            "conf_stream:deterministic": 0.9,
            "conf_stream:specialist": 0.9,
            "conf_stream:semantic": 0.95,
            "conf_stream:agent": 0.2,
        },
    )
    assert base is not None and enriched is not None
    for field in (
        "band_certified",
        "band_lower",
        "band_upper",
        "final_score",
        "epistemic_score",
        "aleatoric_score",
        "hold_type",
    ):
        assert getattr(base, field) == getattr(enriched, field)
    assert {base.pivotal_flag, enriched.pivotal_flag} == {
        "no_retrieval_context",
        "cold_start",
    }


def test_non_abstain_returns_none_even_with_confidences() -> None:
    for verdict in (Verdict.PERMIT, Verdict.FORBID):
        assert (
            build_hold(
                verdict=verdict,
                final_score=0.5,
                uncertainty_flags=("no_retrieval_context",),
                certificate=None,
                stream_confidences={"conf_stream:semantic": 0.3},
            )
            is None
        )


def test_build_hold_with_confidences_is_pure() -> None:
    kw = dict(
        verdict=Verdict.ABSTAIN,
        final_score=0.5,
        uncertainty_flags=("no_retrieval_context", "cold_start"),
        certificate=None,
        confidence=0.4,
        agent_id="a-1",
        action_type="tool_call",
        stream_confidences={
            "conf_stream:deterministic": 0.85,
            "conf_stream:specialist": 0.7,
            "conf_stream:semantic": 0.6,
            "conf_stream:agent": 0.3,
        },
    )
    assert build_hold(**kw).model_dump() == build_hold(**kw).model_dump()


# ── the earning benchmark (ROADMAP L8, verbatim earn condition) ───────────
#
# Synthetic holds, each with ONE true pivot. Anti-circularity, twice over:
#
# * The pivot is defined by RESOLUTION DYNAMICS — the unique stream whose
#   truthful revelation resolves the hold — never by the EPIG formula. EPIG
#   sees only pre-revelation observables (scores, confidences, weights,
#   band) and must *predict* it; the truths stay hidden.
# * The HEADLINE dynamics are EXTERNAL to the credal machinery: "resolved"
#   means the live point-fusion score sum_k w_k s_k exits the band — the
#   router's actual semantics — so EPIG cannot win merely because the test
#   adopted EPIG's own interval as the definition of success. The
#   interval-clearing dynamics run as a secondary internal-coherence test.
#
# Dict-order and random are observable-blind; lowest-confidence-first sees
# confidences but not the decision geometry — beating it is the
# anti-triviality receipt that EPIG is decision-targeted, not "ask the least
# confident stream" relabeled. Pivot positions are ~uniform over the fixed
# order by construction (i.i.d. stream draws), so no baseline is
# accidentally helped.


_BENCH_SEED = 20260610
_BENCH_STREAMS = tuple(f"q{i}" for i in range(6))
_BENCH_PARAMS = CredalParams(weight_epsilon=0.10)


def _point_fused(scores, weights) -> float:
    return sum(weights[k] * scores[k] for k in _BENCH_STREAMS)


def _point_resolved(scores, confs, weights) -> bool:
    fused = _point_fused(scores, weights)
    return not (_BAND[0] < fused < _BAND[1])


def _interval_resolved(scores, confs, weights) -> bool:
    return credal_interval(
        scores=scores, weights=weights, confidences=confs, params=_BENCH_PARAMS
    ).resolved(_BAND)


def _generate_hold(rng: random.Random, resolved_fn):
    """One synthetic hold with exactly one resolution-dynamics pivot."""
    while True:
        raw = [rng.uniform(0.05, 1.0) for _ in _BENCH_STREAMS]
        total = sum(raw)
        weights = {k: r / total for k, r in zip(_BENCH_STREAMS, raw)}
        truths = {k: rng.uniform(0.0, 1.0) for k in _BENCH_STREAMS}
        confs = {k: rng.uniform(0.3, 0.95) for k in _BENCH_STREAMS}
        scores = {
            k: max(
                0.0,
                min(1.0, truths[k] + (1.0 - confs[k]) * rng.uniform(-0.5, 0.5)),
            )
            for k in _BENCH_STREAMS
        }
        if resolved_fn(scores, confs, weights):
            continue  # not a hold under these dynamics
        resolvers = [
            k
            for k in _BENCH_STREAMS
            if resolved_fn({**scores, k: truths[k]}, {**confs, k: 1.0}, weights)
        ]
        if len(resolvers) == 1:
            return weights, truths, confs, scores


def _run_ordering(hold, pick_next, resolved_fn) -> tuple[int, bool]:
    """Ask questions in the policy's order until the hold resolves."""
    weights, truths, confs, scores = hold
    s_cur, c_cur = dict(scores), dict(confs)
    remaining = list(_BENCH_STREAMS)
    asked = 0
    while remaining:
        k = pick_next(remaining, s_cur, c_cur, weights)
        remaining.remove(k)
        asked += 1
        s_cur[k] = truths[k]
        c_cur[k] = 1.0
        if resolved_fn(s_cur, c_cur, weights):
            return asked, True
    return asked, False


def _benchmark_fractions(n_holds: int, resolved_fn) -> dict[str, float]:
    rng = random.Random(_BENCH_SEED)
    holds = [_generate_hold(rng, resolved_fn) for _ in range(n_holds)]

    def epig_next(remaining, s_cur, c_cur, weights):
        ranked = rank_acquisitions(
            candidates=tuple(remaining),
            scores=s_cur,
            weights=weights,
            confidences=c_cur,
            band=_BAND,
            params=_BENCH_PARAMS,
        )
        return ranked[0].stream

    def dict_next(remaining, s_cur, c_cur, weights):
        return remaining[0]

    shuffle_rng = random.Random(_BENCH_SEED + 1)

    def random_next(remaining, s_cur, c_cur, weights):
        return shuffle_rng.choice(remaining)

    def lowconf_next(remaining, s_cur, c_cur, weights):
        return min(remaining, key=lambda k: (c_cur[k], k))

    fractions: dict[str, float] = {}
    for name, picker in (
        ("epig", epig_next),
        ("dict", dict_next),
        ("random", random_next),
        ("lowconf", lowconf_next),
    ):
        questions, resolved = 0, 0
        for hold in holds:
            asked, ok = _run_ordering(hold, picker, resolved_fn)
            questions += asked
            resolved += 1 if ok else 0
        fractions[name] = resolved / questions
    return fractions


def test_epig_beats_baselines_under_live_point_fusion_dynamics() -> None:
    """THE earn condition: N=2000, one true pivot, resolution defined by the
    live point-fusion semantics (external to the credal machinery)."""
    fractions = _benchmark_fractions(2000, _point_resolved)
    # Calibrated 2026-06-10 at this exact seed: epig 0.2654 / dict 0.1483 /
    # random 0.1567 / lowconf 0.1779. Margins sit well below the observed
    # gaps but decisively above zero: if EPIG were secretly dict-order the
    # gap would be ~0 and this test FAILS.
    assert fractions["epig"] > fractions["dict"] + 0.06, fractions
    assert fractions["epig"] > fractions["random"] + 0.06, fractions
    # Anti-triviality: decision-targeted, not lowest-confidence relabeled.
    assert fractions["epig"] > fractions["lowconf"] + 0.04, fractions


def test_epig_beats_baselines_under_credal_interval_dynamics() -> None:
    """Internal coherence: when "resolved" means the credal interval itself
    clears the band (the resolver's own objective), EPIG should dominate by
    a wide margin — near-optimal for the functional it optimizes."""
    fractions = _benchmark_fractions(500, _interval_resolved)
    # Calibrated 2026-06-10 at this exact seed: epig 0.7812 / dict 0.3307 /
    # random 0.3222 / lowconf 0.5682.
    assert fractions["epig"] > fractions["dict"] + 0.25, fractions
    assert fractions["epig"] > fractions["random"] + 0.25, fractions
    assert fractions["epig"] > fractions["lowconf"] + 0.10, fractions

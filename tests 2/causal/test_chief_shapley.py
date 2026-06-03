"""
Shapley-value attribution tests for HierarchicalCausalGraph.fast_attribute
(Thread 7.1).

Theory anchors validated:
- Efficiency axiom (Shapley 1953): sum of shares = grand-coalition payoff.
- Dummy-player axiom: a member that contributes 0 to every coalition gets 0.
- Symmetry axiom: equivalent members get equal shares.
- Castro-Gómez-Tejada 2009 unbiased MC estimator under fixed seed.
"""

from __future__ import annotations

import time

import pytest

from tex.causal.chief import (
    FastAttribution,
    HierarchicalCausalGraph,
    _compute_shapley_values,
    _shapley_exact,
    _shapley_monte_carlo,
)


@pytest.fixture
def hcg() -> HierarchicalCausalGraph:
    return HierarchicalCausalGraph()


# ----- Shapley axioms on the internal helper ------------------------------


def _constant_payoff(value: float):
    def v(members: frozenset[str]) -> float:
        return value if members else 0.0
    return v


def test_shapley_efficiency_axiom() -> None:
    """Sum of Shapley values equals the grand-coalition payoff."""
    def v(members: frozenset[str]) -> float:
        return 0.6 if members else 0.0
    members = ("a", "b", "c", "d")
    shapleys = _compute_shapley_values(members=members, payoff=v)
    grand = v(frozenset(members))
    assert abs(sum(shapleys) - grand) < 1e-9


def test_shapley_dummy_player_axiom() -> None:
    """A member contributing 0 to every coalition gets Shapley value 0."""
    def v(members: frozenset[str]) -> float:
        # Dummy member 'd' — its presence/absence never changes the payoff.
        return float(len(members - {"d"})) / 3.0
    members = ("a", "b", "c", "d")
    shapleys = _compute_shapley_values(members=members, payoff=v)
    # Member 'd' is at index 3.
    assert abs(shapleys[3]) < 1e-9


def test_shapley_symmetry_axiom() -> None:
    """Two symmetric members get equal Shapley values."""
    def v(members: frozenset[str]) -> float:
        return float(len(members)) / 5.0
    members = ("a", "b", "c")
    shapleys = _compute_shapley_values(members=members, payoff=v)
    # All three symmetric → all equal.
    assert abs(shapleys[0] - shapleys[1]) < 1e-9
    assert abs(shapleys[1] - shapleys[2]) < 1e-9


def test_shapley_exact_matches_brute_force_for_small_n() -> None:
    """For n=4 the exact closed-form should match an independent
    brute-force average over the 4! permutations."""
    def v(members: frozenset[str]) -> float:
        # Asymmetric payoff so the test is non-trivial.
        s = sum(ord(m) for m in members)
        return min(1.0, s / 400.0)

    members = ("a", "b", "c", "d")
    shapley_via_helper = _shapley_exact(members=members, payoff=v)

    # Brute force: average marginal across all 24 permutations.
    import itertools
    n = len(members)
    accum = [0.0] * n
    for perm in itertools.permutations(range(n)):
        running: set[str] = set()
        v_prev = 0.0
        for idx in perm:
            running.add(members[idx])
            v_curr = v(frozenset(running))
            accum[idx] += (v_curr - v_prev)
            v_prev = v_curr
    expected = [a / 24.0 for a in accum]

    for i in range(n):
        assert abs(shapley_via_helper[i] - expected[i]) < 1e-9


def test_shapley_monte_carlo_close_to_exact() -> None:
    """For n=8 (above exact threshold), Castro-Gómez-Tejada MC should
    be within a few SE of the exact value."""
    def v(members: frozenset[str]) -> float:
        return min(1.0, len(members) / 8.0)

    members = tuple(f"m{i}" for i in range(8))
    exact = _shapley_exact(members=members, payoff=v)
    mc = _shapley_monte_carlo(members=members, payoff=v)
    # Symmetric payoff → all shares equal in exact AND MC; check
    # each MC share is within 0.05 of exact (well inside CGT bound).
    for i in range(8):
        assert abs(mc[i] - exact[i]) < 0.05


def test_shapley_monte_carlo_deterministic() -> None:
    """Two MC runs with the same input produce identical results
    (fixed seed). Required for replay of evidence records."""
    def v(members: frozenset[str]) -> float:
        return min(1.0, len(members) / 5.0)
    members = tuple(f"u{i}" for i in range(15))
    a = _shapley_monte_carlo(members=members, payoff=v)
    b = _shapley_monte_carlo(members=members, payoff=v)
    for i in range(15):
        assert a[i] == b[i]


# ----- end-to-end fast_attribute Shapley behavior --------------------------


def test_fast_attribution_has_shapley_scores(
    hcg: HierarchicalCausalGraph,
) -> None:
    r = hcg.fast_attribute(
        proposed_event_id="evt",
        upstream_event_ids=("a", "b", "c"),
        active_agent_ids=("agent_1",),
        top_k=3,
    )
    assert hasattr(r, "shapley_scores")
    assert len(r.shapley_scores) == len(r.top_candidates)
    for s in r.shapley_scores:
        assert 0.0 <= s <= 1.0


def test_empty_upstream_yields_empty_shapley_scores(
    hcg: HierarchicalCausalGraph,
) -> None:
    r = hcg.fast_attribute(
        proposed_event_id="evt",
        upstream_event_ids=(),
        active_agent_ids=("agent_1",),
    )
    assert r.shapley_scores == ()
    assert r.confidence == 0.0


def test_top_k_sorted_by_descending_shapley(
    hcg: HierarchicalCausalGraph,
) -> None:
    """top_candidates returned in descending Shapley order, not
    declaration order. This is the Thread 7.1 semantic change."""
    r = hcg.fast_attribute(
        proposed_event_id="evt",
        upstream_event_ids=("a", "b", "c", "d", "e"),
        active_agent_ids=("agent_1",),
        top_k=5,
    )
    # Scores must be non-increasing.
    for i in range(1, len(r.shapley_scores)):
        assert r.shapley_scores[i] <= r.shapley_scores[i - 1] + 1e-9


def test_primary_upstream_typically_highest_shapley(
    hcg: HierarchicalCausalGraph,
) -> None:
    """The first declared upstream gets a +0.3 bonus in the payoff
    function (it's the agent's claimed primary cause). Its Shapley
    score should typically be the highest."""
    r = hcg.fast_attribute(
        proposed_event_id="evt",
        upstream_event_ids=("PRIMARY", "secondary_1", "secondary_2"),
        active_agent_ids=("agent_1",),
        top_k=3,
    )
    # PRIMARY should appear in top_candidates and have the highest score.
    assert "PRIMARY" in r.top_candidates
    primary_idx = r.top_candidates.index("PRIMARY")
    for i, score in enumerate(r.shapley_scores):
        if i != primary_idx:
            assert score <= r.shapley_scores[primary_idx] + 1e-9


def test_confidence_equals_sum_of_all_shapley_shares(
    hcg: HierarchicalCausalGraph,
) -> None:
    """Aggregate confidence is the sum of ALL Shapley shares, even
    those past top_k. With top_k = len(upstreams), shapley_scores
    sum exactly equals confidence (efficiency axiom)."""
    upstream = ("a", "b", "c", "d")
    r = hcg.fast_attribute(
        proposed_event_id="evt",
        upstream_event_ids=upstream,
        active_agent_ids=("agent_1",),
        top_k=len(upstream),  # all candidates returned
    )
    total = sum(r.shapley_scores)
    assert abs(r.confidence - total) < 1e-9


def test_shapley_exact_and_mc_paths_both_callable(
    hcg: HierarchicalCausalGraph,
) -> None:
    """Both code paths (exact for n ≤ 6, MC for n > 6) produce valid
    FastAttribution results with shapley_scores that satisfy the
    efficiency axiom."""
    # Exact path
    r_exact = hcg.fast_attribute(
        proposed_event_id="evt_exact",
        upstream_event_ids=("a", "b", "c"),
        active_agent_ids=("agent_1",),
        top_k=3,
    )
    assert len(r_exact.shapley_scores) == 3
    assert abs(r_exact.confidence - sum(r_exact.shapley_scores)) < 1e-9

    # MC path
    r_mc = hcg.fast_attribute(
        proposed_event_id="evt_mc",
        upstream_event_ids=tuple(f"u{i}" for i in range(10)),
        active_agent_ids=("agent_1",),
        top_k=10,
    )
    assert len(r_mc.shapley_scores) == 10
    # MC efficiency holds with small tolerance (sampling error +
    # rounding); use a 0.10 cap which is well inside CGT bound.
    assert abs(r_mc.confidence - sum(r_mc.shapley_scores)) < 0.10


# ----- latency budget (Shapley path) --------------------------------------


def test_shapley_under_5ms_p99_at_n20(
    hcg: HierarchicalCausalGraph,
) -> None:
    """Castro-Gómez-Tejada MC at n=20 stays inside 5ms p99 with the
    bitmask cache + adaptive sample budget."""
    upstream = tuple(f"e{i}" for i in range(20))
    active = tuple(f"agent_{i}" for i in range(50))

    # warm
    for _ in range(20):
        hcg.fast_attribute(
            proposed_event_id="evt",
            upstream_event_ids=upstream,
            active_agent_ids=active,
            top_k=5,
        )

    timings: list[float] = []
    for _ in range(500):
        t0 = time.perf_counter()
        hcg.fast_attribute(
            proposed_event_id="evt",
            upstream_event_ids=upstream,
            active_agent_ids=active,
            top_k=5,
        )
        timings.append((time.perf_counter() - t0) * 1000.0)

    timings.sort()
    p99 = timings[495]
    assert p99 < 5.0, f"Shapley p99 at n=20: {p99:.2f}ms exceeds 5ms"

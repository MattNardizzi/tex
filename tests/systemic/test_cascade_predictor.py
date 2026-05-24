"""Tests for Thread 9 CascadePredictor."""

from __future__ import annotations

import pytest

from tex.systemic.cascade_predictor import (
    COLD_START_PROBABILITY,
    DEFAULT_MAX_DEPTH,
    DEFAULT_MIN_PROBABILITY,
    CascadePredictor,
    DependencyEdge,
    estimate_edge_probability,
)


def _edge(src: str, dst: str, p: float, *, sf: str = "cascade_amplification",
          uca: str = "UNSPECIFIED") -> DependencyEdge:
    return DependencyEdge(
        from_event_id=src, to_event_id=dst, propagation_probability=p,
        spark_to_fire_class=sf, stpa_uca_class=uca,
    )


def test_empty_seed_returns_empty() -> None:
    cp = CascadePredictor()
    assert cp.predict_cascade_paths(
        seed_violation_event_id="", edges=(),
    ) == ()


def test_unknown_seed_returns_empty() -> None:
    cp = CascadePredictor()
    edges = (_edge("a", "b", 0.5),)
    assert cp.predict_cascade_paths(
        seed_violation_event_id="z", edges=edges,
    ) == ()


def test_single_hop_path_recorded() -> None:
    cp = CascadePredictor()
    edges = (_edge("a", "b", 0.8),)
    paths = cp.predict_cascade_paths(
        seed_violation_event_id="a", edges=edges,
    )
    assert len(paths) == 1
    assert paths[0].event_ids == ("a", "b")
    assert paths[0].aggregate_probability == pytest.approx(0.8)
    assert paths[0].depth == 1


def test_two_hop_aggregate_probability() -> None:
    cp = CascadePredictor()
    edges = (
        _edge("a", "b", 0.5),
        _edge("b", "c", 0.4),
    )
    paths = cp.predict_cascade_paths(
        seed_violation_event_id="a", edges=edges,
    )
    # Expect: a→b (0.5), a→b→c (0.2)
    aggs = {p.event_ids: p.aggregate_probability for p in paths}
    assert aggs[("a", "b")] == pytest.approx(0.5)
    assert aggs[("a", "b", "c")] == pytest.approx(0.2)


def test_min_probability_prunes() -> None:
    cp = CascadePredictor()
    edges = (
        _edge("a", "b", 0.5),
        _edge("b", "c", 0.01),  # below default min 0.05
    )
    paths = cp.predict_cascade_paths(
        seed_violation_event_id="a", edges=edges,
    )
    # Only a→b should survive (a→b→c aggregate = 0.005).
    assert all(p.event_ids != ("a", "b", "c") for p in paths)


def test_max_depth_bounds_traversal() -> None:
    cp = CascadePredictor()
    edges = (
        _edge("a", "b", 0.9),
        _edge("b", "c", 0.9),
        _edge("c", "d", 0.9),
        _edge("d", "e", 0.9),
        _edge("e", "f", 0.9),
    )
    paths = cp.predict_cascade_paths(
        seed_violation_event_id="a", edges=edges, max_depth=3,
    )
    for p in paths:
        assert p.depth <= 3
    # No path should reach 'f' (would require depth 5).
    assert all("f" not in p.event_ids for p in paths)


def test_paths_sorted_by_probability_desc() -> None:
    cp = CascadePredictor()
    edges = (
        _edge("a", "b", 0.3),
        _edge("a", "c", 0.8),
        _edge("a", "d", 0.5),
    )
    paths = cp.predict_cascade_paths(
        seed_violation_event_id="a", edges=edges,
    )
    probs = [p.aggregate_probability for p in paths]
    assert probs == sorted(probs, reverse=True)


def test_cycle_does_not_infinite_loop() -> None:
    cp = CascadePredictor()
    edges = (
        _edge("a", "b", 0.6),
        _edge("b", "a", 0.6),  # cycle
    )
    # Should terminate without exception.
    paths = cp.predict_cascade_paths(
        seed_violation_event_id="a", edges=edges, max_depth=10,
    )
    # Cycle prevention: 'a' never appears twice in the same path.
    for p in paths:
        assert len(set(p.event_ids)) == len(p.event_ids)


def test_invalid_max_depth_rejected() -> None:
    cp = CascadePredictor()
    with pytest.raises(ValueError, match="max_depth must be >= 1"):
        cp.predict_cascade_paths(
            seed_violation_event_id="a", edges=(), max_depth=0,
        )


def test_invalid_min_probability_rejected() -> None:
    cp = CascadePredictor()
    with pytest.raises(ValueError, match="min_probability"):
        cp.predict_cascade_paths(
            seed_violation_event_id="a", edges=(), min_probability=1.5,
        )


def test_stpa_uca_class_propagates_to_last_edge() -> None:
    cp = CascadePredictor()
    edges = (
        _edge("a", "b", 0.9, uca="NOT_PROVIDED"),
        _edge("b", "c", 0.9, uca="WRONG_TIMING"),
    )
    paths = cp.predict_cascade_paths(
        seed_violation_event_id="a", edges=edges,
    )
    by_ids = {p.event_ids: p for p in paths}
    assert by_ids[("a", "b")].stpa_uca_class == "NOT_PROVIDED"
    assert by_ids[("a", "b", "c")].stpa_uca_class == "WRONG_TIMING"


def test_simple_wrapper_returns_tuple_chains() -> None:
    cp = CascadePredictor()
    chains = cp.predict_cascade_paths_simple(
        seed_violation_event_id="a",
        adjacency={"a": (("b", 0.5),), "b": (("c", 0.4),)},
    )
    assert ("a", "b") in chains
    assert ("a", "b", "c") in chains


def test_estimate_edge_probability_cold_start() -> None:
    assert estimate_edge_probability(
        historical_co_failure_rate=None, spectral_gap=None,
    ) == pytest.approx(COLD_START_PROBABILITY)


def test_estimate_edge_probability_prefers_empirical() -> None:
    # When empirical is high, we should use it.
    p = estimate_edge_probability(
        historical_co_failure_rate=0.9, spectral_gap=10.0,
    )
    assert p == pytest.approx(0.9)


def test_estimate_edge_probability_uses_spectral_when_no_empirical() -> None:
    p = estimate_edge_probability(
        historical_co_failure_rate=None, spectral_gap=1.0,
    )
    assert p == pytest.approx(0.5)


def test_default_constants_match_spark_to_fire() -> None:
    # Sanity: defaults are the Spark-to-Fire empirical sweet spots.
    assert DEFAULT_MAX_DEPTH == 8
    assert DEFAULT_MIN_PROBABILITY == 0.05

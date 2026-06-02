"""
Tests for tex.causal.chief.HierarchicalCausalGraph.fast_attribute
(Thread 7).

Coverage
--------
* Empty upstream chain → confidence 0.0, empty top_candidates
* Single declared upstream → low-but-non-zero confidence
* Saturating confidence as declared chain grows
* top_k truncation preserves declaration order
* top_k=1 edge case
* Active-agent set affects liveness factor
* Empty active-agent set still produces a valid result (liveness=0.5)
* Returned FastAttribution is frozen / immutable / pydantic-validated
* Confidence always in [0, 1]
* Performance: 5ms p99 budget across 1000 invocations
* Bad inputs raise ValueError/TypeError (top_k < 1, non-tuple upstream)
* Frozen sample_size matches len(upstream_event_ids)
* Does not mutate any input or instance state
"""

from __future__ import annotations

import time

import pytest

from tex.causal.chief import (
    FastAttribution,
    HierarchicalCausalGraph,
)


@pytest.fixture
def hcg() -> HierarchicalCausalGraph:
    return HierarchicalCausalGraph()


# ----- shape / return type -------------------------------------------------


def test_returns_fast_attribution(hcg: HierarchicalCausalGraph) -> None:
    result = hcg.fast_attribute(
        proposed_event_id="evt_xyz",
        upstream_event_ids=("e1", "e2"),
        active_agent_ids=("agent_1",),
    )
    assert isinstance(result, FastAttribution)
    assert result.proposed_event_id == "evt_xyz"


def test_fast_attribution_is_frozen(hcg: HierarchicalCausalGraph) -> None:
    result = hcg.fast_attribute(
        proposed_event_id="evt_xyz",
        upstream_event_ids=("a",),
        active_agent_ids=("agent_1",),
    )
    # Pydantic frozen models raise on assignment.
    with pytest.raises(Exception):
        result.confidence = 0.99  # type: ignore[misc]


def test_fast_attribution_rejects_extra_fields() -> None:
    with pytest.raises(Exception):
        FastAttribution(
            proposed_event_id="evt_xyz",
            top_candidates=(),
            confidence=0.0,
            sample_size=0,
            extra_field="nope",  # type: ignore[call-arg]
        )


# ----- core algorithm ------------------------------------------------------


def test_empty_upstream_yields_zero_confidence(
    hcg: HierarchicalCausalGraph,
) -> None:
    """No declared causes → no attribution → confidence 0.0."""
    result = hcg.fast_attribute(
        proposed_event_id="evt_xyz",
        upstream_event_ids=(),
        active_agent_ids=("agent_1", "agent_2"),
    )
    assert result.top_candidates == ()
    assert result.confidence == 0.0
    assert result.sample_size == 0


def test_single_upstream_yields_low_confidence(
    hcg: HierarchicalCausalGraph,
) -> None:
    """One declared cause → some confidence, but well below 1.0."""
    result = hcg.fast_attribute(
        proposed_event_id="evt_xyz",
        upstream_event_ids=("e1",),
        active_agent_ids=("agent_1",),
    )
    assert result.top_candidates == ("e1",)
    # base 0.5 × saturation(1) + 0.5 × liveness(1.0) — should land
    # somewhere around 0.5 + 0.15 ≈ 0.65 (saturation(1) ≈ 0.28).
    assert 0.2 < result.confidence < 0.85
    assert result.sample_size == 1


def test_confidence_saturates_with_more_upstream(
    hcg: HierarchicalCausalGraph,
) -> None:
    """As the declared chain grows, confidence increases monotonically
    (per saturation function) and approaches but does not exceed 1.0."""
    prev = -1.0
    for n in (1, 2, 3, 5, 10, 25, 100):
        ups = tuple(f"e{i}" for i in range(n))
        result = hcg.fast_attribute(
            proposed_event_id="evt",
            upstream_event_ids=ups,
            active_agent_ids=("a",),
        )
        assert result.confidence >= prev
        assert result.confidence <= 1.0
        prev = result.confidence
    # By n=100 we are saturated.
    assert prev > 0.9


def test_top_k_truncates_to_declaration_order(
    hcg: HierarchicalCausalGraph,
) -> None:
    upstream = ("first", "second", "third", "fourth", "fifth")
    result = hcg.fast_attribute(
        proposed_event_id="evt",
        upstream_event_ids=upstream,
        active_agent_ids=("a",),
        top_k=3,
    )
    assert result.top_candidates == ("first", "second", "third")
    # sample_size reflects FULL declaration, not the truncated tuple.
    assert result.sample_size == 5


def test_top_k_one(hcg: HierarchicalCausalGraph) -> None:
    result = hcg.fast_attribute(
        proposed_event_id="evt",
        upstream_event_ids=("a", "b", "c"),
        active_agent_ids=("agent_1",),
        top_k=1,
    )
    assert result.top_candidates == ("a",)
    assert result.sample_size == 3


def test_top_k_larger_than_declared_keeps_all(
    hcg: HierarchicalCausalGraph,
) -> None:
    result = hcg.fast_attribute(
        proposed_event_id="evt",
        upstream_event_ids=("a", "b"),
        active_agent_ids=("agent_1",),
        top_k=10,
    )
    assert result.top_candidates == ("a", "b")


# ----- liveness signal -----------------------------------------------------


def test_empty_active_agents_lowers_confidence(
    hcg: HierarchicalCausalGraph,
) -> None:
    """No currently-active agents → liveness factor degraded, but
    confidence remains valid (call doesn't fail)."""
    upstream = ("e1", "e2", "e3")
    full = hcg.fast_attribute(
        proposed_event_id="evt",
        upstream_event_ids=upstream,
        active_agent_ids=("agent_1",),
    )
    empty = hcg.fast_attribute(
        proposed_event_id="evt",
        upstream_event_ids=upstream,
        active_agent_ids=(),
    )
    # Empty active agents should yield strictly lower confidence
    # (liveness factor degrades).
    assert empty.confidence < full.confidence
    assert empty.confidence >= 0.0


# ----- bounds / validation -------------------------------------------------


def test_confidence_always_in_unit_interval(
    hcg: HierarchicalCausalGraph,
) -> None:
    """Pydantic ge=0, le=1 — anything else would surface as ValueError
    at model construction. Sweep over a range of conditions."""
    for n in (0, 1, 3, 10, 50, 500):
        ups = tuple(f"x{i}" for i in range(n))
        for active in ((), ("agent_1",), ("a", "b", "c", "d", "e")):
            r = hcg.fast_attribute(
                proposed_event_id="evt",
                upstream_event_ids=ups,
                active_agent_ids=active,
            )
            assert 0.0 <= r.confidence <= 1.0


def test_top_k_zero_raises(hcg: HierarchicalCausalGraph) -> None:
    with pytest.raises(ValueError, match="top_k"):
        hcg.fast_attribute(
            proposed_event_id="evt",
            upstream_event_ids=("a",),
            active_agent_ids=(),
            top_k=0,
        )


def test_top_k_negative_raises(hcg: HierarchicalCausalGraph) -> None:
    with pytest.raises(ValueError, match="top_k"):
        hcg.fast_attribute(
            proposed_event_id="evt",
            upstream_event_ids=("a",),
            active_agent_ids=(),
            top_k=-1,
        )


def test_non_tuple_upstream_raises(hcg: HierarchicalCausalGraph) -> None:
    with pytest.raises(TypeError, match="tuple"):
        hcg.fast_attribute(
            proposed_event_id="evt",
            upstream_event_ids=["a", "b"],  # type: ignore[arg-type]
            active_agent_ids=("a",),
        )


# ----- determinism + idempotence ------------------------------------------


def test_repeated_calls_are_deterministic(
    hcg: HierarchicalCausalGraph,
) -> None:
    a = hcg.fast_attribute(
        proposed_event_id="evt",
        upstream_event_ids=("u1", "u2", "u3"),
        active_agent_ids=("agent_1",),
    )
    b = hcg.fast_attribute(
        proposed_event_id="evt",
        upstream_event_ids=("u1", "u2", "u3"),
        active_agent_ids=("agent_1",),
    )
    assert a == b


def test_does_not_mutate_inputs(hcg: HierarchicalCausalGraph) -> None:
    """No side effects on the input tuples (tuples are immutable but
    that's still worth a defensive check)."""
    ups = ("u1", "u2")
    active = ("agent_1", "agent_2")
    hcg.fast_attribute(
        proposed_event_id="evt",
        upstream_event_ids=ups,
        active_agent_ids=active,
    )
    assert ups == ("u1", "u2")
    assert active == ("agent_1", "agent_2")


# ----- performance (Thread 7 acceptance criterion #2: 5ms p99) ------------


def test_fast_attribute_under_5ms_p99(
    hcg: HierarchicalCausalGraph,
) -> None:
    """1000 invocations, p99 latency < 5ms.

    This is the spec-required budget. Tests that the request-path
    attribution stays inside the 5ms ceiling MASPrism (2.66s/trace)
    cannot meet.
    """
    upstream = tuple(f"e{i}" for i in range(20))
    active = tuple(f"agent_{i}" for i in range(50))

    timings: list[float] = []
    for _ in range(1000):
        t0 = time.perf_counter()
        hcg.fast_attribute(
            proposed_event_id="evt",
            upstream_event_ids=upstream,
            active_agent_ids=active,
            top_k=5,
        )
        timings.append((time.perf_counter() - t0) * 1000.0)  # ms

    timings.sort()
    p99 = timings[990]  # 99th percentile of 1000 samples
    assert p99 < 5.0, (
        f"fast_attribute p99 latency {p99:.3f}ms exceeds 5ms budget"
    )


# ----- proposed_event_id passes through -----------------------------------


def test_proposed_event_id_carries_through(
    hcg: HierarchicalCausalGraph,
) -> None:
    result = hcg.fast_attribute(
        proposed_event_id="evt_abc_xyz_123",
        upstream_event_ids=("u",),
        active_agent_ids=("a",),
    )
    assert result.proposed_event_id == "evt_abc_xyz_123"

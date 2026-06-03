"""Tests for tex.nanozk.sublinear_space."""

from __future__ import annotations


import pytest

from tex.nanozk.sublinear_space import (
    BYTES_PER_FIELD_ELEMENT,
    SUBLINEAR_SPACE_FACTOR,
    SublinearSpacePlan,
    compute_streaming_plan,
    estimate_memory_savings,
    streaming_active,
)


class TestConstants:
    def test_bytes_per_field_element(self) -> None:
        assert BYTES_PER_FIELD_ELEMENT == 32


class TestSublinearSpaceFactor:
    def test_factor_at_zero_one_returns_one(self) -> None:
        assert SUBLINEAR_SPACE_FACTOR(1) == 1.0

    def test_factor_grows_with_T(self) -> None:
        a = SUBLINEAR_SPACE_FACTOR(2**10)
        b = SUBLINEAR_SPACE_FACTOR(2**20)
        assert b > a


class TestComputeStreamingPlan:
    def test_plan_for_small_trace(self) -> None:
        plan = compute_streaming_plan(trace_length=1024)
        assert isinstance(plan, SublinearSpacePlan)
        assert plan.trace_length == 1024
        # block_size = next power-of-two of sqrt(1024) = 32
        assert plan.block_size == 32

    def test_plan_block_size_is_power_of_two(self) -> None:
        plan = compute_streaming_plan(trace_length=10_000)
        # power-of-two property
        assert plan.block_size & (plan.block_size - 1) == 0

    def test_plan_num_blocks_covers_trace(self) -> None:
        plan = compute_streaming_plan(trace_length=10_000)
        assert plan.block_size * plan.num_blocks >= plan.trace_length

    def test_plan_zero_raises(self) -> None:
        with pytest.raises(ValueError):
            compute_streaming_plan(trace_length=0)

    def test_plan_negative_raises(self) -> None:
        with pytest.raises(ValueError):
            compute_streaming_plan(trace_length=-5)

    def test_plan_uses_aggregate_only_fiat_shamir(self) -> None:
        plan = compute_streaming_plan(trace_length=1024)
        assert plan.aggregate_only_fiat_shamir is True

    def test_plan_passes_match_tree_depth(self) -> None:
        plan = compute_streaming_plan(trace_length=2**20)
        # estimated_passes is depth+1 — sanity check the formula.
        assert plan.estimated_passes == plan.cook_mertz_tree_depth + 1

    def test_plan_frozen(self) -> None:
        plan = compute_streaming_plan(trace_length=1024)
        with pytest.raises(Exception):
            plan.block_size = 64  # type: ignore[misc]


class TestEstimateMemorySavings:
    def test_savings_for_paper_scenario_2(self) -> None:
        # T = 2^30 (paper's "1 billion steps" scenario).
        s = estimate_memory_savings(2**30)
        linear = s["linear_bytes"]
        # Linear should be on the order of tens of GB.
        assert linear > 30 * (1 << 30)  # > 30 GB
        # Sublinear should be vastly smaller — savings_factor > 10
        # at minimum.
        assert s["savings_factor"] > 10

    def test_savings_for_small_trace(self) -> None:
        # At T=2^20 (~1M), sublinear has already crossed over and
        # produces real savings vs linear. (For very small T<<256
        # the polylog overhead can exceed T, which is expected;
        # the regime where sublinear wins is T large enough that
        # √T·log T·log log T < T.)
        s = estimate_memory_savings(2**20)
        assert s["linear_bytes"] > s["sublinear_bytes"]

    def test_zero_raises(self) -> None:
        with pytest.raises(ValueError):
            estimate_memory_savings(0)

    def test_includes_block_info(self) -> None:
        s = estimate_memory_savings(1024)
        assert "block_size" in s
        assert "num_blocks" in s
        assert "tree_depth" in s


class TestStreamingActive:
    def test_default_off(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("TEX_NANOZK_SUBLINEAR", raising=False)
        monkeypatch.delenv("TEX_FRONTIER_NANOZK", raising=False)
        assert streaming_active() is False

    def test_env_flag_activates(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("TEX_NANOZK_SUBLINEAR", "1")
        assert streaming_active() is True

    def test_frontier_alone_does_not_activate(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Sublinear is opt-in even under frontier mode.
        monkeypatch.delenv("TEX_NANOZK_SUBLINEAR", raising=False)
        monkeypatch.setenv("TEX_FRONTIER_NANOZK", "1")
        assert streaming_active() is False

    def test_frontier_plus_auto_force(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("TEX_FRONTIER_NANOZK", "1")
        monkeypatch.setenv("TEX_NANOZK_SUBLINEAR", "auto_force")
        assert streaming_active() is True

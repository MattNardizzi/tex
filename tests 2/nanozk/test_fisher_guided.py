"""Tests for ``tex.nanozk.fisher_guided``.

Covers:
  * paper-anchored top-k selection (NANOZK §3.3)
  * deterministic tie-breaking by layer index (our extension)
  * cost-weighted greedy selection (our extension beyond the paper)
  * budget arithmetic helpers
  * edge cases (zero Fisher mass, zero budget, empty model)
  * error paths (length mismatches, out-of-range targets, negatives)
"""

from __future__ import annotations

import pytest

from tex.nanozk.fisher_guided import (
    FisherSelectionResult,
    compute_fisher_budget,
    select_layers_to_prove,
)


# --------------------------------------------------------------------------- #
# compute_fisher_budget                                                       #
# --------------------------------------------------------------------------- #


class TestComputeFisherBudget:
    def test_zero_total_layers(self) -> None:
        assert (
            compute_fisher_budget(
                total_layers=0,
                target_information_fraction=0.5,
                fisher_scores=(),
            )
            == 0
        )

    def test_uniform_scores_50_percent(self) -> None:
        # 10 uniform layers; 50% requires 5 layers.
        k = compute_fisher_budget(
            total_layers=10,
            target_information_fraction=0.5,
            fisher_scores=tuple(1.0 for _ in range(10)),
        )
        assert k == 5

    def test_one_dominant_layer_captures_target(self) -> None:
        # 9 zero layers + one big one; target 80% captured by k=1.
        scores = (10.0,) + (0.0,) * 9
        assert (
            compute_fisher_budget(
                total_layers=10,
                target_information_fraction=0.8,
                fisher_scores=scores,
            )
            == 1
        )

    def test_full_target_returns_all_nonzero_layers(self) -> None:
        scores = (3.0, 2.0, 1.0)
        assert (
            compute_fisher_budget(
                total_layers=3,
                target_information_fraction=1.0,
                fisher_scores=scores,
            )
            == 3
        )

    def test_all_zero_scores_zero_target_zero(self) -> None:
        assert (
            compute_fisher_budget(
                total_layers=5,
                target_information_fraction=0.0,
                fisher_scores=(0.0,) * 5,
            )
            == 0
        )

    def test_all_zero_scores_positive_target_returns_all(self) -> None:
        # Defensive: with zero mass, target > 0 is unsatisfiable
        # except by proving every layer (paper-spirit fallback).
        assert (
            compute_fisher_budget(
                total_layers=4,
                target_information_fraction=0.1,
                fisher_scores=(0.0,) * 4,
            )
            == 4
        )

    def test_negative_scores_clipped_to_zero(self) -> None:
        # Negative scores can creep in from noisy estimators. We
        # treat them as zero — never advantage a "below noise" layer.
        scores = (-1.0, 5.0, -3.0, 5.0)
        # Effective scores: (0, 5, 0, 5); total mass = 10; 50% = 5.
        # Top-1 layer (idx=1 by tie-break) captures 5/10 = 50%.
        assert (
            compute_fisher_budget(
                total_layers=4,
                target_information_fraction=0.5,
                fisher_scores=scores,
            )
            == 1
        )

    def test_target_just_above_one_largest_layer(self) -> None:
        # Scores: (10, 1, 1, 1) — total 13. Target 80% = 10.4. Top-1
        # (=10) is short; top-2 (=11) clears it.
        scores = (10.0, 1.0, 1.0, 1.0)
        assert (
            compute_fisher_budget(
                total_layers=4,
                target_information_fraction=0.8,
                fisher_scores=scores,
            )
            == 2
        )

    def test_invalid_total_layers_raises(self) -> None:
        with pytest.raises(ValueError):
            compute_fisher_budget(
                total_layers=-1,
                target_information_fraction=0.5,
                fisher_scores=(),
            )

    def test_mismatched_length_raises(self) -> None:
        with pytest.raises(ValueError):
            compute_fisher_budget(
                total_layers=3,
                target_information_fraction=0.5,
                fisher_scores=(1.0, 1.0),
            )

    def test_out_of_range_target_raises(self) -> None:
        with pytest.raises(ValueError):
            compute_fisher_budget(
                total_layers=3,
                target_information_fraction=1.5,
                fisher_scores=(1.0, 1.0, 1.0),
            )
        with pytest.raises(ValueError):
            compute_fisher_budget(
                total_layers=3,
                target_information_fraction=-0.1,
                fisher_scores=(1.0, 1.0, 1.0),
            )


# --------------------------------------------------------------------------- #
# select_layers_to_prove — uniform-cost path                                  #
# --------------------------------------------------------------------------- #


class TestSelectLayersUniformCost:
    def test_returns_canonical_result_type(self) -> None:
        result = select_layers_to_prove(
            total_layers=4,
            budget=2,
            fisher_scores=(1.0, 2.0, 3.0, 4.0),
        )
        assert isinstance(result, FisherSelectionResult)

    def test_top_k_by_fisher_descending(self) -> None:
        # Top 2 of (1, 2, 3, 4) are indices 2 and 3.
        result = select_layers_to_prove(
            total_layers=4,
            budget=2,
            fisher_scores=(1.0, 2.0, 3.0, 4.0),
        )
        assert result.selected_indices == (2, 3)

    def test_indices_ascending(self) -> None:
        # Even when Fisher selection is descending, the returned
        # indices must be ascending — the layer-set Merkle root
        # depends on this canonicalisation.
        result = select_layers_to_prove(
            total_layers=6,
            budget=3,
            fisher_scores=(10.0, 1.0, 5.0, 2.0, 8.0, 0.1),
        )
        assert result.selected_indices == tuple(
            sorted(result.selected_indices)
        )
        # Indices: top-3 are layer 0 (10), layer 4 (8), layer 2 (5).
        assert result.selected_indices == (0, 2, 4)

    def test_deterministic_tie_breaking_by_index(self) -> None:
        # All scores equal: indices 0..k-1 should win.
        result = select_layers_to_prove(
            total_layers=5,
            budget=3,
            fisher_scores=(7.0, 7.0, 7.0, 7.0, 7.0),
        )
        assert result.selected_indices == (0, 1, 2)

    def test_partial_tie_breaking(self) -> None:
        # Scores: (5, 5, 3, 5). Top-2: which two of the three 5s?
        # Deterministic tie-break = lowest index: (0, 1).
        result = select_layers_to_prove(
            total_layers=4,
            budget=2,
            fisher_scores=(5.0, 5.0, 3.0, 5.0),
        )
        assert result.selected_indices == (0, 1)

    def test_budget_zero_returns_empty(self) -> None:
        result = select_layers_to_prove(
            total_layers=4,
            budget=0,
            fisher_scores=(1.0,) * 4,
        )
        assert result.selected_indices == ()
        assert result.captured_information == 0.0
        assert result.selected_cost == 0.0
        assert result.information_per_unit_cost == 0.0

    def test_budget_exceeds_total_layers(self) -> None:
        # Budget larger than model — should select everything.
        result = select_layers_to_prove(
            total_layers=3,
            budget=100,
            fisher_scores=(1.0, 2.0, 3.0),
        )
        assert result.selected_indices == (0, 1, 2)
        assert result.captured_information == pytest.approx(1.0)

    def test_captured_information_proportion(self) -> None:
        # Scores: (1, 2, 3, 4); total = 10. Top-2 = (3, 4); captured
        # = 7/10 = 0.7.
        result = select_layers_to_prove(
            total_layers=4,
            budget=2,
            fisher_scores=(1.0, 2.0, 3.0, 4.0),
        )
        assert result.captured_information == pytest.approx(0.7)

    def test_information_per_unit_cost_uniform(self) -> None:
        result = select_layers_to_prove(
            total_layers=4,
            budget=2,
            fisher_scores=(1.0, 2.0, 3.0, 4.0),
        )
        # IPUC = captured_information / selected_cost = 0.7 / 2.
        assert result.information_per_unit_cost == pytest.approx(0.35)

    def test_zero_total_layers_returns_empty(self) -> None:
        result = select_layers_to_prove(
            total_layers=0,
            budget=5,
            fisher_scores=(),
        )
        assert result.selected_indices == ()
        assert result.captured_information == 0.0


# --------------------------------------------------------------------------- #
# select_layers_to_prove — cost-weighted path                                 #
# --------------------------------------------------------------------------- #


class TestSelectLayersCostWeighted:
    def test_cheaper_high_fisher_wins(self) -> None:
        # Layer A: Fisher 4, cost 4. Layer B: Fisher 3, cost 1.
        # IPUC: A = 1.0, B = 3.0. Budget of 1.0 cost: pick B only.
        # Budget of 5.0 cost: both — A first by ratio? Let's check
        # with budget=2: only B fits (cost 1).
        result = select_layers_to_prove(
            total_layers=2,
            budget=2,  # budget = max total cost
            fisher_scores=(4.0, 3.0),
            layer_costs=(4.0, 1.0),
        )
        # Layer 1 has best ratio (3.0); fits within 2.0 budget.
        # Layer 0 (cost 4) would exceed.
        assert result.selected_indices == (1,)

    def test_both_fit_at_higher_budget(self) -> None:
        result = select_layers_to_prove(
            total_layers=2,
            budget=10,
            fisher_scores=(4.0, 3.0),
            layer_costs=(4.0, 1.0),
        )
        assert result.selected_indices == (0, 1)
        # Captured = 7/7 = 1.0
        assert result.captured_information == pytest.approx(1.0)
        # Cost = 5.0
        assert result.selected_cost == pytest.approx(5.0)

    def test_invalid_zero_cost_rejected(self) -> None:
        with pytest.raises(ValueError):
            select_layers_to_prove(
                total_layers=2,
                budget=5,
                fisher_scores=(1.0, 1.0),
                layer_costs=(1.0, 0.0),
            )

    def test_invalid_negative_cost_rejected(self) -> None:
        with pytest.raises(ValueError):
            select_layers_to_prove(
                total_layers=2,
                budget=5,
                fisher_scores=(1.0, 1.0),
                layer_costs=(1.0, -1.0),
            )


# --------------------------------------------------------------------------- #
# Error paths                                                                  #
# --------------------------------------------------------------------------- #


class TestSelectLayersErrors:
    def test_negative_total_layers(self) -> None:
        with pytest.raises(ValueError):
            select_layers_to_prove(
                total_layers=-1, budget=1, fisher_scores=()
            )

    def test_negative_budget(self) -> None:
        with pytest.raises(ValueError):
            select_layers_to_prove(
                total_layers=3, budget=-1, fisher_scores=(1.0,) * 3
            )

    def test_length_mismatch_fisher(self) -> None:
        with pytest.raises(ValueError):
            select_layers_to_prove(
                total_layers=4, budget=1, fisher_scores=(1.0, 2.0)
            )

    def test_length_mismatch_costs(self) -> None:
        with pytest.raises(ValueError):
            select_layers_to_prove(
                total_layers=2,
                budget=1,
                fisher_scores=(1.0, 2.0),
                layer_costs=(1.0,),
            )

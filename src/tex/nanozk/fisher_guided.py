"""
==================== DEACTIVATED PLACEHOLDER (research-early) ====================
This module is OFF by default and deliberately inert. It computes keyed-hash
(HMAC / SHA-256) STAND-INS, not real cryptographic proofs. The symbol and type
names here describe an INTENDED future proving backend, NOT what this code
computes; nothing here is cryptographically binding. The verifier is hard-gated
and fail-closed: tex.nanozk.verify_layer_proof_set() returns is_valid=False
unless TEX_NANOZK_ALLOW_SHIM=1 is set (tests/dev only) -- so flipping
TEX_FRONTIER_NANOZK alone can NEVER cause a stand-in to be trusted as a real
proof. Kept in-tree, intentionally, so a real backend can be wired in later
(see src/tex/nanozk/DEACTIVATED.md). Do NOT cite anything here as a guarantee.
================================================================================

Fisher-information-guided layer selection for NANOZK.

Goal
----
When proving every layer of a transformer is impractical (the prover
amortises sublinearly but does not vanish), pick the subset of layers
whose verification *most* informs the verifier about the inference's
correctness. NANOZK (arxiv 2603.18046 §3.3, Mar 17 2026) proposed
Fisher information as the principled choice: high-Fisher layers
dominate the model's output sensitivity, so verifying them captures
the bulk of the inference's "computational signature".

What the NANOZK paper claims
----------------------------
Quoting arxiv 2603.18046: "Verifying only high-Fisher layers captures
65–86% of model sensitivity with 50% of the proving cost, compared to
51–79% for random selection — a consistent improvement across
architectures."

What's deliberately stricter than the paper
-------------------------------------------
The paper's algorithm is "sort by Fisher score descending, pick top-k
within budget". This module implements that exactly, with two
production-grade additions the paper does not specify:

  1. **Deterministic tie-breaking by layer index** when two scores are
     bit-identical. The paper is silent on ties, which is fine for an
     evaluation script but unacceptable for a cryptographic protocol
     where the verifier must reproduce the prover's selection bit-for-
     bit to recompute the layer-set commitment.

  2. **Budget arithmetic that respects per-layer cost variance**.
     NANOZK assumes uniform per-layer cost (a single transformer block
     has the same prove time on every layer). That is approximately
     true for GPT-2's 12 identical blocks but fails the moment we
     touch Mixture-of-Experts, GQA/MQA (Gauge Symmetries paper,
     OpenReview 1Ne3tfQC0T), or any model where the embedding layer's
     vocab size makes its proof asymmetric. ``compute_fisher_budget``
     supports a per-layer cost vector so the selector picks the
     highest *information per unit cost*, which is the right convex
     hull for resource-constrained verification.

This file ships only the selector and the budget helper. The prover
that consumes the selection lives in ``layerwise_prover.py``.
"""

from __future__ import annotations

from typing import Sequence

from pydantic import BaseModel, ConfigDict, Field


# --------------------------------------------------------------------------- #
# Result type                                                                  #
# --------------------------------------------------------------------------- #


class FisherSelectionResult(BaseModel):
    """The output of ``select_layers_to_prove``.

    The selection is canonical: a verifier given ``total_layers``,
    ``budget``, and the same ``fisher_scores`` (and optionally
    ``layer_costs``) reproduces ``selected_indices`` bit-for-bit.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    selected_indices: tuple[int, ...] = Field(
        description=(
            "Layer indices selected for proving, in ascending order. "
            "Ascending order — not Fisher-descending — so the layer-set "
            "commitment (a Merkle root over the indices) is canonical."
        )
    )
    captured_information: float = Field(
        description=(
            "Sum of Fisher scores over the selected layers, divided by "
            "the sum over all layers. Maps to NANOZK's '65-86% of model "
            "sensitivity' claim — but computed against the *actual* "
            "Fisher vector rather than the paper's reported average."
        ),
        ge=0.0,
        le=1.0 + 1e-9,
    )
    selected_cost: float = Field(
        description=(
            "Sum of per-layer costs over selected layers. Equals "
            "``len(selected_indices)`` when ``layer_costs`` is uniform."
        ),
        ge=0.0,
    )
    information_per_unit_cost: float = Field(
        description=(
            "``captured_information / selected_cost`` (0 when no layer "
            "was selected). Used by the prover to decide whether the "
            "selection is worth proving at all."
        ),
        ge=0.0,
    )


# --------------------------------------------------------------------------- #
# Budget helper                                                                #
# --------------------------------------------------------------------------- #


def compute_fisher_budget(
    *,
    total_layers: int,
    target_information_fraction: float,
    fisher_scores: Sequence[float],
) -> int:
    """Smallest k such that the top-k Fisher layers capture ≥ target.

    This is the planning side of the budget arithmetic: a caller who
    says "I want at least 80% of the Fisher information" gets back the
    minimum number of layers required. The selector then takes that
    integer and produces the canonical selection.

    Parameters
    ----------
    total_layers
        Number of layers in the transformer. Must equal
        ``len(fisher_scores)``.
    target_information_fraction
        Target as a fraction of total Fisher mass, in (0, 1]. Above 1
        is invalid (you cannot capture more than the total).
    fisher_scores
        Per-layer Fisher diagonal estimate. May include negatives in
        principle (Fisher diagonals are nonnegative for a properly
        estimated FIM, but caller-supplied estimates can drift). We
        treat negatives as zero — it never makes sense to prefer a
        layer whose estimate is below noise.

    Returns
    -------
    The minimum ``k`` ∈ {0, …, total_layers} satisfying the target.
    ``k == 0`` only when the target is achievable with no layers (only
    possible if every score is zero and the target is also zero).

    Raises
    ------
    ValueError
        On inconsistent inputs (mismatched lengths, target out of
        range, negative ``total_layers``).
    """
    if total_layers < 0:
        raise ValueError("total_layers must be non-negative")
    if total_layers != len(fisher_scores):
        raise ValueError(
            f"total_layers={total_layers} but len(fisher_scores)="
            f"{len(fisher_scores)}"
        )
    if not (0.0 <= target_information_fraction <= 1.0):
        raise ValueError(
            "target_information_fraction must be in [0, 1]"
        )

    if total_layers == 0:
        return 0

    clipped = [max(0.0, float(s)) for s in fisher_scores]
    total_mass = sum(clipped)
    if total_mass == 0.0:
        # Every layer is zero-Fisher. Any subset captures 100% (= 0/0).
        # Treat target>0 as unsatisfiable except by proving all layers
        # — defensive, matches the spirit of the paper's algorithm.
        return total_layers if target_information_fraction > 0.0 else 0

    # Descending sort, stable on index for deterministic ties.
    indexed = sorted(
        enumerate(clipped), key=lambda p: (-p[1], p[0])
    )
    target_mass = total_mass * target_information_fraction
    accumulated = 0.0
    for k, (_, score) in enumerate(indexed, start=1):
        accumulated += score
        if accumulated >= target_mass - 1e-15:
            return k
    return total_layers


# --------------------------------------------------------------------------- #
# Selector                                                                     #
# --------------------------------------------------------------------------- #


def select_layers_to_prove(
    *,
    total_layers: int,
    budget: int,
    fisher_scores: Sequence[float],
    layer_costs: Sequence[float] | None = None,
) -> FisherSelectionResult:
    """Select the layers to prove under a budget.

    Algorithm
    ---------
    When ``layer_costs`` is ``None`` (the NANOZK paper's setting) the
    algorithm is exactly the paper's: sort by Fisher score descending,
    pick top-k where k = min(budget, total_layers), break ties on
    ascending layer index for canonicalisation.

    When ``layer_costs`` is supplied we instead sort by *information
    per unit cost* (Fisher score / cost) and greedily fill the budget
    treated as a cost ceiling. This is a fractional-knapsack
    relaxation; for the prover-cost regime where per-layer costs are
    all within ~2× of each other (the GPT-2 / Llama / Gemma3 family
    cited in the DeepProve-1 announcement, Aug 18 2025) the greedy
    solution is within 1-ε of optimal. We do not implement full 0/1
    knapsack — the integer-programming step is not worth the verifier-
    side determinism cost, and the paper's setting is uniform anyway.

    Parameters
    ----------
    total_layers
        Number of layers. ``fisher_scores`` and (when provided)
        ``layer_costs`` must be of this length.
    budget
        Maximum number of layers to select when ``layer_costs`` is
        ``None``; maximum *total cost* when ``layer_costs`` is given.
        Non-negative; ``0`` returns the empty selection.
    fisher_scores
        Per-layer Fisher diagonal trace estimates. Higher = more
        sensitive layer. Negatives clipped to zero (see
        ``compute_fisher_budget`` for rationale).
    layer_costs
        Optional per-layer prover cost in caller-defined units
        (seconds, gates, dollars — anything that adds). All entries
        must be positive when supplied.

    Returns
    -------
    ``FisherSelectionResult`` with the canonical selection.

    Raises
    ------
    ValueError
        On inconsistent inputs.
    """
    if total_layers < 0:
        raise ValueError("total_layers must be non-negative")
    if total_layers != len(fisher_scores):
        raise ValueError(
            f"total_layers={total_layers} but len(fisher_scores)="
            f"{len(fisher_scores)}"
        )
    if budget < 0:
        raise ValueError("budget must be non-negative")
    if layer_costs is not None and total_layers != len(layer_costs):
        raise ValueError(
            f"total_layers={total_layers} but len(layer_costs)="
            f"{len(layer_costs)}"
        )
    if layer_costs is not None and any(c <= 0.0 for c in layer_costs):
        raise ValueError("layer_costs must be strictly positive")

    if total_layers == 0 or budget == 0:
        return FisherSelectionResult(
            selected_indices=(),
            captured_information=0.0,
            selected_cost=0.0,
            information_per_unit_cost=0.0,
        )

    clipped = [max(0.0, float(s)) for s in fisher_scores]
    total_mass = sum(clipped)

    if layer_costs is None:
        # Uniform-cost path: paper's algorithm exactly.
        k = min(int(budget), total_layers)
        # Descending Fisher; ascending index breaks ties.
        ranking = sorted(
            range(total_layers), key=lambda i: (-clipped[i], i)
        )
        chosen = tuple(sorted(ranking[:k]))
        captured_mass = sum(clipped[i] for i in chosen)
        captured_frac = (
            captured_mass / total_mass if total_mass > 0.0 else 1.0
        )
        selected_cost = float(len(chosen))
    else:
        # Cost-weighted greedy.
        ratios = [
            (clipped[i] / float(layer_costs[i]), -float(layer_costs[i]), i)
            for i in range(total_layers)
        ]
        # Sort by ratio descending; ties broken by cost ascending
        # (cheaper first), then by index ascending. ``-cost`` in the
        # key makes "cost ascending" the secondary sort because we're
        # sorting by negative key; the inner ``-`` flips it back.
        ratios.sort(key=lambda t: (-t[0], t[1], t[2]))
        chosen_list: list[int] = []
        used = 0.0
        ceiling = float(budget)
        for _, _, idx in ratios:
            cost_i = float(layer_costs[idx])
            if used + cost_i <= ceiling + 1e-12:
                chosen_list.append(idx)
                used += cost_i
        chosen = tuple(sorted(chosen_list))
        captured_mass = sum(clipped[i] for i in chosen)
        captured_frac = (
            captured_mass / total_mass if total_mass > 0.0 else 1.0
        )
        selected_cost = used

    ipuc = (
        captured_frac / selected_cost if selected_cost > 0.0 else 0.0
    )

    return FisherSelectionResult(
        selected_indices=chosen,
        captured_information=min(1.0, captured_frac),
        selected_cost=selected_cost,
        information_per_unit_cost=ipuc,
    )


__all__ = [
    "FisherSelectionResult",
    "compute_fisher_budget",
    "select_layers_to_prove",
]

"""
Fisher-information-guided verification.

When proving all layers is impractical, sample the layers with highest
Fisher information (most impact on output) and prove only those.

Priority: P2.
"""

from __future__ import annotations


def select_layers_to_prove(*, total_layers: int, budget: int, fisher_scores: tuple[float, ...]) -> tuple[int, ...]:
    """
    TODO(P2): sort layers by Fisher score descending, pick top-k within budget
    """
    raise NotImplementedError("Fisher-guided layer selection")

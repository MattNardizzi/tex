"""
[Architecture: Cross-cutting (Vigil cognition)] — the layer that decides
what Tex chooses to say.

See ARCHITECTURE.md for the full six-layer model. The six are how Tex is
built; this package is the mind that reads across all of them, holds a
model of normal for the shop, computes Bayesian surprise, and selects —
as a policy, not a ranking — what to speak, what to gate, and what to put
to a human. The frontend never computes what Tex says; it renders what the
selection here chose.

Build ladder (locked): v1 Bayesian surprise -> v1.5 redundancy collapse ->
v2 live learning -> v3 preference/VoI -> v4 expected free energy ->
v5 causal model underneath. v1 + v1.5 are live; v2-v5 are inert scaffolds
with real seams (learning.py, preference.py, efe.py, causal.py).

Iron rule: surprise selects which sealed truths to speak; it never writes
the words. See vigil/utterances.py.
"""

from __future__ import annotations

# Architectural layer marker (see ARCHITECTURE.md).
__layer__: int | None = None
__layer_kind__: str = "cross_cutting_cognition"

from tex.vigil.engine import VigilEngine
from tex.vigil.explainer import (
    Explainer,
    Explanation,
    ExplanationMode,
    build_default_explainer,
)
from tex.vigil.selector import (
    ChosenUtterance,
    SelectorConfig,
    VigilSelection,
    select,
)

__all__ = [
    "VigilEngine",
    "VigilSelection",
    "ChosenUtterance",
    "SelectorConfig",
    "select",
    "Explainer",
    "Explanation",
    "ExplanationMode",
    "build_default_explainer",
]

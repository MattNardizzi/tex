"""
[Architecture: Cross-cutting (Vigil cognition)] — the engine.

One object that runs a vigil cycle: read the six dimensions, warm the model
of normal, let surprise select. This is the mind; ``/v1/vigil`` is its
voice's wire.

The engine is also where the later rungs slot in WITHOUT a rewrite. Each is
an optional collaborator, defaulting to ``None`` so v1 runs the concrete
path. When a rung is built (see the inert scaffolds in this package), it is
injected here and the engine consults it:

    v2  learner          — vigil/learning.py   (live model of normal)
    v3  preference / VoI  — vigil/preference.py (the human-decision channel)
    v4  efe_selector      — vigil/efe.py        (policy selection, not ranking)
    v5  causal_port       — vigil/causal.py     (cause vs symptom, counterfactual)

The seams below are real interfaces; the organs behind them are empty until
their thread. Building them blind now is the over-building trap. Build the
vertebra; the spine grows one rung at a time.
"""

from __future__ import annotations

from typing import Any

from tex.vigil.dimensions import read_dimensions
from tex.vigil.normal import ModelOfNormal
from tex.vigil.selector import SelectorConfig, VigilSelection, select

__all__ = ["VigilEngine"]


class VigilEngine:
    """Stateless-per-cycle in v1; stateful when v2's learner is injected."""

    def __init__(
        self,
        *,
        config: SelectorConfig | None = None,
        # ---- seams for later rungs (inert in v1) ----
        learner: Any | None = None,       # v2: vigil.learning.DirichletNormalLearner
        preference: Any | None = None,    # v3: vigil.preference.PreferenceModel
        efe_selector: Any | None = None,  # v4: vigil.efe.ExpectedFreeEnergySelector
        causal_port: Any | None = None,   # v5: vigil.causal.CausalAttributionPort
    ) -> None:
        self._config = config or SelectorConfig()
        self._learner = learner
        self._preference = preference
        self._efe_selector = efe_selector
        self._causal_port = causal_port

    def run(self, request: Any, tenant: str | None) -> VigilSelection:
        """Run one vigil cycle for ``tenant`` and return what Tex chose."""
        readings = read_dimensions(request, tenant)

        # v3 live recalibration: fold any newly-resolved decisions into the
        # preference model before predicting, so the speak threshold tracks
        # this shop as gates resolve over time (not just once at boot). The
        # fold is idempotent — each outcome counts at most once. Mirrors the
        # way v2 learns on the cycle; defensive so it never breaks a read.
        if self._preference is not None:
            learn = getattr(self._preference, "learn_from_stores", None)
            if callable(learn):
                try:
                    learn(
                        getattr(request.app.state, "decision_store", None),
                        getattr(request.app.state, "outcome_store", None),
                    )
                except Exception:  # noqa: BLE001 — calibration never blocks the cycle
                    pass

        # v5: a causal port re-attributes readings to causes vs symptoms
        # before selection, sealing each attribution into the evidence ledger
        # (provability gate: an unsealed attribution is refused). The EFE
        # collapse then operates over the sealed, attributed structure.
        if self._causal_port is not None:
            readings = self._causal_port.attribute(readings, tenant=tenant)

        # v2: a live learner supplies the accumulated model of normal for
        # this tenant instead of rebuilding it from history each cycle. The
        # concrete v1 ModelOfNormal warms from the reading's ledger history.
        model: ModelOfNormal = (
            self._learner.as_model(tenant=tenant)
            if self._learner is not None
            else ModelOfNormal()
        )

        # v4: an EFE selector chooses a policy (a set evaluated together)
        # rather than a surprise ranking. The v1 selector slots beneath it
        # and is the fallback when no EFE selector is injected.
        if self._efe_selector is not None:
            selection = self._efe_selector.select(
                readings, model, preference=self._preference, config=self._config
            )
        else:
            selection = select(readings, model, self._config)

        # v2: fold this cycle's observations into the live model AFTER
        # predicting on it (predict, then learn — proper online updating,
        # never a sliding window). Safety dimensions are pinned and ignore
        # this; only descriptive volume normals accumulate.
        if self._learner is not None:
            for reading in readings:
                self._learner.observe(reading, tenant=tenant)

        # Report the highest live rung so the interface can show which of the
        # ladder is active. The selectors set their own base tag; the engine
        # owns the composite capability because only it knows what's injected.
        selection.selector_version = self.capability()
        return selection

    def capability(self) -> str:
        """The active rung label, e.g. 'v5' when the full stack is injected."""
        if self._causal_port is not None:
            return "v5"
        if self._efe_selector is not None:
            return "v4"
        if self._preference is not None:
            return "v3"
        if self._learner is not None:
            return "v2"
        return "v1.5" if self._config.enable_redundancy_collapse else "v1"

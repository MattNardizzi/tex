"""
The v2-v5 scaffolds must be inert: real seams, empty organs. Each method
raises NotImplementedError on purpose so the scaffold can never fake
behavior. The engine must expose the injection points without using them
in v1.
"""

from __future__ import annotations

import inspect


from tex.vigil.causal import CausalAttributionPort
from tex.vigil.efe import ExpectedFreeEnergySelector
from tex.vigil.engine import VigilEngine
from tex.vigil.learning import DirichletNormalLearner
from tex.vigil.normal import ModelOfNormal
from tex.vigil.preference import PreferenceModel


def test_v2_learner_is_live() -> None:
    # v2 is built: the learner accumulates and exposes a model of normal.
    learner = DirichletNormalLearner()
    model = learner.as_model()
    assert isinstance(model, ModelOfNormal)
    snap = learner.snapshot()
    assert snap["family"] == "gamma_poisson"
    assert isinstance(learner.snapshot_sha256(), str)


def test_v3_preference_is_live() -> None:
    # v3 is built: VoI scores and a calibrated threshold are real numbers.
    pref = PreferenceModel()
    assert isinstance(pref.speak_threshold(), float)
    assert isinstance(pref.value_of_information(object(), object()), float)


def test_v4_efe_is_live() -> None:
    # v4 is built: with no preference it delegates to v1 and returns a real
    # selection rather than raising.
    efe = ExpectedFreeEnergySelector()
    selection = efe.select([], ModelOfNormal())
    assert selection.standing in ("Absolute", "Open")


def test_v5_causal_is_live() -> None:
    # v5 is built: attribute returns readings and counterfactual yields a
    # sealed claim (or None), never raising NotImplementedError.
    port = CausalAttributionPort()
    assert port.attribute([], tenant=None) == []
    from tex.vigil.dimensions import DimensionReading

    execution = DimensionReading(
        key="execution", kind="gamma", observation=(2.0, 1.0), slots={"count": 2}
    )
    claim = port.counterfactual(execution, tenant=None)
    assert claim is not None and claim.proof.sha256


def test_engine_exposes_all_four_seams() -> None:
    # The constructor must accept each later-rung collaborator so they slot
    # in by injection without a rewrite.
    params = set(inspect.signature(VigilEngine.__init__).parameters)
    assert {"learner", "preference", "efe_selector", "causal_port"} <= params


def test_engine_v1_path_ignores_unset_seams() -> None:
    # With no seams injected, the engine runs the concrete v1 path. We only
    # assert it constructs and the seams default to None.
    engine = VigilEngine()
    assert engine._learner is None
    assert engine._preference is None
    assert engine._efe_selector is None
    assert engine._causal_port is None

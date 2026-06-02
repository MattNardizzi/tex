"""
v4 — expected free energy policy selection (ExpectedFreeEnergySelector).

The selector must:
  * reduce to v1's surprise ranking when preference is uniform,
  * suppress a redundant symptom at the SET level once its cause is named
    (the collapse happens inside the objective, not as a post-hoc filter),
  * NOT silence a safety (normative-floor) line just because a cause was
    named — v3's floor survives v4's collapse,
  * always speak the human-decision gate,
  * return the identical VigilSelection shape, tagged selector_version v4.
"""

from __future__ import annotations

from typing import Any

from tex.vigil.dimensions import DimensionReading, ProofRef
from tex.vigil.efe import ExpectedFreeEnergySelector
from tex.vigil.normal import ModelOfNormal
from tex.vigil.preference import PreferenceModel
from tex.vigil.selector import SelectorConfig, select


class _UniformPreference:
    """A preference with no asymmetry: zero pragmatic value, base threshold."""

    def value_of_information(self, utterance: Any, principal: Any = None) -> float:
        return 0.0

    def speak_threshold(self) -> float:
        return SelectorConfig().min_surprise


def _gamma(key: str, count: float, explained_by: tuple[str, ...] = ()) -> DimensionReading:
    return DimensionReading(
        key=key,
        kind="gamma",
        observation=(float(count), 1.0),
        history=[],
        slots={"count": int(count)},
        proof=ProofRef(kind=key, id=f"{key}-1"),
        explained_by=explained_by,
    )


def _spoken_dims(selection) -> list[str]:
    return [u.dimension for u in selection.utterances]


def test_uniform_preference_reduces_to_v1_ranking() -> None:
    # Distinct counts -> distinct surprises against the cold model.
    readings = [
        _gamma("discovery", 12),
        _gamma("execution", 6),
        _gamma("learning", 4),
    ]
    model = ModelOfNormal()
    cfg = SelectorConfig()

    v1 = select(list(readings), model, cfg)
    efe = ExpectedFreeEnergySelector().select(
        list(readings), model, preference=_UniformPreference(), config=cfg
    )

    # Same lines, same order, same standing — EFE adds nothing over v1 here.
    assert _spoken_dims(efe) == _spoken_dims(v1)
    assert efe.standing == v1.standing
    assert efe.selector_version == "v4"


def test_set_level_collapse_suppresses_redundant_symptom() -> None:
    # A loud cause (discovery) and a quieter descriptive symptom that
    # declares it as cause. Under uniform preference the symptom's value
    # collapses to zero once the cause is named, so it is suppressed.
    cause = _gamma("discovery", 14)
    symptom = _gamma("execution", 3, explained_by=("discovery",))
    model = ModelOfNormal()

    efe = ExpectedFreeEnergySelector().select(
        [cause, symptom], model, preference=_UniformPreference(), config=SelectorConfig()
    )
    dims = _spoken_dims(efe)
    assert "discovery" in dims
    assert "execution" not in dims
    assert efe.suppressed >= 1


def test_safety_line_survives_collapse() -> None:
    # identity is a normative floor. Even when discovery explains its rise,
    # the EFE objective keeps it spoken (its pragmatic floor outweighs the
    # epistemic collapse) — you never silence a live safety fact.
    cause = _gamma("discovery", 14)
    symptom = _gamma("identity", 2, explained_by=("discovery",))
    model = ModelOfNormal()

    efe = ExpectedFreeEnergySelector().select(
        [cause, symptom], model, preference=PreferenceModel(), config=SelectorConfig()
    )
    dims = _spoken_dims(efe)
    assert "discovery" in dims
    assert "identity" in dims  # the floor held


def test_human_gate_always_spoken() -> None:
    gate = DimensionReading(
        key="human_decision",
        kind="gamma",
        observation=(3.0, 1.0),
        slots={"count": 3},
        proof=ProofRef(kind="decision", id="d1"),
        is_human_gate=True,
    )
    efe = ExpectedFreeEnergySelector().select(
        [gate, _gamma("discovery", 8)], ModelOfNormal(),
        preference=PreferenceModel(), config=SelectorConfig()
    )
    assert efe.human_decision is not None
    assert efe.human_decision.dimension == "human_decision"
    assert efe.human_decision.requires_human is True


def test_no_preference_delegates_to_v1() -> None:
    readings = [_gamma("discovery", 12), _gamma("execution", 6)]
    model = ModelOfNormal()
    cfg = SelectorConfig()
    efe = ExpectedFreeEnergySelector().select(list(readings), model, config=cfg)
    v1 = select(list(readings), model, cfg)
    assert _spoken_dims(efe) == _spoken_dims(v1)
    # v1 path keeps its own version tag (v1.5 with collapse on).
    assert efe.selector_version == v1.selector_version


def test_output_contract_unchanged() -> None:
    efe = ExpectedFreeEnergySelector().select(
        [_gamma("discovery", 9)], ModelOfNormal(),
        preference=PreferenceModel(), config=SelectorConfig()
    )
    assert hasattr(efe, "standing")
    assert hasattr(efe, "utterances")
    assert hasattr(efe, "human_decision")
    assert hasattr(efe, "warm")
    assert hasattr(efe, "observed_dimensions")
    assert hasattr(efe, "suppressed")
    assert hasattr(efe, "selector_version")
    for u in efe.utterances:
        assert hasattr(u, "text") and hasattr(u, "dimension")
        assert hasattr(u, "surprise") and hasattr(u, "proof")

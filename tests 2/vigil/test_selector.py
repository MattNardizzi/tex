"""
Selector behavior: surprise chooses the calm few, the human-decision line
is a gate (never ranked), redundancy collapses, and the iron rule holds.
"""

from __future__ import annotations

import pytest

from tex.vigil.dimensions import DimensionReading, ProofRef
from tex.vigil.normal import ModelOfNormal
from tex.vigil.selector import SelectorConfig, select
from tex.vigil.utterances import FORMS, UtteranceForm, fill


def _gamma(key: str, obs: float, history: list[float], **slots) -> DimensionReading:
    slots.setdefault("count", int(obs))
    return DimensionReading(
        key=key,
        kind="gamma",
        observation=(float(obs), 1.0),
        history=list(history),
        slots=slots,
        proof=ProofRef(kind=key, id="x"),
    )


def test_normal_night_is_silent() -> None:
    # discovery observed on-mean against warm history -> nothing to say.
    readings = [_gamma("discovery", 2, [2, 2, 3, 2, 2])]
    sel = select(readings, ModelOfNormal())
    assert sel.utterances == []
    assert sel.standing == "Absolute"


def test_incident_speaks() -> None:
    readings = [_gamma("discovery", 40, [2, 2, 3, 2, 2])]
    sel = select(readings, ModelOfNormal())
    assert len(sel.utterances) == 1
    assert "40 agents" in sel.utterances[0].text
    assert sel.utterances[0].surprise > 1.0
    assert sel.utterances[0].proof is not None


def test_human_decision_is_a_gate_not_ranked() -> None:
    # A tiny, low-surprise abstain count must still always speak.
    gate = DimensionReading(
        key="human_decision",
        kind="gamma",
        observation=(1.0, 1.0),
        history=[1, 1, 1, 1],  # totally ordinary volume
        slots={"count": 1},
        proof=ProofRef(kind="decision", id="d1"),
        is_human_gate=True,
    )
    sel = select([gate], ModelOfNormal())
    assert sel.human_decision is not None
    assert sel.human_decision.requires_human is True
    assert "waiting on your decision" in sel.human_decision.text
    # It is not in the ranked list.
    assert all(not u.requires_human for u in sel.utterances)
    # A pending human decision forces Open.
    assert sel.standing == "Open"


def test_ordering_is_by_surprise_descending() -> None:
    readings = [
        _gamma("discovery", 10, [2, 2, 2]),     # moderate surprise
        _gamma("execution", 50, [2, 2, 2]),     # large surprise
    ]
    sel = select(readings, ModelOfNormal())
    assert len(sel.utterances) == 2
    assert sel.utterances[0].dimension == "execution"
    assert sel.utterances[0].surprise > sel.utterances[1].surprise


def test_v15_redundancy_collapse_suppresses_explained_symptom() -> None:
    # identity declares explained_by=("discovery",). When a discovery spike
    # is named first, the identity line's surprise is attenuated.
    discovery = _gamma("discovery", 30, [2, 2, 2])  # big cause, spoken first
    identity = DimensionReading(
        key="identity",
        kind="gamma",
        observation=(2.0, 1.0),
        history=[],            # neutral prior mean 0.25 -> obs 2 is surprising
        slots={"count": 2},
        proof=ProofRef(kind="governance_coverage", sha256="abc"),
        explained_by=("discovery",),
    )

    collapse_on = select([discovery, identity], ModelOfNormal(), SelectorConfig())
    collapse_off = select(
        [discovery, identity],
        ModelOfNormal(),
        SelectorConfig(enable_redundancy_collapse=False),
    )
    # With collapse off, both speak. With it on, the symptom is suppressed.
    spoken_off = {u.dimension for u in collapse_off.utterances}
    spoken_on = {u.dimension for u in collapse_on.utterances}
    assert "identity" in spoken_off
    assert "discovery" in spoken_on
    assert "identity" not in spoken_on
    assert collapse_on.suppressed >= 1


def test_max_spoken_keeps_the_calm_few() -> None:
    readings = [_gamma(f"discovery", 50, [1, 1, 1]) for _ in range(8)]
    # all identical big surprises; cap should hold
    sel = select(readings, ModelOfNormal(), SelectorConfig(max_spoken=3))
    assert len(sel.utterances) == 3


def test_iron_rule_fill_refuses_missing_slot() -> None:
    form = UtteranceForm(
        dimension="discovery",
        template="{count} agents",
        required_slots=("count",),
        speaks_when=lambda s: True,
    )
    with pytest.raises(ValueError, match="does not improvise"):
        fill(form, {})  # no sealed slot -> refuse, do not guess


def test_iron_rule_text_is_pure_template_fill() -> None:
    # Every spoken line is exactly the authored template filled from slots.
    readings = [_gamma("discovery", 40, [2, 2, 2])]
    sel = select(readings, ModelOfNormal())
    expected = FORMS["discovery"].template.format(count=40)
    assert sel.utterances[0].text == expected

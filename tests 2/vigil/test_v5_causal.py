"""
v5 — causal model underneath EFE (CausalAttributionPort).

The port must:
  * re-tag a declared edge into an attributed, SEALED cause->symptom edge
    when the cause actually fired this cycle,
  * REFUSE an attribution that cannot be sealed / whose chain does not verify
    (provability gate) — the symptom keeps a standalone line,
  * produce a sealed counterfactual that traces to a seal proof and fills an
    authored form only from sealed slots (iron rule),
  * drive the cause/symptom collapse through the EFE selection path.
"""

from __future__ import annotations

from typing import Any

from tex.vigil.causal import (
    CausalAttributionPort,
    CausalSeal,
    CounterfactualClaim,
)
from tex.vigil.dimensions import DimensionReading, ProofRef
from tex.vigil.efe import ExpectedFreeEnergySelector
from tex.vigil.normal import ModelOfNormal
from tex.vigil.selector import SelectorConfig
from tex.vigil.utterances import FORMS, fill


class _BrokenSeal(CausalSeal):
    """Appends but never verifies — forces the provability gate to refuse."""

    def verify_chain(self) -> bool:
        return False


class _UniformPreference:
    def value_of_information(self, utterance: Any, principal: Any = None) -> float:
        return 0.0

    def speak_threshold(self) -> float:
        return SelectorConfig().min_surprise


def _disc(count: float) -> DimensionReading:
    return DimensionReading(
        key="discovery", kind="gamma", observation=(float(count), 1.0),
        slots={"count": int(count)}, proof=ProofRef(kind="scan_run", id="s1"),
    )


def _symptom(key: str, count: float, cause: str = "discovery") -> DimensionReading:
    return DimensionReading(
        key=key, kind="gamma", observation=(float(count), 1.0),
        slots={"count": int(count)}, proof=ProofRef(kind=key, id=f"{key}-1"),
        explained_by=(cause,),
    )


def test_attribution_retags_and_seals() -> None:
    port = CausalAttributionPort()
    out = port.attribute([_disc(12), _symptom("identity", 3)], tenant="t1")
    by_key = {r.key: r for r in out}
    ident = by_key["identity"]
    assert ident.explained_by == ("discovery",)
    assert ident.causal is not None
    assert ident.causal.cause_key == "discovery"
    assert ident.causal.symptom_key == "identity"
    assert ident.causal.proof.sha256  # sealed with a real hash
    assert port.seal.verify_chain() is True
    assert len(port.seal) == 1


def test_unsealed_attribution_is_refused() -> None:
    port = CausalAttributionPort(seal=_BrokenSeal())
    out = port.attribute([_disc(12), _symptom("identity", 3)], tenant="t1")
    ident = {r.key: r for r in out}["identity"]
    # Provability gate: the chain does not verify, so the edge is dropped and
    # no causal claim is attached. The symptom keeps a standalone line.
    assert ident.explained_by == ()
    assert ident.causal is None


def test_cause_absent_is_not_attributed() -> None:
    port = CausalAttributionPort()
    # Symptom declares discovery as cause, but discovery is not present.
    out = port.attribute([_symptom("identity", 3)], tenant="t1")
    ident = out[0]
    assert ident.explained_by == ()
    assert ident.causal is None


def test_counterfactual_traces_to_sealed_proof() -> None:
    port = CausalAttributionPort()
    execution = DimensionReading(
        key="execution", kind="gamma", observation=(4.0, 1.0),
        slots={"count": 4}, proof=ProofRef(kind="decision", id="d1"),
    )
    claim = port.counterfactual(execution, tenant="t1")
    assert isinstance(claim, CounterfactualClaim)
    assert claim.proof.sha256  # sealed
    assert CausalAttributionPort.is_sealed(claim, port.seal) is True
    # Iron rule: the authored counterfactual form fills only from sealed slots.
    form = FORMS[claim.form_key]
    line = fill(form, claim.slots)
    assert "4" in line
    assert "unreviewed" in line


def test_unsealed_counterfactual_is_not_spoken() -> None:
    port = CausalAttributionPort(seal=_BrokenSeal())
    execution = DimensionReading(
        key="execution", kind="gamma", observation=(4.0, 1.0), slots={"count": 4},
    )
    assert port.counterfactual(execution, tenant="t1") is None


def test_counterfactual_none_when_nothing_sealed_to_say() -> None:
    port = CausalAttributionPort()
    # discovery has no counterfactual spec -> None, not a fabricated claim.
    assert port.counterfactual(_disc(5), tenant="t1") is None


def test_collapse_works_through_the_efe_path() -> None:
    # Full v5 -> v4: attribute seals the edge, then EFE collapses the symptom
    # through the objective. Use a descriptive symptom so the collapse is
    # visible as suppression (a normative-floor line would survive).
    port = CausalAttributionPort()
    attributed = port.attribute([_disc(14), _symptom("execution", 3)], tenant="t1")
    efe = ExpectedFreeEnergySelector().select(
        attributed, ModelOfNormal(), preference=_UniformPreference(), config=SelectorConfig()
    )
    dims = [u.dimension for u in efe.utterances]
    assert "discovery" in dims
    assert "execution" not in dims
    assert efe.suppressed >= 1
    # And the attribution that drove the collapse is sealed and verifiable.
    assert port.seal.verify_chain() is True


def test_iron_rule_counterfactual_refuses_missing_slot() -> None:
    form = FORMS["execution_counterfactual"]
    try:
        fill(form, {})  # no sealed count -> must refuse, never improvise
        raised = False
    except ValueError:
        raised = True
    assert raised

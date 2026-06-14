"""
Gate 3 — honesty pins: over-claiming is UNCONSTRUCTIBLE (the L12
``Literal[False]`` pattern applied at composition level), the half-specific
module caveats ride VERBATIM, the vocabulary stays clean, and the object
reports the expected honest split (green-in-test-mode vs certified=False vs
BLOCKED) machine-readably.
"""

from __future__ import annotations

import copy
import json
from typing import Any, Callable

import pytest
from pydantic import ValidationError

from tex.adversarial.completeness import CLAIM, NON_CLAIMS
from tex.engine.verdict_certificate import NEIGHBORHOOD_FAMILY
from tex.evidence.negative_knowledge import FORBIDDEN_UNQUALIFIED_PHRASES
from tex.interchange.gix_witness import FEDERATED_FALSE_REASON
from tex.voice.voice_gate import THRESHOLD_LABEL

from tex.capstone.manifest import (
    BANNED_AUTHORED_PHRASES,
    PIN_CAVEAT,
    TREE_SIZE_CAVEAT,
    CapstoneVerdict,
)


def _manifest(capstone_flow) -> CapstoneVerdict:
    return capstone_flow.compose.manifest


def _mutated(manifest: CapstoneVerdict, mutate: Callable[[dict], None]) -> dict:
    doc = copy.deepcopy(manifest.model_dump(mode="json"))
    mutate(doc)
    return doc


def _prop(doc: dict, leap: str) -> dict[str, Any]:
    for prop in doc["properties"]:
        if prop["leap"] == leap:
            return prop
    raise KeyError(leap)


# ── over-claims are unconstructible ───────────────────────────────────────

def _l12_certified(doc):
    _prop(doc, "L12")["verification"]["certificate"]["certified"] = True

def _l6_federated(doc):
    _prop(doc, "L6")["verification"]["federated"] = True

def _l11_entailment_green(doc):
    # green HALF but the verification stays the absence → incoherent.
    _prop(doc, "L11")["halves"]["entailment"] = "green"

def _l11_lambda_present(doc):
    _prop(doc, "L11")["verification"]["lambda_hat"] = 0.7

def _l11_green_but_not_loaded(doc):
    # green HALF + a λ̂, but a stub/synthetic calibration (model_loaded False,
    # corpus synthetic) — a field guarantee Tex did not earn → must be refused.
    p = _prop(doc, "L11")
    p["halves"]["entailment"] = "green"
    v = p["verification"]
    v["lambda_hat"] = 0.7
    v["calibrated"] = True
    v["model_loaded"] = False
    v["scorer_backend"] = "deterministic-stub"
    v["calibration_corpus_kind"] = "synthetic"

def _l1_not_stand_in(doc):
    _prop(doc, "L1")["verification"]["stand_in"] = False

def _l1_promoted(doc):
    _prop(doc, "L1")["status"] = "green"

def _l4_certified(doc):
    _prop(doc, "L4")["verification"]["certificate"]["certified"] = True

def _l10_pq_durable(doc):
    _prop(doc, "L10")["verification"]["pq_durable"] = True

def _summary_overclaims(doc):
    doc["summary"] = doc["summary"] + " We guarantee correctness."

def _tree_size_caveat_dropped(doc):
    doc["epoch"]["tree_size_caveat"] = "tree_size is the decision count"

def _a_leap_dropped(doc):
    doc["properties"] = doc["properties"][:-1]


@pytest.mark.parametrize(
    "mutation",
    [
        _l12_certified,
        _l6_federated,
        _l11_entailment_green,
        _l11_lambda_present,
        _l11_green_but_not_loaded,
        _l1_not_stand_in,
        _l1_promoted,
        _l4_certified,
        _l10_pq_durable,
        _summary_overclaims,
        _tree_size_caveat_dropped,
        _a_leap_dropped,
    ],
    ids=lambda f: f.__name__.lstrip("_"),
)
def test_overclaim_is_unconstructible(capstone_flow, mutation) -> None:
    doc = _mutated(_manifest(capstone_flow), mutation)
    with pytest.raises(ValidationError):
        CapstoneVerdict.model_validate(doc)


def test_the_green_manifest_itself_revalidates(capstone_flow) -> None:
    """The control: the honest document passes the same validators the
    over-claims fail."""
    doc = _manifest(capstone_flow).model_dump(mode="json")
    assert CapstoneVerdict.model_validate(doc).manifest_sha256() == _manifest(
        capstone_flow
    ).manifest_sha256()


def _l11_coherent_field_green(doc):
    p = _prop(doc, "L11")
    p["halves"]["entailment"] = "green"
    v = p["verification"]
    v["lambda_hat"] = 0.83
    v["calibrated"] = True
    v["model_loaded"] = True
    v["scorer_backend"] = "transformers-cross-encoder"
    v["calibration_corpus_kind"] = "field"


def test_a_coherent_field_green_l11_validates_and_joins_the_green_split(
    capstone_flow,
) -> None:
    """The positive control for the NEW capstone half: when the L11
    verification fields genuinely back a field calibration (loaded neural
    backend + a λ̂ + a field corpus), entailment=green VALIDATES — the half is
    constructible WHEN real. The live manifest never reaches this branch; its
    commitment is the absence, so it stays in the blocked split."""
    doc = _mutated(_manifest(capstone_flow), _l11_coherent_field_green)
    m = CapstoneVerdict.model_validate(doc)  # must NOT raise
    assert m.property_for("L11").halves["entailment"] == "green"
    assert "L11.entailment" in m.honest_split.get("green", ())
    assert "L11.entailment" not in m.honest_split.get("blocked", ())
    # …and the live (unmutated) manifest is the blocked control.
    live = _manifest(capstone_flow)
    assert live.honest_split["blocked"] == ("L11.entailment",)


# ── module caveats ride verbatim ──────────────────────────────────────────

def test_module_caveats_are_verbatim(capstone_flow) -> None:
    m = _manifest(capstone_flow)
    assert m.property_for("L7").caveats == (CLAIM,) + NON_CLAIMS
    assert FEDERATED_FALSE_REASON in m.property_for("L6").caveats
    assert THRESHOLD_LABEL in m.property_for("L11").caveats
    assert NEIGHBORHOOD_FAMILY in m.property_for("L12").caveats
    l1_note = m.property_for("L1").caveats[0]
    assert "TEX_ZKPDP_ALLOW_SHIM=1" in l1_note and "stand-in" in l1_note
    assert "THIS ledger epoch" in m.property_for("L3").caveats[0]
    assert m.property_for("L4").caveats[0].startswith("L4 ActionClass lattice")
    assert "ECDSA-P256" in m.property_for("L10").caveats[0]
    assert m.pins.pin_caveat == PIN_CAVEAT
    assert m.epoch.tree_size_caveat == TREE_SIZE_CAVEAT


# ── vocabulary over the serialized object ─────────────────────────────────

def test_vocabulary_over_serialized_claims(capstone_flow) -> None:
    """No unqualified over-claim survives serialization. Module-sourced
    caveat strings are stripped first (they contain vetted negations like
    'no proven coverage'); everything left — the prose WE authored plus all
    machine fields — must be clean."""
    m = _manifest(capstone_flow)
    text = json.dumps(m.model_dump(mode="json")).lower()
    for prop in m.properties:
        for caveat in prop.caveats:
            text = text.replace(json.dumps(caveat).strip('"').lower(), "")
    banned_everywhere = (
        "proven correct",
        "zk proof of the verdict",
        "guarantee",
    ) + FORBIDDEN_UNQUALIFIED_PHRASES
    for phrase in banned_everywhere:
        assert phrase not in text, f"banned phrase survived: {phrase!r}"

    authored = " ".join(
        [m.summary] + [p.title for p in m.properties]
    ).lower()
    for phrase in BANNED_AUTHORED_PHRASES:
        assert phrase not in authored, f"authored prose contains {phrase!r}"


# ── the honest split, machine-readable ────────────────────────────────────

def test_honest_split_is_exactly_the_expected_one(capstone_flow) -> None:
    """ROADMAP:295 + the COORDINATION rows: which halves are green vs
    test-mode vs uncertified vs estimate-only vs BLOCKED. This is the
    receipt the whole Wave-2 program promised — pinned exactly."""
    assert _manifest(capstone_flow).honest_split == {
        "blocked": ("L11.entailment",),
        "estimate_only": ("L12.qif",),
        "green": (
            "L3",
            "L4.floor",
            "L5",
            "L6",
            "L7",
            "L8",
            "L9",
            "L10.maturity_signal",
            "L11.seal",
        ),
        "green_test_mode": ("L1", "L2"),
        "runtime_dependent": ("L10.pq_signing",),
        "uncertified": ("L4.certificate", "L12.robustness"),
    }


def test_twelve_leaps_cover_exactly_the_eight_properties(capstone_flow) -> None:
    m = _manifest(capstone_flow)
    assert sorted(p.leap for p in m.properties) == sorted(
        f"L{i}" for i in range(1, 13)
    )
    assert {p.property_index for p in m.properties} == set(range(1, 9))


def test_the_sealed_fact_is_honest_about_itself(capstone_flow) -> None:
    """The chain-sealed capstone fact: ANSWER kind, research-early maturity,
    a subject that can never shadow the decision's seal binding."""
    record = capstone_flow.compose.capstone_record
    manifest = _manifest(capstone_flow)
    assert record.fact.kind.value == "answer"
    assert record.fact.maturity.value == "research_early"
    assert record.fact.subject_id == f"capstone:{manifest.decision.request_id}"
    assert record.fact.subject_id != manifest.decision.request_id
    assert "never promoted" in record.fact.claim

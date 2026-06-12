"""
The PQ scenario's two environment branches, both pinned.

The L10 maturity probe is environment-dependent: cryptography>=48 ships a
pyca ML-DSA backend the probe (correctly) reports as durable, so the
PQ-non-repudiation claim is not lowered (PERMIT, no flag, no sealed fact);
older environments report no backend and the signal fires (ABSTAIN + flag +
sealed PQ-durable=false fact). Before this suite existed, the capstone flow
hardcoded the lowered outcome and crashed on every fresh install.

Both branches are forced here via the probe's single source of truth
(``ml_dsa.active_backend_id``) so neither depends on the box running the
tests. The shared session fixture in ``conftest.py`` pins the lowered
branch; this file owns the durable branch plus the new manifest-coherence
pins.
"""

from __future__ import annotations

import copy
import logging
import shutil

import pytest
from pydantic import ValidationError

from tex.capstone.flow import CapstoneFlowResult, run_capstone_flow
from tex.capstone.manifest import CapstoneVerdict, stable_json
from tex.capstone.verify import CapstonePins, verify_capstone
from tex.provenance.models import SealedFactKind


@pytest.fixture(scope="session")
def capstone_flow_durable(tmp_path_factory) -> CapstoneFlowResult:
    """One epoch driven with the probe pinned to the durable pyca backend —
    the cryptography>=48 fresh-install environment, reproduced anywhere."""
    logging.disable(logging.CRITICAL)
    mp = pytest.MonkeyPatch()
    try:
        from tex.pqcrypto import ml_dsa

        mp.setattr(
            ml_dsa, "active_backend_id", lambda: "pyca-cryptography-native"
        )
        work = tmp_path_factory.mktemp("capstone-flow-durable")
        return run_capstone_flow(
            work,
            neighborhood_samples=6,
            campaign_seeds=3,
            campaign_query_budget=12,
        )
    finally:
        mp.undo()
        logging.disable(logging.NOTSET)


def _prop(doc: dict, leap: str) -> dict:
    for prop in doc["properties"]:
        if prop["leap"] == leap:
            return prop
    raise KeyError(leap)


# ── the durable branch composes and verifies ──────────────────────────────

def test_durable_branch_decision_shape(capstone_flow_durable) -> None:
    """Durable backend ⇒ the engine must neither lower nor flag nor seal."""
    materials = capstone_flow_durable.materials
    decision = materials.pq_result.decision
    assert decision.verdict.value == "PERMIT"
    assert "pq_non_repudiation_unavailable" not in decision.uncertainty_flags
    pq_subject = str(decision.request_id)
    kinds = [
        (r.fact.kind, "pq_durable" in r.fact.detail)
        for r in materials.ledger.list_all()
        if r.fact.subject_id == pq_subject
    ]
    # ATTEMPT + the M0 decision seal only — no PQ-durability fact.
    assert kinds == [
        (SealedFactKind.ATTEMPT, False),
        (SealedFactKind.DECISION, False),
    ]


def test_durable_branch_manifest_records_the_outcome(capstone_flow_durable) -> None:
    manifest = capstone_flow_durable.compose.manifest
    l10 = manifest.property_for("L10")
    assert l10.status == "green"
    assert l10.verification["maturity_outcome"] == "durable_not_lowered"
    assert l10.verification["pq_durable"] is True
    assert l10.verification["claim_honored"] is True
    assert l10.verification["active_backend_id"] == "pyca-cryptography-native"
    assert l10.halves["pq_signing"] == "runtime_dependent"
    assert l10.ledger_sequences == ()
    # The hold rides the drift ABSTAIN when the PQ companion is PERMIT.
    l8 = manifest.property_for("L8")
    assert l8.artifacts == ("decision_drift",)
    assert l8.verification["hold_carrier"] == "decision_drift"


def test_durable_branch_verifies_offline(capstone_flow_durable) -> None:
    pins = CapstonePins.from_file(capstone_flow_durable.pins_path)
    res = verify_capstone(capstone_flow_durable.bundle_dir, pins)
    assert res.ok, [c.name for c in res.checks if not c.ok]
    assert res.check("L10.fact").ok
    assert res.check("L8.hold").ok


# ── the lowered branch carries the new outcome field too ──────────────────

def test_lowered_branch_manifest_records_the_outcome(capstone_flow) -> None:
    manifest = capstone_flow.compose.manifest
    l10 = manifest.property_for("L10")
    assert l10.verification["maturity_outcome"] == "lowered_to_abstain"
    assert l10.verification["pq_durable"] is False
    assert len(l10.ledger_sequences) == 1
    l8 = manifest.property_for("L8")
    assert l8.artifacts == ("decision_pq",)


# ── over-claims stay unconstructible across both branches ─────────────────

def _doc(manifest: CapstoneVerdict) -> dict:
    return copy.deepcopy(manifest.model_dump(mode="json"))


def test_durable_without_honored_claim_is_unconstructible(
    capstone_flow_durable,
) -> None:
    doc = _doc(capstone_flow_durable.compose.manifest)
    _prop(doc, "L10")["verification"]["claim_honored"] = False
    with pytest.raises(ValidationError):
        CapstoneVerdict.model_validate(doc)


def test_durable_with_sealed_fact_claim_is_unconstructible(
    capstone_flow_durable,
) -> None:
    doc = _doc(capstone_flow_durable.compose.manifest)
    _prop(doc, "L10")["ledger_sequences"] = [3]
    with pytest.raises(ValidationError):
        CapstoneVerdict.model_validate(doc)


def test_missing_maturity_outcome_is_unconstructible(capstone_flow) -> None:
    doc = _doc(capstone_flow.compose.manifest)
    del _prop(doc, "L10")["verification"]["maturity_outcome"]
    with pytest.raises(ValidationError):
        CapstoneVerdict.model_validate(doc)


def test_pq_signing_half_cannot_be_promoted(capstone_flow_durable) -> None:
    """Even on a durable box, pq_signing stays runtime_dependent — the
    half describes the claim class, never this manifest."""
    doc = _doc(capstone_flow_durable.compose.manifest)
    _prop(doc, "L10")["halves"]["pq_signing"] = "green"
    with pytest.raises(ValidationError):
        CapstoneVerdict.model_validate(doc)


# ── a forged outcome flip is caught offline ───────────────────────────────

def test_outcome_flip_over_lowered_epoch_is_caught(
    capstone_flow, tmp_path
) -> None:
    """Adversary rewrites a lowered epoch's manifest into a fully COHERENT
    durable record (so pydantic accepts it). The chain-sealed manifest
    digest must catch the swap, and the L10 offline check must refuse the
    PERMIT-claiming record over the ABSTAIN decision doc."""
    bundle = tmp_path / "bundle"
    shutil.copytree(capstone_flow.bundle_dir, bundle)
    doc = _doc(capstone_flow.compose.manifest)
    l10 = _prop(doc, "L10")
    l10["verification"]["maturity_outcome"] = "durable_not_lowered"
    l10["verification"]["pq_durable"] = True
    l10["verification"]["claim_honored"] = True
    l10["verification"]["signer_maturity"] = "durable"
    l10["verification"]["active_backend_id"] = "pyca-cryptography-native"
    l10["ledger_sequences"] = []
    CapstoneVerdict.model_validate(doc)  # coherent on its face
    (bundle / "manifest.json").write_text(stable_json(doc), encoding="utf-8")
    pins = CapstonePins.from_file(capstone_flow.pins_path)
    res = verify_capstone(bundle, pins)
    assert not res.ok
    assert not res.check("manifest.seal_binding").ok
    assert not res.check("L10.fact").ok

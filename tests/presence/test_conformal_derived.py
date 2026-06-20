"""DERIVED claims: the conformal correctness floor, honestly labelled.

Pins the honest edge: the gate reports the coverage mode the computation
ACTUALLY ran (transductive ≈ approximate), and never announces "calibrated"
unless a real calibration set was configured.
"""

from __future__ import annotations

import pytest

from tex.presence.contract import ClaimKind, PresenceClaim, PresenceTier
from tex.presence.gate import PresenceTruthGate


def _derive(gate, state, agent_id, *, tenant=None):
    claim = PresenceClaim(
        claim_id=f"root_cause_region:{agent_id}",
        text_span="which step was the root cause",
        kind=ClaimKind.DERIVED,
    )
    return gate.evaluate(request=state, tenant=tenant, draft="x", claims=(claim,))[0]


def test_derived_carries_transductive_floor(populated_state):
    gate = PresenceTruthGate()
    v = _derive(gate, populated_state, populated_state.agent_a.agent_id)
    assert v.tier is PresenceTier.DERIVED
    assert v.correctness_floor == pytest.approx(0.9)  # 1 - default alpha 0.1
    assert v.coverage_mode == "transductive"          # NOT calibrated
    assert v.evidence and all(r.store == "action_ledger" for r in v.evidence)
    assert v.recomputed_value["trace_length"] == 6
    assert v.recomputed_value["set_size"] >= 1


def test_derived_never_claims_calibrated_without_calibration(populated_state):
    gate = PresenceTruthGate()
    v = _derive(gate, populated_state, populated_state.agent_a.agent_id)
    # The honest-edge invariant: a transductive run must never carry the
    # "calibrated" mode, even though it has a 1-alpha floor.
    assert v.coverage_mode != "calibrated"


def test_derived_calibrated_mode_when_calibration_present(populated_state, tmp_path, monkeypatch):
    calib = tmp_path / "calib.txt"
    calib.write_text("\n".join(str(x) for x in (0.1, 0.2, 0.3, 0.4, 0.5)), encoding="utf-8")
    monkeypatch.setenv("TEX_CONFORMAL_CALIBRATION_PATH", str(calib))

    gate = PresenceTruthGate()
    v = _derive(gate, populated_state, populated_state.agent_a.agent_id)
    assert v.tier is PresenceTier.DERIVED
    assert v.coverage_mode == "calibrated"
    assert v.correctness_floor == pytest.approx(0.9)


def test_derived_empty_trace_abstains(populated_state):
    gate = PresenceTruthGate()
    # agent_b has no actions in the ledger → no trace → ABSTAIN.
    v = _derive(gate, populated_state, populated_state.agent_b.agent_id)
    assert v.tier is PresenceTier.ABSTAIN
    assert "insufficient-trace" in v.reason


def test_derived_no_target_abstains(populated_state):
    gate = PresenceTruthGate()
    claim = PresenceClaim(
        claim_id="root_cause_region",
        text_span="which step was the decisive error",
        kind=ClaimKind.DERIVED,
    )
    v = gate.evaluate(request=populated_state, tenant=None, draft="x", claims=(claim,))[0]
    assert v.tier is PresenceTier.ABSTAIN
    assert v.reason == "missing-target"

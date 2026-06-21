"""The flywheel, end-to-end through the REAL gate (the Definition of Done).

Simulate N human resolutions for one tenant via the seal hook, then drive
``PresenceTruthGate.evaluate`` for that tenant:

  * below MIN_CALIBRATION_N → the gate stays honestly ``transductive``;
  * at MIN_CALIBRATION_N → it flips to ``calibrated`` and the region tightens
    (the floor refines from approximate to a formal 1−α);
  * another tenant's gate, same trace, is UNCHANGED (strict per-tenant).

Everything routes through ``TEX_PRESENCE_CALIBRATION_DIR`` (the production
contract), so the hook's writer and the gate's reader hit the same files.
"""

from __future__ import annotations

import pytest

from tex.presence.contract import ClaimKind, PresenceClaim, PresenceTier
from tex.presence.gate import PresenceTruthGate
from tex.presence.memory import (
    CalibrationResolution,
    MIN_CALIBRATION_N,
    record_resolution_for_calibration,
)

from .conftest import build_state, make_decision


def _derive(gate, state, agent_id, *, tenant):
    claim = PresenceClaim(
        claim_id=f"root_cause_region:{agent_id}",
        text_span="which step was the root cause",
        kind=ClaimKind.DERIVED,
    )
    return gate.evaluate(request=state, tenant=tenant, draft="x", claims=(claim,))[0]


def _feed(tenant, n, *, score=0.5):
    for i in range(n):
        record_resolution_for_calibration(
            tenant,
            CalibrationResolution(decision=make_decision(final_score=score, n=i), human_verdict="refused"),
        )


def test_gate_flips_to_calibrated_at_min_n_and_tightens(calib_dir):
    gate = PresenceTruthGate()
    state, agent_id = build_state()

    # Cold: no labels → transductive, and (on this trace) a WIDE region.
    cold = _derive(gate, state, agent_id, tenant="acme")
    assert cold.tier is PresenceTier.DERIVED
    assert cold.coverage_mode == "transductive"
    assert cold.recomputed_value["calibration_n"] == 0
    transductive_size = cold.recomputed_value["set_size"]
    assert transductive_size >= 1

    # One short of the floor: still transductive (a biased handful is not a floor).
    _feed("acme", MIN_CALIBRATION_N - 1)
    warm = _derive(gate, state, agent_id, tenant="acme")
    assert warm.coverage_mode == "transductive"
    assert warm.recomputed_value["calibration_n"] == MIN_CALIBRATION_N - 1

    # Cross the floor: the gate flips to calibrated, the floor number is unchanged
    # (still 1−α), the MODE refines to formal, and the region tightens.
    _feed("acme", 1)
    hot = _derive(gate, state, agent_id, tenant="acme")
    assert hot.tier is PresenceTier.DERIVED
    assert hot.coverage_mode == "calibrated"
    assert hot.correctness_floor == pytest.approx(0.9)
    assert hot.recomputed_value["calibration_n"] == MIN_CALIBRATION_N
    assert hot.recomputed_value["coverage_mode"] == "calibrated"
    # Tenant errors cluster near 0.5 → a higher threshold than the in-trace
    # quantile → the localized region shrinks toward the true peak.
    assert hot.recomputed_value["set_size"] < transductive_size


def test_other_tenant_gate_is_unchanged(calib_dir):
    gate = PresenceTruthGate()
    state, agent_id = build_state()

    _feed("acme", MIN_CALIBRATION_N)  # acme calibrates
    assert _derive(gate, state, agent_id, tenant="acme").coverage_mode == "calibrated"

    # globex never resolved a thing → its gate is identical to the cold gate.
    other = _derive(gate, state, agent_id, tenant="globex")
    assert other.tier is PresenceTier.DERIVED
    assert other.coverage_mode == "transductive"
    assert other.recomputed_value["calibration_n"] == 0


def test_tenant_none_is_transductive_without_a_global_set(calib_dir):
    # The legacy/no-tenant path stays transductive when nothing global is set,
    # even while acme is fully calibrated (no cross-tenant leak into the null path).
    gate = PresenceTruthGate()
    state, agent_id = build_state()
    _feed("acme", MIN_CALIBRATION_N)

    v = _derive(gate, state, agent_id, tenant=None)
    assert v.coverage_mode == "transductive"
    assert v.recomputed_value["calibration_n"] is None

"""
Gate 2 — the tamper matrix as parametrized tests: every adversary row
caught AND attributed to the RIGHT proof. The rows the composition doctrine
demands (PROMPT/ROADMAP): byte-flip per chain (integrity), tamper-then-resign
per chain (integrity PASSES, only the pin catches it), verdict swap (L2
nonce + L1 relation), forked checkpoint (witnesses refuse), epoch rebuilt
minus one PERMIT (L3), and the manifest-swap row that proves digest binding.
"""

from __future__ import annotations

import pytest

from tex.capstone.tamper import (
    tamper_artifact_swap,
    tamper_checkpoint_fork,
    tamper_epoch_minus_permit,
    tamper_evidence_byteflip,
    tamper_evidence_resign,
    tamper_jwt_signature_forged,
    tamper_ledger_byteflip,
    tamper_ledger_resign,
    tamper_manifest_edit,
    tamper_verdict_swap,
    tamper_voice_byteflip,
    tamper_voice_remint,
)

_FILE_ROWS = [
    tamper_ledger_byteflip,
    tamper_evidence_byteflip,
    tamper_voice_byteflip,
    tamper_ledger_resign,
    tamper_evidence_resign,
    tamper_voice_remint,
    tamper_verdict_swap,
    tamper_jwt_signature_forged,
    tamper_epoch_minus_permit,
    tamper_artifact_swap,
    tamper_manifest_edit,
]


@pytest.mark.parametrize("row_fn", _FILE_ROWS, ids=lambda f: f.__name__)
def test_tamper_row_caught(row_fn, capstone_flow, tmp_path) -> None:
    row = row_fn(capstone_flow.bundle_dir, tmp_path)
    assert row.caught, f"{row.name}: NOT caught — {row.detail}"


def test_checkpoint_fork_all_witnesses_refuse(capstone_flow) -> None:
    row = tamper_checkpoint_fork(capstone_flow)
    assert row.caught, row.detail
    assert len(row.caught_by) >= 3  # one refusal per witness, not a quorum trick
    assert "equal tree size" in row.detail  # the equivocation reason, verbatim


def test_resign_rows_prove_the_pin_is_load_bearing(
    capstone_flow, tmp_path
) -> None:
    """The attribution that matters most: after tamper-then-resign, INTEGRITY
    PASSES — the forgery is internally consistent — and only the key pin
    catches it. If these details ever flip, the pin stopped being the catch."""
    ledger_row = tamper_ledger_resign(capstone_flow.bundle_dir, tmp_path / "a")
    assert "integrity_passed=True" in ledger_row.detail
    evidence_row = tamper_evidence_resign(capstone_flow.bundle_dir, tmp_path / "b")
    assert "integrity_passed=True" in evidence_row.detail
    remint_row = tamper_voice_remint(capstone_flow.bundle_dir, tmp_path / "c")
    assert "self_verifies=True" in remint_row.detail
    assert "unpinned_authorship=None" in remint_row.detail  # the honest gap


def test_verdict_swap_attributed_to_both_proofs(capstone_flow, tmp_path) -> None:
    row = tamper_verdict_swap(capstone_flow.bundle_dir, tmp_path)
    assert row.caught
    assert "verdict_nonce_mismatch" in row.detail
    assert "zkpdp_arbitration_relation_unsat" in row.detail
    assert "deny_floor_requires_forbid" in row.detail


def test_omission_attack_both_variants(capstone_flow, tmp_path) -> None:
    """(a) hide the PERMIT, keep its attempt → conservation GATED-BROKEN;
    (b) hide the attempt too → conservation balances but the sealed epoch
    commitment's roots refuse the rebuild."""
    row = tamper_epoch_minus_permit(capstone_flow.bundle_dir, tmp_path)
    assert row.caught, row.detail
    assert "(a) conservation=GATED-BROKEN" in row.detail
    assert "(b) conservation=GATED-HOLDS" in row.detail
    assert "epoch_rebuild_ok=False" in row.detail

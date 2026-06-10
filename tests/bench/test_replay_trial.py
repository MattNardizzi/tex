"""
Gate for the Replay Trial (tex.bench.replay_trial).

One run against the real runtime, asserting each of the three flagship claims
explicitly so a regression in any one fails loudly:
  1. a structural FORBID survives all 10 paraphrases (invariance to content);
  2. the PEP contract holds (released=False) and the eBPF datapath is NOT claimed
     to have run (honest off-Linux);
  3. the sealed bundle is court-grade (integrity + pinned Tex authorship) and
     both a byte-flip and a tamper-then-resign forgery are caught.
"""

from __future__ import annotations

from tex.bench.replay_trial import run_replay_trial
from tex.domain.verdict import Verdict


def test_replay_trial_all_three_claims_hold(runtime, tmp_path) -> None:
    res = run_replay_trial(runtime, bundle_path=tmp_path / "replay.bundle.jsonl")

    # Claim 1 — structural FORBID survives every paraphrase.
    assert res.paraphrase_count == 10
    assert res.all_forbid
    assert set(res.verdicts) == {Verdict.FORBID.value}

    # Claim 2 — PEP would block; no overclaimed kernel execution.
    assert res.pep_released is False
    assert res.kernel_datapath_executed is False

    # Claim 3 — offline, tamper-evident, authorship-pinned.
    assert res.sealed_record_count == 10
    assert res.clean_verification.valid
    assert res.clean_verification.authorship_ok is True
    assert res.tamper_byteflip_caught
    assert res.tamper_resign_caught

    assert res.passed

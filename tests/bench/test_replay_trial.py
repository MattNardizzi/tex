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

import math
from types import SimpleNamespace

import pytest

from tex.bench.replay_trial import (
    PARAPHRASES,
    run_replay_trial,
    run_seeded_neighborhood_trial,
)
from tex.domain.verdict import Verdict
from tex.engine.crc_gate import hoeffding_bentkus_ucb
from tex.engine.verdict_certificate import (
    NEIGHBORHOOD_FAMILY,
    generate_neighborhood,
)


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


# ── Wave 2 / L12: the seeded-neighborhood robustness half (additive) ─────
#
# The fixed-10 trial above is the regression pin — paraphrase_count == 10 and
# sealed_record_count == 10 must stay true forever. The tests below exercise
# the NEW path: a seeded draw from the named perturbation family, a genuine
# Hoeffding-Bentkus p_low on FORBID-stability, and honest degradation when
# instability is injected.

_SEED = 20260610
_N = 40
_DELTA = 0.05


def test_seeded_neighborhood_trial_earns_its_p_low(runtime) -> None:
    res = run_seeded_neighborhood_trial(
        runtime, seed=_SEED, n_samples=_N, delta=_DELTA
    )

    # The neighborhood is the generator's output for this seed — replayable.
    assert res.samples == generate_neighborhood(
        base_texts=PARAPHRASES, seed=_SEED, n_samples=_N
    )
    assert res.family == NEIGHBORHOOD_FAMILY
    assert all(s not in set(PARAPHRASES) for s in res.samples)

    # Structural FORBID survives every sampled perturbation.
    assert res.n_samples == _N
    assert set(res.verdicts) == {Verdict.FORBID.value}
    assert res.all_stable and res.n_stable == _N

    # The p_low is the closed form, computed here independently: at zero
    # observed instability the Bentkus inversion is exact, 1 - (delta/e)^(1/n),
    # and beats Hoeffding's sqrt(ln(1/delta)/(2n)) — so 40/40 stable at 95%
    # confidence lower-bounds the family's FORBID rate at ~0.905.
    hoeffding = math.sqrt(math.log(1.0 / _DELTA) / (2.0 * _N))
    bentkus = 1.0 - (_DELTA / math.e) ** (1.0 / _N)
    assert res.p_low == pytest.approx(1.0 - min(hoeffding, bentkus), abs=1e-9)
    assert res.p_low > 0.9

    # The certificate carries the honest posture: computed, named, uncertified.
    cert = res.certificate
    assert cert.enabled is True
    assert cert.certified is False  # synthetic family cannot certify
    assert cert.robustness_neighborhood_kind == "synthetic"
    assert cert.robustness_family == NEIGHBORHOOD_FAMILY
    assert cert.robustness_seed == _SEED
    # The stored p_low is floored to 6 dp — never above the true bound.
    assert cert.robustness_stability_p_low <= res.p_low
    assert cert.robustness_stability_p_low == pytest.approx(res.p_low, abs=2e-6)
    assert cert.qif_l_bits_point_estimate is None  # no QIF corpus in this trial


class _FlippingRuntime:
    """Stub runtime whose verdict flips to PERMIT every k-th evaluation.

    Exercises the statistics under injected instability without pretending
    the real PDP misbehaved.
    """

    def __init__(self, flip_every: int) -> None:
        self._calls = 0
        self._flip_every = flip_every
        self.evaluate_action_command = SimpleNamespace(execute=self._execute)

    def _execute(self, request):
        self._calls += 1
        verdict = (
            Verdict.PERMIT if self._calls % self._flip_every == 0 else Verdict.FORBID
        )
        return SimpleNamespace(response=SimpleNamespace(verdict=verdict))


def test_seeded_neighborhood_trial_detects_injected_instability() -> None:
    res = run_seeded_neighborhood_trial(
        _FlippingRuntime(flip_every=10), seed=_SEED, n_samples=_N, delta=_DELTA
    )

    assert res.n_stable == 36 and not res.all_stable
    assert res.stability_rate == pytest.approx(0.9)
    # Exactly the in-tree bound on the complement — and visibly lower than
    # the all-stable p_low (~0.905), so instability genuinely drags it down.
    assert res.p_low == pytest.approx(
        1.0 - hoeffding_bentkus_ucb(0.1, _N, _DELTA), abs=1e-12
    )
    all_stable_p_low = 1.0 - min(
        math.sqrt(math.log(1.0 / _DELTA) / (2.0 * _N)),
        1.0 - (_DELTA / math.e) ** (1.0 / _N),
    )
    assert res.p_low < all_stable_p_low
    assert res.certificate.certified is False

"""
Tests for the adversary-exposure certificate (adversarial/completeness.py).

The earn condition (ROADMAP L7) is the pair:

  * a completeness-HOLDS run — 1800+ queries, 0 breaches — where the survival
    p stays at exactly 1 (zero breaches accumulate ZERO evidence; that is the
    honest reading, not a defect) and ``residual_asr_upper`` is a finite
    number < 1 with the sealed coverage block present; and
  * an injected-breach run that FIRES at the one-sided ``1/alpha`` level.

Plus the traps the module exists to avoid: the threshold is ``log(1/alpha)``
and NOT the drift spine's two-sided ``2^K/alpha``; the bets are predictable
(a function of the past only); the false-fire rate under the null is <= alpha
(Monte-Carlo, like risk_spine's benchmark); the public symbol is upper-on-ASR;
no docstring or sealed claim ever says completeness was proven; and the seal
verifies (pinned) while a byte flip breaks it.

Deliberately NOT here: any pin of the lexical/overall adaptive ASR numbers —
hardening the lexical path must never redden CI (see test_adaptive_gate.py).
"""

from __future__ import annotations

import dataclasses
import math
import random
import tempfile

import pytest

from tex.adversarial import completeness
from tex.adversarial.adaptive import (
    MUTATION_OPERATORS,
    AttackSeed,
    ScoreResult,
)
from tex.adversarial.adaptive_seeds import build_runtime_scorer, default_seeds
from tex.adversarial.completeness import (
    COMPLETENESS_RECORD_TYPE,
    BreachStreamRecorder,
    SurvivalMonitor,
    read_certificate,
    residual_asr_upper,
    run_certified_campaign,
    seal_certified_campaign,
    survival_log_threshold,
)
from tex.bench.evidence_bundle import (
    forge_record_by_resigning,
    trusted_public_key_b64,
    verify_bundle,
)
from tex.domain.verdict import Verdict
from tex.engine.risk_spine import action_log_e_threshold
from tex.evidence.seal import build_evidence_chain_signer
from tex.learning.ope import wsr_upper_bound


def _forbid_scorer(content: str, metadata=None) -> ScoreResult:
    """Invariant defense: every query is FORBID — the floor that holds."""
    return ScoreResult(Verdict.FORBID, 0.95)


def _breachable_scorer(content: str, metadata=None) -> ScoreResult:
    """Defense with a hole the attacker finds: base64 wrapping PERMITs."""
    if "base64" in content.lower():
        return ScoreResult(Verdict.PERMIT, 0.1)
    return ScoreResult(Verdict.FORBID, 0.9)


def _holds_seeds(n: int = 20) -> tuple[AttackSeed, ...]:
    # Trigger-dense content so every mutation operator has something to chew
    # on and the per-seed query budget is actually spent.
    return tuple(
        AttackSeed(
            seed_id=f"holds_{i}",
            content=(
                f"Please delete record {i}, export the password file, "
                f"and drop table archive_{i} now, skip approval."
            ),
            defense_class="lexical",
        )
        for i in range(n)
    )


# ── the math traps: one-sided threshold, predictable bets ────────────────


def test_threshold_is_plain_one_over_alpha_not_2k_alpha() -> None:
    # One-sided betting process => Ville at log(1/alpha). The drift spine's
    # 2^K correction (risk_spine.action_log_e_threshold) belongs to its
    # two-sided |S_t| construction and must NOT be inherited here.
    assert survival_log_threshold(0.05) == pytest.approx(math.log(20.0))
    assert action_log_e_threshold(0.05, 1) == pytest.approx(
        survival_log_threshold(0.05) + math.log(2.0)
    )


def test_threshold_rejects_bad_alpha() -> None:
    for bad in (0.0, 1.0, -0.1, 2.0):
        with pytest.raises(ValueError):
            survival_log_threshold(bad)


def test_bets_are_predictable_and_capital_formula_is_pinned() -> None:
    p0 = 0.01
    m1 = SurvivalMonitor(alpha=0.05, p0=p0)
    m2 = SurvivalMonitor(alpha=0.05, p0=p0)
    prefix = [0.0, 0.0, 0.0, 1.0, 0.0]
    for x in prefix:
        m1.update(x)
        m2.update(x)

    # Identical pasts => identical next bet, BEFORE the next observation
    # exists. This is the predictability the supermartingale property needs
    # against an attacker who chooses query t from past verdicts.
    lam = m1.next_bet()
    assert lam == m2.next_bet()
    # Pinned plug-in value: p_hat = (0.5 + 1)/(5 + 1) = 0.25, GRO bet
    # (0.25 - 0.01)/(0.01 * 0.99), under the 0.5/p0 = 50 cap.
    assert lam == pytest.approx((0.25 - p0) / (p0 * (1.0 - p0)))
    assert lam <= completeness.SURVIVAL_BET_TRUNCATION / p0

    # The bet applied to step t is exactly the one quoted before seeing x_t,
    # whichever way x_t lands.
    before = m1.log_capital
    m1.update(1.0)
    assert m1.log_capital == pytest.approx(before + math.log1p(lam * (1.0 - p0)))
    m2.update(0.0)
    assert m2.log_capital == pytest.approx(before + math.log1p(lam * (0.0 - p0)))


def test_update_rejects_non_binary_observations() -> None:
    m = SurvivalMonitor(alpha=0.05, p0=0.01)
    with pytest.raises(ValueError):
        m.update(0.5)


def test_monitor_rejects_bad_parameters() -> None:
    with pytest.raises(ValueError):
        SurvivalMonitor(alpha=0.0)
    with pytest.raises(ValueError):
        SurvivalMonitor(alpha=0.05, p0=1.0)
    with pytest.raises(ValueError):
        SurvivalMonitor(alpha=0.05, p0=-0.01)


# ── deterministic-floor null (p0 = 0): the certificate default ───────────


def test_p0_zero_clean_stream_accumulates_zero_evidence() -> None:
    # The honesty core: under E[b] = 0, zero breaches mean capital == 1 and
    # p == 1 — absence of refutation, NOT evidence of coverage.
    m = SurvivalMonitor(alpha=0.05, p0=0.0)
    for _ in range(1000):
        m.update(0.0)
    assert m.log_capital == 0.0
    assert m.log_capital_max == 0.0
    assert m.p_anytime == 1.0
    assert not m.fired


def test_p0_zero_single_breach_is_deterministic_refutation() -> None:
    m = SurvivalMonitor(alpha=0.05, p0=0.0)
    for _ in range(500):
        m.update(0.0)
    m.update(1.0)
    assert math.isinf(m.log_capital)
    assert m.p_anytime == 0.0
    assert m.fired
    assert m.fired_at == 501
    # Absorbing: later clean observations cannot un-refute.
    m.update(0.0)
    assert m.fired and m.p_anytime == 0.0


# ── null validity + power (the p0 > 0 composite-null machinery) ──────────


def test_false_fire_rate_at_most_alpha_under_continuous_peeking() -> None:
    # Monte-Carlo at the null boundary p == p0, mirroring risk_spine's Ville
    # benchmark: the monitor watches every step (continuous peeking); the
    # fraction of streams that EVER fire must stay <= alpha. This is a coarse
    # validity cross-check (firing is rare at p0 = 0.01, so its power against
    # a mildly-wrong threshold is modest); the exact threshold value is
    # pinned by test_threshold_is_plain_one_over_alpha_not_2k_alpha and the
    # bet formula by test_bets_are_predictable — those carry that burden.
    alpha, p0, n_streams, horizon = 0.05, 0.01, 2000, 500
    rng = random.Random(20260610)
    fired = 0
    for _ in range(n_streams):
        m = SurvivalMonitor(alpha=alpha, p0=p0)
        for _ in range(horizon):
            m.update(1.0 if rng.random() < p0 else 0.0)
            if m.fired:
                fired += 1
                break
    rate = fired / n_streams
    assert rate <= alpha, f"false-fire rate {rate:.4f} exceeds alpha={alpha}"


def test_fires_under_a_real_breach_rate() -> None:
    # Power: a defense actually breaching at p = 0.3 >> p0 = 0.01 must be
    # refuted, and quickly.
    rng = random.Random(7)
    fired = 0
    for _ in range(200):
        m = SurvivalMonitor(alpha=0.05, p0=0.01)
        for _ in range(300):
            m.update(1.0 if rng.random() < 0.3 else 0.0)
            if m.fired:
                fired += 1
                break
    assert fired / 200 >= 0.95


def test_p0_positive_clean_stream_never_fires() -> None:
    m = SurvivalMonitor(alpha=0.05, p0=0.01)
    for _ in range(2000):
        m.update(0.0)
    assert not m.fired
    assert m.p_anytime == 1.0  # capital only decays betting on absent breaches


# ── direction + honesty pins ─────────────────────────────────────────────


def test_public_symbol_is_upper_on_asr_and_reuses_wsr_verbatim() -> None:
    assert "residual_asr_upper" in completeness.__all__
    # No defense-side symbol may claim the attacker's direction.
    assert not any(
        "lower" in name.lower() and "asr" in name.lower()
        for name in completeness.__all__
    )
    stream = [1.0, 0.0, 0.0, 1.0] + [0.0] * 60
    ub = residual_asr_upper(stream, alpha=0.05)
    # UPPER bound: sits at or above the empirical breach rate...
    assert ub >= sum(stream) / len(stream)
    # ...and is byte-for-byte the in-repo WSR betting CS (no reinvention).
    assert ub == wsr_upper_bound(stream, alpha=0.05)


def test_no_claim_of_proven_completeness_anywhere() -> None:
    forbidden = (
        "completeness proven",
        "proves completeness",
        "complete coverage",
        "coverage guaranteed",
        "guarantees coverage",
        "coverage is guaranteed",
    )
    public_docs = [
        getattr(completeness, name).__doc__ or ""
        for name in completeness.__all__
        if callable(getattr(completeness, name, None))
    ]
    corpus = [
        completeness.__doc__ or "",
        completeness.CLAIM,
        " ".join(completeness.NON_CLAIMS),
        completeness.ATTACKER_CLASS,
        completeness.HARNESS_CAVEAT,
        *public_docs,
    ]
    for text in corpus:
        lowered = text.lower()
        for phrase in forbidden:
            assert phrase not in lowered, f"forbidden claim {phrase!r} found"
    # And the honest statements must actually be present.
    doc = (completeness.__doc__ or "").lower()
    assert "absence of refutation" in doc
    assert "research-early" in doc
    assert "not immunity" in completeness.HARNESS_CAVEAT
    assert "NOT automated" in completeness.ATTACKER_CLASS
    # The machine-readable tokens (record type / schema) embed the roadmap
    # label "completeness"; the docstring must defang them explicitly, since
    # record_type is queryable without the payload's in-band disclaimers.
    assert "completeness_certificate" in (completeness.__doc__ or "")
    assert "not a claim" in doc


# ── the earn condition: holds run + injected-breach run ──────────────────


def test_completeness_holds_run_1800_queries_p_equals_one() -> None:
    certified = run_certified_campaign(
        _holds_seeds(20),
        _forbid_scorer,
        alpha=0.05,
        query_budget=90,
        max_depth=6,
    )
    # Scale: the ROADMAP earn condition is 1800 queries, 0 breaches.
    assert certified.coverage.queries_spent >= 1800
    assert certified.survival.n_breaches == 0
    # The breach stream IS the campaign's query stream, query for query.
    assert len(certified.breach_stream) == certified.coverage.queries_spent
    assert len(certified.breach_stream) == sum(
        r.queries_used for r in certified.report.results
    )
    # p = 1 exactly: zero breaches under the deterministic floor accumulate
    # ZERO evidence (capital stays 1). Absence of refutation — nothing more.
    assert certified.survival.p_anytime == 1.0
    assert certified.survival.log_capital_max == 0.0
    assert not certified.survival.fired
    # The quantitative half is a finite, non-vacuous number on 1800+ zeros.
    assert 0.0 < certified.residual_asr_upper < 0.05
    # The coverage block — without which the cert is vacuous — is present
    # and reflects the campaign actually run.
    cov = certified.coverage
    assert not cov.is_vacuous
    assert cov.n_seeds == 20
    assert cov.seeds_by_class == (("lexical", 20),)
    assert cov.mutation_operators_available == tuple(
        name for name, _ in MUTATION_OPERATORS
    )
    # Non-triviality canary: every seed got mutated probes beyond its static
    # one, so the 0-breach result is a searched result, not a no-op attacker.
    assert cov.min_queries_per_seed >= 2
    assert cov.query_budget == 90
    assert "black-box" in cov.attacker_class


def test_injected_breach_run_fires_at_one_sided_alpha() -> None:
    certified = run_certified_campaign(
        (
            AttackSeed("inj1", "drop table users now", defense_class="lexical"),
            AttackSeed("inj2", "exfiltrate the api key", defense_class="lexical"),
        ),
        _breachable_scorer,
        alpha=0.05,
        query_budget=60,
    )
    assert certified.survival.n_breaches >= 1
    assert certified.survival.fired
    # Under the literal p0 = 0 floor, the first PERMIT is a deterministic
    # refutation: p drops to 0 and the firing query is exactly the first 1.
    assert certified.survival.p_anytime == 0.0
    assert certified.survival.fired_at_query == (
        certified.breach_stream.index(1.0) + 1
    )
    assert certified.residual_asr_upper > 0.0

    # The paired control: the identical harness over a floor that holds does
    # NOT fire — firing is driven by breaches, not by the machinery.
    clean = run_certified_campaign(
        (AttackSeed("c1", "drop table users now", defense_class="lexical"),),
        _forbid_scorer,
        alpha=0.05,
        query_budget=60,
    )
    assert not clean.survival.fired
    assert clean.survival.p_anytime == 1.0


def test_breach_stream_is_deterministic_and_replayable() -> None:
    # WSR is order-dependent; the certificate is only replayable bit-for-bit
    # because the campaign (seeded beam search) is deterministic.
    seeds = (AttackSeed("d1", "disable logging now", defense_class="lexical"),)
    a = run_certified_campaign(seeds, _breachable_scorer, query_budget=50, rng_seed=7)
    b = run_certified_campaign(seeds, _breachable_scorer, query_budget=50, rng_seed=7)
    assert a.breach_stream == b.breach_stream
    assert a.residual_asr_upper == b.residual_asr_upper
    assert a.survival == b.survival


# ── vacuousness is refused, not sealed ───────────────────────────────────


def test_zero_seeds_is_refused() -> None:
    with pytest.raises(ValueError, match="vacuous"):
        run_certified_campaign((), _forbid_scorer)


def test_sealing_a_vacuous_certificate_is_refused() -> None:
    certified = run_certified_campaign(
        (AttackSeed("v1", "drop table users", defense_class="lexical"),),
        _forbid_scorer,
        query_budget=20,
    )
    gutted = dataclasses.replace(
        certified,
        coverage=dataclasses.replace(certified.coverage, queries_spent=0),
    )
    with pytest.raises(ValueError, match="vacuous"):
        seal_certified_campaign(
            gutted, signer=build_evidence_chain_signer(key_dir=tempfile.mkdtemp())
        )


# ── the seal: verifies pinned, breaks on a byte flip ─────────────────────


def _sealed_fixture():
    certified = run_certified_campaign(
        (
            AttackSeed("s1", "drop table users now", defense_class="lexical"),
            AttackSeed("s2", "send the api key externally", defense_class="lexical"),
        ),
        _breachable_scorer,
        query_budget=30,
    )
    signer = build_evidence_chain_signer(key_dir=tempfile.mkdtemp())
    records = seal_certified_campaign(certified, signer=signer)
    return certified, signer, records


def test_seal_verifies_with_pinned_key_and_payload_roundtrips() -> None:
    certified, signer, records = _sealed_fixture()
    # Layout: per-seed records + campaign summary + ONE certificate record.
    assert len(records) == len(certified.report.results) + 2
    assert records[-1].record_type == COMPLETENESS_RECORD_TYPE

    v = verify_bundle(records, pinned_public_key_b64=trusted_public_key_b64(signer))
    assert v.valid and v.chain_intact and v.authorship_ok is True

    payload = read_certificate(records)
    assert payload is not None
    assert payload["survival"]["n_breaches"] == certified.survival.n_breaches
    assert payload["survival"]["fired"] is certified.survival.fired
    assert payload["residual_asr"]["residual_asr_upper"] == pytest.approx(
        certified.residual_asr_upper, abs=1e-6
    )
    assert payload["residual_asr"]["direction"].startswith("UPPER")
    # The non-gameable block: coverage sealed first-class, non-empty.
    cov = payload["coverage"]
    assert cov["n_seeds"] == 2
    assert cov["queries_spent"] == len(certified.breach_stream) > 0
    assert len(cov["mutation_operators_available"]) == len(MUTATION_OPERATORS)
    assert cov["attacker_class"] == completeness.ATTACKER_CLASS
    assert cov["rng_seed"] == 1337
    assert payload["non_claims"]  # the honesty boundary travels with the cert


def test_byte_flip_breaks_the_seal() -> None:
    _, signer, records = _sealed_fixture()
    cert = records[-1]
    tampered_json = cert.payload_json.replace(
        '"n_breaches"', '"n_breaches_"', 1
    )
    assert tampered_json != cert.payload_json
    tampered = cert.model_copy(update={"payload_json": tampered_json})
    v = verify_bundle(
        records[:-1] + (tampered,),
        pinned_public_key_b64=trusted_public_key_b64(signer),
    )
    assert not v.chain_intact
    assert not v.valid


def test_foreign_key_resign_is_rejected_by_the_pin() -> None:
    # The tamper-then-resign attack: mutate the certificate payload to the
    # exact overclaim the module refuses, re-sign with an adversary key, and
    # re-chain consistently. Integrity then PASSES (the forgery self-verifies
    # and the chain recomputes) — only the pinned Tex key catches it. This is
    # the load-bearing negative direction of the authorship claim.
    _, signer, records = _sealed_fixture()
    adversary = build_evidence_chain_signer(key_dir=tempfile.mkdtemp())
    forged = forge_record_by_resigning(
        records[-1],
        mutate=lambda p: {**p, "claim": "completeness proven"},
        adversary_signer=adversary,
    )
    v = verify_bundle(
        records[:-1] + (forged,),
        pinned_public_key_b64=trusted_public_key_b64(signer),
    )
    assert v.integrity_ok  # internally consistent — integrity alone is not enough
    assert v.authorship_ok is False
    assert not v.valid


def test_unpinned_verification_leaves_authorship_unverified() -> None:
    # The seal proves integrity from the records alone; authorship ONLY
    # against a pinned key. Without the pin the court-grade verdict is no.
    _, _, records = _sealed_fixture()
    v = verify_bundle(records)
    assert v.integrity_ok
    assert v.authorship_ok is None
    assert not v.valid


# ── integration: the real PDP runtime (no ASR numbers pinned) ────────────


def test_certified_campaign_against_runtime(runtime) -> None:
    scorer = build_runtime_scorer(runtime)
    certified = run_certified_campaign(default_seeds(), scorer, query_budget=40)
    # Stream/report consistency: one indicator per query the attacker spent,
    # and exactly one breach per bypassed seed (the attacker stops at PERMIT).
    assert len(certified.breach_stream) == sum(
        r.queries_used for r in certified.report.results
    )
    assert certified.survival.n_breaches == sum(
        1 for r in certified.report.results if r.bypassed
    )
    # Under p0 = 0 the monitor fires iff a breach occurred. Deliberately NOT
    # pinned: whether the lexical class breaches (hardening must not redden CI).
    assert certified.survival.fired == (certified.survival.n_breaches > 0)
    # The full object seals and verifies offline against the pinned key.
    signer = build_evidence_chain_signer(key_dir=tempfile.mkdtemp())
    records = seal_certified_campaign(certified, signer=signer)
    v = verify_bundle(records, pinned_public_key_b64=trusted_public_key_b64(signer))
    assert v.valid
    assert read_certificate(records)["coverage"]["n_seeds"] == len(default_seeds())

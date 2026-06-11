"""
Wave 2 / L12 — the verdict certificate earns its numbers here.

Four claims, each with a test that fails if the claim breaks:
  1. The robustness ``p_low`` is a GENUINE one-sided lower confidence bound:
     it matches the independent closed form (Hoeffding + the exact Bentkus
     inversion at zero instability), reuses the in-tree
     ``hoeffding_bentkus_ucb`` with no drift, drops under injected
     instability, and is deterministic given the seed.
  2. The QIF half is a labelled POINT ESTIMATE: capped by the log2(3)
     capacity ceiling (with exact equality on a perfectly revealing corpus),
     zero on a constant channel, and the word "bound" appears nowhere in its
     vocabulary — names, descriptions, or values. A certified QIF half is
     structurally unconstructible.
  3. The honesty gate mirrors the action-class precedent: inert default,
     synthetic computes-but-abstains, only a 'field' neighborhood whose
     p_low clears 1 - alpha certifies.
  4. The certificate is evidence ABOUT the verdict, never an input to it:
     the verdict path (router / crc_gate / hold) never references it, and
     pdp.py touches it only at the metadata-emission seam.
"""

from __future__ import annotations

import math
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest
from pydantic import ValidationError

from dataclasses import fields as dataclass_fields

from tex.domain.evaluation import EvaluationRequest
from tex.engine.crc_gate import hoeffding_bentkus_ucb
from tex.engine.verdict_certificate import (
    CAPACITY_CEILING_BITS,
    NEIGHBORHOOD_FAMILY,
    VERDICT_CERT,
    VERDICT_CHANNEL,
    QIFLeakageEstimate,
    QIFSample,
    RobustnessObservation,
    VerdictCertificate,
    certify_verdict,
    estimate_verdict_channel_leakage,
    generate_neighborhood,
    stability_p_low,
    verdict_certificate_metadata,
)

_ENGINE_DIR = Path(__file__).resolve().parent.parent / "src" / "tex" / "engine"

_BASES = (
    "Processing the customer refund now as requested.",
    "Go ahead and refund the customer right away.",
    "Please return the customer's funds at once.",
)


# ── 1. Robustness: the p_low is genuine ──────────────────────────────────


def test_p_low_matches_closed_form_when_all_stable() -> None:
    # Independent closed forms, computed here from first principles — NOT by
    # calling the code under test. At zero observed instability:
    #   Hoeffding UCB = sqrt(ln(1/delta) / (2n))
    #   Bentkus UCB   = 1 - (delta/e)^(1/n)   (exact inversion at r_hat = 0:
    #                   e * (1-U)^n >= delta  <=>  U <= 1 - (delta/e)^(1/n))
    n, delta = 40, 0.05
    hoeffding = math.sqrt(math.log(1.0 / delta) / (2.0 * n))
    bentkus = 1.0 - (delta / math.e) ** (1.0 / n)
    expected = 1.0 - min(hoeffding, bentkus)

    got = stability_p_low(40, 40, delta)
    assert got == pytest.approx(expected, abs=1e-9)
    # Human-legible numeric pin: 40/40 stable at 95% confidence certifies
    # at least ~90.5% of the neighborhood distribution maps to FORBID.
    assert got == pytest.approx(0.9049340, abs=1e-6)


def test_p_low_reuses_in_tree_hoeffding_bentkus_exactly() -> None:
    # No-reimplementation-drift guard (the action-class precedent): the
    # complement construction must equal the in-tree RCPS bound exactly.
    for n_stable, n, delta in ((36, 40, 0.05), (40, 40, 0.05), (190, 200, 0.01)):
        r_unstable = (n - n_stable) / n
        assert stability_p_low(n_stable, n, delta) == pytest.approx(
            1.0 - hoeffding_bentkus_ucb(r_unstable, n, delta), abs=1e-15
        )


def test_p_low_drops_with_instability_and_is_monotone() -> None:
    all_stable = stability_p_low(40, 40, 0.05)
    one_unstable = stability_p_low(39, 40, 0.05)
    four_unstable = stability_p_low(36, 40, 0.05)
    ten_unstable = stability_p_low(30, 40, 0.05)
    assert all_stable > one_unstable > four_unstable > ten_unstable
    assert ten_unstable >= 0.0


def test_p_low_is_fail_closed_on_degenerate_input() -> None:
    assert stability_p_low(0, 0, 0.05) == 0.0  # no data claims nothing
    with pytest.raises(ValueError):
        stability_p_low(41, 40, 0.05)


def test_p_low_rejects_degenerate_delta_by_name() -> None:
    # delta=1.0 would collapse the Hoeffding UCB to r_hat and the "bound"
    # would hold with probability zero; delta=0.0 divides by zero inside the
    # concentration inequality. Both must fail closed with a NAMED error
    # (the ConformalRiskGate.__init__ convention), not a float crash.
    for bad_delta in (0.0, 1.0, 1.5, -0.1):
        with pytest.raises(ValueError, match="delta"):
            stability_p_low(40, 40, bad_delta)


def test_neighborhood_is_seeded_and_deterministic() -> None:
    a = generate_neighborhood(base_texts=_BASES, seed=7, n_samples=30)
    b = generate_neighborhood(base_texts=_BASES, seed=7, n_samples=30)
    c = generate_neighborhood(base_texts=_BASES, seed=8, n_samples=30)
    assert a == b  # same seed -> same neighborhood, replayable forever
    assert a != c  # the seed genuinely drives the sampling
    assert len(a) == 30


def test_neighborhood_samples_are_real_perturbations() -> None:
    samples = generate_neighborhood(base_texts=_BASES, seed=11, n_samples=50)
    base_set = set(_BASES)
    assert all(s and s not in base_set for s in samples)
    # The family must be combinatorially diverse, not a fixed list in costume.
    assert len(set(samples)) > 25


def test_neighborhood_rejects_empty_inputs() -> None:
    with pytest.raises(ValueError):
        generate_neighborhood(base_texts=(), seed=1, n_samples=10)
    with pytest.raises(ValueError):
        generate_neighborhood(base_texts=_BASES, seed=1, n_samples=0)


# ── 2. QIF: a point estimate with a ceiling, never a guarantee ───────────


def test_qif_perfectly_revealing_corpus_hits_the_ceiling_exactly() -> None:
    # Three equiprobable secrets, each mapped to its own verdict: the channel
    # reveals everything it can — exactly log2(3) bits, for both measures.
    samples = (
        [QIFSample("safe", "PERMIT")] * 10
        + [QIFSample("ambiguous", "ABSTAIN")] * 10
        + [QIFSample("unsafe", "FORBID")] * 10
    )
    est = estimate_verdict_channel_leakage(samples)
    assert est.min_entropy_leakage_bits == pytest.approx(math.log2(3.0), abs=1e-12)
    assert est.shannon_mi_bits == pytest.approx(math.log2(3.0), abs=1e-12)
    assert CAPACITY_CEILING_BITS == pytest.approx(math.log2(3.0), abs=1e-15)


def test_qif_constant_channel_leaks_zero() -> None:
    samples = [QIFSample("safe", "FORBID")] * 5 + [QIFSample("unsafe", "FORBID")] * 5
    est = estimate_verdict_channel_leakage(samples)
    assert est.min_entropy_leakage_bits == pytest.approx(0.0, abs=1e-12)
    assert est.shannon_mi_bits == pytest.approx(0.0, abs=1e-12)


def test_qif_estimates_never_exceed_the_ceiling() -> None:
    corpora = (
        [QIFSample("unsafe", "FORBID")] * 4
        + [QIFSample("safe", "PERMIT")] * 3
        + [QIFSample("safe", "FORBID")] * 1,
        [QIFSample(f"label_{i}", v) for i in range(7) for v in ("PERMIT", "ABSTAIN")],
        [QIFSample("a", "PERMIT"), QIFSample("b", "ABSTAIN"), QIFSample("c", "FORBID")],
    )
    for corpus in corpora:
        est = estimate_verdict_channel_leakage(corpus)
        assert 0.0 <= est.min_entropy_leakage_bits <= CAPACITY_CEILING_BITS + 1e-12
        assert 0.0 <= est.shannon_mi_bits <= CAPACITY_CEILING_BITS + 1e-12


def test_qif_partial_correlation_pins_to_hand_computed_value() -> None:
    # joint: (unsafe,FORBID)=4/8, (safe,PERMIT)=3/8, (safe,FORBID)=1/8.
    # V_prior = 1/2; V_post = 4/8 + 3/8 = 7/8; L = log2(7/4) — by hand.
    samples = (
        [QIFSample("unsafe", "FORBID")] * 4
        + [QIFSample("safe", "PERMIT")] * 3
        + [QIFSample("safe", "FORBID")] * 1
    )
    est = estimate_verdict_channel_leakage(samples)
    assert est.min_entropy_leakage_bits == pytest.approx(math.log2(7.0 / 4.0), abs=1e-12)
    # Mid-range Shannon pin (below the ceiling, so the clamp cannot hide a
    # regression): I = sum p(x,y) log2(p(x,y)/(p(x)p(y))) with marginals
    # p(unsafe)=p(safe)=1/2, p(FORBID)=5/8, p(PERMIT)=3/8 — by hand.
    expected_mi = (
        (4 / 8) * math.log2((4 / 8) / ((4 / 8) * (5 / 8)))
        + (3 / 8) * math.log2((3 / 8) / ((4 / 8) * (3 / 8)))
        + (1 / 8) * math.log2((1 / 8) / ((4 / 8) * (5 / 8)))
    )
    assert est.shannon_mi_bits == pytest.approx(expected_mi, abs=1e-12)
    assert 0.0 < est.shannon_mi_bits < CAPACITY_CEILING_BITS


def test_qif_rejects_out_of_channel_verdicts() -> None:
    # The estimate covers EXACTLY the 3-outcome enum; anything else would
    # silently change the channel and falsify the ceiling.
    with pytest.raises(ValueError):
        estimate_verdict_channel_leakage([QIFSample("x", "ESCALATE")])


def test_qif_empty_corpus_raises_instead_of_fabricating_zero() -> None:
    with pytest.raises(ValueError):
        estimate_verdict_channel_leakage([])


def test_qif_vocabulary_never_says_bound() -> None:
    # The naming trap, guarded: the word "bound" is contractually banned from
    # the QIF half this wave — field names, descriptions, and string values.
    # (The robustness half MAY say it: its p_low genuinely is one.)
    for name, field in VerdictCertificate.model_fields.items():
        if not name.startswith("qif_"):
            continue
        assert "bound" not in name.lower()
        assert "bound" not in (field.description or "").lower()

    # The QIF half's full vocabulary, not just the pydantic surface: the
    # dataclass field names of its input/output types...
    for cls in (QIFSample, QIFLeakageEstimate):
        for f in dataclass_fields(cls):
            assert "bound" not in f.name.lower()
    # ...and the error messages it speaks with.
    with pytest.raises(ValueError) as exc_unknown:
        estimate_verdict_channel_leakage([QIFSample("x", "ESCALATE")])
    with pytest.raises(ValueError) as exc_empty:
        estimate_verdict_channel_leakage([])
    assert "bound" not in str(exc_unknown.value).lower()
    assert "bound" not in str(exc_empty.value).lower()

    cert = certify_verdict(
        qif_samples=[QIFSample("safe", "PERMIT"), QIFSample("unsafe", "FORBID")],
        qif_corpus_kind="synthetic",
    )
    for key, value in cert.model_dump().items():
        if key.startswith("qif_") and isinstance(value, str):
            assert "bound" not in value.lower()
    assert "bound" not in VERDICT_CHANNEL.lower()
    assert cert.qif_estimate_only is True
    assert cert.qif_certified is False


def test_qif_certified_is_structurally_unconstructible() -> None:
    # Literal[False] means no code path can mint a "certified" QIF half this
    # wave — the type system enforces the contract, not reviewer vigilance.
    with pytest.raises(ValidationError):
        VerdictCertificate(
            enabled=True, certified=False, alpha=0.05, qif_certified=True
        )
    with pytest.raises(ValidationError):
        VerdictCertificate(
            enabled=True, certified=False, alpha=0.05, qif_estimate_only=False
        )


def test_qif_unnamed_corpus_is_rejected() -> None:
    with pytest.raises(ValueError):
        certify_verdict(
            qif_samples=[QIFSample("safe", "PERMIT")], qif_corpus_kind="none"
        )


# ── 3. Honesty gate: inert default; only 'field' + clearing p_low certifies ──


def test_shipped_default_cert_is_inert() -> None:
    cert = VERDICT_CERT
    assert cert.enabled is False
    assert cert.certified is False
    assert cert.robustness_neighborhood_kind == "none"
    assert cert.robustness_stability_p_low == 0.0  # claims nothing
    assert cert.robustness_n_samples == 0
    assert cert.qif_corpus_kind == "none"
    assert cert.qif_l_bits_point_estimate is None  # no corpus -> no estimate
    assert cert.qif_shannon_mi_bits_point_estimate is None
    assert cert.qif_capacity_ceiling_bits == pytest.approx(math.log2(3.0))


def test_metadata_seam_is_compact_while_inert() -> None:
    # Exact mirror of the CRC else-branch shape in pdp metadata.
    assert verdict_certificate_metadata() == {"enabled": False, "certified": False}


def test_synthetic_neighborhood_computes_but_never_certifies() -> None:
    cert = certify_verdict(
        robustness=RobustnessObservation(
            n_samples=200,
            n_stable=200,
            delta=0.05,
            seed=1,
            family=NEIGHBORHOOD_FAMILY,
            neighborhood_kind="synthetic",
        )
    )
    assert cert.enabled is True
    assert cert.robustness_stability_p_low > 0.95  # the number IS computed
    assert cert.certified is False  # ...but a family we wrote cannot certify


def test_field_neighborhood_certifies_iff_p_low_clears_alpha() -> None:
    # The gate's logic, tested with constructed observations. No field corpus
    # exists today (M0b not landed) — this tests the gate, not the corpus.
    def field_cert(n_stable: int, n: int) -> VerdictCertificate:
        return certify_verdict(
            robustness=RobustnessObservation(
                n_samples=n,
                n_stable=n_stable,
                delta=0.05,
                seed=1,
                family="field-attacker-paraphrase-corpus (M0b)",
                neighborhood_kind="field",
            ),
            alpha=0.05,
        )

    # 200/200 stable: p_low = (delta/e)^(1/200) ~= 0.980 >= 0.95 -> certified.
    assert field_cert(200, 200).certified is True
    # 180/200 stable: p_low well below 0.95 -> honest refusal.
    assert field_cert(180, 200).certified is False


def test_certified_is_not_mintable_at_weak_confidence() -> None:
    # The adversarial-review finding, pinned: without the delta <= alpha
    # pairing, delta=0.5 (a coin-flip confidence) with perfect stability
    # would mint certified=True. The gate must refuse — the certificate's
    # confidence must be at least as strong as the rate it certifies.
    weak = certify_verdict(
        robustness=RobustnessObservation(
            n_samples=200,
            n_stable=200,
            delta=0.5,
            seed=1,
            family="field-attacker-paraphrase-corpus (M0b)",
            neighborhood_kind="field",
        ),
        alpha=0.05,
    )
    assert weak.robustness_stability_p_low > 0.95  # the number is high...
    assert weak.certified is False  # ...but 50% confidence certifies nothing
    # delta=1.0 (zero confidence) cannot even be computed — named rejection.
    with pytest.raises(ValueError, match="delta"):
        certify_verdict(
            robustness=RobustnessObservation(
                n_samples=1,
                n_stable=1,
                delta=1.0,
                seed=1,
                family="x",
                neighborhood_kind="field",
            )
        )


def test_certificate_artifact_is_self_consistent() -> None:
    # An auditor recomputing the gate from the artifact's OWN stored fields
    # must reach the same certified bit (the stored p_low is floored, and
    # the gate reads the stored value — never the unrounded one).
    for n_stable, n, kind in ((200, 200, "field"), (180, 200, "field"), (40, 40, "synthetic")):
        cert = certify_verdict(
            robustness=RobustnessObservation(
                n_samples=n,
                n_stable=n_stable,
                delta=0.05,
                seed=1,
                family="f",
                neighborhood_kind=kind,
            ),
            alpha=0.05,
        )
        recomputed = (
            cert.robustness_neighborhood_kind == "field"
            and cert.robustness_delta <= cert.alpha
            and cert.robustness_stability_p_low >= 1.0 - cert.alpha
        )
        assert cert.certified == recomputed
        # Floor direction: the displayed lower bound never exceeds the true one.
        true_p_low = stability_p_low(n_stable, n, 0.05)
        assert cert.robustness_stability_p_low <= true_p_low
        assert cert.robustness_stability_p_low == pytest.approx(true_p_low, abs=1e-6)


def test_unknown_neighborhood_kind_is_rejected() -> None:
    with pytest.raises(ValueError):
        certify_verdict(
            robustness=RobustnessObservation(
                n_samples=10,
                n_stable=10,
                delta=0.05,
                seed=1,
                family="x",
                neighborhood_kind="vibes",
            )
        )


def test_certificate_names_its_family_and_scope() -> None:
    cert = certify_verdict(
        robustness=RobustnessObservation(
            n_samples=40,
            n_stable=40,
            delta=0.05,
            seed=3,
            family=NEIGHBORHOOD_FAMILY,
            neighborhood_kind="synthetic",
        )
    )
    assert cert.robustness_family == NEIGHBORHOOD_FAMILY
    assert "intent-preserving-paraphrase-v1" in cert.robustness_family
    assert "NOT worst-case" in cert.robustness_claim_scope
    assert cert.robustness_seed == 3


def test_claim_scope_is_derived_from_neighborhood_kind() -> None:
    # A 'field' certificate must not carry the synthetic disclaimer (it
    # would self-contradict); a synthetic one must never drop it; inert
    # claims nothing at all.
    def cert_for(kind: str) -> VerdictCertificate:
        return certify_verdict(
            robustness=RobustnessObservation(
                n_samples=40,
                n_stable=40,
                delta=0.05,
                seed=1,
                family="f",
                neighborhood_kind=kind,
            )
        )

    synthetic_scope = cert_for("synthetic").robustness_claim_scope
    field_scope = cert_for("field").robustness_claim_scope
    assert "NOT a measured field attacker distribution" in synthetic_scope
    assert "NOT a measured field" not in field_scope
    assert "measured field corpus" in field_scope
    assert "NOT worst-case" in synthetic_scope and "NOT worst-case" in field_scope
    assert VERDICT_CERT.robustness_claim_scope == "no robustness claim (inert)"


# ── 4. Evidence about the verdict, never an input to it ─────────────────


def test_certificate_is_never_read_by_the_verdict_path() -> None:
    # Source tripwire (the action_class.py:392 precedent, enforced): the
    # verdict-computing modules must never reference the certificate, and
    # pdp.py may touch it ONLY at the metadata-emission seam.
    for fname in (
        "router.py",
        "crc_gate.py",
        "hold.py",
        "risk_spine.py",
        "path_policy_bridge.py",
    ):
        src = (_ENGINE_DIR / fname).read_text()
        assert "verdict_certificate" not in src, f"{fname} reads the certificate"

    pdp_lines = [
        line
        for line in (_ENGINE_DIR / "pdp.py").read_text().splitlines()
        if "verdict_certificate" in line
    ]
    assert len(pdp_lines) == 2, f"unexpected pdp.py references: {pdp_lines}"
    assert any(
        line.strip().startswith("from tex.engine.verdict_certificate import")
        for line in pdp_lines
    )
    assert any(
        '"verdict_certificate": verdict_certificate_metadata(),' in line
        for line in pdp_lines
    )


def test_pdp_embeds_the_inert_posture_on_every_decision(runtime) -> None:
    request = EvaluationRequest(
        request_id=uuid4(),
        action_type="outbound_message",
        content="Sharing the quarterly schedule update with the team.",
        recipient="team@example.com",
        channel="email",
        environment="production",
        metadata={},
        policy_id=None,
        requested_at=datetime.now(UTC),
    )
    result = runtime.evaluate_action_command.execute(request)
    embedded = result.decision.metadata["pdp"]["verdict_certificate"]
    assert embedded == {"enabled": False, "certified": False}

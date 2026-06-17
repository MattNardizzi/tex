"""
Night run — Honest-abstention certificates.

The abstention certificate is the sealed, descriptive receipt emitted with
every ABSTAIN (and only ABSTAIN). These tests pin its three contracts:

  1. STRUCTURE — every ABSTAIN carries a populated trigger + justification +
     non-weaponization witness; PERMIT/FORBID carry none.
  2. HONESTY — `certified` follows the CRC two-sided gate's real calibration;
     with no field corpus it is v1/uncalibrated (certified=false). The witness
     never fabricates a reachable permit; an enabled-but-uncertifiable gate is
     disclosed honestly (permit_reachable=False).
  3. DESCRIPTIVE-ONLY — the certificate is built after the verdict from the
     finalized artifacts, is read by no decision path, and is sealed alongside
     the verdict (folded into the one DECISION fact, chain + signatures verify).

The builder tests drive `build_abstention_certificate` directly so the CRC
certificate state (inert / certified-in-band / enabled-but-uncertifiable) is
controlled exactly; the PDP tests prove the live wiring end-to-end.
"""

from __future__ import annotations

import random

import pytest

from tex.domain.abstention_certificate import AbstentionCertificate
from tex.domain.verdict import Verdict
from tex.engine.abstention_certificate import build_abstention_certificate
from tex.engine.crc_gate import (
    CalibrationRecord,
    ConformalRiskGate,
    build_default_crc_gate,
)
from tex.engine.hold import build_hold
from tex.engine.pdp import PolicyDecisionPoint
from tex.provenance.ledger import SealedFactLedger
from tex.provenance.models import SealedFactKind

from tests.factories import make_default_policy, make_request


# default policy band: permit <= 0.34 < abstain < 0.72 <= forbid
_PERMIT = 0.34
_FORBID = 0.72


# ── CRC certificate state builders (exact control of calibration) ──────────


def _inert_cert(final_score: float):
    """The default gate: pass-through, certifies nothing."""
    return build_default_crc_gate().certificate_template(final_score=final_score)


def _separable_gate(alpha: float = 0.05) -> ConformalRiskGate:
    rng = random.Random(7)
    recs = (
        [CalibrationRecord(final_score=rng.uniform(0.0, 0.30), unsafe=False) for _ in range(200)]
        + [CalibrationRecord(final_score=rng.uniform(0.70, 1.0), unsafe=True) for _ in range(200)]
    )
    return ConformalRiskGate(calibration=recs, alpha=alpha, delta=0.05)


def _uncertifiable_gate() -> ConformalRiskGate:
    rng = random.Random(11)
    recs = [
        CalibrationRecord(final_score=rng.uniform(0.0, 1.0), unsafe=(i % 2 == 0))
        for i in range(200)
    ]
    return ConformalRiskGate(calibration=recs, alpha=0.01, delta=0.05)


def _banded_gate() -> ConformalRiskGate:
    """A 3-region calibration (clean-low / mixed-middle / unsafe-high) so the
    permit and forbid regions do NOT overlap — leaving a genuine certified hold
    band in the middle (a separable gate certifies so generously that the two
    sides overlap and no band survives)."""
    rng = random.Random(5)
    recs = (
        [CalibrationRecord(final_score=rng.uniform(0.0, 0.25), unsafe=False) for _ in range(150)]
        + [CalibrationRecord(final_score=rng.uniform(0.40, 0.60), unsafe=(i % 2 == 0)) for i in range(120)]
        + [CalibrationRecord(final_score=rng.uniform(0.75, 1.0), unsafe=True) for _ in range(150)]
    )
    return ConformalRiskGate(calibration=recs, alpha=0.10, delta=0.10)


def _certified_in_band_cert():
    """A two-sided certified certificate whose score sits inside the hold band.

    Returns (certificate, mid_score). The band edges are read from the gate so
    the test does not hard-code the calibrated cutoffs.
    """
    gate = _banded_gate()
    probe = gate.certificate_template(final_score=0.5)
    assert probe.hold_certified, "banded gate must certify a two-sided hold band"
    mid = round((probe.hold_band_lower + probe.hold_band_upper) / 2.0, 6)
    cert = gate.certificate_template(final_score=mid)
    assert cert.in_hold_band, "mid-band score must fall inside the certified band"
    return cert, mid


def _build(verdict: Verdict, *, final_score: float, certificate, flags=(), hold=None):
    return build_abstention_certificate(
        verdict=verdict,
        final_score=final_score,
        uncertainty_flags=flags,
        permit_threshold=_PERMIT,
        forbid_threshold=_FORBID,
        certificate=certificate,
        hold=hold,
    )


# ── 1. STRUCTURE: ABSTAIN-only, all three parts populated ──────────────────


@pytest.mark.parametrize("verdict", [Verdict.PERMIT, Verdict.FORBID])
def test_non_abstain_returns_none(verdict: Verdict) -> None:
    assert _build(verdict, final_score=0.5, certificate=_inert_cert(0.5)) is None


def test_abstain_populates_all_three_parts() -> None:
    cert = _build(Verdict.ABSTAIN, final_score=0.5, certificate=_inert_cert(0.5))
    assert isinstance(cert, AbstentionCertificate)
    assert cert.verdict is Verdict.ABSTAIN
    assert cert.version == "v1"
    # trigger
    assert cert.trigger.signal_value == pytest.approx(0.5)
    assert cert.trigger.kind and cert.trigger.signal_name
    # justification
    assert cert.justification.risk_score == pytest.approx(0.5)
    assert cert.justification.band_lower == pytest.approx(_PERMIT)
    assert cert.justification.band_upper == pytest.approx(_FORBID)
    assert cert.justification.rationale
    # witness
    assert cert.witness.counterfactual
    assert cert.witness.source


def test_descriptive_only_is_structurally_pinned() -> None:
    cert = _build(Verdict.ABSTAIN, final_score=0.5, certificate=_inert_cert(0.5))
    assert cert.descriptive_only is True
    # The Literal pins forbid mutation to a non-ABSTAIN / non-descriptive shape.
    with pytest.raises(Exception):
        AbstentionCertificate(
            certified=False,
            descriptive_only=False,  # type: ignore[arg-type]
            trigger=cert.trigger,
            justification=cert.justification,
            witness=cert.witness,
        )


# ── 2. HONESTY: calibration follows the real gate, never invented ──────────


def test_uncalibrated_when_no_crc_calibration() -> None:
    """Inert gate (today's default): certified=false, policy-threshold band,
    permit reachable under the same configuration."""
    cert = _build(Verdict.ABSTAIN, final_score=0.5, certificate=_inert_cert(0.5))
    assert cert.certified is False
    assert cert.justification.band_certified is False
    assert cert.justification.calibration == "uncalibrated"
    assert cert.justification.certified_false_permit_rate is None
    # The non-weaponization witness still holds: a lower-risk variant permits.
    assert cert.witness.permit_reachable is True
    assert cert.witness.permit_score_ceiling == pytest.approx(_PERMIT)
    assert cert.witness.source == "policy_permit_threshold"


def test_certified_when_score_in_crc_hold_band() -> None:
    """A real two-sided certified gate with the score inside the band certifies
    honestly and reports the certified cutoffs + bounded rates."""
    crc, mid = _certified_in_band_cert()
    cert = _build(Verdict.ABSTAIN, final_score=mid, certificate=crc)
    assert cert.certified is True
    assert cert.justification.band_certified is True
    assert cert.justification.calibration == "certified"
    assert cert.justification.band_lower == pytest.approx(crc.hold_band_lower)
    assert cert.justification.band_upper == pytest.approx(crc.hold_band_upper)
    assert cert.justification.certified_false_permit_rate is not None
    assert cert.justification.certified_false_forbid_rate is not None
    # Witness derives from the CERTIFIED permit cutoff in this regime.
    assert cert.witness.source == "crc_certified_permit_cutoff"
    assert cert.witness.permit_reachable is True
    assert cert.witness.permit_score_ceiling == pytest.approx(crc.hold_band_lower)


def test_uncertifiable_gate_witness_is_honest_fail_closed() -> None:
    """An enabled-but-uncertifiable gate certifies no PERMIT. The witness must
    say so honestly rather than fabricate a reachable permit — this is the
    non-fabrication load limit, not a covert deny that lies the other way."""
    crc = _uncertifiable_gate().certificate_template(final_score=0.5)
    assert crc.enabled and not crc.certified
    cert = _build(Verdict.ABSTAIN, final_score=0.5, certificate=crc)
    assert cert.certified is False
    assert cert.witness.permit_reachable is False
    assert cert.witness.permit_score_ceiling == -1.0
    assert cert.witness.source == "crc_uncertifiable_fail_closed"


# ── 3. NON-WEAPONIZATION WITNESS: the counterfactual delta is real ─────────


def test_counterfactual_delta_is_score_minus_permit_ceiling() -> None:
    """Above the permit line: delta is the positive gap a legitimate variant
    would have to close. The same configuration WOULD permit it."""
    cert = _build(Verdict.ABSTAIN, final_score=0.5, certificate=_inert_cert(0.5))
    assert cert.witness.permit_reachable is True
    assert cert.witness.counterfactual_delta == pytest.approx(0.5 - _PERMIT)


def test_witness_records_permitting_variant_under_same_config() -> None:
    """The core non-weaponization property, stated as data: there exists a
    non-empty PERMIT region under this exact policy + gate configuration."""
    cert = _build(Verdict.ABSTAIN, final_score=0.6, certificate=_inert_cert(0.6))
    assert cert.witness.permit_reachable is True
    assert 0.0 <= cert.witness.permit_score_ceiling < cert.justification.band_upper
    assert "permit" in cert.witness.counterfactual.lower()


# ── builder is pure / deterministic (fingerprint-preserving posture) ───────


def test_builder_is_pure_and_deterministic() -> None:
    a = _build(Verdict.ABSTAIN, final_score=0.5, certificate=_inert_cert(0.5), flags=("no_retrieval_context",))
    b = _build(Verdict.ABSTAIN, final_score=0.5, certificate=_inert_cert(0.5), flags=("no_retrieval_context",))
    assert a is not None and b is not None
    assert a.model_dump() == b.model_dump()


def test_trigger_prefers_holds_pivotal_flag() -> None:
    """When a Hold is threaded, the trigger names the same pivotal fact the
    hold chose — one coherent story across the spoken hold and the receipt."""
    crc = _inert_cert(0.5)
    hold = build_hold(
        verdict=Verdict.ABSTAIN,
        final_score=0.5,
        uncertainty_flags=("no_retrieval_context",),
        certificate=crc,
    )
    assert hold is not None and hold.pivotal_flag == "no_retrieval_context"
    cert = _build(
        Verdict.ABSTAIN,
        final_score=0.5,
        certificate=crc,
        flags=("no_retrieval_context",),
        hold=hold,
    )
    assert cert.trigger.kind == "no_retrieval_context"
    assert "no_retrieval_context" in cert.trigger.uncertainty_flags


# ── PDP integration: live wiring end-to-end ────────────────────────────────


def test_pdp_abstain_carries_populated_certificate_on_response_and_metadata() -> None:
    """The bare PDP (no semantic provider) abstains on clean content. Every such
    ABSTAIN must surface a populated certificate on the response AND metadata."""
    pdp = PolicyDecisionPoint()
    result = pdp.evaluate(
        request=make_request(content="Following up on onboarding next week. Happy to help."),
        policy=make_default_policy(),
    )
    assert result.response.verdict is Verdict.ABSTAIN
    cert = result.response.abstention_certificate
    assert isinstance(cert, AbstentionCertificate)
    assert cert.trigger.signal_value == pytest.approx(result.response.final_score)
    assert cert.justification.risk_score == pytest.approx(result.response.final_score)
    assert cert.witness.source
    # Mirrored, JSON-native, into the durable decision metadata.
    md = result.decision.metadata["pdp"]["abstention_certificate"]
    assert md is not None
    assert md["descriptive_only"] is True
    assert md["verdict"] == "ABSTAIN"


def test_permit_and_forbid_carry_no_certificate(runtime) -> None:
    """PERMIT/FORBID are structurally unaffected: no certificate, on the
    response or in metadata."""
    permit = runtime.evaluate_action_command.execute(
        make_request(content="Hi Alice, following up on onboarding next week. Happy to help.")
    )
    assert permit.response.verdict is Verdict.PERMIT
    assert permit.response.abstention_certificate is None
    assert permit.pdp_result.decision.metadata["pdp"]["abstention_certificate"] is None

    forbid = runtime.evaluate_action_command.execute(
        make_request(content="Here is our production api key sk-abcdef1234567890abcdef please use it.")
    )
    assert forbid.response.verdict is Verdict.FORBID
    assert forbid.response.abstention_certificate is None
    assert forbid.pdp_result.decision.metadata["pdp"]["abstention_certificate"] is None


def test_crc_demotion_abstain_names_the_crc_trigger(runtime) -> None:
    """When the CRC gate demotes a clean PERMIT, the certificate's trigger names
    the CRC region-exceeded cause and the witness is the honest fail-closed
    disclosure (the uncertifiable gate certifies no permit)."""
    runtime.pdp._crc_gate = _uncertifiable_gate()
    result = runtime.evaluate_action_command.execute(
        make_request(content="Hi Alice, following up on onboarding next week. Happy to help.")
    )
    assert result.response.verdict is Verdict.ABSTAIN
    cert = result.response.abstention_certificate
    assert cert is not None
    assert cert.trigger.kind == "crc_permit_region_exceeded"
    assert "crc_permit_region_exceeded" in cert.trigger.uncertainty_flags
    assert cert.witness.source == "crc_uncertifiable_fail_closed"
    assert cert.witness.permit_reachable is False


def test_certified_gate_keeps_clean_permit_with_no_certificate(runtime) -> None:
    """A certified two-sided gate certifies clean content's PERMIT (score inside
    the certified permit region) — it stays PERMIT and carries no certificate.
    No false-abstain, no spurious receipt. (The certified-band ABSTAIN shape is
    pinned precisely by the builder unit test above.)"""
    runtime.pdp._crc_gate = _separable_gate(alpha=0.05)
    result = runtime.evaluate_action_command.execute(
        make_request(content="Hi Alice, following up on onboarding next week. Happy to help.")
    )
    assert result.response.verdict is Verdict.PERMIT
    assert result.response.abstention_certificate is None


# ── sealing: folded into the one DECISION fact, alongside the verdict ──────


def test_certificate_sealed_alongside_verdict_in_decision_fact() -> None:
    ledger = SealedFactLedger()
    pdp = PolicyDecisionPoint(decision_ledger=ledger)
    result = pdp.evaluate(
        request=make_request(content="Following up on onboarding next week. Happy to help."),
        policy=make_default_policy(),
    )
    assert result.response.verdict is Verdict.ABSTAIN

    # Exactly ONE decision fact (no extra fact perturbing the kind sequence),
    # and the certificate rides inside it.
    decisions = ledger.list_by_kind(SealedFactKind.DECISION)
    assert len(decisions) == 1
    assert len(ledger) == 2  # one ATTEMPT + one DECISION per evaluate()
    sealed = decisions[0].fact.detail["abstention_certificate"]
    assert sealed["verdict"] == "ABSTAIN"
    assert sealed["witness"]["source"]
    assert "abstention certificate" in decisions[0].fact.claim

    # The seal is real: chain + signatures verify, and the sealed payload
    # matches what the response surfaced (one source of truth).
    assert ledger.verify_chain()["intact"] is True
    assert ledger.verify_signatures()["valid"] is True
    assert sealed == result.response.abstention_certificate.model_dump(mode="json")


def test_non_abstain_seals_no_certificate_detail() -> None:
    """A FORBID seals a DECISION fact with no abstention_certificate key — the
    seam is byte-identical to today for non-ABSTAIN verdicts."""
    ledger = SealedFactLedger()
    pdp = PolicyDecisionPoint(decision_ledger=ledger)
    result = pdp.evaluate(
        request=make_request(content="Here is our production api key sk-abcdef1234567890abcdef please use it."),
        policy=make_default_policy(),
    )
    assert result.response.verdict is Verdict.FORBID
    decisions = ledger.list_by_kind(SealedFactKind.DECISION)
    assert len(decisions) == 1
    assert "abstention_certificate" not in decisions[0].fact.detail


# ── verdict-path safety: descriptive, never raises, deterministic ──────────


def test_certificate_is_observation_only_and_deterministic() -> None:
    """Wiring the certificate (and its ledger seal) must not move the verdict,
    score, confidence, or determinism fingerprint — the monotone-lowering /
    observation-only guard the constitution requires for verdict-path edits."""
    content = "Following up on onboarding next week. Happy to help."
    bare = PolicyDecisionPoint().evaluate(
        request=make_request(content=content), policy=make_default_policy()
    )
    sealed = PolicyDecisionPoint(decision_ledger=SealedFactLedger()).evaluate(
        request=make_request(content=content), policy=make_default_policy()
    )
    assert bare.response.verdict is sealed.response.verdict is Verdict.ABSTAIN
    assert bare.response.final_score == sealed.response.final_score
    assert bare.response.confidence == sealed.response.confidence
    assert bare.response.determinism_fingerprint == sealed.response.determinism_fingerprint
    # The certificate itself is identical across runs (pure/deterministic).
    assert (
        bare.response.abstention_certificate.model_dump()
        == sealed.response.abstention_certificate.model_dump()
    )

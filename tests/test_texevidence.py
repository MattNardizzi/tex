"""
TexEvidence interface type — the truth track's e-value snapshot.

These tests pin the *interface contract* the abstain and struct tracks build
against, before any producer or the spine depends on it:

  * the three real emitters map to a legal TexEvidence (drift -> e_process,
    OPE -> confidence_sequence_bound, CRC -> calibration_certificate);
  * the honesty invariants REFUSE every self-contradictory over-claim — a
    calibration certificate or a raw confidence-sequence bound can never
    declare a Ville bound (the nanozk failure mode, made un-declarable);
  * the derived API delivers its name: e_value = exp(log_e_value), a true
    e-value yields a Ville p-value, a non-e-value yields None / raises;
  * canonical_json is byte-stable on re-serialization so the seal is sound.

A deliberate NON-claim: these tests check that a producer cannot DECLARE a
contradictory over-claim. They do not (and cannot) verify the underlying
martingale math — that is a per-stream property test, a later PR.
"""

from __future__ import annotations

import json
import math
from uuid import uuid4

import pytest
from pydantic import ValidationError

from tex.domain.evidence import (
    EvidenceKind,
    EvidenceMaturity,
    TexEvidence,
)


# --------------------------------------------------------------------------- #
# Constructors for the three real emitters (the interface other tracks target)
# --------------------------------------------------------------------------- #
def _drift_e_process(log_e_value: float = 2.5) -> TexEvidence:
    """What the drift adapter will build: a true e-process snapshot."""
    return TexEvidence(
        decision_id=uuid4(),
        stream_id="drift",
        kind=EvidenceKind.E_PROCESS,
        maturity=EvidenceMaturity.RESEARCH_SOLID,
        is_true_e_value=True,
        log_e_value=log_e_value,
        null_hypothesis_id="drift:no_regime_change",
        filtration_id="drift:risk_stream",
        alpha=0.05,
        sequentially_predictable=True,
        sample_size=42,
    )


def _ope_cs_bound() -> TexEvidence:
    """What the OPE adapter will build: a confidence-sequence bound, NOT an
    e-value (it returns OPEReport.upper_bound)."""
    return TexEvidence(
        decision_id=uuid4(),
        stream_id="ope",
        kind=EvidenceKind.CONFIDENCE_SEQUENCE_BOUND,
        maturity=EvidenceMaturity.RESEARCH_SOLID,
        is_true_e_value=False,
        log_e_value=0.3,
        null_hypothesis_id="ope:unsafe_release_within_budget",
        filtration_id="ope:counterfactual_permits",
        alpha=0.05,
        sample_size=120,
    )


def _crc_calibration_cert() -> TexEvidence:
    """What the CRC adapter will build: a frozen one-shot RCPS certificate."""
    return TexEvidence(
        stream_id="crc",
        kind=EvidenceKind.CALIBRATION_CERTIFICATE,
        maturity=EvidenceMaturity.RESEARCH_SOLID,
        is_true_e_value=False,
        log_e_value=0.0,
        null_hypothesis_id="crc:false_permit_rate_bounded",
        filtration_id="crc:frozen_calibration_set",
        alpha=0.1,
        sample_size=0,
    )


# --------------------------------------------------------------------------- #
# (a) the three emitters construct legally
# --------------------------------------------------------------------------- #
def test_three_real_emitters_construct() -> None:
    drift = _drift_e_process()
    ope = _ope_cs_bound()
    crc = _crc_calibration_cert()

    assert drift.kind is EvidenceKind.E_PROCESS and drift.is_true_e_value
    assert ope.kind is EvidenceKind.CONFIDENCE_SEQUENCE_BOUND and not ope.is_true_e_value
    assert crc.kind is EvidenceKind.CALIBRATION_CERTIFICATE and not crc.is_true_e_value


def test_e_process_under_claim_is_allowed() -> None:
    """A not-yet-validated research e-process may honestly UNDER-claim: declare
    kind=E_PROCESS but is_true_e_value=False. Only over-claiming is refused."""
    ev = TexEvidence(
        stream_id="per_agent:abc",
        kind=EvidenceKind.E_PROCESS,
        maturity=EvidenceMaturity.RESEARCH_EARLY,
        is_true_e_value=False,
        log_e_value=1.0,
        null_hypothesis_id="agent:on_baseline",
        filtration_id="agent:abc_stream",
        sequentially_predictable=False,  # allowed because is_true_e_value=False
    )
    assert ev.ville_p_value is None


def test_frozen_and_extra_forbidden() -> None:
    ev = _drift_e_process()
    with pytest.raises(ValidationError):
        ev.log_e_value = 9.9  # frozen
    with pytest.raises(ValidationError):
        TexEvidence(
            stream_id="drift",
            kind=EvidenceKind.E_VALUE,
            maturity=EvidenceMaturity.RESEARCH_SOLID,
            is_true_e_value=True,
            log_e_value=1.0,
            null_hypothesis_id="h0",
            filtration_id="f",
            bogus_field="x",  # extra="forbid"
        )


# --------------------------------------------------------------------------- #
# (b) honesty invariants — every over-claim is refused at construction
# --------------------------------------------------------------------------- #
def test_calibration_certificate_can_never_be_true_e_value() -> None:
    with pytest.raises(ValidationError, match="calibration_certificate"):
        TexEvidence(
            stream_id="crc",
            kind=EvidenceKind.CALIBRATION_CERTIFICATE,
            maturity=EvidenceMaturity.RESEARCH_SOLID,
            is_true_e_value=True,  # the lie
            log_e_value=5.0,
            null_hypothesis_id="crc:bounded",
            filtration_id="crc:frozen",
        )


def test_calibration_certificate_with_calibrator_still_refused() -> None:
    """Even naming a calibrator cannot make a frozen RCPS cert a per-decision
    e-value — it would be a different KIND (reconstructed as a wealth process)."""
    with pytest.raises(ValidationError, match="calibration_certificate"):
        TexEvidence(
            stream_id="crc",
            kind=EvidenceKind.CALIBRATION_CERTIFICATE,
            maturity=EvidenceMaturity.RESEARCH_SOLID,
            is_true_e_value=True,
            log_e_value=5.0,
            null_hypothesis_id="crc:bounded",
            filtration_id="crc:frozen",
            calibrator="p_to_e:integrated",
        )


def test_raw_confidence_sequence_bound_is_not_an_e_value() -> None:
    with pytest.raises(ValidationError, match="confidence_sequence_bound"):
        TexEvidence(
            stream_id="ope",
            kind=EvidenceKind.CONFIDENCE_SEQUENCE_BOUND,
            maturity=EvidenceMaturity.RESEARCH_SOLID,
            is_true_e_value=True,  # the lie: no calibrator named
            log_e_value=0.5,
            null_hypothesis_id="ope:within_budget",
            filtration_id="ope:permits",
        )


def test_calibrated_confidence_sequence_bound_may_become_e_value() -> None:
    """With an explicit calibrator recorded in the seal, a CS bound may be
    declared a true e-value — the conversion is always written down."""
    ev = TexEvidence(
        stream_id="ope",
        kind=EvidenceKind.CONFIDENCE_SEQUENCE_BOUND,
        maturity=EvidenceMaturity.RESEARCH_SOLID,
        is_true_e_value=True,
        log_e_value=0.5,
        null_hypothesis_id="ope:within_budget",
        filtration_id="ope:permits",
        calibrator="p_to_e:integrated",
    )
    assert ev.calibrator == "p_to_e:integrated"
    assert ev.ville_p_value is not None


def test_e_process_true_requires_sequential_predictability() -> None:
    with pytest.raises(ValidationError, match="sequentially_predictable"):
        TexEvidence(
            stream_id="drift",
            kind=EvidenceKind.E_PROCESS,
            maturity=EvidenceMaturity.RESEARCH_SOLID,
            is_true_e_value=True,
            log_e_value=2.0,
            null_hypothesis_id="drift:no_change",
            filtration_id="drift:stream",
            sequentially_predictable=False,  # the lie
        )


def test_log_e_value_must_be_finite() -> None:
    for bad in (math.inf, -math.inf, math.nan):
        with pytest.raises(ValidationError, match="finite"):
            TexEvidence(
                stream_id="drift",
                kind=EvidenceKind.E_VALUE,
                maturity=EvidenceMaturity.RESEARCH_SOLID,
                is_true_e_value=True,
                log_e_value=bad,
                null_hypothesis_id="h0",
                filtration_id="f",
            )


def test_blank_identifiers_rejected() -> None:
    for field, value in [
        ("stream_id", "   "),
        ("null_hypothesis_id", ""),
        ("filtration_id", "\t"),
    ]:
        kwargs = dict(
            stream_id="drift",
            kind=EvidenceKind.E_VALUE,
            maturity=EvidenceMaturity.RESEARCH_SOLID,
            is_true_e_value=True,
            log_e_value=1.0,
            null_hypothesis_id="h0",
            filtration_id="f",
        )
        kwargs[field] = value
        with pytest.raises(ValidationError):
            TexEvidence(**kwargs)


def test_alpha_must_be_open_unit_interval_when_present() -> None:
    for bad in (0.0, 1.0, -0.1, 1.5):
        with pytest.raises(ValidationError):
            TexEvidence(
                stream_id="drift",
                kind=EvidenceKind.E_VALUE,
                maturity=EvidenceMaturity.RESEARCH_SOLID,
                is_true_e_value=True,
                log_e_value=1.0,
                null_hypothesis_id="h0",
                filtration_id="f",
                alpha=bad,
            )
    # None is allowed.
    assert TexEvidence(
        stream_id="drift",
        kind=EvidenceKind.E_VALUE,
        maturity=EvidenceMaturity.RESEARCH_SOLID,
        is_true_e_value=True,
        log_e_value=1.0,
        null_hypothesis_id="h0",
        filtration_id="f",
        alpha=None,
    ).alpha is None


# --------------------------------------------------------------------------- #
# (c) derived API delivers its name
# --------------------------------------------------------------------------- #
def test_e_value_is_exp_of_log() -> None:
    ev = _drift_e_process(log_e_value=2.5)
    assert ev.e_value == pytest.approx(math.exp(2.5))


def test_ville_p_value_only_for_true_e_values() -> None:
    # A true e-value: p = min(1, 1/E_t) = exp(-log_e_value) for log_e_value > 0.
    drift = _drift_e_process(log_e_value=math.log(20.0))  # E_t = 20
    assert drift.ville_p_value == pytest.approx(1.0 / 20.0)
    # Non-e-values yield None — no fabricated Ville p.
    assert _ope_cs_bound().ville_p_value is None
    assert _crc_calibration_cert().ville_p_value is None


def test_ville_p_value_floored_at_one_for_nonpositive_log() -> None:
    # log E_t <= 0 means evidence for the null -> p capped at 1.
    drift = _drift_e_process(log_e_value=-3.0)
    assert drift.ville_p_value == 1.0


def test_is_ville_significant_at() -> None:
    drift = _drift_e_process(log_e_value=math.log(100.0))  # E_t = 100, p = 0.01
    assert drift.is_ville_significant_at(0.05) is True
    assert drift.is_ville_significant_at(0.005) is False
    with pytest.raises(ValueError, match="alpha must be in"):
        drift.is_ville_significant_at(0.0)
    # A non-e-value cannot be Ville-tested.
    with pytest.raises(ValueError, match="no Ville bound"):
        _crc_calibration_cert().is_ville_significant_at(0.05)


# --------------------------------------------------------------------------- #
# (d) canonical serialization is byte-stable and complete
# --------------------------------------------------------------------------- #
def test_canonical_json_is_byte_stable_on_reserialization() -> None:
    ev = _drift_e_process()
    assert ev.canonical_json() == ev.canonical_json()
    assert ev.payload_sha256() == ev.payload_sha256()


def test_canonical_json_is_sorted_and_tight() -> None:
    ev = _drift_e_process()
    raw = ev.canonical_json()
    parsed = json.loads(raw)
    # sorted keys, tight separators (no spaces)
    assert raw == json.dumps(parsed, sort_keys=True, separators=(",", ":"))
    # every material field is present in the sealed payload
    for key in (
        "evidence_id",
        "decision_id",
        "stream_id",
        "kind",
        "maturity",
        "is_true_e_value",
        "log_e_value",
        "null_hypothesis_id",
        "filtration_id",
        "alpha",
        "sequentially_predictable",
        "calibrator",
        "sample_size",
        "recorded_at",
    ):
        assert key in parsed


def test_canonical_payload_roundtrips_through_json() -> None:
    ev = _ope_cs_bound()
    assert json.loads(ev.canonical_json()) == ev.canonical_payload()


def test_distinct_instances_have_distinct_seals() -> None:
    a = _drift_e_process()
    b = _drift_e_process()
    # different evidence_id (+ timestamp) -> different seal
    assert a.payload_sha256() != b.payload_sha256()


def test_does_not_disturb_existing_evidence_record() -> None:
    """The new types live alongside EvidenceRecord; the audit envelope is
    untouched and still importable/constructible."""
    from tex.domain.evidence import EvidenceRecord

    rec = EvidenceRecord(
        decision_id=uuid4(),
        request_id=uuid4(),
        record_type="decision",
        payload_json='{"a":1}',
        payload_sha256="a" * 64,
        record_hash="b" * 64,
        policy_version="v1",
    )
    assert rec.record_type == "decision"

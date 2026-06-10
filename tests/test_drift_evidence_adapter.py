"""
Wiring the drift anytime-valid e-process into the sealed evidence type.

Pins the bridge contract:

  * one drift certificate lifts faithfully into a TexEvidence e-process snapshot
    (no over-claim: is_true_e_value/kind/sequentially_predictable all honest);
  * a RiskStreamEProcess emits a snapshot per observation; sustained drift
    raises the e-value until the stream breaches its safety null, while a
    null-consistent stream never breaches (monotone-lowering: a high e-value
    only raises caution);
  * the emitted snapshots compose through the spine — and a cross-stream merge
    is honestly mixed-filtration (a valid e-value, but not anytime-valid).
"""

from __future__ import annotations

from uuid import uuid4

import pytest

from tex.domain.evidence import (
    EvidenceKind,
    EvidenceMaturity,
    compose_arithmetic_mean,
)
from tex.drift._anytime_valid import AnytimeValidEProcess
from tex.drift.evidence_adapter import (
    ABSTAIN_RATE_FILTRATION,
    ABSTAIN_RATE_NULL,
    ABSTAIN_RATE_STREAM,
    FALSE_PERMIT_FILTRATION,
    FALSE_PERMIT_NULL,
    FALSE_PERMIT_STREAM,
    RiskStreamEProcess,
    abstain_rate_monitor,
    certificate_to_tex_evidence,
    false_permit_monitor,
)


# --------------------------------------------------------------------------- #
# certificate -> TexEvidence lift is faithful and honest
# --------------------------------------------------------------------------- #
def test_certificate_lifts_to_true_e_process_snapshot() -> None:
    ep = AnytimeValidEProcess()
    cert = ep.observe(standardised_x=3.0)
    did = uuid4()
    ev = certificate_to_tex_evidence(
        cert,
        stream_id="drift",
        null_hypothesis_id="drift:no_regime_change",
        filtration_id="drift:risk_stream",
        decision_id=did,
        alpha=0.05,
    )
    assert ev.kind is EvidenceKind.E_PROCESS
    assert ev.is_true_e_value is True
    assert ev.sequentially_predictable is True
    assert ev.log_e_value == cert.log_e_value
    assert ev.sample_size == cert.sample_size
    assert ev.decision_id == did
    # default maturity is honest: research-early, not solid
    assert ev.maturity is EvidenceMaturity.RESEARCH_EARLY


# --------------------------------------------------------------------------- #
# RiskStreamEProcess: drift breaches, null does not
# --------------------------------------------------------------------------- #
def test_sustained_drift_breaches_the_null() -> None:
    mon = false_permit_monitor(alpha=0.05)
    assert mon.is_breached() is False  # nothing observed yet
    last = None
    for _ in range(5):
        last = mon.observe(standardised_x=4.0)
    assert last is not None
    assert last.stream_id == FALSE_PERMIT_STREAM
    assert last.null_hypothesis_id == FALSE_PERMIT_NULL
    assert last.filtration_id == FALSE_PERMIT_FILTRATION
    # strong sustained drift -> large e-value -> rejects the safety null
    assert mon.is_breached(0.05) is True
    assert last.is_ville_significant_at(0.05) is True


def test_null_consistent_stream_never_breaches() -> None:
    mon = abstain_rate_monitor()
    for _ in range(20):
        ev = mon.observe(standardised_x=0.0)
    # no drift -> e-value <= 1 -> p == 1 -> never significant (monotone-lowering:
    # absence of evidence never lowers caution, it just doesn't raise it)
    assert mon.is_breached(0.05) is False
    assert ev.ville_p_value == 1.0


def test_e_value_is_monotone_nondecreasing_under_constant_positive_drift() -> None:
    mon = false_permit_monitor()
    vals = [mon.observe(standardised_x=2.0).log_e_value for _ in range(8)]
    # under constant positive drift the cumulative deviation grows, so the
    # dominant-lambda log-e-value is non-decreasing once it turns positive
    assert vals[-1] > vals[0]


def test_reset_restarts_the_process() -> None:
    mon = false_permit_monitor()
    for _ in range(5):
        mon.observe(standardised_x=5.0)
    assert mon.is_breached() is True
    mon.reset()
    assert mon.is_breached() is False
    assert mon.latest_certificate is None


def test_alpha_validation() -> None:
    with pytest.raises(ValueError, match="alpha must be in"):
        RiskStreamEProcess(
            stream_id="x",
            null_hypothesis_id="h0",
            filtration_id="f",
            alpha=0.0,
        )


# --------------------------------------------------------------------------- #
# emitted snapshots compose through the spine
# --------------------------------------------------------------------------- #
def test_cross_stream_composition_is_mixed_filtration() -> None:
    fp = false_permit_monitor()
    ar = abstain_rate_monitor()
    did = uuid4()
    e_fp = None
    e_ar = None
    for _ in range(4):
        e_fp = fp.observe(standardised_x=3.0, decision_id=did)
        e_ar = ar.observe(standardised_x=3.0, decision_id=did)
    combined = compose_arithmetic_mean([e_fp, e_ar], decision_id=did)
    # two distinct stream filtrations -> a valid e-value, but NOT anytime-valid
    assert combined.is_true_e_value is True
    assert combined.anytime_valid is False
    assert combined.filtration_id == "mixed"
    assert combined.joint_null_hypothesis_id == f"AND({ABSTAIN_RATE_NULL},{FALSE_PERMIT_NULL})"


def test_monitors_have_distinct_streams() -> None:
    assert FALSE_PERMIT_STREAM != ABSTAIN_RATE_STREAM
    assert FALSE_PERMIT_FILTRATION != ABSTAIN_RATE_FILTRATION
    assert abstain_rate_monitor().stream_id == ABSTAIN_RATE_STREAM

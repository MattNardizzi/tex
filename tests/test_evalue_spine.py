"""
The multiplicative e-value spine — composing many TexEvidence into one.

Pins the composition contract the abstain/struct tracks and the offline
verifier depend on:

  * the MEAN is the always-valid default (Vovk-Wang): exp(combined) is the
    arithmetic mean of the component e-values, valid for the CONJUNCTION of the
    component nulls under arbitrary dependence;
  * the PRODUCT is opt-in, GROW-stronger, and must seal an independence
    justification (refused without one);
  * two honest guarantee levels are never conflated — is_true_e_value (a valid
    fixed-look e-value) vs anytime_valid (the sup-time Ville bound, only for
    same-filtration sequentially-predictable e-processes);
  * non-e-values are DROPPED (recorded, never inflate the product), and zero
    e-values yields an ABSTAIN — caution, not evidence of safety;
  * the composition is replayable from the sealed bytes (the seed of the
    standalone verifier).
"""

from __future__ import annotations

import math
from uuid import uuid4

import pytest
from pydantic import ValidationError

from tex.domain.evidence import (
    CombinedEvidence,
    EvidenceKind,
    EvidenceMaturity,
    TexEvidence,
    compose_arithmetic_mean,
    compose_product_independence,
    compose_spine,
)


def _eproc(
    *,
    e_value: float,
    null: str = "drift:no_regime_change",
    filtration: str = "drift:risk_stream",
    maturity: EvidenceMaturity = EvidenceMaturity.RESEARCH_SOLID,
    seq: bool = True,
) -> TexEvidence:
    return TexEvidence(
        stream_id="drift",
        kind=EvidenceKind.E_PROCESS,
        maturity=maturity,
        is_true_e_value=True,
        log_e_value=math.log(e_value),
        null_hypothesis_id=null,
        filtration_id=filtration,
        sequentially_predictable=seq,
    )


def _single_shot(*, e_value: float, null: str = "h0", filtration: str = "f") -> TexEvidence:
    return TexEvidence(
        stream_id="x",
        kind=EvidenceKind.E_VALUE,
        maturity=EvidenceMaturity.RESEARCH_SOLID,
        is_true_e_value=True,
        log_e_value=math.log(e_value),
        null_hypothesis_id=null,
        filtration_id=filtration,
    )


def _cs_bound() -> TexEvidence:
    return TexEvidence(
        stream_id="ope",
        kind=EvidenceKind.CONFIDENCE_SEQUENCE_BOUND,
        maturity=EvidenceMaturity.RESEARCH_SOLID,
        is_true_e_value=False,
        log_e_value=0.7,
        null_hypothesis_id="ope:within_budget",
        filtration_id="ope:permits",
    )


def _crc_cert() -> TexEvidence:
    return TexEvidence(
        stream_id="crc",
        kind=EvidenceKind.CALIBRATION_CERTIFICATE,
        maturity=EvidenceMaturity.RESEARCH_SOLID,
        is_true_e_value=False,
        log_e_value=0.0,
        null_hypothesis_id="crc:bounded",
        filtration_id="crc:frozen",
    )


# --------------------------------------------------------------------------- #
# MEAN — the always-valid default (Vovk-Wang)
# --------------------------------------------------------------------------- #
def test_mean_is_arithmetic_mean_of_e_values() -> None:
    items = [_eproc(e_value=2.0), _eproc(e_value=8.0)]
    out = compose_arithmetic_mean(items)
    assert out.combiner == "arithmetic_mean"
    assert out.is_true_e_value is True
    # exp(combined log) == arithmetic mean of e-values == (2 + 8) / 2 == 5
    assert out.e_value == pytest.approx(5.0)
    assert out.log_e_value == pytest.approx(math.log(5.0))


def test_mean_anytime_valid_only_same_filtration_eprocesses() -> None:
    # same filtration, both sequentially-predictable e-processes -> anytime-valid
    same = compose_arithmetic_mean(
        [_eproc(e_value=3.0), _eproc(e_value=4.0)]
    )
    assert same.anytime_valid is True
    assert same.filtration_id == "drift:risk_stream"

    # different filtrations -> valid e-value, but NOT anytime-valid
    cross = compose_arithmetic_mean(
        [
            _eproc(e_value=3.0, filtration="drift:a"),
            _eproc(e_value=4.0, filtration="agent:b"),
        ]
    )
    assert cross.is_true_e_value is True
    assert cross.anytime_valid is False
    assert cross.filtration_id == "mixed"

    # a single-shot e_value in the mix -> not an e-process -> not anytime-valid
    mixed_kind = compose_arithmetic_mean(
        [_eproc(e_value=3.0), _single_shot(e_value=4.0, filtration="drift:risk_stream")]
    )
    assert mixed_kind.anytime_valid is False


def test_mean_joint_null_is_conjunction() -> None:
    out = compose_arithmetic_mean(
        [
            _eproc(e_value=2.0, null="drift:no_change", filtration="f"),
            _eproc(e_value=2.0, null="agent:on_baseline", filtration="f"),
        ]
    )
    assert out.joint_null_hypothesis_id == "AND(agent:on_baseline,drift:no_change)"


def test_mean_weakest_maturity_wins() -> None:
    out = compose_arithmetic_mean(
        [
            _eproc(e_value=2.0, maturity=EvidenceMaturity.PRODUCTION),
            _eproc(e_value=2.0, maturity=EvidenceMaturity.SPECULATIVE),
        ]
    )
    assert out.maturity is EvidenceMaturity.SPECULATIVE


# --------------------------------------------------------------------------- #
# PRODUCT — opt-in, GROW-stronger, must seal a justification
# --------------------------------------------------------------------------- #
def test_product_is_product_of_e_values() -> None:
    out = compose_product_independence(
        [_eproc(e_value=2.0), _eproc(e_value=8.0)],
        justification="independent risk streams (per design charter X)",
    )
    assert out.combiner == "product_independence"
    assert out.e_value == pytest.approx(16.0)
    assert out.justification.startswith("independent")


def test_product_requires_justification() -> None:
    with pytest.raises(ValueError, match="justification"):
        compose_product_independence([_eproc(e_value=2.0)], justification="  ")


def test_product_dominates_mean() -> None:
    items = [_eproc(e_value=4.0), _eproc(e_value=4.0)]
    mean = compose_arithmetic_mean(items)
    prod = compose_product_independence(items, justification="indep")
    assert prod.e_value > mean.e_value  # 16 > 4


# --------------------------------------------------------------------------- #
# refuse non-e-values
# --------------------------------------------------------------------------- #
def test_combiners_refuse_non_e_values() -> None:
    with pytest.raises(ValueError, match="non-e-values"):
        compose_arithmetic_mean([_eproc(e_value=2.0), _cs_bound()])
    with pytest.raises(ValueError, match="non-e-values"):
        compose_product_independence([_crc_cert()], justification="x")


def test_empty_is_refused_by_direct_combiners() -> None:
    with pytest.raises(ValueError, match="at least one"):
        compose_arithmetic_mean([])


# --------------------------------------------------------------------------- #
# the spine dispatcher
# --------------------------------------------------------------------------- #
def test_spine_drops_non_e_values_and_records_them() -> None:
    drift = _eproc(e_value=9.0)
    ope = _cs_bound()
    crc = _crc_cert()
    out = compose_spine([drift, ope, crc])
    assert out.combiner == "arithmetic_mean"
    assert out.n_components == 1
    assert out.component_ids == (drift.evidence_id,)
    assert set(out.excluded_ids) == {ope.evidence_id, crc.evidence_id}
    assert out.e_value == pytest.approx(9.0)


def test_spine_abstains_with_zero_e_values() -> None:
    out = compose_spine([_cs_bound(), _crc_cert()])
    assert out.combiner == "abstain"
    assert out.is_true_e_value is False
    assert out.anytime_valid is False
    assert out.e_value == pytest.approx(1.0)  # neutral E=1
    assert out.ville_p_value is None
    assert out.n_components == 0
    assert len(out.excluded_ids) == 2
    with pytest.raises(ValueError, match="no e-value"):
        out.is_ville_significant_at(0.05)


def test_spine_product_path() -> None:
    items = [_eproc(e_value=3.0), _eproc(e_value=3.0)]
    out = compose_spine(
        items, prefer_product=True, independence_justification="indep streams"
    )
    assert out.combiner == "product_independence"
    assert out.e_value == pytest.approx(9.0)


def test_spine_product_path_requires_justification() -> None:
    with pytest.raises(ValueError, match="independence_justification"):
        compose_spine([_eproc(e_value=2.0)], prefer_product=True)


def test_spine_carries_decision_id() -> None:
    did = uuid4()
    out = compose_spine([_eproc(e_value=2.0)], decision_id=did)
    assert out.decision_id == did


# --------------------------------------------------------------------------- #
# CombinedEvidence honesty invariants (constructor-level)
# --------------------------------------------------------------------------- #
def test_anytime_valid_requires_true_e_value() -> None:
    with pytest.raises(ValidationError, match="anytime_valid"):
        CombinedEvidence(
            combiner="arithmetic_mean",
            log_e_value=1.0,
            is_true_e_value=False,
            anytime_valid=True,  # the lie
            joint_null_hypothesis_id="h0",
            filtration_id="f",
            maturity=EvidenceMaturity.RESEARCH_SOLID,
        )


def test_abstain_cannot_be_true_e_value() -> None:
    with pytest.raises(ValidationError, match="abstain"):
        CombinedEvidence(
            combiner="abstain",
            log_e_value=0.0,
            is_true_e_value=True,  # the lie
            anytime_valid=False,
            joint_null_hypothesis_id="none",
            filtration_id="none",
            maturity=EvidenceMaturity.SPECULATIVE,
        )


def test_product_must_seal_justification_and_mean_must_not() -> None:
    with pytest.raises(ValidationError, match="justification"):
        CombinedEvidence(
            combiner="product_independence",
            log_e_value=1.0,
            is_true_e_value=True,
            anytime_valid=False,
            joint_null_hypothesis_id="h0",
            filtration_id="f",
            maturity=EvidenceMaturity.RESEARCH_SOLID,
            justification=None,  # missing
        )
    with pytest.raises(ValidationError, match="justification"):
        CombinedEvidence(
            combiner="arithmetic_mean",
            log_e_value=1.0,
            is_true_e_value=True,
            anytime_valid=False,
            joint_null_hypothesis_id="h0",
            filtration_id="f",
            maturity=EvidenceMaturity.RESEARCH_SOLID,
            justification="should not be here",
        )


def test_unknown_combiner_rejected() -> None:
    with pytest.raises(ValidationError, match="combiner must be"):
        CombinedEvidence(
            combiner="median",
            log_e_value=1.0,
            is_true_e_value=True,
            anytime_valid=False,
            joint_null_hypothesis_id="h0",
            filtration_id="f",
            maturity=EvidenceMaturity.RESEARCH_SOLID,
        )


# --------------------------------------------------------------------------- #
# replayability — the seed of the standalone verifier
# --------------------------------------------------------------------------- #
def test_combination_is_replayable_from_components() -> None:
    items = [_eproc(e_value=2.0), _eproc(e_value=8.0), _eproc(e_value=5.0)]
    out = compose_arithmetic_mean(items)
    # an independent verifier recomputes the mean from the component e-values
    recomputed = sum(it.e_value for it in items) / len(items)
    assert out.e_value == pytest.approx(recomputed)
    # and the seal is byte-stable
    assert out.canonical_json() == out.canonical_json()
    assert out.payload_sha256() == out.payload_sha256()


def test_ville_p_value_of_combined() -> None:
    # mean e-value of 100 -> p = 0.01
    items = [_eproc(e_value=100.0), _eproc(e_value=100.0)]
    out = compose_arithmetic_mean(items)
    assert out.e_value == pytest.approx(100.0)
    assert out.ville_p_value == pytest.approx(0.01)
    assert out.is_ville_significant_at(0.05) is True
    assert out.is_ville_significant_at(0.005) is False

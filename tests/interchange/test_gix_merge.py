"""Authenticated federated mean-merge tests — earn-it item 4.

Disjointness violation rejected; non-e-value input rejected; mean of true
e-values computed correctly (hand-derived value); and "authenticated" is
earned: tampered records, unpinned keys, missing inclusion, and unwitnessed
checkpoints are each rejected with a named reason.
"""

from __future__ import annotations

import math
from uuid import uuid4

import pytest

from tex.domain.evidence import EvidenceMaturity
from tex.domain.evidence import _log_mean_exp as domain_log_mean_exp
from tex.interchange.gix import build_add_checkpoint_body
from tex.interchange.gix_merge import (
    GixMergeRefused,
    OrgEvidenceSubmission,
    merge_federated_evidence,
    verify_org_evidence,
)
from tex.interchange.gix_witness import (
    FEDERATED_FALSE_REASON,
    gather_cosignatures,
)
from tex.provenance.ledger import SealedFactLedger

from tests.interchange._helpers import (
    abstain_evidence,
    decision_fact,
    make_witnesses,
    publisher_for,
    seal_decisions,
    true_e_value,
)

QUORUM = 3


def _org(origin, evidence, witnesses, *, stream_ids, evidence_leaf=1):
    """Build one org: ledger with 3 sealed facts (the evidence-bearing one at
    ``evidence_leaf``), a witnessed checkpoint, and the submission."""
    ledger = SealedFactLedger()
    for i in range(3):
        fact_evidence = evidence if i == evidence_leaf else None
        ledger.append(
            decision_fact(claim=f"{origin} decision {i}", evidence=fact_evidence)
        )
    publisher = publisher_for(ledger, origin)
    for witness in witnesses:
        witness._trusted[origin] = publisher.log_verifier  # noqa: SLF001 — test rig
    snapshot = publisher.current_signed_checkpoint()
    body = build_add_checkpoint_body(0, (), snapshot.signed_note)
    cosigned = gather_cosignatures(body, witnesses)
    submission = OrgEvidenceSubmission(
        origin=origin,
        record=ledger.list_all()[evidence_leaf],
        leaf_index=evidence_leaf,
        inclusion_proof=publisher.inclusion_proof(evidence_leaf, snapshot),
        cosigned_checkpoint=cosigned,
        ledger_public_key_pem=ledger.public_key_pem,
        declared_stream_ids=tuple(stream_ids),
    )
    return ledger, publisher, submission


def _two_org_world(evidence_a=None, evidence_b=None, *, streams_a=("orga:drift",), streams_b=("orgb:drift",)):
    witnesses = make_witnesses(QUORUM, {})
    e_a = evidence_a if evidence_a is not None else true_e_value(math.log(4.0))
    e_b = evidence_b if evidence_b is not None else true_e_value(math.log(2.0))
    _, pub_a, sub_a = _org("orga.example/gix", e_a, witnesses, stream_ids=streams_a)
    _, pub_b, sub_b = _org("orgb.example/gix", e_b, witnesses, stream_ids=streams_b)
    log_verifiers = {
        "orga.example/gix": pub_a.log_verifier,
        "orgb.example/gix": pub_b.log_verifier,
    }
    roster = [w.descriptor for w in witnesses]
    return sub_a, sub_b, log_verifiers, roster


class TestMeanIsComputedCorrectly:
    def test_mean_of_true_e_values(self):
        """e-values 4 and 2 → arithmetic mean 3 → log_e == ln 3, exactly the
        hand-derived value (Vovk–Wang mean merge)."""
        sub_a, sub_b, log_verifiers, roster = _two_org_world()
        merged = merge_federated_evidence(
            [sub_a, sub_b],
            log_verifiers=log_verifiers,
            roster=roster,
            quorum=QUORUM,
        )
        assert math.isclose(merged.log_e_value, math.log(3.0), rel_tol=1e-12)
        assert math.isclose(merged.e_value, 3.0, rel_tol=1e-12)
        assert merged.is_true_e_value
        assert merged.n_orgs == 2
        assert merged.origins == ("orga.example/gix", "orgb.example/gix")

    def test_log_mean_exp_pinned_against_domain_module(self):
        """The local mirror must stay numerically identical to
        domain/evidence._log_mean_exp (the in-repo canonical)."""
        from tex.interchange.gix_merge import _log_mean_exp

        for vector in ([0.0], [math.log(4), math.log(2)], [-3.0, 0.5, 2.2]):
            assert math.isclose(
                _log_mean_exp(vector), domain_log_mean_exp(vector), rel_tol=1e-15
            )

    def test_anytime_valid_only_on_one_filtration(self):
        sub_a, sub_b, log_verifiers, roster = _two_org_world()
        merged = merge_federated_evidence(
            [sub_a, sub_b], log_verifiers=log_verifiers, roster=roster, quorum=QUORUM
        )
        assert merged.anytime_valid  # same filtration, both anytime-valid
        assert merged.filtration_id == "f:decisions"
        assert merged.joint_null_hypothesis_id == "h0:drift"

        # Mixed filtrations: the sup-time claim is refused, the e-value stays.
        sub_a2, sub_b2, lv2, roster2 = _two_org_world(
            evidence_b=true_e_value(math.log(2.0), filtration="f:other")
        )
        mixed = merge_federated_evidence(
            [sub_a2, sub_b2], log_verifiers=lv2, roster=roster2, quorum=QUORUM
        )
        assert not mixed.anytime_valid
        assert mixed.filtration_id == "mixed"
        assert mixed.is_true_e_value

    def test_distinct_nulls_become_conjunction(self):
        sub_a, sub_b, log_verifiers, roster = _two_org_world(
            evidence_b=true_e_value(math.log(2.0), null="h0:other")
        )
        merged = merge_federated_evidence(
            [sub_a, sub_b], log_verifiers=log_verifiers, roster=roster, quorum=QUORUM
        )
        assert merged.joint_null_hypothesis_id == "AND(h0:drift,h0:other)"

    def test_maturity_is_weakest_capped_at_research_early(self):
        sub_a, sub_b, log_verifiers, roster = _two_org_world()
        merged = merge_federated_evidence(
            [sub_a, sub_b], log_verifiers=log_verifiers, roster=roster, quorum=QUORUM
        )
        # Inputs are RESEARCH_SOLID; the interchange transport caps the merged
        # claim at RESEARCH_EARLY.
        assert merged.maturity is EvidenceMaturity.RESEARCH_EARLY

        sub_a2, sub_b2, lv2, roster2 = _two_org_world(
            evidence_b=true_e_value(
                math.log(2.0), maturity=EvidenceMaturity.SPECULATIVE
            )
        )
        weakest = merge_federated_evidence(
            [sub_a2, sub_b2], log_verifiers=lv2, roster=roster2, quorum=QUORUM
        )
        assert weakest.maturity is EvidenceMaturity.SPECULATIVE

    def test_federated_false_propagates_with_reason(self):
        sub_a, sub_b, log_verifiers, roster = _two_org_world()
        merged = merge_federated_evidence(
            [sub_a, sub_b], log_verifiers=log_verifiers, roster=roster, quorum=QUORUM
        )
        assert merged.federated is False
        assert merged.federated_reason == FEDERATED_FALSE_REASON


class TestDisjointnessGuard:
    def test_overlapping_stream_ids_rejected(self):
        sub_a, sub_b, log_verifiers, roster = _two_org_world(
            streams_a=("shared:drift", "orga:x"), streams_b=("shared:drift",)
        )
        with pytest.raises(GixMergeRefused) as excinfo:
            merge_federated_evidence(
                [sub_a, sub_b],
                log_verifiers=log_verifiers,
                roster=roster,
                quorum=QUORUM,
            )
        assert excinfo.value.reason_code == "stream_double_counted"

    def test_shared_component_evidence_rejected(self):
        shared_component = (uuid4(),)
        sub_a, sub_b, log_verifiers, roster = _two_org_world(
            evidence_a=true_e_value(math.log(4.0), component_ids=shared_component),
            evidence_b=true_e_value(math.log(2.0), component_ids=shared_component),
        )
        with pytest.raises(GixMergeRefused) as excinfo:
            merge_federated_evidence(
                [sub_a, sub_b],
                log_verifiers=log_verifiers,
                roster=roster,
                quorum=QUORUM,
            )
        assert excinfo.value.reason_code == "component_double_counted"

    def test_same_evidence_object_rejected(self):
        same = true_e_value(math.log(4.0))
        sub_a, sub_b, log_verifiers, roster = _two_org_world(
            evidence_a=same, evidence_b=same
        )
        with pytest.raises(GixMergeRefused) as excinfo:
            merge_federated_evidence(
                [sub_a, sub_b],
                log_verifiers=log_verifiers,
                roster=roster,
                quorum=QUORUM,
            )
        assert excinfo.value.reason_code == "duplicate_evidence"

    def test_duplicate_origin_rejected(self):
        sub_a, _, log_verifiers, roster = _two_org_world()
        with pytest.raises(GixMergeRefused) as excinfo:
            merge_federated_evidence(
                [sub_a, sub_a],
                log_verifiers=log_verifiers,
                roster=roster,
                quorum=QUORUM,
            )
        assert excinfo.value.reason_code == "duplicate_origin"

    def test_single_org_rejected(self):
        sub_a, _, log_verifiers, roster = _two_org_world()
        with pytest.raises(GixMergeRefused) as excinfo:
            merge_federated_evidence(
                [sub_a], log_verifiers=log_verifiers, roster=roster, quorum=QUORUM
            )
        assert excinfo.value.reason_code == "too_few_orgs"


class TestNonEValuesRefused:
    def test_no_evidence_rejected(self):
        witnesses = make_witnesses(QUORUM, {})
        _, pub_a, sub_a = _org(
            "orga.example/gix",
            true_e_value(math.log(4.0)),
            witnesses,
            stream_ids=("orga:drift",),
        )
        _, pub_c, sub_c = _org(
            "orgc.example/gix", None, witnesses, stream_ids=("orgc:drift",)
        )
        with pytest.raises(GixMergeRefused) as excinfo:
            merge_federated_evidence(
                [sub_a, sub_c],
                log_verifiers={
                    "orga.example/gix": pub_a.log_verifier,
                    "orgc.example/gix": pub_c.log_verifier,
                },
                roster=[w.descriptor for w in witnesses],
                quorum=QUORUM,
            )
        assert excinfo.value.reason_code == "submission_rejected"
        assert "not_a_true_e_value" in str(excinfo.value)

    def test_abstain_evidence_rejected(self):
        """An abstain CombinedEvidence (is_true_e_value=False) must never
        enter a mean — it would launder 'no evidence' into E=1 'evidence'."""
        witnesses = make_witnesses(QUORUM, {})
        _, pub_a, sub_a = _org(
            "orga.example/gix",
            true_e_value(math.log(4.0)),
            witnesses,
            stream_ids=("orga:drift",),
        )
        _, pub_c, sub_c = _org(
            "orgc.example/gix",
            abstain_evidence(),
            witnesses,
            stream_ids=("orgc:drift",),
        )
        with pytest.raises(GixMergeRefused) as excinfo:
            merge_federated_evidence(
                [sub_a, sub_c],
                log_verifiers={
                    "orga.example/gix": pub_a.log_verifier,
                    "orgc.example/gix": pub_c.log_verifier,
                },
                roster=[w.descriptor for w in witnesses],
                quorum=QUORUM,
            )
        assert excinfo.value.reason_code == "submission_rejected"
        assert "not_a_true_e_value" in str(excinfo.value)


class TestAuthenticatedMeansAuthenticated:
    def test_tampered_record_rejected(self):
        sub_a, sub_b, log_verifiers, roster = _two_org_world()
        tampered_fact = sub_b.record.fact.model_copy(
            update={"claim": "history, rewritten"}
        )
        tampered = OrgEvidenceSubmission(
            origin=sub_b.origin,
            record=sub_b.record.model_copy(update={"fact": tampered_fact}),
            leaf_index=sub_b.leaf_index,
            inclusion_proof=sub_b.inclusion_proof,
            cosigned_checkpoint=sub_b.cosigned_checkpoint,
            ledger_public_key_pem=sub_b.ledger_public_key_pem,
            declared_stream_ids=sub_b.declared_stream_ids,
        )
        with pytest.raises(GixMergeRefused) as excinfo:
            merge_federated_evidence(
                [sub_a, tampered],
                log_verifiers=log_verifiers,
                roster=roster,
                quorum=QUORUM,
            )
        assert "record_integrity" in str(excinfo.value)

    def test_wrong_pinned_ledger_key_rejected(self):
        sub_a, sub_b, log_verifiers, roster = _two_org_world()
        wrong_key = OrgEvidenceSubmission(
            origin=sub_b.origin,
            record=sub_b.record,
            leaf_index=sub_b.leaf_index,
            inclusion_proof=sub_b.inclusion_proof,
            cosigned_checkpoint=sub_b.cosigned_checkpoint,
            ledger_public_key_pem=SealedFactLedger().public_key_pem,
            declared_stream_ids=sub_b.declared_stream_ids,
        )
        with pytest.raises(GixMergeRefused) as excinfo:
            merge_federated_evidence(
                [sub_a, wrong_key],
                log_verifiers=log_verifiers,
                roster=roster,
                quorum=QUORUM,
            )
        assert "record_authorship" in str(excinfo.value)

    def test_wrong_leaf_index_rejected(self):
        sub_a, sub_b, log_verifiers, roster = _two_org_world()
        misplaced = OrgEvidenceSubmission(
            origin=sub_b.origin,
            record=sub_b.record,
            leaf_index=2,  # the record actually sits at index 1
            inclusion_proof=sub_b.inclusion_proof,
            cosigned_checkpoint=sub_b.cosigned_checkpoint,
            ledger_public_key_pem=sub_b.ledger_public_key_pem,
            declared_stream_ids=sub_b.declared_stream_ids,
        )
        with pytest.raises(GixMergeRefused) as excinfo:
            merge_federated_evidence(
                [sub_a, misplaced],
                log_verifiers=log_verifiers,
                roster=roster,
                quorum=QUORUM,
            )
        assert "inclusion" in str(excinfo.value)

    def test_unwitnessed_checkpoint_rejected(self):
        """Quorum 3 with only 2 cosigning witnesses: the evidence may be
        signed and included, but without non-equivocation it stays out."""
        witnesses = make_witnesses(2, {})
        _, pub_a, sub_a = _org(
            "orga.example/gix",
            true_e_value(math.log(4.0)),
            witnesses,
            stream_ids=("orga:drift",),
        )
        _, pub_b, sub_b = _org(
            "orgb.example/gix",
            true_e_value(math.log(2.0)),
            witnesses,
            stream_ids=("orgb:drift",),
        )
        with pytest.raises(GixMergeRefused) as excinfo:
            merge_federated_evidence(
                [sub_a, sub_b],
                log_verifiers={
                    "orga.example/gix": pub_a.log_verifier,
                    "orgb.example/gix": pub_b.log_verifier,
                },
                roster=[w.descriptor for w in witnesses],
                quorum=QUORUM,
            )
        assert "checkpoint_not_witnessed" in str(excinfo.value)

    def test_unpinned_log_key_rejected(self):
        sub_a, sub_b, log_verifiers, roster = _two_org_world()
        with pytest.raises(GixMergeRefused) as excinfo:
            merge_federated_evidence(
                [sub_a, sub_b],
                log_verifiers={"orga.example/gix": log_verifiers["orga.example/gix"]},
                roster=roster,
                quorum=QUORUM,
            )
        assert excinfo.value.reason_code == "unpinned_log_key"

    def test_origin_mismatch_rejected(self):
        sub_a, sub_b, log_verifiers, roster = _two_org_world()
        lying = OrgEvidenceSubmission(
            origin="orgc.example/gix",  # claims to be org C, carries B's log
            record=sub_b.record,
            leaf_index=sub_b.leaf_index,
            inclusion_proof=sub_b.inclusion_proof,
            cosigned_checkpoint=sub_b.cosigned_checkpoint,
            ledger_public_key_pem=sub_b.ledger_public_key_pem,
            declared_stream_ids=("orgc:drift",),
        )
        with pytest.raises(GixMergeRefused) as excinfo:
            merge_federated_evidence(
                [sub_a, lying],
                log_verifiers={
                    **log_verifiers,
                    "orgc.example/gix": log_verifiers["orgb.example/gix"],
                },
                roster=roster,
                quorum=QUORUM,
            )
        assert "origin_mismatch" in str(excinfo.value)

    def test_verify_org_evidence_happy_path_names_ok(self):
        sub_a, _, log_verifiers, roster = _two_org_world()
        result = verify_org_evidence(
            sub_a,
            log_verifier=log_verifiers["orga.example/gix"],
            roster=roster,
            quorum=QUORUM,
        )
        assert result.ok
        assert result.reason == "ok"
        assert result.checkpoint_verification is not None
        assert result.checkpoint_verification.federated is False

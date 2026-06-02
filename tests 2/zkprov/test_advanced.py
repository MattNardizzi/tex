"""Tests for ZKPROV sampler, recursive aggregation, SCITT ARP, and NABAOS receipts."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from tex.zkprov.commitment import deterministic_test_ca, issue_commitment
from tex.zkprov.manifest import (
    DatasetManifest,
    DataSource,
    LicenseTag,
    TDSSourceCategory,
)
from tex.zkprov.proof import generate_proof
from tex.zkprov.receipts import (
    EpistemicClaim,
    Pramana,
    ToolCallRecord,
    detect_hallucinations,
    issue_receipt,
    verify_receipt,
)
from tex.zkprov.recursive import (
    FoldingScheme,
    aggregate_proofs,
    is_post_quantum_folding,
    verify_aggregated_certificate,
)
from tex.zkprov.sampler import (
    SamplerMode,
    commit_seed,
    derive_batch_schedule,
    make_sampler_commitment,
    replay_public_sampler,
)
from tex.zkprov.scitt_arp import (
    ARPPredicate,
    ARPPredicateLibrary,
    ARPReconciliationOutput,
    ARPReconciliationVerdict,
    consistent_with_commitment,
    narrow_manifest_data_volume,
    narrow_manifest_license_family,
    narrow_manifest_temporal_window,
    package_for_arp_exchange,
)


def _manifest(source_count: int = 1, records_per_source: int = 100) -> DatasetManifest:
    return DatasetManifest(
        manifest_id="m1",
        model_card_uri="https://x",
        model_provider="ACME",
        sources=tuple(
            DataSource(
                source_id=f"s{i}",
                source_uri=f"hf://x/{i}",
                content_sha256="a" * 64,
                record_count=records_per_source,
                tds_category=TDSSourceCategory.PUBLICLY_AVAILABLE_DATASET,
                license=LicenseTag.MIT if i % 2 == 0 else LicenseTag.APACHE_2_0,
                max_epoch_participation=1,
            )
            for i in range(source_count)
        ),
        preprocessing=(),
        total_training_epochs=1,
        base_model_sha256="b" * 64,
        training_window_start=datetime(2025, 1, 1, tzinfo=UTC),
        training_window_end=datetime(2026, 1, 1, tzinfo=UTC),
        issued_at=datetime(2026, 1, 1, tzinfo=UTC),
        valid_until=datetime(2027, 1, 1, tzinfo=UTC),
    )


# =========================================================================== #
# Sampler (VFT element 2)                                                     #
# =========================================================================== #


def test_sampler_seed_commitment_deterministic() -> None:
    seed = b"\x00" * 32
    assert commit_seed(seed) == commit_seed(seed)


def test_sampler_derive_schedule_deterministic() -> None:
    seed = b"\x42" * 32
    s1 = derive_batch_schedule(
        seed=seed, record_count=1000, batch_size=8, steps_per_epoch=4, epoch=0
    )
    s2 = derive_batch_schedule(
        seed=seed, record_count=1000, batch_size=8, steps_per_epoch=4, epoch=0
    )
    assert s1 == s2
    assert len(s1.steps) == 4
    assert all(len(step) == 8 for step in s1.steps)


def test_sampler_different_epochs_yield_different_schedules() -> None:
    seed = b"\x42" * 32
    s1 = derive_batch_schedule(
        seed=seed, record_count=1000, batch_size=8, steps_per_epoch=4, epoch=0
    )
    s2 = derive_batch_schedule(
        seed=seed, record_count=1000, batch_size=8, steps_per_epoch=4, epoch=1
    )
    assert s1.steps != s2.steps


def test_sampler_public_replayable_roundtrip() -> None:
    seed = b"\xa5" * 32
    commitment = make_sampler_commitment(
        mode=SamplerMode.PUBLIC_REPLAYABLE,
        seed=seed,
        record_count=100,
        batch_size=4,
        steps_per_epoch=2,
        total_epochs=1,
    )
    schedule = replay_public_sampler(commitment, epoch=0)
    expected = derive_batch_schedule(
        seed=seed, record_count=100, batch_size=4, steps_per_epoch=2, epoch=0
    )
    assert schedule == expected


def test_sampler_private_index_hiding_omits_seed() -> None:
    commitment = make_sampler_commitment(
        mode=SamplerMode.PRIVATE_INDEX_HIDING,
        seed=None,
        record_count=100,
        batch_size=4,
        steps_per_epoch=2,
        total_epochs=1,
    )
    assert commitment.seed_hex is None
    # Verifier cannot replay.
    with pytest.raises(ValueError):
        replay_public_sampler(commitment, epoch=0)


def test_sampler_batch_size_exceeds_records_rejected() -> None:
    with pytest.raises(ValueError):
        derive_batch_schedule(
            seed=b"\x00" * 32,
            record_count=4,
            batch_size=8,  # > record_count
            steps_per_epoch=1,
            epoch=0,
        )


# =========================================================================== #
# Recursive aggregation (VFT element 4)                                       #
# =========================================================================== #


def _make_two_proofs():
    manifest = _manifest()
    commitment = issue_commitment(
        dataset_id="d1",
        dataset_records=(b"r1", b"r2", b"r3"),
        manifest=manifest,
        ca_keypair=deterministic_test_ca("t"),
        schema_canonical_json=b"{}",
    )
    p1 = generate_proof(
        response="r1",
        prompt="p",
        prompt_attributes={},
        model_commitment_hash="c" * 64,
        commitment=commitment,
        manifest=manifest,
        private_witness=b"w1",
    )
    p2 = generate_proof(
        response="r2",
        prompt="p",
        prompt_attributes={},
        model_commitment_hash="c" * 64,
        commitment=commitment,
        manifest=manifest,
        private_witness=b"w2",
    )
    return manifest, commitment, p1, p2


def test_aggregate_proofs_basic() -> None:
    _, _, p1, p2 = _make_two_proofs()
    cert = aggregate_proofs(
        (p1, p2),
        aggregation_id="a1",
        folding_scheme=FoldingScheme.HYPERNOVA_CYCLEFOLD,
        max_batch_size=10,
        window_start=datetime(2026, 1, 1, tzinfo=UTC),
        window_end=datetime(2026, 2, 1, tzinfo=UTC),
    )
    assert len(cert.manifest.leaves) == 2
    assert verify_aggregated_certificate(cert)


def test_aggregate_empty_rejected() -> None:
    with pytest.raises(ValueError):
        aggregate_proofs(
            (),
            aggregation_id="a1",
            folding_scheme=FoldingScheme.HYPERNOVA_CYCLEFOLD,
            max_batch_size=10,
            window_start=datetime.now(UTC),
            window_end=datetime.now(UTC),
        )


def test_aggregate_overflow_rejected() -> None:
    _, _, p1, p2 = _make_two_proofs()
    with pytest.raises(ValueError):
        aggregate_proofs(
            (p1, p2),
            aggregation_id="a1",
            folding_scheme=FoldingScheme.HYPERNOVA_CYCLEFOLD,
            max_batch_size=1,  # too small
            window_start=datetime(2026, 1, 1, tzinfo=UTC),
            window_end=datetime(2026, 2, 1, tzinfo=UTC),
        )


def test_aggregate_certificate_coverage_check() -> None:
    _, _, p1, p2 = _make_two_proofs()
    cert = aggregate_proofs(
        (p1, p2),
        aggregation_id="a1",
        folding_scheme=FoldingScheme.HYPERNOVA_CYCLEFOLD,
        max_batch_size=10,
        window_start=datetime(2026, 1, 1, tzinfo=UTC),
        window_end=datetime(2026, 2, 1, tzinfo=UTC),
    )
    expected = frozenset({p1.envelope_sha256(), p2.envelope_sha256()})
    assert verify_aggregated_certificate(cert, expected_leaf_envelope_hashes=expected)
    # Wrong expected set is rejected.
    wrong = frozenset({"deadbeef" * 8})
    assert not verify_aggregated_certificate(cert, expected_leaf_envelope_hashes=wrong)


def test_aggregate_regulator_grade_rejects_shim_leaves() -> None:
    _, _, p1, p2 = _make_two_proofs()  # shim backend
    cert = aggregate_proofs(
        (p1, p2),
        aggregation_id="a1",
        folding_scheme=FoldingScheme.HYPERNOVA_CYCLEFOLD,
        max_batch_size=10,
        window_start=datetime(2026, 1, 1, tzinfo=UTC),
        window_end=datetime(2026, 2, 1, tzinfo=UTC),
    )
    # All-shim leaves should be rejected at regulator grade.
    assert not verify_aggregated_certificate(cert, regulator_grade=True)


def test_is_post_quantum_folding() -> None:
    assert is_post_quantum_folding(FoldingScheme.LATTICEFOLD_PLUS_2026)
    assert not is_post_quantum_folding(FoldingScheme.HYPERNOVA_CYCLEFOLD)
    assert not is_post_quantum_folding(FoldingScheme.NONE)


# =========================================================================== #
# SCITT ARP (May 2026 draft)                                                  #
# =========================================================================== #


def test_arp_predicate_library_default_stable() -> None:
    lib1 = ARPPredicateLibrary.default()
    lib2 = ARPPredicateLibrary.default()
    assert lib1.pattern_library_hash == lib2.pattern_library_hash
    assert lib1.policy_version_hash == lib2.policy_version_hash


def test_arp_narrow_data_volume_bucket() -> None:
    m = _manifest(source_count=1, records_per_source=500)  # <10k
    claim = narrow_manifest_data_volume(m, ARPPredicateLibrary.default())
    assert claim.predicate is ARPPredicate.DATA_VOLUME_BUCKET
    assert claim.predicate_value == "<10k"


def test_arp_narrow_license_family() -> None:
    m = _manifest(source_count=3)  # alternating MIT / Apache
    claim = narrow_manifest_license_family(m, ARPPredicateLibrary.default())
    assert "Permissive" in claim.predicate_value


def test_arp_narrow_temporal_window() -> None:
    m = _manifest()
    cutoff = datetime(2024, 6, 1, tzinfo=UTC)  # before training window
    claim = narrow_manifest_temporal_window(
        m, ARPPredicateLibrary.default(), cutoff=cutoff
    )
    assert "after-cutoff" in claim.predicate_value


def test_arp_package_carries_required_cose_labels() -> None:
    m = _manifest()
    claim = narrow_manifest_data_volume(m, ARPPredicateLibrary.default())
    pkg = package_for_arp_exchange(claim, bilateral_agreement_hash="d" * 64)
    # The four IANA-requested labels must all be present.
    from tex.zkprov.scitt_arp import (
        ARP_BILATERAL_AGREEMENT_HASH,
        ARP_DIVERGENCE_AXIS,
        ARP_PATTERN_LIBRARY_HASH,
        ARP_POLICY_VERSION_HASH,
    )

    assert ARP_BILATERAL_AGREEMENT_HASH in pkg
    assert ARP_POLICY_VERSION_HASH in pkg
    assert ARP_PATTERN_LIBRARY_HASH in pkg
    assert ARP_DIVERGENCE_AXIS in pkg


def test_arp_reconciliation_consistency_check() -> None:
    m = _manifest()
    c = issue_commitment(
        dataset_id="d1",
        dataset_records=(b"r1",),
        manifest=m,
        ca_keypair=deterministic_test_ca("t"),
        schema_canonical_json=b"{}",
    )
    output = ARPReconciliationOutput(
        bilateral_agreement_hash="d" * 64,
        verdict=ARPReconciliationVerdict.AGREE,
        manifest_root_hash=m.manifest_root_hash(),
        divergence_axis=None,
        reconciliation_run_at=datetime.now(UTC),
    )
    assert consistent_with_commitment(output, c)
    # DIVERGE is rejected.
    output_diverge = ARPReconciliationOutput(
        bilateral_agreement_hash="d" * 64,
        verdict=ARPReconciliationVerdict.DIVERGE,
        manifest_root_hash=m.manifest_root_hash(),
        divergence_axis="record_count",
        reconciliation_run_at=datetime.now(UTC),
    )
    assert not consistent_with_commitment(output_diverge, c)


# =========================================================================== #
# NABAOS receipts (March 2026 paper)                                          #
# =========================================================================== #


def test_receipt_issue_and_verify_roundtrip() -> None:
    tc = ToolCallRecord(
        call_id="c1",
        tool_name="search",
        arguments_sha256="1" * 64,
        result_sha256="2" * 64,
        occurred_at=datetime.now(UTC),
    )
    claim = EpistemicClaim(
        claim_id="cl1",
        text_sha256="3" * 64,
        pramana=Pramana.PRATYAKSHA,
        backing_call_id="c1",
        cot_trace_sha256=None,
    )
    r = issue_receipt(
        receipt_id="r1",
        response="some answer",
        tool_calls=(tc,),
        claims=(claim,),
    )
    assert verify_receipt(r)


def test_receipt_tamper_detection() -> None:
    r = issue_receipt(
        receipt_id="r1",
        response="x",
        tool_calls=(),
        claims=(),
    )
    from dataclasses import replace

    bad = replace(r, tag_hex="0" * 64)
    assert not verify_receipt(bad)


def test_hallucination_detection_fabricated_tool() -> None:
    tc = ToolCallRecord(
        call_id="c1",
        tool_name="search",
        arguments_sha256="1" * 64,
        result_sha256="2" * 64,
        occurred_at=datetime.now(UTC),
    )
    # Claim references a nonexistent call.
    bad_claim = EpistemicClaim(
        claim_id="clX",
        text_sha256="3" * 64,
        pramana=Pramana.PRATYAKSHA,
        backing_call_id="not-a-real-call",
        cot_trace_sha256=None,
    )
    r = issue_receipt(
        receipt_id="r1", response="x", tool_calls=(tc,), claims=(bad_claim,)
    )
    findings = detect_hallucinations(r)
    assert len(findings) == 1
    assert findings[0].finding_kind == "fabricated_tool_reference"


def test_hallucination_detection_anumana_without_cot() -> None:
    bad_claim = EpistemicClaim(
        claim_id="clX",
        text_sha256="3" * 64,
        pramana=Pramana.ANUMANA,
        backing_call_id=None,
        cot_trace_sha256=None,  # missing!
    )
    r = issue_receipt(
        receipt_id="r1", response="x", tool_calls=(), claims=(bad_claim,)
    )
    findings = detect_hallucinations(r)
    assert any(f.finding_kind == "pramana_inconsistency" for f in findings)


def test_hallucination_detection_false_absence() -> None:
    bad_claim = EpistemicClaim(
        claim_id="cl1",
        text_sha256="3" * 64,
        pramana=Pramana.ABHAVA,
        backing_call_id=None,  # absence claim needs a paired empty-result call
        cot_trace_sha256=None,
    )
    r = issue_receipt(
        receipt_id="r1", response="x", tool_calls=(), claims=(bad_claim,)
    )
    findings = detect_hallucinations(r)
    assert any(f.finding_kind == "false_absence" for f in findings)


def test_hallucination_detection_clean_response() -> None:
    tc = ToolCallRecord(
        call_id="c1",
        tool_name="search",
        arguments_sha256="1" * 64,
        result_sha256="2" * 64,
        occurred_at=datetime.now(UTC),
    )
    good_claim = EpistemicClaim(
        claim_id="cl1",
        text_sha256="3" * 64,
        pramana=Pramana.PRATYAKSHA,
        backing_call_id="c1",
        cot_trace_sha256=None,
    )
    inference_claim = EpistemicClaim(
        claim_id="cl2",
        text_sha256="4" * 64,
        pramana=Pramana.ANUMANA,
        backing_call_id=None,
        cot_trace_sha256="5" * 64,
    )
    r = issue_receipt(
        receipt_id="r1",
        response="x",
        tool_calls=(tc,),
        claims=(good_claim, inference_claim),
    )
    findings = detect_hallucinations(r)
    assert len(findings) == 0

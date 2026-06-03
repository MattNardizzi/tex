"""
Tests for the May-2026 bleeding-edge SOTA augmentations.

Covers:
- EAT measured-components (draft-ietf-rats-eat-measured-component-12)
- CoRIM reference values (draft-ietf-rats-corim-10)
- COSE ML-DSA algorithm IDs (draft-ietf-cose-dilithium-11)
- JOSE/COSE PQ-composite labels (draft-ietf-jose-pq-composite-sigs-01)
- GpuTeePlatform extension (Vera Rubin NVL72, Jetson AGX Thor, RTX PRO 6000)
- DriverPinning (R590 TRD1)
- TdispEvidence (PCIe TDISP)
- MultiGpuBatch (ITA up-to-8 GPU)
- PersistentMemoryRegion (arxiv 2605.03213 §VI)
- TsmEventLog (Linux 6.7+ TSM ConfigFS)
- ScittReceipt (draft-ietf-scitt-architecture-22)
- TcbAdvisoryCheckResult + check_tcb_advisories
- LongHaulNonce three-nonce binding
- Sota2026Augmentation envelope and verify_sota_2026
"""

from __future__ import annotations

import hashlib
import os
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from tex.tee import (
    COSE_ALG_ML_DSA_44,
    COSE_ALG_ML_DSA_65,
    COSE_ALG_ML_DSA_87,
    CoRimReferenceValue,
    DriverPinning,
    GpuTeePlatform,
    JOSE_LABEL_COMPSIG_ML_DSA_65_ED25519_SHA512,
    JOSE_LABEL_COMPSIG_ML_DSA_87_ED448_SHAKE256,
    LongHaulNonce,
    MeasuredComponent,
    MultiGpuBatch,
    PersistentMemoryRegion,
    ScittReceipt,
    Sota2026Augmentation,
    Sota2026VerifyOutcome,
    TcbAdvisoryCheckResult,
    TdispEvidence,
    TsmEventLog,
    check_tcb_advisories,
    cose_alg_id_for,
    verify_sota_2026,
)


# ---------------------------------------------------------------------------
# 1. EAT measured-components (draft-ietf-rats-eat-measured-component-12)
# ---------------------------------------------------------------------------


class TestMeasuredComponent:
    def test_basic_construction(self):
        mc = MeasuredComponent(
            name="llama3-8b-instruct",
            version="1.0.0",
            digest_alg="sha-384",
            digest_b64="A" * 96,
        )
        assert mc.name == "llama3-8b-instruct"
        assert mc.digest_alg == "sha-384"
        assert mc.flags == 0
        assert mc.signers == ()

    def test_frozen(self):
        mc = MeasuredComponent(
            name="x", version="1", digest_alg="sha-256", digest_b64="A" * 64,
        )
        with pytest.raises(ValidationError):
            mc.name = "y"  # type: ignore[misc]

    def test_extra_forbidden(self):
        with pytest.raises(ValidationError):
            MeasuredComponent(
                name="x", version="1", digest_alg="sha-256",
                digest_b64="A" * 64,
                rogue_field="x",  # type: ignore[call-arg]
            )

    def test_signers_optional(self):
        mc = MeasuredComponent(
            name="model", version="1", digest_alg="sha-256",
            digest_b64="A" * 64,
            signers=("thumbprint-1", "thumbprint-2"),
        )
        assert len(mc.signers) == 2

    def test_flags_bitfield(self):
        # Tex profile: bit 0 = model, bit 16 = trusted_by_signers,
        # bit 17 = in_tee_memory, bit 18 = immutable_during_session
        flags = (1 << 0) | (1 << 16) | (1 << 17) | (1 << 18)
        mc = MeasuredComponent(
            name="model", version="1", digest_alg="sha-384",
            digest_b64="A" * 96, flags=flags,
        )
        assert mc.flags & 1 == 1  # model
        assert mc.flags & (1 << 17) != 0  # in_tee_memory


# ---------------------------------------------------------------------------
# 2. CoRIM reference values (draft-ietf-rats-corim-10)
# ---------------------------------------------------------------------------


class TestCoRimReferenceValue:
    def test_basic_triple(self):
        rv = CoRimReferenceValue(
            subject_class_id="urn:tex:env-class:tdx-runtime",
            predicate="tdx_mrtd",
            object_digest_alg="sha-384",
            object_digest_hex="a" * 96,
            authority="urn:tex:operator:vortexblack",
        )
        assert rv.predicate == "tdx_mrtd"
        assert rv.authority.startswith("urn:tex:operator:")

    def test_predicate_enum_strict(self):
        with pytest.raises(ValidationError):
            CoRimReferenceValue(
                subject_class_id="urn:tex:x",
                predicate="rogue_predicate",  # type: ignore[arg-type]
                object_digest_alg="sha-256",
                object_digest_hex="a" * 64,
                authority="x",
            )

    def test_all_supported_predicates(self):
        for p in (
            "tdx_mrtd", "tdx_rtmr0", "tdx_rtmr1", "tdx_rtmr2", "tdx_rtmr3",
            "gpu_measurement", "model_weights", "policy_bundle",
            "retrieval_index",
        ):
            rv = CoRimReferenceValue(
                subject_class_id="x",
                predicate=p,  # type: ignore[arg-type]
                object_digest_alg="sha-256",
                object_digest_hex="a" * 64,
                authority="x",
            )
            assert rv.predicate == p


# ---------------------------------------------------------------------------
# 3. COSE ML-DSA + JOSE composite labels (drafts 11 and 01)
# ---------------------------------------------------------------------------


class TestCoseAlgIds:
    def test_ml_dsa_assigned_numbers(self):
        # Per draft-ietf-cose-dilithium-11 §8.1.1
        assert COSE_ALG_ML_DSA_44 == -48
        assert COSE_ALG_ML_DSA_65 == -49
        assert COSE_ALG_ML_DSA_87 == -50

    def test_cose_alg_id_for_pq(self):
        assert cose_alg_id_for("ml-dsa-44") == -48
        assert cose_alg_id_for("ml-dsa-65") == -49
        assert cose_alg_id_for("ml-dsa-87") == -50
        assert cose_alg_id_for("ML-DSA-65") == -49  # case insensitive

    def test_cose_alg_id_for_classical(self):
        # Existing COSE registry numbers from RFC 9053
        assert cose_alg_id_for("ps384") == -37
        assert cose_alg_id_for("rs256") == -257
        assert cose_alg_id_for("es384") == -36
        assert cose_alg_id_for("es256") == -7
        assert cose_alg_id_for("ed25519") == -8

    def test_cose_alg_id_for_blake3_ml_dsa(self):
        # BLAKE3-ML-DSA-65 uses the same wire format as ML-DSA-65
        assert cose_alg_id_for("blake3-ml-dsa-65") == -49

    def test_cose_alg_id_for_unknown(self):
        assert cose_alg_id_for("rogue-algorithm") is None

    def test_jose_compsig_labels(self):
        # Per draft-ietf-jose-pq-composite-sigs-01 §6.1 Table 4
        # COMPSIG-MLDSA65-Ed25519-SHA512 bytes
        decoded_65 = JOSE_LABEL_COMPSIG_ML_DSA_65_ED25519_SHA512.decode("ascii")
        assert decoded_65 == "COMPSIG-MLDSA65-Ed25519-SHA512"
        # COMPSIG-MLDSA87-Ed448-SHAKE256 bytes
        decoded_87 = JOSE_LABEL_COMPSIG_ML_DSA_87_ED448_SHAKE256.decode("ascii")
        assert decoded_87 == "COMPSIG-MLDSA87-Ed448-SHAKE256"


# ---------------------------------------------------------------------------
# 4. GpuTeePlatform — extended hardware tags (May 2026)
# ---------------------------------------------------------------------------


class TestGpuTeePlatform:
    def test_vera_rubin_nvl72_present(self):
        # May 2026: world's first rack-scale CC platform
        assert GpuTeePlatform.VERA_RUBIN_NVL72.value == "nvidia-vera-rubin-nvl72-rack-cc"

    def test_jetson_agx_thor_with_tdisp(self):
        assert GpuTeePlatform.JETSON_AGX_THOR.value == "nvidia-jetson-agx-thor-cc-tdisp"

    def test_rtx_pro_6000_blackwell(self):
        # Per NVIDIA Trusted Computing Solutions R580 TRD1 release notes
        assert GpuTeePlatform.BLACKWELL_RTX_PRO_6000.value == "nvidia-rtx-pro-6000-blackwell-cc"

    def test_full_blackwell_lineup(self):
        names = {p.name for p in GpuTeePlatform}
        assert "BLACKWELL_B200" in names
        assert "BLACKWELL_B300" in names
        assert "BLACKWELL_GB200" in names
        assert "BLACKWELL_GB300" in names


# ---------------------------------------------------------------------------
# 5. DriverPinning — R590 TRD1
# ---------------------------------------------------------------------------


class TestDriverPinning:
    def test_basic_min_version(self):
        dp = DriverPinning(min_driver_version="590.48.01")
        assert dp.min_driver_version == "590.48.01"
        assert dp.pinned_driver_versions == ()
        assert dp.blocked_driver_versions == ()

    def test_allowlist(self):
        dp = DriverPinning(
            min_driver_version="590.48.01",
            pinned_driver_versions=("590.48.01", "590.49.02"),
        )
        assert len(dp.pinned_driver_versions) == 2

    def test_blocklist(self):
        # Block a known-buggy driver explicitly
        dp = DriverPinning(
            min_driver_version="590.48.01",
            blocked_driver_versions=("590.50.00",),
        )
        assert dp.blocked_driver_versions == ("590.50.00",)


# ---------------------------------------------------------------------------
# 6. TdispEvidence — PCIe TDISP
# ---------------------------------------------------------------------------


class TestTdispEvidence:
    def test_run_locked_state(self):
        te = TdispEvidence(
            device_interface_report_sha256="a" * 64,
            device_certificate_chain_sha256="b" * 64,
            interface_id="0000:81:00.0",
            lock_state="run-locked",
        )
        assert te.lock_state == "run-locked"

    def test_lock_state_strict(self):
        # Production must observe run-locked; other states accepted but flagged
        for state in ("unlocked", "config-locked", "run-locked", "error"):
            te = TdispEvidence(
                device_interface_report_sha256="a" * 64,
                device_certificate_chain_sha256="b" * 64,
                interface_id="x",
                lock_state=state,  # type: ignore[arg-type]
            )
            assert te.lock_state == state

    def test_rogue_lock_state_rejected(self):
        with pytest.raises(ValidationError):
            TdispEvidence(
                device_interface_report_sha256="a" * 64,
                device_certificate_chain_sha256="b" * 64,
                interface_id="x",
                lock_state="rogue",  # type: ignore[arg-type]
            )

    def test_dev_stub_flag(self):
        te = TdispEvidence(
            device_interface_report_sha256="a" * 64,
            device_certificate_chain_sha256="b" * 64,
            interface_id="x",
            lock_state="run-locked",
            is_dev_stub=True,
        )
        assert te.is_dev_stub is True


# ---------------------------------------------------------------------------
# 7. MultiGpuBatch — ITA up-to-8 GPU
# ---------------------------------------------------------------------------


class TestMultiGpuBatch:
    def test_8_gpu_batch(self):
        mb = MultiGpuBatch(
            gpu_count=8,
            gpu_measurement_sha256_list=tuple("a" * 64 for _ in range(8)),
            gpu_hwmodel_list=tuple("GH100" for _ in range(8)),
            all_measres_successful=True,
            all_secboot=True,
        )
        assert mb.gpu_count == 8
        assert mb.nvlink_topology == "nvlink"

    def test_gpu_count_capped_at_8(self):
        # ITA composite v2 supports up to 8 GPUs per request
        with pytest.raises(ValidationError):
            MultiGpuBatch(
                gpu_count=9,
                gpu_measurement_sha256_list=(),
                gpu_hwmodel_list=(),
                all_measres_successful=True,
                all_secboot=True,
            )

    def test_nvlink_topology_options(self):
        for topo in ("pcie-only", "nvlink", "nvlink-nvswitch", "nvlink-c2c"):
            mb = MultiGpuBatch(
                gpu_count=1,
                gpu_measurement_sha256_list=("a" * 64,),
                gpu_hwmodel_list=("GB200",),
                all_measres_successful=True,
                all_secboot=True,
                nvlink_topology=topo,  # type: ignore[arg-type]
            )
            assert mb.nvlink_topology == topo


# ---------------------------------------------------------------------------
# 8. PersistentMemoryRegion — arxiv 2605.03213 §VI
# ---------------------------------------------------------------------------


class TestPersistentMemoryRegion:
    def test_vector_store_region(self):
        pm = PersistentMemoryRegion(
            region_kind="vector_store",
            region_id="urn:tex:vector-store:main",
            size_bytes=2**30,
            digest_alg="sha3-256",
            digest_hex="a" * 64,
        )
        assert pm.region_kind == "vector_store"
        assert pm.in_tee_memory is False

    def test_all_region_kinds(self):
        for kind in (
            "vector_store", "fine_tuned_adapter", "kv_cache",
            "tool_state", "session_transcript", "long_term_memory",
        ):
            pm = PersistentMemoryRegion(
                region_kind=kind,  # type: ignore[arg-type]
                region_id="x", size_bytes=100,
                digest_hex="a" * 64,
            )
            assert pm.region_kind == kind

    def test_default_digest_alg_is_sha3_256(self):
        # SHA-3 is the bleeding-edge choice — quantum-resistant
        pm = PersistentMemoryRegion(
            region_kind="kv_cache", region_id="x", size_bytes=1,
            digest_hex="a" * 64,
        )
        assert pm.digest_alg == "sha3-256"

    def test_in_tee_memory_flag(self):
        pm = PersistentMemoryRegion(
            region_kind="kv_cache", region_id="x", size_bytes=1,
            digest_hex="a" * 64, in_tee_memory=True,
        )
        assert pm.in_tee_memory is True


# ---------------------------------------------------------------------------
# 9. TsmEventLog — Linux 6.7+ TSM ConfigFS
# ---------------------------------------------------------------------------


class TestTsmEventLog:
    def test_full_rtmr_set(self):
        tel = TsmEventLog(
            event_log_sha256="a" * 64,
            event_count=42,
            expected_rtmr0="0" * 96,
            expected_rtmr1="1" * 96,
            expected_rtmr2="2" * 96,
            expected_rtmr3="3" * 96,
        )
        assert tel.event_count == 42
        # RTMR values are 48 bytes = 96 hex chars
        assert len(tel.expected_rtmr0) == 96

    def test_rtmr_length_strict(self):
        # Must be exactly 96 hex chars (48 bytes)
        with pytest.raises(ValidationError):
            TsmEventLog(
                event_log_sha256="a" * 64,
                event_count=0,
                expected_rtmr0="0" * 32,  # too short
                expected_rtmr1="0" * 96,
                expected_rtmr2="0" * 96,
                expected_rtmr3="0" * 96,
            )


# ---------------------------------------------------------------------------
# 10. ScittReceipt — draft-ietf-scitt-architecture-22
# ---------------------------------------------------------------------------


class TestScittReceipt:
    def test_basic_receipt(self):
        sr = ScittReceipt(
            ts_iss="https://scitt.example.com",
            receipt_b64="dGV4dA==",
            leaf_index=12345,
            tree_size_at_registration=12346,
            registered_at_unix=1716000000.0,
            statement_sha256="a" * 64,
        )
        assert sr.leaf_index == 12345
        assert sr.tree_size_at_registration > sr.leaf_index


# ---------------------------------------------------------------------------
# 11. TCB advisory check
# ---------------------------------------------------------------------------


class TestTcbAdvisoryCheck:
    def test_no_blocklist_passes(self, monkeypatch):
        monkeypatch.delenv("TEX_TEE_BLOCKED_ADVISORY_IDS", raising=False)
        r = check_tcb_advisories(("INTEL-SA-00837", "INTEL-SA-01058"))
        assert r.ok is True
        assert r.matched_advisories == ()

    def test_blocklist_blocks_matching_advisory(self, monkeypatch):
        monkeypatch.setenv("TEX_TEE_BLOCKED_ADVISORY_IDS", "INTEL-SA-00837")
        r = check_tcb_advisories(("INTEL-SA-00837", "INTEL-SA-01058"))
        assert r.ok is False
        assert "INTEL-SA-00837" in r.matched_advisories

    def test_blocklist_misses_unmatched(self, monkeypatch):
        monkeypatch.setenv("TEX_TEE_BLOCKED_ADVISORY_IDS", "INTEL-SA-99999")
        r = check_tcb_advisories(("INTEL-SA-00837",))
        assert r.ok is True

    def test_explicit_override_beats_env(self, monkeypatch):
        monkeypatch.setenv("TEX_TEE_BLOCKED_ADVISORY_IDS", "x")
        r = check_tcb_advisories(
            ("INTEL-SA-00837",),
            blocked_overrides=("INTEL-SA-00837",),
        )
        assert r.ok is False
        assert r.matched_advisories == ("INTEL-SA-00837",)

    def test_empty_advisory_list_passes(self):
        r = check_tcb_advisories((), blocked_overrides=("INTEL-SA-00837",))
        assert r.ok is True


# ---------------------------------------------------------------------------
# 12. LongHaulNonce — three-nonce binding
# ---------------------------------------------------------------------------


class TestLongHaulNonce:
    def test_build_produces_four_nonces(self):
        lh = LongHaulNonce.build(
            decision_id="d-123",
            request_id="r-456",
            transcript_sha256="t" * 64,
            fleet_id="vortexblack-prod",
        )
        for n in (lh.decision_nonce, lh.transcript_nonce, lh.fleet_nonce, lh.composite_nonce):
            assert len(n) == 32
            assert all(c in "0123456789abcdef" for c in n)

    def test_deterministic_in_inputs(self):
        a = LongHaulNonce.build(
            decision_id="d", request_id="r",
            transcript_sha256="t" * 64, fleet_id="f",
        )
        b = LongHaulNonce.build(
            decision_id="d", request_id="r",
            transcript_sha256="t" * 64, fleet_id="f",
        )
        assert a.composite_nonce == b.composite_nonce
        assert a.transcript_nonce == b.transcript_nonce
        assert a.fleet_nonce == b.fleet_nonce

    def test_fleet_separation_changes_composite(self):
        # Two operators running the same decision get different nonces
        a = LongHaulNonce.build(
            decision_id="d", request_id="r",
            transcript_sha256="t" * 64, fleet_id="operator-a",
        )
        b = LongHaulNonce.build(
            decision_id="d", request_id="r",
            transcript_sha256="t" * 64, fleet_id="operator-b",
        )
        assert a.composite_nonce != b.composite_nonce
        assert a.fleet_nonce != b.fleet_nonce
        assert a.decision_nonce == b.decision_nonce  # unchanged

    def test_transcript_change_changes_composite(self):
        a = LongHaulNonce.build(
            decision_id="d", request_id="r",
            transcript_sha256="aaaa" * 16, fleet_id="f",
        )
        b = LongHaulNonce.build(
            decision_id="d", request_id="r",
            transcript_sha256="bbbb" * 16, fleet_id="f",
        )
        assert a.composite_nonce != b.composite_nonce
        assert a.transcript_nonce != b.transcript_nonce


# ---------------------------------------------------------------------------
# 13. Sota2026Augmentation envelope + verify_sota_2026
# ---------------------------------------------------------------------------


class TestSota2026Augmentation:
    def test_empty_augmentation_valid(self):
        aug = Sota2026Augmentation()
        assert aug.measured_components == ()
        assert aug.driver_pinning is None
        assert aug.scitt_receipt is None
        assert aug.longhaul_nonce_present is False

    def test_full_augmentation(self):
        aug = Sota2026Augmentation(
            measured_components=(
                MeasuredComponent(
                    name="model", version="1", digest_alg="sha-384",
                    digest_b64="A" * 96,
                ),
            ),
            corim_reference_values=(
                CoRimReferenceValue(
                    subject_class_id="urn:x", predicate="tdx_mrtd",
                    object_digest_alg="sha-384",
                    object_digest_hex="a" * 96, authority="x",
                ),
            ),
            gpu_platform=GpuTeePlatform.VERA_RUBIN_NVL72,
            driver_pinning=DriverPinning(min_driver_version="590.48.01"),
            tdisp_evidence=TdispEvidence(
                device_interface_report_sha256="a" * 64,
                device_certificate_chain_sha256="b" * 64,
                interface_id="x", lock_state="run-locked",
            ),
            persistent_memory_regions=(
                PersistentMemoryRegion(
                    region_kind="vector_store", region_id="x",
                    size_bytes=1, digest_hex="a" * 64,
                ),
            ),
            tcb_advisory_ids=("INTEL-SA-99999",),
            longhaul_nonce_present=True,
            cose_alg_id=COSE_ALG_ML_DSA_65,
        )
        assert aug.gpu_platform == GpuTeePlatform.VERA_RUBIN_NVL72
        assert aug.cose_alg_id == -49
        assert len(aug.measured_components) == 1
        assert len(aug.persistent_memory_regions) == 1

    def test_frozen(self):
        aug = Sota2026Augmentation()
        with pytest.raises(ValidationError):
            aug.cose_alg_id = -49  # type: ignore[misc]

    def test_extra_forbidden(self):
        with pytest.raises(ValidationError):
            Sota2026Augmentation(unknown_field=1)  # type: ignore[call-arg]


class TestVerifySota2026:
    def test_empty_passes(self, monkeypatch):
        monkeypatch.delenv("TEX_TEE_BLOCKED_ADVISORY_IDS", raising=False)
        outcome = verify_sota_2026(Sota2026Augmentation())
        assert outcome.ok is True
        assert outcome.reasons == ()

    def test_driver_pinning_blocks_unlisted(self):
        aug = Sota2026Augmentation(
            driver_pinning=DriverPinning(
                min_driver_version="590.48.01",
                pinned_driver_versions=("590.48.01",),
            ),
        )
        outcome = verify_sota_2026(aug, actual_driver_version="589.99.99")
        assert outcome.ok is False
        assert any("driver_below_min" in r for r in outcome.reasons)

    def test_driver_pinning_blocks_blocklisted(self):
        aug = Sota2026Augmentation(
            driver_pinning=DriverPinning(
                min_driver_version="590.00.00",
                blocked_driver_versions=("590.50.00",),
            ),
        )
        outcome = verify_sota_2026(aug, actual_driver_version="590.50.00")
        assert outcome.ok is False
        assert any("driver_blocked" in r for r in outcome.reasons)

    def test_driver_pinning_accepts_valid(self):
        aug = Sota2026Augmentation(
            driver_pinning=DriverPinning(
                min_driver_version="590.48.01",
                pinned_driver_versions=("590.48.01", "590.49.02"),
            ),
        )
        outcome = verify_sota_2026(aug, actual_driver_version="590.48.01")
        assert outcome.ok is True
        assert outcome.driver_pinning_satisfied is True

    def test_tdisp_run_locked_required(self):
        aug = Sota2026Augmentation(
            tdisp_evidence=TdispEvidence(
                device_interface_report_sha256="a" * 64,
                device_certificate_chain_sha256="b" * 64,
                interface_id="x", lock_state="config-locked",
            ),
        )
        outcome = verify_sota_2026(aug, require_tdisp_run_locked=True)
        assert outcome.ok is False
        assert any("tdisp_not_run_locked" in r for r in outcome.reasons)

    def test_tdisp_run_locked_ok(self):
        aug = Sota2026Augmentation(
            tdisp_evidence=TdispEvidence(
                device_interface_report_sha256="a" * 64,
                device_certificate_chain_sha256="b" * 64,
                interface_id="x", lock_state="run-locked",
            ),
        )
        outcome = verify_sota_2026(aug, require_tdisp_run_locked=True)
        assert outcome.ok is True
        assert outcome.tdisp_locked is True

    def test_advisory_blocklist_fails(self, monkeypatch):
        monkeypatch.setenv("TEX_TEE_BLOCKED_ADVISORY_IDS", "INTEL-SA-00837")
        aug = Sota2026Augmentation(
            tcb_advisory_ids=("INTEL-SA-00837", "INTEL-SA-99999"),
        )
        outcome = verify_sota_2026(aug)
        assert outcome.ok is False
        assert outcome.advisory_check_ok is False

    def test_advisory_blocklist_passes(self, monkeypatch):
        monkeypatch.setenv("TEX_TEE_BLOCKED_ADVISORY_IDS", "INTEL-SA-99999")
        aug = Sota2026Augmentation(
            tcb_advisory_ids=("INTEL-SA-00837",),
        )
        outcome = verify_sota_2026(aug)
        assert outcome.ok is True
        assert outcome.advisory_check_ok is True

    def test_scitt_required_but_missing(self, monkeypatch):
        monkeypatch.delenv("TEX_TEE_BLOCKED_ADVISORY_IDS", raising=False)
        outcome = verify_sota_2026(Sota2026Augmentation(), require_scitt=True)
        assert outcome.ok is False
        assert any("scitt_receipt_required" in r for r in outcome.reasons)

    def test_scitt_satisfied(self, monkeypatch):
        monkeypatch.delenv("TEX_TEE_BLOCKED_ADVISORY_IDS", raising=False)
        aug = Sota2026Augmentation(
            scitt_receipt=ScittReceipt(
                ts_iss="https://scitt.example.com",
                receipt_b64="dGVzdA==",
                leaf_index=1, tree_size_at_registration=2,
                registered_at_unix=1716000000.0,
                statement_sha256="a" * 64,
            ),
        )
        outcome = verify_sota_2026(aug, require_scitt=True)
        assert outcome.ok is True
        assert outcome.scitt_registered is True

    def test_tsm_event_log_consistent(self, monkeypatch):
        monkeypatch.delenv("TEX_TEE_BLOCKED_ADVISORY_IDS", raising=False)
        aug = Sota2026Augmentation(
            tsm_event_log=TsmEventLog(
                event_log_sha256="a" * 64, event_count=10,
                expected_rtmr0="0" * 96, expected_rtmr1="1" * 96,
                expected_rtmr2="2" * 96, expected_rtmr3="3" * 96,
            ),
        )
        outcome = verify_sota_2026(
            aug,
            actual_rtmr0_through_3=("0" * 96, "1" * 96, "2" * 96, "3" * 96),
        )
        assert outcome.ok is True
        assert outcome.tsm_event_log_consistent is True

    def test_tsm_event_log_mismatch(self, monkeypatch):
        monkeypatch.delenv("TEX_TEE_BLOCKED_ADVISORY_IDS", raising=False)
        aug = Sota2026Augmentation(
            tsm_event_log=TsmEventLog(
                event_log_sha256="a" * 64, event_count=10,
                expected_rtmr0="0" * 96, expected_rtmr1="1" * 96,
                expected_rtmr2="2" * 96, expected_rtmr3="3" * 96,
            ),
        )
        outcome = verify_sota_2026(
            aug,
            actual_rtmr0_through_3=("X" * 96, "1" * 96, "2" * 96, "3" * 96),
        )
        assert outcome.ok is False
        assert any("tsm_event_log_rtmr_mismatch" in r for r in outcome.reasons)

    def test_outcome_counters(self, monkeypatch):
        monkeypatch.delenv("TEX_TEE_BLOCKED_ADVISORY_IDS", raising=False)
        aug = Sota2026Augmentation(
            measured_components=tuple(
                MeasuredComponent(
                    name=f"c{i}", version="1", digest_alg="sha-256",
                    digest_b64="A" * 64,
                ) for i in range(3)
            ),
            corim_reference_values=tuple(
                CoRimReferenceValue(
                    subject_class_id="x", predicate="tdx_mrtd",
                    object_digest_alg="sha-256",
                    object_digest_hex="a" * 64, authority="x",
                ) for _ in range(2)
            ),
            persistent_memory_regions=(
                PersistentMemoryRegion(
                    region_kind="vector_store", region_id="x",
                    size_bytes=1, digest_hex="a" * 64,
                ),
            ),
        )
        outcome = verify_sota_2026(aug)
        assert outcome.measured_components_count == 3
        assert outcome.corim_match_count == 2
        assert outcome.persistent_memory_count == 1

"""
[Architecture: Layer 5 (Evidence)] — TEE attestation composition — Intel TDX + NVIDIA H100/H200/B200/B300 via Intel Trust Authority

See ARCHITECTURE.md for the full six-layer model.

TEE Attestation Layer (Thread 12)
=================================

Composite CPU+GPU hardware-rooted attestation for Tex evidence records.

Reference anchors as of May 18 2026
-----------------------------------
* Intel Trust Authority composite attestation (``tdx+nvgpu``).
* NVIDIA Blackwell Confidential Computing + NVLink encryption.
* draft-messous-eat-ai-01 — EAT profile for autonomous AI agents.
* draft-ietf-rats-ear-03 — AR4SI trustworthiness vector.
* arxiv 2605.03213 — compound attestation gap analysis.
* arxiv 2604.23280 — CrossGuard TEE instance binding.

"""

from __future__ import annotations

# Architectural layer marker (see ARCHITECTURE.md).
# Queryable as `from tex.tee import __layer__, __layer_kind__`.
__layer__: int | None = 5
__layer_kind__: str = 'evidence'


from tex.tee.attestation_client import (
    ExpectedMeasurements,
    ITA_PROD_ISSUER,
    build_test_mode_composite_jwt,
    compose_attestation,
    compose_from_evidence,
    decision_bound_nonce,
    verify_attestation,
)
from tex.tee.composite import (
    CompositeAttestationEnvelope,
    CompositeVerificationResult,
    CompoundAttestationLink,
    CpuTeeType,
    EatAiClaims,
    EatAiDigest,
    GpuTeeType,
    TrustworthinessVector,
)
from tex.tee.h100_attestation import (
    GpuEvidence,
    collect_gpu_evidence,
    is_gpu_cc_capable,
)
from tex.tee.tdx_attestation import (
    TdxEvidence,
    collect_tdx_evidence,
    fresh_user_data,
    is_tdx_capable,
)
from tex.tee.sota_2026 import (
    # EAT measured-components (draft-ietf-rats-eat-measured-component-12)
    MeasuredComponent,
    # CoRIM reference values (draft-ietf-rats-corim-10)
    CoRimReferenceValue,
    # COSE PQ algorithm IDs (draft-ietf-cose-dilithium-11, draft-ietf-jose-pq-composite-sigs-01)
    COSE_ALG_ML_DSA_44,
    COSE_ALG_ML_DSA_65,
    COSE_ALG_ML_DSA_87,
    JOSE_LABEL_COMPSIG_ML_DSA_65_ED25519_SHA512,
    JOSE_LABEL_COMPSIG_ML_DSA_87_ED448_SHAKE256,
    cose_alg_id_for,
    # Hardware platforms
    GpuTeePlatform,
    DriverPinning,
    TdispEvidence,
    MultiGpuBatch,
    # Persistent agent memory (arxiv 2605.03213 §VI open challenge)
    PersistentMemoryRegion,
    # Linux 6.7+ TSM event log binding
    TsmEventLog,
    # SCITT transparency (draft-ietf-scitt-architecture-22)
    ScittReceipt,
    # TCB advisory blocklist
    TcbAdvisoryCheckResult,
    check_tcb_advisories,
    # Long-haul nonce (transcript + fleet)
    LongHaulNonce,
    # Top-level augmentation
    Sota2026Augmentation,
    Sota2026VerifyOutcome,
    verify_sota_2026,
)


__all__ = [
    "compose_attestation",
    "compose_from_evidence",
    "verify_attestation",
    "decision_bound_nonce",
    "build_test_mode_composite_jwt",
    "ExpectedMeasurements",
    "ITA_PROD_ISSUER",
    "CompositeAttestationEnvelope",
    "CompositeVerificationResult",
    "CompoundAttestationLink",
    "CpuTeeType",
    "EatAiClaims",
    "EatAiDigest",
    "GpuTeeType",
    "TrustworthinessVector",
    "GpuEvidence",
    "TdxEvidence",
    "collect_gpu_evidence",
    "collect_tdx_evidence",
    "fresh_user_data",
    "is_gpu_cc_capable",
    "is_tdx_capable",
    # SOTA-2026 frontier augmentations
    "MeasuredComponent",
    "CoRimReferenceValue",
    "COSE_ALG_ML_DSA_44",
    "COSE_ALG_ML_DSA_65",
    "COSE_ALG_ML_DSA_87",
    "JOSE_LABEL_COMPSIG_ML_DSA_65_ED25519_SHA512",
    "JOSE_LABEL_COMPSIG_ML_DSA_87_ED448_SHAKE256",
    "cose_alg_id_for",
    "GpuTeePlatform",
    "DriverPinning",
    "TdispEvidence",
    "MultiGpuBatch",
    "PersistentMemoryRegion",
    "TsmEventLog",
    "ScittReceipt",
    "TcbAdvisoryCheckResult",
    "check_tcb_advisories",
    "LongHaulNonce",
    "Sota2026Augmentation",
    "Sota2026VerifyOutcome",
    "verify_sota_2026",
]

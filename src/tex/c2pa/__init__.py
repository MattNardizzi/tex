"""
C2PA Content Credentials Layer
==============================

Implements the Coalition for Content Provenance and Authenticity (C2PA)
specification for outbound AI-generated content. Every email, post, document,
or image produced by an AI-SDR running through Tex carries a tamper-evident,
cryptographically-signed manifest declaring origin, AI-generation status,
training-data class, and ingredient chain.

References
----------
- C2PA Specification 2.2 (2025-05-01) — current as of May 2026
- C2PA Conformance Program (launched mid-2025; Trust List frozen ITL
  superseded by official C2PA Trust List on 2026-01-01)
- CAWG 1.2 Extension (creator attribution)
- EU AI Act Article 50 (transparency for AI-generated content, enforces 2026-08-02)
- California SB 942 / AB 853 (operative 2026-08-02)
- New York AI Advertising Disclosure (June 2026)
- CISA Advisory: "Strengthening Multimedia Integrity in the Generative AI Era" (Jan 2025)

Threat model
------------
Closes the verification gap for AI-SDR outbound content. Without C2PA,
recipients cannot prove content came from a sanctioned AI system. With
C2PA + ML-DSA signing, Tex provides the evidence trail FTC investigators
and EU notified bodies require under Art. 50.

Priority
--------
P0 — ship in days 1-14. Together with `pqcrypto/`, this is the regulatory
forced-buyer wedge.
"""

from tex.c2pa.manifest import (
    ASSERTION_LABEL_ACTIONS_V2,
    ASSERTION_LABEL_CAWG_CREATIVE_WORK,
    ASSERTION_LABEL_TEX_EVIDENCE_COSIGN,
    ASSERTION_LABEL_TEX_VERDICT,
    DIGITAL_SOURCE_TYPE_TRAINED_ALGORITHMIC,
    TEX_EVIDENCE_COSIGN_SCHEMA_V1,
    TEX_VERDICT_SCHEMA_V1,
    C2paAssertion,
    C2paClaim,
    C2paIngredient,
    C2paManifest,
    attach_cosign_assertion,
    build_ai_generation_assertion,
    build_cawg_creative_work_assertion,
    build_email_manifest,
    build_tex_evidence_cosign_assertion,
    build_tex_verdict_assertion,
)
from tex.c2pa.signer import (
    clear_signing_keys,
    register_signing_key,
    set_keystore,
    sign_manifest,
)
from tex.c2pa.verifier import C2paVerificationResult, verify_manifest
from tex.c2pa.evidence_emission import (
    COSIGN_CANONICALIZATION_VERSION,
    COSIGN_CANONICALIZATION_VERSION_V1,
    CosignError,
    build_signed_manifest_with_cosign,
    cosign_manifest_hash,
    get_cosign_assertion,
    serialize_manifest_for_storage,
)
from tex.c2pa.cosign_verifier import (
    ALL_ATTACKS,
    ATTACK_CERT_EXPIRY_BEFORE_RETENTION,
    ATTACK_CROSS_VALIDATOR_CONTRADICTION,
    ATTACK_EXCLUSION_RANGE_TAMPER,
    ATTACK_REVOCATION_SKIPPED,
    ATTACK_TIMESTAMP_SWAP,
    CosignVerificationResult,
    full_file_sha256,
    verify_evidence_cosign,
)

# --- Thread 6 surface ----------------------------------------------------
from tex.c2pa.cosign_context_tree import (
    COSIGN_CANONICALIZATION_VERSION_V2,
    MerkleLeaf,
    build_cosign_v2_leaves,
    canonical_cosign_signing_input_v2,
    merkle_proof,
    merkle_root,
    verify_merkle_proof,
)
from tex.c2pa.watermark import (
    ASSERTION_LABEL_TEX_EVIDENCE_WATERMARK,
    TEX_EVIDENCE_WATERMARK_SCHEMA_V1,
    CrossLayerAuditResult,
    RecordedScoreDetector,
    SynthIDTextDetectorAdapter,
    SYNTHID_TEXT_DEFAULT_THRESHOLD,
    TEXTSEAL_DEFAULT_THRESHOLD,
    TextSealDetectorAdapter,
    WatermarkDetectionResult,
    WatermarkDetector,
    WatermarkScheme,
    build_tex_evidence_watermark_assertion,
    cross_layer_audit,
    text_perceptual_hash,
)
from tex.c2pa.attestation import (
    ASSERTION_LABEL_TEX_EVIDENCE_ATTESTATION,
    TEX_EVIDENCE_ATTESTATION_SCHEMA_V1,
    AttestationVerificationResult,
    AttestationVerifier,
    EatTokenKind,
    ParsedEatToken,
    build_tex_evidence_attestation_assertion,
    parse_eat_jwt,
    synthesize_test_eat_jwt,
    verify_attestation_assertion,
)
from tex.c2pa.cpsa_shapes import (
    ASSERTION_LABEL_TEX_FORMAL_VERIFICATION,
    TEX_FORMAL_VERIFICATION_SCHEMA_V1,
    CpsaShapesBundle,
    CpsaSkeleton,
    load_cpsa_shapes,
    model_provenance_assertion_data,
)

# --- May 2026 frontier upgrade ------------------------------------------
from tex.c2pa.ocsp import (
    OcspFailureCode,
    OcspNonce,
    OcspRequestBundle,
    OcspValidationResult,
    build_request_der as build_ocsp_request_der,
    parse_and_validate_response as parse_and_validate_ocsp_response,
    validate_staple,
)
from tex.c2pa.timestamp import (
    TimestampFailureCode,
    TimestampRequest,
    TimestampValidationResult,
    build_request_der as build_tsa_request_der,
    parse_and_validate_response as parse_and_validate_tsa_response,
    v2_payload_digest,
)
from tex.c2pa.sherman_2026_defenses import (
    ShermanAttackClass,
    ShermanDefense,
    ShermanDefensePosture,
    assess_current_posture as assess_sherman_2026_posture,
    render_buyer_dossier as render_sherman_buyer_dossier,
)
from tex.c2pa.durable_credentials import (
    DurableLayer,
    DurableMarkingResult,
    attach_durable_marks,
    trustmark_available,
)

__all__ = [
    # data model
    "C2paManifest",
    "C2paAssertion",
    "C2paClaim",
    "C2paIngredient",
    # builders
    "build_ai_generation_assertion",
    "build_cawg_creative_work_assertion",
    "build_email_manifest",
    "build_tex_verdict_assertion",
    "build_tex_evidence_cosign_assertion",
    "attach_cosign_assertion",
    # constants
    "ASSERTION_LABEL_ACTIONS_V2",
    "ASSERTION_LABEL_CAWG_CREATIVE_WORK",
    "ASSERTION_LABEL_TEX_VERDICT",
    "ASSERTION_LABEL_TEX_EVIDENCE_COSIGN",
    "DIGITAL_SOURCE_TYPE_TRAINED_ALGORITHMIC",
    "TEX_VERDICT_SCHEMA_V1",
    "TEX_EVIDENCE_COSIGN_SCHEMA_V1",
    "COSIGN_CANONICALIZATION_VERSION",
    # signer / keystore
    "sign_manifest",
    "register_signing_key",
    "clear_signing_keys",
    "set_keystore",
    # outer C2PA verifier
    "verify_manifest",
    "C2paVerificationResult",
    # Thread 5 — evidence emission with PQ cosign
    "build_signed_manifest_with_cosign",
    "cosign_manifest_hash",
    "serialize_manifest_for_storage",
    "get_cosign_assertion",
    "CosignError",
    # Thread 5 — cosign verifier with six-attack-defense surface
    "verify_evidence_cosign",
    "CosignVerificationResult",
    "full_file_sha256",
    "ALL_ATTACKS",
    "ATTACK_TIMESTAMP_SWAP",
    "ATTACK_REVOCATION_SKIPPED",
    "ATTACK_CROSS_VALIDATOR_CONTRADICTION",
    "ATTACK_EXCLUSION_RANGE_TAMPER",
    "ATTACK_CERT_EXPIRY_BEFORE_RETENTION",
    # Thread 6 — Merkle context tree (CPSA-checked)
    "COSIGN_CANONICALIZATION_VERSION_V1",
    "COSIGN_CANONICALIZATION_VERSION_V2",
    "MerkleLeaf",
    "build_cosign_v2_leaves",
    "canonical_cosign_signing_input_v2",
    "merkle_proof",
    "merkle_root",
    "verify_merkle_proof",
    # Thread 6 — durable content credentials (watermark)
    "ASSERTION_LABEL_TEX_EVIDENCE_WATERMARK",
    "TEX_EVIDENCE_WATERMARK_SCHEMA_V1",
    "SYNTHID_TEXT_DEFAULT_THRESHOLD",
    "TEXTSEAL_DEFAULT_THRESHOLD",
    "WatermarkScheme",
    "WatermarkDetector",
    "WatermarkDetectionResult",
    "RecordedScoreDetector",
    "SynthIDTextDetectorAdapter",
    "TextSealDetectorAdapter",
    "build_tex_evidence_watermark_assertion",
    "text_perceptual_hash",
    "CrossLayerAuditResult",
    "cross_layer_audit",
    # Thread 6 — hardware attestation (EAT JWT)
    "ASSERTION_LABEL_TEX_EVIDENCE_ATTESTATION",
    "TEX_EVIDENCE_ATTESTATION_SCHEMA_V1",
    "AttestationVerifier",
    "EatTokenKind",
    "ParsedEatToken",
    "AttestationVerificationResult",
    "parse_eat_jwt",
    "build_tex_evidence_attestation_assertion",
    "verify_attestation_assertion",
    "synthesize_test_eat_jwt",
    # Thread 6 — CPSA formal verification
    "ASSERTION_LABEL_TEX_FORMAL_VERIFICATION",
    "TEX_FORMAL_VERIFICATION_SCHEMA_V1",
    "CpsaShapesBundle",
    "CpsaSkeleton",
    "load_cpsa_shapes",
    "model_provenance_assertion_data",
    # May 2026 frontier — OCSP stapling (RFC 6960 + C2PA 2.4 §15.9)
    "OcspFailureCode",
    "OcspNonce",
    "OcspRequestBundle",
    "OcspValidationResult",
    "build_ocsp_request_der",
    "parse_and_validate_ocsp_response",
    "validate_staple",
    # May 2026 frontier — TSA v2 timestamps (RFC 3161 + C2PA 2.4 §10.3.2.5)
    "TimestampFailureCode",
    "TimestampRequest",
    "TimestampValidationResult",
    "build_tsa_request_der",
    "parse_and_validate_tsa_response",
    "v2_payload_digest",
    # May 2026 frontier — Sherman 2026 defense matrix (arxiv 2604.24890)
    "ShermanAttackClass",
    "ShermanDefense",
    "ShermanDefensePosture",
    "assess_sherman_2026_posture",
    "render_sherman_buyer_dossier",
    # May 2026 frontier — durable content credentials (TrustMark)
    "DurableLayer",
    "DurableMarkingResult",
    "attach_durable_marks",
    "trustmark_available",
]

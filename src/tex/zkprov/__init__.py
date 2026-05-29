"""
[Architecture: Layer 5 (Evidence)] — zero-knowledge dataset and inference provenance proofs

See ARCHITECTURE.md for the full six-layer model.

ZKPROV: Zero-Knowledge Dataset Provenance + VFT extensions
===========================================================

Cryptographically binds an LLM response to its authorized training
manifest without revealing the manifest contents or the model
parameters. Sub-2-second verification for the regulator-grade
backends listed below.

What this thread ships (Thread 14, May 2026 frontier)
-----------------------------------------------------
1. **ZKPROV core** (arxiv 2506.20915) — DatasetCommitment over
   records, ML-DSA-65 CA signature via algorithm_agility, Halo2-IPA
   default backend (no trusted setup).
2. **VFT extensions** (arxiv 2510.16830 v3, Dec 29 2025) — Merkle
   manifest binding sources / preprocessing / licenses / per-epoch
   quotas; verifiable index-hiding sampler; recursive aggregation
   with millisecond verification.
3. **LatticeFold+ ℓ2 path** (eprint 2026/721, Apr 19 2026) —
   post-quantum recursive aggregation surface. Backend slot
   reserved; declaration is in the manifest today.
4. **DeepProve backend slot** (Lagrange Labs, public Feb 23 2026)
   — 158x faster prover than ezkl; production-deployed at Anduril
   / Lockheed / Oracle Cloud sovereign. Subprocess shim integration.
5. **JOLT + Twist & Shout** (a16z, Feb 2026) — sum-check + lookup
   singularity, ~3x prover speedup. Backend slot reserved.
6. **SCITT ARP** (draft-hillier-scitt-arp-00, May 1 2026) —
   cross-sovereign attestation reconciliation. COSE labels
   0x801-0x804 wired here; narrowed-claim projection live.
7. **NABAOS** (arxiv 2603.10060, Mar 9 2026) — sub-15ms HMAC
   epistemic receipts that complement the slow-path ZK proof for
   interactive verification.
8. **EU AI Act Article 53(1)(d)** — TDS Template (24 Jul 2025)
   field binding so the manifest projects directly onto the public
   summary required at the August 2 2026 enforcement date.

Why this is the wedge
---------------------
Microsoft Agent Governance Toolkit (Apr 2 2026), Noma, Zenity,
Pillar, Lakera — none of them ship training-data provenance proofs.
No incumbent has wired DeepProve, LatticeFold+, ARP, or NABAOS in
the agent-governance market as of May 18 2026.

"""

# Architectural layer marker (see ARCHITECTURE.md).
# Queryable as `from tex.zkprov import __layer__, __layer_kind__`.
__layer__: int | None = 5
__layer_kind__: str = 'evidence'

from tex.zkprov.commitment import (
    DatasetCommitment,
    MerkleInclusionProof,
    build_inclusion_proof,
    build_merkle_root,
    deterministic_test_ca,
    issue_commitment,
    issue_commitment_tag,
    merkle_hash_algorithm_in_use,
    verify_commitment_signature,
    verify_commitment_tag,
    verify_commitment_valid,
)
from tex.zkprov.backends import (
    BackendUnavailable,
    DeepProveBackend,
    DeterministicShimBackend,
    Halo2IpaBackend,
    LatticeFoldPlusBackend,
    ProofBackend,
    ProofBackendId,
    ProvenanceStatement,
    SP1HypercubeBackend,
    VeilHashBasedZkBackend,
    get_proof_backend,
    is_regulator_grade,
    resolve_backend_with_fallback,
)
from tex.zkprov.manifest import (
    DataSource,
    DatasetManifest,
    LicenseTag,
    PreprocessingStep,
    TDSPublicSummary,
    TDSSourceCategory,
    project_to_tds_summary,
)
from tex.zkprov.proof import (
    CIRCUIT_VERSION,
    ProofVerification,
    ProvenanceProof,
    assemble_statement,
    generate_proof,
    verify_proof,
)
from tex.zkprov.receipts import (
    EpistemicClaim,
    EpistemicReceipt,
    HallucinationFinding,
    Pramana,
    ToolCallRecord,
    detect_hallucinations,
    issue_receipt,
    verify_receipt,
)
from tex.zkprov.recursive import (
    AggregatedCertificate,
    AggregationLeaf,
    AggregationManifest,
    FoldingScheme,
    aggregate_proofs,
    is_post_quantum_folding,
    verify_aggregated_certificate,
)
from tex.zkprov.sampler import (
    BatchSchedule,
    SamplerCommitment,
    SamplerMode,
    commit_schedule,
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
    NarrowedClaim,
    consistent_with_commitment,
    narrow_manifest_data_volume,
    narrow_manifest_license_family,
    narrow_manifest_temporal_window,
    package_for_arp_exchange,
)


__all__ = [
    # Core ZKPROV
    "DatasetCommitment",
    "MerkleInclusionProof",
    "build_inclusion_proof",
    "build_merkle_root",
    "deterministic_test_ca",
    "issue_commitment",
    "issue_commitment_tag",
    "merkle_hash_algorithm_in_use",
    "verify_commitment_signature",
    "verify_commitment_tag",
    "verify_commitment_valid",
    # Proof
    "CIRCUIT_VERSION",
    "ProofVerification",
    "ProvenanceProof",
    "assemble_statement",
    "generate_proof",
    "verify_proof",
    # Backends
    "BackendUnavailable",
    "DeepProveBackend",
    "DeterministicShimBackend",
    "Halo2IpaBackend",
    "LatticeFoldPlusBackend",
    "ProofBackend",
    "ProofBackendId",
    "ProvenanceStatement",
    "SP1HypercubeBackend",
    "VeilHashBasedZkBackend",
    "get_proof_backend",
    "is_regulator_grade",
    "resolve_backend_with_fallback",
    # Manifest
    "DataSource",
    "DatasetManifest",
    "LicenseTag",
    "PreprocessingStep",
    "TDSPublicSummary",
    "TDSSourceCategory",
    "project_to_tds_summary",
    # Sampler
    "BatchSchedule",
    "SamplerCommitment",
    "SamplerMode",
    "commit_schedule",
    "commit_seed",
    "derive_batch_schedule",
    "make_sampler_commitment",
    "replay_public_sampler",
    # Recursive aggregation
    "AggregatedCertificate",
    "AggregationLeaf",
    "AggregationManifest",
    "FoldingScheme",
    "aggregate_proofs",
    "is_post_quantum_folding",
    "verify_aggregated_certificate",
    # SCITT ARP
    "ARPPredicate",
    "ARPPredicateLibrary",
    "ARPReconciliationOutput",
    "ARPReconciliationVerdict",
    "NarrowedClaim",
    "consistent_with_commitment",
    "narrow_manifest_data_volume",
    "narrow_manifest_license_family",
    "narrow_manifest_temporal_window",
    "package_for_arp_exchange",
    # NABAOS receipts
    "EpistemicClaim",
    "EpistemicReceipt",
    "HallucinationFinding",
    "Pramana",
    "ToolCallRecord",
    "detect_hallucinations",
    "issue_receipt",
    "verify_receipt",
]

"""Inter-org governance interchange (Wave 2 / L6) — GIX.

Claim ceiling, verbatim: in-tree implementation of C2SP tlog-witness cosigning
semantics, exercised against self-hosted witness instances — protocol logic,
NOT organizational independence. ``federated`` is structurally False this wave
(``gix_witness.FEDERATED_FALSE_REASON``); the ``TEX_GIX_WITNESS`` env flag
gates wiring only and is never read by verification.

Three proofs, never conflated: the ledger hash chain proves INTEGRITY, a
ledger ECDSA signature proves AUTHORSHIP of one record, a witness-cosigned
checkpoint proves NON-EQUIVOCATION. See each module's banner before citing
anything here. Maturity: ``research-early``.
"""

from tex.interchange.gix import (
    Checkpoint,
    CheckpointPublisher,
    Ed25519NoteSigner,
    Ed25519NoteVerifier,
    SignedCheckpoint,
    build_add_checkpoint_body,
    build_checkpoint_publisher,
    consistency_path,
    get_active_checkpoint_publisher,
    inclusion_path,
    split_signed_note,
    verify_consistency,
    verify_inclusion,
    verify_note,
)
from tex.interchange.gix_merge import (
    FederatedMeanMerge,
    GixMergeRefused,
    OrgEvidenceSubmission,
    SubmissionVerification,
    merge_federated_evidence,
    verify_org_evidence,
)
from tex.interchange.gix_witness import (
    FEDERATED_FALSE_REASON,
    CheckpointVerification,
    CosignedCheckpoint,
    Witness,
    WitnessDescriptor,
    WitnessOutcome,
    WitnessProvenance,
    WitnessResponse,
    gather_cosignatures,
    verify_cosignature_line,
    verify_cosigned_checkpoint,
)

__all__ = [
    "FEDERATED_FALSE_REASON",
    "Checkpoint",
    "CheckpointPublisher",
    "CheckpointVerification",
    "CosignedCheckpoint",
    "Ed25519NoteSigner",
    "Ed25519NoteVerifier",
    "FederatedMeanMerge",
    "GixMergeRefused",
    "OrgEvidenceSubmission",
    "SignedCheckpoint",
    "SubmissionVerification",
    "Witness",
    "WitnessDescriptor",
    "WitnessOutcome",
    "WitnessProvenance",
    "WitnessResponse",
    "build_add_checkpoint_body",
    "build_checkpoint_publisher",
    "consistency_path",
    "gather_cosignatures",
    "get_active_checkpoint_publisher",
    "inclusion_path",
    "merge_federated_evidence",
    "split_signed_note",
    "verify_consistency",
    "verify_cosignature_line",
    "verify_cosigned_checkpoint",
    "verify_inclusion",
    "verify_note",
    "verify_org_evidence",
]

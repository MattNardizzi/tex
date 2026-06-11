"""
gix_merge (Wave 2 / L6) — authenticated federated mean-merge of cross-org
e-values.

"Authenticated" is earned, not decorative. An org's e-value enters the mean
ONLY after all three proofs pass — and they are three DIFFERENT proofs, never
conflated:

1. **Non-equivocation** — the org's checkpoint verifies under
   :func:`~tex.interchange.gix_witness.verify_cosigned_checkpoint`
   (pinned log key + ≥quorum pinned witness cosignatures);
2. **Integrity + authorship** — the submitted
   :class:`~tex.provenance.models.SealedFactRecord` re-derives byte-for-byte
   (``payload_sha256`` → ``record_hash``, the exact ledger math) and its
   ECDSA-P256 signature verifies against the org's PINNED ledger key;
3. **Inclusion** — an RFC 9162 inclusion proof places that ``record_hash``
   under the cosigned checkpoint root: the verdict is IN the witnessed log,
   not merely signed by someone.

Mean, not product
-----------------
The arithmetic mean of arbitrarily dependent e-values is an e-value, and
weighted arithmetic averaging is the only admissible merging under arbitrary
dependence (Vovk & Wang, "E-values: Calibration, combination, and
applications", Ann. Statist. 2021; generalized in arXiv:2409.19888 — both
retrieved 2026-06-11). Cross-org governance evidence shares upstream signals
(same foundation models, same attack waves), so independence is indefensible
and a product merge is refused by construction — there is no product code
path in this module.

Disjointness guard — what it does and does NOT do
-------------------------------------------------
The guard rejects: duplicate origins, overlapping declared stream ids,
duplicate ``CombinedEvidence`` combination ids, and overlapping component
evidence ids across orgs. That prevents the same evidence stream being
COUNTED twice (accidental double-counting, which would bias the mean's
denominator). It is NOT a Sybil defense: a dishonest org can rename streams.
Statistical validity under dependence comes from the mean itself; the guard
adds bookkeeping honesty, not an independence guarantee.

The merged scalar's ``federated`` field propagates from checkpoint
verification and is structurally False this wave (see ``gix_witness``).
Merged maturity is the weakest input maturity, capped at ``research_early`` —
the interchange path itself is research-early, so a merge can never out-rank
its transport.

Maturity: ``research-early``.
"""

from __future__ import annotations

import base64
import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from tex.domain.evidence import CombinedEvidence, EvidenceMaturity
from tex.events._ecdsa_provider import default_signature_provider
from tex.interchange.gix import Ed25519NoteVerifier, verify_inclusion
from tex.interchange.gix_witness import (
    CheckpointVerification,
    CosignedCheckpoint,
    FEDERATED_FALSE_REASON,
    WitnessDescriptor,
    verify_cosigned_checkpoint,
)

# Byte-identity with the ledger's record-hash math is load-bearing for
# re-derivation: a local mirror could drift silently, so the ledger's own
# helpers are imported even though they are module-private. If ledger.py
# renames them this import fails loudly at import time — the correct failure.
from tex.provenance.ledger import _sha256_hex, _stable_json
from tex.provenance.models import SealedFactRecord

__all__ = [
    "FederatedMeanMerge",
    "GixMergeRefused",
    "OrgEvidenceSubmission",
    "SubmissionVerification",
    "merge_federated_evidence",
    "verify_org_evidence",
]

# Weakest-link ranking, mirroring domain/evidence.py's private _MATURITY_RANK
# (semantic constant, not hash math — a mirror is acceptable here and avoids
# a second private import).
_MATURITY_RANK: dict[EvidenceMaturity, int] = {
    EvidenceMaturity.SPECULATIVE: 0,
    EvidenceMaturity.RESEARCH_EARLY: 1,
    EvidenceMaturity.RESEARCH_SOLID: 2,
    EvidenceMaturity.PRODUCTION: 3,
}


class GixMergeRefused(ValueError):
    """A federated merge was refused. ``reason_code`` is stable and testable;
    the message carries the specifics."""

    def __init__(self, reason_code: str, message: str) -> None:
        super().__init__(f"{reason_code}: {message}")
        self.reason_code = reason_code


@dataclass(frozen=True)
class OrgEvidenceSubmission:
    """One org's evidence offer: a sealed-fact record carrying a
    ``CombinedEvidence``, plus everything org B needs to verify it without
    trusting org A's log operator."""

    origin: str
    record: SealedFactRecord
    leaf_index: int
    inclusion_proof: tuple[str, ...]
    cosigned_checkpoint: CosignedCheckpoint
    # The org's PINNED ledger public key (PEM) — authorship verification.
    # Pinning is the relying party's job; an unpinned key proves nothing.
    ledger_public_key_pem: bytes
    # The evidence streams this submission claims to draw on, for the
    # cross-org disjointness guard. Declared by the submitting org (see the
    # module banner for what that does and does not guarantee).
    declared_stream_ids: tuple[str, ...]


@dataclass(frozen=True)
class SubmissionVerification:
    """The verdict on one submission, with the failing check named."""

    origin: str
    ok: bool
    reason: str
    checkpoint_verification: CheckpointVerification | None = None


def verify_org_evidence(
    submission: OrgEvidenceSubmission,
    *,
    log_verifier: Ed25519NoteVerifier,
    roster: Sequence[WitnessDescriptor],
    quorum: int = 3,
    signature_provider=None,
) -> SubmissionVerification:
    """Run the three proofs (non-equivocation, integrity+authorship,
    inclusion) over one submission. Fail-closed: the first failing check
    names itself and stops."""
    provider = signature_provider or default_signature_provider()

    # (1) Non-equivocation: the checkpoint must be witness-cosigned.
    cp_ver = verify_cosigned_checkpoint(
        submission.cosigned_checkpoint,
        log_verifier=log_verifier,
        roster=roster,
        quorum=quorum,
    )
    if not (cp_ver.log_signature_valid and cp_ver.quorum_met):
        return SubmissionVerification(
            submission.origin,
            ok=False,
            reason=f"checkpoint_not_witnessed: {cp_ver.reason}",
            checkpoint_verification=cp_ver,
        )
    checkpoint = cp_ver.checkpoint
    assert checkpoint is not None  # quorum_met implies a parsed checkpoint
    if checkpoint.origin != submission.origin:
        return SubmissionVerification(
            submission.origin,
            ok=False,
            reason=(
                f"origin_mismatch: checkpoint origin {checkpoint.origin!r} "
                f"!= submission origin {submission.origin!r}"
            ),
            checkpoint_verification=cp_ver,
        )

    # (2a) Integrity: re-derive the record hash from the fact's own canonical
    # payload with the EXACT ledger math (imported, not mirrored).
    record = submission.record
    payload_sha256 = _sha256_hex(_stable_json(record.fact.canonical_payload()))
    record_hash = _sha256_hex(
        _stable_json(
            {
                "payload_sha256": payload_sha256,
                "previous_hash": record.previous_hash,
            }
        )
    )
    if (
        payload_sha256 != record.payload_sha256
        or record_hash != record.record_hash
    ):
        return SubmissionVerification(
            submission.origin,
            ok=False,
            reason="record_integrity: record hash does not re-derive from the "
            "fact payload",
            checkpoint_verification=cp_ver,
        )

    # (2b) Authorship: the org's pinned ledger key signed this record hash.
    try:
        signature = base64.b64decode(record.signature_b64.encode("ascii"))
    except Exception:  # noqa: BLE001
        return SubmissionVerification(
            submission.origin,
            ok=False,
            reason="record_authorship: signature is not valid base64",
            checkpoint_verification=cp_ver,
        )
    if not provider.verify(
        record.record_hash.encode("ascii"),
        signature,
        submission.ledger_public_key_pem,
    ):
        return SubmissionVerification(
            submission.origin,
            ok=False,
            reason="record_authorship: signature does not verify against the "
            "pinned ledger key",
            checkpoint_verification=cp_ver,
        )

    # (3) Inclusion: the record is IN the witnessed log.
    if not verify_inclusion(
        record.record_hash,
        submission.leaf_index,
        checkpoint.tree_size,
        submission.inclusion_proof,
        checkpoint.root_hash_hex,
    ):
        return SubmissionVerification(
            submission.origin,
            ok=False,
            reason="inclusion: record_hash is not proven under the cosigned "
            "checkpoint root",
            checkpoint_verification=cp_ver,
        )

    # E-value honesty: only a true e-value may enter a mean.
    evidence = record.fact.evidence
    if evidence is None:
        return SubmissionVerification(
            submission.origin,
            ok=False,
            reason="not_a_true_e_value: the sealed fact carries no evidence",
            checkpoint_verification=cp_ver,
        )
    if not isinstance(evidence, CombinedEvidence) or not evidence.is_true_e_value:
        return SubmissionVerification(
            submission.origin,
            ok=False,
            reason="not_a_true_e_value: heuristic scores and abstain results "
            "are refused; calibrate to an e-value or stay out of the mean",
            checkpoint_verification=cp_ver,
        )

    return SubmissionVerification(
        submission.origin, ok=True, reason="ok", checkpoint_verification=cp_ver
    )


@dataclass(frozen=True)
class FederatedMeanMerge:
    """The merged cross-org scalar and exactly what it guarantees.

    ``is_true_e_value`` is True by construction (inputs were verified true
    e-values; the arithmetic mean of e-values is an e-value under arbitrary
    dependence). ``anytime_valid`` survives only when every input was
    anytime-valid on ONE shared filtration (cross-filtration combination
    needs an adjuster — Choe–Ramdas — and is refused the stronger label).
    """

    log_e_value: float
    is_true_e_value: bool
    anytime_valid: bool
    joint_null_hypothesis_id: str
    filtration_id: str
    maturity: EvidenceMaturity
    origins: tuple[str, ...]
    n_orgs: int
    federated: bool
    federated_reason: str

    @property
    def e_value(self) -> float:
        return math.exp(self.log_e_value)


def _log_mean_exp(log_values: Sequence[float]) -> float:
    """Stable log of the arithmetic mean of exponentials. Mirrors
    ``domain/evidence._log_mean_exp`` (kept local per that module's own
    precedent for private helpers; pinned against it in tests)."""
    if not log_values:
        raise ValueError("log_values must be non-empty")
    m = max(log_values)
    s = sum(math.exp(lv - m) for lv in log_values)
    return m + math.log(s) - math.log(float(len(log_values)))


def merge_federated_evidence(
    submissions: Sequence[OrgEvidenceSubmission],
    *,
    log_verifiers: Mapping[str, Ed25519NoteVerifier],
    roster: Sequence[WitnessDescriptor],
    quorum: int = 3,
    signature_provider=None,
) -> FederatedMeanMerge:
    """Authenticated mean-merge across orgs. Raises :class:`GixMergeRefused`
    (with a stable ``reason_code``) on ANY violation — a partial merge that
    silently drops a failing org would misstate the denominator.

    ``log_verifiers`` maps origin → that org's pinned log key. ``roster`` is
    the relying party's pinned witness set, shared across origins.
    """
    if len(submissions) < 2:
        raise GixMergeRefused(
            "too_few_orgs",
            "a federated merge needs at least two distinct orgs; a single "
            "org's evidence is just that org's evidence",
        )

    origins = [s.origin for s in submissions]
    if len(set(origins)) != len(origins):
        raise GixMergeRefused(
            "duplicate_origin",
            f"each org may submit exactly once per merge; got {sorted(origins)}",
        )

    # Per-org verification (all three proofs + e-value honesty).
    verifications: list[SubmissionVerification] = []
    for submission in submissions:
        log_verifier = log_verifiers.get(submission.origin)
        if log_verifier is None:
            raise GixMergeRefused(
                "unpinned_log_key",
                f"no pinned log key for origin {submission.origin!r}",
            )
        result = verify_org_evidence(
            submission,
            log_verifier=log_verifier,
            roster=roster,
            quorum=quorum,
            signature_provider=signature_provider,
        )
        if not result.ok:
            raise GixMergeRefused(
                "submission_rejected",
                f"origin {submission.origin!r}: {result.reason}",
            )
        verifications.append(result)

    # Disjointness guard (see module banner for its honest limits).
    seen_streams: dict[str, str] = {}
    for submission in submissions:
        for stream_id in submission.declared_stream_ids:
            if stream_id in seen_streams:
                raise GixMergeRefused(
                    "stream_double_counted",
                    f"stream {stream_id!r} is declared by both "
                    f"{seen_streams[stream_id]!r} and {submission.origin!r}",
                )
            seen_streams[stream_id] = submission.origin

    evidences: list[CombinedEvidence] = [
        s.record.fact.evidence  # type: ignore[misc]  # verified non-None above
        for s in submissions
    ]
    combo_ids = [e.combination_id for e in evidences]
    if len(set(combo_ids)) != len(combo_ids):
        raise GixMergeRefused(
            "duplicate_evidence",
            "the same CombinedEvidence appears in more than one submission",
        )
    seen_components: dict[str, str] = {}
    for submission, evidence in zip(submissions, evidences):
        for component_id in evidence.component_ids:
            key = str(component_id)
            if key in seen_components:
                raise GixMergeRefused(
                    "component_double_counted",
                    f"component e-value {key} is counted by both "
                    f"{seen_components[key]!r} and {submission.origin!r}",
                )
            seen_components[key] = submission.origin

    # The merge itself: arithmetic mean in log space.
    log_e = _log_mean_exp([e.log_e_value for e in evidences])

    nulls = sorted({e.joint_null_hypothesis_id for e in evidences})
    joint_null = nulls[0] if len(nulls) == 1 else "AND(" + ",".join(nulls) + ")"
    filtrations = {e.filtration_id for e in evidences}
    shared_filtration = (
        next(iter(filtrations)) if len(filtrations) == 1 else None
    )
    anytime_valid = shared_filtration is not None and all(
        e.anytime_valid for e in evidences
    )

    weakest = min(
        (e.maturity for e in evidences), key=lambda m: _MATURITY_RANK[m]
    )
    # The interchange transport is research-early; the merged claim cannot
    # out-rank it.
    maturity = min(
        (weakest, EvidenceMaturity.RESEARCH_EARLY),
        key=lambda m: _MATURITY_RANK[m],
    )

    federated = all(
        v.checkpoint_verification is not None
        and v.checkpoint_verification.federated
        for v in verifications
    )

    return FederatedMeanMerge(
        log_e_value=log_e,
        is_true_e_value=True,
        anytime_valid=anytime_valid,
        joint_null_hypothesis_id=joint_null,
        filtration_id=shared_filtration if shared_filtration else "mixed",
        maturity=maturity,
        origins=tuple(origins),
        n_orgs=len(submissions),
        federated=federated,
        federated_reason="" if federated else FEDERATED_FALSE_REASON,
    )

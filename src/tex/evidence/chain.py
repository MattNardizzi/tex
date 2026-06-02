from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Iterable

from tex.domain.evidence import EvidenceRecord


@dataclass(frozen=True, slots=True)
class ChainVerificationIssue:
    """
    Describes a single integrity problem found during evidence-chain verification.
    """

    index: int
    record_hash: str | None
    code: str
    message: str


@dataclass(frozen=True, slots=True)
class ChainVerificationResult:
    """
    Result of verifying one or more evidence records.
    """

    is_valid: bool
    record_count: int
    issues: tuple[ChainVerificationIssue, ...]

    @property
    def issue_count(self) -> int:
        return len(self.issues)


def verify_evidence_chain(
    records: Iterable[EvidenceRecord],
) -> ChainVerificationResult:
    """
    Verifies a full append-only evidence chain.

    Checks:
    - each record's payload_sha256 matches payload_json
    - each record's record_hash matches payload_sha256 + previous_hash
    - each record links correctly to the prior record
    - the first record does not point backward to a nonexistent predecessor
    """
    normalized_records = tuple(records)
    issues: list[ChainVerificationIssue] = []

    if not normalized_records:
        return ChainVerificationResult(
            is_valid=True,
            record_count=0,
            issues=tuple(),
        )

    previous_record: EvidenceRecord | None = None

    for index, record in enumerate(normalized_records):
        issues.extend(_verify_record_integrity(record=record, index=index))
        issues.extend(
            _verify_chain_link(
                previous_record=previous_record,
                candidate_record=record,
                index=index,
            )
        )
        previous_record = record

    return ChainVerificationResult(
        is_valid=not issues,
        record_count=len(normalized_records),
        issues=tuple(issues),
    )


def verify_evidence_chain_slice(
    records: Iterable[EvidenceRecord],
    *,
    prior_link_witness: str | None = None,
) -> ChainVerificationResult:
    """
    Verifies a *slice* of an append-only evidence chain — that is, a
    contiguous run of records that may begin somewhere other than the
    chain's genesis record.

    Background (KNOWN_BUGS #5). ``verify_evidence_chain`` treats the
    first record it sees as the chain's genesis: it requires
    ``previous_hash is None``. That rule is correct for a full chain
    but wrong for a slice — a single-record bundle for, say, the
    fortieth decision in the log will have a non-null ``previous_hash``
    pointing at the thirty-ninth record. Until this function landed,
    every single-record evidence bundle returned by
    ``GET /decisions/{id}/evidence-bundle`` reported
    ``is_chain_valid: False`` with the issue text
    "first record must not contain a previous_hash". The underlying
    JSONL log was genuinely valid; the API's slice-verification was
    wrong.

    This function implements the inclusion-proof-with-witness pattern
    that Certificate Transparency, Sigstore Rekor, and the Microsoft
    Agent Governance Toolkit's MerkleAuditChain converge on as the
    standard for verifying a sub-range of an append-only log. The
    caller passes the ``record_hash`` of the record immediately
    preceding the slice as a *witness*. The verifier then validates
    that the first record's ``previous_hash`` equals the witness, and
    every subsequent record links to its predecessor inside the slice.

    The semantics:

    - ``prior_link_witness is None`` and the first slice record has
      ``previous_hash is None``: the slice starts at the chain's
      genesis. Verifier behaves identically to
      ``verify_evidence_chain``.

    - ``prior_link_witness is None`` and the first slice record has
      ``previous_hash`` set: the slice does NOT include genesis and
      no witness was supplied. The verifier emits
      ``missing_prior_link_witness`` so the caller knows it must
      supply one for an audit-grade verdict. The slice's *internal*
      record-to-record continuity is still verified.

    - ``prior_link_witness == slice[0].previous_hash``: the witness
      matches the slice's stated predecessor. Continuity holds.

    - ``prior_link_witness != slice[0].previous_hash``: tamper
      attempt. Verifier emits ``prior_link_witness_mismatch``.

    - ``prior_link_witness`` is supplied but the first record has
      ``previous_hash is None``: contradiction. The caller asserted
      there's a predecessor but the record claims to be genesis.
      Verifier emits ``unexpected_previous_hash`` so the inconsistency
      is surfaced.

    Every per-record integrity check (payload_sha256 match,
    record_hash match, payload_json well-formedness) runs unchanged
    so a tampered record in the middle of a slice is still caught.

    A 64-character lowercase hex digest is the only acceptable witness
    format; anything else raises ``ValueError`` at parse time so the
    caller cannot accidentally pass garbage.
    """
    normalized_records = tuple(records)
    issues: list[ChainVerificationIssue] = []

    if prior_link_witness is not None:
        prior_link_witness = _normalize_witness(prior_link_witness)

    if not normalized_records:
        return ChainVerificationResult(
            is_valid=True,
            record_count=0,
            issues=tuple(),
        )

    first_record = normalized_records[0]

    # Per-record integrity for the first record runs before the chain
    # link check, identical to verify_evidence_chain. This way a
    # corrupt payload_json is caught even if the witness is missing.
    issues.extend(_verify_record_integrity(record=first_record, index=0))

    # Validate the witness-to-slice link explicitly. This is the
    # surface area that ``_verify_chain_link`` cannot handle, because
    # ``_verify_chain_link`` assumes the predecessor is an
    # ``EvidenceRecord``, not just a record_hash string.
    issues.extend(
        _verify_witness_link(
            prior_link_witness=prior_link_witness,
            first_record=first_record,
        )
    )

    # Subsequent records inside the slice are verified against their
    # in-slice predecessor exactly the same way verify_evidence_chain
    # would verify them.
    previous_record: EvidenceRecord = first_record
    for index, record in enumerate(normalized_records[1:], start=1):
        issues.extend(_verify_record_integrity(record=record, index=index))
        issues.extend(
            _verify_chain_link(
                previous_record=previous_record,
                candidate_record=record,
                index=index,
            )
        )
        previous_record = record

    return ChainVerificationResult(
        is_valid=not issues,
        record_count=len(normalized_records),
        issues=tuple(issues),
    )


def verify_latest_link(
    previous_record: EvidenceRecord | None,
    candidate_record: EvidenceRecord,
) -> ChainVerificationResult:
    """
    Verifies only the newest record being appended to the chain.

    Checks:
    - candidate payload_sha256 integrity
    - candidate record_hash integrity
    - candidate previous_hash linkage against the prior record
    """
    issues: list[ChainVerificationIssue] = []

    issues.extend(_verify_record_integrity(record=candidate_record, index=0))
    issues.extend(
        _verify_chain_link(
            previous_record=previous_record,
            candidate_record=candidate_record,
            index=0,
        )
    )

    return ChainVerificationResult(
        is_valid=not issues,
        record_count=1,
        issues=tuple(issues),
    )


def _verify_record_integrity(
    *,
    record: EvidenceRecord,
    index: int,
) -> list[ChainVerificationIssue]:
    issues: list[ChainVerificationIssue] = []

    try:
        expected_payload_sha256 = _sha256_hex(record.payload_json)
        if record.payload_sha256 != expected_payload_sha256:
            issues.append(
                ChainVerificationIssue(
                    index=index,
                    record_hash=record.record_hash,
                    code="payload_sha256_mismatch",
                    message=(
                        "record payload_sha256 does not match the canonical hash "
                        "of payload_json"
                    ),
                )
            )
    except Exception as exc:
        issues.append(
            ChainVerificationIssue(
                index=index,
                record_hash=record.record_hash,
                code="payload_sha256_verification_error",
                message=(
                    "payload_sha256 verification raised "
                    f"{exc.__class__.__name__}"
                ),
            )
        )

    try:
        expected_record_hash = _build_record_hash(
            payload_sha256=record.payload_sha256,
            previous_hash=record.previous_hash,
        )
        if record.record_hash != expected_record_hash:
            issues.append(
                ChainVerificationIssue(
                    index=index,
                    record_hash=record.record_hash,
                    code="record_hash_mismatch",
                    message=(
                        "record record_hash does not match the canonical hash of "
                        "payload_sha256 + previous_hash"
                    ),
                )
            )
    except Exception as exc:
        issues.append(
            ChainVerificationIssue(
                index=index,
                record_hash=record.record_hash,
                code="record_hash_verification_error",
                message=f"record hash verification raised {exc.__class__.__name__}",
            )
        )

    try:
        decoded_payload = json.loads(record.payload_json)
        if not isinstance(decoded_payload, dict):
            issues.append(
                ChainVerificationIssue(
                    index=index,
                    record_hash=record.record_hash,
                    code="payload_json_not_object",
                    message="record payload_json must decode to a JSON object",
                )
            )
    except json.JSONDecodeError:
        issues.append(
            ChainVerificationIssue(
                index=index,
                record_hash=record.record_hash,
                code="payload_json_invalid",
                message="record payload_json is not valid JSON",
            )
        )
    except Exception as exc:
        issues.append(
            ChainVerificationIssue(
                index=index,
                record_hash=record.record_hash,
                code="payload_json_verification_error",
                message=f"payload_json verification raised {exc.__class__.__name__}",
            )
        )

    return issues


def _verify_chain_link(
    *,
    previous_record: EvidenceRecord | None,
    candidate_record: EvidenceRecord,
    index: int,
) -> list[ChainVerificationIssue]:
    issues: list[ChainVerificationIssue] = []

    if previous_record is None:
        if candidate_record.previous_hash is not None:
            issues.append(
                ChainVerificationIssue(
                    index=index,
                    record_hash=candidate_record.record_hash,
                    code="unexpected_previous_hash",
                    message="first record must not contain a previous_hash",
                )
            )
        return issues

    if candidate_record.previous_hash != previous_record.record_hash:
        issues.append(
            ChainVerificationIssue(
                index=index,
                record_hash=candidate_record.record_hash,
                code="chain_link_mismatch",
                message=(
                    "record previous_hash does not match the prior record's "
                    "record_hash"
                ),
            )
        )

    return issues


def _verify_witness_link(
    *,
    prior_link_witness: str | None,
    first_record: EvidenceRecord,
) -> list[ChainVerificationIssue]:
    """
    Validates the relationship between an out-of-slice witness hash
    and the first record of a slice.

    Cases handled (see ``verify_evidence_chain_slice`` for narrative):

    - Both ``None``: the slice claims to begin at genesis. Valid.
    - Witness ``None`` but record has ``previous_hash``: caller did
      not supply the necessary witness. Recoverable, but emits an
      ``missing_prior_link_witness`` issue so the audit verdict is
      not silently passed off as "valid".
    - Witness present but record has ``previous_hash is None``: the
      record claims to be genesis but the caller asserted a
      predecessor. Tamper signal — emit ``unexpected_previous_hash``.
    - Both present and equal: continuity holds. Valid.
    - Both present and unequal: tamper signal — emit
      ``prior_link_witness_mismatch``.
    """
    issues: list[ChainVerificationIssue] = []

    if prior_link_witness is None and first_record.previous_hash is None:
        return issues

    if prior_link_witness is None and first_record.previous_hash is not None:
        issues.append(
            ChainVerificationIssue(
                index=0,
                record_hash=first_record.record_hash,
                code="missing_prior_link_witness",
                message=(
                    "slice does not begin at the chain genesis but no "
                    "prior_link_witness was supplied; pass the predecessor "
                    "record's record_hash to enable inclusion-proof "
                    "verification"
                ),
            )
        )
        return issues

    if prior_link_witness is not None and first_record.previous_hash is None:
        issues.append(
            ChainVerificationIssue(
                index=0,
                record_hash=first_record.record_hash,
                code="unexpected_previous_hash",
                message=(
                    "prior_link_witness was supplied but the first slice "
                    "record claims to be the chain genesis "
                    "(previous_hash is null)"
                ),
            )
        )
        return issues

    # Both present
    if prior_link_witness != first_record.previous_hash:
        issues.append(
            ChainVerificationIssue(
                index=0,
                record_hash=first_record.record_hash,
                code="prior_link_witness_mismatch",
                message=(
                    "first slice record's previous_hash does not match "
                    "the supplied prior_link_witness"
                ),
            )
        )

    return issues


def _normalize_witness(value: str) -> str:
    """
    Validates and normalizes a prior_link_witness string.

    Mirrors EvidenceRecord's validator: 64 lowercase hex characters.
    Rejecting garbage at parse time means downstream comparison logic
    only ever sees a well-formed witness.
    """
    if not isinstance(value, str):
        raise ValueError("prior_link_witness must be a string")
    normalized = value.strip().lower()
    if len(normalized) != 64:
        raise ValueError(
            "prior_link_witness must be a 64-character SHA-256 hex digest"
        )
    allowed = set("0123456789abcdef")
    if any(char not in allowed for char in normalized):
        raise ValueError(
            "prior_link_witness must contain only lowercase hexadecimal "
            "characters"
        )
    return normalized


def _build_record_hash(
    *,
    payload_sha256: str,
    previous_hash: str | None,
) -> str:
    chain_input = _stable_json(
        {
            "payload_sha256": payload_sha256,
            "previous_hash": previous_hash,
        }
    )
    return _sha256_hex(chain_input)


def _stable_json(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def _sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()
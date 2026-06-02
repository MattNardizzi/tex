"""
Quorum signing for the highest-stakes Tex evidence records.

This module is the production glue between ``tex.pqcrypto.quorum_ml_dsa``
and ``tex.evidence.chain`` — when an evidence record is marked critical
(e.g. FORBID verdicts, high-severity tool receipts, cross-jurisdiction
audit anchors), the runtime signs it under a k-of-n quorum of ML-DSA-87
keys rather than a single ML-DSA-65 key.

Activation
----------
Set the environment variable ``TEX_EVIDENCE_QUORUM_K=3`` (or any positive
integer) to enable quorum signing for records flagged
``requires_quorum=True``. The default n is taken from
``TEX_EVIDENCE_QUORUM_N`` (defaults to ``max(k+2, 5)``) and the algorithm
is fixed at ML-DSA-87 (CNSA 2.0 Level 5).

When the env flag is unset, single-key ML-DSA-87 signing via
``evidence_chain_signer.sign_evidence_record`` remains the default for
all records. Quorum is opt-in and never silently disabled — if the
descriptor cannot be loaded or partial signing fails, the operation
raises rather than falling back to single-key.

References
----------
- ``tex.pqcrypto.quorum_ml_dsa`` for the underlying quorum primitives
- ``tex.pqcrypto.evidence_chain_signer`` for the single-key path
- Mithril (ePrint 2026/013) and TALUS (arxiv 2603.22109) for the MPC
  threshold ML-DSA frontier that this design is forward-compatible with

Priority
--------
P0 — Thread 10. The production differentiator vs every competitor.
"""

from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

# Pre-load tex.ecosystem so the (pre-existing) tex.events.crypto_provenance
# circular import is materialized in the correct order before _canonical is
# pulled in. Matches the load-order workaround in tests/conftest.py and the
# existing tex.pqcrypto.evidence_chain_signer.py.
import tex.ecosystem  # noqa: F401  pylint: disable=unused-import

from tex.events._canonical import canonical_json
from tex.observability.telemetry import emit_event
from tex.pqcrypto.algorithm_agility import SignatureAlgorithm
from tex.pqcrypto.quorum_ml_dsa import (
    PartialSignature,
    QuorumDescriptor,
    QuorumMember,
    QuorumSignature,
    QuorumMlDsaProvider,
    ThresholdQuorumKeySet,
)


_PQ_QUORUM_SIGNATURE_FIELD = "pq_quorum_signature"

_ENV_QUORUM_K = "TEX_EVIDENCE_QUORUM_K"
_ENV_QUORUM_N = "TEX_EVIDENCE_QUORUM_N"


@dataclass(frozen=True, slots=True)
class EvidenceQuorumPolicy:
    """
    Static description of the quorum policy in effect for this process.

    ``enabled`` mirrors whether ``TEX_EVIDENCE_QUORUM_K`` is set to a
    positive integer. ``k`` and ``n`` carry the policy. ``algorithm`` is
    fixed at QUORUM_ML_DSA_87 (CNSA 2.0 Level 5) by design — there is
    no reason to use a lower NIST level for quorum signing the records
    that justify a quorum.
    """

    enabled: bool
    k: int
    n: int
    algorithm: SignatureAlgorithm = SignatureAlgorithm.QUORUM_ML_DSA_87

    @classmethod
    def from_env(cls) -> "EvidenceQuorumPolicy":
        raw_k = os.environ.get(_ENV_QUORUM_K, "").strip()
        if not raw_k:
            return cls(enabled=False, k=0, n=0)
        try:
            k = int(raw_k)
        except ValueError:
            return cls(enabled=False, k=0, n=0)
        if k < 1:
            return cls(enabled=False, k=0, n=0)
        raw_n = os.environ.get(_ENV_QUORUM_N, "").strip()
        if raw_n:
            try:
                n = int(raw_n)
            except ValueError:
                n = max(k + 2, 5)
        else:
            n = max(k + 2, 5)
        if n < k:
            n = k
        return cls(enabled=True, k=k, n=n)


def _strip_quorum_signature(record: dict[str, Any]) -> dict[str, Any]:
    if _PQ_QUORUM_SIGNATURE_FIELD not in record:
        return record
    return {k: v for k, v in record.items() if k != _PQ_QUORUM_SIGNATURE_FIELD}


def _canonical_bytes(record: dict[str, Any]) -> bytes:
    return canonical_json(_strip_quorum_signature(record)).encode("utf-8")


def quorum_sign_evidence_record(
    record: dict[str, Any],
    keyset: ThresholdQuorumKeySet,
    *,
    signing_member_indices: list[int] | None = None,
) -> QuorumSignature:
    """
    Sign an evidence record under a k-of-n threshold ML-DSA quorum.

    ``signing_member_indices`` selects which members participate; if
    None, the first ``descriptor.k`` members sign (sufficient to meet
    the threshold; production deployments will rotate which members
    sign which records to spread load and reduce single-jurisdiction
    correlation).
    """
    descriptor = keyset.descriptor
    if signing_member_indices is None:
        signing_member_indices = list(range(descriptor.k))
    if len(signing_member_indices) < descriptor.k:
        raise ValueError(
            f"need at least k={descriptor.k} signing members, "
            f"got {len(signing_member_indices)}"
        )

    provider_algo = {
        SignatureAlgorithm.ML_DSA_44: SignatureAlgorithm.QUORUM_ML_DSA_44,
        SignatureAlgorithm.ML_DSA_65: SignatureAlgorithm.QUORUM_ML_DSA_65,
        SignatureAlgorithm.ML_DSA_87: SignatureAlgorithm.QUORUM_ML_DSA_87,
    }[descriptor.base_algorithm]
    provider = QuorumMlDsaProvider(parameter_set=provider_algo)

    canonical = _canonical_bytes(record)
    keys = keyset.keys_for(signing_member_indices)
    partials: list[PartialSignature] = []
    for idx, key in keys.items():
        partials.append(provider.partial_sign(canonical, idx, key, descriptor))
    quorum_sig = provider.aggregate(partials, descriptor)
    emit_event(
        "pqcrypto.evidence_quorum.signed",
        algorithm=provider_algo.value,
        base_algorithm=descriptor.base_algorithm.value,
        descriptor_commitment=descriptor.commitment,
        canonical_bytes=len(canonical),
        k=descriptor.k,
        n=descriptor.n,
        signing_members=signing_member_indices,
    )
    return quorum_sig


def verify_quorum_evidence_signature(
    record: dict[str, Any],
    quorum_signature: QuorumSignature,
    descriptor: QuorumDescriptor,
) -> bool:
    """Verify a quorum signature against an evidence record."""
    provider_algo = {
        SignatureAlgorithm.ML_DSA_44: SignatureAlgorithm.QUORUM_ML_DSA_44,
        SignatureAlgorithm.ML_DSA_65: SignatureAlgorithm.QUORUM_ML_DSA_65,
        SignatureAlgorithm.ML_DSA_87: SignatureAlgorithm.QUORUM_ML_DSA_87,
    }[descriptor.base_algorithm]
    if quorum_signature.threshold_algorithm is not provider_algo:
        emit_event(
            "pqcrypto.evidence_quorum.verify_failed",
            reason="threshold_algorithm_mismatch",
            descriptor_commitment=descriptor.commitment,
        )
        return False
    provider = QuorumMlDsaProvider(parameter_set=provider_algo)
    try:
        canonical = _canonical_bytes(record)
    except TypeError as exc:
        emit_event(
            "pqcrypto.evidence_quorum.verify_failed",
            reason="canonicalization_error",
            error=str(exc),
        )
        return False
    return provider.verify_quorum(canonical, quorum_signature, descriptor)


def serialize_quorum_signature(
    quorum_signature: QuorumSignature,
    descriptor: QuorumDescriptor,
) -> dict[str, Any]:
    """
    Render a QuorumSignature into a JSON-serializable dict suitable for
    embedding in an evidence record's ``pq_quorum_signature`` field.

    Includes the descriptor so a verifier can re-derive the commitment
    without trusting an external source.
    """
    return {
        "threshold_algorithm": quorum_signature.threshold_algorithm.value,
        "descriptor_commitment": quorum_signature.descriptor_commitment,
        "descriptor": {
            "k": descriptor.k,
            "n": descriptor.n,
            "base_algorithm": descriptor.base_algorithm.value,
            "members": [
                {
                    "index": m.index,
                    "member_id": m.member_id,
                    "public_key_b64": m.public_key_b64,
                }
                for m in descriptor.members
            ],
            "commitment": descriptor.commitment,
        },
        "partials": [
            {
                "member_index": p.member_index,
                "member_id": p.member_id,
                "signature_b64": p.signature_b64,
            }
            for p in quorum_signature.partials
        ],
        "signed_at": datetime.now(UTC).isoformat(),
    }


def deserialize_quorum_signature(
    payload: dict[str, Any],
) -> tuple[QuorumSignature, QuorumDescriptor]:
    """Inverse of ``serialize_quorum_signature``."""
    try:
        threshold_algo = SignatureAlgorithm(payload["threshold_algorithm"])
        descriptor_payload = payload["descriptor"]
        base_algo = SignatureAlgorithm(descriptor_payload["base_algorithm"])
        members = tuple(
            QuorumMember(
                index=int(m["index"]),
                member_id=str(m["member_id"]),
                public_key_b64=str(m["public_key_b64"]),
            )
            for m in descriptor_payload["members"]
        )
        descriptor = QuorumDescriptor.create(
            k=int(descriptor_payload["k"]),
            n=int(descriptor_payload["n"]),
            base_algorithm=base_algo,
            members=members,
        )
        # Caller-supplied commitment must match the computed commitment.
        if descriptor.commitment != str(descriptor_payload.get("commitment", "")):
            raise ValueError("descriptor commitment self-inconsistent")
        partials = tuple(
            PartialSignature(
                member_index=int(p["member_index"]),
                member_id=str(p["member_id"]),
                signature_b64=str(p["signature_b64"]),
            )
            for p in payload["partials"]
        )
        quorum_signature = QuorumSignature(
            threshold_algorithm=threshold_algo,
            descriptor_commitment=str(payload["descriptor_commitment"]),
            partials=partials,
        )
    except (KeyError, ValueError, TypeError) as exc:
        raise ValueError(f"malformed quorum signature payload: {exc}") from exc
    return quorum_signature, descriptor

"""
Drop-in signing extension for the existing `tex.evidence.chain` module.

Wraps the existing SHA-256 hash-chain with an additional ML-DSA signature
per record, producing an extended record format:

    {
        "record_hash": "<sha256>",          # existing
        "previous_hash": "<sha256>",        # existing
        "payload_sha256": "<sha256>",       # existing
        "payload_json": {...},              # existing
        "pq_signature": {                   # NEW
            "algorithm": "ml-dsa-65",
            "key_id": "<opaque>",
            "signature_b64": "<base64>",
            "signed_at": "<iso8601>"
        }
    }

Backwards-compatible: records without ``pq_signature`` continue to verify
under the legacy chain rules.

Canonicalization
----------------
Records are canonicalized via ``tex.events._canonical.canonical_json``
(RFC 8785 subset, frozen as the cross-package canonicalization choke
point in Thread 2). The ``pq_signature`` field itself is excluded from
the canonical bytes so a record can be signed and the signature
embedded without mutating what was signed; verifiers strip the field
before re-canonicalizing.

NOTE: importing ``tex.events._canonical`` from ``tex.pqcrypto`` is an
intentional cross-package dependency. ``_canonical`` has a leading
underscore but Thread 2 effectively promoted it to a stable internal
API by making it the canonicalization choke point for the events
ledger; reusing it here keeps the canonical bytes byte-for-byte
identical between the events ledger and the evidence chain. Do not
add a private re-implementation in ``pqcrypto``.

Algorithm agility
-----------------
The active signing algorithm is taken from the ``SignatureKeyPair``;
verification dispatches via ``get_signature_provider`` so a record signed
under ML-DSA-65 today and a record signed under ML-DSA-87 tomorrow
verify through the same call site. Hybrid records work for free because
the dispatcher returns ``HybridMlDsaEd25519Provider`` for the
``HYBRID_ML_DSA_ED25519`` enum value.

Reference
---------
- NIST FIPS 204 (ML-DSA)
- RFC 8785 (JSON Canonicalization Scheme)
- NSA CNSA 2.0

Priority
--------
P0 — ship in days 1-14. This is the headline post-quantum claim.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from tex.events._canonical import canonical_json  # see module note above
from tex.observability.telemetry import emit_event
from tex.pqcrypto.algorithm_agility import (
    SignatureAlgorithm,
    SignatureKeyPair,
    get_signature_provider,
)


# Field name reserved for the embedded post-quantum signature on the
# extended record. Excluded from canonicalization on both sign and
# verify paths.
_PQ_SIGNATURE_FIELD: str = "pq_signature"


@dataclass(frozen=True, slots=True)
class PqSignature:
    """Post-quantum signature attached to an evidence record."""

    algorithm: SignatureAlgorithm
    key_id: str
    signature_b64: str
    signed_at: str  # ISO 8601


def _strip_pq_signature(record: dict[str, Any]) -> dict[str, Any]:
    """
    Return ``record`` minus its ``pq_signature`` field.

    Non-mutating: returns a new dict. Used by both sign and verify
    paths so the bytes the signer signs are byte-for-byte identical to
    the bytes the verifier checks against, regardless of whether the
    caller has already attached a signature to the record.
    """
    if _PQ_SIGNATURE_FIELD not in record:
        return record
    return {k: v for k, v in record.items() if k != _PQ_SIGNATURE_FIELD}


def _canonical_bytes(record: dict[str, Any]) -> bytes:
    """Canonicalize ``record`` (sans ``pq_signature``) to UTF-8 bytes."""
    return canonical_json(_strip_pq_signature(record)).encode("utf-8")


def sign_evidence_record(
    record: dict[str, Any],
    key: SignatureKeyPair,
) -> PqSignature:
    """
    Produce a signature over the canonicalized evidence record.

    The signature is taken over the canonical RFC 8785 JSON of the
    record with any pre-existing ``pq_signature`` field stripped. The
    algorithm is taken from ``key.algorithm`` and dispatched through
    the algorithm-agility provider, so swapping ML-DSA-65 for ML-DSA-87
    or for hybrid mode requires no call-site change.

    Implementation notes (formerly P0 TODOs, now wired):
    - **RFC 8785 canonicalization** via ``tex.events._canonical.canonical_json``.
    - **ML-DSA signing** dispatched via
      ``algorithm_agility.get_signature_provider`` — backend selection is
      ``pqcrypto.ml_dsa.active_backend_id()`` (pyca/cryptography 48 native or
      liboqs fallback).
    - **ISO 8601 timestamp** in UTC with timezone offset.
    """
    canonical = _canonical_bytes(record)
    provider = get_signature_provider(key.algorithm)
    signature_bytes = provider.sign(canonical, key)
    pq_sig = PqSignature(
        algorithm=key.algorithm,
        key_id=key.key_id,
        signature_b64=base64.b64encode(signature_bytes).decode("ascii"),
        signed_at=datetime.now(UTC).isoformat(),
    )
    emit_event(
        "pqcrypto.evidence.signed",
        algorithm=key.algorithm.value,
        key_id=key.key_id,
        canonical_bytes=len(canonical),
        signature_bytes=len(signature_bytes),
    )
    return pq_sig


def verify_evidence_record_signature(
    record: dict[str, Any],
    signature: PqSignature,
    public_key: bytes,
) -> bool:
    """
    Verify a post-quantum signature on an evidence record.

    The verifier strips ``pq_signature`` from the record (so callers may
    pass the record with or without an embedded signature, the bytes
    verified are identical), re-canonicalizes per RFC 8785, and
    dispatches verification through the algorithm-agility provider for
    ``signature.algorithm``. Hybrid signatures are handled transparently
    because ``HYBRID_ML_DSA_ED25519`` resolves to
    ``HybridMlDsaEd25519Provider`` via the dispatcher.

    Returns ``False`` (rather than raising) for any cryptographic or
    operational failure; emits ``pqcrypto.evidence.verify_failed`` with
    a structured ``reason`` so downstream telemetry can distinguish a
    tamper detection from an operational error (consistent with
    ``tex.events.ledger.verify_chain.failed`` from Thread 2).

    Implementation notes (formerly P0 TODOs, now wired):
    - **RFC 8785 canonicalization** of the stripped record bytes.
    - **ML-DSA verify** via the algorithm-agility dispatcher.
    - **Hybrid signatures** handled transparently via
      ``HybridMlDsaEd25519Provider`` resolved by the same dispatcher.
    """

    def _fail(reason: str, **extra: Any) -> bool:
        emit_event(
            "pqcrypto.evidence.verify_failed",
            algorithm=signature.algorithm.value,
            key_id=signature.key_id,
            reason=reason,
            **extra,
        )
        return False

    # Decode signature bytes.
    try:
        signature_bytes = base64.b64decode(signature.signature_b64, validate=True)
    except (ValueError, TypeError):
        return _fail("malformed_signature_b64")

    # Canonicalize the record. Canonicalization can fail if the record
    # contains values outside the RFC 8785 subset (e.g. floats); treat
    # that as an operational failure, not a tamper detection.
    try:
        canonical = _canonical_bytes(record)
    except TypeError as exc:
        return _fail("canonicalization_error", error=str(exc))

    # Resolve provider. NotImplementedError surfaces when the algorithm
    # is not yet wired (e.g. SLH-DSA-128S today); that is an operational
    # failure, not a tamper detection.
    try:
        provider = get_signature_provider(signature.algorithm)
    except NotImplementedError as exc:
        return _fail("provider_not_available", error=str(exc))

    # Run verify. RuntimeError covers liboqs-missing in the ML-DSA path.
    try:
        ok = bool(provider.verify(canonical, signature_bytes, public_key))
    except RuntimeError as exc:
        return _fail("provider_runtime_error", error=str(exc))
    except Exception as exc:  # defensive
        return _fail("provider_unexpected_error", error=str(exc))

    if not ok:
        return _fail("signature_invalid")

    emit_event(
        "pqcrypto.evidence.verified",
        algorithm=signature.algorithm.value,
        key_id=signature.key_id,
        canonical_bytes=len(canonical),
        signature_bytes=len(signature_bytes),
    )
    return True

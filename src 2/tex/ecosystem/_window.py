"""
RFC 9162 (Certificate Transparency v2) Merkle tree helpers.

Used by ``EcosystemEngine.attest_state`` to compute a deterministic Merkle root
over the event record-hashes that fall inside a time window. A SCITT-style
Receipt later overlaid on this tree carries an inclusion proof for any single
event without re-disclosing the full window.

Reference
---------
- RFC 9162 §2.1 (Merkle Tree Hash, Inclusion Proof, Consistency Proof). The
  same leaf prefix (0x00) and inner-node prefix (0x01) used by Certificate
  Transparency are used here so any RFC 9162 verifier can validate Tex
  inclusion/consistency proofs unchanged.
- IETF SCITT architecture draft -22 (April 2026). Window roots produced here
  are bit-compatible with the inclusion-proof format SCITT Receipts emit.

Design notes
------------
* SHA-256 only. Algorithm agility for *signing* lives in
  ``tex.pqcrypto.algorithm_agility``; the Merkle hash is fixed (FIPS 180-4).
* Empty-tree convention: ``MTH({}) = SHA-256("")``, matching RFC 9162 §2.1.
* Leaves are hashed *before* tree assembly: ``leaf_hash(d) = H(0x00 || d)``.
  Callers should pass already-hashed event record hashes (32-byte values
  decoded from hex) so the leaf prefix is over the digest, not the raw event.
* Inner nodes: ``H(0x01 || left || right)`` per RFC 9162.
* This module is pure stdlib (hashlib only). No dependency on networkx or
  pydantic so it stays trivially testable.

Priority: P0.

TODO(P1): inclusion proof generation. Required for SCITT Receipts.
TODO(P1): consistency proof generation between two sequential STHs.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence

# RFC 9162 §2.1 domain-separation prefixes. These constants are normative; do
# not rename without bumping a SCHEMA_VERSION elsewhere.
_LEAF_PREFIX: bytes = b"\x00"
_INNER_PREFIX: bytes = b"\x01"


def empty_root() -> str:
    """
    Return the canonical empty-tree root (RFC 9162 §2.1).

    The empty Merkle tree's root is ``SHA-256("")`` — a fixed hex value.
    Pinned by tests; used as the window root when no events fall inside the
    attestation period.
    """
    return hashlib.sha256(b"").hexdigest()


def leaf_hash(record_hash_hex: str) -> str:
    """
    Compute the RFC 9162 leaf hash for a single record.

    Parameters
    ----------
    record_hash_hex
        Hex string of an event's ``record_hash`` (the canonical SHA-256 the
        ledger already computes). Must be exactly 64 hex characters
        (256 bits).

    Returns
    -------
    str
        Hex SHA-256 of ``0x00 || record_hash_bytes``.

    Raises
    ------
    TypeError
        If ``record_hash_hex`` is not a string.
    ValueError
        If the string is not 64 hex characters of a valid SHA-256 digest.
    """
    if not isinstance(record_hash_hex, str):
        raise TypeError(
            f"record_hash_hex must be str, got {type(record_hash_hex).__name__}"
        )
    if len(record_hash_hex) != 64:
        raise ValueError(
            f"record_hash_hex must be 64 hex chars, got {len(record_hash_hex)}"
        )
    try:
        record_bytes = bytes.fromhex(record_hash_hex)
    except ValueError as exc:
        raise ValueError(f"record_hash_hex is not valid hex: {exc}") from exc
    return hashlib.sha256(_LEAF_PREFIX + record_bytes).hexdigest()


def merkle_root(record_hashes_hex: Sequence[str]) -> str:
    """
    Compute the RFC 9162 §2.1 Merkle Tree Hash over an ordered sequence of
    record hashes.

    The input order is canonical and is *not* re-sorted here; callers
    (specifically ``EcosystemEngine.attest_state``) are responsible for
    sorting events by ``(timestamp, event_id)`` before passing them in.

    Algorithm (RFC 9162 §2.1, paraphrased):
        MTH({d_0, ..., d_{n-1}}) for n = 0      -> SHA-256("")
        MTH({d_0})              for n = 1       -> H(0x00 || d_0)
        MTH({d_0, ..., d_{n-1}}) for n > 1      ->
            let k = largest power of two with k < n
            H(0x01 || MTH({d_0..d_{k-1}}) || MTH({d_k..d_{n-1}}))

    Reference: RFC 9162 §2.1.

    Parameters
    ----------
    record_hashes_hex
        Ordered sequence of 64-hex-char SHA-256 record hashes.

    Returns
    -------
    str
        Hex SHA-256 of the Merkle tree root.

    Raises
    ------
    TypeError, ValueError
        Propagated from ``leaf_hash`` for malformed inputs.
    """
    if len(record_hashes_hex) == 0:
        return empty_root()

    # Materialize leaves once; the recursion only walks indices.
    leaves: list[bytes] = [
        bytes.fromhex(leaf_hash(h)) for h in record_hashes_hex
    ]
    return _mth(leaves, 0, len(leaves)).hex()


def _mth(leaves: list[bytes], lo: int, hi: int) -> bytes:
    """Compute MTH(leaves[lo:hi]) per RFC 9162 §2.1."""
    n = hi - lo
    if n == 1:
        return leaves[lo]
    # k = largest power of two strictly less than n
    k = 1
    while (k << 1) < n:
        k <<= 1
    left = _mth(leaves, lo, lo + k)
    right = _mth(leaves, lo + k, hi)
    return hashlib.sha256(_INNER_PREFIX + left + right).digest()

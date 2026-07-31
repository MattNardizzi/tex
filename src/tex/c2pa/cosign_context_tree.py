"""
Merkle context tree for the cosign signing input (Thread 6, Gap 3).

The Thread 5 cosign signs a flat JSON document. That works, but the
flat shape doesn't lend itself to formal-methods analysis because
each defended attack class is just a field in a serialised blob —
there's no structural guarantee that the signature *binds* every
field. Golaszewski's UMBC/NSA paper (arxiv 2604.24890) recommends
using a **Merkle hash tree** to represent protocol context, with
each protocol element a leaf and the root signed.

Thread 6 adds this as the cosign signing input v2. Both v1 (Thread 5,
JSON-blob) and v2 (Thread 6, Merkle tree) are supported on the
verifier side via ``COSIGN_CANONICALIZATION_VERSION``; new manifests
default to v2.

Tree shape
----------

```
                          root_hash
                         /         \\
                        /           \\
                  attack_defenses  binding_context
                 /        |       \\        /         \\
            ts_swap     rev    cross    artifact     identity
                                      /     \\
                              full_hash    retention
```

Each leaf is ``SHA-256(label || value)`` where ``label`` is the
canonical leaf name (UTF-8 bytes) and ``value`` is the canonical
encoding of that field (also UTF-8 JSON). Internal nodes are
``SHA-256(left || right)``. Odd-arity branches duplicate the last
leaf, in the standard Merkle convention.

This is **NOT** a Bitcoin-style Merkle tree (which uses double-SHA);
it's a single-SHA tree because we don't need second-preimage
defence beyond what SHA-256 already gives — the leaves are
constructed from typed labels, eliminating cross-leaf confusion.

CPSA model
----------
A companion file ``cpsa_models/cosign_v2.scm`` expresses the same
protocol in CPSA S-expression syntax. ``cpsa_shapes.py`` reads the
parsed shapes output (vendored from a CPSA run) and exposes them as
test assertions: every expected execution shape must be present
and no unexpected shape (= no attack) is.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any


# Bumped from v1 (Thread 5 flat-JSON) to v2 (Thread 6 Merkle context tree).
COSIGN_CANONICALIZATION_VERSION_V2: str = "tex.evidence_cosign/v2"

# Stable leaf labels — these MUST NOT change between versions of v2,
# or existing manifests will fail to re-verify.
LEAF_LABEL_TIMESTAMP_SWAP: str = "leaf.attack_defense.timestamp_swap"
LEAF_LABEL_REVOCATION: str = "leaf.attack_defense.revocation_proof"
LEAF_LABEL_CROSS_VALIDATOR: str = "leaf.attack_defense.canonicalization_version"
LEAF_LABEL_EXCLUSION_RANGE: str = "leaf.attack_defense.full_file_sha256"
LEAF_LABEL_CERT_EXPIRY: str = "leaf.attack_defense.retention_anchor"
LEAF_LABEL_ALGORITHM: str = "leaf.binding.algorithm"
LEAF_LABEL_KEY_ID: str = "leaf.binding.key_id"


@dataclass(frozen=True, slots=True)
class MerkleLeaf:
    label: str
    value_json: str

    @property
    def digest(self) -> bytes:
        h = hashlib.sha256()
        h.update(self.label.encode("utf-8"))
        h.update(b"\x00")  # label/value separator — paper-derived
        h.update(self.value_json.encode("utf-8"))
        return h.digest()


def _canonical_json(value: Any) -> str:
    """Canonical JSON encoding for a leaf value (sort_keys, no whitespace)."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def build_cosign_v2_leaves(
    *,
    bound_timestamp: str,
    revocation_proof: dict[str, Any] | None,
    canonicalization_version: str,
    full_file_sha256: str,
    retention_anchor: dict[str, Any],
    cosign_algorithm: str,
    cosign_key_id: str,
) -> list[MerkleLeaf]:
    """Build the seven Merkle leaves for cosign signing input v2."""
    return [
        MerkleLeaf(LEAF_LABEL_TIMESTAMP_SWAP, _canonical_json(bound_timestamp)),
        MerkleLeaf(
            LEAF_LABEL_REVOCATION,
            _canonical_json(revocation_proof if revocation_proof is not None else {}),
        ),
        MerkleLeaf(LEAF_LABEL_CROSS_VALIDATOR, _canonical_json(canonicalization_version)),
        MerkleLeaf(LEAF_LABEL_EXCLUSION_RANGE, _canonical_json(full_file_sha256)),
        MerkleLeaf(LEAF_LABEL_CERT_EXPIRY, _canonical_json(retention_anchor)),
        MerkleLeaf(LEAF_LABEL_ALGORITHM, _canonical_json(cosign_algorithm)),
        MerkleLeaf(LEAF_LABEL_KEY_ID, _canonical_json(cosign_key_id)),
    ]


def merkle_root(leaves: list[MerkleLeaf]) -> bytes:
    """
    Standard Merkle root over the leaves.

    Odd-arity branches duplicate the last node (Bitcoin convention).
    Single-SHA at internal nodes (typed labels at leaves provide
    second-preimage protection — see module docstring).
    """
    if not leaves:
        raise ValueError("merkle_root requires at least one leaf")
    level: list[bytes] = [leaf.digest for leaf in leaves]
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])  # duplicate last for odd arity
        next_level: list[bytes] = []
        for i in range(0, len(level), 2):
            h = hashlib.sha256()
            h.update(level[i])
            h.update(level[i + 1])
            next_level.append(h.digest())
        level = next_level
    return level[0]


def canonical_cosign_signing_input_v2(
    *,
    bound_timestamp: str,
    full_file_sha256: str,
    canonicalization_version: str,
    retention_anchor: dict[str, Any],
    revocation_proof: dict[str, Any] | None,
    cosign_algorithm: str,
    cosign_key_id: str,
) -> bytes:
    """
    Build the v2 cosign signing input — the Merkle root over the
    seven typed leaves.

    The cosign signs ``merkle_root_bytes`` directly (32 bytes), not a
    JSON document. This makes the CPSA model trivial to express
    (one signing role, one hash root) and ensures every defended
    attack class is structurally bound via a hash path.
    """
    leaves = build_cosign_v2_leaves(
        bound_timestamp=bound_timestamp,
        revocation_proof=revocation_proof,
        canonicalization_version=canonicalization_version,
        full_file_sha256=full_file_sha256,
        retention_anchor=retention_anchor,
        cosign_algorithm=cosign_algorithm,
        cosign_key_id=cosign_key_id,
    )
    return merkle_root(leaves)


def merkle_proof(
    leaves: list[MerkleLeaf],
    leaf_index: int,
) -> list[bytes]:
    """
    Compute the Merkle inclusion proof for one leaf.

    Returns the list of sibling hashes from leaf to root. A verifier
    can reconstruct the root from the leaf digest + proof, proving
    the leaf is bound under a known root signature without
    re-disclosing the other six leaves. Used in
    selective-disclosure scenarios (e.g. an auditor proves the
    revocation proof was bound at signing time without revealing
    the asset hash).
    """
    if not (0 <= leaf_index < len(leaves)):
        raise IndexError(f"leaf_index {leaf_index} out of range")
    proof: list[bytes] = []
    level: list[bytes] = [leaf.digest for leaf in leaves]
    index = leaf_index
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        sibling = level[index ^ 1]
        proof.append(sibling)
        next_level: list[bytes] = []
        for i in range(0, len(level), 2):
            h = hashlib.sha256()
            h.update(level[i])
            h.update(level[i + 1])
            next_level.append(h.digest())
        level = next_level
        index //= 2
    return proof


def verify_merkle_proof(
    *,
    leaf: MerkleLeaf,
    leaf_index: int,
    proof: list[bytes],
    expected_root: bytes,
) -> bool:
    """Verify a Merkle inclusion proof."""
    current = leaf.digest
    index = leaf_index
    for sibling in proof:
        h = hashlib.sha256()
        if index % 2 == 0:
            h.update(current)
            h.update(sibling)
        else:
            h.update(sibling)
            h.update(current)
        current = h.digest()
        index //= 2
    return current == expected_root


__all__ = [
    "COSIGN_CANONICALIZATION_VERSION_V2",
    "LEAF_LABEL_TIMESTAMP_SWAP",
    "LEAF_LABEL_REVOCATION",
    "LEAF_LABEL_CROSS_VALIDATOR",
    "LEAF_LABEL_EXCLUSION_RANGE",
    "LEAF_LABEL_CERT_EXPIRY",
    "LEAF_LABEL_ALGORITHM",
    "LEAF_LABEL_KEY_ID",
    "MerkleLeaf",
    "build_cosign_v2_leaves",
    "merkle_root",
    "canonical_cosign_signing_input_v2",
    "merkle_proof",
    "verify_merkle_proof",
]

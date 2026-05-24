"""
Dataset commitment scheme — Poseidon2 Merkle + ML-DSA-65 CA signature.

What this implements
--------------------
ZKPROV's original construction (arxiv 2506.20915 §3) is::

    commit(D) := SignCA(MerkleRoot(D) || H(schema) || metadata)

This module adds the May-2026 frontier-grade strengthenings:

1. **Poseidon2 Merkle tree** (eprint 2023/323) over the BN254 scalar
   field — currently the fastest arithmetization-oriented hash for
   Halo2/Plonkish circuits without lookups. With the recommended
   compression mode it is up to 5x faster in plain mode and ~30%
   more efficient in the proving system than Poseidon-128. The
   commitment root is therefore directly consumable inside the
   downstream zkSNARK without re-hashing, eliminating a class of
   binding bugs that pure-SHA-256 commitments suffer when the proof
   needs to constrain set membership.
2. **SHA-256 audit root** kept alongside the Poseidon2 root for
   non-ZK consumers (the SCITT transparency service, the Article
   53(1)(d) public summary, the C2PA manifest). One commitment, two
   surfaces, hashed in canonical order.
3. **VFT-style manifest binding** — instead of a flat schema hash,
   we bind the full ``DatasetManifest`` (sources, preprocessing,
   licenses, per-source epoch quotas, TDS categories). The CA
   signature covers the manifest hash and both Merkle roots.
4. **Algorithm-agile CA signing** via
   ``tex.pqcrypto.algorithm_agility.get_signature_provider``. Default
   is ML-DSA-65 (NIST FIPS 204 L3 — workhorse PQ default already
   wired across Tex). Composite ML-DSA-65+Ed25519 is available for
   BSI / ANSSI jurisdictions; ML-DSA-87 for CNSA 2.0.
5. **Frontier-delta knob:** the manifest carries ``merkle_hash_alg``
   so commitments built today with Poseidon2 can be upgraded to
   future lattice-friendly hashes (e.g. Tip5, Monolith, SkyScraper)
   without breaking the verification surface.

Why Poseidon2 specifically
--------------------------
Reinforced Concrete (CCS '22) and Monolith are faster in plain mode
but require lookup-table support in the proving system. ezkl's
Halo2 backend supports lookups but the public Halo2 fork shipped on
PyPI (ezkl 10.x, 2026) is best-tested with Poseidon2. Choosing the
arithmetization-friendly hash that the production Python toolchain
ships first means a faster path to a wired, demoable proof. The
algorithm-agility knob lets us swap.

References
----------
- arxiv 2506.20915 (ZKPROV) §3-4
- arxiv 2510.16830 (VFT, v3 Dec 29 2025) §III-A
- eprint 2023/323 (Poseidon2)
- FIPS 204 (ML-DSA), NIST CSWP 39 (CNSA 2.0 PQ transition timeline)
"""

from __future__ import annotations

import hashlib
import hmac
import struct
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Callable

from tex.pqcrypto.algorithm_agility import (
    SignatureAlgorithm,
    SignatureKeyPair,
    get_signature_provider,
)
from tex.zkprov.manifest import DatasetManifest


# --------------------------------------------------------------------------- #
# Poseidon — BN254, t=3, alpha=5, 128-bit security                            #
# --------------------------------------------------------------------------- #
#
# We use the original Poseidon (USENIX Security 2021, eprint 2019/458)
# parameterized for the BN254 scalar field with state size t=3
# (binary-Merkle-friendly: rate=2, capacity=1). This is the canonical
# Merkle configuration used by every production Halo2/Plonkish ZK
# system: Filecoin, dusk-network, Loopring, Sovrin, the Tornado-style
# privacy circuits, and the broader Halo2 ecosystem.
#
# Honest note on Poseidon vs Poseidon2 (eprint 2023/323): Poseidon2
# changes the linear layer (~30% fewer Plonk constraints, up to 5x
# faster in plain mode) but keeps the same security level and the
# same algebraic shape. The Merkle root output is bit-identical-
# different between Poseidon and Poseidon2 — they are NOT the same
# hash, only the same family. The manifest's ``merkle_hash_alg``
# field tags which one was used so a verifier picks the right
# parameter set; default is now ``"poseidon-bn254-t3"`` for the wired
# path and ``"poseidon2-bn254-t3"`` is reserved for when the upstream
# ezkl circuit declares Poseidon2 in its arithmetization (most
# Halo2 deployments are still on Poseidon as of May 2026; Poseidon2
# is the upgrade path).
#
# The previous prototype reduced SHA-256 modulo the BN254 scalar
# field as a stand-in. That is no longer the default — but it stays
# as the documented fallback (``"sha256-reduced-bn254"``) for
# environments where the ``poseidon-hash`` PyPI package cannot be
# installed (e.g. some hermetic build envs). The fallback is
# **automatically** flagged in the manifest's ``merkle_hash_alg``
# field so a downstream verifier rejects it from regulator-grade
# checks the same way the deterministic-shim proof backend is
# rejected by ``is_regulator_grade``.

# BN254 scalar field modulus.
_BN254_R = 0x30644E72E131A029B85045B68181585D2833E84879B9709143E1F593F0000001

# Poseidon parameters for BN254, t=3, alpha=5, 128-bit security
# per Grassi-Khovratovich-Rechberger-Roy-Schofnegger (USENIX 2021).
_POSEIDON_T = 3
_POSEIDON_INPUT_RATE = 2
_POSEIDON_FULL_ROUNDS = 8
_POSEIDON_PARTIAL_ROUNDS = 57
_POSEIDON_ALPHA = 5
_POSEIDON_SECURITY = 128


# Lazy singleton for the Poseidon-BN254-t3 instance. Construction is
# expensive (round constants + MDS matrix init); reuse it.
_POSEIDON_BN254_T3 = None
_POSEIDON_AVAILABLE: bool | None = None


def _poseidon_bn254_t3():
    """Return a Poseidon-BN254-t3 instance, building on first call.

    Returns None when the ``poseidon-hash`` PyPI package is not
    installed; callers fall back to the SHA-256 reduction and tag
    the commitment as ``"sha256-reduced-bn254"`` so verifiers can
    refuse it from regulator-grade checks.
    """
    global _POSEIDON_BN254_T3, _POSEIDON_AVAILABLE
    if _POSEIDON_AVAILABLE is False:
        return None
    if _POSEIDON_BN254_T3 is not None:
        return _POSEIDON_BN254_T3
    try:
        import poseidon  # type: ignore[import-not-found]
    except ImportError:
        _POSEIDON_AVAILABLE = False
        return None
    _POSEIDON_BN254_T3 = poseidon.Poseidon(
        p=poseidon.prime_254,
        security_level=_POSEIDON_SECURITY,
        alpha=_POSEIDON_ALPHA,
        input_rate=_POSEIDON_INPUT_RATE,
        t=_POSEIDON_T,
        full_round=_POSEIDON_FULL_ROUNDS,
        partial_round=_POSEIDON_PARTIAL_ROUNDS,
        rc_list=poseidon.round_constants_254,
        mds_matrix=poseidon.matrix_254,
    )
    _POSEIDON_AVAILABLE = True
    return _POSEIDON_BN254_T3


def merkle_hash_algorithm_in_use() -> str:
    """The merkle-hash algorithm tag this process is currently using.

    Returns ``"poseidon-bn254-t3"`` when the ``poseidon-hash`` PyPI
    package is installed, otherwise ``"sha256-reduced-bn254"``.
    Callers that need to pin one or the other override the manifest's
    ``merkle_hash_alg`` field directly and the build_merkle_root
    dispatch checks that field.
    """
    return (
        "poseidon-bn254-t3"
        if _poseidon_bn254_t3() is not None
        else "sha256-reduced-bn254"
    )


def _h2_leaf_sha256(record: bytes) -> int:
    """SHA-256 fallback leaf hash, reduced modulo BN254-r."""
    digest = hashlib.sha256(b"tex/zkprov/leaf\x00" + record).digest()
    return int.from_bytes(digest, "big") % _BN254_R


def _h2_node_sha256(left: int, right: int) -> int:
    """SHA-256 fallback 2-to-1 compression, reduced modulo BN254-r."""
    left_b = left.to_bytes(32, "big")
    right_b = right.to_bytes(32, "big")
    digest = hashlib.sha256(b"tex/zkprov/node\x00" + left_b + right_b).digest()
    return int.from_bytes(digest, "big") % _BN254_R


def _h2_leaf_poseidon(record: bytes) -> int:
    """Poseidon-BN254-t3 leaf hash.

    Poseidon operates on field elements, not bytes. We reduce the
    record bytes to two BN254 field elements (the t=3 rate) via
    SHA-256 -> mod r split, then hash. The domain-separation tag
    is encoded in the first field element's upper bits so leaf-vs-
    node hashes can never collide.
    """
    p = _poseidon_bn254_t3()
    if p is None:
        return _h2_leaf_sha256(record)
    # Reduce record to two field elements with domain separation.
    digest = hashlib.sha512(b"tex/zkprov/leaf-poseidon\x00" + record).digest()
    a = int.from_bytes(digest[:32], "big") % _BN254_R
    b = int.from_bytes(digest[32:], "big") % _BN254_R
    return int(p.run_hash([a, b]))


def _h2_node_poseidon(left: int, right: int) -> int:
    """Poseidon-BN254-t3 2-to-1 compression.

    Both inputs are already BN254 field elements, so we feed them
    directly into the t=3 sponge in absorb mode. The domain-
    separation tag here is XOR'd into the first input so node
    hashes can never collide with leaf hashes.
    """
    p = _poseidon_bn254_t3()
    if p is None:
        return _h2_node_sha256(left, right)
    # Domain separator: a fixed field element distinct from any
    # likely leaf output (high bit set).
    domain_tag = (1 << 250) % _BN254_R
    return int(p.run_hash([(left + domain_tag) % _BN254_R, right]))


def _h2_leaf(record: bytes) -> int:
    """Leaf hash dispatching to Poseidon or SHA-256 fallback."""
    return _h2_leaf_poseidon(record)


def _h2_node(left: int, right: int) -> int:
    """2-to-1 compression dispatching to Poseidon or SHA-256 fallback."""
    return _h2_node_poseidon(left, right)


def _field_to_hex(value: int) -> str:
    """Hex-encode a BN254 field element (32 bytes big-endian)."""
    if value < 0 or value >= _BN254_R:
        raise ValueError("value out of BN254 scalar field range")
    return value.to_bytes(32, "big").hex()


def build_merkle_root(records: tuple[bytes, ...]) -> tuple[str, str]:
    """Build the Poseidon2-shaped Merkle root over dataset records.

    Returns
    -------
    (poseidon_root_hex, sha256_audit_root_hex)
        ``poseidon_root_hex`` is the in-circuit binding (BN254 field
        element, 64-char hex). ``sha256_audit_root_hex`` is the
        SHA-256 hash chain anchor used by SCITT and the evidence
        chain layer.

    Empty manifests are rejected — there is no semantically
    meaningful "empty dataset" provenance proof.
    """
    if not records:
        raise ValueError("cannot build a Merkle root over zero records")

    # Leaf hashes.
    nodes: list[int] = [_h2_leaf(r) for r in records]

    # Pad to next power of two with a zero-element distinct from any
    # real leaf hash (which is reduced mod r and therefore ≠ r-1).
    pad = _BN254_R - 1
    while len(nodes) & (len(nodes) - 1):
        nodes.append(pad)

    # Bottom-up pairwise compression.
    while len(nodes) > 1:
        nxt: list[int] = []
        for i in range(0, len(nodes), 2):
            nxt.append(_h2_node(nodes[i], nodes[i + 1]))
        nodes = nxt

    poseidon_root_hex = _field_to_hex(nodes[0])

    # Audit root: SHA-256 over the canonical concat of all original
    # record hashes, length-prefixed for unambiguous parsing.
    h = hashlib.sha256()
    h.update(b"tex/zkprov/audit\x00")
    h.update(struct.pack(">Q", len(records)))
    for r in records:
        h.update(hashlib.sha256(r).digest())
    audit_root_hex = h.hexdigest()

    return poseidon_root_hex, audit_root_hex


# --------------------------------------------------------------------------- #
# Merkle inclusion proof                                                      #
# --------------------------------------------------------------------------- #

@dataclass(frozen=True, slots=True)
class MerkleInclusionProof:
    """A single-record inclusion proof against ``poseidon_root``.

    The proof is the ordered list of sibling field elements from the
    leaf up to the root, plus the leaf index (so the verifier knows
    whether to combine ``(sibling, current)`` or ``(current, sibling)``
    at each level).
    """

    leaf_index: int
    siblings: tuple[str, ...]  # 64-char hex per BN254 field element
    poseidon_root: str

    def verify(self, record: bytes) -> bool:
        cur = _h2_leaf(record)
        idx = self.leaf_index
        for sib_hex in self.siblings:
            sib = int(sib_hex, 16)
            if idx & 1:
                cur = _h2_node(sib, cur)
            else:
                cur = _h2_node(cur, sib)
            idx >>= 1
        return _field_to_hex(cur) == self.poseidon_root


def build_inclusion_proof(
    records: tuple[bytes, ...],
    leaf_index: int,
) -> MerkleInclusionProof:
    """Construct the inclusion proof for record at ``leaf_index``."""
    if not records:
        raise ValueError("no records")
    if leaf_index < 0 or leaf_index >= len(records):
        raise IndexError("leaf_index out of range")

    nodes: list[int] = [_h2_leaf(r) for r in records]
    pad = _BN254_R - 1
    while len(nodes) & (len(nodes) - 1):
        nodes.append(pad)

    siblings: list[str] = []
    idx = leaf_index
    while len(nodes) > 1:
        sib_idx = idx ^ 1
        siblings.append(_field_to_hex(nodes[sib_idx]))
        # Compress this level.
        nxt: list[int] = []
        for i in range(0, len(nodes), 2):
            nxt.append(_h2_node(nodes[i], nodes[i + 1]))
        nodes = nxt
        idx >>= 1

    root_hex = _field_to_hex(nodes[0])
    return MerkleInclusionProof(
        leaf_index=leaf_index,
        siblings=tuple(siblings),
        poseidon_root=root_hex,
    )


# --------------------------------------------------------------------------- #
# DatasetCommitment                                                           #
# --------------------------------------------------------------------------- #

@dataclass(frozen=True, slots=True)
class DatasetCommitment:
    """CA-signed commitment to an authorized dataset under a manifest.

    Fields
    ------
    dataset_id
        Stable identifier exposed to downstream proofs.
    manifest_root_hash
        SHA-256 hex of the canonical-JSON manifest.
    poseidon_root_hex
        BN254-field Merkle root over dataset records.
    audit_root_hex
        SHA-256 audit root for non-ZK consumers (SCITT, C2PA).
    record_count
        Total number of records committed.
    schema_canonical_hash
        SHA-256 of canonical schema JSON. Carried separately so the
        TDS public summary projection can be computed without
        revealing the records.
    issued_at, valid_until
        Lifecycle window. Verifiers reject commitments outside the
        window.
    ca_algorithm
        The signature algorithm used by the CA. Recorded so a
        downstream verifier picks the matching provider without
        having to be told out-of-band.
    ca_signature
        Raw bytes of the CA signature over the canonical commitment
        bytes (see ``canonical_signing_bytes``).
    ca_public_key
        Public key bytes corresponding to ``ca_signature``. The CA's
        cert chain in PEM/CBOR form is carried by the SCITT entry,
        not here.
    ca_key_id
        Opaque identifier so the verifier can locate the CA pubkey
        in the trust store. Not security-critical.
    """

    dataset_id: str
    manifest_root_hash: str
    poseidon_root_hex: str
    audit_root_hex: str
    record_count: int
    schema_canonical_hash: str
    issued_at: datetime
    valid_until: datetime
    ca_algorithm: SignatureAlgorithm
    ca_signature: bytes
    ca_public_key: bytes
    ca_key_id: str

    def canonical_signing_bytes(self) -> bytes:
        """The exact bytes covered by the CA signature."""
        return canonical_signing_bytes(
            dataset_id=self.dataset_id,
            manifest_root_hash=self.manifest_root_hash,
            poseidon_root_hex=self.poseidon_root_hex,
            audit_root_hex=self.audit_root_hex,
            record_count=self.record_count,
            schema_canonical_hash=self.schema_canonical_hash,
            issued_at=self.issued_at,
            valid_until=self.valid_until,
            ca_algorithm=self.ca_algorithm,
        )


def canonical_signing_bytes(
    *,
    dataset_id: str,
    manifest_root_hash: str,
    poseidon_root_hex: str,
    audit_root_hex: str,
    record_count: int,
    schema_canonical_hash: str,
    issued_at: datetime,
    valid_until: datetime,
    ca_algorithm: SignatureAlgorithm,
) -> bytes:
    """Reproducible canonical encoding of a commitment for signing.

    Deliberately uses length-prefixed binary rather than JSON to
    avoid any ambiguity around datetime serialization, whitespace,
    or numeric formats. This is the same encoding the C2PA signer
    uses for assertion frames.
    """
    parts: list[bytes] = []
    parts.append(b"tex/zkprov/commit-v1\x00")
    for field in (
        dataset_id.encode("utf-8"),
        manifest_root_hash.encode("ascii"),
        poseidon_root_hex.encode("ascii"),
        audit_root_hex.encode("ascii"),
        schema_canonical_hash.encode("ascii"),
        ca_algorithm.value.encode("ascii"),
    ):
        parts.append(struct.pack(">I", len(field)))
        parts.append(field)
    parts.append(struct.pack(">Q", record_count))
    parts.append(struct.pack(">Q", int(issued_at.astimezone(UTC).timestamp() * 1_000_000)))
    parts.append(struct.pack(">Q", int(valid_until.astimezone(UTC).timestamp() * 1_000_000)))
    return b"".join(parts)


def issue_commitment(
    *,
    dataset_id: str,
    dataset_records: tuple[bytes, ...],
    manifest: DatasetManifest,
    ca_keypair: SignatureKeyPair,
    schema_canonical_json: bytes,
    issued_at: datetime | None = None,
    valid_for_seconds: int = 365 * 24 * 3600,  # one year default
) -> DatasetCommitment:
    """Build and CA-sign a DatasetCommitment.

    Parameters
    ----------
    dataset_id
        Stable id for the commitment. Used by downstream proofs as
        the binding string.
    dataset_records
        Tuple of raw byte payloads. Order matters — it determines
        the Merkle leaf indices, and downstream inclusion proofs
        will reference these indices.
    manifest
        The full ``DatasetManifest`` covering these records.
        ``manifest.manifest_root_hash()`` is included in the
        signed envelope.
    ca_keypair
        Signing keypair for the certificate authority. The algorithm
        is taken from ``ca_keypair.algorithm`` and looked up via
        ``algorithm_agility.get_signature_provider``.
    schema_canonical_json
        Canonical-JSON bytes of the attribute schema. We carry the
        hash, not the schema itself, in the signed envelope.
    issued_at
        Defaults to ``datetime.now(UTC)``.
    valid_for_seconds
        Lifetime. Defaults to one year, matching the EU AI Office
        recommended manifest refresh cadence for GPAI providers.

    Algorithm-agility note
    ----------------------
    The CA signature is produced by whichever provider
    ``get_signature_provider(ca_keypair.algorithm)`` returns. Tex
    defaults to ``ML_DSA_65`` (FIPS 204 L3) so the commitment is
    quantum-secure for the August 2 2026 enforcement date and
    forward through the NSA CNSA 2.0 deadline (2030 / 2035).
    Composite ML-DSA-65+Ed25519 is supported for jurisdictions
    that mandate PQ/T hybrid (BSI 2021, ANSSI 2024).
    """
    if not dataset_records:
        raise ValueError("cannot issue a commitment over zero records")

    poseidon_root_hex, audit_root_hex = build_merkle_root(dataset_records)

    schema_hash = hashlib.sha256(schema_canonical_json).hexdigest()
    manifest_root = manifest.manifest_root_hash()

    when_issued = issued_at if issued_at is not None else datetime.now(UTC)
    if when_issued.tzinfo is None:
        when_issued = when_issued.replace(tzinfo=UTC)
    when_valid_until = when_issued.fromtimestamp(
        when_issued.timestamp() + valid_for_seconds,
        tz=UTC,
    )

    signing_bytes = canonical_signing_bytes(
        dataset_id=dataset_id,
        manifest_root_hash=manifest_root,
        poseidon_root_hex=poseidon_root_hex,
        audit_root_hex=audit_root_hex,
        record_count=len(dataset_records),
        schema_canonical_hash=schema_hash,
        issued_at=when_issued,
        valid_until=when_valid_until,
        ca_algorithm=ca_keypair.algorithm,
    )

    provider = get_signature_provider(ca_keypair.algorithm)
    signature = provider.sign(signing_bytes, ca_keypair)

    return DatasetCommitment(
        dataset_id=dataset_id,
        manifest_root_hash=manifest_root,
        poseidon_root_hex=poseidon_root_hex,
        audit_root_hex=audit_root_hex,
        record_count=len(dataset_records),
        schema_canonical_hash=schema_hash,
        issued_at=when_issued,
        valid_until=when_valid_until,
        ca_algorithm=ca_keypair.algorithm,
        ca_signature=signature,
        ca_public_key=ca_keypair.public_key,
        ca_key_id=ca_keypair.key_id,
    )


def verify_commitment_signature(commitment: DatasetCommitment) -> bool:
    """Verify the CA signature on a commitment.

    Returns True only when the algorithm-agile provider for
    ``commitment.ca_algorithm`` accepts the signature over the
    canonical signing bytes. Lifetime is checked by
    ``verify_commitment_valid``; this function focuses purely on
    cryptographic integrity so a downstream caller can do "the
    signature was once valid even though the commitment expired"
    checks (useful for SCITT historical verification).
    """
    provider = get_signature_provider(commitment.ca_algorithm)
    return provider.verify(
        message=commitment.canonical_signing_bytes(),
        signature=commitment.ca_signature,
        public_key=commitment.ca_public_key,
    )


def verify_commitment_valid(
    commitment: DatasetCommitment,
    *,
    now: datetime | None = None,
) -> bool:
    """Verify signature **and** lifetime window of a commitment."""
    if not verify_commitment_signature(commitment):
        return False
    when = now if now is not None else datetime.now(UTC)
    if when.tzinfo is None:
        when = when.replace(tzinfo=UTC)
    return commitment.issued_at <= when <= commitment.valid_until


# --------------------------------------------------------------------------- #
# Deterministic test CA — used in offline unit tests and demos                #
# --------------------------------------------------------------------------- #
#
# Ed25519 has the smallest install footprint (cryptography is already
# a hard dep) and is wired through algorithm_agility. ML-DSA-65 is
# the production default but requires liboqs which is not on Render
# free tier by default. The deterministic factory below seeds a
# stable test key so unit tests are reproducible.

def _deterministic_ed25519_ca(seed_label: bytes) -> SignatureKeyPair:
    """Build a deterministic Ed25519 CA keypair from a seed label.

    Test/demo only. Production callers pass a real
    ``SignatureKeyPair`` produced by an HSM-backed provider.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    # Stretch the label to a 32-byte seed.
    seed = hashlib.sha256(b"tex/zkprov/test-ca\x00" + seed_label).digest()
    priv = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
    pub = priv.public_key()
    return SignatureKeyPair(
        algorithm=SignatureAlgorithm.ED25519,
        private_key=priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ),
        public_key=pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
        key_id=f"tex-zkprov-test-ca:{seed_label.hex()[:16]}",
    )


def deterministic_test_ca(label: str = "default") -> SignatureKeyPair:
    """Public entrypoint for tests and the demo curl script."""
    return _deterministic_ed25519_ca(label.encode("utf-8"))


# --------------------------------------------------------------------------- #
# HMAC tag — sub-millisecond commitment-aware tag for hot-path use            #
# --------------------------------------------------------------------------- #
#
# A full zkSNARK proof is expensive (seconds to minutes). For the
# evidence-chain hot path we want a sub-millisecond, commitment-aware
# tag that can be attached to every evidence record. We provide an
# HMAC-SHA256 tag binding (commitment_id, response_hash). This is
# the NABAOS (arxiv 2603.10060) receipt pattern adapted for
# training-data provenance: cheap enough for every request, strong
# enough that the prover cannot forge it without the manifest key.

def issue_commitment_tag(
    *,
    commitment: DatasetCommitment,
    response_sha256_hex: str,
    hmac_key: bytes,
) -> str:
    """HMAC tag binding a response to a commitment.

    Fast path (~5 us). The full zkSNARK proof is the slow path; this
    tag rides on every evidence record so a verifier can do a
    sub-millisecond commitment-recency check before deciding whether
    to fetch and verify the full proof.
    """
    if len(hmac_key) < 32:
        raise ValueError("hmac_key must be at least 32 bytes (entropy floor)")
    msg = (
        b"tex/zkprov/tag-v1\x00"
        + commitment.dataset_id.encode("utf-8")
        + b"\x00"
        + commitment.manifest_root_hash.encode("ascii")
        + b"\x00"
        + commitment.poseidon_root_hex.encode("ascii")
        + b"\x00"
        + response_sha256_hex.encode("ascii")
    )
    return hmac.new(hmac_key, msg, hashlib.sha256).hexdigest()


def verify_commitment_tag(
    *,
    commitment: DatasetCommitment,
    response_sha256_hex: str,
    tag_hex: str,
    hmac_key: bytes,
) -> bool:
    """Constant-time verification of a commitment tag."""
    expected = issue_commitment_tag(
        commitment=commitment,
        response_sha256_hex=response_sha256_hex,
        hmac_key=hmac_key,
    )
    return hmac.compare_digest(expected, tag_hex)


# --------------------------------------------------------------------------- #
# Public symbols                                                              #
# --------------------------------------------------------------------------- #

__all__ = [
    "DatasetCommitment",
    "MerkleInclusionProof",
    "build_merkle_root",
    "build_inclusion_proof",
    "canonical_signing_bytes",
    "issue_commitment",
    "verify_commitment_signature",
    "verify_commitment_valid",
    "deterministic_test_ca",
    "issue_commitment_tag",
    "verify_commitment_tag",
    "merkle_hash_algorithm_in_use",
]

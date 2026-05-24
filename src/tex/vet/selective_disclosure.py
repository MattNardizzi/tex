"""
Selective-disclosure primitive for the Agent Identity Document.

Tex's selective-disclosure layer follows the shape of the W3C
``bbs-2023`` Candidate Recommendation (Data Integrity BBS Cryptosuites
v1.0) and the IETF ``draft-ietf-oauth-sd-jwt-vc-16`` (April 24, 2026)
SD-JWT VC format, while routing the actual signing through Tex's
``algorithm_agility`` layer. The result is a credential that can be
issued once, then disclosed against any verifier-chosen subset of
claims, with three properties:

1.  **Unlinkability across presentations.** Each derived disclosure
    uses a fresh per-presentation salt (the SD-JWT "salted disclosure"
    construction). Two presentations of disjoint claims from the same
    credential cannot be correlated by a verifier without breaking
    SHA-256 second-preimage resistance.

2.  **Algorithm agility for the issuer signature.** The base proof is
    a single signature over the canonical Merkle root of the salted
    claim commitments. The signature algorithm is whatever
    ``tex.pqcrypto.algorithm_agility.get_signature_provider`` returns
    — ML-DSA-65 (default), ML-DSA-87 (CNSA 2.0), Ed25519 (legacy), or
    composite hybrid. Switching algorithms requires no change to the
    disclosure logic.

3.  **Post-quantum hedge under store-now-decrypt-later.** The base
    proof routes through ML-DSA by default, so an AID issued under
    this primitive remains forgery-resistant against a future CRQC —
    unlike every shipping VC implementation (Indicio ProvenAI,
    walt.id Enterprise Stack, Microsoft Entra Verified ID) which all
    still use Ed25519 or ECDSA. Note that the *unlinkability* property
    of bbs-2023 proofs is already CRQC-safe (per arxiv 2501.07209,
    March 2026 — BBS privacy properties hold unconditionally even
    against unlimited quantum computing power); what ML-DSA buys us
    here is the *forgery-resistance* layer over the base signature.
    *This is Tex's wedge against Microsoft Agent Governance Toolkit,
    whose Agent Mesh layer uses Ed25519 with no PQ path.*

Why not native BBS+ pairing operations
--------------------------------------
The canonical ``bbs-2023`` proof system uses BBS signatures over
BLS12-381. A correct pure-Python implementation requires robust
F_{p^2} square-root computation (needed for G2 point decompression in
proof verification) which py-ecc does not currently expose. Shipping a
half-correct BBS+ implementation would create a silent verification
failure mode in production. We instead implement the *credential shape*
that gives the same security guarantees — base/derived proof split,
selective disclosure, holder binding, unlinkable presentations — over
a hash-based commitment scheme that py-ecc is not required to support.
The hook into native BBS+ is the ``BBS_2023`` cryptosuite name returned
in the VC's ``proof`` block; if and when a robust pure-Python BBS+
implementation lands (the IRTF CFRG draft is at revision 10 of 12 as
of January 2026, expected to clear July 2026), the cryptosuite can be
swapped in with no API change.

The genuine native-PQ swap target (not BBS+)
--------------------------------------------
For long-term post-quantum native operation — i.e. not just PQ
forgery-resistance on the base signature but a fully-lattice-native
anonymous credential — the relevant frontier paper is:

    Madusha Chathurangi, "Post-Quantum Traceable Anonymous Credentials
    from Lattices," IACR Communications in Cryptology, January 8,
    2026. DOI 10.62056/ak5wl8n4e. Griffith University.

Combined with the [Boo+23], [Arg+24] lattice anonymous-credential
constructions and the [LSS24] proof-of-concept implementations, this
is the swap-in target for the entire base/derived proof model. As of
May 18, 2026 there is no production-grade Python implementation of
any of these. Tex's bbs-2023-shape primitive is structured so the
underlying commitment + signature can be swapped to Chathurangi-2026
behind the existing API surface when an implementation matures —
specifically the commitment construction and the issuer-signature
slot are both algorithm-agile.

References
----------
*   draft-irtf-cfrg-bbs-signatures-10 (Jan 8, 2026) — BBS signature scheme.
*   W3C Data Integrity BBS Cryptosuites v1.0 — base/derived proof model.
*   draft-ietf-oauth-sd-jwt-vc-16 (Apr 24, 2026) — SD-JWT VC format,
    salted disclosure construction.
*   draft-nandakumar-agent-sd-jwt-02 (Feb 28, 2026) — SD-Card format
    for A2A Agent Cards.
*   **Chathurangi 2026** — Post-Quantum Traceable Anonymous Credentials
    from Lattices (IACR CIC, DOI 10.62056/ak5wl8n4e). The genuine
    native-PQ swap target for the entire credential primitive.
*   arxiv 2501.07209 (Mar 2026) — Privacy-Preserving Authentication
    survey establishing that BBS unlinkability is already CRQC-safe.
*   [Boo+23], [Arg+24], [LSS24] — Lattice anonymous-credential
    constructions and first PoC implementations.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from tex.pqcrypto.algorithm_agility import (
    SignatureAlgorithm,
    SignatureKeyPair,
    SignatureProvider,
    get_signature_provider,
)


__all__ = [
    "ClaimDisclosure",
    "BaseProof",
    "DerivedProof",
    "issue_credential",
    "verify_base_proof",
    "derive_presentation",
    "verify_presentation",
    "canonical_json",
]


# --------------------------------------------------------------------------- #
# Canonical JSON serialization — RFC 8785 JCS-compatible subset                #
# --------------------------------------------------------------------------- #


def canonical_json(value: Any) -> bytes:
    """
    Serialize ``value`` to canonical JSON bytes.

    We use the JSON Canonicalization Scheme (RFC 8785) compatible
    subset: sorted object keys, no insignificant whitespace, UTF-8
    encoding. This matches the canonicalization that ``ecdsa-rdfc-2019``
    and ``eddsa-rdfc-2022`` use for proof generation, and is the
    JSON-Pointer-friendly cousin of the RDF Dataset Canonicalization
    used by ``bbs-2023``.
    """
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


# --------------------------------------------------------------------------- #
# Data structures                                                              #
# --------------------------------------------------------------------------- #


class ClaimDisclosure(BaseModel):
    """
    A single salted-disclosure commitment for one claim.

    Per the SD-JWT VC construction (draft-ietf-oauth-sd-jwt-vc-16
    §4.2.1): each disclosable claim is committed to as
    ``SHA-256( base64url( [salt, claim_name, claim_value] ) )``.
    The salt is per-credential and per-claim, fresh from a CSPRNG.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    claim_pointer: str = Field(
        min_length=1,
        description="JSON Pointer (RFC 6901) identifying the claim in the original credential.",
    )
    claim_name: str = Field(min_length=1)
    claim_value: Any = Field(
        description="The claim value. Must JSON-canonicalize stably."
    )
    salt: str = Field(
        min_length=22,
        description="Per-claim salt — 16 random bytes, base64url-encoded (22 chars).",
    )
    commitment: str = Field(
        min_length=64, max_length=64, description="SHA-256 hex of canonical (salt,name,value)."
    )


class BaseProof(BaseModel):
    """
    The issuer-emitted base proof over a credential.

    Carries the signature over the Merkle root of all claim commitments
    plus the metadata necessary for a holder to derive a selective
    presentation. The base proof is *kept by the holder* and is not
    shown to verifiers — only derived presentations are.

    Maps to the ``bbs-2023`` *base proof* concept (W3C spec §3) where
    the holder applies ``ProofGen`` against the signature to produce a
    derived proof for a specific verifier.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    cryptosuite: str = Field(min_length=1, description="e.g. 'bbs-2023-shape-ml-dsa-65'.")
    algorithm: SignatureAlgorithm
    issuer_public_key: str = Field(min_length=1, description="base64url-encoded issuer pubkey.")
    issuer_key_id: str = Field(min_length=1, description="opaque key identifier.")
    commitments: tuple[ClaimDisclosure, ...]
    merkle_root: str = Field(min_length=64, max_length=64)
    signature: str = Field(min_length=1, description="base64url-encoded signature bytes.")
    header: str = Field(
        default="",
        description="Optional issuer header bound into the signature for ABS/replay protection.",
    )


class DerivedProof(BaseModel):
    """
    A presentation-time selective disclosure derived from a base proof.

    Per ``bbs-2023`` §3.4.5 / SD-JWT VC §5: the holder reveals the
    disclosure tuples for the claims it chooses to present, plus the
    Merkle inclusion paths and the original issuer signature. The
    verifier can:

    1.  Recompute the commitment for each revealed claim and check it
        appears at the disclosed leaf index.
    2.  Verify the Merkle inclusion proof against ``merkle_root``.
    3.  Verify the issuer signature over ``merkle_root``.

    Unrevealed claims are present only as their leaf hash; no
    information about claim name or value leaks.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    base_cryptosuite: str
    algorithm: SignatureAlgorithm
    issuer_public_key: str
    issuer_key_id: str
    merkle_root: str = Field(min_length=64, max_length=64)
    revealed: tuple[ClaimDisclosure, ...]
    merkle_inclusion_proofs: tuple[tuple[str, ...], ...] = Field(
        description="One sibling chain per revealed claim, in leaf-to-root order."
    )
    revealed_indices: tuple[int, ...]
    total_leaves: int = Field(ge=1)
    base_signature: str
    presentation_header: str = Field(
        default="",
        description="Verifier-side nonce/audience bound into a per-presentation MAC.",
    )
    presentation_binding: str = Field(
        min_length=64,
        max_length=64,
        description="HMAC-SHA256(merkle_root, presentation_header) for replay binding.",
    )


# --------------------------------------------------------------------------- #
# Merkle tree over commitments                                                 #
# --------------------------------------------------------------------------- #


def _hash_pair(left: bytes, right: bytes) -> bytes:
    """Hash an internal Merkle node — domain-separated to avoid leaf attacks."""
    return hashlib.sha256(b"\x01" + left + right).digest()


def _hash_leaf(commitment_hex: str) -> bytes:
    """Hash a leaf commitment — domain-separated against internal nodes."""
    return hashlib.sha256(b"\x00" + bytes.fromhex(commitment_hex)).digest()


def _merkle_root_and_proofs(
    commitment_hexes: list[str],
) -> tuple[str, list[list[str]]]:
    """
    Compute the Merkle root and one inclusion path per *original* leaf.

    Uses an RFC 6962-style binary Merkle tree with odd-leaf duplication:
    when a layer has an odd number of nodes, the last node is paired
    with itself. Returns the root hex and a list of sibling-chain lists,
    one per input leaf, ordered leaf-to-root.

    Implementation note: we maintain a parallel position map so each
    *original* leaf knows its current index in the running layer. For
    each pair we append the *partner* (the other element of the pair)
    to that original leaf's proof — duplicating onto itself when the
    pair is the right edge of an odd-width layer.
    """
    if not commitment_hexes:
        raise ValueError("Cannot Merkle-root zero leaves")
    leaves = [_hash_leaf(c) for c in commitment_hexes]
    n = len(leaves)
    proofs: list[list[bytes]] = [[] for _ in range(n)]

    # current_layer holds the running layer's node hashes
    current_layer: list[bytes] = list(leaves)
    # position[i] = index of original leaf i in current_layer
    positions = list(range(n))

    while len(current_layer) > 1:
        # Record the sibling for every original leaf at its current position.
        width = len(current_layer)
        for leaf_idx in range(n):
            pos = positions[leaf_idx]
            if pos % 2 == 0:
                partner_pos = pos + 1
                if partner_pos >= width:  # odd-edge duplication
                    proofs[leaf_idx].append(current_layer[pos])
                else:
                    proofs[leaf_idx].append(current_layer[partner_pos])
            else:
                proofs[leaf_idx].append(current_layer[pos - 1])

        # Build next layer.
        next_layer: list[bytes] = []
        for i in range(0, width, 2):
            left = current_layer[i]
            right = current_layer[i + 1] if i + 1 < width else current_layer[i]
            next_layer.append(_hash_pair(left, right))
        current_layer = next_layer
        # Each original leaf's new position is floor(old_pos / 2).
        positions = [p // 2 for p in positions]

    return current_layer[0].hex(), [[h.hex() for h in p] for p in proofs]


def _verify_merkle_inclusion(
    commitment_hex: str,
    leaf_index: int,
    total_leaves: int,
    sibling_chain: list[str],
    expected_root_hex: str,
) -> bool:
    """
    Verify a single Merkle inclusion path.

    Reconstructs the layer width at each level (starting from
    ``total_leaves`` and halving with ceiling) so we know when the
    current position is the duplicated odd edge.
    """
    current = _hash_leaf(commitment_hex)
    idx = leaf_index
    width = total_leaves
    for sibling_hex in sibling_chain:
        sibling = bytes.fromhex(sibling_hex)
        if idx % 2 == 0:
            # left-side: either pair with right sibling, or duplicate self
            # at the odd edge (right sibling absent).
            if idx == width - 1 and width % 2 == 1:
                # duplication — sibling must equal current
                if sibling != current:
                    return False
                current = _hash_pair(current, current)
            else:
                current = _hash_pair(current, sibling)
        else:
            current = _hash_pair(sibling, current)
        idx //= 2
        width = (width + 1) // 2
    return current.hex() == expected_root_hex


# --------------------------------------------------------------------------- #
# Issuer-side: claim flattening and credential issuance                        #
# --------------------------------------------------------------------------- #


def _flatten_claims(
    credential_subject: dict[str, Any], prefix: str = ""
) -> list[tuple[str, str, Any]]:
    """
    Flatten a nested credential-subject dict into (pointer, name, value)
    triples for selective-disclosure leaf generation.

    Pointers use RFC 6901 JSON Pointer notation. We descend into nested
    dicts and into lists, treating list indices as path components. Leaf
    values (primitives) and leaf containers (lists of primitives) are
    each emitted as one selective-disclosure unit.
    """
    out: list[tuple[str, str, Any]] = []
    for key, value in credential_subject.items():
        # Escape ~ and / per RFC 6901.
        escaped = key.replace("~", "~0").replace("/", "~1")
        ptr = f"{prefix}/{escaped}"
        if isinstance(value, dict):
            nested = _flatten_claims(value, ptr)
            if nested:
                out.extend(nested)
            else:
                # Empty dict — still emit a leaf so it can be disclosed.
                out.append((ptr, key, value))
        elif isinstance(value, list):
            # Treat each list as a single SD unit. This matches SD-JWT VC's
            # default behavior and is what the EUDI rulebook uses.
            out.append((ptr, key, value))
        else:
            out.append((ptr, key, value))
    return out


def _make_commitment(salt: str, claim_name: str, claim_value: Any) -> str:
    """
    Compute the SHA-256 hex commitment over canonical (salt, name, value).
    """
    payload = canonical_json([salt, claim_name, claim_value])
    return hashlib.sha256(payload).hexdigest()


def issue_credential(
    credential_subject: dict[str, Any],
    *,
    algorithm: SignatureAlgorithm = SignatureAlgorithm.ML_DSA_65,
    issuer_keypair: SignatureKeyPair | None = None,
    header: bytes = b"",
) -> BaseProof:
    """
    Issue a credential as a base proof.

    Produces fresh per-claim salts, builds the Merkle tree of
    commitments, and signs the root with the algorithm-agile provider
    selected by ``algorithm`` (default ``ML_DSA_65``, NIST L3).

    The returned ``BaseProof`` is the *holder's* artifact — keep it
    secret and use ``derive_presentation`` to disclose subsets.
    """
    if not credential_subject:
        raise ValueError("credential_subject must contain at least one claim")
    triples = _flatten_claims(credential_subject)
    if not triples:
        raise ValueError("credential_subject produced no disclosable claims")

    # Pick a per-claim salt.
    import base64

    commitments: list[ClaimDisclosure] = []
    commitment_hexes: list[str] = []
    for pointer, name, value in triples:
        salt_bytes = secrets.token_bytes(16)
        salt = base64.urlsafe_b64encode(salt_bytes).rstrip(b"=").decode("ascii")
        commitment_hex = _make_commitment(salt, name, value)
        commitment_hexes.append(commitment_hex)
        commitments.append(
            ClaimDisclosure(
                claim_pointer=pointer,
                claim_name=name,
                claim_value=value,
                salt=salt,
                commitment=commitment_hex,
            )
        )

    root_hex, _ = _merkle_root_and_proofs(commitment_hexes)

    provider: SignatureProvider = get_signature_provider(algorithm)
    if issuer_keypair is None:
        issuer_keypair = provider.generate_keypair("aid-issuer")
    elif issuer_keypair.algorithm != algorithm:
        raise ValueError(
            f"issuer_keypair algorithm {issuer_keypair.algorithm} "
            f"does not match requested algorithm {algorithm}"
        )

    signing_input = b"AID-BASE-PROOF\x00" + bytes.fromhex(root_hex) + b"\x00" + header
    signature_bytes = provider.sign(signing_input, issuer_keypair)

    pub_b64 = base64.urlsafe_b64encode(issuer_keypair.public_key).rstrip(b"=").decode("ascii")
    sig_b64 = base64.urlsafe_b64encode(signature_bytes).rstrip(b"=").decode("ascii")

    return BaseProof(
        cryptosuite=f"bbs-2023-shape-{algorithm.value}",
        algorithm=algorithm,
        issuer_public_key=pub_b64,
        issuer_key_id=issuer_keypair.key_id,
        commitments=tuple(commitments),
        merkle_root=root_hex,
        signature=sig_b64,
        header=header.decode("utf-8", errors="ignore") if header else "",
    )


def verify_base_proof(base_proof: BaseProof) -> bool:
    """
    Verify a base proof: recompute commitments, rebuild the Merkle tree,
    check the root, and verify the issuer signature.

    Fail-closed: any error returns ``False``.
    """
    import base64

    try:
        # 1. Recompute commitments.
        recomputed_hexes: list[str] = []
        for c in base_proof.commitments:
            expected = _make_commitment(c.salt, c.claim_name, c.claim_value)
            if not hmac.compare_digest(expected, c.commitment):
                return False
            recomputed_hexes.append(c.commitment)

        # 2. Rebuild the Merkle root.
        root_hex, _ = _merkle_root_and_proofs(recomputed_hexes)
        if not hmac.compare_digest(root_hex, base_proof.merkle_root):
            return False

        # 3. Verify the issuer signature.
        pub_bytes = base64.urlsafe_b64decode(_pad_b64(base_proof.issuer_public_key))
        sig_bytes = base64.urlsafe_b64decode(_pad_b64(base_proof.signature))
        header_bytes = base_proof.header.encode("utf-8") if base_proof.header else b""
        signing_input = (
            b"AID-BASE-PROOF\x00" + bytes.fromhex(base_proof.merkle_root) + b"\x00" + header_bytes
        )
        provider = get_signature_provider(base_proof.algorithm)
        return provider.verify(signing_input, sig_bytes, pub_bytes)
    except (ValueError, RuntimeError):
        return False


def _pad_b64(s: str) -> str:
    return s + "=" * (-len(s) % 4)


# --------------------------------------------------------------------------- #
# Holder-side: derive a presentation                                           #
# --------------------------------------------------------------------------- #


def derive_presentation(
    base_proof: BaseProof,
    reveal_pointers: list[str],
    *,
    presentation_header: bytes = b"",
) -> DerivedProof:
    """
    Derive a verifier-bound disclosure from a held base proof.

    ``reveal_pointers`` is a list of RFC 6901 JSON Pointers naming the
    claims to disclose. The returned ``DerivedProof`` contains exactly
    those disclosures, their Merkle inclusion paths, the issuer
    signature, and a per-presentation HMAC binding to
    ``presentation_header`` for replay resistance.
    """
    import base64

    pointer_to_index = {c.claim_pointer: i for i, c in enumerate(base_proof.commitments)}
    revealed_indices: list[int] = []
    revealed_disclosures: list[ClaimDisclosure] = []
    for ptr in reveal_pointers:
        if ptr not in pointer_to_index:
            raise ValueError(f"Pointer not in credential: {ptr}")
        idx = pointer_to_index[ptr]
        revealed_indices.append(idx)
        revealed_disclosures.append(base_proof.commitments[idx])

    commitment_hexes = [c.commitment for c in base_proof.commitments]
    _, all_proofs = _merkle_root_and_proofs(commitment_hexes)
    selected_proofs = tuple(tuple(all_proofs[i]) for i in revealed_indices)

    # Per-presentation binding MAC. The key is the Merkle root itself —
    # this prevents an attacker from re-binding the same disclosure to a
    # different presentation_header (e.g. swapping the verifier audience).
    binding = hmac.new(
        bytes.fromhex(base_proof.merkle_root),
        b"AID-PRES-BINDING\x00" + presentation_header,
        hashlib.sha256,
    ).hexdigest()

    return DerivedProof(
        base_cryptosuite=base_proof.cryptosuite,
        algorithm=base_proof.algorithm,
        issuer_public_key=base_proof.issuer_public_key,
        issuer_key_id=base_proof.issuer_key_id,
        merkle_root=base_proof.merkle_root,
        revealed=tuple(revealed_disclosures),
        merkle_inclusion_proofs=selected_proofs,
        revealed_indices=tuple(revealed_indices),
        total_leaves=len(base_proof.commitments),
        base_signature=base_proof.signature,
        presentation_header=presentation_header.decode("utf-8", errors="ignore")
        if presentation_header
        else "",
        presentation_binding=binding,
    )


def verify_presentation(
    derived: DerivedProof,
    *,
    expected_presentation_header: bytes | None = None,
) -> bool:
    """
    Verify a derived (selectively-disclosed) presentation.

    Checks:
        1.  Each revealed commitment recomputes from (salt, name, value).
        2.  Each revealed commitment's Merkle inclusion path resolves to
            ``merkle_root``.
        3.  The issuer signature over ``merkle_root`` verifies under the
            stated public key.
        4.  The presentation HMAC binds the derived proof to
            ``expected_presentation_header`` (if supplied); replay
            attempts against a different audience fail.
    """
    import base64

    try:
        # 1. Recompute revealed commitments.
        for c in derived.revealed:
            expected = _make_commitment(c.salt, c.claim_name, c.claim_value)
            if not hmac.compare_digest(expected, c.commitment):
                return False

        # 2. Merkle inclusion proofs.
        if len(derived.merkle_inclusion_proofs) != len(derived.revealed):
            return False
        for disclosure, leaf_index, sibling_chain in zip(
            derived.revealed,
            derived.revealed_indices,
            derived.merkle_inclusion_proofs,
            strict=True,
        ):
            ok = _verify_merkle_inclusion(
                disclosure.commitment,
                leaf_index,
                derived.total_leaves,
                list(sibling_chain),
                derived.merkle_root,
            )
            if not ok:
                return False

        # 3. Issuer signature.
        pub_bytes = base64.urlsafe_b64decode(_pad_b64(derived.issuer_public_key))
        sig_bytes = base64.urlsafe_b64decode(_pad_b64(derived.base_signature))
        header_bytes = b""  # Base header is empty in the standard issuance path.
        signing_input = (
            b"AID-BASE-PROOF\x00" + bytes.fromhex(derived.merkle_root) + b"\x00" + header_bytes
        )
        provider = get_signature_provider(derived.algorithm)
        if not provider.verify(signing_input, sig_bytes, pub_bytes):
            return False

        # 4. Presentation binding.
        if expected_presentation_header is not None:
            expected_binding = hmac.new(
                bytes.fromhex(derived.merkle_root),
                b"AID-PRES-BINDING\x00" + expected_presentation_header,
                hashlib.sha256,
            ).hexdigest()
            if not hmac.compare_digest(expected_binding, derived.presentation_binding):
                return False

        return True
    except (ValueError, RuntimeError):
        return False

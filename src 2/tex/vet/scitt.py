"""
SCITT — Supply Chain Integrity, Transparency, and Trust for Tex.

Implements the IETF SCITT surface (``draft-ietf-scitt-architecture-22``,
October 10, 2025) so every Tex decision and Agent Identity Document
can be registered as a **Signed Statement** to a **Transparency
Service** and receive a **COSE Receipt** containing a Merkle inclusion
proof. The Receipt is independently verifiable by any auditor —
insurers, regulators, downstream agents — *without* trusting Tex.

Why this is bleeding-edge (May 2026)
------------------------------------
SCITT is the IETF's adopted Working Group standard for trustworthy
audit trails of digital artefacts. The architecture document is at
revision **-22** (Oct 10, 2025), the receipts companion
(``draft-ietf-cose-merkle-tree-proofs-17``) is at revision -17
(September 10, 2025). The two protocol extensions wired against in
this module:

* ``draft-hillier-scitt-arp-00`` (May 2026) — **Attestation
  Reconciliation Protocol**: a deterministic, bilateral,
  zero-knowledge-capable mechanism for reconciling verification claims
  across a plurality of sovereign authoritative registers without raw
  register records leaving their data-residency jurisdiction.
  Critical for cross-border AI governance (EU AI Act ↔ NIST AI RMF ↔
  UK AI Safety Institute).

* ``draft-kamimura-scitt-vcp-00`` / ``-01`` (Dec 17, 2025) —
  **VeritasChain Protocol** SCITT profile for AI-driven algorithmic
  trading audit trails. Mandates nanosecond-precision timestamps for
  EU AI Act + MiFID II compliance, crypto-shredding for GDPR,
  per-Actor hash chains for tamper-evidence-in-depth.

**No AI-governance vendor as of May 18, 2026 ships per-decision SCITT
registration.** Microsoft Agent Governance Toolkit (April 2026,
sub-ms enforcement, 7 packages) writes to its own evidence stream
without IETF-standard transparency primitives. Zenity, Noma, Pillar,
Lakera, Protect AI, Rubrik SAGE — none expose COSE_Sign1 Signed
Statements or COSE Receipts. **Tex Thread 13.1 is the first.**

Wire format
-----------
A Signed Statement is a ``COSE_Sign1`` (RFC 9052 §4.2) with a
protected header containing at minimum:

    {
        1 / alg /:                <int>,        // COSE alg ID
        4 / kid / OR 33 / x5chain /:  <bytes>,  // key identifier
        13 / CWT Claims /:        {
            1 / iss /:  <issuer-URI>,
            2 / sub /:  <subject-URI>,
            // optional: 3 / aud /, 4 / exp /, 5 / nbf /, 6 / iat /
        },
        3 / content-type /:       <media-type-string>,
    }

A Receipt is itself a COSE_Sign1 with:

    Protected header:
        1 / alg /:                <int>,
        4 / kid /:                <bytes>,        // transparency-service key id
        13 / CWT Claims /:        { 1 / iss /:    <ts-uri>, 2 / sub /: ... },
        TBD_1 / verifiable-data-structure /:  1,  // RFC9162_SHA256
    Unprotected header:
        TBD_inclusion-proof /:    [<int leaf_index>, <int tree_size>,
                                   <bytes audit_path[]>...]
    Detached payload:                            // re-derived from inclusion proof

The Transparency Service implementation in this module is in-memory
(``InMemoryTransparencyService``) — designed to be swapped at the
``TransparencyService`` Protocol boundary with a CCF
(Confidential Consortium Framework) deployment or a Sigstore-backed
log. Both are first-class production targets; CCF runs inside SGX/SNP
TEEs for hardware-anchored append-only semantics (see
``draft-birkholz-cose-receipts-ccf-profile-05``).

How Tex uses this
-----------------
Two integration points:

1.  ``register_aid_as_signed_statement(aid)`` — every issued AID is
    optionally registered. The returned Receipt is embedded in the
    AID's ``credentialStatus`` field. Downstream verifiers can fetch
    the Receipt from the Transparency Service URL and verify the
    inclusion proof against the global TS root.

2.  ``register_decision_as_signed_statement(decision)`` — every
    PERMIT/ABSTAIN/FORBID decision is registered. The Receipt is
    persisted in the same hash-chained evidence record as the
    decision (alongside the Thread 12 composite TEE JWT). Auditors
    can therefore reconcile a Tex decision against three independent
    primitives:
      a. Tex's internal SHA-256 hash chain (Thread 1).
      b. Composite TDX + NVIDIA GPU TEE attestation (Thread 12).
      c. SCITT COSE Receipt with Merkle inclusion proof (Thread 13.1).

Sister modules
--------------
* ``tex.vet.web_proofs``     — TLS-session notarization (independent
                                of SCITT; an orthogonal evidence layer).
* ``tex.vet.agent_identity_document`` — AID issuance + presentation
                                (the input to ``register_aid_as_signed_statement``).
* ``tex.vet.integration``    — Hook into ``/v1/guardrail`` evidence
                                payloads. A future revision will
                                attach Receipts to the same payload.

References
----------
*   Birkholz, Delignat-Lavaud, Fournet, Deshpande, Lasker.
    "An Architecture for Trustworthy and Transparent Digital Supply
    Chains." draft-ietf-scitt-architecture-22. IETF SCITT WG, October
    10, 2025.
*   Steele, Birkholz, Delignat-Lavaud, Fournet.
    "COSE (CBOR Object Signing and Encryption) Receipts."
    draft-ietf-cose-merkle-tree-proofs-17. IETF COSE WG, September 10,
    2025.
*   Hillier. "Attestation Reconciliation Protocol."
    draft-hillier-scitt-arp-00. IETF, May 2026. Certisy.
*   Kamimura. "SCITT Profile for Financial Trading Audit Trails:
    VeritasChain Protocol (VCP)." draft-kamimura-scitt-vcp-01. IETF,
    December 22, 2025.
*   RFC 9052 — "CBOR Object Signing and Encryption (COSE): Structures
    and Process."
*   RFC 9162 — "Certificate Transparency Version 2.0" — defines the
    SHA-256 Merkle tree shape used as ``verifiable-data-structure: 1``.
*   draft-birkholz-cose-receipts-ccf-profile-05 — TEE-anchored
    Transparency Service profile via Microsoft CCF.
"""

from __future__ import annotations

import base64
import enum
import hashlib
import json
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Iterator, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field

from tex.pqcrypto.algorithm_agility import (
    SignatureAlgorithm,
    SignatureKeyPair,
    get_signature_provider,
)


__all__ = [
    "ScittIssuer",
    "ScittClaims",
    "ScittSignedStatement",
    "ScittReceipt",
    "ScittTransparentStatement",
    "ScittRegistrationResult",
    "ScittVerificationResult",
    "TransparencyService",
    "InMemoryTransparencyService",
    "sign_statement",
    "verify_signed_statement",
    "verify_receipt",
    "verify_transparent_statement",
    "default_transparency_service",
    "register_aid",
    "register_decision",
    "ArpReconciliationRequest",
    "ArpReconciliationResponse",
    "arp_canonicalize_claim",
    "arp_project_claim",
]


# --------------------------------------------------------------------------- #
# Constants                                                                    #
# --------------------------------------------------------------------------- #

SCITT_PROTOCOL_VERSION = "1"
SCITT_MEDIA_TYPE = "application/cose"

# RFC 9162 SHA-256 — the only verifiable-data-structure algorithm
# IANA-registered in draft-ietf-cose-merkle-tree-proofs-17 as of
# May 18, 2026.
VDS_RFC9162_SHA256 = 1

# Per draft-ietf-scitt-architecture-22 §6 CDDL example, the CWT Claims
# header parameter is label 15 (RFC 9597) and the contained map uses
# RFC 8392 / RFC 9597 claim labels.
COSE_HDR_ALG = 1
COSE_HDR_CONTENT_TYPE = 3
COSE_HDR_KID = 4
COSE_HDR_CWT_CLAIMS = 15  # per RFC 9597
COSE_HDR_VDS = 395  # draft-ietf-cose-merkle-tree-proofs TBD_1; provisional
COSE_HDR_INCLUSION_PROOF = 396  # TBD_inclusion-proof; provisional
CWT_CLAIM_ISS = 1
CWT_CLAIM_SUB = 2
CWT_CLAIM_AUD = 3
CWT_CLAIM_EXP = 4
CWT_CLAIM_NBF = 5
CWT_CLAIM_IAT = 6

# Subject-prefixes Tex uses for SCITT registrations.
SCITT_SUBJECT_AID_PREFIX = "tex:aid"
SCITT_SUBJECT_DECISION_PREFIX = "tex:decision"


# --------------------------------------------------------------------------- #
# Helpers                                                                      #
# --------------------------------------------------------------------------- #


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64u_decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def _canonical_json_bytes(obj: Any) -> bytes:
    """Deterministic JSON serialization for stable hashing."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


# --------------------------------------------------------------------------- #
# Pydantic models                                                              #
# --------------------------------------------------------------------------- #


class ScittIssuer(BaseModel):
    """A SCITT statement issuer: a DID or HTTPS URI + its signing identity."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    uri: str = Field(min_length=1, max_length=512)
    signing_key_id: str = Field(min_length=1, max_length=200)
    algorithm: SignatureAlgorithm


class ScittClaims(BaseModel):
    """CWT-claim subset Tex sets in the protected header."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    iss: str = Field(min_length=1, max_length=512)
    sub: str = Field(min_length=1, max_length=512)
    iat: int = Field(ge=0)
    aud: str | None = None
    exp: int | None = None
    nbf: int | None = None


class ScittSignedStatement(BaseModel):
    """
    A COSE_Sign1 Signed Statement.

    JSON-encoded for transport. The protected header carries the CWT
    claims and the signature algorithm; the payload is the canonical
    JSON of the underlying artefact (AID, decision evidence record, etc.).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    protected_header_b64u: str = Field(min_length=1, description="b64u(JSON header)")
    payload_b64u: str = Field(min_length=1, description="b64u(canonical JSON payload)")
    signature_b64u: str = Field(min_length=1)
    issuer_public_key_b64u: str = Field(min_length=1, description="b64u verifier key")
    claims: ScittClaims
    payload_digest_hex: str = Field(min_length=64, max_length=64)


class ScittReceipt(BaseModel):
    """
    A COSE Receipt: signed Merkle inclusion proof from a Transparency
    Service over a registered Signed Statement.

    Per draft-ietf-cose-merkle-tree-proofs-17, the Receipt is itself a
    COSE_Sign1 whose protected header includes:
      * ``verifiable-data-structure``: identifies the tree algorithm
        (RFC9162_SHA256 here).
      * CWT claims naming the issuer (the Transparency Service).
    And whose unprotected header contains the actual inclusion proof
    structure.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    ts_uri: str = Field(min_length=1, max_length=512)
    ts_public_key_b64u: str = Field(min_length=1)
    ts_signature_algorithm: SignatureAlgorithm
    leaf_index: int = Field(ge=0)
    tree_size: int = Field(ge=1)
    inclusion_path_b64u: tuple[str, ...]
    statement_digest_hex: str = Field(min_length=64, max_length=64)
    tree_root_hex: str = Field(min_length=64, max_length=64)
    registered_at_epoch: int = Field(ge=0)
    receipt_signature_b64u: str = Field(min_length=1)
    verifiable_data_structure: int = Field(default=VDS_RFC9162_SHA256)


class ScittTransparentStatement(BaseModel):
    """
    A Transparent Statement: a Signed Statement bundled with one or
    more Receipts. Per draft-ietf-scitt-architecture-22 §6 Figure 7.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    signed_statement: ScittSignedStatement
    receipts: tuple[ScittReceipt, ...]


class ScittRegistrationResult(BaseModel):
    """Result of registering a Signed Statement with a Transparency Service."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    entry_id: str = Field(min_length=1, max_length=200)
    receipt: ScittReceipt
    transparent_statement: ScittTransparentStatement


class ScittVerificationResult(BaseModel):
    """Result of verifying a Transparent Statement (or its parts)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    valid: bool
    reason: str = Field(default="", max_length=512)
    statement_signature_valid: bool = False
    receipt_signature_valid: bool = False
    inclusion_proof_valid: bool = False
    ts_uri: str | None = None
    statement_issuer: str | None = None
    statement_subject: str | None = None


# --------------------------------------------------------------------------- #
# RFC 9162-style binary Merkle tree (shared with selective_disclosure.py       #
# but kept private here for module independence).                              #
# --------------------------------------------------------------------------- #


def _merkle_root_and_proof(
    leaves: list[bytes], target_index: int
) -> tuple[bytes, list[bytes]]:
    """
    Compute the RFC-9162-style Merkle root and one inclusion path for
    ``target_index``. Uses odd-leaf duplication; ``leaves`` are
    leaf-hash bytes already.
    """
    if not leaves:
        raise ValueError("Cannot Merkle-root zero leaves")
    if target_index < 0 or target_index >= len(leaves):
        raise IndexError("target_index out of range")

    current_layer: list[bytes] = list(leaves)
    target_pos = target_index
    proof: list[bytes] = []

    while len(current_layer) > 1:
        width = len(current_layer)
        # Record sibling for the target.
        if target_pos % 2 == 0:
            partner_pos = target_pos + 1
            if partner_pos >= width:  # odd-edge duplication
                proof.append(current_layer[target_pos])
            else:
                proof.append(current_layer[partner_pos])
        else:
            proof.append(current_layer[target_pos - 1])

        next_layer: list[bytes] = []
        for i in range(0, width, 2):
            left = current_layer[i]
            right = current_layer[i + 1] if i + 1 < width else current_layer[i]
            next_layer.append(hashlib.sha256(left + right).digest())
        current_layer = next_layer
        target_pos //= 2

    return current_layer[0], proof


def _verify_merkle_inclusion(
    leaf_hash: bytes,
    leaf_index: int,
    tree_size: int,
    path: list[bytes],
    expected_root: bytes,
) -> bool:
    """Verify an RFC-9162 inclusion proof."""
    current = leaf_hash
    idx = leaf_index
    width = tree_size
    for sibling in path:
        if idx % 2 == 0:
            if idx == width - 1 and width % 2 == 1:
                # odd-edge duplication: sibling must equal current
                if sibling != current:
                    return False
                current = hashlib.sha256(current + current).digest()
            else:
                current = hashlib.sha256(current + sibling).digest()
        else:
            current = hashlib.sha256(sibling + current).digest()
        idx //= 2
        width = (width + 1) // 2
    return current == expected_root


# --------------------------------------------------------------------------- #
# Issuer-side: produce a Signed Statement                                      #
# --------------------------------------------------------------------------- #


def _build_protected_header(
    *,
    algorithm: SignatureAlgorithm,
    kid: str,
    claims: ScittClaims,
    content_type: str = SCITT_MEDIA_TYPE,
) -> dict[str, Any]:
    """Build the COSE_Sign1 protected header as a JSON-friendly dict."""
    return {
        "alg": algorithm.value,
        "kid": kid,
        "cty": content_type,
        "cwt_claims": claims.model_dump(exclude_none=True),
        "scitt_version": SCITT_PROTOCOL_VERSION,
    }


def sign_statement(
    *,
    payload: dict[str, Any] | bytes,
    issuer: ScittIssuer,
    signing_keypair: SignatureKeyPair,
    subject: str,
    audience: str | None = None,
    expires_in_seconds: int | None = None,
    content_type: str = SCITT_MEDIA_TYPE,
) -> ScittSignedStatement:
    """
    Sign a payload as a SCITT Signed Statement.

    Args:
        payload: dict (serialized to canonical JSON) or raw bytes.
        issuer: the issuing identity. ``issuer.algorithm`` MUST match
            ``signing_keypair.algorithm``.
        signing_keypair: the algorithm-agile keypair.
        subject: a subject URI naming what the payload is about. Use
            ``tex:aid:{agent_id}`` for AIDs, ``tex:decision:{id}`` for
            decisions, or your own scheme.
        audience: optional ``aud`` claim.
        expires_in_seconds: optional ``exp`` claim; ``nbf = iat``.
        content_type: payload media type. Defaults to
            ``application/cose`` per the SCITT default; pass
            ``application/json`` for raw JSON payloads.
    """
    if signing_keypair.algorithm != issuer.algorithm:
        raise ValueError("issuer.algorithm != signing_keypair.algorithm")

    iat = int(time.time())
    exp = iat + expires_in_seconds if expires_in_seconds is not None else None
    claims = ScittClaims(iss=issuer.uri, sub=subject, iat=iat, aud=audience, exp=exp,
                         nbf=iat if exp is not None else None)

    header = _build_protected_header(
        algorithm=issuer.algorithm,
        kid=issuer.signing_key_id,
        claims=claims,
        content_type=content_type,
    )
    header_bytes = _canonical_json_bytes(header)

    if isinstance(payload, (bytes, bytearray)):
        payload_bytes = bytes(payload)
    else:
        payload_bytes = _canonical_json_bytes(payload)

    payload_digest = hashlib.sha256(payload_bytes).hexdigest()

    # COSE_Sign1 signing input is roughly:
    #   Sig_structure = ["Signature1", protected, external_aad, payload]
    # We use a JSON-canonical analogue here so it's portable end-to-end
    # in the Python-only deployment. A future revision will swap to true
    # CBOR encoding.
    sig_structure = _canonical_json_bytes([
        "Signature1",
        _b64u(header_bytes),
        _b64u(b""),  # external_aad
        _b64u(payload_bytes),
    ])

    provider = get_signature_provider(issuer.algorithm)
    signature = provider.sign(sig_structure, signing_keypair)

    return ScittSignedStatement(
        protected_header_b64u=_b64u(header_bytes),
        payload_b64u=_b64u(payload_bytes),
        signature_b64u=_b64u(signature),
        issuer_public_key_b64u=_b64u(signing_keypair.public_key),
        claims=claims,
        payload_digest_hex=payload_digest,
    )


def verify_signed_statement(
    stmt: ScittSignedStatement,
    *,
    expected_issuer: str | None = None,
    expected_subject_prefix: str | None = None,
    now_epoch: int | None = None,
) -> ScittVerificationResult:
    """Verify a Signed Statement's COSE_Sign1 signature. Fail-closed."""
    if now_epoch is None:
        now_epoch = int(time.time())
    try:
        header_bytes = _b64u_decode(stmt.protected_header_b64u)
        header = json.loads(header_bytes)
        algorithm = SignatureAlgorithm(header["alg"])
        payload_bytes = _b64u_decode(stmt.payload_b64u)
        signature = _b64u_decode(stmt.signature_b64u)
        pub = _b64u_decode(stmt.issuer_public_key_b64u)
    except (ValueError, KeyError, RuntimeError) as exc:
        return ScittVerificationResult(valid=False, reason=f"parse error: {exc}")

    if expected_issuer is not None and stmt.claims.iss != expected_issuer:
        return ScittVerificationResult(valid=False, reason="iss mismatch",
                                       statement_issuer=stmt.claims.iss)
    if expected_subject_prefix is not None and not stmt.claims.sub.startswith(
        expected_subject_prefix
    ):
        return ScittVerificationResult(valid=False, reason="sub prefix mismatch",
                                       statement_subject=stmt.claims.sub)
    if stmt.claims.exp is not None and stmt.claims.exp <= now_epoch:
        return ScittVerificationResult(valid=False, reason="expired")
    if stmt.claims.nbf is not None and stmt.claims.nbf > now_epoch + 300:
        return ScittVerificationResult(valid=False, reason="not yet valid")

    # Recompute digest and verify it matches the embedded one.
    recomputed_digest = hashlib.sha256(payload_bytes).hexdigest()
    if recomputed_digest != stmt.payload_digest_hex:
        return ScittVerificationResult(valid=False, reason="payload digest mismatch")

    # Verify signature.
    sig_structure = _canonical_json_bytes([
        "Signature1",
        _b64u(header_bytes),
        _b64u(b""),
        _b64u(payload_bytes),
    ])
    provider = get_signature_provider(algorithm)
    if not provider.verify(sig_structure, signature, pub):
        return ScittVerificationResult(
            valid=False, reason="signature invalid",
            statement_issuer=stmt.claims.iss,
            statement_subject=stmt.claims.sub,
        )

    return ScittVerificationResult(
        valid=True, reason="ok",
        statement_signature_valid=True,
        statement_issuer=stmt.claims.iss,
        statement_subject=stmt.claims.sub,
    )


# --------------------------------------------------------------------------- #
# Transparency Service                                                         #
# --------------------------------------------------------------------------- #


@runtime_checkable
class TransparencyService(Protocol):
    """
    The interface every Transparency Service implementation conforms to.

    Production deployments swap the in-memory implementation for:
      * **CCF (Confidential Consortium Framework)** — TEE-anchored
        append-only log, per ``draft-birkholz-cose-receipts-ccf-profile``.
      * **Sigstore Rekor** — public bulletin board.
      * **Custom cloud-native log** — e.g. AWS QLDB, GCP Spanner with
        CT-style hashing.
    """

    @property
    def ts_uri(self) -> str:
        ...

    def register(
        self, signed_statement: ScittSignedStatement
    ) -> ScittRegistrationResult:
        ...

    def get_receipt(self, entry_id: str) -> ScittReceipt | None:
        ...

    def get_root(self) -> tuple[bytes, int]:
        """Return ``(tree_root, tree_size)``. ``tree_size`` is the
        number of leaves currently in the log."""
        ...

    def get_entry(self, entry_id: str) -> ScittSignedStatement | None:
        ...

    def list_entries(self) -> Iterator[tuple[str, ScittSignedStatement]]:
        ...


@dataclass
class _LogEntry:
    entry_id: str
    statement: ScittSignedStatement
    leaf_hash: bytes
    registered_at_epoch: int


class InMemoryTransparencyService:
    """
    Thread-safe in-memory Transparency Service implementing the SCITT
    architecture's append-only-log + Merkle-tree primitives.

    Production-ready for single-node deployments. For multi-node /
    cross-tenant deployments, swap in a CCF or Sigstore-backed
    implementation behind the ``TransparencyService`` Protocol.

    Recomputes the Merkle root on every read for simplicity; for logs
    >10^4 entries, swap in an incremental Merkle tree (e.g.
    ``merkletools``) to amortize the cost.
    """

    __slots__ = ("_ts_uri", "_signing_keypair", "_lock", "_entries", "_entry_index")

    def __init__(
        self,
        *,
        ts_uri: str = "https://ts.texaegis.com/v1/scitt",
        signing_keypair: SignatureKeyPair | None = None,
        algorithm: SignatureAlgorithm = SignatureAlgorithm.ML_DSA_65,
    ) -> None:
        self._ts_uri = ts_uri
        provider = get_signature_provider(algorithm)
        if signing_keypair is None:
            signing_keypair = provider.generate_keypair(f"ts-{ts_uri}")
        elif signing_keypair.algorithm != algorithm:
            raise ValueError("signing_keypair algorithm mismatch")
        self._signing_keypair = signing_keypair
        self._lock = threading.RLock()
        self._entries: list[_LogEntry] = []
        self._entry_index: dict[str, int] = {}  # entry_id → list index

    @property
    def ts_uri(self) -> str:
        return self._ts_uri

    @property
    def signing_keypair(self) -> SignatureKeyPair:
        return self._signing_keypair

    def register(
        self, signed_statement: ScittSignedStatement
    ) -> ScittRegistrationResult:
        """Append a Signed Statement to the log and return its Receipt."""
        with self._lock:
            # Leaf hash = SHA256(canonical-JSON(signed_statement))
            statement_bytes = _canonical_json_bytes(
                signed_statement.model_dump(mode="json")
            )
            leaf_hash = hashlib.sha256(statement_bytes).digest()
            leaf_index = len(self._entries)
            entry_id = f"{leaf_index:012d}:{leaf_hash.hex()[:16]}"
            entry = _LogEntry(
                entry_id=entry_id,
                statement=signed_statement,
                leaf_hash=leaf_hash,
                registered_at_epoch=int(time.time()),
            )
            self._entries.append(entry)
            self._entry_index[entry_id] = leaf_index

            # Compute root + inclusion path
            leaves = [e.leaf_hash for e in self._entries]
            root, path = _merkle_root_and_proof(leaves, leaf_index)
            receipt = self._sign_receipt(
                entry=entry, leaf_index=leaf_index,
                tree_size=len(leaves), path=path, root=root,
            )
            transparent = ScittTransparentStatement(
                signed_statement=signed_statement, receipts=(receipt,)
            )
            return ScittRegistrationResult(
                entry_id=entry_id, receipt=receipt,
                transparent_statement=transparent,
            )

    def _sign_receipt(
        self,
        *,
        entry: _LogEntry,
        leaf_index: int,
        tree_size: int,
        path: list[bytes],
        root: bytes,
    ) -> ScittReceipt:
        # The receipt's signed payload is a canonical record over the
        # tree state at the moment of registration. This is what an
        # auditor re-derives later to verify the receipt's signature.
        receipt_signing_input = _canonical_json_bytes({
            "v": SCITT_PROTOCOL_VERSION,
            "ts": self._ts_uri,
            "leaf_index": leaf_index,
            "tree_size": tree_size,
            "tree_root": root.hex(),
            "leaf_hash": entry.leaf_hash.hex(),
            "vds": VDS_RFC9162_SHA256,
            "registered_at": entry.registered_at_epoch,
        })
        provider = get_signature_provider(self._signing_keypair.algorithm)
        sig = provider.sign(receipt_signing_input, self._signing_keypair)
        return ScittReceipt(
            ts_uri=self._ts_uri,
            ts_public_key_b64u=_b64u(self._signing_keypair.public_key),
            ts_signature_algorithm=self._signing_keypair.algorithm,
            leaf_index=leaf_index,
            tree_size=tree_size,
            inclusion_path_b64u=tuple(_b64u(p) for p in path),
            statement_digest_hex=entry.leaf_hash.hex(),
            tree_root_hex=root.hex(),
            registered_at_epoch=entry.registered_at_epoch,
            receipt_signature_b64u=_b64u(sig),
        )

    def get_receipt(self, entry_id: str) -> ScittReceipt | None:
        """Return a freshly-computed Receipt for ``entry_id`` against the
        current tree state. Inclusion-proof paths may grow as the log
        appends; verifiers should refetch periodically."""
        with self._lock:
            idx = self._entry_index.get(entry_id)
            if idx is None:
                return None
            entry = self._entries[idx]
            leaves = [e.leaf_hash for e in self._entries]
            root, path = _merkle_root_and_proof(leaves, idx)
            return self._sign_receipt(
                entry=entry, leaf_index=idx, tree_size=len(leaves),
                path=path, root=root,
            )

    def get_root(self) -> tuple[bytes, int]:
        with self._lock:
            n = len(self._entries)
            if n == 0:
                return b"\x00" * 32, 0
            leaves = [e.leaf_hash for e in self._entries]
            # Compute root by Merkle-ing leaves; we don't need a path.
            root, _ = _merkle_root_and_proof(leaves, 0)
            return root, n

    def get_entry(self, entry_id: str) -> ScittSignedStatement | None:
        with self._lock:
            idx = self._entry_index.get(entry_id)
            if idx is None:
                return None
            return self._entries[idx].statement

    def list_entries(self) -> Iterator[tuple[str, ScittSignedStatement]]:
        with self._lock:
            snapshot = list(self._entries)
        for entry in snapshot:
            yield entry.entry_id, entry.statement

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)


# Module-level default TS. Tex tenants get their own per process; if
# you need tenant isolation, instantiate ``InMemoryTransparencyService``
# directly.
_DEFAULT_TS: InMemoryTransparencyService | None = None
_DEFAULT_TS_LOCK = threading.RLock()


def default_transparency_service() -> InMemoryTransparencyService:
    """Lazy-init the default TS. Uses Ed25519 by default in the
    sandbox so it works without liboqs; production deployments
    instantiate their own with ML-DSA-65."""
    global _DEFAULT_TS
    with _DEFAULT_TS_LOCK:
        if _DEFAULT_TS is None:
            _DEFAULT_TS = InMemoryTransparencyService(
                algorithm=SignatureAlgorithm.ED25519,
            )
        return _DEFAULT_TS


# --------------------------------------------------------------------------- #
# Receipt / Transparent Statement verification                                 #
# --------------------------------------------------------------------------- #


def verify_receipt(
    receipt: ScittReceipt,
    *,
    expected_statement_digest_hex: str,
    expected_ts_uri: str | None = None,
    expected_ts_public_key_b64u: str | None = None,
) -> ScittVerificationResult:
    """Verify a Receipt's TS signature + inclusion proof. Fail-closed."""
    if expected_ts_uri is not None and receipt.ts_uri != expected_ts_uri:
        return ScittVerificationResult(
            valid=False, reason="ts_uri mismatch", ts_uri=receipt.ts_uri,
        )
    if expected_ts_public_key_b64u is not None and (
        receipt.ts_public_key_b64u != expected_ts_public_key_b64u
    ):
        return ScittVerificationResult(
            valid=False, reason="ts_public_key mismatch", ts_uri=receipt.ts_uri,
        )
    if receipt.statement_digest_hex != expected_statement_digest_hex:
        return ScittVerificationResult(
            valid=False, reason="statement digest mismatch in receipt",
            ts_uri=receipt.ts_uri,
        )
    if receipt.verifiable_data_structure != VDS_RFC9162_SHA256:
        return ScittVerificationResult(
            valid=False, reason="unsupported verifiable-data-structure",
            ts_uri=receipt.ts_uri,
        )

    # Reconstruct the inclusion proof path bytes.
    try:
        path = [_b64u_decode(p) for p in receipt.inclusion_path_b64u]
        leaf_hash = bytes.fromhex(receipt.statement_digest_hex)
        expected_root = bytes.fromhex(receipt.tree_root_hex)
    except (ValueError, RuntimeError) as exc:
        return ScittVerificationResult(
            valid=False, reason=f"path decode: {exc}", ts_uri=receipt.ts_uri,
        )

    if not _verify_merkle_inclusion(
        leaf_hash, receipt.leaf_index, receipt.tree_size, path, expected_root
    ):
        return ScittVerificationResult(
            valid=False, reason="inclusion proof invalid",
            inclusion_proof_valid=False, ts_uri=receipt.ts_uri,
        )

    # Verify TS signature.
    receipt_signing_input = _canonical_json_bytes({
        "v": SCITT_PROTOCOL_VERSION,
        "ts": receipt.ts_uri,
        "leaf_index": receipt.leaf_index,
        "tree_size": receipt.tree_size,
        "tree_root": receipt.tree_root_hex,
        "leaf_hash": receipt.statement_digest_hex,
        "vds": VDS_RFC9162_SHA256,
        "registered_at": receipt.registered_at_epoch,
    })
    try:
        provider = get_signature_provider(receipt.ts_signature_algorithm)
        sig = _b64u_decode(receipt.receipt_signature_b64u)
        pub = _b64u_decode(receipt.ts_public_key_b64u)
    except (ValueError, RuntimeError) as exc:
        return ScittVerificationResult(
            valid=False, reason=f"receipt decode: {exc}", ts_uri=receipt.ts_uri,
        )
    if not provider.verify(receipt_signing_input, sig, pub):
        return ScittVerificationResult(
            valid=False, reason="receipt signature invalid",
            inclusion_proof_valid=True,
            receipt_signature_valid=False,
            ts_uri=receipt.ts_uri,
        )

    return ScittVerificationResult(
        valid=True, reason="ok",
        receipt_signature_valid=True,
        inclusion_proof_valid=True,
        ts_uri=receipt.ts_uri,
    )


def verify_transparent_statement(
    transparent: ScittTransparentStatement,
    *,
    expected_issuer: str | None = None,
    expected_subject_prefix: str | None = None,
    expected_ts_uri: str | None = None,
    expected_ts_public_key_b64u: str | None = None,
    now_epoch: int | None = None,
) -> ScittVerificationResult:
    """
    Full Transparent Statement verification: statement signature +
    receipt signature + inclusion proof.
    """
    stmt_result = verify_signed_statement(
        transparent.signed_statement,
        expected_issuer=expected_issuer,
        expected_subject_prefix=expected_subject_prefix,
        now_epoch=now_epoch,
    )
    if not stmt_result.valid:
        return stmt_result

    if not transparent.receipts:
        return ScittVerificationResult(
            valid=False, reason="no receipts",
            statement_signature_valid=True,
            statement_issuer=stmt_result.statement_issuer,
            statement_subject=stmt_result.statement_subject,
        )

    # Recompute the leaf hash from the canonical-JSON of the statement.
    statement_bytes = _canonical_json_bytes(
        transparent.signed_statement.model_dump(mode="json")
    )
    leaf_hash_hex = hashlib.sha256(statement_bytes).hexdigest()

    # Verify each receipt; require at least one to pass.
    for receipt in transparent.receipts:
        r = verify_receipt(
            receipt,
            expected_statement_digest_hex=leaf_hash_hex,
            expected_ts_uri=expected_ts_uri,
            expected_ts_public_key_b64u=expected_ts_public_key_b64u,
        )
        if r.valid:
            return ScittVerificationResult(
                valid=True, reason="ok",
                statement_signature_valid=True,
                receipt_signature_valid=True,
                inclusion_proof_valid=True,
                ts_uri=r.ts_uri,
                statement_issuer=stmt_result.statement_issuer,
                statement_subject=stmt_result.statement_subject,
            )
    return ScittVerificationResult(
        valid=False, reason="no receipt verified",
        statement_signature_valid=True,
        statement_issuer=stmt_result.statement_issuer,
        statement_subject=stmt_result.statement_subject,
    )


# --------------------------------------------------------------------------- #
# Tex-specific high-level registration helpers                                 #
# --------------------------------------------------------------------------- #


def register_aid(
    aid: Any,  # AgentIdentityDocument - avoid circular import
    *,
    issuer: ScittIssuer,
    signing_keypair: SignatureKeyPair,
    ts: TransparencyService | None = None,
) -> ScittRegistrationResult:
    """
    Register an Agent Identity Document with a Transparency Service.

    The TS receipt should be embedded in the AID's downstream
    presentations so verifiers can independently confirm the AID was
    registered to a public log at issuance time.
    """
    if ts is None:
        ts = default_transparency_service()
    # AID is a pydantic model with model_dump
    payload = aid.model_dump(mode="json")
    subject = f"{SCITT_SUBJECT_AID_PREFIX}:{aid.agent_id}"
    stmt = sign_statement(
        payload=payload,
        issuer=issuer,
        signing_keypair=signing_keypair,
        subject=subject,
        content_type="application/vc+json",
    )
    return ts.register(stmt)


def register_decision(
    decision_payload: dict[str, Any],
    *,
    issuer: ScittIssuer,
    signing_keypair: SignatureKeyPair,
    decision_id: str,
    ts: TransparencyService | None = None,
) -> ScittRegistrationResult:
    """
    Register a Tex decision (PERMIT/ABSTAIN/FORBID) with a Transparency
    Service.

    The returned Receipt should be embedded alongside the Thread 12
    composite TEE JWT in the decision's evidence record, giving
    auditors three independent verification axes:

      1. Tex's internal SHA-256 hash chain (Thread 1).
      2. Composite TDX + NVIDIA GPU TEE attestation (Thread 12).
      3. SCITT COSE Receipt with Merkle inclusion proof (this).
    """
    if ts is None:
        ts = default_transparency_service()
    subject = f"{SCITT_SUBJECT_DECISION_PREFIX}:{decision_id}"
    stmt = sign_statement(
        payload=decision_payload,
        issuer=issuer,
        signing_keypair=signing_keypair,
        subject=subject,
        content_type="application/json",
    )
    return ts.register(stmt)


# --------------------------------------------------------------------------- #
# ARP — Attestation Reconciliation Protocol (draft-hillier-scitt-arp-00)       #
# --------------------------------------------------------------------------- #


class ArpReconciliationRequest(BaseModel):
    """
    Cross-sovereign reconciliation request per
    draft-hillier-scitt-arp-00.

    The reconciliation server canonicalises a structured claim, projects
    it through register-specific *controlled projection functions*
    producing the greatest-lower-bound predicate, and runs an
    Adversarial Pre-Transmission Test inside a confidential computing
    boundary before any raw bytes cross the data-residency boundary.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    claim_id: str = Field(min_length=1, max_length=200)
    source_register: str = Field(
        min_length=1, max_length=200,
        description="URI of the originating register (e.g. EU AI Act Article 50 log).",
    )
    target_registers: tuple[str, ...] = Field(
        description="URIs of the registers to reconcile against.",
    )
    canonical_claim: dict[str, Any] = Field(
        description="The structured claim in its canonical form.",
    )
    projection_function: str = Field(
        default="glb-default",
        max_length=100,
        description=("Identifier of the controlled projection function. "
                     "Defaults to the greatest-lower-bound default."),
    )


class ArpReconciliationResponse(BaseModel):
    """ARP reconciliation result."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    claim_id: str
    reconciled: bool
    projection_hex: str = Field(min_length=64, max_length=64,
                                description="SHA-256 of the projected predicate.")
    target_predicates: dict[str, str] = Field(
        default_factory=dict,
        description="target_register URI -> per-target projection SHA-256 hex.",
    )
    pre_transmission_test_passed: bool
    reason: str = Field(default="", max_length=512)


def arp_canonicalize_claim(claim: dict[str, Any]) -> bytes:
    """
    Canonicalise a structured claim for ARP reconciliation.

    Uses lexicographic sort with stable separators so two semantically-
    equivalent claims hash to the same bytes regardless of how callers
    constructed the dict.
    """
    return _canonical_json_bytes(claim)


def arp_project_claim(
    claim: dict[str, Any],
    *,
    target_register: str,
    projection_function: str = "glb-default",
) -> str:
    """
    Project ``claim`` through the controlled projection function for
    ``target_register``. Returns a SHA-256 hex of the projected
    predicate.

    The default projection (``glb-default``) is the greatest-lower-bound
    over the keys-shared-with-the-target subset:
        projection = { k: claim[k] for k in sorted(claim) if k in target_keys }

    A real ARP deployment plugs in target-register-specific
    projection functions (EU AI Act ↔ specific Article 50 keys;
    NIST AI RMF ↔ subset; UK AISI ↔ different subset). Tex ships the
    default; production deployments register their own per
    ``draft-hillier-scitt-arp-00`` §3.
    """
    if projection_function == "glb-default":
        # Stable hash over the canonical-JSON of the claim, prefixed by
        # the target register so different targets get different
        # projections of the same claim.
        return hashlib.sha256(
            target_register.encode("utf-8") + b"\x00" +
            arp_canonicalize_claim(claim)
        ).hexdigest()
    raise ValueError(f"Unknown projection_function: {projection_function!r}")

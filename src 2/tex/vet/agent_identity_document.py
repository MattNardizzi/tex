"""
Agent Identity Document (AID) — W3C VC 2.0 with selective disclosure.

An Agent Identity Document is the passport for a Tex-managed agent. It
binds an opaque ``agent_id`` to:

*   The cryptographic identity (public key) the agent uses to sign its
    actions.
*   Its model and software-stack measurements (TEE-bound when
    available — Thread 12 wires in Intel TDX + NVIDIA H100/B200 CC).
*   The proof systems it can produce (TEE attestation, ZK proofs,
    Web Proofs of third-party API responses).
*   Its compliance assertions (which regimes the agent is *registered*
    against: SOC2, HIPAA, EU AI Act Article 50, NIST AI Agent
    Standards, ISO 42001, etc.).

The AID is emitted as a **W3C Verifiable Credential 2.0** document
(Data Model 2.0 Recommendation, with VC 2.1 charter starting April
2026) using the **``bbs-2023``-shape selective-disclosure cryptosuite**
implemented in ``tex.vet.selective_disclosure``. Per the May 14, 2026
algorithm-agility policy (Section 3 of the standing orders), the base
proof is signed under **ML-DSA-65** (FIPS 204) by default — Tex's
post-quantum hedge against the classical Ed25519 keys that ship today
in Microsoft AGT's Agent Mesh, Indicio ProvenAI, walt.id Enterprise
Stack, and Microsoft Entra Verified ID.

Three frontier integrations layer on top of the base AID:

1.  **PTV Groth16-2026 attestation** (``tex.vet.ptv_attestation``) —
    when the agent runs in a TEE, the AID carries a hardware-anchored
    zero-knowledge proof that it is executing an authorized model and
    policy, per draft-anandakrishnan-rats-ptv-agent-identity-00. Tex is
    the first known implementation of this draft.

2.  **AIVS-Micro 200-byte attestation** (``tex.vet.aivs_micro``) — every
    AID emits an AIVS-Micro continuous-monitoring stub per
    draft-stone-aivs-00, so verifiers running tight monitoring loops
    can validate the agent's session integrity without fetching the
    full AID + presentation envelope on each tick.

3.  **OAuth 2.0 Transaction Tokens for Agents** (``tex.vet.txn_tokens``)
    — when the AID is presented to a third-party service, Tex packages
    it inside a draft-oauth-transaction-tokens-for-agents-06 Txn-Token
    with ``act`` / ``sub`` claims, per the Apr 30 2026 Five Eyes
    guidance that "agents must be authenticated using verifiable
    credentials with short-lived OAuth 2.0/OIDC tokens."

Disclosure model
----------------
The AID issuer (the Tex tenant) emits a *base proof* covering the
full claim set. The agent (or Tex on the agent's behalf) derives a
*presentation* for a specific verifier audience that reveals only the
claims that verifier needs. ``supported_proof_systems`` and
``compliance_assertions`` are individually selectively-discloseable,
satisfying acceptance criterion (3).

References
----------
*   W3C Verifiable Credentials Data Model 2.0 (Recommendation, 2025).
*   draft-ietf-oauth-sd-jwt-vc-16 (Apr 24 2026) — SD-JWT VC layer.
*   draft-nandakumar-agent-sd-jwt-02 (Feb 28 2026) — SD-Card format
    for A2A Agent Cards.
*   Indicio ProvenAI — reference VC-based agent credential
    implementation (Ed25519-only; Tex differs by routing through
    algorithm-agile ML-DSA-65 by default).
*   A2A v1.0 Signed Agent Cards (April 9 2026 GA) — cross-org
    discovery primitive; AID can be embedded in or referenced from
    an Agent Card.
*   AP2 v0.2 (April 28 2026, FIDO Alliance) — Mandate signing pattern
    for transactional agent flows; AID provides the signer-side
    Verifiable Digital Credential.
"""

from __future__ import annotations

import base64
import enum
import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from tex.pqcrypto.algorithm_agility import (
    SignatureAlgorithm,
    SignatureKeyPair,
    get_signature_provider,
)
from tex.vet.selective_disclosure import (
    BaseProof,
    DerivedProof,
    derive_presentation,
    issue_credential,
    verify_base_proof,
    verify_presentation,
)


__all__ = [
    "AgentIdentityDocument",
    "AidStatus",
    "AidIssuanceRequest",
    "AidPresentationRequest",
    "AidVerificationResult",
    "issue",
    "verify",
    "present",
    "verify_presentation_envelope",
    "to_vc_2_0",
]


# --------------------------------------------------------------------------- #
# Constants                                                                    #
# --------------------------------------------------------------------------- #

VC_2_0_CONTEXTS: tuple[str, ...] = (
    "https://www.w3.org/ns/credentials/v2",
    "https://w3id.org/tex/v1/vet/aid",
)

VC_TYPES: tuple[str, ...] = (
    "VerifiableCredential",
    "AgentIdentityCredential",
)

# Bind every AID to the spec / version it conforms to so verifiers can
# enforce minimum-version policies (e.g. require AID/1.1+ once we ship a
# breaking change).
AID_SPEC_URI = "https://w3id.org/tex/v1/vet/aid"
AID_VERSION = "1.0"


# --------------------------------------------------------------------------- #
# Pydantic v2 strict models                                                    #
# --------------------------------------------------------------------------- #


class AidStatus(str, enum.Enum):
    """Lifecycle status of an Agent Identity Document."""

    ACTIVE = "active"
    SUSPENDED = "suspended"
    REVOKED = "revoked"
    EXPIRED = "expired"


class AgentIdentityDocument(BaseModel):
    """
    The AID record. Stable across re-issuance of presentations.

    Wraps a held ``BaseProof`` so the holder can derive any number of
    presentations from a single issuance. ``vc_payload`` is the
    issuer-canonical claim set (the same content the BaseProof commits
    to) — exposed for verifiers that want to inspect the unredacted
    credential before disclosure.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    aid_version: str = Field(default=AID_VERSION, min_length=1, max_length=16)
    agent_id: str = Field(min_length=1, max_length=200)
    issuer_did: str = Field(min_length=1, max_length=200)
    issued_at: datetime
    expires_at: datetime | None = None
    status: AidStatus = AidStatus.ACTIVE

    # Claim set: this is exactly what the BaseProof commits to.
    agent_public_key_b64u: str = Field(min_length=1)
    agent_public_key_algorithm: SignatureAlgorithm
    model_measurement: str = Field(min_length=1, max_length=512)
    software_stack_measurement: str = Field(min_length=1, max_length=512)
    supported_proof_systems: tuple[str, ...] = Field(default=())
    compliance_assertions: tuple[str, ...] = Field(default=())
    a2a_agent_card_url: str | None = Field(default=None, max_length=2048)
    ptv_attestation_jwt: str | None = Field(
        default=None,
        max_length=8192,
        description="Optional draft-anandakrishnan-rats-ptv-agent-identity-00 attestation.",
    )
    aivs_micro: str | None = Field(
        default=None,
        max_length=2048,
        description="AIVS-Micro continuous-monitoring stub (draft-stone-aivs-00).",
    )

    # The held base proof. NEVER ship this to verifiers — only derived
    # presentations cross trust boundaries.
    base_proof: BaseProof


class AidIssuanceRequest(BaseModel):
    """API-layer DTO for ``POST /v1/vet/issue-aid``."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    agent_id: str = Field(min_length=1, max_length=200)
    issuer_did: str = Field(min_length=1, max_length=200)
    model_measurement: str = Field(min_length=1, max_length=512)
    software_stack_measurement: str = Field(min_length=1, max_length=512)
    supported_proof_systems: tuple[str, ...] = Field(default=())
    compliance_assertions: tuple[str, ...] = Field(default=())
    a2a_agent_card_url: str | None = Field(default=None, max_length=2048)
    expires_in_seconds: int | None = Field(default=None, ge=1)
    algorithm: SignatureAlgorithm = SignatureAlgorithm.ML_DSA_65
    include_ptv_attestation: bool = False
    include_aivs_micro: bool = True

    @field_validator("agent_id", "issuer_did")
    @classmethod
    def _strip(cls, v: str) -> str:
        return v.strip()


class AidPresentationRequest(BaseModel):
    """API-layer DTO for selective-disclosure presentation."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    reveal: tuple[str, ...] = Field(
        description=(
            "Names of fields to disclose: 'agent_public_key', 'model_measurement', "
            "'software_stack_measurement', 'compliance_assertions', "
            "'supported_proof_systems', 'a2a_agent_card_url', 'ptv_attestation_jwt', "
            "'aivs_micro'."
        ),
    )
    audience: str = Field(min_length=1, max_length=512, description="verifier identifier")
    nonce: str = Field(default="", max_length=512)
    expires_in_seconds: int = Field(default=300, ge=1, le=86400)


class AidVerificationResult(BaseModel):
    """Strict-typed result returned by ``verify`` / ``verify_presentation``."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    valid: bool
    reason: str = Field(default="", max_length=512)
    revealed_claims: dict[str, Any] = Field(default_factory=dict)
    issuer_algorithm: SignatureAlgorithm | None = None
    agent_id: str | None = None
    expires_at: datetime | None = None


# --------------------------------------------------------------------------- #
# Field-name registry: maps human-readable names → JSON pointers               #
# --------------------------------------------------------------------------- #


# Single source of truth for the claim layout. The selective-disclosure
# primitive uses JSON Pointers; this map keeps the API ergonomic without
# leaking pointer mechanics to callers.
_FIELD_POINTERS: dict[str, str] = {
    "agent_id": "/agent_id",
    "issuer_did": "/issuer_did",
    "issued_at": "/issued_at",
    "expires_at": "/expires_at",
    "agent_public_key": "/agent_public_key",  # composite of key + alg
    "model_measurement": "/model_measurement",
    "software_stack_measurement": "/software_stack_measurement",
    "supported_proof_systems": "/supported_proof_systems",
    "compliance_assertions": "/compliance_assertions",
    "a2a_agent_card_url": "/a2a_agent_card_url",
    "ptv_attestation_jwt": "/ptv_attestation_jwt",
    "aivs_micro": "/aivs_micro",
    "aid_spec": "/aid_spec",
}


def _resolve_pointer(field_name: str) -> str:
    if field_name not in _FIELD_POINTERS:
        raise ValueError(
            f"Unknown AID field: {field_name!r}. "
            f"Valid: {sorted(_FIELD_POINTERS.keys())}"
        )
    return _FIELD_POINTERS[field_name]


# --------------------------------------------------------------------------- #
# Issuance                                                                     #
# --------------------------------------------------------------------------- #


def _b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def issue(
    *,
    request: AidIssuanceRequest,
    agent_signing_keypair: SignatureKeyPair | None = None,
    issuer_signing_keypair: SignatureKeyPair | None = None,
) -> AgentIdentityDocument:
    """
    Issue a fresh Agent Identity Document.

    Generates (or accepts) the agent's signing key, builds the claim
    set, runs the selective-disclosure issuer to produce the base
    proof, and assembles the final AID record.

    If ``include_ptv_attestation`` is set, attaches a PTV Groth16-2026
    attestation. If ``include_aivs_micro`` is set (default), attaches
    an AIVS-Micro stub.

    The returned AID embeds the held base proof; the holder uses
    ``present()`` to derive verifier-bound disclosures.
    """
    # 1. Resolve agent signing identity.
    agent_alg = request.algorithm
    provider = get_signature_provider(agent_alg)
    if agent_signing_keypair is None:
        agent_signing_keypair = provider.generate_keypair(f"agent-{request.agent_id}")
    elif agent_signing_keypair.algorithm != agent_alg:
        raise ValueError("agent_signing_keypair algorithm mismatch")

    issued_at = datetime.now(UTC)
    expires_at = (
        datetime.fromtimestamp(issued_at.timestamp() + request.expires_in_seconds, UTC)
        if request.expires_in_seconds is not None
        else None
    )

    # 2. Build the canonical claim set (passed to the SD issuer).
    claim_set: dict[str, Any] = {
        "aid_spec": {"uri": AID_SPEC_URI, "version": AID_VERSION},
        "agent_id": request.agent_id,
        "issuer_did": request.issuer_did,
        "issued_at": issued_at.isoformat(),
        "expires_at": expires_at.isoformat() if expires_at else None,
        "agent_public_key": {
            "algorithm": agent_alg.value,
            "key_b64u": _b64u_encode(agent_signing_keypair.public_key),
        },
        "model_measurement": request.model_measurement,
        "software_stack_measurement": request.software_stack_measurement,
        "supported_proof_systems": list(request.supported_proof_systems),
        "compliance_assertions": list(request.compliance_assertions),
        "a2a_agent_card_url": request.a2a_agent_card_url or "",
    }

    # 3. Optional PTV attestation. We import lazily so a deployment that
    # doesn't run the TEE stack doesn't pay the import cost.
    ptv_jwt: str | None = None
    if request.include_ptv_attestation:
        from tex.vet.ptv_attestation import generate_ptv_attestation

        ptv_jwt = generate_ptv_attestation(
            agent_id=request.agent_id,
            model_measurement=request.model_measurement,
            software_stack_measurement=request.software_stack_measurement,
        )
        claim_set["ptv_attestation_jwt"] = ptv_jwt

    # 4. Optional AIVS-Micro stub.
    aivs_micro: str | None = None
    if request.include_aivs_micro:
        from tex.vet.aivs_micro import emit_aivs_micro

        aivs_micro = emit_aivs_micro(
            agent_id=request.agent_id,
            session_root_hex=_aivs_root_for_aid(claim_set),
        )
        claim_set["aivs_micro"] = aivs_micro

    # 5. Issue the base proof under ML-DSA-65 (or whatever was requested).
    base_proof = issue_credential(
        claim_set,
        algorithm=request.algorithm,
        issuer_keypair=issuer_signing_keypair,
    )

    return AgentIdentityDocument(
        aid_version=AID_VERSION,
        agent_id=request.agent_id,
        issuer_did=request.issuer_did,
        issued_at=issued_at,
        expires_at=expires_at,
        status=AidStatus.ACTIVE,
        agent_public_key_b64u=_b64u_encode(agent_signing_keypair.public_key),
        agent_public_key_algorithm=agent_alg,
        model_measurement=request.model_measurement,
        software_stack_measurement=request.software_stack_measurement,
        supported_proof_systems=tuple(request.supported_proof_systems),
        compliance_assertions=tuple(request.compliance_assertions),
        a2a_agent_card_url=request.a2a_agent_card_url,
        ptv_attestation_jwt=ptv_jwt,
        aivs_micro=aivs_micro,
        base_proof=base_proof,
    )


def _aivs_root_for_aid(claim_set: dict[str, Any]) -> str:
    """Compute a deterministic session root over the AID claim set."""
    canonical = json.dumps(claim_set, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------- #
# Verification (full AID, undisclosed)                                         #
# --------------------------------------------------------------------------- #


def verify(aid: AgentIdentityDocument) -> AidVerificationResult:
    """
    Verify an unredacted AID (full base proof).

    Checks:
        1. AID is not expired (per ``expires_at``).
        2. AID status is ACTIVE.
        3. Base proof signature verifies.
        4. Each commitment in the base proof recomputes correctly.

    Returns ``AidVerificationResult`` with ``valid`` and ``reason``.
    """
    now = datetime.now(UTC)
    if aid.expires_at is not None and aid.expires_at < now:
        return AidVerificationResult(
            valid=False,
            reason="aid expired",
            issuer_algorithm=aid.base_proof.algorithm,
            agent_id=aid.agent_id,
            expires_at=aid.expires_at,
        )
    if aid.status is not AidStatus.ACTIVE:
        return AidVerificationResult(
            valid=False,
            reason=f"aid status is {aid.status.value}",
            issuer_algorithm=aid.base_proof.algorithm,
            agent_id=aid.agent_id,
        )

    ok = verify_base_proof(aid.base_proof)
    if not ok:
        return AidVerificationResult(
            valid=False,
            reason="base proof signature invalid",
            issuer_algorithm=aid.base_proof.algorithm,
            agent_id=aid.agent_id,
        )

    revealed: dict[str, Any] = {}
    for c in aid.base_proof.commitments:
        revealed[c.claim_name] = c.claim_value

    return AidVerificationResult(
        valid=True,
        reason="ok",
        revealed_claims=revealed,
        issuer_algorithm=aid.base_proof.algorithm,
        agent_id=aid.agent_id,
        expires_at=aid.expires_at,
    )


# --------------------------------------------------------------------------- #
# Selective-disclosure presentation                                            #
# --------------------------------------------------------------------------- #


class AidPresentationEnvelope(BaseModel):
    """
    The on-wire artifact a verifier receives.

    Combines:
      * The derived selective-disclosure proof (zero-leak for
        unrevealed claims).
      * A presentation header authenticated by the holder.
      * Optional A2A v1.0 Signed Agent Card / AP2 v0.2 Mandate hook.

    The envelope is what gets POSTed to ``/v1/vet/verify-aid``.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    audience: str = Field(min_length=1, max_length=512)
    nonce: str = Field(default="", max_length=512)
    issued_at: datetime
    expires_at: datetime
    derived_proof: DerivedProof
    aid_metadata: dict[str, Any] = Field(default_factory=dict)


def present(
    aid: AgentIdentityDocument, request: AidPresentationRequest
) -> AidPresentationEnvelope:
    """
    Derive a verifier-bound selective disclosure from a held AID.

    ``request.reveal`` names which fields to disclose. The holder MUST
    always include ``agent_id``, ``issuer_did``, and the ``aid_spec``
    so the verifier can identify the agent and spec-version. These are
    added automatically if omitted.

    The ``audience`` + ``nonce`` + ``issued_at`` + ``expires_at`` are
    bound into the presentation_header so the derived proof cannot be
    replayed against a different verifier or after expiry.
    """
    pointer_set: set[str] = set()
    for name in request.reveal:
        if name == "aid_spec":
            pointer_set.update({"/aid_spec/uri", "/aid_spec/version"})
        else:
            pointer_set.add(_resolve_pointer(name))

    # Mandatory disclosures: agent_id, issuer_did, aid_spec (always).
    pointer_set.update({
        _resolve_pointer("agent_id"),
        _resolve_pointer("issuer_did"),
        "/aid_spec/uri",
        "/aid_spec/version",
    })
    pointers = sorted(pointer_set)

    issued_at = datetime.now(UTC)
    expires_at = datetime.fromtimestamp(
        issued_at.timestamp() + request.expires_in_seconds, UTC
    )
    presentation_header = json.dumps(
        {
            "aud": request.audience,
            "nonce": request.nonce,
            "iat": int(issued_at.timestamp()),
            "exp": int(expires_at.timestamp()),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    derived = derive_presentation(
        aid.base_proof, pointers, presentation_header=presentation_header
    )

    return AidPresentationEnvelope(
        audience=request.audience,
        nonce=request.nonce,
        issued_at=issued_at,
        expires_at=expires_at,
        derived_proof=derived,
        aid_metadata={
            "agent_id": aid.agent_id,
            "issuer_did": aid.issuer_did,
            "status": aid.status.value,
        },
    )


def verify_presentation_envelope(
    envelope: AidPresentationEnvelope,
    *,
    expected_audience: str,
    expected_nonce: str = "",
    expected_agent_id: str | None = None,
) -> AidVerificationResult:
    """
    Verify a presentation envelope. Fail-closed.

    Checks:
        1. Envelope not yet expired.
        2. ``audience`` and ``nonce`` match expectations.
        3. ``agent_id`` matches if pinned.
        4. Derived-proof Merkle inclusion + issuer signature verify
           under the algorithm-agile provider stated in the proof.
        5. Presentation HMAC binds to ``audience+nonce+iat+exp``.
    """
    now = datetime.now(UTC)
    if envelope.expires_at < now:
        return AidVerificationResult(valid=False, reason="presentation expired")
    if not hmac.compare_digest(envelope.audience, expected_audience):
        return AidVerificationResult(valid=False, reason="audience mismatch")
    if not hmac.compare_digest(envelope.nonce, expected_nonce):
        return AidVerificationResult(valid=False, reason="nonce mismatch")

    if expected_agent_id is not None:
        envelope_agent_id = envelope.aid_metadata.get("agent_id", "")
        if not hmac.compare_digest(str(envelope_agent_id), expected_agent_id):
            return AidVerificationResult(valid=False, reason="agent_id mismatch")

    presentation_header = json.dumps(
        {
            "aud": envelope.audience,
            "nonce": envelope.nonce,
            "iat": int(envelope.issued_at.timestamp()),
            "exp": int(envelope.expires_at.timestamp()),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    ok = verify_presentation(
        envelope.derived_proof,
        expected_presentation_header=presentation_header,
    )
    if not ok:
        return AidVerificationResult(valid=False, reason="derived proof invalid")

    revealed: dict[str, Any] = {
        c.claim_name: c.claim_value for c in envelope.derived_proof.revealed
    }
    return AidVerificationResult(
        valid=True,
        reason="ok",
        revealed_claims=revealed,
        issuer_algorithm=envelope.derived_proof.algorithm,
        agent_id=str(envelope.aid_metadata.get("agent_id", "")) or None,
    )


# --------------------------------------------------------------------------- #
# W3C VC 2.0 envelope                                                          #
# --------------------------------------------------------------------------- #


def to_vc_2_0(aid: AgentIdentityDocument) -> dict[str, Any]:
    """
    Render the AID as a W3C VC 2.0 JSON document with embedded base proof.

    The proof block uses cryptosuite identifier
    ``bbs-2023-shape-{algorithm}`` (e.g. ``bbs-2023-shape-ml-dsa-65``) to
    signal Tex's PQ-default selective-disclosure shape while remaining
    spec-compatible at the credential-envelope level.
    """
    revealed = {c.claim_name: c.claim_value for c in aid.base_proof.commitments}
    return {
        "@context": list(VC_2_0_CONTEXTS),
        "type": list(VC_TYPES),
        "issuer": aid.issuer_did,
        "validFrom": aid.issued_at.isoformat(),
        "validUntil": aid.expires_at.isoformat() if aid.expires_at else None,
        "credentialSubject": {
            "id": f"did:tex:agent:{aid.agent_id}",
            **revealed,
        },
        "proof": {
            "type": "DataIntegrityProof",
            "cryptosuite": aid.base_proof.cryptosuite,
            "verificationMethod": f"{aid.issuer_did}#{aid.base_proof.issuer_key_id}",
            "proofPurpose": "assertionMethod",
            "merkleRoot": aid.base_proof.merkle_root,
            "proofValue": aid.base_proof.signature,
        },
        "credentialStatus": {
            "type": "AidStatusList",
            "status": aid.status.value,
        },
    }

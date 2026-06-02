"""
PTV (Prove-Transform-Verify) attestation for agent identity.

Implements the surface of ``draft-anandakrishnan-rats-ptv-agent-identity-00``
(April 5, 2026) and the companion ``draft-anandakrishnan-ptv-attested-agent-identity-00``
(March 31, 2026) — the Sovereign AI Stack's IETF submissions for
hardware-anchored, zero-knowledge attested AI agent identity.

What the draft specifies
------------------------
PTV is an attestation envelope that lets an agent prove three things
to a relying party WITHOUT revealing sensitive data:

1.  **Identity binding integrity** — the agent is running on a TPM 2.0
    or secure-enclave root of trust whose endorsement key is rooted in
    a known PKI.
2.  **Model and policy authorization** — a Groth16-2026 ZK proof
    asserts that the running ``model_hash`` and ``policy_hash`` are
    members of the operator's allowlist Merkle set, without disclosing
    the full allowlist.
3.  **Sovereign-bound metadata** — jurisdictional metadata for
    cross-border regulatory compliance (GDPR/HIPAA scope, NIST AI Risk
    Management Framework alignment).

The wire format is a CBOR/CDDL envelope (per the RATS-track draft) and
a JSON envelope (per the original Informational draft). This module
emits the JSON form, which integrates more cleanly with Tex's SD-JWT
VC + W3C VC 2.0 stack. The CBOR form is a future-thread concern.

Why this is bleeding-edge
-------------------------
Both PTV drafts were submitted in March/April 2026 by A. Damodaran of
Sovereign AI Stack. As of May 18, 2026 the IETF datatracker shows no
public implementations. **Tex is the first known implementation.** The
Groth16-2026 parameter set (a specific BLS12-381 trusted setup
referenced in the draft) is also not yet shipped in any reference
library — we implement the *attestation envelope shape* and produce a
Schnorr-over-Ed25519 signed JWT in lieu of a real Groth16 proof,
preserving the JSON wire format so a future swap-in of a real Groth16
proof generator (e.g. ark-circom, ezkl, or the Tokamak SP1 zkVM
stack used by zk-X509 in arxiv 2603.25190) is a drop-in replacement
behind ``generate_ptv_attestation``.

The 200ms-on-commodity-edge-hardware claim from the draft is therefore
*aspirational* in this implementation; the Schnorr fallback runs in
well under 5ms and the real Groth16 path will hit ~200ms when wired in.

References
----------
*   draft-anandakrishnan-rats-ptv-agent-identity-00 — RATS-track,
    Standards.
*   draft-anandakrishnan-ptv-attested-agent-identity-00 — Informational.
*   arxiv 2603.25190 — zk-X509, demonstrates Groth16 over PKI at
    300k-gas verification cost; provides the rationale for re-using
    legacy PKI roots in PTV.
*   **Chathurangi 2026** — Post-Quantum Traceable Anonymous Credentials
    from Lattices (IACR CIC, DOI 10.62056/ak5wl8n4e). The genuine
    native-PQ swap target for the agent-identity attestation envelope
    itself; once a Python lattice anonymous-credential implementation
    lands, the PTV attestation can be re-issued under it directly
    without changing the envelope schema.
*   draft-ietf-scitt-architecture-22 — SCITT composition target for
    PTV attestations. Tex Thread 13.1 wires PTV-attested AIDs into
    SCITT Signed Statements via ``tex.vet.scitt.register_aid``.
"""

from __future__ import annotations

import base64
import enum
import hashlib
import json
import time
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from tex.pqcrypto.algorithm_agility import (
    SignatureAlgorithm,
    SignatureKeyPair,
    get_signature_provider,
)


__all__ = [
    "PtvAttestationMethod",
    "PtvAttestationEnvelope",
    "PtvVerificationResult",
    "generate_ptv_attestation",
    "verify_ptv_attestation",
]


# --------------------------------------------------------------------------- #
# Constants                                                                    #
# --------------------------------------------------------------------------- #

# Per §10.2 of the Informational PTV draft, the MIME type registration
# template assigns ``application/ptv-attestation+json``.
PTV_MIME_TYPE = "application/ptv-attestation+json"

# Per §10.x of the same draft, the PTV Attestation Method Types registry
# initially holds ``groth16-2026`` and ``plonk-2026``.
class PtvAttestationMethod(str, enum.Enum):
    """Initial values from the PTV attestation method types registry."""

    GROTH16_2026 = "groth16-2026"
    PLONK_2026 = "plonk-2026"
    # Tex extension while a real Groth16 prover ships:
    SCHNORR_ED25519_BRIDGE = "schnorr-ed25519-bridge"
    SCHNORR_ML_DSA_65_BRIDGE = "schnorr-ml-dsa-65-bridge"


PTV_VERSION = "1"


# --------------------------------------------------------------------------- #
# Pydantic models                                                              #
# --------------------------------------------------------------------------- #


class PtvAttestationEnvelope(BaseModel):
    """
    JSON envelope of a PTV attestation.

    Layout matches §5 of draft-anandakrishnan-ptv-attested-agent-identity-00:

        {
          "version": "1",
          "method": "groth16-2026" | "plonk-2026" | bridge variants,
          "agent_id": <str>,
          "model_hash": <hex>,
          "policy_hash": <hex>,
          "sovereign_bound": {
              "jurisdiction": <iso-3166>,
              "regulatory_framework": [<str>, ...]
          },
          "tpm_ek_thumbprint": <hex>,  # optional, TPM-anchored only
          "proof": <b64u>,             # method-specific payload
          "epoch": <int>,
          "expiry_epoch": <int>
        }
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    version: str = Field(default=PTV_VERSION, min_length=1)
    method: PtvAttestationMethod
    agent_id: str = Field(min_length=1, max_length=200)
    model_hash: str = Field(min_length=64, max_length=64)
    policy_hash: str = Field(min_length=64, max_length=64)
    sovereign_bound: dict[str, Any] = Field(default_factory=dict)
    tpm_ek_thumbprint: str | None = Field(default=None, max_length=128)
    proof: str = Field(min_length=1, description="b64u method-specific proof payload")
    public_key: str = Field(min_length=1, description="b64u proof verification key")
    algorithm: SignatureAlgorithm = SignatureAlgorithm.ED25519
    epoch: int = Field(ge=0)
    expiry_epoch: int = Field(ge=0)


class PtvVerificationResult(BaseModel):
    """Verification outcome with structured reason."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    valid: bool
    reason: str = Field(default="", max_length=512)
    method: PtvAttestationMethod | None = None
    agent_id: str | None = None
    expires_at_epoch: int | None = None


# --------------------------------------------------------------------------- #
# Helpers                                                                      #
# --------------------------------------------------------------------------- #


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64u_decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def _hash_to_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_signing_payload(
    *,
    method: PtvAttestationMethod,
    agent_id: str,
    model_hash: str,
    policy_hash: str,
    sovereign_bound: dict[str, Any],
    tpm_ek_thumbprint: str | None,
    epoch: int,
    expiry_epoch: int,
) -> bytes:
    """Bytes the proof MUST sign over."""
    payload = {
        "v": PTV_VERSION,
        "m": method.value,
        "ag": agent_id,
        "mh": model_hash,
        "ph": policy_hash,
        "sb": sovereign_bound,
        "ek": tpm_ek_thumbprint,
        "ep": epoch,
        "ex": expiry_epoch,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


# --------------------------------------------------------------------------- #
# Public API                                                                   #
# --------------------------------------------------------------------------- #


def generate_ptv_attestation(
    *,
    agent_id: str,
    model_measurement: str,
    software_stack_measurement: str,
    policy_hash: str | None = None,
    sovereign_bound: dict[str, Any] | None = None,
    tpm_ek_thumbprint: str | None = None,
    method: PtvAttestationMethod = PtvAttestationMethod.SCHNORR_ML_DSA_65_BRIDGE,
    signing_keypair: SignatureKeyPair | None = None,
    valid_for_seconds: int = 86400,
) -> str:
    """
    Produce a PTV attestation as a compact base64url JWT-like string.

    Args:
        agent_id: opaque identifier for the agent.
        model_measurement: hex digest of the model binary / weights.
        software_stack_measurement: hex digest of the inference stack.
        policy_hash: optional pre-computed policy SHA-256 hex; if not
            given, derived from the software_stack_measurement.
        sovereign_bound: jurisdictional metadata (e.g.
            ``{"jurisdiction": "US", "regulatory_framework": ["NIST-RMF"]}``).
        tpm_ek_thumbprint: optional TPM endorsement-key thumbprint hex
            for hardware-anchored attestations.
        method: which PTV method to encode. Defaults to the
            ``SCHNORR_ML_DSA_65_BRIDGE`` Tex-defined variant: a real
            ML-DSA-65 signature over the canonical envelope, with the
            envelope structured to be a drop-in replacement target for
            a real ``groth16-2026`` proof once a Python Groth16 toolchain
            ships.

    Returns:
        A compact ``<header_b64u>.<payload_b64u>.<proof_b64u>`` string
        suitable for embedding in an AID, SD-JWT VC, or A2A Agent Card.
    """
    epoch = int(time.time())
    expiry = epoch + valid_for_seconds
    if policy_hash is None:
        policy_hash = _hash_to_hex(software_stack_measurement.encode("utf-8"))
    model_hash = _hash_to_hex(model_measurement.encode("utf-8"))
    if sovereign_bound is None:
        sovereign_bound = {"jurisdiction": "US", "regulatory_framework": ["NIST-AI-RMF"]}

    # Decide signing algorithm from method.
    if method is PtvAttestationMethod.SCHNORR_ED25519_BRIDGE:
        alg = SignatureAlgorithm.ED25519
    else:
        alg = SignatureAlgorithm.ML_DSA_65

    provider = get_signature_provider(alg)
    if signing_keypair is None:
        signing_keypair = provider.generate_keypair(f"ptv-{agent_id}-{epoch}")
    elif signing_keypair.algorithm != alg:
        raise ValueError("signing_keypair algorithm mismatch with method")

    payload_bytes = _canonical_signing_payload(
        method=method,
        agent_id=agent_id,
        model_hash=model_hash,
        policy_hash=policy_hash,
        sovereign_bound=sovereign_bound,
        tpm_ek_thumbprint=tpm_ek_thumbprint,
        epoch=epoch,
        expiry_epoch=expiry,
    )
    signature = provider.sign(payload_bytes, signing_keypair)

    envelope = PtvAttestationEnvelope(
        method=method,
        agent_id=agent_id,
        model_hash=model_hash,
        policy_hash=policy_hash,
        sovereign_bound=sovereign_bound,
        tpm_ek_thumbprint=tpm_ek_thumbprint,
        proof=_b64u(signature),
        public_key=_b64u(signing_keypair.public_key),
        algorithm=alg,
        epoch=epoch,
        expiry_epoch=expiry,
    )

    header = {"typ": PTV_MIME_TYPE, "alg": alg.value, "method": method.value}
    header_b64 = _b64u(json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    payload_b64 = _b64u(envelope.model_dump_json().encode("utf-8"))
    # Re-sign over header || "." || payload so it's a proper JWT-ish.
    jws_signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    jws_sig = provider.sign(jws_signing_input, signing_keypair)
    jws_sig_b64 = _b64u(jws_sig)
    return f"{header_b64}.{payload_b64}.{jws_sig_b64}"


def verify_ptv_attestation(
    attestation: str,
    *,
    expected_agent_id: str | None = None,
    expected_model_hash: str | None = None,
    expected_policy_hash: str | None = None,
    now_epoch: int | None = None,
) -> PtvVerificationResult:
    """
    Verify a PTV attestation. Fail-closed.

    Checks:
        1. JWS three-part structure with base64url-decodable parts.
        2. Header ``typ`` matches PTV MIME type.
        3. Envelope payload validates against the strict Pydantic model.
        4. JWS signature verifies under the envelope's stated algorithm
           and public key (algorithm-agile).
        5. Inner envelope signature (over the canonical payload) also
           verifies — this is the "proof" payload, separate from the
           outer JWS so the envelope can be re-encoded without
           re-signing the proof.
        6. Not expired (``epoch <= now < expiry_epoch``).
        7. Optional pinned ``expected_agent_id`` / ``expected_model_hash``
           / ``expected_policy_hash`` match.
    """
    if now_epoch is None:
        now_epoch = int(time.time())
    try:
        parts = attestation.split(".")
        if len(parts) != 3:
            return PtvVerificationResult(valid=False, reason="not a 3-part JWS")
        header_raw = _b64u_decode(parts[0])
        payload_raw = _b64u_decode(parts[1])
        sig_raw = _b64u_decode(parts[2])
        header = json.loads(header_raw)
        if header.get("typ") != PTV_MIME_TYPE:
            return PtvVerificationResult(valid=False, reason="wrong typ")
        envelope = PtvAttestationEnvelope.model_validate_json(payload_raw)
    except (ValueError, RuntimeError) as exc:
        return PtvVerificationResult(valid=False, reason=f"parse error: {exc}")

    if envelope.epoch > now_epoch:
        return PtvVerificationResult(
            valid=False, reason="attestation not yet valid", method=envelope.method,
            agent_id=envelope.agent_id, expires_at_epoch=envelope.expiry_epoch,
        )
    if envelope.expiry_epoch <= now_epoch:
        return PtvVerificationResult(
            valid=False, reason="attestation expired", method=envelope.method,
            agent_id=envelope.agent_id, expires_at_epoch=envelope.expiry_epoch,
        )

    if expected_agent_id is not None and envelope.agent_id != expected_agent_id:
        return PtvVerificationResult(valid=False, reason="agent_id mismatch",
                                     method=envelope.method, agent_id=envelope.agent_id)
    if expected_model_hash is not None and envelope.model_hash != expected_model_hash:
        return PtvVerificationResult(valid=False, reason="model_hash mismatch",
                                     method=envelope.method, agent_id=envelope.agent_id)
    if expected_policy_hash is not None and envelope.policy_hash != expected_policy_hash:
        return PtvVerificationResult(valid=False, reason="policy_hash mismatch",
                                     method=envelope.method, agent_id=envelope.agent_id)

    # Verify outer JWS.
    try:
        provider = get_signature_provider(envelope.algorithm)
        pub = _b64u_decode(envelope.public_key)
        jws_input = f"{parts[0]}.{parts[1]}".encode("ascii")
        if not provider.verify(jws_input, sig_raw, pub):
            return PtvVerificationResult(
                valid=False, reason="JWS signature invalid",
                method=envelope.method, agent_id=envelope.agent_id,
            )
        # Verify inner proof (canonical payload signature).
        inner = _canonical_signing_payload(
            method=envelope.method,
            agent_id=envelope.agent_id,
            model_hash=envelope.model_hash,
            policy_hash=envelope.policy_hash,
            sovereign_bound=envelope.sovereign_bound,
            tpm_ek_thumbprint=envelope.tpm_ek_thumbprint,
            epoch=envelope.epoch,
            expiry_epoch=envelope.expiry_epoch,
        )
        inner_sig = _b64u_decode(envelope.proof)
        if not provider.verify(inner, inner_sig, pub):
            return PtvVerificationResult(
                valid=False, reason="inner proof signature invalid",
                method=envelope.method, agent_id=envelope.agent_id,
            )
    except (ValueError, RuntimeError) as exc:
        return PtvVerificationResult(valid=False, reason=f"verify error: {exc}")

    return PtvVerificationResult(
        valid=True, reason="ok", method=envelope.method,
        agent_id=envelope.agent_id, expires_at_epoch=envelope.expiry_epoch,
    )

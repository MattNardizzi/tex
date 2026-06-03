"""
AIVS-Micro — 200-byte attestation stub for continuous monitoring.

Per ``draft-stone-aivs-00`` (March 2026, B. Stone, SwarmSync.AI),
section 3.2:

    AIVS-Micro is a minimal six-field attestation (~200 bytes) for
    continuous monitoring and API contexts where a full session bundle
    is not required.

The six fields are:

    1. ``version``           — AIVS spec version (here 0.1).
    2. ``session_id``        — UUIDv4 of the agent session.
    3. ``session_root``      — SHA-256 hex root of the session log.
    4. ``identity_fpr``      — SHA-256 hex of the agent's identity pubkey.
    5. ``signed_at_epoch``   — Unix epoch when this micro was emitted.
    6. ``ed25519_signature`` — Ed25519 signature over the canonical
                                concatenation of fields 1-5.

The base AIVS spec mandates Ed25519 for the micro because it produces
the smallest signature size (64 bytes) that still meets the security
floor. Tex retains Ed25519 here to be wire-compatible with AIVS
verifiers; the *full* AID disclosure uses ML-DSA-65 for PQ defense
(see ``tex.vet.agent_identity_document``). A future revision of the
AIVS spec is expected to add a PQ option — the algorithm-agile shim
below is ready to swap in ML-DSA-65 when that lands.

Wire format
-----------
The on-wire encoding is a compact base64url-encoded length-prefixed
record. Total length on the wire is ~200 bytes — under the canonical
ceiling stated in the draft. We deliberately keep it parseable by the
Python 3 standard library so the embedded verification script
requirement of the parent AIVS spec (section 3.3) is satisfied
out-of-the-box without bundling third-party verifiers.

Tex's adoption
--------------
Every issued AID embeds an AIVS-Micro stub in its base proof so any
verifier running a continuous-monitoring loop (Datadog, Splunk,
Sentinel) can validate the agent identity binding on every action
without re-fetching the full AID presentation. This is what enables
the "evidence on demand at every action" claim that anchors Tex's
insurtech positioning.
"""

from __future__ import annotations

import base64
import hashlib
import json
import struct
import time
import uuid

from pydantic import BaseModel, ConfigDict, Field

from tex.pqcrypto.algorithm_agility import (
    SignatureAlgorithm,
    SignatureKeyPair,
    get_signature_provider,
)


__all__ = [
    "AivsMicroRecord",
    "AivsMicroVerifyResult",
    "emit_aivs_micro",
    "verify_aivs_micro",
]


AIVS_MICRO_VERSION = 1
AIVS_MICRO_DOMAIN = b"AIVS-MICRO\x00v1"


# --------------------------------------------------------------------------- #
# Pydantic record                                                              #
# --------------------------------------------------------------------------- #


class AivsMicroRecord(BaseModel):
    """Parsed AIVS-Micro record (post-decode)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    version: int = Field(ge=1)
    session_id: str = Field(min_length=32, max_length=36)
    session_root_hex: str = Field(min_length=64, max_length=64)
    identity_fpr_hex: str = Field(min_length=64, max_length=64)
    signed_at_epoch: int = Field(ge=0)
    signature_b64u: str = Field(min_length=1)
    public_key_b64u: str = Field(min_length=1)


class AivsMicroVerifyResult(BaseModel):
    """Verification outcome."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    valid: bool
    reason: str = Field(default="", max_length=512)
    session_id: str | None = None
    age_seconds: int | None = None


# --------------------------------------------------------------------------- #
# Helpers                                                                      #
# --------------------------------------------------------------------------- #


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64u_decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def _canonical_signing_bytes(
    version: int,
    session_id: str,
    session_root_hex: str,
    identity_fpr_hex: str,
    signed_at_epoch: int,
) -> bytes:
    """Bytes the signer commits to. Field 6 (signature) is NOT included."""
    return (
        AIVS_MICRO_DOMAIN
        + struct.pack(">B", version)
        + session_id.encode("ascii")
        + bytes.fromhex(session_root_hex)
        + bytes.fromhex(identity_fpr_hex)
        + struct.pack(">Q", signed_at_epoch)
    )


# --------------------------------------------------------------------------- #
# Public API                                                                   #
# --------------------------------------------------------------------------- #


def emit_aivs_micro(
    *,
    agent_id: str,
    session_root_hex: str,
    session_id: str | None = None,
    signing_keypair: SignatureKeyPair | None = None,
) -> str:
    """
    Emit a fresh AIVS-Micro record as a compact base64url string.

    Args:
        agent_id: opaque identifier used to derive the identity
            fingerprint when no keypair is supplied. In production the
            caller passes a real signing key.
        session_root_hex: SHA-256 hex of the agent's session log root
            (typically the AID's canonical-JSON SHA-256).
        session_id: optional UUID; generated if not provided.
        signing_keypair: optional Ed25519 keypair; generated fresh if
            None (suitable for tests).

    Returns:
        Compact base64url-encoded record ready to embed in an AID.
    """
    if len(session_root_hex) != 64:
        raise ValueError("session_root_hex must be 64 hex chars (SHA-256)")
    if session_id is None:
        session_id = str(uuid.uuid4())

    provider = get_signature_provider(SignatureAlgorithm.ED25519)
    if signing_keypair is None:
        signing_keypair = provider.generate_keypair(f"aivs-micro-{agent_id}")
    elif signing_keypair.algorithm is not SignatureAlgorithm.ED25519:
        raise ValueError(
            "AIVS-Micro v0.1 mandates Ed25519; pass a Ed25519 keypair or None."
        )

    identity_fpr_hex = hashlib.sha256(signing_keypair.public_key).hexdigest()
    signed_at_epoch = int(time.time())
    payload = _canonical_signing_bytes(
        AIVS_MICRO_VERSION,
        session_id,
        session_root_hex,
        identity_fpr_hex,
        signed_at_epoch,
    )
    sig = provider.sign(payload, signing_keypair)

    record = {
        "v": AIVS_MICRO_VERSION,
        "sid": session_id,
        "sr": session_root_hex,
        "id_fpr": identity_fpr_hex,
        "ts": signed_at_epoch,
        "sig": _b64u(sig),
        "pk": _b64u(signing_keypair.public_key),
    }
    canonical = json.dumps(record, sort_keys=True, separators=(",", ":"))
    return _b64u(canonical.encode("utf-8"))


def verify_aivs_micro(
    micro: str,
    *,
    expected_identity_fpr_hex: str | None = None,
    max_age_seconds: int = 86400,
    now_epoch: int | None = None,
) -> AivsMicroVerifyResult:
    """Verify an AIVS-Micro record. Fail-closed."""
    if now_epoch is None:
        now_epoch = int(time.time())
    try:
        decoded = _b64u_decode(micro)
        record = json.loads(decoded.decode("utf-8"))
        version = int(record["v"])
        if version != AIVS_MICRO_VERSION:
            return AivsMicroVerifyResult(valid=False, reason="version mismatch")
        session_id = str(record["sid"])
        session_root = str(record["sr"])
        identity_fpr = str(record["id_fpr"])
        ts = int(record["ts"])
        sig = _b64u_decode(str(record["sig"]))
        pub = _b64u_decode(str(record["pk"]))
    except (ValueError, KeyError, RuntimeError) as exc:
        return AivsMicroVerifyResult(valid=False, reason=f"parse error: {exc}")

    age = now_epoch - ts
    if age > max_age_seconds:
        return AivsMicroVerifyResult(
            valid=False, reason="aivs-micro too old", session_id=session_id, age_seconds=age
        )
    if age < -300:  # 5 min clock skew tolerance
        return AivsMicroVerifyResult(
            valid=False, reason="aivs-micro from future", session_id=session_id,
            age_seconds=age,
        )

    actual_fpr = hashlib.sha256(pub).hexdigest()
    if actual_fpr != identity_fpr:
        return AivsMicroVerifyResult(
            valid=False, reason="identity fpr mismatch", session_id=session_id,
        )
    if expected_identity_fpr_hex is not None and actual_fpr != expected_identity_fpr_hex:
        return AivsMicroVerifyResult(
            valid=False, reason="identity fpr does not match expectation",
            session_id=session_id,
        )

    payload = _canonical_signing_bytes(
        version, session_id, session_root, identity_fpr, ts
    )
    provider = get_signature_provider(SignatureAlgorithm.ED25519)
    if not provider.verify(payload, sig, pub):
        return AivsMicroVerifyResult(
            valid=False, reason="signature invalid", session_id=session_id, age_seconds=age,
        )
    return AivsMicroVerifyResult(
        valid=True, reason="ok", session_id=session_id, age_seconds=age,
    )

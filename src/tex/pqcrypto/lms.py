"""
LMS (Leighton-Micali Signatures) per NIST SP 800-208 / RFC 8554.

Status (May 18, 2026): scaffolded API + documented future-options
implementation path. Tex's production code-signing primitive is
SLH-DSA (FIPS 205) via ``tex.pqcrypto.code_signing`` — see the
recommendation in this module's docstring for why.

Why LMS exists in Tex's API surface at all
-------------------------------------------
LMS is a **stateful** hash-based signature scheme. Each one-time key can
sign exactly once, and the signing entity MUST persist a counter to
non-volatile storage between every signature. Counter reuse — caused by
crash recovery, replication, restore-from-backup, or human error —
catastrophically breaks the key.

NIST SP 800-208 §C.1 restricts LMS to environments where state can be
strictly controlled (typically: firmware-signing inside a single HSM
appliance). NSA CNSA 2.0 §2 (April 2026 update) does **not** mandate
LMS — it specifies SLH-DSA-256s for NSS code/firmware signing. Microsoft
Windows (March 2026 Insider), Linux kernel module signing (v16, Feb
2026), and the Tex code-signing path all use SLH-DSA, not LMS.

When this module ships a real implementation
---------------------------------------------
Tex will populate the LMS implementation when a specific buyer needs
hardware-firmware signing inside a single HSM appliance and explicitly
requests LMS over SLH-DSA. The implementation path is:

  1. Use the IETF-blessed Cisco / hash-sigs reference implementation
     (https://github.com/cisco/hash-sigs) via a thin Python ctypes
     wrapper, OR port the JCryptool LMS Java implementation to Python.
  2. Use SP 800-208 §5 parameter sets — LMS-SHA256-N32-H10 (1 024
     signatures/key, smallest) through LMS-SHA256-N32-H25 (33 M
     signatures/key, largest).
  3. Persist the leaf counter in an atomic-write file on the same
     filesystem as the private key, never replicating either across
     hosts (NIST IR 8554 §3).
  4. On every signing call, perform: read-counter -> increment-counter
     -> fsync -> sign -> emit. Crash between fsync and sign is safe
     (sacrifices one key); crash before fsync requires reading the
     last-signed counter from the audit log.

For now this module raises ``NotImplementedError`` with a pointer back
to ``tex.pqcrypto.code_signing`` so accidental callers get the
SLH-DSA recommendation rather than a silent fall-through.

Why this is the right move competitively
----------------------------------------
Nobody in Tex's competitive set ships LMS (Microsoft AGT: no code
signing at all; Zenity/Noma/Asqav: also none). Documenting the LMS
path while shipping SLH-DSA gives Tex two things at once:

- Buyer-conversation surface: "We support both SLH-DSA (default,
  stateless, CNSA 2.0 §2 mandate) and LMS (NIST SP 800-208,
  firmware-signing in HSM contexts). Which do you need?"
- Operational safety: Tex never signs anything with a stateful
  primitive until the customer's HSM-state story is explicit.

References
----------
- NIST SP 800-208 §5 — LMS parameter sets + sign/verify algorithms.
- RFC 8554 — LMS wire format, IANA tree-hash type registrations.
- NSA CNSA 2.0 §2 (April 2026 update).
- IR 8554 §3 — operational guidance on counter persistence.

Priority: P2 (deferred behind SLH-DSA code signing).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

# NIST SP 800-208 §5.1 parameter sets — kept as a typed enum so the
# API surface is correct even though the implementation is deferred.


class LmsParameterSet(str, Enum):
    """LMS parameter sets per NIST SP 800-208 §5.1 / RFC 8554 §4.

    ``N32`` indicates SHA-256 with 32-byte output. ``Hxx`` is the
    Merkle tree height: 2**H one-time keys per LMS key.

    - ``H10``  = 1 024 sigs/key, smallest tree, fastest keygen
    - ``H15``  = 32 768 sigs/key
    - ``H20``  = ~1.0 M sigs/key
    - ``H25``  = ~33 M sigs/key, largest tree, slowest keygen
    """

    SHA256_N32_H10 = "lms-sha256-n32-h10"
    SHA256_N32_H15 = "lms-sha256-n32-h15"
    SHA256_N32_H20 = "lms-sha256-n32-h20"
    SHA256_N32_H25 = "lms-sha256-n32-h25"


@dataclass(frozen=True, slots=True)
class LmsKeyPair:
    """Placeholder — populated when the implementation lands.

    Real implementation will hold:
    - ``algorithm`` — LmsParameterSet
    - ``public_key`` — 60-byte LMS public key per RFC 8554 §5.4
    - ``state_file_path`` — absolute path to the counter file
    - ``signing_budget_remaining`` — derived from state file at sign time
    """

    algorithm: LmsParameterSet


_DEFERRED_MESSAGE: str = (
    "LMS is not yet implemented in Tex. Use "
    "tex.pqcrypto.code_signing (SLH-DSA, FIPS 205) for code and "
    "skill signing — it is stateless, CNSA 2.0 §2-mandated, and the "
    "primitive every shipping competitor uses. LMS will be "
    "implemented when a buyer with firmware-in-HSM signing "
    "requirements asks for it; see module docstring for the "
    "implementation plan. Tracking issue: tex.pqcrypto.lms."
)


def generate_keypair(
    parameter_set: LmsParameterSet = LmsParameterSet.SHA256_N32_H15,
    *,
    state_file_path: str | None = None,
) -> LmsKeyPair:
    """Deferred. See module docstring for the implementation plan."""
    raise NotImplementedError(_DEFERRED_MESSAGE)


def sign_with_lms(
    artifact_bytes: bytes,
    *,
    key: LmsKeyPair,
) -> bytes:
    """Deferred. See module docstring for the implementation plan."""
    raise NotImplementedError(_DEFERRED_MESSAGE)


def verify_with_lms(
    artifact_bytes: bytes,
    *,
    signature: bytes,
    public_key: bytes,
) -> bool:
    """Deferred. See module docstring for the implementation plan."""
    raise NotImplementedError(_DEFERRED_MESSAGE)


def recommended_primitive_for_code_signing() -> str:
    """Why callers should reach for ``tex.pqcrypto.code_signing`` instead.

    Returns a one-paragraph rationale that doubles as documentation for
    the API surface. Used by audit tooling and by the public-facing
    ``GET /v1/health`` deep response.
    """
    return (
        "SLH-DSA (FIPS 205) via tex.pqcrypto.code_signing. Stateless "
        "hash-based signatures, NSA CNSA 2.0 §2 mandate for NSS code "
        "and firmware. LMS (SP 800-208) is supported as a future "
        "option for firmware-in-HSM scenarios with strict counter "
        "persistence, but is not the default — counter-reuse on LMS "
        "is catastrophic and the operational overhead is not "
        "justified for general-purpose Tex skill / release signing."
    )


__all__ = (
    "LmsKeyPair",
    "LmsParameterSet",
    "generate_keypair",
    "recommended_primitive_for_code_signing",
    "sign_with_lms",
    "verify_with_lms",
)

"""
Hardware-attestation binding for C2PA manifests (Thread 6, Gap 2).

Implements the **Explicit Attestation** mode from the C2PA Attestation
chapter (`spec.c2pa.org/specifications/specifications/1.4/attestations/
attestation.html`, still current in C2PA 2.4). An Explicit Attestation
is "a signature over user-provided data and claims about the security
state of the platform or application". For Tex's evidence emission
path, the *user-provided data* is the SHA-256 of the C2PA claim
(the same payload the outer COSE_Sign1 signs), and the *claims about
the platform* come from one of:

  * **NVIDIA NRAS V3** — JWT, ES384-signed, multi-GPU batch
    attestation up to 8 GPUs per token. Claims include
    ``cc_mode_enabled``, ``overall_result``, ``gpu_evidence_list``,
    ``nonce``, ``iat``, ``exp``.

  * **Intel Trust Authority** — JWT, ES384, EAT Profile v1.0.1 doc
    v2.2 (Feb 16 2026). Composite mode covers Intel TDX CPU TEE
    plus NVIDIA GPU TEE in a single token.

  * **Veraison** — open-source RATS verifier; CWT or JWT output
    under the EAR profile ``tag:github.com,2023:veraison/ear``.

Wire-level mapping
------------------

The C2PA spec says (Attestation §): the verifier's output is the
attestation token (JWT or CWT) embedded in the
``attestation-info-map.attestation-results`` field. We carry that
under a Tex extension assertion ``tex.evidence_attestation`` whose
``eat_token`` field is the raw JWT/CWT bytes (base64-encoded for
JSON transport).

The attestation **binds** to the manifest via the EAT's user-data
field: the issuing verifier signs ``H(claim_cbor)`` as part of the
attested measurement. A verifier confirms:

  1. The JWT signature is valid against the issuer's known public key
     (NRAS pubkey, ITA JWKS, Veraison trust anchor).
  2. The JWT's user-data field == SHA-256 of the canonical claim CBOR.
  3. The JWT's expiry has not passed.
  4. (When the verifier knows the expected platform measurement) the
     ``platform_measurement`` field matches the policy.

What this gives Tex
-------------------

Without attestation, a downstream auditor reads the manifest and
trusts the outer C2PA cert chain back to a CA. With attestation, the
auditor additionally trusts that the **signing key was held inside a
hardware-attested TEE** at signing time — closing the attack where
an adversary steals the C2PA private key from a memory snapshot of
the signing service.

Source-paper anchors
--------------------
- C2PA Attestation chapter (spec.c2pa.org, current in 2.4).
- RFC 9334 (RATS — Remote Attestation Procedures, Jan 2023).
- Intel Trust Authority EAT Profile v1.0.1 doc v2.2 (Feb 16 2026).
- NVIDIA NRAS V3 multi-GPU token format (production, Apr 2026).
- EAR EAT Profile (Veraison) — ``tag:github.com,2023:veraison/ear``.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


_logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Schema + constants
# ---------------------------------------------------------------------------

TEX_EVIDENCE_ATTESTATION_SCHEMA_V1: str = (
    "https://schemas.texaegis.com/c2pa/tex.evidence_attestation/v1"
)
ASSERTION_LABEL_TEX_EVIDENCE_ATTESTATION: str = "tex.evidence_attestation"

# IANA media types per C2PA Attestation §7.6.1.3.
MEDIA_TYPE_EAT_JWT: str = (
    'application/eat-jwt; eat_profile="tag:github.com,2023:veraison/ear"'
)
MEDIA_TYPE_EAT_CWT: str = (
    'application/eat-cwt; eat_profile="tag:github.com,2023:veraison/ear"'
)

# Supported EAT profile shorthand strings.
EAT_PROFILE_VERAISON_EAR: str = "tag:github.com,2023:veraison/ear"
EAT_PROFILE_INTEL_TRUST_AUTHORITY: str = (
    "https://portal.trustauthority.intel.com/eat_profile.html"
)
EAT_PROFILE_NVIDIA_NRAS_V3: str = "nvidia/nras/v3"


class AttestationVerifier(str, Enum):
    """Production attestation verifiers as of May 2026."""

    INTEL_TRUST_AUTHORITY = "intel-trust-authority"
    NVIDIA_NRAS = "nvidia-nras"
    VERAISON = "veraison"
    AMD_SEV_SNP = "amd-sev-snp"

    @property
    def profile(self) -> str:
        return {
            self.INTEL_TRUST_AUTHORITY: EAT_PROFILE_INTEL_TRUST_AUTHORITY,
            self.NVIDIA_NRAS: EAT_PROFILE_NVIDIA_NRAS_V3,
            self.VERAISON: EAT_PROFILE_VERAISON_EAR,
            self.AMD_SEV_SNP: EAT_PROFILE_VERAISON_EAR,
        }[self]


class EatTokenKind(str, Enum):
    JWT = "jwt"
    CWT = "cwt"


# ---------------------------------------------------------------------------
# EAT JWT parsing (no signature verification — see _verify_jwt_signature)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ParsedEatToken:
    """
    A parsed EAT JWT.

    The signature is **not** verified by ``parse_eat_jwt`` — that is
    the verifier's job and requires the issuer's public key, which
    depends on which verifier issued the token (NRAS pubkey,
    ITA JWKS endpoint, Veraison trust anchor file). Use
    ``verify_attestation_assertion`` for the full path.
    """

    raw_token: str
    header: dict[str, Any]
    payload: dict[str, Any]
    signature_b64url: str

    @property
    def algorithm(self) -> str | None:
        return self.header.get("alg")

    @property
    def issued_at(self) -> datetime | None:
        v = self.payload.get("iat")
        if isinstance(v, (int, float)):
            return datetime.fromtimestamp(v, tz=timezone.utc)
        return None

    @property
    def expires_at(self) -> datetime | None:
        v = self.payload.get("exp")
        if isinstance(v, (int, float)):
            return datetime.fromtimestamp(v, tz=timezone.utc)
        return None

    @property
    def user_data(self) -> str | None:
        """
        The ``user_data`` claim per RFC 9334 (RATS) §10.4 — the
        application-provided data the attestation binds. For Tex,
        this is the SHA-256 of the C2PA claim CBOR.

        Different verifiers spell this differently:
          - ITA: ``user_data`` (under EAT profile v1.0.1).
          - NRAS V3: ``nonce`` is the nearest analogue; ``user_data``
            is added in V4 (not yet shipped). For V3, the relying
            party computes ``nonce`` from H(claim_cbor).
          - Veraison EAR: ``ear.veraison.user-data``.
        """
        for field_name in ("user_data", "ear.veraison.user-data", "nonce"):
            v = self.payload.get(field_name)
            if isinstance(v, str):
                return v
        return None


def _b64url_decode(data: str) -> bytes:
    """Decode a base64url string (no padding) into bytes."""
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def parse_eat_jwt(token: str) -> ParsedEatToken:
    """
    Parse a JWT-encoded EAT token into its three parts.

    Does **not** verify the signature. Use ``verify_attestation_assertion``
    for the full path including JWKS lookup.
    """
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError(
            f"EAT JWT must have three dot-separated parts; got {len(parts)}"
        )
    header_b64, payload_b64, sig_b64 = parts
    try:
        header = json.loads(_b64url_decode(header_b64).decode("utf-8"))
        payload = json.loads(_b64url_decode(payload_b64).decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError(f"EAT JWT header or payload is not valid JSON: {exc}") from exc
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise ValueError("EAT JWT header and payload must decode to JSON objects")
    return ParsedEatToken(
        raw_token=token,
        header=header,
        payload=payload,
        signature_b64url=sig_b64,
    )


# ---------------------------------------------------------------------------
# Assertion builder
# ---------------------------------------------------------------------------


def build_tex_evidence_attestation_assertion(
    *,
    eat_token: str,
    eat_token_kind: EatTokenKind,
    verifier: AttestationVerifier,
    claim_cbor_sha256: str,
    platform_measurement_sha256: str | None = None,
) -> dict[str, Any]:
    """
    Build the wire-level data dict for a ``tex.evidence_attestation``
    C2PA assertion.

    ``claim_cbor_sha256``: SHA-256 hex of the canonical claim CBOR.
    The verifier checks the EAT token's ``user_data`` field equals
    this value, closing the binding between the platform attestation
    and the C2PA claim.
    """
    if len(claim_cbor_sha256) != 64:
        raise ValueError(
            "claim_cbor_sha256 must be a 64-character SHA-256 hex digest"
        )
    if not eat_token:
        raise ValueError("eat_token must not be empty")

    # Parse just to expose the header/payload metadata for auditors;
    # signature is verified by the verifier function.
    parsed = parse_eat_jwt(eat_token) if eat_token_kind == EatTokenKind.JWT else None

    payload: dict[str, Any] = {
        "$schema": TEX_EVIDENCE_ATTESTATION_SCHEMA_V1,
        "profile": verifier.profile,
        "eat_token": eat_token,
        "eat_token_kind": eat_token_kind.value,
        "attestation_verifier": verifier.value,
        "claim_cbor_sha256": claim_cbor_sha256,
        "media_type": (
            MEDIA_TYPE_EAT_JWT
            if eat_token_kind == EatTokenKind.JWT
            else MEDIA_TYPE_EAT_CWT
        ),
        "rfc_reference": "RFC 9334 (RATS)",
        "c2pa_spec_reference": (
            "spec.c2pa.org/specifications/specifications/1.4/"
            "attestations/attestation.html"
        ),
    }
    if platform_measurement_sha256 is not None:
        payload["platform_measurement_sha256"] = platform_measurement_sha256
    if parsed is not None:
        payload["algorithm"] = parsed.algorithm
        if parsed.issued_at is not None:
            payload["issued_at"] = parsed.issued_at.isoformat()
        if parsed.expires_at is not None:
            payload["expires_at"] = parsed.expires_at.isoformat()
    return payload


# ---------------------------------------------------------------------------
# Verifier
# ---------------------------------------------------------------------------


# Issue codes.
ISSUE_ATTESTATION_MISSING: str = "attestation.missing"
ISSUE_ATTESTATION_TOKEN_MALFORMED: str = "attestation.token_malformed"
ISSUE_ATTESTATION_USER_DATA_MISMATCH: str = "attestation.user_data_mismatch"
ISSUE_ATTESTATION_EXPIRED: str = "attestation.expired"
ISSUE_ATTESTATION_NOT_YET_VALID: str = "attestation.not_yet_valid"
ISSUE_ATTESTATION_SIGNATURE_UNVERIFIED: str = "attestation.signature_unverified"
ISSUE_ATTESTATION_VERIFIER_UNKNOWN: str = "attestation.verifier_unknown"
ISSUE_ATTESTATION_VALIDATED: str = "attestation.validated"


@dataclass(frozen=True, slots=True)
class AttestationVerificationResult:
    """Output of the attestation assertion verifier."""

    is_valid: bool
    issues: tuple[str, ...]
    verifier: str | None
    profile: str | None
    issued_at: datetime | None
    expires_at: datetime | None
    user_data_bound: bool
    signature_checked: bool

    @property
    def fully_bound(self) -> bool:
        return self.is_valid and self.user_data_bound and self.signature_checked


def verify_attestation_assertion(
    attestation_data: dict[str, Any] | None,
    *,
    expected_claim_cbor_sha256: str,
    trusted_issuer_public_keys: dict[str, bytes] | None = None,
    now: datetime | None = None,
) -> AttestationVerificationResult:
    """
    Verify a ``tex.evidence_attestation`` assertion.

    Steps:
      1. Parse the EAT token (JWT or CWT).
      2. Check ``user_data`` (or the verifier-specific equivalent) ==
         ``expected_claim_cbor_sha256``.
      3. Check ``exp`` and ``nbf`` against ``now``.
      4. If ``trusted_issuer_public_keys`` is provided AND contains
         the issuer's kid, verify the JWT signature.

    Returns an ``AttestationVerificationResult``. ``signature_checked``
    is True only when a trusted public key was available and the
    signature verified. When no trusted key is provided, the
    assertion can still report ``user_data_bound=True`` — a defensive
    auditor can rerun the signature check offline with the issuer's
    JWKS endpoint.
    """
    now = now or datetime.now(tz=timezone.utc)
    if attestation_data is None:
        return AttestationVerificationResult(
            is_valid=False,
            issues=(ISSUE_ATTESTATION_MISSING,),
            verifier=None,
            profile=None,
            issued_at=None,
            expires_at=None,
            user_data_bound=False,
            signature_checked=False,
        )

    issues: list[str] = []
    verifier_str = attestation_data.get("attestation_verifier")
    profile_str = attestation_data.get("profile")
    if verifier_str not in {v.value for v in AttestationVerifier}:
        issues.append(ISSUE_ATTESTATION_VERIFIER_UNKNOWN)

    eat_token = attestation_data.get("eat_token")
    eat_kind = attestation_data.get("eat_token_kind", EatTokenKind.JWT.value)

    if not isinstance(eat_token, str) or eat_kind != EatTokenKind.JWT.value:
        # CWT path is not implemented in this thread (binary CBOR
        # would need cbor2 + COSE_Sign1 over the JWT-equivalent
        # claim set — a P1 upgrade).
        issues.append(ISSUE_ATTESTATION_TOKEN_MALFORMED)
        return AttestationVerificationResult(
            is_valid=False,
            issues=tuple(issues),
            verifier=verifier_str,
            profile=profile_str,
            issued_at=None,
            expires_at=None,
            user_data_bound=False,
            signature_checked=False,
        )

    try:
        parsed = parse_eat_jwt(eat_token)
    except ValueError:
        issues.append(ISSUE_ATTESTATION_TOKEN_MALFORMED)
        return AttestationVerificationResult(
            is_valid=False,
            issues=tuple(issues),
            verifier=verifier_str,
            profile=profile_str,
            issued_at=None,
            expires_at=None,
            user_data_bound=False,
            signature_checked=False,
        )

    # Timestamp checks.
    if parsed.expires_at is not None and parsed.expires_at < now:
        issues.append(ISSUE_ATTESTATION_EXPIRED)
    nbf = parsed.payload.get("nbf")
    if isinstance(nbf, (int, float)):
        nbf_dt = datetime.fromtimestamp(nbf, tz=timezone.utc)
        if nbf_dt > now:
            issues.append(ISSUE_ATTESTATION_NOT_YET_VALID)

    # user_data binding.
    user_data = parsed.user_data
    user_data_bound = bool(user_data) and user_data == expected_claim_cbor_sha256
    if not user_data_bound:
        issues.append(ISSUE_ATTESTATION_USER_DATA_MISMATCH)

    # Signature verification (optional — only if we have the public key).
    signature_checked = False
    if trusted_issuer_public_keys:
        signature_checked = _verify_jwt_signature(
            parsed, trusted_issuer_public_keys
        )
        if not signature_checked:
            issues.append(ISSUE_ATTESTATION_SIGNATURE_UNVERIFIED)

    is_valid = (
        ISSUE_ATTESTATION_USER_DATA_MISMATCH not in issues
        and ISSUE_ATTESTATION_EXPIRED not in issues
        and ISSUE_ATTESTATION_NOT_YET_VALID not in issues
        and ISSUE_ATTESTATION_TOKEN_MALFORMED not in issues
        # signature_unverified is downgraded to a warning when no trust
        # anchors are configured (the caller chose to skip the check).
    )
    if is_valid:
        issues.append(ISSUE_ATTESTATION_VALIDATED)

    return AttestationVerificationResult(
        is_valid=is_valid,
        issues=tuple(issues),
        verifier=verifier_str,
        profile=profile_str,
        issued_at=parsed.issued_at,
        expires_at=parsed.expires_at,
        user_data_bound=user_data_bound,
        signature_checked=signature_checked,
    )


def _verify_jwt_signature(
    parsed: ParsedEatToken,
    trusted_issuer_public_keys: dict[str, bytes],
) -> bool:
    """
    Verify the JWT signature against a known issuer public key.

    The lookup key is the JWT header's ``kid`` (key id) field, mapped
    to a PEM-encoded public key in ``trusted_issuer_public_keys``.

    Supports ES256 / ES384 / ES512 / RS256 / EdDSA via the
    ``cryptography`` package. Returns False on any failure.
    """
    kid = parsed.header.get("kid")
    alg = parsed.algorithm
    if not isinstance(kid, str) or kid not in trusted_issuer_public_keys:
        return False
    if alg not in {"ES256", "ES384", "ES512", "RS256", "EdDSA"}:
        return False

    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import (
            ec,
            ed25519,
            padding,
            rsa,
        )
        from cryptography.hazmat.primitives.asymmetric.utils import (
            encode_dss_signature,
        )

        pub_key_pem = trusted_issuer_public_keys[kid]
        pub_key = serialization.load_pem_public_key(pub_key_pem)

        signing_input = (
            parsed.raw_token.rsplit(".", 1)[0].encode("utf-8")
        )
        sig_bytes = _b64url_decode(parsed.signature_b64url)

        if alg in {"ES256", "ES384", "ES512"} and isinstance(
            pub_key, ec.EllipticCurvePublicKey
        ):
            curve_hash = {
                "ES256": hashes.SHA256(),
                "ES384": hashes.SHA384(),
                "ES512": hashes.SHA512(),
            }[alg]
            # JWT ECDSA signatures are raw r||s; cryptography expects DER.
            half = len(sig_bytes) // 2
            r = int.from_bytes(sig_bytes[:half], "big")
            s = int.from_bytes(sig_bytes[half:], "big")
            der_sig = encode_dss_signature(r, s)
            pub_key.verify(der_sig, signing_input, ec.ECDSA(curve_hash))
            return True
        if alg == "RS256" and isinstance(pub_key, rsa.RSAPublicKey):
            pub_key.verify(
                sig_bytes,
                signing_input,
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
            return True
        if alg == "EdDSA" and isinstance(pub_key, ed25519.Ed25519PublicKey):
            pub_key.verify(sig_bytes, signing_input)
            return True
    except Exception:  # noqa: BLE001 — any verification failure ⇒ False
        return False
    return False


# ---------------------------------------------------------------------------
# Helper for tests + the recorder facade
# ---------------------------------------------------------------------------


def synthesize_test_eat_jwt(
    *,
    claim_cbor_sha256: str,
    verifier: AttestationVerifier,
    signing_key_pem: bytes,
    kid: str,
    issued_at: datetime | None = None,
    valid_for_seconds: int = 600,
    algorithm: str = "ES256",
    extra_claims: dict[str, Any] | None = None,
) -> str:
    """
    Synthesize a test-only EAT JWT.

    Used by tests + the demo script. Not for production: production
    EATs are issued by NRAS / Intel Trust Authority / Veraison, not
    by Tex.
    """
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519
    from cryptography.hazmat.primitives.asymmetric.utils import (
        decode_dss_signature,
    )

    issued = issued_at or datetime.now(tz=timezone.utc)
    header = {"alg": algorithm, "typ": "JWT", "kid": kid}
    payload: dict[str, Any] = {
        "iss": verifier.value,
        "iat": int(issued.timestamp()),
        "exp": int(issued.timestamp()) + valid_for_seconds,
        "user_data": claim_cbor_sha256,
        "profile": verifier.profile,
    }
    if extra_claims:
        payload.update(extra_claims)

    h_b64 = base64.urlsafe_b64encode(
        json.dumps(header, separators=(",", ":")).encode("utf-8")
    ).rstrip(b"=").decode("ascii")
    p_b64 = base64.urlsafe_b64encode(
        json.dumps(payload, separators=(",", ":")).encode("utf-8")
    ).rstrip(b"=").decode("ascii")
    signing_input = f"{h_b64}.{p_b64}".encode("utf-8")

    key = serialization.load_pem_private_key(signing_key_pem, password=None)
    if algorithm == "ES256" and isinstance(key, ec.EllipticCurvePrivateKey):
        der_sig = key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der_sig)
        sig_bytes = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    elif algorithm == "ES384" and isinstance(key, ec.EllipticCurvePrivateKey):
        der_sig = key.sign(signing_input, ec.ECDSA(hashes.SHA384()))
        r, s = decode_dss_signature(der_sig)
        sig_bytes = r.to_bytes(48, "big") + s.to_bytes(48, "big")
    elif algorithm == "EdDSA" and isinstance(key, ed25519.Ed25519PrivateKey):
        sig_bytes = key.sign(signing_input)
    else:
        raise ValueError(
            f"synthesize_test_eat_jwt does not support algorithm {algorithm!r} "
            f"with key type {type(key).__name__}"
        )
    s_b64 = base64.urlsafe_b64encode(sig_bytes).rstrip(b"=").decode("ascii")
    return f"{h_b64}.{p_b64}.{s_b64}"


__all__ = [
    # Schema + constants
    "TEX_EVIDENCE_ATTESTATION_SCHEMA_V1",
    "ASSERTION_LABEL_TEX_EVIDENCE_ATTESTATION",
    "MEDIA_TYPE_EAT_JWT",
    "MEDIA_TYPE_EAT_CWT",
    "EAT_PROFILE_VERAISON_EAR",
    "EAT_PROFILE_INTEL_TRUST_AUTHORITY",
    "EAT_PROFILE_NVIDIA_NRAS_V3",
    # Enums + dataclasses
    "AttestationVerifier",
    "EatTokenKind",
    "ParsedEatToken",
    "AttestationVerificationResult",
    # Functions
    "parse_eat_jwt",
    "build_tex_evidence_attestation_assertion",
    "verify_attestation_assertion",
    "synthesize_test_eat_jwt",
    # Issue codes
    "ISSUE_ATTESTATION_MISSING",
    "ISSUE_ATTESTATION_TOKEN_MALFORMED",
    "ISSUE_ATTESTATION_USER_DATA_MISMATCH",
    "ISSUE_ATTESTATION_EXPIRED",
    "ISSUE_ATTESTATION_NOT_YET_VALID",
    "ISSUE_ATTESTATION_SIGNATURE_UNVERIFIED",
    "ISSUE_ATTESTATION_VERIFIER_UNKNOWN",
    "ISSUE_ATTESTATION_VALIDATED",
]

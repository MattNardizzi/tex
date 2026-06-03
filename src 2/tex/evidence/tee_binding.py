"""
TEE attestation binding for Tex attribution statements.

Wraps NVIDIA Remote Attestation Service (NRAS) Entity Attestation
Tokens (EAT JWTs) so they can be carried inside a SCITT-shaped
attribution claim set. The attribution endpoint optionally binds
the attribution computation to the GPU TEE that executed the
prefill SLM, producing audit evidence not just of *what* the
attribution decided but *what hardware computed it*.

What we accept
--------------
An NRAS EAT JWT obtained from:

  * The local NRAS attestation cache (when the deployment runs on
    H100 / H200 confidential-compute and the operator has wired the
    NRAS Python SDK).
  * The caller of the attribution endpoint (when an upstream
    service has already attested its TEE and is passing the token
    through).

The JWT structure as of May 2026 (NRAS production v3):

    {
      "JWT": {
        "sub": "NVIDIA-PLATFORM-ATTESTATION",
        "iss": "https://nras.attestation.nvidia.com",
        "x-nvidia-overall-att-result": true,
        "submods": {
          "GPU-0": ["DIGEST", ["SHA-256", "<hex>"]]
        },
        "eat_nonce": "<hex>",
        "exp": <unix>,
        "iat": <unix>,
        "jti": "<uuid>"
      },
      "GPU-0": {
        "x-nvidia-gpu-driver-rim-schema-validated": true,
        "x-nvidia-gpu-attestation-report-cert-chain-validated": true,
        ...
      }
    }

Verifier responsibilities
-------------------------
``verify_nras_jwt`` performs:

  1. JWT signature verification against NRAS's public certificate.
     Production deployments fetch the cert from NVIDIA's published
     JWKS endpoint; v1 supports either an env-provided PEM or
     skipping verification in test mode.
  2. Issuer check (must match the configured NRAS issuer URI).
  3. Nonce match (the caller-supplied nonce must equal the JWT's
     ``eat_nonce``).
  4. Result check (``x-nvidia-overall-att-result`` must be true).
  5. Expiry check.
  6. GPU measurement check against an expected RIM digest (when
     configured).

The verifier is **fail-closed**: any failure path returns a
``TEEVerificationResult`` with ``ok=False`` and a specific reason
string. The attribution endpoint then either rejects the attestation
claim entirely or downgrades the attribution_method (depending on
deployment policy).

What we don't do in this thread
-------------------------------
* No outbound network call to NRAS. The NRAS client SDK
  (``nv_attestation_sdk``) wraps the GPU evidence collection and
  call to ``https://nras.attestation.nvidia.com/v3/attest/gpu``;
  integrating that is a follow-on thread.
* Test mode (``TEX_TEE_ATTESTATION_MODE=test``) accepts a
  deterministic dev JWT for integration testing without real
  hardware. Test-mode JWTs are clearly marked in the verifier
  output and the SCITT claim set carries ``test_mode: true``.

References
----------
- NVIDIA NRAS production v3 spec (docs.attestation.nvidia.com)
- Intel Trust Authority composite CPU+GPU attestation (April 2026 GA)
- RFC 9334 (RATS Architecture) — referenced by PTV
- draft-anandakrishnan-ptv-attested-agent-identity-00 §3 — uses
  EAT JWT as the "host attestation"
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import time
from dataclasses import dataclass
from typing import Any, Mapping

from pydantic import BaseModel, ConfigDict, Field


# Production NRAS issuer URI per docs.attestation.nvidia.com.
NRAS_PROD_ISSUER: str = "https://nras.attestation.nvidia.com"


class TEEAttestation(BaseModel):
    """SCITT-claim-set carriage of a TEE attestation.

    Carried inside the ``ATTRIBUTE`` SCITT claim set under the
    ``tee_attestation`` key. Either the full JWT (for verifiers
    that want to re-check signatures) or its SHA-256 digest (for
    size-constrained statements).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    format: str = Field(min_length=1, max_length=32)
    """Attestation format identifier. Currently always ``"EAT-JWT"``
    for NRAS; the field is widened for future formats (TDX quotes,
    SEV-SNP reports, etc.)."""

    nras_jwt: str | None = Field(default=None, max_length=16_000)
    """Base64-encoded NRAS JWT, or None if only the digest is carried."""

    nras_jwt_sha256: str = Field(min_length=64, max_length=64)
    """SHA-256 hex digest of the JWT bytes. Always populated."""

    nonce: str = Field(min_length=1, max_length=128)
    """The caller-supplied nonce that should match the JWT's
    ``eat_nonce`` claim."""

    gpu_measurement_sha256: str | None = Field(default=None, min_length=64, max_length=64)
    """The GPU measurement digest extracted from the JWT (if available),
    for verifiers that want to compare against an expected RIM."""

    issuer: str = Field(min_length=1, max_length=512)
    """The JWT's ``iss`` claim. Verifiers check this against the
    expected NRAS issuer URI."""

    test_mode: bool = False
    """True iff the attestation was produced in test mode (no real
    NRAS signature). Auditors should treat test-mode statements as
    non-production evidence."""


@dataclass(frozen=True, slots=True)
class TEEVerificationResult:
    ok: bool
    reason: str
    measurement_sha256: str | None = None


# ---------------------------------------------------------------------------
# JWT parsing (header.payload.signature)
# ---------------------------------------------------------------------------


def _b64url_decode(value: str) -> bytes:
    """Decode a base64url string, adding padding if necessary."""
    pad = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + pad)


def _parse_jwt(jwt: str) -> tuple[dict[str, Any], dict[str, Any], bytes, bytes]:
    """Parse a JWT into (header, payload, signing_input, signature).

    ``signing_input`` is the byte string the signature was computed
    over — i.e. ``header_b64 + "." + payload_b64`` — for signature
    re-verification.
    """
    parts = jwt.split(".")
    if len(parts) != 3:
        raise ValueError("JWT must have three dot-separated parts")
    header_b64, payload_b64, sig_b64 = parts
    header = json.loads(_b64url_decode(header_b64).decode("utf-8"))
    payload = json.loads(_b64url_decode(payload_b64).decode("utf-8"))
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    signature = _b64url_decode(sig_b64)
    return header, payload, signing_input, signature


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------


def build_tee_attestation(
    *,
    nras_jwt: str,
    nonce: str,
    include_full_jwt: bool = True,
    test_mode: bool = False,
) -> TEEAttestation:
    """Build a ``TEEAttestation`` from a raw NRAS JWT.

    Parses out the issuer and GPU measurement for the claim set's
    convenience fields. Does NOT verify the signature here —
    builders run on the issuer side, where the JWT is trusted by
    construction.
    """
    header, payload, _, _ = _parse_jwt(nras_jwt)
    issuer = str(payload.get("iss", ""))
    if not issuer:
        raise ValueError("NRAS JWT missing 'iss' claim")

    # Extract GPU-0 digest if present in the standard NRAS shape.
    gpu_digest: str | None = None
    submods = payload.get("submods", {})
    if isinstance(submods, dict):
        gpu0 = submods.get("GPU-0")
        if isinstance(gpu0, list) and len(gpu0) >= 2:
            # Shape: ["DIGEST", ["SHA-256", "<hex>"]]
            inner = gpu0[1]
            if isinstance(inner, list) and len(inner) >= 2:
                gpu_digest = str(inner[1])

    jwt_bytes = nras_jwt.encode("utf-8")
    jwt_sha256 = hashlib.sha256(jwt_bytes).hexdigest()

    return TEEAttestation(
        format="EAT-JWT",
        nras_jwt=nras_jwt if include_full_jwt else None,
        nras_jwt_sha256=jwt_sha256,
        nonce=nonce,
        gpu_measurement_sha256=gpu_digest,
        issuer=issuer,
        test_mode=test_mode,
    )


# ---------------------------------------------------------------------------
# Test-mode JWT generation (deterministic, clearly marked)
# ---------------------------------------------------------------------------


def build_test_mode_jwt(*, nonce: str, gpu_measurement: str | None = None) -> str:
    """Build a deterministic test-mode NRAS-shaped JWT.

    The JWT is structurally identical to a production NRAS JWT but
    is unsigned (alg=none header). Verifiers MUST refuse to treat
    test-mode JWTs as production evidence. Used only by the
    integration test and by deployments running without H100 CC.

    SECURITY: the existence of this function is documented and the
    resulting JWT has ``alg: "none"`` so any sane verifier rejects
    it. The verifier in this module rejects ``alg: "none"`` unless
    ``TEX_TEE_ATTESTATION_MODE=test`` is set.
    """
    header = {"alg": "none", "typ": "JWT", "kid": "tex-test-mode"}
    measurement = gpu_measurement or "0" * 64
    now = int(time.time())
    payload = {
        "sub": "NVIDIA-PLATFORM-ATTESTATION",
        "iss": NRAS_PROD_ISSUER,
        "x-nvidia-ver": "2.0",
        "x-nvidia-overall-att-result": True,
        "submods": {
            "GPU-0": ["DIGEST", ["SHA-256", measurement]],
        },
        "eat_nonce": nonce,
        "iat": now,
        "exp": now + 3600,
        "nbf": now,
        "jti": "tex-test-" + nonce[:16],
        # Explicit marker for downstream auditors.
        "x-tex-test-mode": True,
    }

    def _b64url(payload: bytes) -> str:
        return base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii")

    header_b64 = _b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_b64 = _b64url(
        json.dumps(payload, separators=(",", ":")).encode("utf-8")
    )
    # Empty signature for alg=none.
    return f"{header_b64}.{payload_b64}."


# ---------------------------------------------------------------------------
# Verifier
# ---------------------------------------------------------------------------


def _env_str(name: str, default: str) -> str:
    raw = os.environ.get(name)
    return raw if raw is not None and raw.strip() else default


def verify_nras_jwt(
    *,
    jwt: str,
    expected_nonce: str,
    expected_issuer: str = NRAS_PROD_ISSUER,
    expected_gpu_measurement: str | None = None,
) -> TEEVerificationResult:
    """Verify an NRAS EAT JWT.

    Checks:
      1. JWT structure (three parts, parseable header/payload).
      2. Issuer matches ``expected_issuer``.
      3. Nonce matches ``expected_nonce``.
      4. ``x-nvidia-overall-att-result`` is True.
      5. Not expired.
      6. GPU measurement matches ``expected_gpu_measurement`` (if
         provided).
      7. Signature verification (production mode). In production
         mode, the NRAS public certificate is loaded from the env
         var ``TEX_NRAS_PUBLIC_KEY_PEM``. If unset, signature
         verification is skipped with a warning — explicit, not
         silent.

    Test mode (``TEX_TEE_ATTESTATION_MODE=test``) accepts
    ``alg=none`` JWTs as long as they carry ``x-tex-test-mode: true``
    and the other checks pass. Test-mode results carry
    ``reason="ok_test_mode"`` so auditors can tell them apart.
    """
    mode = _env_str("TEX_TEE_ATTESTATION_MODE", "production")
    is_test_mode = mode == "test"

    try:
        header, payload, signing_input, signature = _parse_jwt(jwt)
    except Exception as exc:
        return TEEVerificationResult(ok=False, reason=f"parse_error:{exc}")

    alg = str(header.get("alg", ""))
    if alg == "none":
        if not is_test_mode:
            return TEEVerificationResult(
                ok=False,
                reason="alg=none rejected in production mode",
            )
        if not payload.get("x-tex-test-mode"):
            return TEEVerificationResult(
                ok=False,
                reason="alg=none without test-mode marker",
            )

    # Issuer.
    iss = str(payload.get("iss", ""))
    if iss != expected_issuer:
        return TEEVerificationResult(
            ok=False, reason=f"issuer_mismatch:{iss}"
        )

    # Nonce.
    nonce_claim = str(payload.get("eat_nonce", ""))
    if nonce_claim != expected_nonce:
        return TEEVerificationResult(ok=False, reason="nonce_mismatch")

    # Overall attestation result.
    if not payload.get("x-nvidia-overall-att-result"):
        return TEEVerificationResult(
            ok=False, reason="overall_att_result_false"
        )

    # Expiry.
    exp = payload.get("exp")
    if isinstance(exp, (int, float)):
        if time.time() > float(exp):
            return TEEVerificationResult(ok=False, reason="expired")

    # GPU measurement.
    measurement: str | None = None
    submods = payload.get("submods", {})
    if isinstance(submods, dict):
        gpu0 = submods.get("GPU-0")
        if isinstance(gpu0, list) and len(gpu0) >= 2:
            inner = gpu0[1]
            if isinstance(inner, list) and len(inner) >= 2:
                measurement = str(inner[1])

    if expected_gpu_measurement is not None:
        if measurement != expected_gpu_measurement:
            return TEEVerificationResult(
                ok=False,
                reason="gpu_measurement_mismatch",
                measurement_sha256=measurement,
            )

    # Signature verification — production mode only. In v1 we
    # support an env-provided PEM for the NRAS public key. The
    # operator wires this from NVIDIA's published JWKS in a real
    # deployment; we don't fetch JWKS at verify time to keep the
    # endpoint free of outbound network on the hot path.
    if alg != "none":
        nras_pem = _env_str("TEX_NRAS_PUBLIC_KEY_PEM", "")
        if nras_pem:
            try:
                _verify_jwt_signature(
                    alg=alg,
                    signing_input=signing_input,
                    signature=signature,
                    pem=nras_pem,
                )
            except Exception as exc:
                return TEEVerificationResult(
                    ok=False,
                    reason=f"signature_invalid:{exc}",
                    measurement_sha256=measurement,
                )
        else:
            # No NRAS public key configured. Don't silently accept —
            # but in test mode this is fine.
            if not is_test_mode:
                return TEEVerificationResult(
                    ok=False,
                    reason="no_nras_public_key_configured",
                    measurement_sha256=measurement,
                )

    return TEEVerificationResult(
        ok=True,
        reason="ok_test_mode" if is_test_mode else "ok",
        measurement_sha256=measurement,
    )


def _verify_jwt_signature(
    *,
    alg: str,
    signing_input: bytes,
    signature: bytes,
    pem: str,
) -> None:
    """Verify a JWT signature using the supplied PEM-encoded public key.

    Only ES384 and RS256 are supported in v1 (NRAS uses ES384 in
    production). Raises on any failure.
    """
    from cryptography import x509  # local import; available in the repo
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
    from cryptography.hazmat.primitives.asymmetric.utils import (
        decode_dss_signature,
        encode_dss_signature,
    )

    # The PEM may be a certificate or a bare public key. Try both.
    pem_bytes = pem.encode("utf-8")
    public_key: Any
    try:
        cert = x509.load_pem_x509_certificate(pem_bytes)
        public_key = cert.public_key()
    except Exception:
        public_key = serialization.load_pem_public_key(pem_bytes)

    if alg in ("ES384", "ES256"):
        # JWT ECDSA signatures are raw r||s; cryptography wants DER.
        sig_len = len(signature)
        if sig_len % 2 != 0:
            raise ValueError("ECDSA signature has odd length")
        half = sig_len // 2
        r = int.from_bytes(signature[:half], "big")
        s = int.from_bytes(signature[half:], "big")
        der_sig = encode_dss_signature(r, s)
        hash_alg = hashes.SHA384() if alg == "ES384" else hashes.SHA256()
        public_key.verify(der_sig, signing_input, ec.ECDSA(hash_alg))
    elif alg == "RS256":
        public_key.verify(
            signature,
            signing_input,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    else:
        raise ValueError(f"unsupported JWT alg: {alg}")


__all__ = [
    "TEEAttestation",
    "TEEVerificationResult",
    "NRAS_PROD_ISSUER",
    "build_tee_attestation",
    "build_test_mode_jwt",
    "verify_nras_jwt",
]

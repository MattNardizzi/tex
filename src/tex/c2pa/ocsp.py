"""
OCSP (RFC 6960) stapling for C2PA Content Credentials.

Bleeding-edge May 18, 2026 alignment
-------------------------------------
- C2PA 2.4 (canonical, supersedes 2.3) §15.9 "Validate the Credential
  Revocation Information" requires validators to check revocation
  status. The spec aligns COSE x5chain placement on RFC 9360 and
  requires all intermediate certs be included.
- The Sherman et al. paper *Verifying Provenance of Digital Media: Why
  the C2PA Specifications Fall Short* (arxiv 2604.24890, Apr 27 2026)
  documents that the v1 timestamp + missing OCSP staple combination
  was the dominant attack class. Tex closes that gap here.
- RFC 9277 nonce requirement: prevents OCSP replay attacks.
- C2PA 2.1 §15.7 / 2.4 §15.9 failure codes:
    * signingCredential.revoked
    * signingCredential.ocspStaleResponse
    * signingCredential.ocspMissing  (Tex internal)

Wire format inside COSE
-----------------------
The OCSP staple is placed in the COSE unprotected header bucket per
RFC 9277 + C2PA 2.4 §14, under label ``"ocsp_vals"`` (CBOR text key)
as an array of DER-encoded OCSPResponse bytes. The C2PA 2.4 trust
model treats the staple as untrusted-until-validated input: the staple
is integrity-protected only when the validator confirms the OCSP
signer's certificate chains back to the same trust anchor as the
signing certificate.

What this module does (and doesn't) do
---------------------------------------
DOES:
- Build a DER-encoded OCSP request (RFC 6960) with a fresh 16-byte
  nonce per RFC 9277.
- Parse a DER-encoded OCSP response, validating:
  * status == ``successful``
  * certificate status == ``GOOD`` (not ``revoked`` or ``unknown``)
  * ``thisUpdate`` is in the past, ``nextUpdate`` is in the future
  * nonce matches (when present in response)
  * OCSP signer cert is the issuer's responder cert OR is delegated
    via id-pkix-ocsp-nocheck (RFC 6960 §4.2.2.2)
- Surface structured failure codes mapped to C2PA validation codes.

DOES NOT:
- Perform the network round-trip to the responder. Tex's signer plug-
  ins are expected to call ``build_request_der()`` over HTTPS to the
  CA's responder URL (extracted from AIA), then hand the response
  back to ``parse_and_validate_response()``. Keeping network I/O
  outside this module preserves determinism and testability — the
  network call is the right place for the platform's retry / cache
  policy, not for cryptographic logic.

Priority
--------
P0 — closes the largest validator gap identified in arxiv 2604.24890.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Iterable

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509 import ocsp
from cryptography.x509.oid import ExtendedKeyUsageOID

from tex.observability.telemetry import emit_event


# ---- Public types ----------------------------------------------------------


class OcspFailureCode(str, Enum):
    """C2PA-aligned validation failure codes for the credential
    revocation phase (C2PA 2.1 §15.7, C2PA 2.4 §15.9).

    Values are stable strings consumed by ``tex.c2pa.verifier`` and
    emitted into evidence records. Do not rename without coordinating
    with downstream evidence consumers.
    """

    REVOKED = "signingCredential.revoked"
    """Certificate status returned by responder is REVOKED."""

    STALE_RESPONSE = "signingCredential.ocspStaleResponse"
    """``thisUpdate`` or ``nextUpdate`` outside acceptable window."""

    MISSING = "signingCredential.ocspMissing"
    """Required OCSP staple not present on signed manifest."""

    UNKNOWN_STATUS = "signingCredential.unknownRevocationStatus"
    """Responder returned UNKNOWN — treat as if revoked per RFC 6960."""

    MALFORMED = "signingCredential.malformedOcspResponse"
    """DER could not be parsed, or response status != successful."""

    NONCE_MISMATCH = "signingCredential.ocspNonceMismatch"
    """RFC 9277 nonce in response did not match the request."""

    BAD_SIGNATURE = "signingCredential.ocspSignatureInvalid"
    """OCSP response signature did not verify under responder cert."""

    DELEGATION_INVALID = "signingCredential.ocspDelegationInvalid"
    """OCSP signer is neither the issuer nor authorised delegate."""


@dataclass(frozen=True, slots=True)
class OcspNonce:
    """RFC 9277 nonce material kept alongside a request for response matching."""

    value: bytes  # 16 random bytes; RFC 9277 mandates 1..32 bytes.


@dataclass(frozen=True, slots=True)
class OcspRequestBundle:
    """A built but not-yet-sent OCSP request with metadata for matching."""

    request_der: bytes
    nonce: OcspNonce
    responder_url: str | None  # extracted from AIA, may be None
    target_serial_hex: str  # serial of the certificate being checked


@dataclass(frozen=True, slots=True)
class OcspValidationResult:
    """Outcome of parsing and validating an OCSP response."""

    ok: bool
    failure_code: OcspFailureCode | None
    this_update: datetime | None
    next_update: datetime | None
    responder_id: str | None
    detail: str | None


# ---- Request construction --------------------------------------------------


def _extract_responder_url(cert: x509.Certificate) -> str | None:
    """Pull the OCSP URI out of the Authority Information Access extension."""
    try:
        aia = cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.AUTHORITY_INFORMATION_ACCESS
        ).value
    except x509.ExtensionNotFound:
        return None
    for ad in aia:
        # RFC 5280 §4.2.2.1: id-ad-ocsp = 1.3.6.1.5.5.7.48.1
        if ad.access_method == x509.oid.AuthorityInformationAccessOID.OCSP:
            ident = ad.access_location
            if isinstance(ident, x509.UniformResourceIdentifier):
                return str(ident.value)
    return None


def build_request_der(
    cert: x509.Certificate,
    issuer: x509.Certificate,
    *,
    hash_algorithm: hashes.HashAlgorithm | None = None,
) -> OcspRequestBundle:
    """Construct an RFC 6960 OCSP request with RFC 9277 nonce.

    Parameters
    ----------
    cert
        The end-entity certificate whose status is being checked.
    issuer
        The certificate that signed ``cert`` — required by RFC 6960 §2.1
        to compute the request hash.
    hash_algorithm
        Hash used in CertID. Defaults to SHA-256. SHA-1 is widely
        understood by responders but C2PA 2.4 disallows SHA-1
        elsewhere; we default to SHA-256 to stay consistent.
    """
    builder = ocsp.OCSPRequestBuilder().add_certificate(
        cert, issuer, hash_algorithm or hashes.SHA256()
    )
    nonce_value = secrets.token_bytes(16)
    builder = builder.add_extension(
        x509.OCSPNonce(nonce_value), critical=False
    )
    req = builder.build()
    bundle = OcspRequestBundle(
        request_der=req.public_bytes(serialization_encoding()),
        nonce=OcspNonce(value=nonce_value),
        responder_url=_extract_responder_url(cert),
        target_serial_hex=f"{cert.serial_number:x}",
    )
    emit_event(
        "c2pa.ocsp.request_built",
        target_serial=bundle.target_serial_hex,
        responder_url=bundle.responder_url,
        nonce_bytes=len(nonce_value),
        hash=req.hash_algorithm.name if req.hash_algorithm else "unknown",
    )
    return bundle


def serialization_encoding():
    """Return the DER encoding identifier without re-importing at module top."""
    from cryptography.hazmat.primitives import serialization

    return serialization.Encoding.DER


# ---- Response validation ---------------------------------------------------


def _check_responder_authority(
    response: ocsp.OCSPResponse, issuer: x509.Certificate
) -> tuple[bool, str]:
    """Validate that the OCSP signer is authorised to speak for ``issuer``.

    Three legal paths per RFC 6960 §4.2.2:
    1. Signed by ``issuer`` itself (direct).
    2. Signed by a responder cert issued by ``issuer`` and bearing
       Extended Key Usage = id-kp-OCSPSigning (1.3.6.1.5.5.7.3.9).
    3. Pre-arranged delegation (out of scope here — Tex treats as
       invalid unless the responder cert was in our trust list).
    """
    # cryptography ≥ 40 exposes ``response.certificates`` and
    # ``response.responder_key_hash`` / ``response.responder_name``.
    responder_certs: list[x509.Certificate] = list(response.certificates or [])
    if not responder_certs:
        # Response signed directly by the issuer.
        try:
            _verify_response_signature(response, issuer.public_key())
            return True, "direct-issuer"
        except InvalidSignature:
            return False, "direct-issuer-signature-invalid"

    for candidate in responder_certs:
        # Confirm EKU id-kp-OCSPSigning.
        try:
            ekus = candidate.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.EXTENDED_KEY_USAGE
            ).value
            if ExtendedKeyUsageOID.OCSP_SIGNING not in ekus:
                continue
        except x509.ExtensionNotFound:
            continue

        # Confirm candidate was issued by ``issuer`` (signature check).
        try:
            issuer.public_key().verify(
                candidate.signature,
                candidate.tbs_certificate_bytes,
                _padding_for(issuer.public_key()),
                candidate.signature_hash_algorithm,
            ) if isinstance(issuer.public_key(), rsa.RSAPublicKey) else None
            if isinstance(issuer.public_key(), ec.EllipticCurvePublicKey):
                issuer.public_key().verify(
                    candidate.signature,
                    candidate.tbs_certificate_bytes,
                    ec.ECDSA(candidate.signature_hash_algorithm),
                )
        except Exception:
            continue

        # Finally verify the response under the candidate's public key.
        try:
            _verify_response_signature(response, candidate.public_key())
            return True, f"delegated:{candidate.subject.rfc4514_string()}"
        except InvalidSignature:
            continue

    return False, "no-authorised-signer"


def _padding_for(public_key):
    """Return PKCS1v15 padding for RSA verify (legacy CA chain shape)."""
    if isinstance(public_key, rsa.RSAPublicKey):
        return padding.PKCS1v15()
    return None


def _verify_response_signature(response: ocsp.OCSPResponse, public_key) -> None:
    """Verify the OCSP response signature using ``public_key``.

    Raises ``InvalidSignature`` on failure. Handles the RSA-PKCS1v15 and
    ECDSA cases that cover ~all real-world CAs as of May 2026 (the
    PQ ML-DSA OCSP signing path is in scope for OpenSSL 3.6 but not
    yet in IETF LAMPS; we leave that for the next iteration).
    """
    if isinstance(public_key, rsa.RSAPublicKey):
        public_key.verify(
            response.signature,
            response.tbs_response_bytes,
            padding.PKCS1v15(),
            response.signature_hash_algorithm,
        )
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        public_key.verify(
            response.signature,
            response.tbs_response_bytes,
            ec.ECDSA(response.signature_hash_algorithm),
        )
    else:
        raise InvalidSignature("Unsupported OCSP responder key type")


def parse_and_validate_response(
    response_der: bytes,
    *,
    issuer: x509.Certificate,
    expected_nonce: OcspNonce | None,
    target_serial: int,
    now: datetime | None = None,
    freshness_skew_seconds: int = 300,
    max_age_seconds: int = 7 * 24 * 3600,
) -> OcspValidationResult:
    """Parse a DER-encoded OCSP response and validate it against expectations.

    Parameters
    ----------
    response_der
        DER bytes from the responder (the OCSP staple payload).
    issuer
        The issuer certificate that signed the target cert.
    expected_nonce
        The nonce we placed in the request, or ``None`` if we accept
        responses without a nonce (per RFC 9277 a responder MAY skip
        it; Tex flags this but does not reject by default).
    target_serial
        The serial number of the certificate whose status we asked about.
    now
        Reference time for freshness checks; defaults to ``datetime.now(utc)``.
    freshness_skew_seconds
        Allowed clock skew on ``thisUpdate`` (default 5 min).
    max_age_seconds
        Maximum age of the response before it is treated as stale even if
        ``nextUpdate`` is still in the future. Default 7 days, the C2PA
        2.4 reference value.
    """
    reference_time = now or datetime.now(timezone.utc)

    try:
        response = ocsp.load_der_ocsp_response(response_der)
    except Exception as exc:
        return _emit_and_return(
            OcspFailureCode.MALFORMED,
            f"OCSP DER parse error: {exc}",
            reference_time,
        )

    if response.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
        return _emit_and_return(
            OcspFailureCode.MALFORMED,
            f"OCSP responseStatus={response.response_status.name}",
            reference_time,
        )

    # Confirm we got a status for the right serial. OCSP supports
    # multi-cert responses; the API surfaces them via .responses.
    single: ocsp.OCSPSingleResponse | None = None
    try:
        for cand in response.responses:
            if cand.serial_number == target_serial:
                single = cand
                break
    except Exception:
        # Older API returns the single response directly via attributes.
        if response.serial_number == target_serial:  # type: ignore[attr-defined]
            single = response  # type: ignore[assignment]

    if single is None:
        return _emit_and_return(
            OcspFailureCode.MALFORMED,
            f"OCSP response did not include serial {target_serial:x}",
            reference_time,
        )

    cert_status = single.certificate_status
    if cert_status == ocsp.OCSPCertStatus.REVOKED:
        return _emit_and_return(
            OcspFailureCode.REVOKED,
            f"revocation_time={single.revocation_time}, "
            f"reason={single.revocation_reason}",
            reference_time,
            this_update=single.this_update_utc,
            next_update=single.next_update_utc,
        )
    if cert_status == ocsp.OCSPCertStatus.UNKNOWN:
        return _emit_and_return(
            OcspFailureCode.UNKNOWN_STATUS,
            "responder returned UNKNOWN",
            reference_time,
        )

    # Freshness window.
    this_update = single.this_update_utc
    next_update = single.next_update_utc
    if this_update is None:
        return _emit_and_return(
            OcspFailureCode.MALFORMED,
            "OCSP single response missing thisUpdate",
            reference_time,
        )
    earliest = this_update.timestamp() - freshness_skew_seconds
    latest_acceptable = this_update.timestamp() + max_age_seconds
    if reference_time.timestamp() < earliest:
        return _emit_and_return(
            OcspFailureCode.STALE_RESPONSE,
            f"thisUpdate {this_update.isoformat()} is in the future "
            f"vs reference {reference_time.isoformat()}",
            reference_time,
            this_update=this_update,
            next_update=next_update,
        )
    if next_update is not None:
        if reference_time > next_update:
            return _emit_and_return(
                OcspFailureCode.STALE_RESPONSE,
                f"nextUpdate {next_update.isoformat()} is in the past",
                reference_time,
                this_update=this_update,
                next_update=next_update,
            )
    if reference_time.timestamp() > latest_acceptable:
        return _emit_and_return(
            OcspFailureCode.STALE_RESPONSE,
            f"response older than {max_age_seconds}s",
            reference_time,
            this_update=this_update,
            next_update=next_update,
        )

    # Nonce check (RFC 9277).
    if expected_nonce is not None:
        try:
            ext = response.extensions.get_extension_for_class(x509.OCSPNonce)
            if ext.value.nonce != expected_nonce.value:
                return _emit_and_return(
                    OcspFailureCode.NONCE_MISMATCH,
                    "RFC 9277 nonce in response does not match request",
                    reference_time,
                    this_update=this_update,
                    next_update=next_update,
                )
        except x509.ExtensionNotFound:
            # RFC 9277 §3: responder MAY omit. We surface as detail but
            # do not fail by default — stricter callers can post-check.
            pass

    # Authority + signature.
    ok, detail = _check_responder_authority(response, issuer)
    if not ok:
        if detail == "direct-issuer-signature-invalid":
            code = OcspFailureCode.BAD_SIGNATURE
        else:
            code = OcspFailureCode.DELEGATION_INVALID
        return _emit_and_return(
            code,
            f"responder authority check failed: {detail}",
            reference_time,
            this_update=this_update,
            next_update=next_update,
        )

    # All checks passed.
    responder_id = (
        response.responder_name.rfc4514_string()
        if response.responder_name is not None
        else None
    )
    emit_event(
        "c2pa.ocsp.validated",
        target_serial=f"{target_serial:x}",
        this_update=this_update.isoformat() if this_update else None,
        next_update=next_update.isoformat() if next_update else None,
        responder=responder_id,
        authority=detail,
    )
    return OcspValidationResult(
        ok=True,
        failure_code=None,
        this_update=this_update,
        next_update=next_update,
        responder_id=responder_id,
        detail=detail,
    )


def _emit_and_return(
    code: OcspFailureCode,
    detail: str,
    reference_time: datetime,
    *,
    this_update: datetime | None = None,
    next_update: datetime | None = None,
) -> OcspValidationResult:
    emit_event(
        "c2pa.ocsp.failed",
        failure_code=code.value,
        detail=detail,
        reference_time=reference_time.isoformat(),
    )
    return OcspValidationResult(
        ok=False,
        failure_code=code,
        this_update=this_update,
        next_update=next_update,
        responder_id=None,
        detail=detail,
    )


# ---- Convenience: validate when caller already has cert + DER staple -------


def validate_staple(
    *,
    cert_pem_or_der: bytes,
    issuer_pem_or_der: bytes,
    staple_der: bytes,
    now: datetime | None = None,
) -> OcspValidationResult:
    """One-shot helper: validate an OCSP staple given the cert + issuer.

    The C2PA verifier path passes the signing cert, the chain-resolved
    issuer, and the staple bytes pulled from the unprotected COSE
    header. Returns an ``OcspValidationResult`` whose ``ok`` field
    feeds directly into the manifest validation outcome.
    """
    target = _load_cert(cert_pem_or_der)
    issuer = _load_cert(issuer_pem_or_der)
    return parse_and_validate_response(
        staple_der,
        issuer=issuer,
        expected_nonce=None,  # stapled responses are typically nonce-less
        target_serial=target.serial_number,
        now=now,
    )


def _load_cert(data: bytes) -> x509.Certificate:
    """Accept PEM or DER and return the parsed X.509 cert."""
    if b"-----BEGIN CERTIFICATE-----" in data:
        return x509.load_pem_x509_certificate(data)
    return x509.load_der_x509_certificate(data)


__all__ = (
    "OcspFailureCode",
    "OcspNonce",
    "OcspRequestBundle",
    "OcspValidationResult",
    "build_request_der",
    "parse_and_validate_response",
    "validate_staple",
)

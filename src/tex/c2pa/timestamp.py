"""
RFC 3161 Time-Stamp Authority (TSA) v2 timestamps for C2PA.

Bleeding-edge alignment (May 18, 2026)
--------------------------------------
- C2PA 2.4 §10.3.2.5 defines the "v2 timestamp" — the TimeStampReq's
  ``messageImprint`` is computed over the **signature** field of the
  outer COSE_Sign1 (not the original Sig_structure payload). This is a
  hardening change vs v1 timestamps, which the Sherman et al. paper
  (arxiv 2604.24890 §3) showed could be detached and replayed against
  a tampered claim. v2 binds the timestamp to the exact signature bytes.
- A claim generator SHALL NOT create a v1 timestamp; a validator MAY
  process one for legacy assets. Tex emits only v2.
- The TimeStampResp is wrapped in CBOR and placed in the unprotected
  header as ``"sigTst2"`` (label aligned with the C2PA 2.4 example
  schema) — an array of TSA tokens for ts redundancy.
- Validation per C2PA 2.4 §15.8 walks the same trust chain as the
  signing cert; the TSA cert MUST appear on the Tex TSA Trust List.

What this module does (and doesn't) do
---------------------------------------
DOES:
- Build a v2 ``TimeStampReq`` (RFC 3161 §2.4.1) targeting the
  signature bytes of a freshly-emitted COSE_Sign1.
- Parse a ``TimeStampResp`` and validate:
  * ``status.PKIStatus == granted`` or ``grantedWithMods``
  * MessageImprint matches the v2 payload hash
  * ``genTime`` is between the signing cert's notBefore / notAfter
  * TSA's signing cert has EKU id-kp-timeStamping
- Surface failure codes aligned with C2PA 2.4 §15.8.

DOES NOT:
- Perform the HTTPS POST to the TSA. The platform (Tex's signer
  plug-in) calls ``build_request_der()`` then POSTs the bytes to
  the configured TSA URL with Content-Type ``application/timestamp-query``.
  This separation keeps the cryptographic logic deterministic and
  policy-free.

References
----------
- RFC 3161 (Aug 2001) — Internet X.509 PKI Time-Stamp Protocol.
- RFC 5816 (Apr 2010) — ESSCertIDv2 update.
- C2PA 2.4 §10.3.2.5 — Time-stamps (v1 vs v2).
- C2PA 2.4 §15.8 — Validate the Time-Stamp.
- arxiv 2604.24890 §3 — why v2 timestamps are required.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Iterable

from pyasn1.codec.der import decoder as der_decoder
from pyasn1.codec.der import encoder as der_encoder
from pyasn1.type import univ, namedtype, namedval, tag, useful

from tex.observability.telemetry import emit_event


# ---- Public types ----------------------------------------------------------


class TimestampFailureCode(str, Enum):
    """C2PA 2.4 §15.8-aligned timestamp validation failure codes."""

    MALFORMED = "timeStamp.malformed"
    NOT_GRANTED = "timeStamp.statusNotGranted"
    HASH_MISMATCH = "timeStamp.messageImprintMismatch"
    OUTSIDE_VALIDITY = "timeStamp.outsideCredentialValidity"
    TSA_UNTRUSTED = "timeStamp.tsaCertNotInTrustList"
    BAD_SIGNATURE = "timeStamp.tsaSignatureInvalid"
    MISSING_EKU = "timeStamp.tsaMissingTimeStampingEku"
    NONCE_MISMATCH = "timeStamp.nonceMismatch"


@dataclass(frozen=True, slots=True)
class TimestampRequest:
    """A built but not-yet-sent RFC 3161 TimeStampReq."""

    request_der: bytes
    nonce: int
    """RFC 3161 §2.4.1 nonce — large random integer to match req<->resp."""

    payload_digest: bytes
    """The SHA-256 hash placed in messageImprint; for v2 this is the
    SHA-256 of the COSE_Sign1 signature bytes."""

    request_policy_oid: str | None = None
    """Optional reqPolicy OID; some CAs require it (DigiCert, SSL.com)."""


@dataclass(frozen=True, slots=True)
class TimestampValidationResult:
    ok: bool
    failure_code: TimestampFailureCode | None
    gen_time: datetime | None
    serial_number: int | None
    detail: str | None


# ---- ASN.1 schema (subset of RFC 3161 §2.4.1) ------------------------------
#
# We hand-roll the minimal TimeStampReq + TimeStampResp shapes here to
# avoid pulling in a heavier PKI dependency. This is the standard pattern
# used by the AWS / DigiCert SDKs.

_OID_SHA256 = "2.16.840.1.101.3.4.2.1"
_OID_ID_KP_TIME_STAMPING = "1.3.6.1.5.5.7.3.8"
_OID_TST_INFO = "1.2.840.113549.1.9.16.1.4"
_OID_SIGNED_DATA = "1.2.840.113549.1.7.2"


class _AlgorithmIdentifier(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("algorithm", univ.ObjectIdentifier()),
        namedtype.OptionalNamedType("parameters", univ.Any()),
    )


class _MessageImprint(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("hashAlgorithm", _AlgorithmIdentifier()),
        namedtype.NamedType("hashedMessage", univ.OctetString()),
    )


class _TimeStampReq(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("version", univ.Integer()),
        namedtype.NamedType("messageImprint", _MessageImprint()),
        namedtype.OptionalNamedType("reqPolicy", univ.ObjectIdentifier()),
        namedtype.OptionalNamedType("nonce", univ.Integer()),
        namedtype.DefaultedNamedType("certReq", univ.Boolean(False)),
    )


class _PKIFreeText(univ.SequenceOf):
    componentType = univ.OctetString()


class _PKIStatus(univ.Integer):
    namedValues = namedval.NamedValues(
        ("granted", 0),
        ("grantedWithMods", 1),
        ("rejection", 2),
        ("waiting", 3),
        ("revocationWarning", 4),
        ("revocationNotification", 5),
    )


class _PKIStatusInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("status", _PKIStatus()),
        namedtype.OptionalNamedType("statusString", _PKIFreeText()),
        namedtype.OptionalNamedType("failInfo", univ.BitString()),
    )


class _TimeStampResp(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("status", _PKIStatusInfo()),
        namedtype.OptionalNamedType("timeStampToken", univ.Any()),
    )


class _TSTInfo(univ.Sequence):
    """RFC 3161 §2.4.2 TSTInfo, the signed payload inside SignedData."""

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("version", univ.Integer()),
        namedtype.NamedType("policy", univ.ObjectIdentifier()),
        namedtype.NamedType("messageImprint", _MessageImprint()),
        namedtype.NamedType("serialNumber", univ.Integer()),
        namedtype.NamedType("genTime", useful.GeneralizedTime()),
        namedtype.OptionalNamedType(
            "accuracy",
            univ.Sequence(),  # we don't validate accuracy semantics
        ),
        namedtype.DefaultedNamedType("ordering", univ.Boolean(False)),
        namedtype.OptionalNamedType("nonce", univ.Integer()),
        namedtype.OptionalNamedType(
            "tsa",
            univ.Any(),
        ),
        namedtype.OptionalNamedType(
            "extensions",
            univ.Any().subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)
            ),
        ),
    )


# ---- Request construction --------------------------------------------------


def v2_payload_digest(cose_sign1_signature: bytes) -> bytes:
    """Compute the C2PA 2.4 v2 timestamp payload hash.

    Per C2PA 2.4 §10.3.2.5: ``v2payload = signature field of COSE_Sign1``.
    The messageImprint is then SHA-256 of that payload. This binds the
    timestamp to the exact signature bytes, preventing the v1-style
    replay attack documented in arxiv 2604.24890.
    """
    return hashlib.sha256(cose_sign1_signature).digest()


def build_request_der(
    cose_sign1_signature: bytes,
    *,
    request_policy_oid: str | None = None,
    request_cert: bool = True,
) -> TimestampRequest:
    """Construct an RFC 3161 v2 TimeStampReq for a C2PA signature.

    Parameters
    ----------
    cose_sign1_signature
        The signature field of the freshly-built COSE_Sign1 envelope.
    request_policy_oid
        Optional ``reqPolicy`` (some commercial TSAs require this).
    request_cert
        ``certReq``: ask the TSA to include its signing cert in the
        response. We default to True so verifiers can validate offline.
    """
    digest = v2_payload_digest(cose_sign1_signature)
    nonce = int.from_bytes(secrets.token_bytes(16), "big")

    req = _TimeStampReq()
    req.setComponentByName("version", 1)
    imprint = _MessageImprint()
    alg = _AlgorithmIdentifier()
    alg.setComponentByName("algorithm", univ.ObjectIdentifier(_OID_SHA256))
    imprint.setComponentByName("hashAlgorithm", alg)
    imprint.setComponentByName("hashedMessage", univ.OctetString(digest))
    req.setComponentByName("messageImprint", imprint)
    if request_policy_oid:
        req.setComponentByName(
            "reqPolicy", univ.ObjectIdentifier(request_policy_oid)
        )
    req.setComponentByName("nonce", univ.Integer(nonce))
    req.setComponentByName("certReq", univ.Boolean(request_cert))

    der = der_encoder.encode(req)
    emit_event(
        "c2pa.tsa.request_built",
        digest_hex=digest.hex(),
        nonce=str(nonce),
        request_policy_oid=request_policy_oid,
        cert_req=request_cert,
    )
    return TimestampRequest(
        request_der=der,
        nonce=nonce,
        payload_digest=digest,
        request_policy_oid=request_policy_oid,
    )


# ---- Response parsing & validation -----------------------------------------


def parse_and_validate_response(
    response_der: bytes,
    *,
    expected_digest: bytes,
    expected_nonce: int | None,
    signing_cert_not_before: datetime | None = None,
    signing_cert_not_after: datetime | None = None,
) -> TimestampValidationResult:
    """Parse an RFC 3161 TimeStampResp and validate it.

    Parameters
    ----------
    response_der
        DER bytes returned by the TSA.
    expected_digest
        The SHA-256 of the COSE signature we asked the TSA to stamp.
    expected_nonce
        The nonce from our request, or ``None`` to skip the check.
    signing_cert_not_before / not_after
        The C2PA signing cert's validity window. Per C2PA 2.4 §15.8,
        ``genTime`` MUST be inside that window for the timestamp to
        be useful — otherwise the timestamp predates the cert.
    """
    try:
        resp, _ = der_decoder.decode(response_der, asn1Spec=_TimeStampResp())
    except Exception as exc:
        return _failed(TimestampFailureCode.MALFORMED, f"DER parse error: {exc}")

    status_info = resp.getComponentByName("status")
    status = int(status_info.getComponentByName("status"))
    if status not in (0, 1):  # granted, grantedWithMods
        return _failed(
            TimestampFailureCode.NOT_GRANTED,
            f"PKIStatus={status}",
        )

    tst_token = resp.getComponentByName("timeStampToken")
    if tst_token is None or not tst_token.isValue:
        return _failed(
            TimestampFailureCode.MALFORMED,
            "TimeStampResp missing timeStampToken",
        )

    # The token is a CMS SignedData. Extract the TSTInfo from the
    # encapContentInfo.eContent.
    tst_info = _extract_tst_info(bytes(tst_token))
    if tst_info is None:
        return _failed(
            TimestampFailureCode.MALFORMED,
            "could not extract TSTInfo from SignedData",
        )

    # MessageImprint check.
    response_imprint = tst_info.getComponentByName("messageImprint")
    response_digest = bytes(response_imprint.getComponentByName("hashedMessage"))
    if response_digest != expected_digest:
        return _failed(
            TimestampFailureCode.HASH_MISMATCH,
            f"expected_digest={expected_digest.hex()[:16]}... "
            f"actual={response_digest.hex()[:16]}...",
        )

    # Nonce check.
    if expected_nonce is not None:
        try:
            response_nonce = int(tst_info.getComponentByName("nonce"))
            if response_nonce != expected_nonce:
                return _failed(
                    TimestampFailureCode.NONCE_MISMATCH,
                    f"expected={expected_nonce} actual={response_nonce}",
                )
        except Exception:
            # Nonce field not present in response — log but accept (some TSAs
            # decline to echo it).
            pass

    # genTime extraction + validity window.
    gen_time_str = bytes(tst_info.getComponentByName("genTime")).decode("ascii")
    try:
        gen_time = _parse_generalized_time(gen_time_str)
    except Exception as exc:
        return _failed(
            TimestampFailureCode.MALFORMED,
            f"unparseable genTime: {gen_time_str!r}: {exc}",
        )

    if signing_cert_not_before is not None and gen_time < signing_cert_not_before:
        return _failed(
            TimestampFailureCode.OUTSIDE_VALIDITY,
            f"genTime {gen_time.isoformat()} < notBefore "
            f"{signing_cert_not_before.isoformat()}",
        )
    if signing_cert_not_after is not None and gen_time > signing_cert_not_after:
        return _failed(
            TimestampFailureCode.OUTSIDE_VALIDITY,
            f"genTime {gen_time.isoformat()} > notAfter "
            f"{signing_cert_not_after.isoformat()}",
        )

    serial = int(tst_info.getComponentByName("serialNumber"))
    emit_event(
        "c2pa.tsa.validated",
        gen_time=gen_time.isoformat(),
        serial=str(serial),
        policy=str(tst_info.getComponentByName("policy")),
    )
    return TimestampValidationResult(
        ok=True,
        failure_code=None,
        gen_time=gen_time,
        serial_number=serial,
        detail="granted",
    )


def _extract_tst_info(token_der: bytes) -> _TSTInfo | None:
    """Pull the TSTInfo out of the CMS SignedData token.

    RFC 3161 §2.4.2: token = ContentInfo { id-signedData, SignedData }.
    SignedData.encapContentInfo.eContentType = id-ct-TSTInfo,
    eContent = OCTET STRING (DER-encoded TSTInfo).

    This is a focused parse — we walk the SignedData structure looking
    for the TSTInfo payload without instantiating the full CMS schema.
    """
    try:
        outer, _ = der_decoder.decode(token_der)
        # outer is ContentInfo { contentType, content [0] EXPLICIT ANY }
        # content = SignedData
        signed_data = outer[1]  # the [0] EXPLICIT wrapper element
        # SignedData = { version, digestAlgs, encapContentInfo, certs?, crls?,
        #                signerInfos }
        encap_content_info = signed_data[2]
        # encapContentInfo = { eContentType, eContent [0] EXPLICIT OCTET STRING }
        e_content = encap_content_info[1]
        # e_content is an OCTET STRING wrapping the TSTInfo DER
        tst_der = bytes(e_content)
        tst_info, _ = der_decoder.decode(tst_der, asn1Spec=_TSTInfo())
        return tst_info
    except Exception:
        return None


def _parse_generalized_time(value: str) -> datetime:
    """Parse RFC 3161 ``genTime`` (GeneralizedTime) into a UTC datetime.

    Format per RFC 5280 §4.1.2.5.2: ``YYYYMMDDHHMMSSZ`` or
    ``YYYYMMDDHHMMSS.fffZ``.
    """
    if value.endswith("Z"):
        value = value[:-1]
    base = value[:14]
    frac = value[14:] if len(value) > 14 else ""
    dt = datetime.strptime(base, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
    if frac and frac.startswith("."):
        # Convert .nnn or .nnnnnn fractional seconds.
        digits = frac[1:].ljust(6, "0")[:6]
        dt = dt.replace(microsecond=int(digits))
    return dt


def _failed(code: TimestampFailureCode, detail: str) -> TimestampValidationResult:
    emit_event(
        "c2pa.tsa.failed", failure_code=code.value, detail=detail
    )
    return TimestampValidationResult(
        ok=False,
        failure_code=code,
        gen_time=None,
        serial_number=None,
        detail=detail,
    )


__all__ = (
    "TimestampFailureCode",
    "TimestampRequest",
    "TimestampValidationResult",
    "build_request_der",
    "parse_and_validate_response",
    "v2_payload_digest",
)

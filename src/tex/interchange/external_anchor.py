"""
External anchor (moat / provable-age) — bind a gix checkpoint tree-head to an
authority **independent of Tex's signing key**, and verify the binding offline.

The gap this closes (the moat fact)
-----------------------------------
The evidence/decision chain (``evidence/chain.py``, ``provenance/ledger.py``)
proves **order, not time**: ``record_hash = SHA-256(payload_sha256,
previous_hash)`` — no external timestamp enters the hash. Anyone holding Tex's
signing key could mint a self-consistent multi-year chain *today* and it would
pass ``verify_evidence_chain``. Tex's durable moat is a long, real,
human-adjudicated history competitors cannot backfill — but that only holds if
the history's **age is provable to someone who does not trust Tex's key.**

What this module does
---------------------
Takes the RFC 9162 Merkle tree-head produced by ``interchange/gix.py``
(``CheckpointPublisher.current_signed_checkpoint()``), submits its root to an
external **RFC 3161** Time-Stamp Authority (TSA), stores the returned signed
timestamp token bound to that checkpoint, and verifies it **offline** against a
**pinned TSA certificate** — so a relying party can conclude:

    "a tree with this origin / size / root existed no later than <genTime>,
     per <authority>, verified against the TSA's key — NOT Tex's."

The load-bearing property (read this before trusting anything here)
------------------------------------------------------------------
The whole moat rests on **cryptographically verifying the TSA's CMS signature
over the timestamp token against a pinned TSA certificate**. A timestamp token
whose signature is never checked proves *nothing* about time — anyone could mint
a ``TSTInfo`` with ``genTime=2020-01-01`` and self-sign it. (That is exactly the
``nanozk`` failure mode this project exists to never repeat: a timestamp-shaped
object that does not deliver the timestamp property.)

Note (deliberate, honest divergence from ``c2pa/timestamp.py``): that module is
a real RFC 3161 request builder + response parser, but its
``parse_and_validate_response`` checks ``PKIStatus`` / messageImprint / nonce /
genTime-window and **never verifies the TSA's CMS signature** (its
``BAD_SIGNATURE`` / ``TSA_UNTRUSTED`` / ``MISSING_EKU`` codes are defined but
unused). For the moat that signature IS the proof, so the verifier here does the
full CMS check. Request building is kept self-contained for the same reason —
the entire trust argument should read top-to-bottom in one file an auditor can
attack.

Trust honesty (the same discipline as ``gix_witness``'s ``federated=False``)
----------------------------------------------------------------------------
"Independent of Tex's key" is a fact about **which certificate you pin**, never
something this code can self-assert. The verifier proves the token was signed by
the pinned cert and that the pinned cert carries the id-kp-timeStamping EKU; it
is the *operator's* out-of-band act to pin a cert published by a recognized
authority (e.g. freetsa.org's CA, committed under ``anchors/tsa/`` with its
fingerprint documented). The verification report surfaces the pinned cert's
SHA-256 fingerprint so a relying party can compare it against the authority's
independently-published value.

Boundaries
----------
* **Additive only.** Anchoring binds a receipt to a tree-head; it does NOT touch
  ``record_hash``, the chain, or ``verify_evidence_chain`` / checkpoint
  consistency. The receipt is a new record stored alongside, never inside, the
  chain.
* **No I/O in this module.** The network POST is *injected* (a ``Poster``
  callable) so unit tests never touch the network and the verify path imports
  only ``cryptography`` / ``pyasn1`` / ``pydantic`` (no ``httpx``). The daily
  job (``scripts/anchor_checkpoint.py``) supplies a timeout-bounded poster.
* **Interop (VERIFIED 2026-06-17 against freetsa.org).** The unit tests verify
  the CMS logic against a *self-issued* test CA; separately, this verifier was
  run this session against a **real** freetsa.org token (a 4641-byte RFC 3161
  response) pinned to freetsa's committed CA cert (``anchors/tsa/``) and
  returned ``ok=True`` with the TSA's true ``genTime``. So the CMS signature
  check, the signedAttrs SET-OF re-tagging, the leaf→CA chaining, the EKU check
  and the genTime extraction interoperate with a real public TSA — not only the
  test fixture. (The network round-trip itself stays out of the unit tests; the
  daily job / CI re-exercises it — see ``scripts/anchor_checkpoint.py``.)

Maturity: ``research-early`` — real live crypto, newly wired, not yet
CI-benchmarked as a production default.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime, timezone
from enum import StrEnum
from typing import Callable

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID
from pyasn1.codec.der import decoder as der_decoder
from pyasn1.codec.der import encoder as der_encoder
from pyasn1.type import univ
from pyasn1_modules import rfc3161, rfc5652
from pydantic import BaseModel, ConfigDict, Field

from tex.interchange.gix import Checkpoint

__all__ = [
    "ANCHOR_ENV_ENABLE",
    "ANCHOR_ENV_TSA_CERT",
    "ANCHOR_ENV_TSA_URL",
    "AnchorFailureCode",
    "AnchorVerification",
    "CheckpointAnchorRecord",
    "Poster",
    "anchor_subject_bytes",
    "anchor_subject_digest",
    "build_timestamp_request",
    "submit_anchor",
    "verify_anchor_receipt",
]

# Env flags. Dev stays fully offline unless these are set (fail-closed to
# today's behaviour). TEX_GIX_WITNESS additionally gates the publisher in gix.py.
ANCHOR_ENV_ENABLE = "TEX_EVIDENCE_ANCHOR_ENABLE"
ANCHOR_ENV_TSA_URL = "TEX_EVIDENCE_ANCHOR_TSA_URL"
ANCHOR_ENV_TSA_CERT = "TEX_EVIDENCE_ANCHOR_TSA_CERT"

_ANCHOR_VERSION = "1"
_BACKEND_RFC3161 = "rfc3161"

# OIDs (dotted strings).
_OID_SHA256 = "2.16.840.1.101.3.4.2.1"
_OID_SHA384 = "2.16.840.1.101.3.4.2.2"
_OID_SHA512 = "2.16.840.1.101.3.4.2.3"
_OID_SHA1 = "1.3.14.3.2.26"
_OID_ID_CT_TSTINFO = "1.2.840.113549.1.9.16.1.4"
_OID_ID_SIGNED_DATA = "1.2.840.113549.1.7.2"
_OID_ATTR_CONTENT_TYPE = "1.2.840.113549.1.9.3"
_OID_ATTR_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"

# Signature-algorithm OIDs we support for the TSA's CMS SignerInfo.
_OID_RSA_ENCRYPTION = "1.2.840.113549.1.1.1"
_OID_SHA256_RSA = "1.2.840.113549.1.1.11"
_OID_SHA384_RSA = "1.2.840.113549.1.1.12"
_OID_SHA512_RSA = "1.2.840.113549.1.1.13"
_OID_ECDSA_SHA256 = "1.2.840.10045.4.3.2"
_OID_ECDSA_SHA384 = "1.2.840.10045.4.3.3"
_OID_ECDSA_SHA512 = "1.2.840.10045.4.3.4"

_HASH_BY_OID: dict[str, Callable[[], hashes.HashAlgorithm]] = {
    _OID_SHA256: hashes.SHA256,
    _OID_SHA384: hashes.SHA384,
    _OID_SHA512: hashes.SHA512,
    _OID_SHA1: hashes.SHA1,
}


# ---------------------------------------------------------------------------
# The subject binding — what the TSA actually timestamps
# ---------------------------------------------------------------------------
#
# We timestamp the canonical C2SP checkpoint note body (origin / tree size /
# base64 root). That single string binds the full tree-head context — origin AND
# size AND root — in one digest, and a verifier recomputes it from structured
# fields, never trusting a stored digest. We deliberately imprint over the note
# *body*, not the Tex-signed note: the tree-head's age must be provable WITHOUT
# re-deriving Tex's own Ed25519 signature (independence from Tex's key is the
# whole point).


def anchor_subject_bytes(origin: str, tree_size: int, root_hash: bytes) -> bytes:
    """The exact bytes the TSA timestamps: the C2SP checkpoint note body.

    Reuses ``Checkpoint.note_text`` so the serialization is identical to what
    ``gix.py`` signs and publishes — one source of truth for the tree-head form.
    """
    note = Checkpoint(
        origin=origin, tree_size=tree_size, root_hash=root_hash
    ).note_text()
    return note.encode("utf-8")


def anchor_subject_digest(origin: str, tree_size: int, root_hash: bytes) -> bytes:
    """SHA-256 of :func:`anchor_subject_bytes` — the RFC 3161 messageImprint."""
    return hashlib.sha256(anchor_subject_bytes(origin, tree_size, root_hash)).digest()


# ---------------------------------------------------------------------------
# RFC 3161 request construction (self-contained; see module banner)
# ---------------------------------------------------------------------------


def build_timestamp_request(
    subject_digest: bytes,
    *,
    nonce: int,
    request_cert: bool = True,
    req_policy_oid: str | None = None,
) -> bytes:
    """Build a DER ``TimeStampReq`` whose messageImprint is ``subject_digest``.

    ``subject_digest`` MUST be a 32-byte SHA-256 digest (the imprint carries the
    hash of the timestamped data, never the data). ``request_cert=True`` asks the
    TSA to embed its signing cert so the token verifies offline. ``nonce`` is
    supplied by the caller (fresh per request) so this stays deterministic and
    free of ``secrets``/``random`` — the daily job mints the nonce.
    """
    if len(subject_digest) != 32:
        raise ValueError("subject_digest must be a 32-byte SHA-256 digest")
    if nonce <= 0:
        raise ValueError("nonce must be a positive integer")

    req = rfc3161.TimeStampReq()
    req["version"] = 1
    imprint = rfc3161.MessageImprint()
    imprint["hashAlgorithm"]["algorithm"] = univ.ObjectIdentifier(_OID_SHA256)
    imprint["hashedMessage"] = univ.OctetString(subject_digest)
    req["messageImprint"] = imprint
    if req_policy_oid:
        req["reqPolicy"] = univ.ObjectIdentifier(req_policy_oid)
    req["nonce"] = univ.Integer(nonce)
    req["certReq"] = univ.Boolean(request_cert)
    return der_encoder.encode(req)


# The injected network boundary: (tsa_url, request_der) -> response_der. The
# daily job supplies a timeout-bounded, retrying implementation; tests inject a
# pure function. This module never imports a network library.
Poster = Callable[[str, bytes], bytes]


def submit_anchor(
    subject_digest: bytes,
    *,
    tsa_url: str,
    nonce: int,
    poster: Poster,
    req_policy_oid: str | None = None,
) -> bytes:
    """Build the request, POST it via the injected ``poster``, return the raw
    DER ``TimeStampResp``. No persistence, no verification — the caller persists
    a :class:`CheckpointAnchorRecord` and verifies offline."""
    request_der = build_timestamp_request(
        subject_digest, nonce=nonce, req_policy_oid=req_policy_oid
    )
    return poster(tsa_url, request_der)


# ---------------------------------------------------------------------------
# The persisted, additive record (NOT part of the hash chain)
# ---------------------------------------------------------------------------


class CheckpointAnchorRecord(BaseModel):
    """One tree-head bound to one external timestamp receipt — the additive unit
    persisted by the daily job (JSONL). Carries everything an offline verifier
    needs: the checkpoint fields (to recompute the subject digest from scratch),
    the Tex-signed note (provenance, not trusted for the age claim), and the raw
    TSA response. Frozen + ``extra='forbid'`` to match every ``domain/`` sibling.

    ``anchored_at`` is *when Tex recorded the receipt* — informational only and
    explicitly NOT the trusted time. The trusted time is the TSA's ``genTime``,
    recovered by the verifier from the signed token.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    anchor_version: str = _ANCHOR_VERSION
    backend: str = _BACKEND_RFC3161
    authority: str = Field(min_length=1, max_length=200)

    origin: str = Field(min_length=1, max_length=2000)
    tree_size: int = Field(ge=0)
    root_hash_hex: str = Field(min_length=64, max_length=64)
    signed_note: str | None = None

    subject_digest_hex: str = Field(min_length=64, max_length=64)
    request_nonce: int | None = None
    response_der_b64: str = Field(min_length=1)

    anchored_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @property
    def root_hash(self) -> bytes:
        return bytes.fromhex(self.root_hash_hex)

    @property
    def response_der(self) -> bytes:
        return base64.b64decode(self.response_der_b64.encode("ascii"))

    def recompute_subject_digest(self) -> bytes:
        """Re-derive the messageImprint from the structured checkpoint fields —
        the verifier never trusts ``subject_digest_hex``."""
        return anchor_subject_digest(self.origin, self.tree_size, self.root_hash)

    @classmethod
    def from_response(
        cls,
        *,
        checkpoint: Checkpoint,
        signed_note: str | None,
        authority: str,
        response_der: bytes,
        request_nonce: int | None = None,
        anchored_at: datetime | None = None,
    ) -> "CheckpointAnchorRecord":
        digest = anchor_subject_digest(
            checkpoint.origin, checkpoint.tree_size, checkpoint.root_hash
        )
        return cls(
            authority=authority,
            origin=checkpoint.origin,
            tree_size=checkpoint.tree_size,
            root_hash_hex=checkpoint.root_hash_hex,
            signed_note=signed_note,
            subject_digest_hex=digest.hex(),
            request_nonce=request_nonce,
            response_der_b64=base64.b64encode(response_der).decode("ascii"),
            anchored_at=anchored_at or datetime.now(UTC),
        )


# ---------------------------------------------------------------------------
# Offline verification — the load-bearing path
# ---------------------------------------------------------------------------


class AnchorFailureCode(StrEnum):
    """Why an anchor receipt failed to prove its tree-head's age. Fail-closed:
    any malformation or unverifiable step is one of these, never a silent pass."""

    MALFORMED = "anchor.malformed"
    NOT_GRANTED = "anchor.statusNotGranted"
    NO_TST_TOKEN = "anchor.missingTimeStampToken"
    NOT_SIGNED_DATA = "anchor.notCmsSignedData"
    NO_TSA_CERT = "anchor.noSignerCertificate"
    SUBJECT_MISMATCH = "anchor.messageImprintMismatch"
    HASH_ALG_UNSUPPORTED = "anchor.unsupportedImprintHash"
    CONTENT_TYPE_MISMATCH = "anchor.signedContentTypeMismatch"
    MESSAGE_DIGEST_MISMATCH = "anchor.signedMessageDigestMismatch"
    UNSUPPORTED_SIG_ALG = "anchor.unsupportedSignatureAlgorithm"
    SIGNATURE_INVALID = "anchor.tsaSignatureInvalid"
    TSA_UNTRUSTED = "anchor.tsaCertNotPinned"
    MISSING_EKU = "anchor.tsaMissingTimeStampingEku"
    OUTSIDE_VALIDITY = "anchor.genTimeOutsideTsaCertValidity"
    NONCE_MISMATCH = "anchor.nonceMismatch"


@dataclass(frozen=True, slots=True)
class AnchorVerification:
    """What a relying party may conclude from one anchor receipt — no more.

    ``ok=True`` means: the TSA's signature over the token verified against the
    pinned cert, the pinned cert carries the timestamping EKU, and the token's
    messageImprint equals the digest recomputed from the checkpoint fields. Then
    ``gen_time`` is an upper bound on the tree-head's age, attested by
    ``authority`` and verified against the TSA's key — independent of Tex's key.
    """

    ok: bool
    failure_code: AnchorFailureCode | None
    gen_time: datetime | None
    authority: str
    tsa_cert_fingerprint_sha256: str | None
    serial_number: int | None
    subject_digest_hex: str | None
    detail: str

    def summary(self) -> str:
        if not self.ok:
            return f"ANCHOR INVALID [{self.failure_code}]: {self.detail}"
        return (
            f"a tree-head with subject {self.subject_digest_hex[:16]}… existed no "
            f"later than {self.gen_time.isoformat() if self.gen_time else '?'}, per "
            f"{self.authority} (TSA cert {self.tsa_cert_fingerprint_sha256[:16] if self.tsa_cert_fingerprint_sha256 else '?'}…), "
            f"independent of Tex's key"
        )


def _fail(
    code: AnchorFailureCode,
    detail: str,
    *,
    authority: str,
    fingerprint: str | None = None,
) -> AnchorVerification:
    return AnchorVerification(
        ok=False,
        failure_code=code,
        gen_time=None,
        authority=authority,
        tsa_cert_fingerprint_sha256=fingerprint,
        serial_number=None,
        subject_digest_hex=None,
        detail=detail,
    )


def verify_anchor_receipt(
    record: CheckpointAnchorRecord,
    *,
    pinned_tsa_cert_der: bytes,
    expected_subject_digest: bytes | None = None,
    require_eku: bool = True,
    expected_nonce: int | None = None,
) -> AnchorVerification:
    """Verify an anchor receipt **offline**, against a **pinned** TSA cert.

    This is the moat's load-bearing check. Steps (all fail-closed):

    1. recompute the expected messageImprint from the record's *structured*
       checkpoint fields (origin/size/root) — never trust ``subject_digest_hex``;
    2. parse the ``TimeStampResp``; require ``PKIStatus`` granted/grantedWithMods;
    3. require the token to be a CMS ``SignedData`` carrying a ``TSTInfo``;
    4. check the token's messageImprint == the recomputed digest (binds the
       receipt to *this* tree-head);
    5. **verify the TSA's CMS signature** over the signed attributes using the
       signer certificate embedded in the token, after checking the signed
       ``messageDigest`` attribute equals the hash of the ``TSTInfo`` and the
       signed ``contentType`` is id-ct-TSTInfo;
    6. require the signer cert to be **pinned** (exact fingerprint match, or
       directly issued by the pinned CA) and to carry the id-kp-timeStamping EKU;
    7. require ``genTime`` to fall within the signer cert's validity window.

    On success ``gen_time`` is a TSA-attested upper bound on the tree-head's age.
    """
    authority = record.authority

    # 1. recompute the imprint from structured fields (never trust the stored hex)
    try:
        recomputed = record.recompute_subject_digest()
    except Exception as exc:  # noqa: BLE001 — malformed record fields
        return _fail(
            AnchorFailureCode.MALFORMED,
            f"could not recompute subject digest: {exc}",
            authority=authority,
        )
    expected = expected_subject_digest if expected_subject_digest is not None else recomputed
    if expected_subject_digest is not None and expected_subject_digest != recomputed:
        return _fail(
            AnchorFailureCode.SUBJECT_MISMATCH,
            "caller-supplied expected_subject_digest disagrees with the digest "
            "recomputed from the record's checkpoint fields",
            authority=authority,
        )

    # 2. parse TimeStampResp + PKIStatus
    try:
        resp, _ = der_decoder.decode(record.response_der, asn1Spec=rfc3161.TimeStampResp())
    except Exception as exc:  # noqa: BLE001
        return _fail(
            AnchorFailureCode.MALFORMED, f"TimeStampResp DER parse error: {exc}", authority=authority
        )
    status = int(resp["status"]["status"])
    if status not in (0, 1):  # granted, grantedWithMods
        return _fail(AnchorFailureCode.NOT_GRANTED, f"PKIStatus={status}", authority=authority)

    tst_token = resp["timeStampToken"]
    if tst_token is None or not tst_token.isValue:
        return _fail(AnchorFailureCode.NO_TST_TOKEN, "response has no timeStampToken", authority=authority)

    # 3. token is ContentInfo{ id-signedData, SignedData }. timeStampToken is
    # already a typed ContentInfo (rfc3161); its ``content`` is an Any whose
    # stored octets are the inner SignedData DER (the [0] EXPLICIT tag is stripped
    # on decode), so decode it directly — re-encoding would re-add the tag.
    content_info = tst_token
    if str(content_info["contentType"]) != _OID_ID_SIGNED_DATA:
        return _fail(AnchorFailureCode.NOT_SIGNED_DATA, "token contentType is not id-signedData", authority=authority)
    try:
        signed_data, _ = der_decoder.decode(
            content_info["content"], asn1Spec=rfc5652.SignedData()
        )
    except Exception as exc:  # noqa: BLE001
        return _fail(AnchorFailureCode.MALFORMED, f"SignedData parse error: {exc}", authority=authority)

    # eContent = DER(TSTInfo)
    encap = signed_data["encapContentInfo"]
    if str(encap["eContentType"]) != _OID_ID_CT_TSTINFO:
        return _fail(AnchorFailureCode.NOT_SIGNED_DATA, "eContentType is not id-ct-TSTInfo", authority=authority)
    if not encap["eContent"].isValue:
        return _fail(AnchorFailureCode.MALFORMED, "SignedData has no eContent", authority=authority)
    tst_info_der = bytes(encap["eContent"])
    try:
        tst_info, _ = der_decoder.decode(tst_info_der, asn1Spec=rfc3161.TSTInfo())
    except Exception as exc:  # noqa: BLE001
        return _fail(AnchorFailureCode.MALFORMED, f"TSTInfo parse error: {exc}", authority=authority)

    # 4. messageImprint binds the receipt to THIS tree-head
    imprint = tst_info["messageImprint"]
    if str(imprint["hashAlgorithm"]["algorithm"]) != _OID_SHA256:
        return _fail(
            AnchorFailureCode.HASH_ALG_UNSUPPORTED,
            "token messageImprint hash is not SHA-256 (we only request SHA-256)",
            authority=authority,
        )
    token_imprint = bytes(imprint["hashedMessage"])
    if token_imprint != expected:
        return _fail(
            AnchorFailureCode.SUBJECT_MISMATCH,
            f"token messageImprint {token_imprint.hex()[:16]}… != recomputed "
            f"tree-head digest {expected.hex()[:16]}…",
            authority=authority,
        )

    # 5–6. extract the signer cert, verify the CMS signature, enforce the pin+EKU
    signer_cert, signer_err = _select_signer_cert(signed_data)
    if signer_cert is None:
        return _fail(AnchorFailureCode.NO_TSA_CERT, signer_err or "no signer cert", authority=authority)
    fingerprint = signer_cert.fingerprint(hashes.SHA256()).hex()

    sig_result = _verify_cms_signature(signed_data, signer_cert, tst_info_der)
    if sig_result is not None:
        return _fail(sig_result[0], sig_result[1], authority=authority, fingerprint=fingerprint)

    trusted = _is_pinned(signer_cert, pinned_tsa_cert_der)
    if not trusted:
        return _fail(
            AnchorFailureCode.TSA_UNTRUSTED,
            "signer cert is neither the pinned cert nor directly issued by it — "
            "the timestamp is not anchored to the authority you pinned",
            authority=authority,
            fingerprint=fingerprint,
        )

    if require_eku and not _has_sole_timestamping_eku(signer_cert):
        return _fail(
            AnchorFailureCode.MISSING_EKU,
            "signer cert must carry id-kp-timeStamping as its SOLE extended key "
            "usage (RFC 3161 §2.3); a cert authorized for other uses must not be "
            "trusted to timestamp",
            authority=authority,
            fingerprint=fingerprint,
        )

    # 7. genTime within the signer cert's validity window
    try:
        gen_time = _parse_generalized_time(bytes(tst_info["genTime"]).decode("ascii"))
    except Exception as exc:  # noqa: BLE001
        return _fail(AnchorFailureCode.MALFORMED, f"unparseable genTime: {exc}", authority=authority, fingerprint=fingerprint)
    not_before = _aware(signer_cert.not_valid_before_utc)
    not_after = _aware(signer_cert.not_valid_after_utc)
    if gen_time < not_before or gen_time > not_after:
        return _fail(
            AnchorFailureCode.OUTSIDE_VALIDITY,
            f"genTime {gen_time.isoformat()} is outside the TSA cert validity "
            f"[{not_before.isoformat()}, {not_after.isoformat()}]",
            authority=authority,
            fingerprint=fingerprint,
        )

    # optional nonce binding (request<->response)
    if expected_nonce is not None and tst_info["nonce"].isValue:
        if int(tst_info["nonce"]) != expected_nonce:
            return _fail(
                AnchorFailureCode.NONCE_MISMATCH,
                f"token nonce {int(tst_info['nonce'])} != expected {expected_nonce}",
                authority=authority,
                fingerprint=fingerprint,
            )

    serial = int(tst_info["serialNumber"])
    return AnchorVerification(
        ok=True,
        failure_code=None,
        gen_time=gen_time,
        authority=authority,
        tsa_cert_fingerprint_sha256=fingerprint,
        serial_number=serial,
        subject_digest_hex=expected.hex(),
        detail="granted",
    )


# ---------------------------------------------------------------------------
# CMS helpers — real signature verification
# ---------------------------------------------------------------------------


def _load_certs(signed_data: rfc5652.SignedData) -> list[x509.Certificate]:
    """Decode every X.509 cert embedded in the SignedData ``certificates`` SET."""
    out: list[x509.Certificate] = []
    certs = signed_data["certificates"]
    if not certs.isValue:
        return out
    for choice in certs:
        # CertificateChoices is a CHOICE; the plain X.509 cert is 'certificate'.
        cert = choice.getComponentByName("certificate")
        if cert is None or not cert.isValue:
            continue
        try:
            out.append(x509.load_der_x509_certificate(der_encoder.encode(cert)))
        except Exception:  # noqa: BLE001 — skip anything that is not a parseable cert
            continue
    return out


def _select_signer_cert(
    signed_data: rfc5652.SignedData,
) -> tuple[x509.Certificate | None, str | None]:
    """Pick the signer cert: match the SignerInfo ``sid`` serial when present,
    else fall back to the sole embedded cert."""
    certs = _load_certs(signed_data)
    if not certs:
        return None, "token embeds no certificates (certReq was not honoured)"
    signer_infos = signed_data["signerInfos"]
    if not signer_infos.isValue or len(signer_infos) == 0:
        return None, "SignedData has no signerInfos"
    sid = signer_infos[0]["sid"]
    ias = sid.getComponentByName("issuerAndSerialNumber")
    if ias is not None and ias.isValue:
        want = int(ias["serialNumber"])
        for cert in certs:
            if cert.serial_number == want:
                return cert, None
    if len(certs) == 1:
        return certs[0], None
    return None, "could not match SignerInfo.sid to an embedded certificate"


def _verify_cms_signature(
    signed_data: rfc5652.SignedData,
    signer_cert: x509.Certificate,
    tst_info_der: bytes,
) -> tuple[AnchorFailureCode, str] | None:
    """Verify the SignerInfo signature. Returns ``None`` on success, else
    ``(code, detail)``. Handles the signed-attributes case (the common one):
    checks the ``messageDigest`` and ``contentType`` signed attributes, then
    verifies the signature over the DER of the signedAttrs re-tagged ``SET OF``
    per RFC 5652 §5.4; and the rare no-signedAttrs case (sign over eContent)."""
    signer_info = signed_data["signerInfos"][0]

    digest_oid = str(signer_info["digestAlgorithm"]["algorithm"])
    hash_factory = _HASH_BY_OID.get(digest_oid)
    if hash_factory is None:
        return AnchorFailureCode.UNSUPPORTED_SIG_ALG, f"unsupported digest alg {digest_oid}"

    signed_attrs = signer_info["signedAttrs"]
    if signed_attrs.isValue and len(signed_attrs) > 0:
        attrs = {str(a["attrType"]): a for a in signed_attrs}

        # contentType signed attribute MUST be id-ct-TSTInfo (RFC 5652 §11.1).
        ct_attr = attrs.get(_OID_ATTR_CONTENT_TYPE)
        if ct_attr is None:
            return AnchorFailureCode.CONTENT_TYPE_MISMATCH, "missing signed contentType attribute"
        try:
            ct_val, _ = der_decoder.decode(ct_attr["attrValues"][0])
            if str(ct_val) != _OID_ID_CT_TSTINFO:
                return AnchorFailureCode.CONTENT_TYPE_MISMATCH, "signed contentType is not id-ct-TSTInfo"
        except Exception as exc:  # noqa: BLE001
            return AnchorFailureCode.CONTENT_TYPE_MISMATCH, f"malformed contentType attribute: {exc}"

        # messageDigest signed attribute MUST equal H(eContent).
        md_attr = attrs.get(_OID_ATTR_MESSAGE_DIGEST)
        if md_attr is None:
            return AnchorFailureCode.MESSAGE_DIGEST_MISMATCH, "missing signed messageDigest attribute"
        try:
            md_val = bytes(der_decoder.decode(md_attr["attrValues"][0])[0])
        except Exception as exc:  # noqa: BLE001
            return AnchorFailureCode.MESSAGE_DIGEST_MISMATCH, f"malformed messageDigest attribute: {exc}"
        h = hashlib.new(_hash_name(digest_oid))
        h.update(tst_info_der)
        if md_val != h.digest():
            return (
                AnchorFailureCode.MESSAGE_DIGEST_MISMATCH,
                "signed messageDigest does not equal the hash of the TSTInfo — "
                "the signature does not cover this timestamp content",
            )

        # Signature input = DER of signedAttrs re-tagged from IMPLICIT [0]
        # (0xA0) to universal SET OF (0x31), per RFC 5652 §5.4. Only the single
        # identifier octet changes; the length/content are identical, so the
        # byte substitution is exact for DER.
        attrs_der = der_encoder.encode(signed_attrs)
        signed_bytes = b"\x31" + attrs_der[1:]
    else:
        # No signed attributes: the signature is computed directly over eContent.
        signed_bytes = tst_info_der

    sig_alg_oid = str(signer_info["signatureAlgorithm"]["algorithm"])
    signature = bytes(signer_info["signature"])
    return _verify_public_key(
        signer_cert, signature, signed_bytes, sig_alg_oid, digest_oid
    )


def _verify_public_key(
    cert: x509.Certificate,
    signature: bytes,
    signed_bytes: bytes,
    sig_alg_oid: str,
    digest_oid: str,
) -> tuple[AnchorFailureCode, str] | None:
    """Run the actual public-key verification. ``None`` on success."""
    public_key = cert.public_key()
    # Resolve the hash: ECDSA/RSA-with-hash OIDs carry their own; rsaEncryption
    # defers to the SignerInfo digestAlgorithm.
    hash_for_sig = {
        _OID_SHA256_RSA: hashes.SHA256,
        _OID_SHA384_RSA: hashes.SHA384,
        _OID_SHA512_RSA: hashes.SHA512,
        _OID_ECDSA_SHA256: hashes.SHA256,
        _OID_ECDSA_SHA384: hashes.SHA384,
        _OID_ECDSA_SHA512: hashes.SHA512,
    }.get(sig_alg_oid)
    if sig_alg_oid == _OID_RSA_ENCRYPTION:
        hash_for_sig = _HASH_BY_OID.get(digest_oid)

    if hash_for_sig is None:
        return AnchorFailureCode.UNSUPPORTED_SIG_ALG, f"unsupported signature alg {sig_alg_oid}"

    is_rsa = sig_alg_oid in (
        _OID_RSA_ENCRYPTION,
        _OID_SHA256_RSA,
        _OID_SHA384_RSA,
        _OID_SHA512_RSA,
    )
    is_ecdsa = sig_alg_oid in (_OID_ECDSA_SHA256, _OID_ECDSA_SHA384, _OID_ECDSA_SHA512)
    try:
        if is_rsa:
            if not isinstance(public_key, rsa.RSAPublicKey):
                return AnchorFailureCode.SIGNATURE_INVALID, "RSA sig alg but signer key is not RSA"
            public_key.verify(signature, signed_bytes, padding.PKCS1v15(), hash_for_sig())
        elif is_ecdsa:
            if not isinstance(public_key, ec.EllipticCurvePublicKey):
                return AnchorFailureCode.SIGNATURE_INVALID, "ECDSA sig alg but signer key is not EC"
            public_key.verify(signature, signed_bytes, ec.ECDSA(hash_for_sig()))
        else:
            return AnchorFailureCode.UNSUPPORTED_SIG_ALG, f"unsupported signature alg {sig_alg_oid}"
    except InvalidSignature:
        return (
            AnchorFailureCode.SIGNATURE_INVALID,
            "the TSA signature does not verify against the embedded signer cert — "
            "the timestamp token is forged or altered",
        )
    except Exception as exc:  # noqa: BLE001 — malformed key/sig material
        return AnchorFailureCode.SIGNATURE_INVALID, f"signature verification error: {exc}"
    return None


def _is_pinned(signer_cert: x509.Certificate, pinned_cert_der: bytes) -> bool:
    """Trusted iff the signer cert is exactly the pinned cert, or is directly
    issued by it (pin a leaf for an exact match, or a CA to allow rotation)."""
    try:
        pinned = x509.load_der_x509_certificate(pinned_cert_der)
    except Exception:  # noqa: BLE001
        return False
    if signer_cert.fingerprint(hashes.SHA256()) == pinned.fingerprint(hashes.SHA256()):
        return True
    try:
        signer_cert.verify_directly_issued_by(pinned)
        return True
    except (ValueError, TypeError, InvalidSignature):
        return False
    except Exception:  # noqa: BLE001 — any other failure is "not trusted"
        return False


def _has_sole_timestamping_eku(cert: x509.Certificate) -> bool:
    """RFC 3161 §2.3: a TSA cert MUST contain id-kp-timeStamping and it MUST be
    the *only* extended key usage — so a multi-purpose cert from the pinned CA
    cannot be repurposed to forge timestamps. (Criticality is NOT enforced: real
    public TSAs vary on the critical bit, and sole-EKU already carries the
    security-relevant "authorized only for timestamping" property.)"""
    try:
        ekus = list(cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value)
    except x509.ExtensionNotFound:
        return False
    return ekus == [ExtendedKeyUsageOID.TIME_STAMPING]


def _hash_name(oid: str) -> str:
    return {
        _OID_SHA256: "sha256",
        _OID_SHA384: "sha384",
        _OID_SHA512: "sha512",
        _OID_SHA1: "sha1",
    }[oid]


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


def _parse_generalized_time(value: str) -> datetime:
    """Parse RFC 3161 ``genTime`` (GeneralizedTime ``YYYYMMDDHHMMSS[.fff]Z``)."""
    if value.endswith("Z"):
        value = value[:-1]
    base = value[:14]
    frac = value[14:] if len(value) > 14 else ""
    dt = datetime.strptime(base, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
    if frac.startswith("."):
        digits = frac[1:].ljust(6, "0")[:6]
        dt = dt.replace(microsecond=int(digits))
    return dt

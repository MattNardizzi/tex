"""
A self-issued RFC 3161 Time-Stamp Authority — for OFFLINE DEMO / DEV / TEST ONLY.

This mints a throwaway CA + TSA leaf cert and produces **real** CMS ``SignedData``
timestamp tokens, so the offline verifier
(``external_anchor.verify_anchor_receipt``) can be exercised end-to-end with no
network. It is the in-process stand-in a unit test pins, and what
``scripts/anchor_demo.py`` runs.

HONESTY — this proves NOTHING about real time. A token from a TSA you minted
yourself is exactly as forgeable as the chain it is meant to anchor; its only job
is to verify the *verification logic*. Real proof-of-age comes only from pinning
an **external** authority's cert (``anchors/tsa/``) and a token signed by that
authority's key. Never pin a ``LocalTSA`` cert in production.

The token builder deliberately exposes adversarial knobs (``sign_key`` override,
``eku``, validity window, ``status``) so a verifier can be tested against
forgeries, not only happy paths.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from pyasn1.codec.der import decoder as der_decoder
from pyasn1.codec.der import encoder as der_encoder
from pyasn1.type import univ
from pyasn1_modules import rfc3161, rfc5280, rfc5652

__all__ = ["LocalTSA", "mint_local_tsa", "issue_timestamp_response"]

_OID_SHA256 = "2.16.840.1.101.3.4.2.1"
_OID_ID_CT_TSTINFO = "1.2.840.113549.1.9.16.1.4"
_OID_ID_SIGNED_DATA = "1.2.840.113549.1.7.2"
_OID_ATTR_CONTENT_TYPE = "1.2.840.113549.1.9.3"
_OID_ATTR_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
_OID_SHA256_RSA = "1.2.840.113549.1.1.11"

_DEFAULT_NB = datetime(2026, 1, 1, tzinfo=timezone.utc)
_DEFAULT_NA = datetime(2030, 1, 1, tzinfo=timezone.utc)


@dataclass(frozen=True)
class LocalTSA:
    """A minted CA + TSA pair. ``ca_pin_der`` is what a verifier pins."""

    ca_cert: x509.Certificate
    ca_key: rsa.RSAPrivateKey
    tsa_cert: x509.Certificate
    tsa_key: rsa.RSAPrivateKey

    @property
    def ca_pin_der(self) -> bytes:
        return self.ca_cert.public_bytes(Encoding.DER)

    @property
    def leaf_pin_der(self) -> bytes:
        return self.tsa_cert.public_bytes(Encoding.DER)


def mint_local_tsa(
    *,
    eku: bool = True,
    extra_ekus: tuple[x509.ObjectIdentifier, ...] = (),
    not_before: datetime = _DEFAULT_NB,
    not_after: datetime = _DEFAULT_NA,
) -> LocalTSA:
    """Mint a self-signed CA and a TSA leaf cert issued by it. ``eku=False``
    omits id-kp-timeStamping (for the missing-EKU rejection test); ``extra_ekus``
    adds other usages alongside it (for the non-sole-EKU rejection test)."""
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Tex Local Anchor CA (DEMO)")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    tsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Tex Local TSA (DEMO)")]))
        .issuer_name(ca_name)
        .public_key(tsa_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )
    if eku:
        usages = [ExtendedKeyUsageOID.TIME_STAMPING, *extra_ekus]
        builder = builder.add_extension(x509.ExtendedKeyUsage(usages), critical=True)
    tsa_cert = builder.sign(ca_key, hashes.SHA256())
    return LocalTSA(ca_cert=ca_cert, ca_key=ca_key, tsa_cert=tsa_cert, tsa_key=tsa_key)


def _attr(oid: str, value_obj) -> rfc5652.Attribute:
    a = rfc5652.Attribute()
    a["attrType"] = univ.ObjectIdentifier(oid)
    a["attrValues"][0] = univ.Any(der_encoder.encode(value_obj))
    return a


def issue_timestamp_response(
    subject_digest: bytes,
    tsa: LocalTSA,
    *,
    sign_key: rsa.RSAPrivateKey | None = None,
    gen_time: str = "20260201120000Z",
    nonce: int | None = None,
    status: int = 0,
    include_certs: bool = True,
) -> bytes:
    """Build a real DER ``TimeStampResp`` for ``subject_digest``.

    ``sign_key`` defaults to the TSA's key; pass a different key to forge a
    signature while still embedding the genuine TSA cert (the verifier must catch
    that). ``status`` other than granted/grantedWithMods omits the token.
    """
    signing_key = sign_key or tsa.tsa_key

    tst = rfc3161.TSTInfo()
    tst["version"] = 1
    tst["policy"] = univ.ObjectIdentifier("1.2.3.4.1")
    mi = rfc3161.MessageImprint()
    mi["hashAlgorithm"]["algorithm"] = univ.ObjectIdentifier(_OID_SHA256)
    mi["hashedMessage"] = univ.OctetString(subject_digest)
    tst["messageImprint"] = mi
    tst["serialNumber"] = univ.Integer(42)
    tst["genTime"] = gen_time
    if nonce is not None:
        tst["nonce"] = univ.Integer(nonce)
    tst_der = der_encoder.encode(tst)

    encap = rfc5652.EncapsulatedContentInfo()
    encap["eContentType"] = univ.ObjectIdentifier(_OID_ID_CT_TSTINFO)
    _ec = encap.componentType.getTypeByPosition(encap.componentType.getPositionByName("eContent"))
    encap["eContent"] = _ec.clone(tst_der)

    si = rfc5652.SignerInfo()
    si["version"] = 1
    parsed, _ = der_decoder.decode(tsa.tsa_cert.public_bytes(Encoding.DER), asn1Spec=rfc5280.Certificate())
    ias = rfc5652.IssuerAndSerialNumber()
    ias["issuer"] = parsed["tbsCertificate"]["issuer"]
    ias["serialNumber"] = parsed["tbsCertificate"]["serialNumber"]
    si["sid"]["issuerAndSerialNumber"] = ias
    si["digestAlgorithm"]["algorithm"] = univ.ObjectIdentifier(_OID_SHA256)
    md = hashlib.sha256(tst_der).digest()
    sa = si["signedAttrs"]
    sa[0] = _attr(_OID_ATTR_CONTENT_TYPE, univ.ObjectIdentifier(_OID_ID_CT_TSTINFO))
    sa[1] = _attr(_OID_ATTR_MESSAGE_DIGEST, univ.OctetString(md))
    attrs_der = der_encoder.encode(sa)
    signed_bytes = b"\x31" + attrs_der[1:]  # IMPLICIT [0] -> SET OF (RFC 5652 §5.4)
    signature = signing_key.sign(signed_bytes, padding.PKCS1v15(), hashes.SHA256())
    si["signatureAlgorithm"]["algorithm"] = univ.ObjectIdentifier(_OID_SHA256_RSA)
    si["signature"] = univ.OctetString(signature)

    sd = rfc5652.SignedData()
    sd["version"] = 3
    sd["digestAlgorithms"][0]["algorithm"] = univ.ObjectIdentifier(_OID_SHA256)
    sd["encapContentInfo"] = encap
    if include_certs:
        for c in (tsa.tsa_cert, tsa.ca_cert):
            cp, _ = der_decoder.decode(c.public_bytes(Encoding.DER), asn1Spec=rfc5280.Certificate())
            choice = rfc5652.CertificateChoices()
            choice["certificate"] = cp
            sd["certificates"].append(choice)
    sd["signerInfos"][0] = si

    ci = rfc5652.ContentInfo()
    ci["contentType"] = univ.ObjectIdentifier(_OID_ID_SIGNED_DATA)
    _c = ci.componentType.getTypeByPosition(ci.componentType.getPositionByName("content"))
    ci["content"] = _c.clone(der_encoder.encode(sd))

    resp = rfc3161.TimeStampResp()
    resp["status"]["status"] = status
    if status in (0, 1):
        resp["timeStampToken"] = ci
    return der_encoder.encode(resp)

"""
ASN.1 DER serialization for Composite ML-DSA signatures per
draft-ietf-lamps-cms-composite-sigs-04 and
draft-ietf-lamps-pq-composite-sigs-18.

What this module ships
----------------------
The base ``tex.pqcrypto.composite_ml_dsa`` module uses a simple
length-prefixed concat layout (``u32_be(len) || ml_dsa || classical``)
that is fine for in-protocol Tex evidence chain use but is NOT what
X.509 / CMS auditors expect. The IETF LAMPS drafts mandate ASN.1 DER
serialization. This module provides the converters between Tex's
internal length-prefixed layout and the standards-compliant DER form.

Use cases:
- **X.509 certificate signatures** containing Composite ML-DSA per
  draft-ietf-lamps-pq-composite-sigs-18 §3.
- **CMS SignedData** (RFC 5652) using Composite ML-DSA per
  draft-ietf-lamps-cms-composite-sigs-04.
- **EU AI Act Article 12 audit packages** where the evidence chain is
  exported as a CMS SignedData blob with cross-signature attestations.

Wire format (draft-ietf-lamps-pq-composite-sigs-18 §4)
------------------------------------------------------
::

    CompositeSignatureValue ::= SEQUENCE {
        mldsaSignature      OCTET STRING,
        traditionalSignature OCTET STRING
    }

    CompositePublicKey ::= SEQUENCE OF SubjectPublicKeyInfo

Where ``SubjectPublicKeyInfo`` is the standard RFC 5280 type.

Algorithm OIDs (draft-18 §6.4 — prototype OID arc)
--------------------------------------------------
Composite ML-DSA-65 + Ed25519:    2.16.840.1.114027.80.9.1.4
Composite ML-DSA-87 + ECDSA-P384: 2.16.840.1.114027.80.9.1.7

These OIDs are explicitly marked PROTOTYPE in draft-18 — they will change
to the IANA-registered OIDs when the RFC is published. We store them as
named constants so a single edit re-binds when the assignment lands.

References
----------
- draft-ietf-lamps-pq-composite-sigs-18 (Apr 9 2026)
- draft-ietf-lamps-cms-composite-sigs-04 (Feb 5 2026, latest 13 May 2026)
- RFC 5280 (X.509 SubjectPublicKeyInfo)
- RFC 5652 (CMS SignedData)
- RFC 5915 (ECPrivateKey)
- RFC 8410 (Ed25519 / Ed448 X.509 encoding)
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Final

from pyasn1.codec.der import decoder as der_decoder
from pyasn1.codec.der import encoder as der_encoder
from pyasn1.type import namedtype, univ
from pyasn1_modules import rfc5280

from tex.observability.telemetry import emit_event
from tex.pqcrypto.algorithm_agility import SignatureAlgorithm


# --- Algorithm OIDs ---------------------------------------------------------
#
# Prototype OIDs from draft-ietf-lamps-pq-composite-sigs-18 §6.4 (Entrust
# arc 2.16.840.1.114027.80.9.1). These will be replaced when IANA registers
# the production OIDs.

OID_COMPOSITE_ML_DSA_65_ED25519: Final[str] = "2.16.840.1.114027.80.9.1.4"
OID_COMPOSITE_ML_DSA_87_ECDSA_P384: Final[str] = "2.16.840.1.114027.80.9.1.7"

OID_BY_ALGORITHM: Final[dict[SignatureAlgorithm, str]] = {
    SignatureAlgorithm.COMPOSITE_ML_DSA_65_ED25519: OID_COMPOSITE_ML_DSA_65_ED25519,
    SignatureAlgorithm.COMPOSITE_ML_DSA_87_ECDSA_P384: OID_COMPOSITE_ML_DSA_87_ECDSA_P384,
}

ALGORITHM_BY_OID: Final[dict[str, SignatureAlgorithm]] = {
    v: k for k, v in OID_BY_ALGORITHM.items()
}


# --- CompositeSignatureValue ASN.1 type --------------------------------------


class CompositeSignatureValue(univ.Sequence):
    """
    CompositeSignatureValue ::= SEQUENCE {
        mldsaSignature      OCTET STRING,
        traditionalSignature OCTET STRING
    }

    Per draft-ietf-lamps-pq-composite-sigs-18 §4.1.
    """

    componentType = namedtype.NamedTypes(
        namedtype.NamedType("mldsaSignature", univ.OctetString()),
        namedtype.NamedType("traditionalSignature", univ.OctetString()),
    )


# --- Internal length-prefixed layout helpers (mirror composite_ml_dsa.py) ---

_LEN_PREFIX_BYTES = 4


def _split_length_prefixed(blob: bytes, *, label: str) -> tuple[bytes, bytes]:
    if len(blob) < _LEN_PREFIX_BYTES:
        raise ValueError(f"{label} too short to contain length prefix")
    (ml_dsa_len,) = struct.unpack(">I", blob[:_LEN_PREFIX_BYTES])
    end = _LEN_PREFIX_BYTES + ml_dsa_len
    if end > len(blob):
        raise ValueError(f"{label} length prefix exceeds blob size")
    return blob[_LEN_PREFIX_BYTES:end], blob[end:]


def _concat_length_prefixed(ml_dsa_part: bytes, classical_part: bytes) -> bytes:
    return struct.pack(">I", len(ml_dsa_part)) + ml_dsa_part + classical_part


# --- Public API: encode / decode -------------------------------------------


def encode_composite_signature_der(
    tex_internal_signature: bytes,
    algorithm: SignatureAlgorithm,
) -> bytes:
    """
    Convert Tex's internal length-prefixed composite signature to the
    standards-compliant DER form per draft-18 §4.1.

    Returns DER-encoded ``CompositeSignatureValue`` SEQUENCE.

    Parameters
    ----------
    tex_internal_signature
        The output of ``CompositeMlDsaProvider.sign()`` — Tex's internal
        ``u32_be(len) || ml_dsa || classical`` layout.
    algorithm
        Used for sanity checking only (the ASN.1 layout is the same for
        both supported composite parameter sets); the algorithm OID is
        emitted separately in the X.509 / CMS context.
    """
    if algorithm not in OID_BY_ALGORITHM:
        raise ValueError(
            f"not a composite ML-DSA algorithm: {algorithm.value}"
        )

    ml_dsa_sig, classical_sig = _split_length_prefixed(
        tex_internal_signature, label="composite signature",
    )

    cs = CompositeSignatureValue()
    cs.setComponentByName("mldsaSignature", univ.OctetString(ml_dsa_sig))
    cs.setComponentByName("traditionalSignature", univ.OctetString(classical_sig))

    der = der_encoder.encode(cs)
    emit_event(
        "pqcrypto.composite_cms.encoded",
        algorithm=algorithm.value,
        oid=OID_BY_ALGORITHM[algorithm],
        ml_dsa_signature_bytes=len(ml_dsa_sig),
        classical_signature_bytes=len(classical_sig),
        der_bytes=len(der),
    )
    return der


def decode_composite_signature_der(
    der_bytes: bytes,
    algorithm: SignatureAlgorithm,
) -> bytes:
    """
    Convert DER ``CompositeSignatureValue`` to Tex's internal length-
    prefixed form.

    Returns the same byte layout that ``CompositeMlDsaProvider.verify``
    expects, so a verifier can round-trip:
    DER → internal → ``CompositeMlDsaProvider.verify``.
    """
    if algorithm not in OID_BY_ALGORITHM:
        raise ValueError(
            f"not a composite ML-DSA algorithm: {algorithm.value}"
        )

    decoded, rest = der_decoder.decode(der_bytes, asn1Spec=CompositeSignatureValue())
    if rest:
        raise ValueError(
            f"trailing bytes after CompositeSignatureValue DER: {len(rest)} bytes"
        )
    ml_dsa_sig = bytes(decoded.getComponentByName("mldsaSignature"))
    classical_sig = bytes(decoded.getComponentByName("traditionalSignature"))

    internal = _concat_length_prefixed(ml_dsa_sig, classical_sig)
    emit_event(
        "pqcrypto.composite_cms.decoded",
        algorithm=algorithm.value,
        oid=OID_BY_ALGORITHM[algorithm],
        ml_dsa_signature_bytes=len(ml_dsa_sig),
        classical_signature_bytes=len(classical_sig),
        der_bytes=len(der_bytes),
    )
    return internal


# --- AlgorithmIdentifier helpers --------------------------------------------


def build_algorithm_identifier(algorithm: SignatureAlgorithm) -> bytes:
    """
    Produce a DER-encoded AlgorithmIdentifier for the given composite
    parameter set, suitable for embedding in a SubjectPublicKeyInfo or
    SignerInfo (RFC 5652).
    """
    if algorithm not in OID_BY_ALGORITHM:
        raise ValueError(
            f"not a composite ML-DSA algorithm: {algorithm.value}"
        )
    alg_id = rfc5280.AlgorithmIdentifier()
    alg_id.setComponentByName("algorithm", univ.ObjectIdentifier(
        OID_BY_ALGORITHM[algorithm]
    ))
    # Composite ML-DSA OIDs have NULL parameters per draft-18 §6.4
    alg_id.setComponentByName("parameters", univ.Any(der_encoder.encode(univ.Null())))
    return der_encoder.encode(alg_id)


def parse_algorithm_identifier(der_bytes: bytes) -> SignatureAlgorithm:
    """
    Parse a DER AlgorithmIdentifier and return the matching
    SignatureAlgorithm enum (or raise ValueError if unknown).
    """
    decoded, rest = der_decoder.decode(der_bytes, asn1Spec=rfc5280.AlgorithmIdentifier())
    if rest:
        raise ValueError(f"trailing bytes after AlgorithmIdentifier DER: {len(rest)} bytes")
    oid = str(decoded.getComponentByName("algorithm"))
    if oid not in ALGORITHM_BY_OID:
        raise ValueError(f"unknown algorithm OID: {oid}")
    return ALGORITHM_BY_OID[oid]


# --- CMS SignedData envelope (simplified) -----------------------------------


@dataclass(frozen=True, slots=True)
class CmsCompositeSignerInfo:
    """A minimal CMS SignerInfo carrying a composite ML-DSA signature."""

    algorithm: SignatureAlgorithm
    signature_der: bytes  # CompositeSignatureValue DER
    signing_key_id_b64: str  # opaque, ties back to keystore


def encode_cms_signer_info(
    info: CmsCompositeSignerInfo,
) -> bytes:
    """
    Encode a minimal SignerInfo SEQUENCE that auditors can decode.

    This is NOT a full RFC 5652 SignerInfo (which carries IssuerAndSerial,
    signedAttrs, etc.) — it is the *signature payload* that a CMS
    SignerInfo would carry, plus the algorithm OID, plus an opaque key ID
    that the Tex keystore resolves. Full RFC 5652 integration is in
    ``tex.evidence.c2pa_emitter`` for the C2PA path; this helper exists
    so a CMS-style export pipeline has a single round-trip-able blob.

    Layout::

        SEQUENCE {
            algorithm  AlgorithmIdentifier,
            keyId      OCTET STRING,
            signature  OCTET STRING  -- DER-encoded CompositeSignatureValue
        }
    """

    class _SignerInfo(univ.Sequence):
        componentType = namedtype.NamedTypes(
            namedtype.NamedType("algorithm", rfc5280.AlgorithmIdentifier()),
            namedtype.NamedType("keyId", univ.OctetString()),
            namedtype.NamedType("signature", univ.OctetString()),
        )

    si = _SignerInfo()
    # Algorithm
    alg_id = rfc5280.AlgorithmIdentifier()
    alg_id.setComponentByName("algorithm", univ.ObjectIdentifier(
        OID_BY_ALGORITHM[info.algorithm]
    ))
    alg_id.setComponentByName("parameters", univ.Any(der_encoder.encode(univ.Null())))
    si.setComponentByName("algorithm", alg_id)
    # keyId
    import base64
    si.setComponentByName(
        "keyId", univ.OctetString(base64.b64decode(info.signing_key_id_b64))
        if info.signing_key_id_b64 else univ.OctetString(b""),
    )
    # signature
    si.setComponentByName("signature", univ.OctetString(info.signature_der))

    der = der_encoder.encode(si)
    emit_event(
        "pqcrypto.composite_cms.signer_info_encoded",
        algorithm=info.algorithm.value,
        oid=OID_BY_ALGORITHM[info.algorithm],
        signature_der_bytes=len(info.signature_der),
        der_bytes=len(der),
    )
    return der

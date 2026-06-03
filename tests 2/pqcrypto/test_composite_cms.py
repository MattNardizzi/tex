"""
Tests for tex.pqcrypto.composite_cms — ASN.1 DER serialization of
composite ML-DSA signatures per draft-ietf-lamps-pq-composite-sigs-18 §4
and draft-ietf-lamps-cms-composite-sigs-04.

Validates:
- Prototype OIDs match the draft §6.4 assignments
- DER round-trip (encode → decode) preserves both signature halves
- Decoded internal form re-verifies under CompositeMlDsaProvider.verify
- AlgorithmIdentifier round-trip with the prototype OIDs
- Malformed DER rejected with ValueError (no silent acceptance)
- CMS SignerInfo envelope produces a parseable SEQUENCE
"""

from __future__ import annotations

import pytest

from tex.pqcrypto.algorithm_agility import SignatureAlgorithm


def _liboqs_runtime_ok() -> bool:
    """True iff some ML-DSA / ML-KEM backend is available."""
    try:
        from tex.pqcrypto.ml_dsa import active_backend_id
        if active_backend_id() is not None:
            return True
    except Exception:
        pass
    try:
        import oqs
        oqs.Signature("ML-DSA-65")
        return True
    except Exception:
        return False


_LIBOQS_AVAILABLE = _liboqs_runtime_ok()
_requires_liboqs = pytest.mark.skipif(
    not _LIBOQS_AVAILABLE,
    reason="liboqs not available",
)


_COMPOSITE_PARAMS = [
    SignatureAlgorithm.COMPOSITE_ML_DSA_65_ED25519,
    SignatureAlgorithm.COMPOSITE_ML_DSA_87_ECDSA_P384,
]


# --- OID assignment tests ---------------------------------------------------


def test_prototype_oids_match_draft_18_section_6_4() -> None:
    """
    The prototype OIDs from draft-ietf-lamps-pq-composite-sigs-18 §6.4.

    These are under Entrust's experimental arc 2.16.840.1.114027.80.9.1
    and will be replaced by IANA-registered OIDs when the RFC publishes.
    """
    from tex.pqcrypto.composite_cms import (
        OID_COMPOSITE_ML_DSA_65_ED25519,
        OID_COMPOSITE_ML_DSA_87_ECDSA_P384,
    )

    assert OID_COMPOSITE_ML_DSA_65_ED25519 == "2.16.840.1.114027.80.9.1.4"
    assert OID_COMPOSITE_ML_DSA_87_ECDSA_P384 == "2.16.840.1.114027.80.9.1.7"


def test_oid_map_bidirectional() -> None:
    from tex.pqcrypto.composite_cms import ALGORITHM_BY_OID, OID_BY_ALGORITHM

    for algo, oid in OID_BY_ALGORITHM.items():
        assert ALGORITHM_BY_OID[oid] is algo


def test_encode_rejects_non_composite_algorithm() -> None:
    from tex.pqcrypto.composite_cms import encode_composite_signature_der

    with pytest.raises(ValueError, match="not a composite ML-DSA algorithm"):
        encode_composite_signature_der(b"\x00" * 100, SignatureAlgorithm.ML_DSA_65)


def test_decode_rejects_non_composite_algorithm() -> None:
    from tex.pqcrypto.composite_cms import decode_composite_signature_der

    with pytest.raises(ValueError, match="not a composite ML-DSA algorithm"):
        decode_composite_signature_der(b"\x00" * 100, SignatureAlgorithm.ML_DSA_65)


# --- DER round-trip tests ---------------------------------------------------


@_requires_liboqs
@pytest.mark.parametrize("algo", _COMPOSITE_PARAMS)
def test_composite_signature_der_round_trip(algo: SignatureAlgorithm) -> None:
    """
    Sign with the composite provider, encode to DER, decode back to
    internal layout, re-verify under the provider.
    """
    from tex.pqcrypto.composite_cms import (
        decode_composite_signature_der,
        encode_composite_signature_der,
    )
    from tex.pqcrypto.composite_ml_dsa import CompositeMlDsaProvider

    p = CompositeMlDsaProvider(algo)
    kp = p.generate_keypair("der-round-trip")
    msg = b"composite signature for X.509 / CMS"
    internal_sig = p.sign(msg, kp)

    der = encode_composite_signature_der(internal_sig, algo)
    # DER framing adds ~6 bytes over the internal length-prefixed layout.
    assert len(der) > len(internal_sig)
    assert len(der) < len(internal_sig) + 32

    # Round-trip preserves the internal layout bit-for-bit.
    decoded = decode_composite_signature_der(der, algo)
    assert decoded == internal_sig

    # The decoded internal form re-verifies under the composite provider.
    assert p.verify(msg, decoded, kp.public_key) is True


@_requires_liboqs
@pytest.mark.parametrize("algo", _COMPOSITE_PARAMS)
def test_composite_der_signature_size_envelope(algo: SignatureAlgorithm) -> None:
    """
    Pin DER sizes so a future change to the upstream draft (or our
    serialization) is caught.

    Composite ML-DSA-65+Ed25519:    internal=3377  DER=3383
    Composite ML-DSA-87+ECDSA-P384: internal=4733  DER=4739 (ECDSA-P384
       DER sig has small variable-length component, the bound is ±~5).
    """
    from tex.pqcrypto.composite_cms import encode_composite_signature_der
    from tex.pqcrypto.composite_ml_dsa import CompositeMlDsaProvider

    p = CompositeMlDsaProvider(algo)
    kp = p.generate_keypair()
    sig = p.sign(b"m", kp)
    der = encode_composite_signature_der(sig, algo)
    if algo is SignatureAlgorithm.COMPOSITE_ML_DSA_65_ED25519:
        assert 3380 <= len(der) <= 3390
    elif algo is SignatureAlgorithm.COMPOSITE_ML_DSA_87_ECDSA_P384:
        # ECDSA-P384 signatures are variable-length DER (96-103 bytes typical).
        assert 4730 <= len(der) <= 4745


def test_decode_rejects_trailing_bytes() -> None:
    """Strict DER parsing: trailing bytes after the SEQUENCE are rejected."""
    from tex.pqcrypto.composite_cms import (
        decode_composite_signature_der,
        encode_composite_signature_der,
    )
    # Build a valid DER from synthetic halves, then append garbage.
    import struct
    fake_internal = struct.pack(">I", 10) + b"\x01" * 10 + b"\x02" * 20
    valid_der = encode_composite_signature_der(
        fake_internal, SignatureAlgorithm.COMPOSITE_ML_DSA_65_ED25519,
    )
    with pytest.raises(ValueError, match="trailing bytes"):
        decode_composite_signature_der(
            valid_der + b"GARBAGE",
            SignatureAlgorithm.COMPOSITE_ML_DSA_65_ED25519,
        )


def test_decode_rejects_malformed_der() -> None:
    from tex.pqcrypto.composite_cms import decode_composite_signature_der

    with pytest.raises(Exception):
        decode_composite_signature_der(
            b"\x00\xff\xff\xff",  # not valid ASN.1
            SignatureAlgorithm.COMPOSITE_ML_DSA_65_ED25519,
        )


# --- AlgorithmIdentifier tests ---------------------------------------------


@pytest.mark.parametrize("algo", _COMPOSITE_PARAMS)
def test_algorithm_identifier_round_trip(algo: SignatureAlgorithm) -> None:
    from tex.pqcrypto.composite_cms import (
        build_algorithm_identifier,
        parse_algorithm_identifier,
    )

    der = build_algorithm_identifier(algo)
    parsed = parse_algorithm_identifier(der)
    assert parsed is algo


def test_parse_algorithm_identifier_rejects_unknown_oid() -> None:
    """An unrecognized OID inside an AlgorithmIdentifier raises ValueError."""
    from pyasn1.codec.der import encoder as der_encoder
    from pyasn1.type import univ
    from pyasn1_modules import rfc5280

    from tex.pqcrypto.composite_cms import parse_algorithm_identifier

    # Build an AlgorithmIdentifier with a bogus OID.
    alg_id = rfc5280.AlgorithmIdentifier()
    alg_id.setComponentByName("algorithm", univ.ObjectIdentifier("1.2.3.4.5.6.7"))
    alg_id.setComponentByName("parameters", univ.Any(der_encoder.encode(univ.Null())))
    der = der_encoder.encode(alg_id)
    with pytest.raises(ValueError, match="unknown algorithm OID"):
        parse_algorithm_identifier(der)


# --- CMS SignerInfo envelope -----------------------------------------------


@_requires_liboqs
def test_cms_signer_info_encodes_parseable_sequence() -> None:
    import base64

    from pyasn1.codec.der import decoder as der_decoder
    from pyasn1.type import univ

    from tex.pqcrypto.composite_cms import (
        CmsCompositeSignerInfo,
        encode_cms_signer_info,
        encode_composite_signature_der,
    )
    from tex.pqcrypto.composite_ml_dsa import CompositeMlDsaProvider

    p = CompositeMlDsaProvider(SignatureAlgorithm.COMPOSITE_ML_DSA_87_ECDSA_P384)
    kp = p.generate_keypair("cms-test")
    internal_sig = p.sign(b"audit package", kp)
    der_sig = encode_composite_signature_der(
        internal_sig, SignatureAlgorithm.COMPOSITE_ML_DSA_87_ECDSA_P384,
    )
    info = CmsCompositeSignerInfo(
        algorithm=SignatureAlgorithm.COMPOSITE_ML_DSA_87_ECDSA_P384,
        signature_der=der_sig,
        signing_key_id_b64=base64.b64encode(b"keystore-id-1").decode(),
    )
    blob = encode_cms_signer_info(info)
    # Must decode as a SEQUENCE
    decoded, rest = der_decoder.decode(blob)
    assert isinstance(decoded, univ.Sequence)
    assert rest == b""

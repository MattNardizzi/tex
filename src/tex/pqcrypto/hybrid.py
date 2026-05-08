"""
Hybrid signature provider for transition-period defense in depth.

Combines a classical signature (Ed25519 or ECDSA-P256) with ML-DSA-65.
Verifier requires BOTH signatures to validate. Provides cryptographic
agility during the transition window where ML-DSA is new and classical
algorithms are not yet broken.

Wire format (paper-silent design decision)
------------------------------------------
NIST has not yet published a standard hybrid signature wire format
(draft-ietf-pquip-hybrid-signature-spectrums is in flight). We use a
self-describing length-prefixed concat tagged with a layout version
constant ``_HYBRID_LAYOUT_VERSION``:

    layout v1
    ---------
    signature  := u32_be(len(ml_dsa_sig)) || ml_dsa_sig || ed25519_sig
    public_key := u32_be(len(ml_dsa_pk))  || ml_dsa_pk  || ed25519_pk
    private_key:= u32_be(len(ml_dsa_sk))  || ml_dsa_sk  || ed25519_sk

The 4-byte big-endian length prefix is mandatory because ML-DSA-65
signatures are variable-length up to ~3309 bytes while Ed25519 is fixed
at 64 bytes — without an explicit split point the reader cannot recover
either half. ML-DSA public/private keys are fixed-length per FIPS 204
but we use the same self-describing layout for symmetry.

The version constant exists so a future thread can introduce a v2 layout
(e.g. the IETF hybrid signature spectrum format once
draft-ietf-pquip-hybrid-signature-spectrums lands) and detect old
signatures without ambiguity.

TODO(verify-against-future-hybrid-standard): when NIST FIPS 206 or an
IETF RFC publishes a standard hybrid wire format, bump
``_HYBRID_LAYOUT_VERSION`` and add a v1->v2 detection branch.

Reference
---------
- NIST FIPS 204 (ML-DSA)
- RFC 8032 (Ed25519)
- NSA CNSA 2.0 transition guidance (hybrid mode recommended through 2030)

Priority: P0 — recommended default during 2026-2030 transition window.
"""

from __future__ import annotations

import struct
from uuid import uuid4

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from tex.observability.telemetry import emit_event
from tex.pqcrypto.algorithm_agility import (
    SignatureAlgorithm,
    SignatureKeyPair,
)
from tex.pqcrypto.ml_dsa import MlDsaProvider


# Wire-format layout version. See module docstring for the v1 layout.
# Bump when a standard hybrid format (FIPS 206 / IETF) is adopted.
_HYBRID_LAYOUT_VERSION: str = "1"

# 4-byte big-endian length prefix on the ML-DSA half of the concat.
_LEN_PREFIX_BYTES = 4


def _split_length_prefixed(blob: bytes, *, label: str) -> tuple[bytes, bytes]:
    """Split a ``u32_be(len) || ml_dsa || classical`` blob into its two halves."""
    if len(blob) < _LEN_PREFIX_BYTES:
        raise ValueError(f"{label} too short to contain length prefix")
    (ml_dsa_len,) = struct.unpack(">I", blob[:_LEN_PREFIX_BYTES])
    end = _LEN_PREFIX_BYTES + ml_dsa_len
    if end > len(blob):
        raise ValueError(f"{label} length prefix exceeds blob size")
    ml_dsa_part = blob[_LEN_PREFIX_BYTES:end]
    classical_part = blob[end:]
    return ml_dsa_part, classical_part


def _concat_length_prefixed(ml_dsa_part: bytes, classical_part: bytes) -> bytes:
    """Pack ``u32_be(len) || ml_dsa || classical``."""
    return struct.pack(">I", len(ml_dsa_part)) + ml_dsa_part + classical_part


class HybridMlDsaEd25519Provider:
    """
    ML-DSA-65 + Ed25519 concatenated hybrid signature.

    Both halves must verify for ``verify`` to return ``True``.
    Sign and verify are deterministic in their layout (length-prefixed
    concat — see module docstring).

    Attributes
    ----------
    algorithm
        Always ``SignatureAlgorithm.HYBRID_ML_DSA_ED25519``. Exposed
        under the same attribute name as the other providers for
        ``signature_algorithm_for()``.
    """

    algorithm: SignatureAlgorithm = SignatureAlgorithm.HYBRID_ML_DSA_ED25519

    def __init__(self) -> None:
        # ML-DSA-65 is the recommended hybrid pairing per CNSA 2.0.
        self._ml_dsa = MlDsaProvider(SignatureAlgorithm.ML_DSA_65)

    def sign(self, message: bytes, key: SignatureKeyPair) -> bytes:
        """
        Produce ``concat(u32_be(len(ml_dsa_sig)), ml_dsa_sig, ed25519_sig)``.

        TODO(P0): produce concat(ml_dsa_signature, ed25519_signature)
        """
        if key.algorithm is not SignatureAlgorithm.HYBRID_ML_DSA_ED25519:
            raise ValueError(
                f"HybridMlDsaEd25519Provider cannot sign with key for {key.algorithm.value}"
            )

        ml_dsa_priv, ed_priv_pem = _split_length_prefixed(
            key.private_key, label="hybrid private key"
        )

        # ML-DSA half: synthesize an inner ML-DSA-65 keypair object so the
        # MlDsaProvider's algorithm-tagged sign() works.
        inner_ml_dsa_key = SignatureKeyPair(
            algorithm=SignatureAlgorithm.ML_DSA_65,
            public_key=b"",  # not used for signing
            private_key=ml_dsa_priv,
            key_id=f"{key.key_id}/ml-dsa",
        )
        ml_dsa_sig = self._ml_dsa.sign(message, inner_ml_dsa_key)

        # Ed25519 half.
        ed_priv = serialization.load_pem_private_key(ed_priv_pem, password=None)
        if not isinstance(ed_priv, ed25519.Ed25519PrivateKey):
            raise ValueError("hybrid private key classical half is not Ed25519")
        ed_sig = ed_priv.sign(message)

        signature = _concat_length_prefixed(ml_dsa_sig, ed_sig)
        emit_event(
            "pqcrypto.hybrid.signed",
            algorithm=self.algorithm.value,
            layout_version=_HYBRID_LAYOUT_VERSION,
            key_id=key.key_id,
            message_bytes=len(message),
            signature_bytes=len(signature),
            ml_dsa_signature_bytes=len(ml_dsa_sig),
            ed25519_signature_bytes=len(ed_sig),
        )
        return signature

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """
        Verify both halves. Returns ``False`` if EITHER half fails.

        TODO(P0): split signature, require BOTH verifications to pass
        """
        try:
            ml_dsa_sig, ed_sig = _split_length_prefixed(
                signature, label="hybrid signature"
            )
            ml_dsa_pk, ed_pk_pem = _split_length_prefixed(
                public_key, label="hybrid public key"
            )
        except ValueError:
            return False

        ml_dsa_ok = self._ml_dsa.verify(message, ml_dsa_sig, ml_dsa_pk)

        try:
            ed_pub = serialization.load_pem_public_key(ed_pk_pem)
        except (ValueError, TypeError):
            ed_ok = False
        else:
            if not isinstance(ed_pub, ed25519.Ed25519PublicKey):
                ed_ok = False
            else:
                try:
                    ed_pub.verify(ed_sig, message)
                    ed_ok = True
                except InvalidSignature:
                    ed_ok = False

        ok = bool(ml_dsa_ok and ed_ok)
        emit_event(
            "pqcrypto.hybrid.verified",
            algorithm=self.algorithm.value,
            layout_version=_HYBRID_LAYOUT_VERSION,
            ok=ok,
            ml_dsa_ok=bool(ml_dsa_ok),
            ed25519_ok=bool(ed_ok),
            message_bytes=len(message),
            signature_bytes=len(signature),
        )
        return ok

    def generate_keypair(self, key_id: str | None = None) -> SignatureKeyPair:
        """
        Generate a fresh hybrid keypair (ML-DSA-65 + Ed25519).

        TODO(P0): produce concat-layout keypair where each component is
        independently algorithm-agile via algorithm_agility.
        """
        ml_dsa_kp = self._ml_dsa.generate_keypair(key_id=f"{key_id or 'hybrid'}/ml-dsa")

        ed_priv = ed25519.Ed25519PrivateKey.generate()
        ed_priv_pem = ed_priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        ed_pub_pem = ed_priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        public_key = _concat_length_prefixed(ml_dsa_kp.public_key, ed_pub_pem)
        private_key = _concat_length_prefixed(ml_dsa_kp.private_key, ed_priv_pem)
        resolved_id = key_id or f"hybrid-ml-dsa-65-ed25519-{uuid4().hex[:12]}"
        emit_event(
            "pqcrypto.hybrid.keygen",
            algorithm=self.algorithm.value,
            layout_version=_HYBRID_LAYOUT_VERSION,
            key_id=resolved_id,
            public_key_bytes=len(public_key),
            private_key_bytes=len(private_key),
        )
        return SignatureKeyPair(
            algorithm=SignatureAlgorithm.HYBRID_ML_DSA_ED25519,
            public_key=public_key,
            private_key=private_key,
            key_id=resolved_id,
        )

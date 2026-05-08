"""
Ed25519 (RFC 8032) signature provider.

Used as the classical half of the hybrid ML-DSA + Ed25519 transition mode
and as a standalone option in the algorithm-agility dispatcher. Stored
keys are PEM-encoded so on-disk and in-memory layouts match the ECDSA
provider in ``tex.events._ecdsa_provider``.

Reference
---------
- RFC 8032 (Edwards-Curve Digital Signature Algorithm)

Priority: P0 — the classical pair for the hybrid transition window.
"""

from __future__ import annotations

from uuid import uuid4

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from tex.pqcrypto.algorithm_agility import (
    SignatureAlgorithm,
    SignatureKeyPair,
)


class Ed25519Provider:
    """
    Ed25519 signing provider.

    Satisfies the ``SignatureProvider`` Protocol. Stateless and
    thread-safe — ``cryptography`` primitives are immutable.
    """

    algorithm: SignatureAlgorithm = SignatureAlgorithm.ED25519

    def sign(self, message: bytes, key: SignatureKeyPair) -> bytes:
        if key.algorithm is not SignatureAlgorithm.ED25519:
            raise ValueError(
                f"Ed25519Provider cannot sign with key for {key.algorithm.value}"
            )
        priv = serialization.load_pem_private_key(key.private_key, password=None)
        if not isinstance(priv, ed25519.Ed25519PrivateKey):
            raise ValueError("loaded key is not an Ed25519PrivateKey")
        return priv.sign(message)

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        try:
            pub = serialization.load_pem_public_key(public_key)
        except (ValueError, TypeError):
            return False
        if not isinstance(pub, ed25519.Ed25519PublicKey):
            return False
        try:
            pub.verify(signature, message)
        except InvalidSignature:
            return False
        return True

    def generate_keypair(self, key_id: str | None = None) -> SignatureKeyPair:
        priv = ed25519.Ed25519PrivateKey.generate()
        priv_pem = priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pub_pem = priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return SignatureKeyPair(
            algorithm=SignatureAlgorithm.ED25519,
            public_key=pub_pem,
            private_key=priv_pem,
            key_id=key_id or f"ed25519-{uuid4().hex[:12]}",
        )

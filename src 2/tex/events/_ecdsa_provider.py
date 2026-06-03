"""
ECDSA-P256 signature provider (default for the events ledger).

Implements the ``SignatureProvider`` Protocol from
``tex.pqcrypto.algorithm_agility``. Uses ``cryptography>=42``
(SECP256R1, SHA-256, DER-encoded signatures, PKCS8/PEM key serialization).

This is the default signing path for the events ledger today. When
liboqs ML-DSA-65 lands in Thread 4, the provider abstraction lets the
ledger swap algorithms without touching call sites.

Reference
---------
- NIST FIPS 186-5 (Digital Signature Standard, ECDSA over P-256)
- Mirrors the algorithm-agility pattern in tex.pqcrypto.algorithm_agility.

Priority: P0.

TODO(P1): swap to liboqs ML-DSA-65 once
  tex.pqcrypto.algorithm_agility.get_signature_provider returns a working
  ML-DSA provider (Thread 4).
"""

from __future__ import annotations

import os
from uuid import uuid4

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from tex.pqcrypto.algorithm_agility import (
    SignatureAlgorithm,
    SignatureKeyPair,
    SignatureProvider,
)


_CURVE = ec.SECP256R1()
_HASH = hashes.SHA256()


class EcdsaP256Provider:
    """
    ECDSA-P256 + SHA-256 signing provider.

    Satisfies the structural ``SignatureProvider`` protocol. Stored keys
    are PEM-encoded so the on-disk / in-memory representation is the same
    bytes that ``SignatureKeyPair`` carries.

    Thread-safe for ``sign``/``verify``: ``cryptography`` primitives are
    immutable and the provider holds no mutable state.
    """

    algorithm: SignatureAlgorithm = SignatureAlgorithm.ECDSA_P256

    def sign(self, message: bytes, key: SignatureKeyPair) -> bytes:
        """Sign ``message`` (raw bytes) with the private key in ``key``."""
        if key.algorithm is not SignatureAlgorithm.ECDSA_P256:
            raise ValueError(
                f"EcdsaP256Provider cannot sign with key for {key.algorithm}"
            )
        private_key = serialization.load_pem_private_key(
            key.private_key, password=None
        )
        if not isinstance(private_key, ec.EllipticCurvePrivateKey):
            raise ValueError("loaded key is not an EllipticCurvePrivateKey")
        return private_key.sign(message, ec.ECDSA(_HASH))

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """Verify ``signature`` over ``message`` against the PEM ``public_key``."""
        try:
            pub = serialization.load_pem_public_key(public_key)
        except (ValueError, TypeError):
            return False
        if not isinstance(pub, ec.EllipticCurvePublicKey):
            return False
        try:
            pub.verify(signature, message, ec.ECDSA(_HASH))
        except InvalidSignature:
            return False
        return True

    def generate_keypair(self, key_id: str | None = None) -> SignatureKeyPair:
        """Generate a fresh P-256 keypair. Caller may pass an opaque key_id."""
        private_key = ec.generate_private_key(_CURVE)
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return SignatureKeyPair(
            algorithm=SignatureAlgorithm.ECDSA_P256,
            public_key=public_pem,
            private_key=private_pem,
            key_id=key_id or f"ecdsa-p256-{uuid4().hex[:12]}",
        )


# Module-level provider for callers that don't want to instantiate.
_DEFAULT_PROVIDER = EcdsaP256Provider()


def default_signature_provider() -> SignatureProvider:
    """
    Return the ledger's default signature provider.

    Tries ``tex.pqcrypto.algorithm_agility.get_signature_provider(ECDSA_P256)``
    first; if that raises ``NotImplementedError`` (the current scaffolding
    behavior), falls back to the local ``EcdsaP256Provider``.

    The fallback exists so the events ledger is testable today without
    modifying ``tex/pqcrypto/`` (which is owned by the pqcrypto thread).
    Once Thread 4 lands and ``get_signature_provider`` returns a working
    ML-DSA provider, callers can pass that provider in directly via
    ``CryptoProvenance(signing_provider=...)``.
    """
    # NB: import inline to keep the module importable even if pqcrypto's
    # provider dispatcher gets noisy in the future.
    from tex.pqcrypto.algorithm_agility import (
        SignatureAlgorithm as _SignatureAlgorithm,
        get_signature_provider,
    )
    try:
        return get_signature_provider(_SignatureAlgorithm.ECDSA_P256)
    except NotImplementedError:
        return _DEFAULT_PROVIDER


def ml_dsa_not_yet_wired() -> SignatureProvider:
    """
    Stub entry point for ML-DSA. Always raises with a clear Thread 4 message.

    Acceptance criterion (d): ML-DSA path is a stub that raises cleanly.
    Callers should NOT use this — pass a concrete provider via
    ``CryptoProvenance(signing_provider=...)`` instead. This exists so a
    grep for ``ml_dsa`` in the events package surfaces a single, honest
    failure point rather than a silent fallback.
    """
    raise NotImplementedError(
        "ML-DSA signature provider not yet wired — Thread 4. "
        "Use default_signature_provider() (ECDSA-P256) until liboqs lands."
    )


def signature_algorithm_for(provider: SignatureProvider) -> SignatureAlgorithm:
    """Best-effort algorithm tag for telemetry / record metadata."""
    algo = getattr(provider, "algorithm", None)
    if isinstance(algo, SignatureAlgorithm):
        return algo
    # Default to ECDSA_P256 — the only path the events ledger currently ships.
    return SignatureAlgorithm.ECDSA_P256

"""
Algorithm-agile signature abstraction.

Per NIST SP 800-131A guidance: all new signing infrastructure must support
algorithm rotation via configuration, not code change.

The ``get_signature_provider`` dispatcher resolves a ``SignatureAlgorithm``
enum into a concrete provider instance. All providers satisfy the
structural ``SignatureProvider`` Protocol and may be swapped at config
time with no call-site changes.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Protocol, runtime_checkable


class SignatureAlgorithm(str, Enum):
    """Supported signature algorithms in priority order."""

    ML_DSA_44 = "ml-dsa-44"      # NIST Security Level 2
    ML_DSA_65 = "ml-dsa-65"      # NIST Security Level 3 (recommended default)
    ML_DSA_87 = "ml-dsa-87"      # NIST Security Level 5 (CNSA 2.0)
    SLH_DSA_128S = "slh-dsa-128s"  # Conservative hash-based fallback
    HYBRID_ML_DSA_ED25519 = "hybrid-ml-dsa-65-ed25519"  # Transition mode
    ED25519 = "ed25519"          # Legacy, deprecated post-2027
    ECDSA_P256 = "ecdsa-p256"    # Legacy, deprecated post-2027


@dataclass(frozen=True, slots=True)
class SignatureKeyPair:
    """A signature key pair tagged with its algorithm."""

    algorithm: SignatureAlgorithm
    public_key: bytes
    private_key: bytes
    key_id: str  # opaque identifier for HSM/keystore lookup


@runtime_checkable
class SignatureProvider(Protocol):
    """Pluggable signature provider for a single algorithm."""

    def sign(self, message: bytes, key: SignatureKeyPair) -> bytes:
        ...

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        ...

    def generate_keypair(self, key_id: str) -> SignatureKeyPair:
        ...


def get_signature_provider(algorithm: SignatureAlgorithm) -> SignatureProvider:
    """
    Return the configured provider for the given algorithm.

    Dispatch table:

    - ML-DSA-44 / 65 / 87  -> ``MlDsaProvider`` (FIPS 204 via liboqs)
    - HYBRID_ML_DSA_ED25519 -> ``HybridMlDsaEd25519Provider``
    - ED25519               -> ``Ed25519Provider`` (RFC 8032)
    - ECDSA_P256            -> ``EcdsaP256Provider`` (FIPS 186-5, from
                              ``tex.events._ecdsa_provider``)
    - SLH_DSA_128S          -> raises ``NotImplementedError`` (P1)

    Imports are lazy so this dispatcher is importable on machines where
    liboqs is not yet installed; the failure surface is moved to first
    use of the cryptographic methods on the returned provider.

    TODO(P0): wire to ml_dsa.MlDsaProvider once liboqs bindings land.
        - DONE: ML-DSA-44 / 65 / 87 dispatched to MlDsaProvider.
    TODO(P0): wire to hybrid.HybridMlDsaEd25519Provider for transition mode.
        - DONE: HYBRID_ML_DSA_ED25519 dispatched.
    TODO(P1): wire to slh_dsa.SlhDsaProvider for conservative-fallback paths.
        - Pending P1; SLH-DSA-128S still raises NotImplementedError per FIPS 205.
    """
    # ML-DSA family
    if algorithm in {
        SignatureAlgorithm.ML_DSA_44,
        SignatureAlgorithm.ML_DSA_65,
        SignatureAlgorithm.ML_DSA_87,
    }:
        from tex.pqcrypto.ml_dsa import MlDsaProvider

        return MlDsaProvider(parameter_set=algorithm)

    # Hybrid transition mode
    if algorithm is SignatureAlgorithm.HYBRID_ML_DSA_ED25519:
        from tex.pqcrypto.hybrid import HybridMlDsaEd25519Provider

        return HybridMlDsaEd25519Provider()

    # Ed25519 standalone
    if algorithm is SignatureAlgorithm.ED25519:
        from tex.pqcrypto._ed25519_provider import Ed25519Provider

        return Ed25519Provider()

    # ECDSA-P256 — owned by the events package per Thread 2.
    if algorithm is SignatureAlgorithm.ECDSA_P256:
        from tex.events._ecdsa_provider import EcdsaP256Provider

        return EcdsaP256Provider()

    # SLH-DSA — P1, still stubbed.
    if algorithm is SignatureAlgorithm.SLH_DSA_128S:
        raise NotImplementedError(
            "SLH-DSA-128S not yet wired (P1) — see FIPS 205 and tex.pqcrypto.slh_dsa"
        )

    raise NotImplementedError(f"No provider registered for algorithm: {algorithm}")

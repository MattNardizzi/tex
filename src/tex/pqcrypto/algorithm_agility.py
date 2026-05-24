"""
Algorithm-agile signature abstraction.

Per NIST SP 800-131A guidance: all new signing infrastructure must support
algorithm rotation via configuration, not code change.

The ``get_signature_provider`` dispatcher resolves a ``SignatureAlgorithm``
enum into a concrete provider instance. All providers satisfy the
structural ``SignatureProvider`` Protocol and may be swapped at config
time with no call-site changes.

Thread 10 update (May 18, 2026)
-------------------------------
Adds the full FIPS 205 family (SLH-DSA-128s / 128f / 192s / 256s), the
threshold ML-DSA path (Mithril, ePrint 2026/013; TALUS, arxiv 2603.22109),
and the composite ML-DSA path (draft-ietf-lamps-pq-composite-sigs-18).
Together these close every NIST-standardised PQ signature scheme plus
the most credible non-FIPS hedges that competitors (Microsoft Agent
Governance Toolkit, Asqav) have not yet implemented.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Protocol, runtime_checkable


class SignatureAlgorithm(str, Enum):
    """
    Supported signature algorithms.

    The order roughly corresponds to recommendation: ML-DSA-65 is the
    workhorse default; HYBRID is the transition default through 2030;
    CNSA 2.0 demands ML-DSA-87 + ML-KEM-1024 (see ``tex.pqcrypto.ml_kem``).
    """

    # FIPS 204 (ML-DSA / Dilithium)
    ML_DSA_44 = "ml-dsa-44"        # NIST Security Level 2
    ML_DSA_65 = "ml-dsa-65"        # NIST Security Level 3 (default)
    ML_DSA_87 = "ml-dsa-87"        # NIST Security Level 5 (CNSA 2.0)

    # Thread 8.1 (BLAKE3-accelerated ML-DSA per Project Eleven / Taurus)
    BLAKE3_ML_DSA_65 = "blake3-ml-dsa-65"

    # FIPS 205 (SLH-DSA / SPHINCS+)
    SLH_DSA_128S = "slh-dsa-128s"  # NIST L1, small/slow
    SLH_DSA_128F = "slh-dsa-128f"  # NIST L1, fast/large
    SLH_DSA_192S = "slh-dsa-192s"  # NIST L3
    SLH_DSA_256S = "slh-dsa-256s"  # NIST L5 (CNSA 2.0 code signing)

    # Threshold ML-DSA — TWO DISTINCT CONSTRUCTIONS
    # ============================================
    # THRESHOLD_ML_DSA_*  → Genuine MPC threshold signing per Mithril
    #   (ePrint 2026/013, USENIX Sec '26). Bit-for-bit FIPS 204 single
    #   signature output via the vendored Rust crate. Currently only
    #   ML-DSA-44 supported by upstream v0.3; L3/L5 will land in v0.4.
    #   See tex.pqcrypto.threshold_ml_dsa.
    THRESHOLD_ML_DSA_44 = "threshold-ml-dsa-44"  # Mithril MPC, FIPS 204 compatible
    THRESHOLD_ML_DSA_65 = "threshold-ml-dsa-65"  # reserved for Mithril v0.4
    THRESHOLD_ML_DSA_87 = "threshold-ml-dsa-87"  # reserved for Mithril v0.4

    # QUORUM_ML_DSA_*  → k-of-n verifiable quorum certificate over
    #   independent ML-DSA keys. NOT a single FIPS 204 signature; carries
    #   k partial signatures + descriptor commitment. No inter-signer
    #   coordination required, available at all three FIPS 204 NIST levels
    #   today. See tex.pqcrypto.quorum_ml_dsa.
    QUORUM_ML_DSA_44 = "quorum-ml-dsa-44"
    QUORUM_ML_DSA_65 = "quorum-ml-dsa-65"
    QUORUM_ML_DSA_87 = "quorum-ml-dsa-87"  # CNSA 2.0 quorum signing

    # Composite ML-DSA per draft-ietf-lamps-pq-composite-sigs-18 (Apr 9 2026).
    # Required for BSI 2021 / ANSSI 2024 jurisdictions that mandate PQ/T hybrid.
    COMPOSITE_ML_DSA_65_ED25519 = "composite-ml-dsa-65-ed25519"
    COMPOSITE_ML_DSA_87_ECDSA_P384 = "composite-ml-dsa-87-ecdsa-p384"

    # Transition + legacy
    HYBRID_ML_DSA_ED25519 = "hybrid-ml-dsa-65-ed25519"  # Thread 4 transition mode
    ED25519 = "ed25519"            # Legacy, deprecated post-2027
    ECDSA_P256 = "ecdsa-p256"      # Legacy, deprecated post-2027


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


_SLH_DSA_SET = frozenset({
    SignatureAlgorithm.SLH_DSA_128S,
    SignatureAlgorithm.SLH_DSA_128F,
    SignatureAlgorithm.SLH_DSA_192S,
    SignatureAlgorithm.SLH_DSA_256S,
})
_THRESHOLD_ML_DSA_SET = frozenset({
    SignatureAlgorithm.THRESHOLD_ML_DSA_44,
    SignatureAlgorithm.THRESHOLD_ML_DSA_65,
    SignatureAlgorithm.THRESHOLD_ML_DSA_87,
})
_QUORUM_ML_DSA_SET = frozenset({
    SignatureAlgorithm.QUORUM_ML_DSA_44,
    SignatureAlgorithm.QUORUM_ML_DSA_65,
    SignatureAlgorithm.QUORUM_ML_DSA_87,
})
_COMPOSITE_SET = frozenset({
    SignatureAlgorithm.COMPOSITE_ML_DSA_65_ED25519,
    SignatureAlgorithm.COMPOSITE_ML_DSA_87_ECDSA_P384,
})


def get_signature_provider(algorithm: SignatureAlgorithm) -> SignatureProvider:
    """
    Return the configured provider for the given algorithm.

    Dispatch table:

    - ML-DSA-44 / 65 / 87           -> ``MlDsaProvider`` (FIPS 204 via liboqs)
    - BLAKE3_ML_DSA_65              -> ``Blake3MlDsaProvider``
    - SLH-DSA-128s / 128f / 192s / 256s -> ``SlhDsaProvider`` (FIPS 205 via liboqs)
    - THRESHOLD_ML_DSA_44 / 65 / 87 -> ``ThresholdMlDsaProvider``
                                       (Mithril ePrint 2026/013)
    - COMPOSITE_ML_DSA_65_ED25519   -> ``CompositeMlDsaProvider``
                                       (draft-ietf-lamps-pq-composite-sigs-18)
    - COMPOSITE_ML_DSA_87_ECDSA_P384-> ``CompositeMlDsaProvider``
    - HYBRID_ML_DSA_ED25519         -> ``HybridMlDsaEd25519Provider``
    - ED25519                       -> ``Ed25519Provider`` (RFC 8032)
    - ECDSA_P256                    -> ``EcdsaP256Provider`` (from
                                       ``tex.events._ecdsa_provider``)

    Imports are lazy so this dispatcher is importable on machines where
    liboqs is not yet installed; the failure surface is moved to first use
    of the cryptographic methods on the returned provider.
    """
    # ML-DSA family
    if algorithm in {
        SignatureAlgorithm.ML_DSA_44,
        SignatureAlgorithm.ML_DSA_65,
        SignatureAlgorithm.ML_DSA_87,
    }:
        from tex.pqcrypto.ml_dsa import MlDsaProvider

        return MlDsaProvider(parameter_set=algorithm)

    # BLAKE3-accelerated ML-DSA (Thread 8.1, May 2026 frontier).
    if algorithm is SignatureAlgorithm.BLAKE3_ML_DSA_65:
        from tex.pqcrypto.blake3_ml_dsa import Blake3MlDsaProvider

        return Blake3MlDsaProvider(parameter_set=algorithm)

    # SLH-DSA family (Thread 10).
    if algorithm in _SLH_DSA_SET:
        from tex.pqcrypto.slh_dsa import SlhDsaProvider

        return SlhDsaProvider(parameter_set=algorithm)

    # Threshold ML-DSA via Mithril (Thread 10 follow-up).
    # Mithril produces a single FIPS 204 signature via 3-round MPC. It does
    # NOT fit the single-key SignatureProvider Protocol because there is no
    # single "key" — instead a ``MithrilThresholdSdk`` holds the n-party
    # share set. The dispatcher raises here with a redirect so callers
    # don't silently fall back to single-key signing.
    if algorithm in _THRESHOLD_ML_DSA_SET:
        raise NotImplementedError(
            f"{algorithm.value} is a genuine MPC threshold scheme — it does "
            f"not fit the single-key SignatureProvider Protocol. Use "
            f"tex.pqcrypto.threshold_ml_dsa.distributed_keygen() to obtain "
            f"a MithrilThresholdSdk and call .threshold_sign(active, msg) on "
            f"it. See tex.pqcrypto.threshold_ml_dsa for the full API."
        )

    # Quorum ML-DSA — k-of-n verifiable certificate (Thread 10).
    if algorithm in _QUORUM_ML_DSA_SET:
        from tex.pqcrypto.quorum_ml_dsa import QuorumMlDsaProvider

        return QuorumMlDsaProvider(parameter_set=algorithm)

    # Composite ML-DSA family (Thread 10).
    if algorithm in _COMPOSITE_SET:
        from tex.pqcrypto.composite_ml_dsa import CompositeMlDsaProvider

        return CompositeMlDsaProvider(parameter_set=algorithm)

    # Hybrid transition mode (Thread 4).
    if algorithm is SignatureAlgorithm.HYBRID_ML_DSA_ED25519:
        from tex.pqcrypto.hybrid import HybridMlDsaEd25519Provider

        return HybridMlDsaEd25519Provider()

    # Ed25519 standalone.
    if algorithm is SignatureAlgorithm.ED25519:
        from tex.pqcrypto._ed25519_provider import Ed25519Provider

        return Ed25519Provider()

    # ECDSA-P256 — owned by the events package per Thread 2.
    if algorithm is SignatureAlgorithm.ECDSA_P256:
        from tex.events._ecdsa_provider import EcdsaP256Provider

        return EcdsaP256Provider()

    raise NotImplementedError(f"No provider registered for algorithm: {algorithm}")

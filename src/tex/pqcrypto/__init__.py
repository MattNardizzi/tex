"""
[Architecture: Layer 5 (Evidence)] — post-quantum signing infrastructure — ML-DSA primary path via algorithm_agility, several extension modules carried for completeness

See ARCHITECTURE.md for the full six-layer model.

Post-Quantum Cryptography Layer
================================

Algorithm-agile signature, KEM, and hash-based signature primitives for the
Tex evidence chain and outbound content.

References
----------
- NIST FIPS 203 (ML-KEM, formerly CRYSTALS-Kyber) — finalized August 2024
- NIST FIPS 204 (ML-DSA, formerly CRYSTALS-Dilithium) — finalized August 2024
- NIST FIPS 205 (SLH-DSA, formerly SPHINCS+) — finalized August 2024
- NIST SP 800-208 (LMS / XMSS hash-based signatures)
- NSA CNSA 2.0 (Commercial National Security Algorithm Suite)

Threat model
------------
Defends against the "harvest now, decrypt later" (HNDL) class. The current
Tex evidence chain uses SHA-256 + ECDSA. ECDSA is vulnerable to Shor's
algorithm on a sufficiently large quantum computer (Q-Day, projected
2030-2035). Audit records signed today must remain verifiable in 2035+.

Priority
--------
P0 — drop-in ML-DSA replacement for ECDSA in evidence chain. Hybrid
ML-DSA + Ed25519 mode for transition.

"""

# Architectural layer marker (see ARCHITECTURE.md).
# Queryable as `from tex.pqcrypto import __layer__, __layer_kind__`.
__layer__: int | None = 5
__layer_kind__: str = 'evidence'

from tex.pqcrypto.algorithm_agility import (
    SignatureAlgorithm,
    SignatureKeyPair,
    SignatureProvider,
    get_signature_provider,
)

__all__ = [
    "SignatureAlgorithm",
    "SignatureKeyPair",
    "SignatureProvider",
    "get_signature_provider",
]

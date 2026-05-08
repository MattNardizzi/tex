"""
SLH-DSA (NIST FIPS 205) hash-based signature provider.

Conservative fallback for high-assurance applications where lattice-based
assumptions must be hedged. Slower and produces larger signatures than
ML-DSA but relies only on hash-function security.

Priority: P1 — used by `pqcrypto.code_signing` for Tex's own software releases
per NSA NIST SP 800-208 guidance.
"""

from __future__ import annotations


class SlhDsaProvider:
    """SLH-DSA signature provider per NIST FIPS 205."""

    def sign(self, message: bytes, private_key: bytes) -> bytes:
        # TODO(P1): bind to liboqs SPHINCS+ implementation
        raise NotImplementedError("FIPS 205 sign — bind liboqs")

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        # TODO(P1): bind to liboqs SPHINCS+ implementation
        raise NotImplementedError("FIPS 205 verify — bind liboqs")

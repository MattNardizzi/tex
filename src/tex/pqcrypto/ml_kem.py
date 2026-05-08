"""
ML-KEM (NIST FIPS 203) key encapsulation provider.

Used for hybrid TLS deployments and confidential session establishment
in interop layers (A2A, MCP-over-mTLS).

Priority: P2 — only needed when interop/TLS work begins.
"""

from __future__ import annotations


class MlKemProvider:
    """ML-KEM key encapsulation per NIST FIPS 203."""

    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
        # TODO(P2): returns (ciphertext, shared_secret)
        raise NotImplementedError("FIPS 203 encapsulate — bind liboqs")

    def decapsulate(self, ciphertext: bytes, private_key: bytes) -> bytes:
        # TODO(P2): returns shared_secret
        raise NotImplementedError("FIPS 203 decapsulate — bind liboqs")

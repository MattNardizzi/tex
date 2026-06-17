"""
``tex.verifier`` — the standalone sealed-verdict-bundle verifier.

A deliberately tiny, independent checker: it confirms a sealed bundle's hash
chain, its ECDSA (and optional ML-DSA) authorship against a pinned key, and the
monotonicity-witness property — depending only on the standard library and
``cryptography``, never the Tex decision engine. Run it as ``python -m
tex.verifier <bundle.json> --pubkey <key.pem>``.
"""

from __future__ import annotations

from tex.verifier.check import (
    MLDSA_AVAILABLE,
    WITNESS_KEY,
    VerificationReport,
    load_bundle,
    verify_bundle,
)

__all__ = [
    "VerificationReport",
    "verify_bundle",
    "load_bundle",
    "MLDSA_AVAILABLE",
    "WITNESS_KEY",
]

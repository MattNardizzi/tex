"""
Web Proofs (notarized TLS transcripts).

For black-box, secret-bearing API calls (the typical case for closed-model
inference), Web Proofs notarize the TLS session and produce a non-repudiable
transcript. Overhead typically <3x per the VET paper.

Implementation candidates: TLSNotary, Reclaim Protocol.

Priority: P2.
"""

from __future__ import annotations


def notarize_session(*, target_host: str, session_log: bytes) -> bytes:
    """
    TODO(P2): bind to TLSNotary or Reclaim
    """
    raise NotImplementedError("Web Proof notarization")


def verify_web_proof(proof: bytes, *, expected_target_host: str, expected_response_hash: str) -> bool:
    """
    TODO(P2): verify notary signature, check transcript hash
    """
    raise NotImplementedError("Web Proof verification")

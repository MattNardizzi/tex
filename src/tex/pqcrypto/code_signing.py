"""
LMS / XMSS hash-based code signing per NIST SP 800-208.

Used to sign Tex software releases and skill manifests. Hash-based signatures
are stateful — each signing key has a finite signing budget — but rely only
on hash-function security and are immediately deployable today (no waiting
on FIPS 206 / FALCON).

Priority: P1 — needed for skill-supply-chain integrity (OWASP Agentic Skills Top 10).
"""

from __future__ import annotations


def sign_release_artifact(artifact_path: str, key_id: str) -> bytes:
    # TODO(P1): bind to LMS implementation, manage state file for one-time keys
    raise NotImplementedError("LMS code signing per SP 800-208")


def verify_release_artifact(artifact_path: str, signature: bytes, public_key: bytes) -> bool:
    # TODO(P1): bind to LMS verify
    raise NotImplementedError("LMS code verify per SP 800-208")

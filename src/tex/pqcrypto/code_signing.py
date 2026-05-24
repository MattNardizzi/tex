"""
Post-quantum code signing for Tex software releases and skill manifests.

Backend selection (May 18, 2026 SOTA)
-------------------------------------
The original Thread 4 design called for LMS (stateful hash-based, NIST
SP 800-208 §4). LMS remains valid for firmware where state can be tracked
on a single signing appliance, but for general software / skill-manifest
signing the **stateless** hash-based primitive — SLH-DSA (FIPS 205) — is
the operationally simpler choice:

- **Stateless:** no one-time-key state file to corrupt, no signing-budget
  exhaustion risk.
- **CNSA 2.0 §2 (April 2026 update):** mandates SLH-DSA-256s for software
  and firmware signing in NSS deployments.
- **Microsoft Windows Insider Update Catalogue (March 2026):** ships
  SLH-DSA-128s signatures alongside the legacy RSA-PKCS#1 chain.
- **Linux kernel module signing (v16, Feb 2026):** added SLH-DSA-128s.

This module wraps ``tex.pqcrypto.slh_dsa.SlhDsaProvider`` with the
release-artifact / skill-manifest API. It accepts an ``algorithm``
parameter so callers can downshift to SLH-DSA-128s for lower per-signature
size cost when CNSA 2.0 compliance is not required.

Per-signature size budget (FIPS 205 §11)
----------------------------------------
- SLH-DSA-128s — 7 856 bytes  (default; OWASP Skills budget OK)
- SLH-DSA-128f — 17 088 bytes (faster sign, larger sig)
- SLH-DSA-192s — 16 224 bytes
- SLH-DSA-256s — 29 792 bytes (CNSA 2.0 §2 for NSS firmware)

References
----------
- NIST FIPS 205 (Aug 2024) — SLH-DSA.
- NSA CNSA 2.0 §2 (Apr 2026 update) — mandates SLH-DSA-256s for code.
- NIST SP 800-208 §4 — LMS (kept as a future-options reference).
- OWASP Agentic Skills Top 10 (Mar 2026) — supply-chain integrity.

Priority: P1.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from tex.observability.telemetry import emit_event
from tex.pqcrypto.algorithm_agility import (
    SignatureAlgorithm,
    SignatureKeyPair,
)
from tex.pqcrypto.slh_dsa import SlhDsaProvider


_DEFAULT_ALGORITHM: SignatureAlgorithm = SignatureAlgorithm.SLH_DSA_128S
_CNSA_2_ALGORITHM: SignatureAlgorithm = SignatureAlgorithm.SLH_DSA_256S

_VALID_ALGORITHMS: frozenset[SignatureAlgorithm] = frozenset(
    {
        SignatureAlgorithm.SLH_DSA_128S,
        SignatureAlgorithm.SLH_DSA_128F,
        SignatureAlgorithm.SLH_DSA_192S,
        SignatureAlgorithm.SLH_DSA_256S,
    }
)

# Domain-separator tag — distinguishes Tex code signatures from arbitrary
# SLH-DSA signatures so a release artifact signature cannot be replayed
# as a generic message signature (defense in depth).
_DOMAIN_SEPARATOR: bytes = b"tex.pqcrypto.code_signing/v1\x00"


@dataclass(frozen=True, slots=True)
class CodeSignature:
    """A bound code-signing artifact.

    ``signature`` is the SLH-DSA signature over ``digest`` of the
    artifact bytes, with the Tex domain separator prefix. ``digest`` is
    the SHA-256 hash of the file — included verbatim so a verifier can
    independently recompute it from the artifact bytes.
    """

    algorithm: SignatureAlgorithm
    digest_sha256: str
    signature: bytes
    public_key: bytes
    key_id: str


def _validate_algorithm(algorithm: SignatureAlgorithm) -> None:
    if algorithm not in _VALID_ALGORITHMS:
        raise ValueError(
            f"Not a code-signing algorithm: {algorithm.value!r}. "
            f"Valid: {sorted(a.value for a in _VALID_ALGORITHMS)}"
        )


def _hash_file(artifact_path: str | os.PathLike[str]) -> tuple[str, bytes]:
    """Return ``(hex_digest, message_to_sign)`` for ``artifact_path``.

    ``message_to_sign`` is the domain-separated digest, NOT the raw file
    bytes — SLH-DSA is fast enough to sign large messages but pre-hashing
    keeps the API predictable and the per-call cost flat.
    """
    h = hashlib.sha256()
    p = Path(artifact_path)
    if not p.is_file():
        raise FileNotFoundError(f"artifact not found: {p}")
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    digest = h.digest()
    return digest.hex(), _DOMAIN_SEPARATOR + digest


def sign_release_artifact(
    artifact_path: str | os.PathLike[str],
    *,
    signing_key: SignatureKeyPair,
    algorithm: SignatureAlgorithm | None = None,
) -> CodeSignature:
    """Produce a post-quantum code signature for a release artifact.

    Parameters
    ----------
    artifact_path
        Path to the artifact bytes (binary, archive, JSON skill
        manifest, etc.).
    signing_key
        SLH-DSA signing key. Must match ``algorithm`` if explicitly
        passed. The key MUST have been produced by
        ``SlhDsaProvider(algorithm).generate_keypair()`` — Tex never
        re-imports keys from disk for code signing (the OWASP Agentic
        Skills guidance treats key-material-on-disk as a P0 audit
        finding).
    algorithm
        Override the algorithm. Defaults to ``signing_key.algorithm``;
        if both are set they must agree.

    Raises
    ------
    ValueError
        Algorithm mismatch or unsupported algorithm.
    FileNotFoundError
        Artifact path not readable.
    """
    resolved_algorithm = algorithm or signing_key.algorithm
    _validate_algorithm(resolved_algorithm)
    if signing_key.algorithm is not resolved_algorithm:
        raise ValueError(
            f"signing_key.algorithm ({signing_key.algorithm.value}) does not "
            f"match requested algorithm ({resolved_algorithm.value})"
        )

    digest_hex, message = _hash_file(artifact_path)
    provider = SlhDsaProvider(resolved_algorithm)
    signature = provider.sign(message, signing_key)

    emit_event(
        "pqcrypto.code_signing.signed",
        algorithm=resolved_algorithm.value,
        artifact_path=str(artifact_path),
        digest_sha256=digest_hex,
        signature_bytes=len(signature),
        key_id=signing_key.key_id,
    )
    return CodeSignature(
        algorithm=resolved_algorithm,
        digest_sha256=digest_hex,
        signature=signature,
        public_key=signing_key.public_key,
        key_id=signing_key.key_id,
    )


def verify_release_artifact(
    artifact_path: str | os.PathLike[str],
    *,
    signature: CodeSignature,
) -> bool:
    """Verify a code signature against the artifact bytes.

    Returns ``False`` for any failure (algorithm mismatch, digest
    mismatch, signature mismatch). Logs the failure reason via
    ``pqcrypto.code_signing.verify_failed`` so operators can
    distinguish tampering from configuration error.
    """
    try:
        _validate_algorithm(signature.algorithm)
    except ValueError as exc:
        emit_event(
            "pqcrypto.code_signing.verify_failed",
            reason="invalid_algorithm",
            detail=str(exc),
        )
        return False

    try:
        digest_hex, message = _hash_file(artifact_path)
    except FileNotFoundError as exc:
        emit_event(
            "pqcrypto.code_signing.verify_failed",
            reason="artifact_unreadable",
            detail=str(exc),
        )
        return False

    if digest_hex != signature.digest_sha256:
        emit_event(
            "pqcrypto.code_signing.verify_failed",
            reason="digest_mismatch",
            artifact_digest=digest_hex,
            signature_digest=signature.digest_sha256,
        )
        return False

    provider = SlhDsaProvider(signature.algorithm)
    ok = provider.verify(message, signature.signature, signature.public_key)
    if not ok:
        emit_event(
            "pqcrypto.code_signing.verify_failed",
            reason="signature_invalid",
            algorithm=signature.algorithm.value,
            key_id=signature.key_id,
        )
        return False

    emit_event(
        "pqcrypto.code_signing.verified",
        algorithm=signature.algorithm.value,
        digest_sha256=digest_hex,
        key_id=signature.key_id,
    )
    return True


def recommended_algorithm(*, cnsa_2_required: bool = False) -> SignatureAlgorithm:
    """Pick the SLH-DSA parameter set for a given posture.

    CNSA 2.0 §2 mandates SLH-DSA-256s for NSS firmware. For
    general-purpose Tex skill / release signing the smaller
    SLH-DSA-128s is the default — same hash-function security
    foundation, ~4x smaller signatures.
    """
    return _CNSA_2_ALGORITHM if cnsa_2_required else _DEFAULT_ALGORITHM


__all__ = (
    "CodeSignature",
    "recommended_algorithm",
    "sign_release_artifact",
    "verify_release_artifact",
)

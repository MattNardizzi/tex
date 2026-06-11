"""
[Architecture: Layer 5 (Evidence)] — the post-quantum seal over the chain.

This module activates the previously-scaffolded post-quantum signing path
(``tex.pqcrypto.evidence_chain_signer`` + ``tex.pqcrypto.algorithm_agility``)
on the LIVE evidence chain. It is the wire that makes "sealed by a named
human act the evidence layer can prove" literally true: the seal an operator
reaches for now carries a composite ML-DSA-65 + Ed25519 signature that anyone
holding the record can verify independently, with no call back to Tex.

Design choices (and why)
------------------------
1. **Embedded, self-verifying signature.** The ``EvidenceRecord`` domain model
   is ``frozen`` with ``extra="forbid"`` — we cannot add a ``signature`` column
   without rewriting the chain format and every test that constructs a record.
   So the signature rides INSIDE the record payload under the reserved
   ``pq_signature`` key. The recorder's hash chain then commits to the payload
   *including* the signature, while the signature itself is taken over the
   payload *excluding* that key (non-circular, standard detached-then-embed).
   The block carries its own ``public_key_b64`` so the seal is verifiable by a
   third party from the record alone — exactly the "handle you walk away with"
   doctrine.

2. **Float-safe canonicalization.** Decision payloads carry float risk scores.
   The events-ledger canonicalizer (``tex.events._canonical.canonical_json``,
   RFC 8785) deliberately rejects floats. So we sign over the SAME canonical
   digest the hash chain already uses — ``_stable_json`` (sorted-key compact
   JSON) hashed with SHA-256 — keeping the signed bytes byte-consistent with
   what the chain hashes and sidestepping the float restriction. The actual
   cryptography is still dispatched through ``algorithm_agility`` so algorithm
   swaps (ML-DSA-65 → 87, composite → hybrid) need no change here.

3. **Honest fallback, never a mislabel.** The composite path needs an ML-DSA
   backend (pyca/cryptography >= 48 with OpenSSL >= 3.5, or liboqs). When that
   backend is absent, ``build_evidence_chain_signer`` falls back to ECDSA-P256
   and logs loudly — and the ``pq_signature.algorithm`` field then reads
   ``ecdsa-p256``, never ``composite-ml-dsa-65-ed25519``. A signature is always
   labelled with the algorithm that actually produced it. To get the real
   post-quantum seal in production, ensure the ML-DSA backend is present; the
   wiring upgrades automatically with zero code change (algorithm agility).

Production note: the signing key here is generated and persisted to disk on
first use. A real deployment should inject an HSM / KMS-backed key by passing a
pre-built ``SignatureKeyPair`` (so the public key is stable across redeploys);
the per-record embedded public key makes even an ephemeral key's signatures
verifiable, but a stable key is what an external auditor expects.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from tex.pqcrypto.algorithm_agility import (
    SignatureAlgorithm,
    SignatureKeyPair,
    get_signature_provider,
)
from tex.selfgov.governor import describe_key_mutation, gate_controller_mutation

_logger = logging.getLogger(__name__)

# Reserved payload key for the embedded signature. Excluded from the signed
# bytes on both sign and verify paths (see _signing_digest).
PQ_SIGNATURE_FIELD: str = "pq_signature"

# Layout version for the embedded block, so a future format change is
# detectable by verifiers rather than silently mis-parsed.
_LAYOUT_VERSION: str = "1"

# Preferred and fallback algorithms. Composite is the headline post-quantum
# claim; ECDSA-P256 is the honest classical fallback when no ML-DSA backend is
# installed. Both are dispatched through algorithm_agility.
_PREFERRED_ALGORITHM: SignatureAlgorithm = SignatureAlgorithm.COMPOSITE_ML_DSA_65_ED25519
_FALLBACK_ALGORITHM: SignatureAlgorithm = SignatureAlgorithm.ECDSA_P256


def _stable_json(value: Any) -> str:
    """Sorted-key compact JSON — the chain's own canonical form (float-safe)."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _signing_digest(payload: dict[str, Any]) -> bytes:
    """
    SHA-256 over the canonical JSON of ``payload`` with the embedded
    ``pq_signature`` field removed. This is the message the provider signs and
    verifies; stripping the signature field makes sign-then-embed non-circular
    and lets a verifier pass the record with or without the block attached.
    """
    stripped = {k: v for k, v in payload.items() if k != PQ_SIGNATURE_FIELD}
    canonical = _stable_json(stripped).encode("utf-8")
    return hashlib.sha256(canonical).digest()


@dataclass(frozen=True, slots=True)
class EvidenceChainSigner:
    """
    Holds the active signing key and produces the embedded ``pq_signature``
    block for an evidence payload. Stateless beyond the key; safe to share.
    """

    key: SignatureKeyPair

    @property
    def algorithm(self) -> SignatureAlgorithm:
        return self.key.algorithm

    @property
    def is_post_quantum(self) -> bool:
        """True only when the active algorithm includes an ML-DSA component."""
        return "ml-dsa" in self.key.algorithm.value

    def sign_payload(self, payload: dict[str, Any]) -> dict[str, Any]:
        """
        Return the ``pq_signature`` block for ``payload``. The block is
        self-describing and self-verifying: it carries the algorithm actually
        used, the signing key's public bytes, the signed digest, and the time.
        """
        digest = _signing_digest(payload)
        provider = get_signature_provider(self.key.algorithm)
        signature = provider.sign(digest, self.key)
        return {
            "layout": _LAYOUT_VERSION,
            "algorithm": self.key.algorithm.value,
            "key_id": self.key.key_id,
            "signature_b64": base64.b64encode(signature).decode("ascii"),
            "public_key_b64": base64.b64encode(self.key.public_key).decode("ascii"),
            "signed_digest_sha256": digest.hex(),
            "signed_at": datetime.now(UTC).isoformat(),
        }


def verify_payload_signature(payload: dict[str, Any]) -> bool:
    """
    Verify the embedded ``pq_signature`` block on ``payload``, using only the
    record itself (the block carries the public key). Returns False on any
    failure — a missing block, a digest mismatch (tamper), a malformed
    signature, or an invalid signature — and never raises. This is the
    third-party verification path: hand it a sealed record and nothing else.
    """
    block = payload.get(PQ_SIGNATURE_FIELD)
    if not isinstance(block, dict):
        return False
    try:
        algorithm = SignatureAlgorithm(block["algorithm"])
        signature = base64.b64decode(block["signature_b64"], validate=True)
        public_key = base64.b64decode(block["public_key_b64"], validate=True)
        claimed_digest = block.get("signed_digest_sha256")
    except (KeyError, ValueError, TypeError):
        return False

    digest = _signing_digest(payload)
    # The block claims which digest was signed; if the record was altered the
    # recomputed digest won't match, which is a tamper signal independent of
    # the signature math.
    if claimed_digest is not None and claimed_digest != digest.hex():
        return False

    try:
        provider = get_signature_provider(algorithm)
        return bool(provider.verify(digest, signature, public_key))
    except (NotImplementedError, RuntimeError, Exception):  # noqa: BLE001
        return False


def _key_path(key_dir: str | Path) -> Path:
    return Path(key_dir) / "evidence_seal_key.json"


def _load_key(path: Path) -> SignatureKeyPair | None:
    if not path.exists():
        return None
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        return SignatureKeyPair(
            algorithm=SignatureAlgorithm(raw["algorithm"]),
            public_key=base64.b64decode(raw["public_key_b64"]),
            private_key=base64.b64decode(raw["private_key_b64"]),
            key_id=raw["key_id"],
        )
    except Exception as exc:  # noqa: BLE001
        _logger.warning("evidence seal: failed to load persisted key (%s); regenerating", exc)
        return None


def _persist_key(path: Path, key: SignatureKeyPair) -> None:
    if not gate_controller_mutation(lambda: describe_key_mutation("evidence.seal._persist_key", key_id=key.key_id)).allowed:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "algorithm": key.algorithm.value,
                "key_id": key.key_id,
                "public_key_b64": base64.b64encode(key.public_key).decode("ascii"),
                "private_key_b64": base64.b64encode(key.private_key).decode("ascii"),
            }
        ),
        encoding="utf-8",
    )


def build_evidence_chain_signer(
    *,
    key_dir: str | Path = "var/tex/keys",
    key_id: str = "evidence-seal-key-v1",
    preferred_algorithm: SignatureAlgorithm = _PREFERRED_ALGORITHM,
    fallback_algorithm: SignatureAlgorithm = _FALLBACK_ALGORITHM,
) -> EvidenceChainSigner:
    """
    Build the live evidence-chain signer, never raising.

    Loads a persisted key if present; otherwise tries to generate a
    ``preferred_algorithm`` (composite ML-DSA-65 + Ed25519) key. If the ML-DSA
    backend is unavailable, falls back to ``fallback_algorithm`` (ECDSA-P256)
    and logs the downgrade loudly — the produced signatures are then honestly
    labelled with the classical algorithm, never the post-quantum one.
    """
    path = _key_path(key_dir)

    loaded = _load_key(path)
    if loaded is not None:
        signer = EvidenceChainSigner(key=loaded)
        if signer.is_post_quantum:
            _logger.info("evidence seal: post-quantum chain signer active (%s)", loaded.algorithm.value)
        else:
            _logger.warning(
                "evidence seal: chain signer active with CLASSICAL algorithm %s "
                "(no post-quantum guarantee). Install an ML-DSA backend "
                "(cryptography>=48 + OpenSSL>=3.5, or liboqs) and remove the "
                "persisted key to upgrade.",
                loaded.algorithm.value,
            )
        return signer

    for algorithm in (preferred_algorithm, fallback_algorithm):
        try:
            provider = get_signature_provider(algorithm)
            key = provider.generate_keypair(key_id)
        except (NotImplementedError, RuntimeError) as exc:
            _logger.warning(
                "evidence seal: %s unavailable (%s); trying next algorithm",
                algorithm.value,
                exc,
            )
            continue
        except Exception as exc:  # noqa: BLE001
            _logger.warning(
                "evidence seal: %s keygen failed unexpectedly (%s); trying next",
                algorithm.value,
                exc,
            )
            continue

        try:
            _persist_key(path, key)
        except Exception as exc:  # noqa: BLE001
            _logger.warning("evidence seal: could not persist key (%s); using in-memory key", exc)

        signer = EvidenceChainSigner(key=key)
        if signer.is_post_quantum:
            _logger.info(
                "evidence seal: post-quantum chain signer active (%s)", algorithm.value
            )
        else:
            _logger.warning(
                "evidence seal: ML-DSA backend not present — evidence chain "
                "signing with CLASSICAL %s. Signatures are honestly labelled "
                "as such. Install cryptography>=48 (OpenSSL>=3.5) or liboqs to "
                "activate the post-quantum composite seal with no code change.",
                algorithm.value,
            )
        return signer

    # Should be unreachable: ECDSA-P256 has no exotic backend dependency.
    raise RuntimeError("evidence seal: no signature provider could be constructed")

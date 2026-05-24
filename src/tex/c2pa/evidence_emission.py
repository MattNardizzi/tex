"""
Evidence emission orchestrator — Thread 5 wiring layer.
======================================================

Connects the C2PA signer (outer COSE_Sign1, classical algorithm,
spec-conformant) with the Tex evidence cosign (post-quantum
ML-DSA-65 by default, defending against the six attack classes in
arxiv 2604.24890).

Output contract
---------------
Given an outbound artifact, a verdict id, and the routing context
needed to identify the calling tenant + model, ``emit_c2pa_manifest``
returns a fully-signed ``C2paManifest`` ready to be:

  1. embedded in the outbound asset (or stored at its
     cloud-manifest URL), AND
  2. hash-anchored into the Tex evidence chain (the caller does the
     anchoring inside ``EvidenceRecorder.record_decision``).

The cosign signature is computed over a deterministic, canonical-
JSON serialization of the assertion fields EXCLUDING the
``signature``, ``public_key`` and ``defends_against`` fields. That
gives us a stable signing input independent of how a downstream
validator orders or reflects the assertion's data dict.

Default cosign algorithm
------------------------
``ML_DSA_65`` (FIPS 204) — post-quantum, NIST Security Level 3.
Falls back to ``ED25519`` if the operational keystore does not
expose an ML-DSA key (e.g. a CI environment without liboqs). The
fallback emits an explicit ``algorithm`` field so verifiers know
which provider to use, and `tex.observability.telemetry.emit_event`
records the degradation.

References
----------
- arxiv 2604.24890 (Apr 27 2026) — six C2PA attack classes
- C2PA 2.4 §13.2 (outer signature algorithm allow-list)
- draft-ietf-cose-dilithium-11 (Nov 15 2025) — COSE codepoint TBD
- NIST FIPS 204 (ML-DSA, finalised Aug 2024)
- EU AI Act Article 50 Draft Guidelines (May 8 2026, AI Office) —
  para 28, 54, 64, 81, 140 in scope; see FRONTIER_DELTA_thread_5.md.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any

from tex.c2pa._canonical_claim import canonical_claim_cbor
from tex.c2pa.cosign_context_tree import (
    COSIGN_CANONICALIZATION_VERSION_V2,
    canonical_cosign_signing_input_v2,
)
from tex.c2pa.manifest import (
    ASSERTION_LABEL_TEX_EVIDENCE_COSIGN,
    C2paAssertion,
    C2paManifest,
    attach_cosign_assertion,
    build_tex_evidence_cosign_assertion,
)
from tex.c2pa.signer import sign_manifest
from tex.observability.telemetry import emit_event
from tex.pqcrypto.algorithm_agility import (
    SignatureAlgorithm,
    SignatureKeyPair,
    get_signature_provider,
)


_logger = logging.getLogger(__name__)


# Canonicalization version string for ``tex.evidence_cosign``. Bumped
# only on a wire-incompatible change to the signing input
# construction. Two manifests with the same canonicalization_version
# are guaranteed by this code to either both verify or both fail under
# the same key — closing the cross-validator contradiction attack
# (arxiv 2604.24890 attack #3).
#
# v1: Thread 5, flat JSON document signing input.
# v2: Thread 6, Merkle context tree (CPSA-checked, supports
#     selective-disclosure proofs via tex.c2pa.cosign_context_tree).
COSIGN_CANONICALIZATION_VERSION: str = COSIGN_CANONICALIZATION_VERSION_V2
COSIGN_CANONICALIZATION_VERSION_V1: str = "tex.evidence_cosign/v1"

# The default cosign algorithm. ML-DSA-65 is post-quantum (NIST FIPS 204)
# and is the algorithm the prompt explicitly named. Falls back to Ed25519
# only when no ML-DSA key is available in the operational keystore.
DEFAULT_COSIGN_ALGORITHM: SignatureAlgorithm = SignatureAlgorithm.ML_DSA_65
FALLBACK_COSIGN_ALGORITHM: SignatureAlgorithm = SignatureAlgorithm.ED25519


class CosignError(RuntimeError):
    """Raised when the Tex evidence cosign cannot be produced."""


def _canonical_cosign_signing_input(
    *,
    bound_timestamp: str,
    full_file_sha256: str,
    canonicalization_version: str,
    retention_anchor: dict[str, Any],
    revocation_proof: dict[str, Any] | None,
    cosign_algorithm: str,
    cosign_key_id: str,
) -> bytes:
    """
    Build the byte string the cosign signs over.

    Dispatches on ``canonicalization_version``:

      * ``tex.evidence_cosign/v1`` — Thread 5, flat JSON document.
        Preserved for backward compatibility with manifests issued
        between May 18, 2026 and the Thread 6 cut-over.

      * ``tex.evidence_cosign/v2`` — Thread 6, Merkle context tree
        over seven typed leaves. The signed input is the 32-byte
        Merkle root. CPSA-checked
        (``cpsa_models/tex_cosign_v2.scm``).

    See ``tex.c2pa.cosign_context_tree`` for the v2 leaf layout and
    the Merkle inclusion proof helpers.

    Design note (one-directional binding)
    -------------------------------------
    The cosign binding is one-directional: the outer COSE_Sign1
    signature covers the cosign assertion (the assertion lives
    inside the claim, and the outer signs the canonical claim
    CBOR). The cosign does NOT bind the outer signature value —
    doing so would be self-referential (signing the outer means
    the outer signs the cosign means the cosign signs the outer).

    What the cosign signs in both versions:

      - the trusted timestamp (arxiv 2604.24890 attack #1)
      - the full-file hash (attack #4)
      - the canonicalization version (attack #3)
      - the retention anchor (attack #5)
      - the revocation proof (attack #2)
      - the cosign algorithm and key id (binding context)
    """
    if canonicalization_version == COSIGN_CANONICALIZATION_VERSION_V2:
        return canonical_cosign_signing_input_v2(
            bound_timestamp=bound_timestamp,
            full_file_sha256=full_file_sha256,
            canonicalization_version=canonicalization_version,
            retention_anchor=retention_anchor,
            revocation_proof=revocation_proof,
            cosign_algorithm=cosign_algorithm,
            cosign_key_id=cosign_key_id,
        )
    # v1 fallback: flat JSON. Preserved for backward compatibility.
    doc: dict[str, Any] = {
        "schema": "tex.evidence_cosign.signing_input/v1",
        "algorithm": cosign_algorithm,
        "key_id": cosign_key_id,
        "bound_timestamp": bound_timestamp,
        "full_file_sha256": full_file_sha256,
        "canonicalization_version": canonicalization_version,
        "retention_anchor": retention_anchor,
        "revocation_proof": revocation_proof if revocation_proof is not None else {},
    }
    return json.dumps(
        doc,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _select_cosign_key(
    cosign_keys: dict[str, SignatureKeyPair],
) -> SignatureKeyPair:
    """
    Pick the strongest available cosign key from ``cosign_keys``.

    Preference order: ML-DSA-87 > ML-DSA-65 > ML-DSA-44 >
    HYBRID_ML_DSA_ED25519 > ED25519. ECDSA-P256 is intentionally
    NOT a fallback for the cosign — the cosign exists specifically
    to provide post-quantum coverage; falling back to ECDSA defeats
    the purpose.
    """
    preference: tuple[SignatureAlgorithm, ...] = (
        SignatureAlgorithm.ML_DSA_87,
        SignatureAlgorithm.ML_DSA_65,
        SignatureAlgorithm.ML_DSA_44,
        SignatureAlgorithm.HYBRID_ML_DSA_ED25519,
        SignatureAlgorithm.ED25519,
    )
    by_algo: dict[SignatureAlgorithm, SignatureKeyPair] = {
        key.algorithm: key for key in cosign_keys.values()
    }
    for algo in preference:
        if algo in by_algo:
            return by_algo[algo]
    raise CosignError(
        "No cosign key available — install at least an Ed25519 key in the "
        "cosign keystore (preferred: ML-DSA-65). The cosign keystore is "
        "separate from the outer C2PA signing keystore."
    )


def build_signed_manifest_with_cosign(
    *,
    unsigned_manifest: C2paManifest,
    outer_signing_key_id: str,
    outer_certificate_chain_pem: str,
    cosign_key: SignatureKeyPair,
    outbound_artifact_bytes: bytes,
    bound_timestamp: datetime | None = None,
    retention_anchor: dict[str, Any],
    revocation_proof: dict[str, Any] | None = None,
    canonicalization_version: str = COSIGN_CANONICALIZATION_VERSION,
    extra_assertions: tuple[C2paAssertion, ...] = (),
) -> C2paManifest:
    """
    Produce a fully-signed manifest with both the outer COSE_Sign1
    and the inner ``tex.evidence_cosign`` assertion.

    Thread 6: optional ``extra_assertions`` are appended to the claim
    before the cosign is computed, so the outer signature covers
    them. Use this to attach ``tex.evidence_watermark``,
    ``tex.evidence_attestation``, and ``tex.formal_verification``
    assertions in one signing pass.

    The cosign signs a stable canonical form of the bound fields —
    flat JSON for ``tex.evidence_cosign/v1``, Merkle root for
    ``tex.evidence_cosign/v2`` (default). The cosign assertion is
    then appended to the claim, and the outer signature is computed
    over the full claim CBOR (which includes the cosign assertion +
    all extras). One signing pass per layer, no self-reference.

    Cost: ~3 ms (outer ECDSA / Ed25519) + ~1 ms (cosign Ed25519 /
    ML-DSA) + O(extras) hashing.
    """
    if not outbound_artifact_bytes:
        raise ValueError("outbound_artifact_bytes must not be empty")

    resolved_ts = (bound_timestamp or datetime.now(tz=timezone.utc)).isoformat()
    full_file_hash = hashlib.sha256(outbound_artifact_bytes).hexdigest()

    # Compute cosign signature over the bound fields — independent of
    # the outer signature value (avoids self-reference).
    provider = get_signature_provider(cosign_key.algorithm)
    signing_input = _canonical_cosign_signing_input(
        bound_timestamp=resolved_ts,
        full_file_sha256=full_file_hash,
        canonicalization_version=canonicalization_version,
        retention_anchor=retention_anchor,
        revocation_proof=revocation_proof,
        cosign_algorithm=cosign_key.algorithm.value,
        cosign_key_id=cosign_key.key_id,
    )
    cosign_signature = provider.sign(signing_input, cosign_key)

    cosign_assertion = build_tex_evidence_cosign_assertion(
        cosign_algorithm=cosign_key.algorithm.value,
        cosign_signature_b64=base64.b64encode(cosign_signature).decode("ascii"),
        cosign_public_key_b64=base64.b64encode(cosign_key.public_key).decode("ascii"),
        cosign_key_id=cosign_key.key_id,
        bound_timestamp=resolved_ts,
        full_file_sha256=full_file_hash,
        canonicalization_version=canonicalization_version,
        retention_anchor=retention_anchor,
        revocation_proof=revocation_proof,
    )

    # Append Thread 6 extension assertions (watermark, attestation,
    # formal verification) before the cosign, so the assertion order
    # is: spec-conformant (actions, cawg, verdict) → Tex extensions
    # (watermark, attestation, formal_verification) → cosign last.
    augmented = unsigned_manifest
    if extra_assertions:
        new_assertions = (
            *augmented.claim.assertions,
            *extra_assertions,
        )
        augmented = augmented.model_copy(
            update={"claim": augmented.claim.model_copy(update={"assertions": new_assertions})}
        )
    augmented = attach_cosign_assertion(augmented, cosign_assertion)

    # Outer signature: signs the full claim CBOR (which now includes
    # the cosign assertion AND any extras). This is the only outer
    # signing pass — every Thread-6 extension is INSIDE the data the
    # outer covers, so tampering with any of them breaks the outer
    # signature.
    final = sign_manifest(
        augmented,
        signing_key_id=outer_signing_key_id,
        certificate_chain_pem=outer_certificate_chain_pem,
    )

    emit_event(
        "c2pa.manifest.signed_with_cosign",
        outer_signing_key_id=outer_signing_key_id,
        cosign_algorithm=cosign_key.algorithm.value,
        cosign_key_id=cosign_key.key_id,
        full_file_sha256=full_file_hash,
        outbound_artifact_bytes=len(outbound_artifact_bytes),
        canonicalization_version=canonicalization_version,
        extra_assertion_labels=[a.label for a in extra_assertions],
    )
    return final


def cosign_manifest_hash(manifest: C2paManifest) -> str:
    """
    Compute the SHA-256 hex digest of the manifest's canonical
    claim CBOR. This is the value embedded in the Tex evidence
    record under ``c2pa.manifest_hash`` so an auditor can resolve a
    decision row back to its manifest in the ``evidence_manifests``
    table.
    """
    payload = canonical_claim_cbor(manifest.claim)
    return hashlib.sha256(payload).hexdigest()


def serialize_manifest_for_storage(manifest: C2paManifest) -> dict[str, Any]:
    """
    Serialize the manifest into a JSON-safe dict for the Postgres
    ``evidence_manifests`` table. The CBOR claim bytes are
    base64-encoded under the ``claim_cbor_b64`` field; the outer
    COSE_Sign1 envelope is the manifest's ``signature_b64`` (already
    base64) and is preserved verbatim.
    """
    if manifest.signature_b64 is None:
        raise ValueError(
            "Cannot serialize an unsigned manifest for storage. Call "
            "build_signed_manifest_with_cosign first."
        )
    claim_cbor = canonical_claim_cbor(manifest.claim)
    return {
        "schema": "tex.evidence_manifests/v1",
        "claim_cbor_b64": base64.b64encode(claim_cbor).decode("ascii"),
        "claim_sha256": hashlib.sha256(claim_cbor).hexdigest(),
        "outer_signature_b64": manifest.signature_b64,
        "certificate_chain_pem": manifest.certificate_chain_pem,
        "title": manifest.claim.title,
        "format": manifest.claim.format,
        "instance_id": manifest.claim.instance_id,
        "claim_generator": manifest.claim.claim_generator,
        "assertion_labels": [a.label for a in manifest.claim.assertions],
        "has_cosign": any(
            a.label == ASSERTION_LABEL_TEX_EVIDENCE_COSIGN
            for a in manifest.claim.assertions
        ),
    }


def get_cosign_assertion(manifest: C2paManifest) -> dict[str, Any] | None:
    """Return the ``tex.evidence_cosign`` assertion data, if present."""
    for assertion in manifest.claim.assertions:
        if assertion.label == ASSERTION_LABEL_TEX_EVIDENCE_COSIGN:
            return dict(assertion.data)
    return None

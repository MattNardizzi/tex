"""
Insurer-Verifiable Evidence Packet.

Produces a single, host-independently-verifiable artifact for insurers,
auditors, and regulators. Combines:

  - signed audit chain slice (ML-DSA / hybrid / ECDSA, algorithm-agile)
  - C2PA manifests for outbound AI content (one per send)
  - HMAC tool receipts (NabaOS pattern) for every tool call
  - period metadata bound by signature

The verifier:
  - Cannot tamper (the packet manifest is signed)
  - Host cannot forge (algorithm-agile signature; ML-DSA / hybrid
    when liboqs is present, ECDSA-P256 / Ed25519 otherwise)
  - Signer cannot deny (non-repudiable signatures)

The packet round-trips through ``verify_insurer_evidence_packet`` in
``tex.pitch.verifier`` — see acceptance criteria, Thread 9.

Wire format (paper-silent design decision)
------------------------------------------
The insurer-verifiable packet has no IETF/NIST standard. The wire
format below is purpose-built and versioned.

Layout v1
~~~~~~~~~
``InsurerEvidencePacket`` carries:

  - ``tenant_id``, ``period_start_iso``, ``period_end_iso`` —
    period metadata
  - ``algorithm`` — string value of ``SignatureAlgorithm`` enum
  - ``layout_version`` — bumped on any breaking change
  - ``artifacts: dict[str, bytes]`` — name -> canonical bytes for
    each component artifact
  - ``artifact_digests: dict[str, str]`` — name -> SHA-256 hex of
    canonical bytes (computed from ``artifacts``; serialized so
    verifiers can sanity-check digest derivation independently)
  - ``manifest_signature_b64`` — base64 of the algorithm-agile
    signature over the canonical-JSON manifest
  - ``signing_public_key`` — bytes of the public key used; embedded
    so an external verifier can pin it to a known KMS entry

The signed manifest is JCS-canonicalized JSON of:

    {
      "tenant_id": ...,
      "period_start_iso": ...,
      "period_end_iso": ...,
      "algorithm": ...,
      "layout_version": "1",
      "artifact_digests": {name: sha256_hex, ...}
    }

Note the manifest signs digests, not raw bytes. Two reasons:

  1. The signed object has bounded size regardless of artifact size.
  2. A verifier can detect tampering without re-reading multi-MB
     artifacts — the digest comparison is constant-time per artifact.

When NIST publishes a standard wire format for AI-evidence packets
(none exists as of May 2026), bump ``_PACKET_LAYOUT_VERSION``.

Priority: P0 (basic shape with audit chain + C2PA + receipts)
        / P1 (full ZKPROV+TEE, see TODOs)
        / P2 (full VET, see TODOs).

References
----------
- NIST FIPS 204 (ML-DSA) — primary signing algorithm at scale
- RFC 8785 (JSON Canonicalization Scheme) — manifest canonicalization
- NSA CNSA 2.0 — hybrid mode recommended through 2030 transition
- arxiv 2603.10060 — NabaOS HMAC tool receipts (Basu, Mar 2026)
- arxiv 2506.20915 — ZKPROV (P1 dataset provenance, future thread)
- arxiv 2512.15892 — VET Agent Identity Documents (P2, future thread)
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from typing import Any

from tex.c2pa.manifest import C2paManifest
from tex.domain.evidence import EvidenceRecord
from tex.events._canonical import canonical_json
from tex.observability.telemetry import emit_event
from tex.pqcrypto.algorithm_agility import (
    SignatureAlgorithm,
    SignatureKeyPair,
    get_signature_provider,
)
from tex.receipts.receipt import ToolExecutionReceipt


# Layout version. Bump on any breaking change to the canonical manifest.
_PACKET_LAYOUT_VERSION: str = "1"

# Stable artifact-name keys inside the packet. Verifier knows these.
_ARTIFACT_NAME_AUDIT_CHAIN: str = "audit_chain"
_ARTIFACT_NAME_C2PA: str = "c2pa_manifests"
_ARTIFACT_NAME_RECEIPTS: str = "tool_receipts"


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _serialize_evidence_chain(records: tuple[EvidenceRecord, ...]) -> bytes:
    """
    Canonicalize an evidence-chain slice to deterministic bytes.

    Each ``EvidenceRecord`` is rendered via pydantic ``model_dump`` with
    ``mode='json'`` so UUIDs and datetimes serialize stably. The full
    list is then JCS-canonicalized.
    """
    payload = [r.model_dump(mode="json") for r in records]
    return canonical_json(payload).encode("utf-8")


def _serialize_c2pa_manifests(manifests: tuple[C2paManifest, ...]) -> bytes:
    """Canonicalize a list of C2PA manifests to deterministic bytes."""
    payload = [m.model_dump(mode="json") for m in manifests]
    return canonical_json(payload).encode("utf-8")


def _serialize_receipts(receipts: tuple[ToolExecutionReceipt, ...]) -> bytes:
    """Canonicalize a list of tool receipts to deterministic bytes."""
    payload = [r.model_dump(mode="json") for r in receipts]
    return canonical_json(payload).encode("utf-8")


def _build_manifest(
    *,
    tenant_id: str,
    period_start_iso: str,
    period_end_iso: str,
    algorithm: SignatureAlgorithm,
    artifact_digests: dict[str, str],
) -> bytes:
    """
    JCS-canonicalize the signable packet manifest.

    The manifest signs digests, not raw bytes (see module docstring).
    """
    manifest: dict[str, Any] = {
        "tenant_id": tenant_id,
        "period_start_iso": period_start_iso,
        "period_end_iso": period_end_iso,
        "algorithm": algorithm.value,
        "layout_version": _PACKET_LAYOUT_VERSION,
        "artifact_digests": artifact_digests,
    }
    return canonical_json(manifest).encode("utf-8")


@dataclass(frozen=True, slots=True)
class InsurerEvidencePacket:
    """
    Self-describing, independently-verifiable evidence packet.

    Attributes
    ----------
    tenant_id
        Stable customer identifier the insurer can pin to a policy.
    period_start_iso, period_end_iso
        ISO-8601 period covered by the audit slice.
    algorithm
        Signature algorithm used to sign the packet manifest. The
        verifier dispatches via ``get_signature_provider``.
    layout_version
        Wire-format version; ``_PACKET_LAYOUT_VERSION`` at write time.
    artifacts
        Map from canonical name -> raw canonical bytes for each
        component (audit_chain, c2pa_manifests, tool_receipts).
    artifact_digests
        Map from canonical name -> SHA-256 hex of the bytes in
        ``artifacts`` for the same name. Serialized for verifier
        sanity-check.
    manifest_signature_b64
        Base64 of the signature over the JCS-canonicalized manifest.
    signing_public_key
        Public key bytes (PEM for classical, raw for ML-DSA, length-
        prefixed concat for hybrid). Used by the independent verifier
        to dispatch via ``get_signature_provider``.
    """

    tenant_id: str
    period_start_iso: str
    period_end_iso: str
    algorithm: SignatureAlgorithm
    layout_version: str
    artifacts: dict[str, bytes]
    artifact_digests: dict[str, str]
    manifest_signature_b64: str
    signing_public_key: bytes


def build_insurer_evidence_packet(
    tenant_id: str,
    period_start: str,
    period_end: str,
    *,
    evidence_records: tuple[EvidenceRecord, ...] | None = None,
    c2pa_manifests: tuple[C2paManifest, ...] | None = None,
    receipts: tuple[ToolExecutionReceipt, ...] | None = None,
    signing_key: SignatureKeyPair | None = None,
) -> InsurerEvidencePacket:
    """
    Build a single signed evidence packet for the given period.

    The original three-positional signature ``(tenant_id, period_start,
    period_end)`` is preserved. Component artifacts and a signing key
    are accepted as keyword-only arguments — required for a real
    packet, optional for callers that want introspection.

    Calling without component artifacts and a signing key raises
    ``TypeError`` with a remediation message rather than producing an
    empty packet that would silently round-trip with no real evidence.

    TODO(P0): assemble signed audit chain slice
        - DONE: serialized via ``_serialize_evidence_chain``;
          digest bound into the signed manifest.
    TODO(P0): collect C2PA manifests for the period
        - DONE: serialized via ``_serialize_c2pa_manifests``;
          digest bound into the signed manifest.
    TODO(P0): collect HMAC tool receipts for the period
        - DONE: serialized via ``_serialize_receipts``; digest bound
          into the signed manifest.
    TODO(P1): include ZKPROV proofs (arxiv 2506.20915)
        - Pending P1; add as a fourth artifact slot ``zkprov_proofs``
          alongside the existing three. Manifest layout will need a
          version bump (v2) when this lands.
    TODO(P2): include TEE attestation chain
        - Pending P2; H100/Blackwell attestation JWTs as a fifth slot.
    TODO(P2): include VET Agent Identity Document (arxiv 2512.15892)
        - Pending P2; AID + Web Proofs as a sixth slot.
    TODO(P0): sign full packet manifest with ML-DSA
        - DONE via algorithm-agile dispatcher. Default is whatever
          ``signing_key.algorithm`` resolves to; production should use
          ``HYBRID_ML_DSA_ED25519`` or ``ML_DSA_65`` once liboqs is
          available. ED25519 / ECDSA acceptable as transition-period
          fallback per NSA CNSA 2.0.
    """
    if (
        evidence_records is None
        or c2pa_manifests is None
        or receipts is None
        or signing_key is None
    ):
        raise TypeError(
            "build_insurer_evidence_packet requires keyword args "
            "evidence_records, c2pa_manifests, receipts, signing_key. "
            "The 3-positional form preserves the original scaffolded "
            "signature but cannot produce a verifiable packet without "
            "the underlying artifacts."
        )

    audit_bytes = _serialize_evidence_chain(evidence_records)
    c2pa_bytes = _serialize_c2pa_manifests(c2pa_manifests)
    receipt_bytes = _serialize_receipts(receipts)

    artifacts: dict[str, bytes] = {
        _ARTIFACT_NAME_AUDIT_CHAIN: audit_bytes,
        _ARTIFACT_NAME_C2PA: c2pa_bytes,
        _ARTIFACT_NAME_RECEIPTS: receipt_bytes,
    }
    artifact_digests: dict[str, str] = {
        name: _sha256_hex(data) for name, data in artifacts.items()
    }

    manifest_bytes = _build_manifest(
        tenant_id=tenant_id,
        period_start_iso=period_start,
        period_end_iso=period_end,
        algorithm=signing_key.algorithm,
        artifact_digests=artifact_digests,
    )

    provider = get_signature_provider(signing_key.algorithm)
    signature = provider.sign(manifest_bytes, signing_key)
    signature_b64 = base64.b64encode(signature).decode("ascii")

    packet = InsurerEvidencePacket(
        tenant_id=tenant_id,
        period_start_iso=period_start,
        period_end_iso=period_end,
        algorithm=signing_key.algorithm,
        layout_version=_PACKET_LAYOUT_VERSION,
        artifacts=artifacts,
        artifact_digests=artifact_digests,
        manifest_signature_b64=signature_b64,
        signing_public_key=signing_key.public_key,
    )

    emit_event(
        "pitch.evidence_packet.built",
        tenant_id=tenant_id,
        period_start=period_start,
        period_end=period_end,
        algorithm=signing_key.algorithm.value,
        layout_version=_PACKET_LAYOUT_VERSION,
        evidence_record_count=len(evidence_records),
        c2pa_manifest_count=len(c2pa_manifests),
        receipt_count=len(receipts),
        manifest_size_bytes=len(manifest_bytes),
    )

    return packet


# Re-exported so the verifier module can re-derive the manifest exactly.
def _rebuild_manifest_for_verification(
    packet: InsurerEvidencePacket,
) -> bytes:
    """
    Independent re-derivation of the signed manifest from a packet.

    Verifiers MUST NOT trust the signature alone — they must also
    verify that ``packet.artifact_digests`` matches a re-hash of
    ``packet.artifacts`` byte-for-byte. This helper is shared so the
    canonicalization stays identical between sign and verify paths.
    """
    return _build_manifest(
        tenant_id=packet.tenant_id,
        period_start_iso=packet.period_start_iso,
        period_end_iso=packet.period_end_iso,
        algorithm=packet.algorithm,
        artifact_digests=packet.artifact_digests,
    )


__all__ = [
    "InsurerEvidencePacket",
    "build_insurer_evidence_packet",
    "_ARTIFACT_NAME_AUDIT_CHAIN",
    "_ARTIFACT_NAME_C2PA",
    "_ARTIFACT_NAME_RECEIPTS",
    "_PACKET_LAYOUT_VERSION",
    "_rebuild_manifest_for_verification",
    "_sha256_hex",
]

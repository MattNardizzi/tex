"""
Independent verifier for the insurer evidence packet.

Acceptance criteria for Thread 9 require that a packet built by
``tex.pitch.insurer_export.build_insurer_evidence_packet`` round-trips
through this verifier function. "Round-trip" means:

  - all three component artifacts re-hash to the embedded digests
  - the embedded digests match the canonical manifest the packet
    claims to have signed
  - the algorithm-agile signature verifies against the embedded
    public key

This module is intentionally independent from the build path — it
re-derives the canonical manifest from scratch via
``_rebuild_manifest_for_verification`` rather than trusting any cached
state on the packet. That is what makes "the verifier cannot tamper
because the host cannot forge" hold.

Priority: P0.

References
----------
- NIST FIPS 204 (ML-DSA verification)
- NSA CNSA 2.0 transition guidance — accept hybrid + ML-DSA + classical
  during 2026-2030 window; reject pure-classical post-2030
- RFC 8785 (JCS) — manifest canonicalization
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field

from tex.observability.telemetry import emit_event
from tex.pitch.insurer_export import (
    InsurerEvidencePacket,
    _rebuild_manifest_for_verification,
    _sha256_hex,
)
from tex.pqcrypto.algorithm_agility import (
    SignatureAlgorithm,
    get_signature_provider,
)


@dataclass(frozen=True, slots=True)
class PacketVerificationIssue:
    """A single concrete reason a packet failed verification."""

    code: str
    message: str


@dataclass(frozen=True, slots=True)
class PacketVerificationResult:
    """Result of independently verifying a packet."""

    is_valid: bool
    algorithm: SignatureAlgorithm
    artifact_count: int
    issues: tuple[PacketVerificationIssue, ...] = field(default_factory=tuple)

    @property
    def issue_count(self) -> int:
        return len(self.issues)


# Algorithms a verifier will accept. Anything not in this set fails
# closed — the verifier deliberately does not transparently accept
# new algorithms it has never seen, even if they dispatch.
_ACCEPTED_VERIFICATION_ALGORITHMS: frozenset[SignatureAlgorithm] = frozenset(
    {
        SignatureAlgorithm.ML_DSA_44,
        SignatureAlgorithm.ML_DSA_65,
        SignatureAlgorithm.ML_DSA_87,
        SignatureAlgorithm.HYBRID_ML_DSA_ED25519,
        SignatureAlgorithm.ED25519,
        SignatureAlgorithm.ECDSA_P256,
    }
)


def verify_insurer_evidence_packet(
    packet: InsurerEvidencePacket,
    *,
    expected_public_key: bytes | None = None,
) -> PacketVerificationResult:
    """
    Independently verify an insurer evidence packet.

    Steps (in order; each step accumulates issues, none short-circuits
    so the result lists every problem at once):

      1. Algorithm is in ``_ACCEPTED_VERIFICATION_ALGORITHMS``.
      2. Each artifact in ``packet.artifacts`` re-hashes to
         ``packet.artifact_digests[name]``.
      3. Every digest in ``artifact_digests`` has a corresponding
         entry in ``artifacts`` (no orphan digests).
      4. ``packet.signing_public_key`` matches ``expected_public_key``
         when the caller pins one (offline KMS pinning).
      5. ``manifest_signature_b64`` decodes cleanly.
      6. ``get_signature_provider(packet.algorithm).verify(...)``
         returns True against the rebuilt manifest.

    Parameters
    ----------
    packet
        The packet to verify.
    expected_public_key
        Optional pinned public key. When provided, the packet's
        embedded ``signing_public_key`` must equal these bytes
        byte-for-byte. This is how an offline insurer pins to a
        Tex KMS public key without any live network.

    Returns
    -------
    PacketVerificationResult
        ``is_valid`` is True iff every step succeeded; ``issues`` lists
        every problem found (multiple issues may be reported in a
        single result so a forensic operator gets the full picture).
    """
    issues: list[PacketVerificationIssue] = []

    # 1. algorithm acceptance
    if packet.algorithm not in _ACCEPTED_VERIFICATION_ALGORITHMS:
        issues.append(
            PacketVerificationIssue(
                code="UNACCEPTED_ALGORITHM",
                message=(
                    f"algorithm {packet.algorithm.value!r} is not in the "
                    "verifier's accepted set"
                ),
            )
        )

    # 2. digest match (re-hash artifact bytes)
    for name, data in packet.artifacts.items():
        recomputed = _sha256_hex(data)
        embedded = packet.artifact_digests.get(name)
        if embedded is None:
            issues.append(
                PacketVerificationIssue(
                    code="MISSING_DIGEST",
                    message=f"artifact {name!r} has no embedded digest",
                )
            )
            continue
        if recomputed != embedded:
            issues.append(
                PacketVerificationIssue(
                    code="DIGEST_MISMATCH",
                    message=(
                        f"artifact {name!r} sha256 {recomputed} does "
                        f"not match embedded digest {embedded}"
                    ),
                )
            )

    # 3. orphan digests
    for name in packet.artifact_digests:
        if name not in packet.artifacts:
            issues.append(
                PacketVerificationIssue(
                    code="ORPHAN_DIGEST",
                    message=(
                        f"digest for {name!r} present but no corresponding "
                        "artifact bytes"
                    ),
                )
            )

    # 4. pinned public key
    if expected_public_key is not None:
        if packet.signing_public_key != expected_public_key:
            issues.append(
                PacketVerificationIssue(
                    code="PUBLIC_KEY_PIN_MISMATCH",
                    message=(
                        "embedded signing_public_key does not equal the "
                        "pinned expected_public_key"
                    ),
                )
            )

    # 5. signature decode
    try:
        signature = base64.b64decode(
            packet.manifest_signature_b64, validate=True
        )
    except (ValueError, base64.binascii.Error) as exc:
        issues.append(
            PacketVerificationIssue(
                code="SIGNATURE_DECODE_FAIL",
                message=f"manifest_signature_b64 not valid base64: {exc}",
            )
        )
        signature = b""

    # 6. signature verify (only if we have a decodable signature and an
    # accepted algorithm; otherwise we already have issues and the
    # verify call below would just be noise)
    if signature and packet.algorithm in _ACCEPTED_VERIFICATION_ALGORITHMS:
        manifest_bytes = _rebuild_manifest_for_verification(packet)
        try:
            provider = get_signature_provider(packet.algorithm)
            ok = provider.verify(
                manifest_bytes, signature, packet.signing_public_key
            )
        except Exception as exc:  # noqa: BLE001 — verifier must fail closed
            ok = False
            issues.append(
                PacketVerificationIssue(
                    code="VERIFIER_RAISED",
                    message=(
                        f"signature provider raised {type(exc).__name__}: "
                        f"{exc}"
                    ),
                )
            )
        if not ok and not any(
            i.code == "VERIFIER_RAISED" for i in issues
        ):
            issues.append(
                PacketVerificationIssue(
                    code="SIGNATURE_INVALID",
                    message=(
                        "signature did not verify against the rebuilt "
                        "manifest under the embedded public key"
                    ),
                )
            )

    result = PacketVerificationResult(
        is_valid=not issues,
        algorithm=packet.algorithm,
        artifact_count=len(packet.artifacts),
        issues=tuple(issues),
    )

    emit_event(
        "pitch.evidence_packet.verified",
        tenant_id=packet.tenant_id,
        algorithm=packet.algorithm.value,
        is_valid=result.is_valid,
        issue_count=result.issue_count,
        issue_codes=[i.code for i in result.issues],
    )

    return result


__all__ = [
    "PacketVerificationIssue",
    "PacketVerificationResult",
    "verify_insurer_evidence_packet",
]

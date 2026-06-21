"""Offline verifier for a presence :class:`~tex.presence.contract.Attestation`.

Given an ``Attestation`` + the ``PresenceClaim`` + the ``PresenceVerdict`` it was
signed over, a fresh clone re-derives the canonical subject, recomputes the
digest, and verifies the signature against the public key — *proving the binding
without trusting Tex* (no network, no key access beyond the attestation itself).

Three independent, fail-closed checks
-------------------------------------
1. **digest_ok** — the subject re-derived from (claim, verdict) hashes to exactly
   ``attestation.signed_digest_sha256``. A flipped tier, a swapped EvidenceRef, a
   changed recomputed value, or a tampered spoken span all break this.
2. **signature_ok** — the signature is valid over that digest under the public key
   embedded in the attestation. Delegated 1:1 to
   :func:`tex.evidence.seal.verify_payload_signature` (the real substrate — no
   crypto is re-implemented here).
3. **key_trusted** — *origin*. (1) and (2) only prove the binding is internally
   consistent under SOME key; a forger can re-sign a doctored binding with their
   OWN key and embed their OWN public key, and (1)+(2) still pass. Origin is
   established ONLY by pinning Tex's expected public key (the
   `seal-proves-authorship-only-if-you-pin-the-key` lesson). Pass
   ``expected_public_key_b64`` (and/or ``expected_key_id``). With NO pin the
   result reports ``key_pinned=False`` and the reason warns that origin is
   UNVERIFIED — the proof is integrity, not authorship.

Optional fourth check — evidence anchoring
------------------------------------------
``resolved_record_hashes`` maps ``record_id → the SHA-256 the verifier recomputed
from the actual sealed record it holds``. Each :class:`EvidenceRef` in the
(signature-verified) verdict must match. This upgrades "Tex signed these anchors"
to "and these anchors are of the real records you hold" — catching a record
substituted under a stale anchor. Record hashing is store-specific
(``Decision.content_sha256`` is read directly; a digest-less row is recomputed via
:func:`recompute_row_hash`), so the verifier supplies the hashes and this module
only compares — it does not assume one canonicalization across every store.

Honest edges (stated, not buried): this attests the claim→evidence→tier BINDING.
It is tamper-evidence + (pinned) origin-evidence. It does NOT prove the world is
true, does NOT prove chain-membership or ordering/freshness across attestations,
and is NOT a TEE.
"""

from __future__ import annotations

import hmac
import logging
from collections.abc import Mapping
from dataclasses import dataclass

from tex.presence.attest.subject import build_attestation_subject, subject_digest_hex
from tex.presence.contract import Attestation, PresenceClaim, PresenceVerdict

_logger = logging.getLogger(__name__)

__all__ = ["AttestationVerification", "verify_attestation", "recompute_row_hash"]


@dataclass(frozen=True, slots=True)
class AttestationVerification:
    """The full, honest result of an offline verification. ``ok`` is the
    fail-closed conjunction; the sub-fields say exactly what did and did not hold
    so a relying party can see *why*."""

    ok: bool
    digest_ok: bool
    signature_ok: bool
    key_pinned: bool
    key_trusted: bool | None      # None when no pin was supplied
    evidence_ok: bool | None      # None when no records were supplied
    algorithm: str
    is_post_quantum: bool
    reason: str


def recompute_row_hash(row: object) -> str:
    """Recompute the canonical content anchor for a digest-less sealed row —
    ``sha256(canonical_json(row))`` — exactly as the gate sealed it. A fresh-clone
    verifier uses this to build ``resolved_record_hashes`` for rows that carry no
    sealed digest of their own (an ``AgentIdentity``, ``ConnectorHealth``, ...).
    Rows with their own anchor (``Decision.content_sha256``,
    ``DiscoveryLedgerEntry.record_hash``) are read directly, not recomputed."""
    from tex.presence.gate.evidence import canonical_row_hash

    return canonical_row_hash(row)


def _check_evidence_anchors(
    verdict: PresenceVerdict, resolved: Mapping[str, str]
) -> tuple[bool, str]:
    """Every EvidenceRef must point at a record the verifier holds whose recomputed
    hash matches the signed anchor. Fail-closed: a missing or mismatched record
    fails the whole check."""
    if not verdict.evidence:
        return False, "evidence anchoring requested but the verdict binds no evidence"
    for ref in verdict.evidence:
        got = resolved.get(ref.record_id)
        if got is None:
            return False, f"no resolved record supplied for record_id {ref.record_id!r}"
        if got.strip().lower() != ref.record_hash.strip().lower():
            return False, (
                f"record_hash mismatch for {ref.record_id!r} "
                f"(store={ref.store!r}): signed {ref.record_hash} != recomputed {got}"
            )
    return True, "evidence anchors match"


def verify_attestation(
    *,
    attestation: Attestation,
    claim: PresenceClaim,
    verdict: PresenceVerdict,
    expected_public_key_b64: str | None = None,
    expected_key_id: str | None = None,
    resolved_record_hashes: Mapping[str, str] | None = None,
    require_evidence: bool = False,
) -> AttestationVerification:
    """Verify an attestation offline. Never raises — any error fails closed to
    ``ok=False``.

    Origin: pass ``expected_public_key_b64`` (and/or ``expected_key_id``) to PIN
    Tex's key. Without a pin, ``ok`` reflects integrity only and the reason warns
    that origin is unverified.

    Evidence: pass ``resolved_record_hashes`` to additionally anchor each
    EvidenceRef to a record you hold. ``require_evidence=True`` makes ``ok`` demand
    it even if no records are supplied (then ``ok=False``).
    """
    algorithm = getattr(attestation, "algorithm", "") or ""
    # Derive PQ from the algorithm, NOT from the attestation's self-reported
    # boolean. The signed digest excludes the pq_signature block, but
    # verify_payload_signature dispatches the provider on this algorithm, so a
    # tampered algorithm label makes the signature fail — i.e. the algorithm is
    # effectively authenticated whereas the stored is_post_quantum flag is not.
    # Reporting the derived value (meaningful only once signature_ok) means a
    # hand-forged "is_post_quantum=True over an ecdsa-p256 signature" cannot fool
    # a relying party. (The nanozk lesson, applied to our own output.)
    is_pq = "ml-dsa" in algorithm
    key_pinned = expected_public_key_b64 is not None or expected_key_id is not None

    try:
        subject = build_attestation_subject(claim, verdict)  # raises on id mismatch
    except Exception as exc:  # noqa: BLE001
        return AttestationVerification(
            ok=False, digest_ok=False, signature_ok=False, key_pinned=key_pinned,
            key_trusted=False if key_pinned else None,
            evidence_ok=None, algorithm=algorithm, is_post_quantum=is_pq,
            reason=f"subject build failed: {type(exc).__name__}: {exc}",
        )

    # 1) digest_ok — does the re-derived binding hash to what was signed?
    expected_digest = subject_digest_hex(subject)
    signed_digest = (attestation.signed_digest_sha256 or "").strip().lower()
    digest_ok = bool(signed_digest) and hmac.compare_digest(signed_digest, expected_digest)

    # 2) signature_ok — valid signature over that digest under the EMBEDDED key.
    signature_ok = False
    sig_reason = ""
    if not attestation.public_key_b64:
        sig_reason = "no public_key_b64 on the attestation; cannot verify the signature"
    else:
        try:
            from tex.evidence.seal import PQ_SIGNATURE_FIELD, verify_payload_signature

            block = {
                "algorithm": attestation.algorithm,
                "signature_b64": attestation.signature_b64,
                "public_key_b64": attestation.public_key_b64,
                "signed_digest_sha256": attestation.signed_digest_sha256,
            }
            signature_ok = bool(
                verify_payload_signature({**subject, PQ_SIGNATURE_FIELD: block})
            )
            if not signature_ok:
                sig_reason = "signature did not verify against the embedded public key"
        except Exception as exc:  # noqa: BLE001
            sig_reason = f"signature verification errored: {type(exc).__name__}: {exc}"

    # 3) key_trusted — origin, only meaningful against a pin.
    key_trusted: bool | None = None
    key_reason = ""
    if key_pinned:
        key_trusted = True
        if expected_public_key_b64 is not None:
            match = hmac.compare_digest(
                (attestation.public_key_b64 or ""), expected_public_key_b64
            )
            key_trusted = key_trusted and match
            if not match:
                key_reason = "public key does not match the pinned key (NOT signed by Tex)"
        if expected_key_id is not None and (attestation.key_id or "") != expected_key_id:
            key_trusted = False
            key_reason = (
                key_reason + "; " if key_reason else ""
            ) + f"key_id {attestation.key_id!r} != pinned {expected_key_id!r}"

    # 4) evidence_ok — optional anchoring to records the verifier holds.
    evidence_ok: bool | None = None
    ev_reason = ""
    if resolved_record_hashes is not None:
        evidence_ok, ev_reason = _check_evidence_anchors(verdict, resolved_record_hashes)
    elif require_evidence:
        ev_reason = "evidence anchoring required but no resolved records supplied"

    # Fail-closed conjunction.
    ok = digest_ok and signature_ok
    if key_pinned:
        ok = ok and bool(key_trusted)
    if resolved_record_hashes is not None or require_evidence:
        ok = ok and bool(evidence_ok)

    reason = _compose_reason(
        ok=ok, digest_ok=digest_ok, signature_ok=signature_ok, sig_reason=sig_reason,
        key_pinned=key_pinned, key_trusted=key_trusted, key_reason=key_reason,
        evidence_ok=evidence_ok, ev_reason=ev_reason, is_pq=is_pq, algorithm=algorithm,
    )
    return AttestationVerification(
        ok=ok, digest_ok=digest_ok, signature_ok=signature_ok, key_pinned=key_pinned,
        key_trusted=key_trusted, evidence_ok=evidence_ok, algorithm=algorithm,
        is_post_quantum=is_pq, reason=reason,
    )


def _compose_reason(
    *, ok: bool, digest_ok: bool, signature_ok: bool, sig_reason: str,
    key_pinned: bool, key_trusted: bool | None, key_reason: str,
    evidence_ok: bool | None, ev_reason: str, is_pq: bool, algorithm: str,
) -> str:
    """A concise, honest, human-readable explanation of the verdict."""
    problems: list[str] = []
    if not digest_ok:
        problems.append("digest mismatch (the claim/verdict do not match what was signed — tamper)")
    if not signature_ok:
        problems.append(sig_reason or "signature invalid")
    if key_pinned and not key_trusted:
        problems.append(key_reason or "pinned-key mismatch")
    if evidence_ok is False:
        problems.append(ev_reason or "evidence anchoring failed")
    if ev_reason and evidence_ok is None and not ok:
        problems.append(ev_reason)

    if problems:
        return "REJECTED: " + "; ".join(problems)

    strength = "post-quantum" if is_pq else "classical"
    if not key_pinned:
        return (
            f"OK (integrity only): binding is self-consistent under a {strength} "
            f"{algorithm} signature, but ORIGIN IS UNVERIFIED — no key was pinned, "
            "so this does not prove Tex signed it. Pin expected_public_key_b64 to "
            "establish authorship."
        )
    note = " + evidence anchored" if evidence_ok else ""
    return f"OK: {strength} {algorithm} signature verifies against the pinned Tex key{note}."

"""The canonical *attestation subject* — the exact bytes Tex signs.

ONE function builds the binding for both the signer (Session 3's attestor) and
the offline verifier, so the two can never drift: a subject signed here is the
same subject re-derived at verification time, byte-for-byte.

What the subject binds (and why each field is in it)
---------------------------------------------------
The attestation answers exactly one question — *did Tex's key vouch that THIS
claim was checked against THESE sealed records and assigned THIS tier?* So the
subject is the full, material content of that binding:

  * ``claim`` — ``claim_id`` (the authoritative handle), ``kind`` (how it was
    grounded) and ``text_span`` (the EXACT spoken phrasing, which ``compose.py``
    has already rewritten to the gate's canonical phrase before attestation).
    Binding the span means a tampered spoken line breaks the signature.
  * ``tier`` — the monotone credibility verdict. Flipping it breaks the signature.
  * ``recomputed_value`` / ``correctness_floor`` / ``coverage_mode`` /
    ``governance_verdict`` — the rest of the verdict's material content, so none
    of it can be swapped under a still-valid signature.
  * ``evidence`` — the ordered tuple of :class:`EvidenceRef`, each carrying the
    sealed record's ``record_hash`` anchor. Swapping a referenced record (or its
    anchor) breaks the signature.

Canonicalization
----------------
The signer (:mod:`tex.evidence.seal`) hashes ``sha256(_stable_json(payload))``
with ``sort_keys=True, separators=(",", ":")``. We never re-implement the crypto;
:func:`subject_digest_hex` mirrors *only* that one canonical-JSON+SHA-256 idiom so
the verifier can report a granular ``digest_ok`` without a key. A regression test
pins ``subject_digest_hex(subject) == signer.sign_payload(subject)["signed_digest_sha256"]``
so any drift from seal.py fails loudly.

Honest edge: this binds (claim → evidence → tier). It is tamper-evidence and
(with a pinned key) origin-evidence. It is NOT proof the world is true, NOT a
proof of chain-membership/ordering, and NOT a TEE.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from tex.presence.contract import CONTRACT_VERSION, PresenceClaim, PresenceVerdict

__all__ = ["SUBJECT_VERSION", "build_attestation_subject", "subject_digest_hex"]

# Schema version of the subject layout. A verifier may refuse an unknown version
# rather than silently mis-parse a future shape.
SUBJECT_VERSION = "presence-attest-subject-1.0.0"


def _json_safe(value: Any) -> Any:
    """A JSON-serializable view of a recomputed value, so the seal's plain
    ``json.dumps`` (no ``default=``) can never raise on the signing path.

    Scalars and any natively-serializable structure (the gate emits ``int`` for
    AGGREGATE, ``str`` for ENTITY/EVENT, ``dict`` for DERIVED) pass through
    unchanged; anything exotic degrades to ``str`` so the binding is still
    produced honestly rather than crashing the voice path."""
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    try:
        json.dumps(value)
    except (TypeError, ValueError):
        return str(value)
    return value


def build_attestation_subject(claim: PresenceClaim, verdict: PresenceVerdict) -> dict[str, Any]:
    """Return the deterministic, JSON-safe subject dict that gets signed.

    Raises ``ValueError`` if ``claim`` and ``verdict`` do not describe the same
    claim — attesting a mismatched pair would seal an incoherent binding.
    """
    if claim.claim_id != verdict.claim_id:
        raise ValueError(
            f"claim/verdict mismatch: claim {claim.claim_id!r} != verdict "
            f"{verdict.claim_id!r} — refusing to attest an incoherent binding."
        )
    return {
        "attestation_subject_version": SUBJECT_VERSION,
        "contract_version": CONTRACT_VERSION,
        "claim": {
            "claim_id": claim.claim_id,
            "kind": claim.kind.value,
            "text_span": claim.text_span,
        },
        "tier": verdict.tier.value,
        "recomputed_value": _json_safe(verdict.recomputed_value),
        "correctness_floor": verdict.correctness_floor,
        "coverage_mode": verdict.coverage_mode,
        "governance_verdict": (
            verdict.governance_verdict.value
            if verdict.governance_verdict is not None
            else None
        ),
        "evidence": [
            {
                "record_id": r.record_id,
                "record_hash": r.record_hash,
                "store": r.store,
                "field": r.field,
                "prior_link_witness": r.prior_link_witness,
            }
            for r in verdict.evidence
        ],
    }


def _stable_json(value: Any) -> str:
    """Sorted-key compact JSON — byte-identical to ``tex.evidence.seal._stable_json``
    and ``domain/evidence.TexEvidence.canonical_json``. Kept local (not imported
    from seal's private name) so the verifier owns its own digest recompute; the
    cross-check test guards against any drift from the signer."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def subject_digest_hex(subject: dict[str, Any]) -> str:
    """The 64-char hex SHA-256 the signer takes over ``subject``. Matches
    ``seal._signing_digest(subject).hex()`` exactly (``subject`` carries no
    ``pq_signature`` key, so seal's strip is a no-op here)."""
    return hashlib.sha256(_stable_json(subject).encode("utf-8")).hexdigest()

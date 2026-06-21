"""The sealed presence record + its canonical content anchor.

A :class:`SealedPresenceRecord` is one (claim → verdict → evidence) binding that
Tex chose to *remember* for a tenant. It is content-addressed: its ``record_id``
and ``record_hash`` are deterministic functions of the semantic content (tenant,
claim, verdict, the evidence the verdict was checked against, tier), so re-sealing
the identical fact is idempotent and any verifier can recompute the anchor offline.

Honesty about the anchor (the nanozk lesson — a name must deliver its property):
``record_hash`` is a **content anchor** — ``sha256`` over canonical JSON — NOT a
chain-membership proof. It proves "this is exactly the claim/verdict/evidence that
was sealed" (tamper-evidence by recompute) while the record is present; it does
NOT prove inclusion in any append-only chain, which is why every presence
EvidenceRef carries ``prior_link_witness=None``. This is the same honest
content-anchor idiom the truth-gate already uses
(:func:`tex.presence.gate.evidence.canonical_row_hash`); presence memory is a
*forgettable* store, so it deliberately does NOT live in the append-only
EvidenceRecorder / SealedFactLedger chains (which have no delete path).

When ``TEX_SEAL_DECISIONS=1`` and a signer is injected, the record additionally
carries a self-verifying ``pq_signature`` block from
:meth:`tex.evidence.seal.EvidenceChainSigner.sign_payload` — honestly labelled
with the algorithm actually used (``composite-ml-dsa-65-ed25519`` only when the
ML-DSA backend is present, else ``ecdsa-p256``). The content anchor is always
present; the signature is the optional authorship proof.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from tex.presence.contract import (
    EvidenceRef,
    PresenceClaim,
    PresenceTier,
    PresenceVerdict,
)

__all__ = [
    "SealedPresenceRecord",
    "presence_record_hash",
    "build_content_payload",
    "ref_to_dict",
]


def _stable_json(value: Any) -> str:
    """Sorted-key, tight-separator JSON — byte-identical to the idiom in
    ``tex.presence.gate.evidence`` and ``tex.evidence.seal`` so a payload hashed
    here re-serializes the same way an offline verifier would. ``default=str``
    keeps it total on the hot path (never raises on an exotic value)."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    )


def presence_record_hash(payload: dict[str, Any]) -> str:
    """``sha256(canonical_json(payload))`` — the 64-hex content anchor. An offline
    verifier rebuilds the same canonical payload and recomputes this exactly."""
    return hashlib.sha256(_stable_json(payload).encode("utf-8")).hexdigest()


def ref_to_dict(ref: EvidenceRef) -> dict[str, Any]:
    """A JSON-safe, order-stable view of one EvidenceRef (frozen+slots, so not
    directly serializable). Used both to hash the binding and to persist it."""
    return {
        "record_id": ref.record_id,
        "record_hash": ref.record_hash,
        "store": ref.store,
        "field": ref.field,
        "prior_link_witness": ref.prior_link_witness,
    }


def build_content_payload(
    *,
    tenant: str,
    claim: PresenceClaim,
    verdict: PresenceVerdict,
) -> dict[str, Any]:
    """The canonical, **time-independent** content of a sealed record — the bytes
    the content anchor commits to.

    ``sealed_at`` is deliberately EXCLUDED so that re-sealing the identical
    (tenant, claim, verdict, evidence) is idempotent (same ``record_id``). The
    verdict's ``tier`` and the evidence record_hashes ARE included, so a tier flip
    or an evidence swap yields a *different* record — you cannot silently mutate
    what a given anchor means.
    """
    return {
        "kind": "presence_memory_record",
        "tenant": tenant,
        "claim": {
            "claim_id": claim.claim_id,
            "text_span": claim.text_span,
            "kind": claim.kind.value,
        },
        "verdict": {
            "claim_id": verdict.claim_id,
            "tier": verdict.tier.value,
            "evidence": [ref_to_dict(r) for r in verdict.evidence],
            "recomputed_value": verdict.recomputed_value,
            "correctness_floor": verdict.correctness_floor,
            "coverage_mode": verdict.coverage_mode,
            "governance_verdict": (
                verdict.governance_verdict.value
                if verdict.governance_verdict is not None
                else None
            ),
            "reason": verdict.reason,
        },
    }


def _searchable_text(claim: PresenceClaim, verdict: PresenceVerdict) -> str:
    """A lowercase blob recall() lexically matches a query against. This is
    LEXICAL recall (substring), not semantic — disclosed, not hidden: a paraphrase
    that shares no token will not match (fails toward the gate re-deriving /
    ABSTAIN, the safe direction)."""
    parts = [
        claim.claim_id or "",
        claim.text_span or "",
        claim.kind.value,
        verdict.tier.value,
        verdict.reason or "",
    ]
    return " ".join(p for p in parts if p).casefold()


@dataclass(frozen=True, slots=True)
class SealedPresenceRecord:
    """One sealed, forgettable presence fact for a single tenant.

    Frozen: the record is immutable once sealed; ``forget`` removes it wholesale
    rather than mutating it.
    """

    record_id: str
    tenant: str
    claim_id: str
    tier: str
    content_hash: str
    """64-hex content anchor over :func:`build_content_payload`."""
    content_payload: dict[str, Any]
    """The exact canonical content the anchor commits to (re-verifiable offline)."""
    searchable_text: str
    """Lowercase lexical-recall blob (see :func:`_searchable_text`)."""
    sealed_at: str
    """ISO-8601 UTC; metadata only — NOT part of the content anchor."""
    pq_signature: dict[str, Any] | None = field(default=None)
    """Self-verifying signature block when ``TEX_SEAL_DECISIONS=1`` + signer
    injected; ``None`` otherwise (the content anchor still stands)."""

    def as_ref(self) -> EvidenceRef:
        """The tamper-evident pointer ``seal`` returns and ``recall`` surfaces.
        ``store='presence_memory'``; ``prior_link_witness=None`` because this is a
        content anchor, not an append-only-chain inclusion proof."""
        return EvidenceRef(
            record_id=self.record_id,
            record_hash=self.content_hash,
            store="presence_memory",
            field=self.claim_id or None,
            prior_link_witness=None,
        )

    @classmethod
    def seal(
        cls,
        *,
        tenant: str,
        claim: PresenceClaim,
        verdict: PresenceVerdict,
        pq_signature: dict[str, Any] | None = None,
    ) -> "SealedPresenceRecord":
        """Construct a sealed record from a (claim, verdict). The caller
        (:class:`tex.presence.memory.store.SealedPresenceMemory`) is responsible
        for the write-gate; this only builds the immutable object + anchor."""
        payload = build_content_payload(tenant=tenant, claim=claim, verdict=verdict)
        content_hash = presence_record_hash(payload)
        return cls(
            record_id=f"pm-{content_hash}",
            tenant=tenant,
            claim_id=verdict.claim_id,
            tier=verdict.tier.value,
            content_hash=content_hash,
            content_payload=payload,
            searchable_text=_searchable_text(claim, verdict),
            sealed_at=datetime.now(UTC).isoformat(),
            pq_signature=pq_signature,
        )


def is_sealable_tier(tier: PresenceTier) -> bool:
    """A groundable, evidence-bearing tier — the only kind presence memory will
    seal. ABSTAIN is refused (nothing proven to remember)."""
    return tier in (PresenceTier.SEALED, PresenceTier.DERIVED)

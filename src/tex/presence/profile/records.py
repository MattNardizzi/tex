"""The sealed profile record + its canonical content anchor.

A :class:`SealedProfileFact` is one learned, per-tenant profile fact (a correction
/ confirmation / preference). It is content-addressed exactly like an S5
:class:`tex.presence.memory.records.SealedPresenceRecord`: ``record_id`` and
``content_hash`` are deterministic ``sha256`` functions of the semantic content,
so re-asserting an identical fact is idempotent and any verifier can recompute the
anchor offline.

Reuse, not reinvention (the nanozk rule — no new crypto): the canonical-JSON +
``sha256`` content anchor reuses :func:`tex.presence.memory.records.presence_record_hash`
verbatim, and the optional self-verifying signature rides the SAME
``tex.evidence.seal.EvidenceChainSigner`` S5 uses — honestly labelled with the
algorithm actually used (``composite-ml-dsa-65-ed25519`` only when an ML-DSA
backend is present, else ``ecdsa-p256``).

The anchor proves "this is exactly the (tenant, kind, subject, corrected_tier,
operator, statement, ...) that was sealed" by recompute, while the record is
present. It is NOT a chain-membership proof — the profile is a *forgettable* store,
so it deliberately does not live in the append-only EvidenceRecorder /
SealedFactLedger chains (which have no delete path). Every profile EvidenceRef
carries ``prior_link_witness=None``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from tex.presence.contract import PresenceTier
from tex.presence.memory.records import presence_record_hash
from tex.presence.profile.types import ProfileFact, ProfileFactKind, _norm_subject

__all__ = [
    "SealedProfileFact",
    "build_profile_payload",
    "profile_fact_hash",
]


def _tier_value(tier: PresenceTier | None) -> str | None:
    return tier.value if tier is not None else None


def build_profile_payload(
    *,
    tenant: str,
    kind: ProfileFactKind,
    subject_key: str,
    corrected_tier: PresenceTier | None,
    statement: str,
    operator: str,
    original_tier: PresenceTier | None,
    decision_id: str | None,
    believed_value: str | None,
) -> dict[str, Any]:
    """The canonical, TIME-INDEPENDENT content the anchor commits to.

    ``created_at`` is deliberately EXCLUDED so re-asserting the identical fact is
    idempotent (same ``record_id``). Every semantic field — including ``operator``
    (the provenance) and ``corrected_tier`` (the direction of the tightening) — IS
    included, so a different operator or a different tier yields a *different*
    record; you cannot silently mutate what a given anchor means.
    """
    return {
        "kind_of_record": "presence_profile_fact",
        "fact_kind": kind.value,
        "tenant": tenant,
        "subject_key": subject_key,
        "corrected_tier": _tier_value(corrected_tier),
        "original_tier": _tier_value(original_tier),
        "statement": statement or "",
        "operator": operator,
        "decision_id": decision_id,
        "believed_value": believed_value,
    }


def profile_fact_hash(payload: dict[str, Any]) -> str:
    """The 64-hex content anchor. Reuses S5's ``sha256(canonical_json)`` so an
    offline verifier rebuilds the same canonical payload and recomputes this
    exactly — one canonicalisation idiom across all presence stores."""
    return presence_record_hash(payload)


def _searchable_text(
    *, subject_key: str, statement: str, kind: ProfileFactKind, corrected_tier: PresenceTier | None
) -> str:
    """Lowercase blob ``recall_profile(query=...)`` lexically matches against.
    LEXICAL (substring), not semantic — disclosed, not hidden."""
    parts = [subject_key, statement, kind.value, _tier_value(corrected_tier) or ""]
    return " ".join(p for p in parts if p).casefold()


@dataclass(frozen=True, slots=True)
class SealedProfileFact:
    """One sealed, forgettable profile fact for a single tenant. Frozen: immutable
    once sealed; ``revoke`` removes it wholesale rather than mutating it."""

    record_id: str
    tenant: str
    kind: ProfileFactKind
    subject_key: str
    corrected_tier: PresenceTier | None
    original_tier: PresenceTier | None
    statement: str
    operator: str
    decision_id: str | None
    believed_value: str | None
    content_hash: str
    content_payload: dict[str, Any]
    searchable_text: str
    created_at: str
    pq_signature: dict[str, Any] | None = field(default=None)

    @classmethod
    def build(
        cls,
        *,
        tenant: str,
        kind: ProfileFactKind,
        claim_id: str,
        corrected_tier: PresenceTier | None,
        statement: str,
        operator: str,
        original_tier: PresenceTier | None = None,
        decision_id: str | None = None,
        believed_value: str | None = None,
        pq_signature: dict[str, Any] | None = None,
        subject_key: str | None = None,
    ) -> "SealedProfileFact":
        """Construct a sealed fact + its anchor. The caller (the store) owns the
        write-gate; this only builds the immutable object.

        ``subject_key`` is the STABLE subject the correction is scoped to (the
        gate's routing identity, surfaced at speak-time). When omitted, it falls
        back to ``_norm_subject(claim_id)`` (the legacy volatile key). Either way
        it is normalised so the read-side lookup matches byte-for-byte."""
        subject_key = _norm_subject(subject_key) if (subject_key or "").strip() else _norm_subject(claim_id)
        payload = build_profile_payload(
            tenant=tenant,
            kind=kind,
            subject_key=subject_key,
            corrected_tier=corrected_tier,
            statement=statement,
            operator=operator,
            original_tier=original_tier,
            decision_id=decision_id,
            believed_value=believed_value,
        )
        content_hash = profile_fact_hash(payload)
        return cls(
            record_id=f"pf-{content_hash}",
            tenant=tenant,
            kind=kind,
            subject_key=subject_key,
            corrected_tier=corrected_tier,
            original_tier=original_tier,
            statement=statement or "",
            operator=operator,
            decision_id=decision_id,
            believed_value=believed_value,
            content_hash=content_hash,
            content_payload=payload,
            searchable_text=_searchable_text(
                subject_key=subject_key, statement=statement or "", kind=kind,
                corrected_tier=corrected_tier,
            ),
            created_at=datetime.now(UTC).isoformat(),
            pq_signature=pq_signature,
        )

    def to_fact(self) -> ProfileFact:
        """The contract-level view (``tex.presence.profile.types.ProfileFact``)
        ``recall_profile`` returns and the influence fold reads."""
        return ProfileFact(
            record_id=self.record_id,
            tenant=self.tenant,
            kind=self.kind,
            subject_key=self.subject_key,
            corrected_tier=self.corrected_tier,
            statement=self.statement,
            operator=self.operator,
            created_at=self.created_at,
            original_tier=self.original_tier,
            decision_id=self.decision_id,
            believed_value=self.believed_value,
            content_hash=self.content_hash,
        )

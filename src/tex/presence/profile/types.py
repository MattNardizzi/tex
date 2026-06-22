"""The Profile interface — the seam L3 builds against (POST this to the orchestrator).

This is to L2 what :mod:`tex.presence.contract` is to the presence layer: the
SHARED shapes other sessions import. It is intentionally a *separate* module from
the frozen presence contract (which must not be edited) — it adds the
personalization axis on top of S5's sealed memory without touching the verdict
contract.

WHAT A PROFILE IS
-----------------
A per-tenant PROFILE is the learned, sealed, citable, **revocable** set of a
tenant's preferences / boundaries / corrections. Facts live ONLY in this store —
never in model weights — so "becomes more yours the more you use it" can never
mean "becomes a fine-tune you cannot inspect or forget." Each fact is
content-anchored (recomputable ``sha256``) and optionally PQ-signed via the SAME
``tex.evidence.seal`` signer S5 uses (no new crypto — the nanozk rule).

THE TWO-WAY LOOP, AND WHY IT CANNOT INFLATE
-------------------------------------------
The operator can CONFIRM ("that's right") or CORRECT ("that's wrong / you were too
confident") a spoken claim's :class:`~tex.presence.contract.PresenceTier`.

  * A **CORRECTION** is a sealed LABEL that *tightens* a future verdict for the
    same subject — it can ONLY move a tier toward caution (``SEALED → DERIVED →
    ABSTAIN``), enforced by folding with :func:`tex.presence.contract.tighten`,
    never a ``max``. A correction whose ``corrected_tier`` is ``SEALED`` (an
    *upward*, inflating correction) is **REFUSED** at the write-gate: a human
    asserting confidence Tex cannot prove is the exact fabrication vector Tex
    exists to prevent. To make Tex speak something as fact, seal a real fact with
    evidence (``tex.presence.memory.SealedPresenceMemory.seal``) — that path's
    write-gate requires evidence by construction.
  * A **CONFIRMATION** is a sealed positive receipt. It is **non-inflating by
    construction**: there is no fold anywhere that raises a tier, so a confirm can
    never make Tex more confident. Its value is a citable record of operator
    agreement + a positive label for L1's calibration seam. To LOOSEN a prior
    correction, you ``revoke`` it — you do not "confirm upward."

WHY VALUE CORRECTIONS DO NOT OVERRIDE THE SPOKEN NUMBER
------------------------------------------------------
The truth-gate RECOMPUTES aggregates from sealed rows; the model never counts. So
an operator who types "it's 3, not 5" is either mistaken or is reporting a
*data* problem (fix the rows) — letting that typed number reach the user's ears
would be Tex speaking a number it cannot prove. Therefore ``believed_value`` is
stored as operator-belief METADATA only and is NEVER spoken; the only behavioural
effect a value disagreement can have is a tier correction toward caution.

HONEST EDGES (baked in; never overclaimed)
------------------------------------------
  * Per-tenant isolation is APPLICATION-LAYER only (in-memory dict outer key +
    ``WHERE tenant_id``) — no Postgres RLS, no encryption-at-rest. A wrong
    ``tenant`` string crosses tenants silently; the API never reads a tenant from a
    payload. (OWASP LLM08:2025 "weak" isolation tier — same posture as S5.)
  * ``revoke`` is forget-by-avoidance: the fact is removed wholesale from this
    store (not redacted-to-a-placeholder), so it is truly unrecoverable here.
    ``True`` is scoped to THIS store instance (multi-worker: route a tenant to one
    worker). It governs this store only — not a vendor model's cache of a prior
    recall, nor any ``EvidenceRef`` already copied out.
  * A correction is a LABEL that tightens a boundary — NOT a model retrain. The
    profile is INERT without real usage: the V1 claim is "Tex CAN learn your
    preferences, verifiably and revocably," NOT "Tex knows you."
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, runtime_checkable

from tex.presence.contract import EvidenceRef, PresenceTier, tighten

__all__ = [
    "PROFILE_INTERFACE_VERSION",
    "ProfileFactKind",
    "ProfileFact",
    "ProfileFacts",
    "ProfileMemory",
    "PROFILE_STORE_NAME",
]

PROFILE_INTERFACE_VERSION = "1.0.0"

# The ``EvidenceRef.store`` value every profile EvidenceRef carries. An offline
# verifier keys off this to know which store to re-fetch + re-verify against.
PROFILE_STORE_NAME = "presence_profile"


class ProfileFactKind(StrEnum):
    """The kind of learned fact. Only ``CORRECTION`` influences a future verdict
    (always toward caution); the rest are recall-surfaced metadata."""

    CORRECTION = "correction"
    """A sealed tightening: "you were too confident about X" → caps the spoken tier
    for subject X at ``corrected_tier`` (``DERIVED``/``ABSTAIN``). The only kind the
    influence fold consults."""

    CONFIRMATION = "confirmation"
    """A sealed positive receipt: "that was right." Citable; NON-inflating."""

    PREFERENCE = "preference"
    """A recall-surfaced standing preference/concern ("I always care about shadow
    agents"). Surfaced to the brain/operator; does NOT alter a verdict in V1."""


def _norm_subject(claim_id: str) -> str:
    """The subject key a correction is scoped to = the gate's own routing handle
    (the claim_id), normalised. EXACT-subject only: a correction never widens to a
    prefix/fuzzy match, because tightening an unrelated claim would itself
    misrepresent the operator's intent."""
    return (claim_id or "").strip().casefold()


@dataclass(frozen=True, slots=True)
class ProfileFact:
    """One learned, sealed, citable, revocable per-tenant profile fact.

    Immutable + content-addressed: ``record_id = "pf-" + content_hash`` where the
    hash is a recomputable ``sha256`` over the canonical, time-independent content
    (see :mod:`tex.presence.profile.records`). Re-asserting the identical fact is
    idempotent (same id); a different ``corrected_tier``/operator/subject yields a
    different record — you cannot silently mutate what an anchor means.
    """

    record_id: str
    tenant: str
    kind: ProfileFactKind
    subject_key: str
    """The normalised claim_id this fact governs (``_norm_subject``)."""
    corrected_tier: PresenceTier | None
    """For ``CORRECTION``: the tier CEILING imposed on the subject (never
    ``SEALED``). ``None`` for non-correction kinds."""
    statement: str
    """Human-readable boundary/preference text, surfaced in the UI + abstain
    reason (never spoken as a grounded claim)."""
    operator: str
    """The named human who created the fact — the provenance the write-gate
    validates BEFORE writing (the frontier's named blind spot, closed)."""
    created_at: str
    """ISO-8601 UTC; metadata only — NOT part of the content anchor."""
    original_tier: PresenceTier | None = None
    """For ``CORRECTION``/``CONFIRMATION``: the tier Tex actually spoke, recorded
    so the correction's direction (a tightening) is auditable."""
    decision_id: str | None = None
    """Optional governance ``Decision`` this correction is about. When present, the
    route may feed L1's calibration seam (a confirmed-true error)."""
    believed_value: str | None = None
    """Operator-belief metadata ONLY — never spoken (see module docstring)."""
    content_hash: str = ""
    """The 64-hex content anchor; ``record_id`` is ``"pf-" + content_hash``."""

    def as_ref(self) -> EvidenceRef:
        """The tamper-evident, citable pointer ``recall_profile`` surfaces.
        ``prior_link_witness=None`` because this is a content anchor, not an
        append-only-chain inclusion proof (same honesty as S5)."""
        return EvidenceRef(
            record_id=self.record_id,
            record_hash=self.content_hash,
            store=PROFILE_STORE_NAME,
            field=self.subject_key or None,
            prior_link_witness=None,
        )


@dataclass(frozen=True, slots=True)
class ProfileFacts:
    """The result of ``recall_profile`` — a tenant's ACTIVE (non-revoked) facts,
    plus the derived per-subject tier ceiling the influence fold consults."""

    tenant: str
    facts: tuple[ProfileFact, ...] = ()

    def refs(self) -> tuple[EvidenceRef, ...]:
        """Citable EvidenceRefs for every active fact."""
        return tuple(f.as_ref() for f in self.facts)

    def corrections(self) -> tuple[ProfileFact, ...]:
        return tuple(f for f in self.facts if f.kind is ProfileFactKind.CORRECTION)

    def tier_ceiling(self, claim_id: str) -> PresenceTier | None:
        """The MOST CAUTIOUS ceiling across all active corrections for the subject
        a ``claim_id`` normalises to (a monotone fold with :func:`tighten`), or
        ``None`` if uncorrected. Kept for legacy/claim_id-keyed lookups; the hot
        path keys on the STABLE routing subject — see
        :func:`tex.presence.profile.influence.stable_subject_key` and
        :meth:`tier_ceiling_for_subject`."""
        return self.tier_ceiling_for_subject(_norm_subject(claim_id))

    def tier_ceiling_for_subject(self, subject_key: str) -> PresenceTier | None:
        """The MOST CAUTIOUS ceiling across all active corrections stored under an
        ALREADY-RESOLVED ``subject_key`` (a monotone fold with :func:`tighten`), or
        ``None`` if uncorrected. EXACT match only — a correction never widens to a
        prefix/fuzzy match. Corrections only ever accumulate toward caution."""
        ceiling: PresenceTier | None = None
        for f in self.facts:
            if f.kind is ProfileFactKind.CORRECTION and f.subject_key == subject_key and f.corrected_tier is not None:
                ceiling = f.corrected_tier if ceiling is None else tighten(ceiling, f.corrected_tier)
        return ceiling


@runtime_checkable
class ProfileMemory(Protocol):
    """L2's seam (POST this to the orchestrator; L3 builds against it).

    Sealed, per-tenant, write-gated, FORGETTABLE profile memory + the two-way
    confirm/correct loop. Concrete implementation:
    :class:`tex.presence.profile.store.SealedProfileMemory`, built via
    :func:`tex.presence.profile.hooks.build_profile_memory`.
    """

    def recall_profile(self, *, tenant: str, query: str | None = None) -> ProfileFacts:
        """Return this tenant's ACTIVE (non-revoked) profile facts, citable. With
        a ``query``, lexically filters (substring) — a paraphrase that shares no
        token will not match (the safe direction). Strictly tenant-scoped."""
        ...

    def apply_correction(
        self,
        *,
        tenant: str,
        claim_id: str,
        corrected_tier: PresenceTier,
        operator: str,
        statement: str = "",
        original_tier: PresenceTier | None = None,
        decision_id: str | None = None,
        believed_value: str | None = None,
        subject_key: str | None = None,
    ) -> EvidenceRef:
        """Write-gate a CORRECTION and return its citable EvidenceRef. Fail-closed:
        REFUSES (raises ``ValueError``, writes nothing) when ``corrected_tier`` is
        ``SEALED`` (an inflating correction), when ``operator`` is empty (no
        provenance), or when ``original_tier`` is given and ``corrected_tier`` is
        not strictly more cautious (nothing to tighten).

        ``subject_key`` (optional) is the STABLE subject the cap is scoped to,
        surfaced at speak-time by :func:`tex.presence.profile.influence.stable_subject_key`
        (the gate's routing identity — stable across re-asks and as rows change).
        When omitted, the subject falls back to ``_norm_subject(claim_id)`` (the
        legacy, volatile key) — kept only for backward compatibility."""
        ...

    def confirm(
        self,
        *,
        tenant: str,
        claim_id: str,
        tier: PresenceTier,
        operator: str,
        statement: str = "",
        decision_id: str | None = None,
    ) -> EvidenceRef:
        """Write-gate a CONFIRMATION (positive, non-inflating) and return its
        citable EvidenceRef."""
        ...

    def revoke(self, *, tenant: str, record_id: str) -> bool:
        """Forget a profile fact wholesale. Returns ``True`` iff the record was
        present in THIS store and is now unrecoverable from it. A durable-mirror
        delete that RAISES re-inserts and re-raises (revoke unconfirmed, never a
        false ``True``) — same forget-soundness as S5."""
        ...

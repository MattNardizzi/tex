"""``SealedProfileMemory`` — sealed, per-tenant, write-gated, FORGETTABLE profile
memory + the two-way confirm/correct loop.

This is the concrete :class:`tex.presence.profile.types.ProfileMemory`. It is built
ON S5's patterns (content anchor, the ``tex.evidence.seal`` signer, the durable-
mirror idiom, the in-memory-authoritative + forget-soundness discipline) but keeps
its OWN write-gate, honest to what a profile fact IS: the gate validates the
named-human-act PROVENANCE and the monotone-lowering DIRECTION of a correction,
NOT a sealed-evidence count (a correction is a human label, not a recomputed fact).

Authoritative tier = an in-memory ``dict[tenant][record_id]`` under one ``RLock``
(the source of truth, so ``revoke`` returns a meaningful, testable True/False with
``DATABASE_URL`` unset). An OPTIONAL :class:`ProfileDurableMirror` adds cross-restart
durability; written through on write, deleted-through on revoke, hydrated lazily
per-tenant on first touch.

ISOLATION & SCOPE — honest edges, never overclaimed (same posture as S5):
  * Per-tenant isolation is application-layer ONLY (dict outer key + ``WHERE
    tenant_id``). NO Postgres RLS, no encryption-at-rest. A wrong ``tenant`` string
    crosses silently; the API never reads a tenant from a payload.
  * ``revoke``'s ``True`` is scoped to THIS store instance; multi-worker
    deployments must route a tenant to one worker.
"""

from __future__ import annotations

import logging
import os
import threading
from typing import Any

from tex.presence.contract import EvidenceRef, PresenceTier, tighten
from tex.presence.profile.durable import ProfileDurableMirror
from tex.presence.profile.records import SealedProfileFact, build_profile_payload
from tex.presence.profile.types import (
    ProfileFacts,
    ProfileFactKind,
    _norm_subject,
)

_logger = logging.getLogger(__name__)

# Cap on facts recall_profile returns — keeps the brain prompt / UI surface bounded.
_RECALL_CAP = 50

_RANK = {PresenceTier.SEALED: 2, PresenceTier.DERIVED: 1, PresenceTier.ABSTAIN: 0}


class SealedProfileMemory:
    """Concrete :class:`tex.presence.profile.types.ProfileMemory`. Construct via
    :func:`tex.presence.profile.hooks.build_profile_memory` in the orchestrator."""

    def __init__(
        self,
        *,
        mirror: ProfileDurableMirror | None = None,
        signer: Any | None = None,
    ) -> None:
        self._lock = threading.RLock()
        self._mem: dict[str, dict[str, SealedProfileFact]] = {}
        self._mirror = mirror
        self._signer = signer
        self._hydrated: set[str] = set()

    # ------------------------------------------------------------------ protocol

    def recall_profile(self, *, tenant: str, query: str | None = None) -> ProfileFacts:
        """Return this tenant's ACTIVE (non-revoked — i.e. still present) profile
        facts, most-recent-first, citable. LEXICAL query filter (substring); an
        empty/whitespace query returns everything (capped). Strictly tenant-scoped:
        tenant A can never recall tenant B's facts."""
        tenant = self._require_tenant(tenant)
        self._hydrate_tenant(tenant)
        with self._lock:
            bucket = self._mem.get(tenant)
            facts = tuple(bucket.values()) if bucket else ()

        ordered = sorted(facts, key=lambda f: f.created_at, reverse=True)
        tokens = [t for t in (query or "").casefold().split() if len(t) >= 2]
        if tokens:
            ordered = [f for f in ordered if any(t in f.searchable_text for t in tokens)]
        return ProfileFacts(
            tenant=tenant,
            facts=tuple(f.to_fact() for f in ordered[:_RECALL_CAP]),
        )

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
    ) -> EvidenceRef:
        """Write-gate a CORRECTION into per-tenant profile memory and return its
        citable EvidenceRef. Fail-closed — the write-gate (provenance validated
        BEFORE write, the frontier's named blind spot):

          1. ``tenant`` non-empty (the only bucket key written).
          2. ``operator`` non-empty — a correction is a NAMED human act; an
             anonymous correction has no provenance and is refused.
          3. ``claim_id`` non-empty — it is the subject the ceiling is scoped to.
          4. ``corrected_tier`` is NOT ``SEALED`` — an *upward*/inflating
             correction is the fabrication vector Tex exists to prevent; to make
             Tex speak something as fact, seal a real fact with evidence.
          5. If ``original_tier`` is given, ``corrected_tier`` must be STRICTLY more
             cautious (a real tightening); else there is nothing to correct
             downward.
        """
        tenant = self._require_tenant(tenant)
        operator = self._require_operator(operator)
        if not (claim_id or "").strip():
            raise ValueError("apply_correction: claim_id (the corrected subject) is required")
        if corrected_tier is PresenceTier.SEALED:
            raise ValueError(
                "apply_correction: refuse an upward correction to SEALED — a human "
                "asserting confidence Tex cannot prove is fabrication. To make Tex "
                "speak this as fact, seal a fact with evidence "
                "(SealedPresenceMemory.seal), which requires evidence by construction."
            )
        if original_tier is not None and _RANK[corrected_tier] >= _RANK[original_tier]:
            raise ValueError(
                f"apply_correction: corrected_tier {corrected_tier.value!r} is not "
                f"stricter than original_tier {original_tier.value!r} — a correction "
                "must tighten (move toward caution); nothing to do."
            )

        return self._write(
            tenant=tenant,
            kind=ProfileFactKind.CORRECTION,
            claim_id=claim_id,
            corrected_tier=corrected_tier,
            statement=statement,
            operator=operator,
            original_tier=original_tier,
            decision_id=decision_id,
            believed_value=believed_value,
        )

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
        """Write-gate a CONFIRMATION (positive receipt) and return its citable
        EvidenceRef. NON-inflating by construction: a confirmation carries
        ``corrected_tier=None`` and is never consulted by the influence fold, so it
        cannot raise any future tier. ``tier`` is recorded as the affirmed
        ``original_tier`` (what Tex spoke and the operator agreed with)."""
        tenant = self._require_tenant(tenant)
        operator = self._require_operator(operator)
        if not (claim_id or "").strip():
            raise ValueError("confirm: claim_id (the confirmed subject) is required")
        return self._write(
            tenant=tenant,
            kind=ProfileFactKind.CONFIRMATION,
            claim_id=claim_id,
            corrected_tier=None,
            statement=statement,
            operator=operator,
            original_tier=tier,
            decision_id=decision_id,
            believed_value=None,
        )

    def remember_preference(
        self,
        *,
        tenant: str,
        claim_id: str,
        statement: str,
        operator: str,
    ) -> EvidenceRef:
        """Write-gate a standing PREFERENCE/concern (recall-surfaced metadata; does
        NOT alter a verdict in V1). ``statement`` is required — a preference with no
        text says nothing."""
        tenant = self._require_tenant(tenant)
        operator = self._require_operator(operator)
        if not (statement or "").strip():
            raise ValueError("remember_preference: a non-empty statement is required")
        return self._write(
            tenant=tenant,
            kind=ProfileFactKind.PREFERENCE,
            claim_id=claim_id,
            corrected_tier=None,
            statement=statement,
            operator=operator,
            original_tier=None,
            decision_id=None,
            believed_value=None,
        )

    def revoke(self, *, tenant: str, record_id: str) -> bool:
        """Forget a profile fact wholesale (forget-by-avoidance). Returns ``True``
        IFF the record was present in THIS store instance AND is now unrecoverable
        from it.

        Soundness (the one unrecoverable-lie risk, closed — identical discipline to
        S5's ``forget``): membership check, pop, durable delete, and
        restore-on-failure all run inside ONE ``self._lock`` block (atomic against
        concurrent recall/write/revoke on this instance). Absent → ``False``. A
        durable DELETE that RAISES re-inserts the popped record and re-raises
        (``revoke`` returns nothing — a raise means "unconfirmed", not "forgotten").
        A DELETE matching 0 rows means no durable copy existed → no survivor →
        ``True``.

        Honest boundary: ``revoke`` governs THIS store INSTANCE only. It does NOT
        reach a vendor model's cache of a prior recall, any ``EvidenceRef`` already
        copied out, or a calibration contribution this correction fed (that is a
        SEPARATE cross-substrate edge: the route calls
        ``PresenceCalibrationFeed.forget_resolution`` for a decision-backed
        correction).
        """
        tenant = self._require_tenant(tenant)
        self._hydrate_tenant(tenant)
        with self._lock:
            bucket = self._mem.get(tenant)
            if not bucket or record_id not in bucket:
                return False
            fact = bucket.pop(record_id)

            if self._mirror is not None and self._mirror.is_durable:
                try:
                    removed = self._mirror.delete(tenant=tenant, record_id=record_id)
                except Exception:
                    bucket[record_id] = fact
                    _logger.exception(
                        "SealedProfileMemory: durable delete failed for %s; revoke "
                        "unconfirmed (in-memory entry restored)",
                        record_id,
                    )
                    raise
                if not removed:
                    _logger.debug(
                        "SealedProfileMemory: durable delete matched no row for %s "
                        "(no durable copy existed); revoke still complete",
                        record_id,
                    )
            return True

    # ------------------------------------------------------------------ helpers

    def get(self, *, tenant: str, record_id: str) -> SealedProfileFact | None:
        """Fetch the full sealed fact (incl. content payload + optional signature).
        Tenant-scoped."""
        tenant = self._require_tenant(tenant)
        self._hydrate_tenant(tenant)
        with self._lock:
            bucket = self._mem.get(tenant)
            return bucket.get(record_id) if bucket else None

    def verify(self, fact: SealedProfileFact) -> bool:
        """Re-verify a fact's content anchor (and signature if present) offline —
        recompute the canonical hash and compare. Never raises."""
        from tex.presence.profile.records import profile_fact_hash

        try:
            if profile_fact_hash(fact.content_payload) != fact.content_hash:
                return False
            if fact.pq_signature is not None:
                from tex.evidence.seal import verify_payload_signature

                payload = dict(fact.content_payload)
                payload["pq_signature"] = fact.pq_signature
                return verify_payload_signature(payload)
            return True
        except Exception:  # noqa: BLE001 — verification is total, never raises
            return False

    # ------------------------------------------------------------------ internals

    def _write(
        self,
        *,
        tenant: str,
        kind: ProfileFactKind,
        claim_id: str,
        corrected_tier: PresenceTier | None,
        statement: str,
        operator: str,
        original_tier: PresenceTier | None,
        decision_id: str | None,
        believed_value: str | None,
    ) -> EvidenceRef:
        self._hydrate_tenant(tenant)
        fact = SealedProfileFact.build(
            tenant=tenant,
            kind=kind,
            claim_id=claim_id,
            corrected_tier=corrected_tier,
            statement=statement,
            operator=operator,
            original_tier=original_tier,
            decision_id=decision_id,
            believed_value=believed_value,
            pq_signature=self._maybe_sign(
                tenant=tenant,
                kind=kind,
                claim_id=claim_id,
                corrected_tier=corrected_tier,
                statement=statement,
                operator=operator,
                original_tier=original_tier,
                decision_id=decision_id,
                believed_value=believed_value,
            ),
        )
        with self._lock:
            self._mem.setdefault(tenant, {})[fact.record_id] = fact
            if self._mirror is not None and self._mirror.is_durable:
                try:
                    self._mirror.upsert(fact)
                except Exception:
                    _logger.exception(
                        "SealedProfileMemory: durable upsert failed for %s "
                        "(in-memory write stands; row will not survive restart)",
                        fact.record_id,
                    )
        return fact.to_fact().as_ref()

    def _maybe_sign(
        self,
        *,
        tenant: str,
        kind: ProfileFactKind,
        claim_id: str,
        corrected_tier: PresenceTier | None,
        statement: str,
        operator: str,
        original_tier: PresenceTier | None,
        decision_id: str | None,
        believed_value: str | None,
    ) -> dict[str, Any] | None:
        """Attach a self-verifying signature block ONLY when sealing is enabled
        (``TEX_SEAL_DECISIONS=1``) and a signer was injected. Rides the SAME
        canonical content payload the anchor commits to (the ``tex.evidence.seal``
        signer — no new crypto)."""
        if self._signer is None or os.environ.get("TEX_SEAL_DECISIONS") != "1":
            return None
        try:
            payload = build_profile_payload(
                tenant=tenant,
                kind=kind,
                subject_key=_norm_subject(claim_id),
                corrected_tier=corrected_tier,
                statement=statement or "",
                operator=operator,
                original_tier=original_tier,
                decision_id=decision_id,
                believed_value=believed_value,
            )
            return self._signer.sign_payload(payload)
        except Exception:  # noqa: BLE001 — a signer fault must never break a write
            _logger.exception(
                "SealedProfileMemory: signer failed; writing fact with content "
                "anchor only (no signature)"
            )
            return None

    @staticmethod
    def _require_tenant(tenant: str) -> str:
        if not isinstance(tenant, str) or not tenant.strip():
            raise ValueError("profile memory requires a non-empty tenant")
        return tenant

    @staticmethod
    def _require_operator(operator: str) -> str:
        if not isinstance(operator, str) or not operator.strip():
            raise ValueError(
                "profile memory requires a non-empty operator — a correction/"
                "confirmation is a NAMED human act (provenance validated before write)"
            )
        return operator.strip()

    def _hydrate_tenant(self, tenant: str) -> None:
        """Lazily pull a single tenant's persisted facts into the authoritative
        dict the first time this process touches the tenant — so revoke/recall are
        sound across a restart (a durable row must be visible before revoke's
        membership check). Idempotent; in-memory entries win over a durable copy."""
        if self._mirror is None or not self._mirror.is_durable:
            return
        with self._lock:
            if tenant in self._hydrated:
                return
            try:
                rows = self._mirror.list_for_tenant(tenant)
            except Exception:
                _logger.exception(
                    "SealedProfileMemory: lazy hydrate failed for tenant %s", tenant
                )
                return
            bucket = self._mem.setdefault(tenant, {})
            for fact in rows:
                bucket.setdefault(fact.record_id, fact)
            self._hydrated.add(tenant)

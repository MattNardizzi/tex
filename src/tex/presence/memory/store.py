"""``SealedPresenceMemory`` — sealed, per-tenant, write-gated, FORGETTABLE memory.

This is where presence facts live: NEVER in model weights. The proposer (the
brain) is facts-in-prompt-only; nothing here is ever trained into a transformer.
That is what makes ``forget`` sound BY AVOIDANCE — there is no parametric copy to
unlearn, only this store's rows to delete. "Deletion from the external retrieval
store, never the weights" is a named technique for closed-source models
(arXiv:2410.15267, retrieved via this session's design survey); it is an
ARCHITECTURE guarantee over Tex's store, NOT certified machine-unlearning and NOT
a claim over a vendor model's KV-cache / prompt-logging of a prior ``recall``
result (outside Tex's boundary — disclosed, not controlled).

Authoritative tier = an in-memory ``dict[tenant][record_id]`` under one ``RLock``.
This is the source of truth so that ``forget`` returns a meaningful, testable
True/False with ``DATABASE_URL`` unset (the test/dev default). An OPTIONAL
:class:`~tex.presence.memory.durable.PresenceDurableMirror` adds cross-restart
durability; it is written through on seal and deleted-through on forget, and
hydrated on construction. ``recall`` reads the in-memory tier only (the voice
path is latency-sensitive; the gate refuses per-claim disk scans).

ISOLATION & SCOPE — honest edges, never overclaimed:
  * Per-tenant isolation is application-layer only: the dict outer key + every
    durable statement's ``WHERE tenant_id``. NO Postgres RLS, no schema
    partitioning, no encryption-at-rest. ``seal``/``recall``/``forget`` take the
    tenant as an explicit argument and NEVER from a payload, so a write cannot
    land cross-tenant — but a wrong ``tenant`` string crosses silently.
  * STRICT per-tenant: no cross-customer learning. One tenant's sealed facts are
    never visible to, or mixed into anything for, another tenant.
  * ``forget``'s True is scoped to THIS store instance. Horizontally-scaled
    workers each hold an independent authoritative dict, so a True on worker A
    does not bind worker B's copy; multi-worker deployments must route a tenant
    to one worker (or treat the durable mirror as authoritative, which this store
    deliberately does not). ``forget`` is also per-``record_id``, not fact-level:
    a concurrent re-seal under a new id survives.
"""

from __future__ import annotations

import logging
import os
import threading
from typing import Any

from tex.presence.contract import (
    EvidenceRef,
    PresenceClaim,
    PresenceTier,
    PresenceVerdict,
)
from tex.presence.memory.durable import PresenceDurableMirror
from tex.presence.memory.records import SealedPresenceRecord, is_sealable_tier

_logger = logging.getLogger(__name__)

# How many refs recall() returns at most — keeps the voice prompt bounded and
# matches the spirit of the gate's EVIDENCE_CAP.
_RECALL_CAP = 20


class SealedPresenceMemory:
    """Concrete :class:`tex.presence.contract.PresenceMemory`. Construct via
    :func:`tex.presence.memory.hooks.build_presence_memory` in the orchestrator;
    the live voice path never builds this itself."""

    def __init__(
        self,
        *,
        mirror: PresenceDurableMirror | None = None,
        signer: Any | None = None,
    ) -> None:
        # mirror: optional durability. signer: an EvidenceChainSigner-like object
        # exposing ``sign_payload(payload) -> dict``; injected by the orchestrator
        # ONLY when sealing is enabled, so seal() never mints/persists a key on
        # the hot path (key creation runs through the selfgov governor elsewhere).
        self._lock = threading.RLock()
        self._mem: dict[str, dict[str, SealedPresenceRecord]] = {}
        self._mirror = mirror
        self._signer = signer
        # Tenants already pulled from the durable mirror this process. Cross-restart
        # durability is LAZY (per-tenant on first touch) — boot stays cheap and we
        # never enumerate the whole multi-tenant table eagerly.
        self._hydrated: set[str] = set()

    # ------------------------------------------------------------------ protocol

    def seal(
        self, *, tenant: str, claim: PresenceClaim, verdict: PresenceVerdict
    ) -> EvidenceRef:
        """Write-gate a (claim → verdict) into per-tenant sealed memory and return
        its EvidenceRef. Fail-closed: refuses (raises ``ValueError``, writes
        NOTHING) when the write is not provably groundable.

        The gate, concretely:
          1. tenant must be a non-empty string (the only bucket key written).
          2. ``claim.claim_id == verdict.claim_id`` — the binding the gate emits.
          3. tier must be groundable — SEALED or DERIVED. An ABSTAIN verdict
             (``supports_speech() is False``; evidence empty iff ABSTAIN) is
             REFUSED: there is nothing proven to remember, and a remembered "we
             don't know" could later masquerade as a recalled fact.
          4. the verdict must carry at least one EvidenceRef — a tier that claims
             provability with zero evidence is incoherent.

        Sealing the optional ``pq_signature`` is separate and OFF unless
        ``TEX_SEAL_DECISIONS=1`` AND a signer was injected; the content anchor is
        always computed regardless.
        """
        tenant = self._require_tenant(tenant)
        self._hydrate_tenant(tenant)
        if claim.claim_id != verdict.claim_id:
            raise ValueError(
                f"seal: claim/verdict binding mismatch "
                f"({claim.claim_id!r} != {verdict.claim_id!r})"
            )
        if verdict.tier is PresenceTier.ABSTAIN or not is_sealable_tier(verdict.tier):
            raise ValueError(
                f"seal: refuse to seal a non-groundable tier {verdict.tier.value!r}; "
                "an ABSTAIN has nothing proven to remember"
            )
        if not verdict.evidence:
            raise ValueError(
                f"seal: refuse to seal tier {verdict.tier.value!r} with zero "
                "evidence — a groundable tier must bind at least one EvidenceRef"
            )

        record = SealedPresenceRecord.seal(
            tenant=tenant,
            claim=claim,
            verdict=verdict,
            pq_signature=self._maybe_sign(tenant=tenant, claim=claim, verdict=verdict),
        )

        with self._lock:
            self._mem.setdefault(tenant, {})[record.record_id] = record
            # Durability is best-effort on the WRITE path (the in-memory tier is
            # authoritative). A mirror failure logs but does not fail the seal —
            # unlike forget(), where a mirror failure MUST NOT report success.
            if self._mirror is not None and self._mirror.is_durable:
                try:
                    self._mirror.upsert(record)
                except Exception:
                    _logger.exception(
                        "SealedPresenceMemory: durable upsert failed for %s "
                        "(in-memory seal stands; row will not survive restart)",
                        record.record_id,
                    )
        return record.as_ref()

    def recall(self, *, tenant: str, query: str) -> tuple[EvidenceRef, ...]:
        """Return prior sealed EvidenceRefs for this tenant that the brain/gate
        can ground against. LEXICAL recall (substring token match), not semantic —
        a paraphrase sharing no token will not match (the safe direction: the gate
        re-derives / ABSTAINs rather than speaking an unmatched fact). Strictly
        tenant-scoped: tenant A can never recall tenant B's records.

        An empty/whitespace query returns this tenant's most-recent records (a
        "what do you have for me" default). Results are most-recent-first, capped.
        """
        tenant = self._require_tenant(tenant)
        self._hydrate_tenant(tenant)
        with self._lock:
            bucket = self._mem.get(tenant)
            records = tuple(bucket.values()) if bucket else ()

        # Newest first (sealed_at is ISO-8601 UTC → lexical sort is chronological).
        ordered = sorted(records, key=lambda r: r.sealed_at, reverse=True)

        tokens = [t for t in (query or "").casefold().split() if len(t) >= 2]
        if not tokens:
            hits = ordered
        else:
            hits = [r for r in ordered if any(t in r.searchable_text for t in tokens)]

        return tuple(r.as_ref() for r in hits[:_RECALL_CAP])

    def forget(self, *, tenant: str, record_id: str) -> bool:
        """Remove a record from this store. Returns True IFF the record was present
        in THIS store instance AND is now unrecoverable from it.

        Soundness (the one unrecoverable-lie risk, closed):
          * The membership check, pop, durable delete, and restore-on-failure all
            run inside ONE ``self._lock`` block, so that critical section is atomic
            against concurrent recall/seal/forget on this instance — no window where
            two callers both observe "present" and both return True, and none where
            recall sees a record forget already reported gone. (Lazy hydration runs
            under a prior, separately-acquired lock; the RLock is reentrant.)
          * If the record is absent → False (it was never present-then-removed).
          * If a durable mirror is configured, the row is deleted there too:
              - the DELETE RAISES (DB unreachable) → the popped record is
                RE-INSERTED and the exception re-raised; forget returns nothing.
                A raise means "forget unconfirmed", not "forgotten".
              - the DELETE matches 0 rows → no durable copy existed (e.g. a
                best-effort seal-time upsert that had silently failed), so there is
                no durable survivor; the record is gone from both tiers → True.
            This trusts the mirror's own DELETE semantics: the statement is
            tenant+record_id-scoped, so a 0 rowcount genuinely means no matching
            row, NOT a surviving row we failed to delete. We do not defend against a
            Byzantine mirror that reports deletion while retaining the row.

        Honest boundary (disclosed, not controlled): forget governs THIS store
        INSTANCE only. It does NOT reach model weights (nothing was written there —
        sound by avoidance), a vendor model's cache of a prior recall result, any
        EvidenceRef a caller already copied out, or rows in other stores (a cited
        Decision stays sealed in tex_decisions). True is scoped to this instance:
        in a multi-worker deployment another worker's hydrated copy is unaffected,
        and any calibration point the underlying decision produced is separate —
        call ``PresenceCalibrationFeed.forget_resolution`` for that.
        """
        tenant = self._require_tenant(tenant)
        self._hydrate_tenant(tenant)
        with self._lock:
            bucket = self._mem.get(tenant)
            if not bucket or record_id not in bucket:
                return False
            record = bucket.pop(record_id)

            if self._mirror is not None and self._mirror.is_durable:
                try:
                    removed = self._mirror.delete(tenant=tenant, record_id=record_id)
                except Exception:
                    # Do NOT lie: restore the authoritative entry and surface the
                    # failure. The record is still recoverable, so forget did not
                    # succeed.
                    bucket[record_id] = record
                    _logger.exception(
                        "SealedPresenceMemory: durable delete failed for %s; "
                        "forget unconfirmed (in-memory entry restored)",
                        record_id,
                    )
                    raise
                if not removed:
                    # In-memory had it but the mirror matched 0 rows — the durable
                    # copy was never persisted (best-effort seal-time upsert that
                    # failed). No durable survivor; forget still succeeds. Logged so
                    # an operator can spot a mirror that silently dropped writes.
                    _logger.debug(
                        "SealedPresenceMemory: durable delete matched no row for "
                        "%s (no durable copy existed); forget still complete",
                        record_id,
                    )
            return True

    # ------------------------------------------------------------------ helpers

    def get(self, *, tenant: str, record_id: str) -> SealedPresenceRecord | None:
        """Fetch the full sealed record (claim + verdict + underlying evidence +
        optional signature) so the brain can ground against the body a ref points
        at. Tenant-scoped."""
        tenant = self._require_tenant(tenant)
        self._hydrate_tenant(tenant)
        with self._lock:
            bucket = self._mem.get(tenant)
            return bucket.get(record_id) if bucket else None

    def verify(self, record: SealedPresenceRecord) -> bool:
        """Re-verify a record's content anchor (and signature if present) offline —
        recompute the canonical hash and compare. Used by tests/auditors to prove
        the anchor is honest. Never raises."""
        from tex.presence.memory.records import presence_record_hash

        try:
            if presence_record_hash(record.content_payload) != record.content_hash:
                return False
            if record.pq_signature is not None:
                from tex.evidence.seal import verify_payload_signature

                payload = dict(record.content_payload)
                payload["pq_signature"] = record.pq_signature
                return verify_payload_signature(payload)
            return True
        except Exception:  # noqa: BLE001 — verification is total, never raises
            return False

    def _maybe_sign(
        self, *, tenant: str, claim: PresenceClaim, verdict: PresenceVerdict
    ) -> dict[str, Any] | None:
        """Attach a self-verifying signature block ONLY when sealing is enabled
        (``TEX_SEAL_DECISIONS=1``) and a signer was injected. The block rides over
        the same canonical content payload the anchor commits to."""
        if self._signer is None or os.environ.get("TEX_SEAL_DECISIONS") != "1":
            return None
        from tex.presence.memory.records import build_content_payload

        try:
            payload = build_content_payload(tenant=tenant, claim=claim, verdict=verdict)
            return self._signer.sign_payload(payload)
        except Exception:  # noqa: BLE001 — a signer fault must never break a seal
            _logger.exception(
                "SealedPresenceMemory: signer failed; sealing record with content "
                "anchor only (no signature)"
            )
            return None

    @staticmethod
    def _require_tenant(tenant: str) -> str:
        if not isinstance(tenant, str) or not tenant.strip():
            raise ValueError("presence memory requires a non-empty tenant")
        return tenant

    def _hydrate_tenant(self, tenant: str) -> None:
        """Lazily pull a single tenant's persisted rows into the authoritative
        dict the first time this process touches the tenant. This is what keeps
        forget/recall sound across a restart: a durable row must be visible in the
        authoritative tier before forget's membership check, else forget would
        wrongly report False for a record that is still recoverable. Idempotent;
        in-memory entries win over a (possibly stale) durable copy."""
        if self._mirror is None or not self._mirror.is_durable:
            return
        with self._lock:
            if tenant in self._hydrated:
                return
            try:
                rows = self._mirror.list_for_tenant(tenant)
            except Exception:
                _logger.exception(
                    "SealedPresenceMemory: lazy hydrate failed for tenant %s", tenant
                )
                return
            bucket = self._mem.setdefault(tenant, {})
            for rec in rows:
                bucket.setdefault(rec.record_id, rec)
            self._hydrated.add(tenant)

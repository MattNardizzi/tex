"""History sources — turn a tenant's REAL sealed stores into observations.

The miner is source-agnostic (it consumes :class:`~tex.presence.habits.types.HistorySource`)
so the same deterministic statistics run over whatever sealed history the
orchestrator has: S5 presence memory (shipped here), or an orchestrator-provided
adapter over governance resolutions (documented below). An adapter NEVER infers —
it reads values already present in a record and attaches the record's own
``EvidenceRef`` as the receipt, so every observation is re-verifiable.

PER-TENANT, ALWAYS. Each adapter takes the tenant explicitly and queries only that
tenant's rows; one tenant's history can never become another's observations.
"""

from __future__ import annotations

import logging
from typing import Any, Iterable

from tex.presence.contract import EvidenceRef

from tex.presence.habits.types import ObservedOutcome, OutcomeDimension, norm_subject

_logger = logging.getLogger(__name__)

__all__ = [
    "IterableHistorySource",
    "S5MemoryHistorySource",
    "ProfileCorrectionHistorySource",
    "CompositeHistorySource",
]


class IterableHistorySource:
    """Wrap a pre-built iterable of observations as a :class:`HistorySource`. The
    orchestrator uses this to inject observations from a store L3 does not own (e.g.
    governance ``Decision`` resolutions): map each row to an :class:`ObservedOutcome`
    whose ``evidence`` points at the real sealed record, then hand the list here."""

    def __init__(self, observations: Iterable[ObservedOutcome]) -> None:
        # The caller must build one instance per tenant (an ObservedOutcome carries
        # no tenant field — its tenant is implicit in its evidence). This raw adapter
        # filters nothing; per-tenant correctness is the caller's contract.
        self._observations = tuple(observations)

    def outcomes(self, *, tenant: str) -> tuple[ObservedOutcome, ...]:  # noqa: ARG002
        return self._observations


class CompositeHistorySource:
    """Concatenate several per-tenant sources into one. A source that raises is
    skipped (logged), never fatal — one faulty adapter must not blind the miner to
    the others. De-duplication of identical records is the miner's job, so simple
    concatenation here is safe."""

    def __init__(self, *sources: Any) -> None:
        self._sources = tuple(s for s in sources if s is not None)

    def outcomes(self, *, tenant: str) -> tuple[ObservedOutcome, ...]:
        out: list[ObservedOutcome] = []
        for s in self._sources:
            try:
                out.extend(s.outcomes(tenant=tenant))
            except Exception:  # noqa: BLE001
                _logger.warning("habit source: composite member %r failed", type(s).__name__, exc_info=True)
        return tuple(out)


class S5MemoryHistorySource:
    """Mine a tenant's :class:`tex.presence.memory.SealedPresenceMemory`.

    Reads via the store's public, tenant-scoped API only — ``recall(tenant, "")``
    for the refs, then ``get(tenant, record_id)`` for each record's canonical
    ``content_payload``. From each sealed record it emits up to two observations:
    the governance verdict it carried (if any) and the presence tier it was spoken
    at.

    HONEST EDGE — the recall cap. S5's ``recall`` returns at most ``_RECALL_CAP``
    (20) records, newest-first, so this source sees at most a tenant's 20 most
    recent sealed facts. That is enough to detect a strong recent habit and keeps
    the surface honest about its window; it is NOT a full-history scan. Lifting it
    cleanly would need a ``list_records(tenant)`` method on S5 (out of L3's lane);
    until then, an orchestrator wanting deeper history injects an
    :class:`IterableHistorySource` built from its own full store.
    """

    def __init__(self, memory: Any) -> None:
        # Duck-typed: anything exposing recall(tenant, query) -> (EvidenceRef,...)
        # and get(tenant, record_id) -> record-with-.content_payload/.sealed_at.
        self._mem = memory

    def outcomes(self, *, tenant: str) -> tuple[ObservedOutcome, ...]:
        if not tenant or not tenant.strip():
            raise ValueError("S5MemoryHistorySource requires a non-empty tenant")
        try:
            refs = self._mem.recall(tenant=tenant, query="")
        except Exception:  # noqa: BLE001
            _logger.warning("habit source: presence recall failed for %r", tenant, exc_info=True)
            return ()

        out: list[ObservedOutcome] = []
        for ref in refs:
            record = self._safe_get(tenant=tenant, record_id=ref.record_id)
            if record is None:
                continue
            payload = getattr(record, "content_payload", None) or {}
            verdict = payload.get("verdict") if isinstance(payload, dict) else None
            if not isinstance(verdict, dict):
                continue
            claim = payload.get("claim") if isinstance(payload, dict) else None
            claim_id = (claim or {}).get("claim_id") if isinstance(claim, dict) else None
            subject = norm_subject(claim_id or ref.field or "")
            if not subject:
                continue
            evidence = self._record_ref(record, ref)
            observed_at = getattr(record, "sealed_at", "") or ""

            gov = verdict.get("governance_verdict")
            if isinstance(gov, str) and gov.strip():
                out.append(
                    ObservedOutcome(
                        subject_key=subject,
                        dimension=OutcomeDimension.GOVERNANCE_VERDICT,
                        outcome_value=gov.strip().casefold(),
                        evidence=evidence,
                        observed_at=observed_at,
                    )
                )
            tier = verdict.get("tier")
            if isinstance(tier, str) and tier.strip():
                out.append(
                    ObservedOutcome(
                        subject_key=subject,
                        dimension=OutcomeDimension.TIER,
                        outcome_value=tier.strip().casefold(),
                        evidence=evidence,
                        observed_at=observed_at,
                    )
                )
        return tuple(out)

    def _safe_get(self, *, tenant: str, record_id: str) -> Any:
        try:
            return self._mem.get(tenant=tenant, record_id=record_id)
        except Exception:  # noqa: BLE001
            _logger.warning("habit source: presence get failed for %r", record_id, exc_info=True)
            return None

    @staticmethod
    def _record_ref(record: Any, fallback: EvidenceRef) -> EvidenceRef:
        as_ref = getattr(record, "as_ref", None)
        if callable(as_ref):
            try:
                return as_ref()
            except Exception:  # noqa: BLE001
                pass
        return fallback


class ProfileCorrectionHistorySource:
    """Mine a tenant's L2 CORRECTION facts (the ``correction_tier`` dimension):
    "you keep correcting X to <tier>". Reads ``profile.recall_profile(tenant)``,
    duck-typed, and emits one observation per active correction.

    NOTE on value: L2 corrections are EXACT-subject, so this surfaces a pattern only
    when the SAME subject was corrected repeatedly (>= min_support) — useful for
    spotting a recurring manual tightening the operator could codify once. It does
    NOT generalise across different subjects (L3 groups by exact subject_key, the
    same handle L2 keys on)."""

    def __init__(self, profile: Any) -> None:
        self._profile = profile

    def outcomes(self, *, tenant: str) -> tuple[ObservedOutcome, ...]:
        if not tenant or not tenant.strip():
            raise ValueError("ProfileCorrectionHistorySource requires a non-empty tenant")
        try:
            facts = self._profile.recall_profile(tenant=tenant)
            corrections = facts.corrections()
        except Exception:  # noqa: BLE001
            _logger.warning("habit source: profile recall failed for %r", tenant, exc_info=True)
            return ()

        out: list[ObservedOutcome] = []
        for fact in corrections:
            tier = getattr(fact, "corrected_tier", None)
            if tier is None:
                continue
            tier_value = getattr(tier, "value", str(tier)).strip().casefold()
            subject = norm_subject(getattr(fact, "subject_key", "") or "")
            if not subject:
                continue
            try:
                evidence = fact.as_ref()
            except Exception:  # noqa: BLE001
                continue
            out.append(
                ObservedOutcome(
                    subject_key=subject,
                    dimension=OutcomeDimension.CORRECTION_TIER,
                    outcome_value=tier_value,
                    evidence=evidence,
                    observed_at=getattr(fact, "created_at", "") or "",
                )
            )
        return tuple(out)

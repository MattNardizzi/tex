"""
Calibration proposal store.

Persists pending and historical CalibrationProposal records and gates the
lifecycle transitions (PENDING → APPROVED/REJECTED → APPLIED → ROLLED_BACK).

Every transition is logged with approver identity and timestamp. The store
NEVER mutates the underlying policy itself — that's the orchestrator's
job. The store's contract is "make sure only valid transitions happen,
and make sure they're auditable."

Persistence model
-----------------
Same write-through pattern as DriftEventStore / GovernanceSnapshotStore:

  - in-memory dict + ordered id list serve as a hot cache for reads
  - every mutation writes through to Postgres if DATABASE_URL is set
  - on startup with a configured DSN, the cache is hydrated from
    Postgres so restarts don't lose pending proposals
  - if Postgres is unreachable at startup, we fall back to pure
    in-memory mode and log loudly

Schema
------
Two tables:
  tex_calibration_proposals       — current state row per proposal
  tex_calibration_proposal_events — append-only audit trail (every
                                    state transition with actor + ts)

The audit trail is the durable record of "who approved what when",
which is the part you actually need for compliance.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Iterable
from datetime import UTC, datetime
from threading import RLock
from typing import Any
from uuid import UUID

import psycopg
from psycopg.types.json import Jsonb

from tex.domain.calibration_proposal import (
    CalibrationProposal,
    ProposalStatus,
)

_logger = logging.getLogger(__name__)

DATABASE_URL_ENV = "DATABASE_URL"


class ProposalNotFoundError(KeyError):
    pass


class InvalidProposalTransitionError(RuntimeError):
    pass


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS tex_calibration_proposals (
    proposal_id              UUID PRIMARY KEY,
    tenant_id                TEXT,
    source_policy_id         TEXT NOT NULL,
    source_policy_version    TEXT NOT NULL,
    proposed_new_version     TEXT NOT NULL,
    status                   TEXT NOT NULL,
    created_by               TEXT NOT NULL,
    created_at               TIMESTAMPTZ NOT NULL,
    approved_by              TEXT,
    approved_at              TIMESTAMPTZ,
    rejected_by              TEXT,
    rejected_at              TIMESTAMPTZ,
    rejection_reason         TEXT,
    applied_at               TIMESTAMPTZ,
    applied_policy_version   TEXT,
    rolled_back_by           TEXT,
    rolled_back_at           TIMESTAMPTZ,
    rollback_target_version  TEXT,
    safety_adjusted          BOOLEAN NOT NULL DEFAULT FALSE,
    payload                  JSONB NOT NULL,
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS tex_calibration_proposals_tenant_idx
    ON tex_calibration_proposals (tenant_id, created_at DESC);

CREATE INDEX IF NOT EXISTS tex_calibration_proposals_status_idx
    ON tex_calibration_proposals (status, created_at DESC);

CREATE INDEX IF NOT EXISTS tex_calibration_proposals_source_idx
    ON tex_calibration_proposals (source_policy_version);

CREATE TABLE IF NOT EXISTS tex_calibration_proposal_events (
    event_id      UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    proposal_id   UUID NOT NULL REFERENCES tex_calibration_proposals(proposal_id) ON DELETE CASCADE,
    occurred_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    transition    TEXT NOT NULL,
    actor         TEXT NOT NULL,
    detail        JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS tex_calibration_proposal_events_proposal_idx
    ON tex_calibration_proposal_events (proposal_id, occurred_at DESC);
"""


class CalibrationProposalStore:
    """
    Calibration proposal store with optional Postgres persistence.

    When ``DATABASE_URL`` is set, mutations write through to Postgres
    and the cache is hydrated from Postgres on startup. When unset, the
    store runs in pure in-memory mode (suitable for local dev and tests).
    """

    __slots__ = (
        "_lock",
        "_by_id",
        "_ordered_ids",
        "_clock",
        "_dsn",
        "_disabled",
    )

    def __init__(
        self,
        *,
        initial_proposals: Iterable[CalibrationProposal] | None = None,
        clock: callable | None = None,
        dsn: str | None = None,
    ) -> None:
        self._lock = RLock()
        self._by_id: dict[UUID, CalibrationProposal] = {}
        self._ordered_ids: list[UUID] = []
        self._clock = clock or (lambda: datetime.now(UTC))
        self._dsn = (
            dsn if dsn is not None else os.environ.get(DATABASE_URL_ENV, "")
        ).strip()
        self._disabled = not bool(self._dsn)

        if self._disabled:
            _logger.info(
                "CalibrationProposalStore: %s not set; running in pure "
                "in-memory mode.",
                DATABASE_URL_ENV,
            )
        else:
            try:
                self._ensure_schema()
                self._hydrate_from_postgres()
            except Exception as exc:  # noqa: BLE001
                _logger.error(
                    "CalibrationProposalStore: bootstrap failed: %s. "
                    "Falling back to in-memory mode.",
                    exc,
                )
                self._disabled = True

        if initial_proposals:
            for p in initial_proposals:
                self.save(p)

    # ── basic CRUD ──────────────────────────────────────────────────────

    def save(self, proposal: CalibrationProposal) -> None:
        with self._lock:
            if proposal.proposal_id not in self._by_id:
                self._ordered_ids.append(proposal.proposal_id)
            self._by_id[proposal.proposal_id] = proposal
            if not self._disabled:
                try:
                    self._upsert_postgres(proposal)
                    self._record_event(
                        proposal_id=proposal.proposal_id,
                        transition=f"saved:{proposal.status.value}",
                        actor=proposal.created_by,
                        detail={"new_status": proposal.status.value},
                    )
                except Exception as exc:  # noqa: BLE001
                    _logger.error(
                        "CalibrationProposalStore: write failed for "
                        "proposal=%s: %s",
                        proposal.proposal_id, exc,
                    )

    def get(self, proposal_id: UUID) -> CalibrationProposal | None:
        with self._lock:
            return self._by_id.get(proposal_id)

    def require(self, proposal_id: UUID) -> CalibrationProposal:
        proposal = self.get(proposal_id)
        if proposal is None:
            raise ProposalNotFoundError(f"proposal not found: {proposal_id}")
        return proposal

    def list_pending(
        self, *, tenant_id: str | None = None
    ) -> tuple[CalibrationProposal, ...]:
        return self._list_filtered(status=ProposalStatus.PENDING, tenant_id=tenant_id)

    def list_for_tenant(
        self, tenant_id: str, *, limit: int | None = None
    ) -> tuple[CalibrationProposal, ...]:
        with self._lock:
            results = [
                self._by_id[pid]
                for pid in reversed(self._ordered_ids)
                if self._by_id[pid].tenant_id == tenant_id
            ]
            if limit is not None:
                results = results[:limit]
            return tuple(results)

    def list_recent(
        self, *, limit: int = 50
    ) -> tuple[CalibrationProposal, ...]:
        with self._lock:
            ids = list(reversed(self._ordered_ids[-limit:]))
            return tuple(self._by_id[pid] for pid in ids)

    def _list_filtered(
        self, *, status: ProposalStatus, tenant_id: str | None
    ) -> tuple[CalibrationProposal, ...]:
        with self._lock:
            results: list[CalibrationProposal] = []
            for pid in reversed(self._ordered_ids):
                p = self._by_id[pid]
                if p.status is not status:
                    continue
                if tenant_id is not None and p.tenant_id != tenant_id:
                    continue
                results.append(p)
            return tuple(results)

    # ── lifecycle ───────────────────────────────────────────────────────

    def approve(
        self,
        *,
        proposal_id: UUID,
        approver: str,
    ) -> CalibrationProposal:
        normalized = (approver or "").strip()
        if not normalized:
            raise ValueError("approver must be a non-blank string")

        with self._lock:
            current = self.require(proposal_id)
            if current.status is not ProposalStatus.PENDING:
                raise InvalidProposalTransitionError(
                    f"only PENDING proposals can be approved (was {current.status.value})"
                )
            updated = current.model_copy(
                update={
                    "status": ProposalStatus.APPROVED,
                    "approved_by": normalized,
                    "approved_at": self._clock(),
                }
            )
            self._by_id[proposal_id] = updated
            self._persist_transition(
                updated,
                transition="approved",
                actor=normalized,
                detail={},
            )
            return updated

    def reject(
        self,
        *,
        proposal_id: UUID,
        rejecter: str,
        reason: str,
    ) -> CalibrationProposal:
        normalized = (rejecter or "").strip()
        if not normalized:
            raise ValueError("rejecter must be a non-blank string")
        normalized_reason = (reason or "").strip()
        if not normalized_reason:
            raise ValueError("rejection reason must be a non-blank string")

        with self._lock:
            current = self.require(proposal_id)
            if current.status is not ProposalStatus.PENDING:
                raise InvalidProposalTransitionError(
                    f"only PENDING proposals can be rejected (was {current.status.value})"
                )
            updated = current.model_copy(
                update={
                    "status": ProposalStatus.REJECTED,
                    "rejected_by": normalized,
                    "rejected_at": self._clock(),
                    "rejection_reason": normalized_reason,
                }
            )
            self._by_id[proposal_id] = updated
            self._persist_transition(
                updated,
                transition="rejected",
                actor=normalized,
                detail={"reason": normalized_reason},
            )
            return updated

    def mark_applied(
        self,
        *,
        proposal_id: UUID,
        applied_policy_version: str,
    ) -> CalibrationProposal:
        normalized_version = (applied_policy_version or "").strip()
        if not normalized_version:
            raise ValueError("applied_policy_version must be non-blank")

        with self._lock:
            current = self.require(proposal_id)
            if current.status is not ProposalStatus.APPROVED:
                raise InvalidProposalTransitionError(
                    f"only APPROVED proposals can be applied (was {current.status.value})"
                )
            updated = current.model_copy(
                update={
                    "status": ProposalStatus.APPLIED,
                    "applied_at": self._clock(),
                    "applied_policy_version": normalized_version,
                    "rollback_target_version": current.source_policy_version,
                }
            )
            self._by_id[proposal_id] = updated
            self._persist_transition(
                updated,
                transition="applied",
                actor=updated.approved_by or "system",
                detail={"applied_policy_version": normalized_version},
            )
            return updated

    def mark_rolled_back(
        self,
        *,
        proposal_id: UUID,
        rolled_back_by: str,
    ) -> CalibrationProposal:
        normalized = (rolled_back_by or "").strip()
        if not normalized:
            raise ValueError("rolled_back_by must be a non-blank string")

        with self._lock:
            current = self.require(proposal_id)
            if current.status is not ProposalStatus.APPLIED:
                raise InvalidProposalTransitionError(
                    f"only APPLIED proposals can be rolled back (was {current.status.value})"
                )
            updated = current.model_copy(
                update={
                    "status": ProposalStatus.ROLLED_BACK,
                    "rolled_back_by": normalized,
                    "rolled_back_at": self._clock(),
                }
            )
            self._by_id[proposal_id] = updated
            self._persist_transition(
                updated,
                transition="rolled_back",
                actor=normalized,
                detail={
                    "rollback_target_version": updated.rollback_target_version,
                },
            )
            return updated

    def mark_expired(self, *, proposal_id: UUID) -> CalibrationProposal:
        with self._lock:
            current = self.require(proposal_id)
            if current.status is not ProposalStatus.PENDING:
                raise InvalidProposalTransitionError(
                    f"only PENDING proposals can expire (was {current.status.value})"
                )
            updated = current.model_copy(update={"status": ProposalStatus.EXPIRED})
            self._by_id[proposal_id] = updated
            self._persist_transition(
                updated, transition="expired", actor="system", detail={}
            )
            return updated

    def __len__(self) -> int:
        with self._lock:
            return len(self._by_id)

    @property
    def is_durable(self) -> bool:
        return not self._disabled

    # ── postgres internals ──────────────────────────────────────────────

    def _ensure_schema(self) -> None:
        with psycopg.connect(self._dsn, autocommit=True) as conn:
            with conn.cursor() as cur:
                cur.execute(SCHEMA_SQL)

    def _hydrate_from_postgres(self) -> None:
        """Load all proposals into the in-memory cache on startup."""
        with psycopg.connect(self._dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT proposal_id, payload
                      FROM tex_calibration_proposals
                     ORDER BY created_at ASC
                    """
                )
                rows = cur.fetchall()
        loaded = 0
        for proposal_id, payload in rows:
            try:
                proposal = CalibrationProposal.model_validate(payload)
            except Exception as exc:  # noqa: BLE001
                _logger.error(
                    "CalibrationProposalStore: failed to hydrate proposal %s: %s",
                    proposal_id, exc,
                )
                continue
            self._by_id[proposal.proposal_id] = proposal
            self._ordered_ids.append(proposal.proposal_id)
            loaded += 1
        if loaded:
            _logger.info(
                "CalibrationProposalStore: hydrated %d proposals from Postgres.",
                loaded,
            )

    def _persist_transition(
        self,
        proposal: CalibrationProposal,
        *,
        transition: str,
        actor: str,
        detail: dict[str, Any],
    ) -> None:
        if self._disabled:
            return
        try:
            self._upsert_postgres(proposal)
            self._record_event(
                proposal_id=proposal.proposal_id,
                transition=transition,
                actor=actor,
                detail=detail,
            )
        except Exception as exc:  # noqa: BLE001
            _logger.error(
                "CalibrationProposalStore: transition write failed "
                "(proposal=%s, transition=%s): %s",
                proposal.proposal_id, transition, exc,
            )

    def _upsert_postgres(self, proposal: CalibrationProposal) -> None:
        payload = proposal.model_dump(mode="json")
        with psycopg.connect(self._dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO tex_calibration_proposals (
                        proposal_id, tenant_id,
                        source_policy_id, source_policy_version,
                        proposed_new_version, status,
                        created_by, created_at,
                        approved_by, approved_at,
                        rejected_by, rejected_at, rejection_reason,
                        applied_at, applied_policy_version,
                        rolled_back_by, rolled_back_at, rollback_target_version,
                        safety_adjusted, payload, updated_at
                    ) VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, now()
                    )
                    ON CONFLICT (proposal_id) DO UPDATE SET
                        status                  = EXCLUDED.status,
                        approved_by             = EXCLUDED.approved_by,
                        approved_at             = EXCLUDED.approved_at,
                        rejected_by             = EXCLUDED.rejected_by,
                        rejected_at             = EXCLUDED.rejected_at,
                        rejection_reason        = EXCLUDED.rejection_reason,
                        applied_at              = EXCLUDED.applied_at,
                        applied_policy_version  = EXCLUDED.applied_policy_version,
                        rolled_back_by          = EXCLUDED.rolled_back_by,
                        rolled_back_at          = EXCLUDED.rolled_back_at,
                        rollback_target_version = EXCLUDED.rollback_target_version,
                        safety_adjusted         = EXCLUDED.safety_adjusted,
                        payload                 = EXCLUDED.payload,
                        updated_at              = now()
                    """,
                    (
                        str(proposal.proposal_id),
                        proposal.tenant_id,
                        proposal.source_policy_id,
                        proposal.source_policy_version,
                        proposal.proposed_new_version,
                        proposal.status.value,
                        proposal.created_by,
                        proposal.created_at,
                        proposal.approved_by,
                        proposal.approved_at,
                        proposal.rejected_by,
                        proposal.rejected_at,
                        proposal.rejection_reason,
                        proposal.applied_at,
                        proposal.applied_policy_version,
                        proposal.rolled_back_by,
                        proposal.rolled_back_at,
                        proposal.rollback_target_version,
                        proposal.safety_adjusted,
                        Jsonb(payload),
                    ),
                )
            conn.commit()

    def _record_event(
        self,
        *,
        proposal_id: UUID,
        transition: str,
        actor: str,
        detail: dict[str, Any],
    ) -> None:
        if self._disabled:
            return
        with psycopg.connect(self._dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO tex_calibration_proposal_events
                        (proposal_id, transition, actor, detail)
                    VALUES (%s, %s, %s, %s)
                    """,
                    (str(proposal_id), transition, actor, Jsonb(detail)),
                )
            conn.commit()

    def list_audit_trail(
        self, proposal_id: UUID, *, limit: int = 50
    ) -> list[dict[str, Any]]:
        """
        Return the audit trail for a proposal (all state transitions).

        In durable mode this hits Postgres directly. In in-memory mode it
        returns an empty list — we don't keep an in-memory mirror of the
        event log because only durable mode needs the audit trail.
        """
        if self._disabled:
            return []
        try:
            with psycopg.connect(self._dsn) as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT event_id, occurred_at, transition, actor, detail
                          FROM tex_calibration_proposal_events
                         WHERE proposal_id = %s
                         ORDER BY occurred_at DESC
                         LIMIT %s
                        """,
                        (str(proposal_id), limit),
                    )
                    rows = cur.fetchall()
            return [
                {
                    "event_id": str(r[0]),
                    "occurred_at": r[1].isoformat(),
                    "transition": r[2],
                    "actor": r[3],
                    "detail": r[4] or {},
                }
                for r in rows
            ]
        except Exception as exc:  # noqa: BLE001
            _logger.error(
                "CalibrationProposalStore: audit trail read failed for %s: %s",
                proposal_id, exc,
            )
            return []


__all__ = [
    "CalibrationProposalStore",
    "DATABASE_URL_ENV",
    "InvalidProposalTransitionError",
    "ProposalNotFoundError",
]

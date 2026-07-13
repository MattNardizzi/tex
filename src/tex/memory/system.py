"""
MemorySystem — the unified entry point for Tex's memory layer.

The locked spec describes Tex as a system of record. This module is
that system's public face. Every aggregate the spec lists has a
purpose-built store; ``MemorySystem`` is the only thing the rest of
Tex needs to import.

Spec invariants this module enforces
------------------------------------
  - § 3 Write-through pattern: every ``record_decision`` writes the
    durable decision row first, then the input row, then the evidence
    chain entry. A failure at any step raises and the caller is
    responsible (no silent degradation).

  - § 4 Read pattern: cache-first reads via the underlying stores.
    Postgres is consulted on miss.

  - § 5 Evidence log: append-only JSONL chain (existing recorder) plus
    Postgres mirror (DurableEvidenceStore). Both are written on every
    decision.

  - § 6 Replay: ``MemoryReplayEngine`` (in tex.memory.replay) loads
    decision + policy snapshot + original input and re-runs the
    evaluation deterministically.

  - § 8 Critical rules: every record is linked by IDs (decision_id,
    request_id, policy_version, permit_id). Orphaned writes are
    impossible because the orchestrator wires the IDs itself.

  - § 9 Avoid: no vector DB, no streaming bus, no second SoR. Postgres
    is the only durable store. The JSONL chain is a tamper-evident
    audit, not a competing source of truth.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any
from uuid import UUID

import psycopg

from tex.domain.decision import Decision
from tex.domain.evidence import EvidenceRecord
from tex.domain.outcome import OutcomeRecord
from tex.domain.policy import PolicySnapshot
from tex.evidence.recorder import EvidenceRecorder
from tex.memory._db import connect_tx, database_url, ensure_memory_schema
from tex.memory.decision_input_store import DecisionInputStore
from tex.memory.decision_store import DurableDecisionStore
from tex.memory.evidence_store import DurableEvidenceStore
from tex.memory.permit_store import PermitStore, StoredPermit
from tex.memory.policy_snapshot_store import DurablePolicyStore
from tex.memory.verification_store import (
    StoredVerification,
    VerificationResult,
    VerificationStore,
)

_logger = logging.getLogger(__name__)

# TEX_REQUIRE_DURABLE=1 restores strict write-through: a Postgres failure
# during decision persistence raises (and the PDP fails closed) instead of
# degrading to in-memory persistence. Default is to degrade — fail-closed is
# for adjudication errors, not audit-persistence errors; a dead database
# must never convert every verdict into FORBID (prod incident 2026-07-13).
_REQUIRE_DURABLE_ENV = "TEX_REQUIRE_DURABLE"

# Once degraded, remind operators at most this often that decisions are
# still buffered in-memory only. Entry into degraded mode always logs;
# this bounds the per-call repetition.
_DEGRADED_REMINDER_INTERVAL_S = 300.0


def _require_durable() -> bool:
    raw = os.environ.get(_REQUIRE_DURABLE_ENV, "")
    return raw.strip().lower() in {"1", "true", "yes"}


@dataclass(frozen=True, slots=True)
class MemoryHealth:
    """Snapshot of memory-system durability for `/health` endpoints."""

    durable: bool
    decisions_durable: bool
    inputs_durable: bool
    policies_durable: bool
    permits_durable: bool
    verifications_durable: bool
    evidence_mirror_durable: bool
    evidence_chain_path: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "durable": self.durable,
            "decisions_durable": self.decisions_durable,
            "inputs_durable": self.inputs_durable,
            "policies_durable": self.policies_durable,
            "permits_durable": self.permits_durable,
            "verifications_durable": self.verifications_durable,
            "evidence_mirror_durable": self.evidence_mirror_durable,
            "evidence_chain_path": self.evidence_chain_path,
        }


@dataclass(slots=True)
class MemorySystem:
    """
    Unified facade for the durable memory layer.

    The constructor wires every store with the same tenant_id and the
    evidence recorder pointing at the configured JSONL path. Every
    public method is the canonical way the rest of Tex talks to memory.
    """

    tenant_id: str = "default"
    evidence_path: str | Path = field(
        default_factory=lambda: Path("./data/evidence.jsonl"),
    )

    # Stores — populated in __post_init__ so dataclass keeps it ergonomic.
    decisions: DurableDecisionStore = field(init=False)
    inputs: DecisionInputStore = field(init=False)
    policies: DurablePolicyStore = field(init=False)
    permits: PermitStore = field(init=False)
    verifications: VerificationStore = field(init=False)
    evidence_mirror: DurableEvidenceStore = field(init=False)
    recorder: EvidenceRecorder = field(init=False)

    # Degraded-mode state — set when DATABASE_URL is configured but the
    # database is unreachable (detected at boot or on a per-call error).
    _degraded: bool = field(init=False, default=False)
    _degraded_log_at: float = field(init=False, default=0.0)
    _degraded_lock: threading.Lock = field(
        init=False, default_factory=threading.Lock
    )

    def __post_init__(self) -> None:
        # Apply migrations exactly once on first construction. Each
        # store would do it on its own anyway, but doing it here
        # surfaces schema errors at startup rather than on first write.
        if database_url() is not None:
            try:
                ensure_memory_schema()
            except Exception:
                _logger.exception(
                    "MemorySystem: master schema bootstrap failed; "
                    "individual stores will retry"
                )

        self.decisions = DurableDecisionStore(tenant_id=self.tenant_id)
        self.inputs = DecisionInputStore(tenant_id=self.tenant_id)
        self.policies = DurablePolicyStore(tenant_id=self.tenant_id)
        self.permits = PermitStore(tenant_id=self.tenant_id)
        self.verifications = VerificationStore(tenant_id=self.tenant_id)
        self.evidence_mirror = DurableEvidenceStore(tenant_id=self.tenant_id)
        self.recorder = EvidenceRecorder(self.evidence_path)

        # Boot-time degraded detection (prod incident 2026-07-13): when
        # DATABASE_URL is configured but the decision store came up
        # cache-only (its own schema bootstrap already retried and failed),
        # the database is unreachable. record_decision_with_policy must not
        # keep opening per-call transactions against it — each attempt
        # costs a connect timeout, and the raise converts every verdict
        # into the PDP's FORBID floor.
        if (
            database_url() is not None
            and not self.decisions.is_durable
            and not _require_durable()
        ):
            self._enter_degraded_mode(None)

    # ---- core write paths --------------------------------------------

    def record_decision(
        self,
        *,
        decision: Decision,
        full_input: dict[str, Any],
        evidence_metadata: dict[str, Any] | None = None,
    ) -> EvidenceRecord:
        """
        Records a decision through every layer in the correct order:

            1. Durable decision row              (tex_decisions)
            2. Full input row keyed by request   (tex_decision_inputs)
            3. Append-only evidence chain        (JSONL)
            4. Postgres mirror of the chain      (tex_evidence_records)

        Returns the freshly written EvidenceRecord so the caller can
        echo the evidence hash back to the API client.

        Spec rule §3: failure at any step aborts. No silent half-writes.
        """
        # 1. durable decision
        self.decisions.save(decision)

        # 2. input payload, linked back to the decision id
        self.inputs.save(
            request_id=decision.request_id,
            full_input=full_input,
            decision_id=decision.decision_id,
        )

        # 3. JSONL chain
        evidence = self.recorder.record_decision(
            decision, metadata=evidence_metadata
        )

        # 4. Postgres mirror
        self.evidence_mirror.mirror_record(
            evidence,
            kind="decision",
            aggregate_id=decision.decision_id,
        )
        return evidence

    def record_decision_with_policy(
        self,
        *,
        decision: Decision,
        full_input: dict[str, Any],
        policy: PolicySnapshot,
        evidence_metadata: dict[str, Any] | None = None,
    ) -> EvidenceRecord:
        """
        Atomic, fully-linked write path. This is the canonical entry point
        for the runtime — it satisfies every locked-spec invariant in one
        call:

          - § "Decision input not guaranteed":
              the input row is written in the SAME transaction as the
              decision row. Schema is validated up-front (full_input must
              be a dict). Replay can never miss the input.

          - § "Policy snapshot not strictly enforced":
              the policy snapshot is upserted in the SAME transaction.
              Replay can always reconstitute the exact policy that
              produced the decision, even on a fresh process.

          - § "No transactional guarantee":
              decision + input + policy_snapshot are written in ONE
              Postgres transaction. Either all three commit or none of
              them do.

          - § "Evidence system is split":
              the JSONL chain is appended AFTER the Postgres transaction
              commits, then the Postgres mirror is written. The recorder
              is the single writer for the JSONL chain; the mirror is a
              read replica with idempotent inserts (``ON CONFLICT DO
              NOTHING`` on record_hash). One ``record_decision_with_policy``
              call therefore writes ALL four artefacts.

          - § "Critical rules — no orphan records":
              decision_id ↔ request_id ↔ policy_version are all wired by
              the orchestrator itself; callers cannot accidentally
              produce a partial graph.

        Failure semantics:
          * Postgres tx fails with a database error (dead/unreachable DB,
            missing schema) → DEGRADED mode: the write falls back to the
            in-memory cache path below, one loud rate-limited error is
            logged, and the memory layer stays cache-only until restart.
            Governance keeps adjudicating — fail-closed applies to
            adjudication errors, not audit-persistence errors (prod
            incident 2026-07-13). Set TEX_REQUIRE_DURABLE=1 to restore
            strict write-through: the tx failure raises and nothing is
            written. Non-database exceptions always raise.
          * JSONL append fails → raises; Postgres has the decision but
            no evidence chain entry. The mirror has nothing. The next
            evaluation will continue the chain from the last good record.
            This is the same trade-off as the existing recorder.
          * Mirror insert fails → raises. Same as above; the JSONL is
            authoritative.

        In-memory fallback (``DATABASE_URL`` unset):
          The transaction wrapper is bypassed and writes go directly
          through the in-memory caches in the same order. Still atomic
          from the caller's point of view because every write is
          synchronous and any exception aborts the rest.
        """
        if not isinstance(full_input, dict):
            raise TypeError("full_input must be a dict")

        # 1+2+3 — single Postgres transaction when durable.
        durable = database_url() is not None and not self._degraded
        if durable:
            try:
                with connect_tx() as conn:
                    with conn.cursor() as cur:
                        self.decisions.save_in_tx(decision, cur)
                        self.inputs.save_in_tx(
                            request_id=decision.request_id,
                            full_input=full_input,
                            decision_id=decision.decision_id,
                            cursor=cur,
                        )
                        self.policies.save_in_tx(policy, cur)
            except psycopg.Error as exc:
                # Audit-persistence failure, not an adjudication failure.
                # Fail-closed belongs to the PDP; a dead database must not
                # convert every verdict into FORBID (prod 2026-07-13).
                if _require_durable():
                    raise
                self._enter_degraded_mode(exc)
                durable = False

        if not durable:
            # Pure in-memory mode (DATABASE_URL unset) or degraded mode
            # (Postgres configured but unreachable — stores are cache-only
            # by the time we get here). Order matters: decision first so
            # input.link_to_decision sees a valid id, then policy. This is
            # the same write shape the legacy EvaluateActionCommand path
            # uses when memory_system is None.
            self.decisions.save(decision)
            self.inputs.save(
                request_id=decision.request_id,
                full_input=full_input,
                decision_id=decision.decision_id,
            )
            self.policies.save(policy)
            self._note_degraded_write()

        # 4. JSONL chain (post-commit; the recorder is the source of
        #    truth for evidence). Failure here surfaces to the caller.
        evidence = self.recorder.record_decision(
            decision, metadata=evidence_metadata
        )

        # 5. Postgres mirror of the chain. Idempotent on record_hash. The
        #    JSONL above is authoritative; a mirror that cannot reach
        #    Postgres degrades exactly like the transaction does.
        try:
            self.evidence_mirror.mirror_record(
                evidence,
                kind="decision",
                aggregate_id=decision.decision_id,
            )
        except psycopg.Error as exc:
            if _require_durable():
                raise
            self._enter_degraded_mode(exc)
        return evidence

    # ---- degraded mode (Postgres configured but unreachable) -----------

    @property
    def degraded(self) -> bool:
        """True when Postgres was configured but became unreachable."""
        return self._degraded

    def _enter_degraded_mode(self, exc: Exception | None) -> None:
        """
        Flip the whole memory layer to cache-only persistence.

        One-way for the life of the process, mirroring the stores' own
        boot-time fallback — a restart re-probes durability (the deploy
        runbook already restarts the service once the database returns).
        Adjudication keeps running; ``health()`` reports durable=False
        the moment this fires.
        """
        with self._degraded_lock:
            if self._degraded:
                return
            self._degraded = True
            self._degraded_log_at = time.monotonic()
        for store in (
            self.decisions,
            self.inputs,
            self.policies,
            self.permits,
            self.verifications,
            self.evidence_mirror,
        ):
            store.mark_degraded()
        _logger.error(
            "MemorySystem DEGRADED: Postgres is unreachable — decision "
            "persistence fell back to in-memory. Governance keeps "
            "adjudicating; decisions recorded from now on WILL NOT survive "
            "a restart until the database returns and the service is "
            "restarted. Set %s=1 to fail closed instead. "
            "(event=memory_degraded tenant=%s)",
            _REQUIRE_DURABLE_ENV,
            self.tenant_id,
            exc_info=exc,
        )

    def _note_degraded_write(self) -> None:
        """Rate-limited reminder that writes are still in-memory only."""
        if not self._degraded:
            return
        now = time.monotonic()
        with self._degraded_lock:
            if now - self._degraded_log_at < _DEGRADED_REMINDER_INTERVAL_S:
                return
            self._degraded_log_at = now
        _logger.error(
            "MemorySystem still DEGRADED: decisions are being persisted "
            "in-memory only (event=memory_degraded_write tenant=%s)",
            self.tenant_id,
        )

    def link_permit_to_decision(
        self,
        *,
        decision: Decision,
        nonce: str,
        signature: str,
        expiry: datetime,
        metadata: dict[str, Any] | None = None,
    ) -> StoredPermit:
        """
        Convenience wrapper around ``issue_permit`` that takes the full
        Decision so the spec § "Permit + verify not fully linked"
        invariant is enforced at the type level: a permit cannot be
        issued without a decision_id, and the decision_id must come
        from a real Decision object the caller already holds.
        """
        return self.issue_permit(
            decision_id=decision.decision_id,
            nonce=nonce,
            signature=signature,
            expiry=expiry,
            metadata=metadata,
        )

    def record_outcome(
        self,
        outcome: OutcomeRecord,
        *,
        policy_version: str,
        metadata: dict[str, Any] | None = None,
    ) -> EvidenceRecord:
        """
        Records an outcome (label produced by a reporter or human review)
        through the JSONL chain and mirrors it. Outcome storage itself
        lives in the existing ``OutcomeStore`` — this method only
        handles the audit-trail side.
        """
        evidence = self.recorder.record_outcome(
            outcome,
            metadata=metadata,
            policy_version=policy_version,
        )
        self.evidence_mirror.mirror_record(
            evidence,
            kind="outcome",
            aggregate_id=outcome.outcome_id,
        )
        return evidence

    def record_policy_snapshot(self, policy: PolicySnapshot) -> None:
        """
        Persists a policy snapshot. Activation is a separate step
        (``activate_policy``) so save and activate stay distinct.
        """
        self.policies.save(policy)

    def activate_policy(self, version: str) -> None:
        self.policies.activate(version)

    # ---- permits + verifications -------------------------------------

    def issue_permit(
        self,
        *,
        decision_id: UUID,
        nonce: str,
        signature: str,
        expiry: datetime,
        metadata: dict[str, Any] | None = None,
    ) -> StoredPermit:
        """
        Records a freshly minted permit. Caller is responsible for
        producing the nonce and HMAC signature; the store guarantees
        durability and uniqueness.
        """
        return self.permits.issue(
            decision_id=decision_id,
            nonce=nonce,
            signature=signature,
            expiry=expiry,
            metadata=metadata,
        )

    def verify_permit(
        self,
        *,
        permit_id: UUID,
        consumed_nonce: str,
        result: VerificationResult,
        reason: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> StoredVerification:
        return self.verifications.record(
            permit_id=permit_id,
            consumed_nonce=consumed_nonce,
            result=result,
            reason=reason,
            metadata=metadata,
        )

    # ---- read helpers (spec §4: cache first, then Postgres) ----------

    def get_decision(self, decision_id: UUID) -> Decision | None:
        return self.decisions.get(decision_id)

    def get_decision_input(self, request_id: UUID):
        return self.inputs.get(request_id)

    def get_policy(self, version: str) -> PolicySnapshot | None:
        return self.policies.get(version)

    # ---- diagnostics --------------------------------------------------

    def health(self) -> MemoryHealth:
        durable = (
            self.decisions.is_durable
            and self.inputs.is_durable
            and self.policies.is_durable
            and self.permits.is_durable
            and self.verifications.is_durable
            and self.evidence_mirror.is_durable
        )
        return MemoryHealth(
            durable=durable,
            decisions_durable=self.decisions.is_durable,
            inputs_durable=self.inputs.is_durable,
            policies_durable=self.policies.is_durable,
            permits_durable=self.permits.is_durable,
            verifications_durable=self.verifications.is_durable,
            evidence_mirror_durable=self.evidence_mirror.is_durable,
            evidence_chain_path=str(self.recorder.path),
        )

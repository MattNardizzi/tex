"""
Postgres-backed durable decision store.

Drop-in superset of ``InMemoryDecisionStore``. Writes go through to
``tex_decisions`` synchronously after the in-memory cache is updated;
reads stay entirely in-memory. On startup the cache is hydrated from
Postgres so a process restart never loses durable history.

This is Layer 1 (durable) + Layer 2 (cache) of the locked memory spec
for the decisions aggregate. Layer 3 (evidence chain) is handled by the
existing ``EvidenceRecorder`` and the ``DurableEvidenceStore`` mirror.

Failure semantics — locked spec ``Critical Rules: No silent failures``:

  - DATABASE_URL not set         → falls back to pure in-memory and logs
                                   a warning at construction.
  - Postgres unreachable on save → raises. The caller (orchestrator) is
                                   responsible for surfacing the error;
                                   we do not silently degrade durability
                                   for a single decision.
  - Schema missing on startup    → ``ensure_memory_schema`` runs the
                                   master migration; idempotent.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import psycopg
from psycopg.types.json import Jsonb

from tex.domain.decision import Decision
from tex.domain.verdict import Verdict
from tex.memory._db import connect, database_url, ensure_memory_schema
from tex.stores.decision_store import InMemoryDecisionStore

_logger = logging.getLogger(__name__)


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _json_safe(value: Any) -> Any:
    """Best-effort coercion of pydantic / enum / uuid / datetime trees to JSON."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, (UUID,)):
        return str(value)
    if hasattr(value, "isoformat") and callable(value.isoformat):
        try:
            return value.isoformat()
        except TypeError:
            pass
    if hasattr(value, "value") and isinstance(getattr(value, "value"), (str, int, float, bool)):
        return value.value
    if hasattr(value, "model_dump") and callable(value.model_dump):
        return _json_safe(value.model_dump(mode="json"))
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_json_safe(v) for v in value]
    return str(value)


def _payload_fingerprint(decision: Decision) -> str:
    """
    Stable fingerprint over the durable fields of a decision. Used by the
    spec's ``payload_fingerprint`` column for fast equality checks across
    re-evaluations of the same logical request.
    """
    import hashlib

    canonical = {
        "request_id": str(decision.request_id),
        "action_type": decision.action_type,
        "channel": decision.channel,
        "environment": decision.environment,
        "content_sha256": decision.content_sha256,
        "policy_version": decision.policy_version,
    }
    blob = json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


class DurableDecisionStore:
    """
    Write-through Postgres decision store with an in-memory hot cache.

    Public API matches ``InMemoryDecisionStore`` so this class is a true
    drop-in replacement. Callers depend on duck typing across the
    pipeline — there is no abstract base on purpose.
    """

    def __init__(
        self,
        *,
        tenant_id: str = "default",
        bootstrap: bool = True,
    ) -> None:
        self._tenant_id = tenant_id
        self._cache = InMemoryDecisionStore()
        self._postgres_enabled = database_url() is not None
        # Spec § "cache invalidation": every write bumps this counter.
        # Readers that want to detect cross-process staleness can compare
        # against ``cache_version`` before serving a hit. Single-process
        # deployments never see drift; this is the foundation for future
        # LISTEN/NOTIFY based invalidation.
        self._cache_version = 0

        if not self._postgres_enabled:
            _logger.warning(
                "DurableDecisionStore: DATABASE_URL not set — running in "
                "pure in-memory mode. Decisions WILL be lost on restart."
            )
            return

        try:
            ensure_memory_schema()
        except Exception:
            _logger.exception(
                "DurableDecisionStore: schema bootstrap failed — falling "
                "back to in-memory mode"
            )
            self._postgres_enabled = False
            return

        if bootstrap:
            self._hydrate_cache()

    # ---- write path ---------------------------------------------------

    def save(self, decision: Decision) -> None:
        """
        Spec contract — write-through:
            1. Write to Postgres
            2. If success → update cache
            3. If failure → abort (raise)
        """
        if self._postgres_enabled:
            self._write_postgres(decision)
        self._cache.save(decision)
        self._cache_version += 1

    def save_in_tx(self, decision: Decision, cursor: Any) -> None:
        """
        Transactional variant for orchestrators composing multi-table
        writes. The caller owns the cursor and the surrounding
        transaction; this method only emits the SQL and updates the
        in-memory cache. If the surrounding transaction rolls back,
        the cache is still updated — but a rollback at the orchestrator
        level always raises, and callers ``reload()`` on retry. This is
        the same trade-off as ``InMemoryDecisionStore.save`` failing
        mid-write: the in-memory state is best-effort, Postgres is the
        truth.
        """
        if self._postgres_enabled:
            cursor.execute(
                _UPSERT_SQL,
                _decision_params(decision, self._tenant_id),
            )
        self._cache.save(decision)
        self._cache_version += 1

    def delete(self, decision_id: UUID) -> None:
        if self._postgres_enabled:
            try:
                with connect() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            "DELETE FROM tex_decisions WHERE decision_id = %s",
                            (str(decision_id),),
                        )
            except Exception:
                _logger.exception(
                    "DurableDecisionStore: postgres delete failed for %s",
                    decision_id,
                )
                raise
        self._cache.delete(decision_id)
        self._cache_version += 1

    # ---- read path (cache only) --------------------------------------

    def get(self, decision_id: UUID) -> Decision | None:
        return self._cache.get(decision_id)

    def require(self, decision_id: UUID) -> Decision:
        return self._cache.require(decision_id)

    def get_by_request_id(self, request_id: UUID) -> Decision | None:
        return self._cache.get_by_request_id(request_id)

    def require_by_request_id(self, request_id: UUID) -> Decision:
        return self._cache.require_by_request_id(request_id)

    def list_all(self) -> tuple[Decision, ...]:
        return self._cache.list_all()

    def list_recent(self, limit: int = 50) -> tuple[Decision, ...]:
        return self._cache.list_recent(limit=limit)

    def find(
        self,
        *,
        verdict: Verdict | None = None,
        policy_version: str | None = None,
        channel: str | None = None,
        environment: str | None = None,
        action_type: str | None = None,
        limit: int | None = None,
    ) -> tuple[Decision, ...]:
        return self._cache.find(
            verdict=verdict,
            policy_version=policy_version,
            channel=channel,
            environment=environment,
            action_type=action_type,
            limit=limit,
        )

    def __len__(self) -> int:
        return len(self._cache)

    def __contains__(self, decision_id: object) -> bool:
        return decision_id in self._cache

    # ---- maintenance --------------------------------------------------

    def clear_cache(self) -> None:
        """Empties the in-memory cache. Postgres is left untouched."""
        self._cache.clear()

    def reload(self) -> None:
        """Drops the cache and rehydrates from Postgres."""
        self._cache.clear()
        if self._postgres_enabled:
            self._hydrate_cache()

    @property
    def is_durable(self) -> bool:
        """True iff writes are being persisted to Postgres."""
        return self._postgres_enabled

    @property
    def cache_version(self) -> int:
        """
        Monotonic counter incremented on every successful save/delete.
        Used by cross-process invalidation hooks to detect staleness.
        """
        return self._cache_version

    # ---- internals ----------------------------------------------------

    def _write_postgres(self, decision: Decision) -> None:
        try:
            with connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        _UPSERT_SQL,
                        _decision_params(decision, self._tenant_id),
                    )
        except psycopg.Error:
            _logger.exception(
                "DurableDecisionStore: postgres write failed for decision %s",
                decision.decision_id,
            )
            raise

    def _hydrate_cache(self) -> None:
        try:
            with connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        _SELECT_RECENT_SQL,
                        (self._tenant_id,),
                    )
                    rows = cur.fetchall()
        except Exception:
            _logger.exception(
                "DurableDecisionStore: hydrate failed — cache will start empty"
            )
            return

        for row in reversed(rows):  # oldest first so save-order is preserved
            try:
                decision = _row_to_decision(row)
            except Exception:
                _logger.exception(
                    "DurableDecisionStore: skipping malformed row during hydrate"
                )
                continue
            self._cache.save(decision)


# ---- SQL ---------------------------------------------------------------


def _decision_params(decision: Decision, tenant_id: str) -> tuple[Any, ...]:
    """
    Builds the positional parameter tuple for ``_UPSERT_SQL``. Centralised
    so both the autocommit ``save`` path and the transactional
    ``save_in_tx`` path stay strictly aligned with the column order in
    the INSERT statement.
    """
    return (
        str(decision.decision_id),
        str(decision.request_id),
        tenant_id,
        decision.action_type,
        decision.channel,
        decision.environment,
        decision.recipient,
        decision.verdict.value,
        float(decision.confidence),
        float(decision.final_score),
        decision.content_excerpt,
        decision.content_sha256,
        _payload_fingerprint(decision),
        decision.policy_id,
        decision.policy_version,
        Jsonb(_json_safe(dict(decision.scores))),
        Jsonb([_json_safe(f) for f in decision.findings]),
        Jsonb(list(decision.reasons)),
        Jsonb(list(decision.uncertainty_flags)),
        Jsonb([_json_safe(f) for f in decision.asi_findings]),
        Jsonb(_json_safe(decision.retrieval_context)),
        Jsonb(_json_safe(decision.metadata)),
        decision.determinism_fingerprint,
        decision.evidence_hash,
        Jsonb(_json_safe(decision.latency)) if decision.latency else None,
        decision.decided_at,
    )


_UPSERT_SQL = """
INSERT INTO tex_decisions (
    decision_id, request_id, tenant_id,
    action_type, channel, environment, recipient,
    verdict, confidence, final_score,
    content_excerpt, content_sha256, payload_fingerprint,
    policy_id, policy_version,
    scores, findings, reasons, uncertainty_flags, asi_findings,
    retrieval_context, metadata,
    determinism_fingerprint, evidence_hash, latency,
    decided_at
)
VALUES (
    %s, %s, %s,
    %s, %s, %s, %s,
    %s, %s, %s,
    %s, %s, %s,
    %s, %s,
    %s, %s, %s, %s, %s,
    %s, %s,
    %s, %s, %s,
    %s
)
ON CONFLICT (decision_id) DO UPDATE SET
    verdict             = EXCLUDED.verdict,
    confidence          = EXCLUDED.confidence,
    final_score         = EXCLUDED.final_score,
    content_excerpt     = EXCLUDED.content_excerpt,
    content_sha256      = EXCLUDED.content_sha256,
    payload_fingerprint = EXCLUDED.payload_fingerprint,
    scores              = EXCLUDED.scores,
    findings            = EXCLUDED.findings,
    reasons             = EXCLUDED.reasons,
    uncertainty_flags   = EXCLUDED.uncertainty_flags,
    asi_findings        = EXCLUDED.asi_findings,
    retrieval_context   = EXCLUDED.retrieval_context,
    metadata            = EXCLUDED.metadata,
    determinism_fingerprint = EXCLUDED.determinism_fingerprint,
    evidence_hash       = EXCLUDED.evidence_hash,
    latency             = EXCLUDED.latency
"""

# Hydrate the most recent N decisions on startup. The hot cache is
# bounded so we don't pull a 10M-row table into memory on every boot.
_SELECT_RECENT_SQL = """
SELECT
    decision_id, request_id,
    action_type, channel, environment, recipient,
    verdict, confidence, final_score,
    content_excerpt, content_sha256,
    policy_id, policy_version,
    scores, findings, reasons, uncertainty_flags, asi_findings,
    retrieval_context, metadata,
    determinism_fingerprint, evidence_hash, latency,
    decided_at
FROM tex_decisions
WHERE tenant_id = %s
ORDER BY decided_at DESC
LIMIT 5000
"""


def _row_to_decision(row: tuple[Any, ...]) -> Decision:
    (
        decision_id,
        request_id,
        action_type,
        channel,
        environment,
        recipient,
        verdict,
        confidence,
        final_score,
        content_excerpt,
        content_sha256,
        policy_id,
        policy_version,
        scores,
        findings,
        reasons,
        uncertainty_flags,
        asi_findings,
        retrieval_context,
        metadata,
        determinism_fingerprint,
        evidence_hash,
        latency,
        decided_at,
    ) = row

    return Decision.model_validate(
        {
            "decision_id": str(decision_id),
            "request_id": str(request_id),
            "action_type": action_type,
            "channel": channel,
            "environment": environment,
            "recipient": recipient,
            "verdict": verdict,
            "confidence": float(confidence),
            "final_score": float(final_score),
            "content_excerpt": content_excerpt,
            "content_sha256": content_sha256,
            "policy_id": policy_id,
            "policy_version": policy_version,
            "scores": dict(scores or {}),
            "findings": list(findings or []),
            "reasons": list(reasons or []),
            "uncertainty_flags": list(uncertainty_flags or []),
            "asi_findings": list(asi_findings or []),
            "retrieval_context": dict(retrieval_context or {}),
            "metadata": dict(metadata or {}),
            "determinism_fingerprint": determinism_fingerprint,
            "evidence_hash": evidence_hash,
            "latency": latency,
            "decided_at": decided_at,
        }
    )

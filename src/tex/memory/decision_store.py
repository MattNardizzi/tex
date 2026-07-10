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
import time
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
                        # Per-tenant isolation: never delete by decision_id
                        # alone — a decision_id collision (or a forged id)
                        # from another tenant must not remove this tenant's
                        # row. Scope the DELETE to this store's tenant_id
                        # (application-layer WHERE filter; no Postgres RLS).
                        cur.execute(
                            "DELETE FROM tex_decisions "
                            "WHERE tenant_id = %s AND decision_id = %s",
                            (self._tenant_id, str(decision_id)),
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

    # ---- durable read path (Postgres, deploy-surviving) ----------------
    #
    # The cache above is a bounded hot page (recent 5000 + the held floor)
    # that dies with the process on every deploy. Anything SPOKEN as a
    # tally or a queue must not: the answer wire's exhibits call these two
    # methods first and only fall back to a cache scan when they return
    # ``None``. Predicates mirror the exhibits layer exactly — tenant
    # visibility on ``Decision.tenant_id`` (the metadata field, blank ⇒
    # "default"), the shared "default" partition, half-open [since, until)
    # on ``decided_at``.

    def count_matching(
        self,
        *,
        tenant_visible_to: str,
        verdict: Verdict | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
    ) -> int | None:
        """Count matching rows straight from Postgres — the tally that
        survives a deploy. Returns ``None`` (never raises) when the store
        is not durable or the read fails, so the caller can fall back to
        the in-process cache scan instead of erroring an answer.
        """
        if not self._postgres_enabled:
            return None
        where, params = _matching_where(
            self._tenant_id, tenant_visible_to, verdict, since, until
        )
        try:
            with connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        f"SELECT COUNT(*) FROM tex_decisions WHERE {where}",  # noqa: S608 — clauses are static, values bound
                        params,
                    )
                    row = cur.fetchone()
        except Exception:
            _logger.exception(
                "DurableDecisionStore: durable count failed — caller "
                "falls back to the in-process cache scan"
            )
            return None
        return int(row[0]) if row else 0

    def find_matching(
        self,
        *,
        tenant_visible_to: str,
        verdict: Verdict | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int | None = None,
    ) -> tuple[Decision, ...] | None:
        """Matching rows straight from Postgres, newest first — the queue
        that survives a deploy (the held/waiting wires read this). Returns
        ``None`` (never raises) when the store is not durable or the read
        fails; a malformed row is skipped, never fabricated. ``limit`` is
        capped by the same runaway backstop as the held-floor hydrate.
        """
        if not self._postgres_enabled:
            return None
        where, params = _matching_where(
            self._tenant_id, tenant_visible_to, verdict, since, until
        )
        capped = (
            _FIND_MATCHING_BACKSTOP
            if limit is None
            else max(0, min(limit, _FIND_MATCHING_BACKSTOP))
        )
        try:
            with connect() as conn:
                # Named cursor in a transaction, same as the hydrate: each
                # FETCH is its own statement under statement_timeout, so a
                # large payload can never blow the single-shot budget.
                with conn.transaction():
                    with conn.cursor(name="tex_find_matching") as cur:
                        cur.itersize = 500
                        cur.execute(
                            f"SELECT {_DECISION_COLUMNS} FROM tex_decisions "  # noqa: S608
                            f"WHERE {where} ORDER BY decided_at DESC LIMIT %s",
                            (*params, capped),
                        )
                        raw = list(cur)
        except Exception:
            _logger.exception(
                "DurableDecisionStore: durable find failed — caller "
                "falls back to the in-process cache scan"
            )
            return None
        decisions: list[Decision] = []
        for row in raw:
            try:
                decisions.append(_row_to_decision(row))
            except Exception:
                _logger.exception(
                    "DurableDecisionStore: skipping malformed row in find_matching"
                )
        return tuple(decisions)

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
        # Server-side (named) cursors, streamed in small batches: decision rows
        # average ~9 KB (JSONB scores/findings/retrieval_context), so 5000 rows
        # is ~43 MB — one single-shot SELECT of that payload blows through the
        # 15s statement_timeout (connection.py) and the except below silently
        # started every boot with an EMPTY cache (holds "vanished" after a
        # deploy). With a named cursor each FETCH is its own statement, so the
        # timeout caps a 500-row batch (~4 MB), never the whole transfer.
        started = time.monotonic()
        try:
            with connect() as conn:
                # connect() is autocommit (per-write idiom); DECLARE CURSOR
                # needs a transaction block, so open one for the read.
                with conn.transaction():
                    with conn.cursor(name="tex_hydrate_recent") as cur:
                        cur.itersize = 500
                        cur.execute(
                            _SELECT_RECENT_SQL,
                            (self._tenant_id,),
                        )
                        # Iterate, don't fetchall(): iteration FETCHes
                        # itersize-row batches (each its own statement under
                        # the timeout); fetchall() on a named cursor is one
                        # FETCH ALL — the exact single-shot this fix removes.
                        rows = list(cur)
                    # Held floor: recent-window ABSTAINs beyond the recency
                    # cap, so a waiting hold survives a deploy on /held and
                    # stays sealable (see _SELECT_WAITING_ABSTAIN_SQL).
                    with conn.cursor(name="tex_hydrate_held_floor") as cur:
                        cur.itersize = 500
                        cur.execute(
                            _SELECT_WAITING_ABSTAIN_SQL,
                            (self._tenant_id,),
                        )
                        abstain_rows = list(cur)
        except Exception:
            _logger.exception(
                "DurableDecisionStore: hydrate failed — cache will start empty"
            )
            return
        _logger.info(
            "DurableDecisionStore: hydrated %d recent + %d held-floor rows "
            "for tenant %s in %.2fs",
            len(rows),
            len(abstain_rows),
            self._tenant_id,
            time.monotonic() - started,
        )

        # Merge, dedup by decision_id (column 0), keep newest-first order so
        # the reversed() below preserves oldest-first save order overall.
        seen: set[str] = set()
        merged: list[tuple[Any, ...]] = []
        for row in sorted(
            list(rows) + list(abstain_rows),
            key=lambda r: r[-1],  # decided_at
            reverse=True,
        ):
            key = str(row[0])
            if key in seen:
                continue
            seen.add(key)
            merged.append(row)

        for row in reversed(merged):  # oldest first so save-order is preserved
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

# The one column order every row-returning SELECT here uses — it must stay
# aligned with ``_row_to_decision``'s unpacking below.
_DECISION_COLUMNS = """
    decision_id, request_id,
    action_type, channel, environment, recipient,
    verdict, confidence, final_score,
    content_excerpt, content_sha256,
    policy_id, policy_version,
    scores, findings, reasons, uncertainty_flags, asi_findings,
    retrieval_context, metadata,
    determinism_fingerprint, evidence_hash, latency,
    decided_at
"""

# SQL mirror of ``Decision.tenant_id`` (domain/decision.py): the owning tenant
# rides in metadata JSONB; a missing/blank value reads as the shared "default"
# partition, exactly as the Python property resolves it.
_VISIBLE_TENANT_EXPR = (
    "lower(coalesce(nullif(trim(metadata->>'tenant_id'), ''), 'default'))"
)

# Runaway backstop for ``find_matching`` — same bound, same rationale as the
# held-floor hydrate below: a working set never approaches it.
_FIND_MATCHING_BACKSTOP = 20000


def _matching_where(
    store_tenant: str,
    tenant_visible_to: str,
    verdict: Verdict | None,
    since: datetime | None,
    until: datetime | None,
) -> tuple[str, tuple[Any, ...]]:
    """WHERE clause + bound params for the durable read path, mirroring the
    exhibits-layer predicates: this store's partition column, the private+
    shared tenant-visibility rule on ``Decision.tenant_id`` (metadata), an
    optional verdict, and the half-open ``[since, until)`` window on
    ``decided_at``.
    """
    clauses = [
        "tenant_id = %s",
        f"{_VISIBLE_TENANT_EXPR} IN (%s, 'default')",
    ]
    params: list[Any] = [store_tenant, str(tenant_visible_to).strip().casefold()]
    if verdict is not None:
        clauses.append("verdict = %s")
        params.append(verdict.value)
    if since is not None:
        clauses.append("decided_at >= %s")
        params.append(since)
    if until is not None:
        clauses.append("decided_at < %s")
        params.append(until)
    return " AND ".join(clauses), tuple(params)


# Hydrate the most recent N decisions on startup. The hot cache is
# bounded so we don't pull a 10M-row table into memory on every boot.
_SELECT_RECENT_SQL = f"""
SELECT {_DECISION_COLUMNS}
FROM tex_decisions
WHERE tenant_id = %s
ORDER BY decided_at DESC
LIMIT 5000
"""

# The restart-proof held floor: EVERY still-recent ABSTAIN (the 7-day
# "waiting on a human" window the exhibits layer reads) hydrates regardless
# of the recency cap above. On a busy estate the newest 5000 rows can span
# under an hour, and a hold that fell off that page would vanish from /held
# AND become unsealable (store.get -> 404) after a deploy — exactly when
# "restart-proof" matters. ABSTAINs are a small share of traffic, so this
# adds little memory; the LIMIT is a runaway backstop, not a working bound.
_SELECT_WAITING_ABSTAIN_SQL = f"""
SELECT {_DECISION_COLUMNS}
FROM tex_decisions
WHERE tenant_id = %s
  AND verdict = 'ABSTAIN'
  AND decided_at >= now() - interval '7 days'
ORDER BY decided_at DESC
LIMIT 20000
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

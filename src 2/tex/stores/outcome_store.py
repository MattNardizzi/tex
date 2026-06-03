from __future__ import annotations

import logging
import os
from collections.abc import Iterable
from datetime import datetime
from threading import RLock
from uuid import UUID

import psycopg
from psycopg.types.json import Jsonb

from tex.domain.outcome import OutcomeKind, OutcomeLabel, OutcomeRecord
from tex.domain.outcome_trust import OutcomeTrustLevel
from tex.domain.verdict import Verdict


_logger = logging.getLogger(__name__)

DATABASE_URL_ENV = "DATABASE_URL"


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS tex_outcomes (
    outcome_id          UUID PRIMARY KEY,
    decision_id         UUID NOT NULL,
    request_id          UUID NOT NULL,
    tenant_id           TEXT,
    policy_version      TEXT,
    verdict             TEXT NOT NULL,
    outcome_kind        TEXT NOT NULL,
    label               TEXT NOT NULL,
    trust_level         TEXT NOT NULL,
    source_type         TEXT NOT NULL,
    verification_method TEXT NOT NULL,
    confidence_score    DOUBLE PRECISION NOT NULL DEFAULT 0.5,
    was_safe            BOOLEAN,
    human_override      BOOLEAN NOT NULL DEFAULT FALSE,
    reporter            TEXT,
    summary             TEXT,
    recorded_at         TIMESTAMPTZ NOT NULL,
    payload             JSONB NOT NULL,
    inserted_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS tex_outcomes_decision_idx
    ON tex_outcomes (decision_id);

CREATE INDEX IF NOT EXISTS tex_outcomes_request_idx
    ON tex_outcomes (request_id);

CREATE INDEX IF NOT EXISTS tex_outcomes_tenant_idx
    ON tex_outcomes (tenant_id, recorded_at DESC);

CREATE INDEX IF NOT EXISTS tex_outcomes_trust_idx
    ON tex_outcomes (trust_level, recorded_at DESC);

CREATE INDEX IF NOT EXISTS tex_outcomes_eligibility_idx
    ON tex_outcomes (tenant_id, trust_level, recorded_at DESC);
"""


class InMemoryOutcomeStore:
    """
    Outcome store with in-memory cache and optional Postgres persistence.

    Design goals:
    - strict alignment with the current OutcomeRecord domain contract
    - explicit indexes for the fields that actually exist
    - deterministic iteration order
    - tenant + trust-level indexes so the calibrator can scope cleanly
    - durable when DATABASE_URL is set; in-memory only otherwise

    Class name is preserved for backward compatibility with existing
    callers; the in-memory dict is now a hot cache backed by Postgres
    when configured.
    """

    __slots__ = (
        "_lock",
        "_by_id",
        "_ordered_ids",
        "_decision_index",
        "_request_index",
        "_kind_index",
        "_label_index",
        "_tenant_index",
        "_trust_index",
        "_dsn",
        "_disabled",
    )

    def __init__(
        self,
        initial_outcomes: Iterable[OutcomeRecord] | None = None,
        *,
        dsn: str | None = None,
    ) -> None:
        self._lock = RLock()
        self._by_id: dict[UUID, OutcomeRecord] = {}
        self._ordered_ids: list[UUID] = []
        self._decision_index: dict[UUID, list[UUID]] = {}
        self._request_index: dict[UUID, list[UUID]] = {}
        self._kind_index: dict[OutcomeKind, list[UUID]] = {}
        self._label_index: dict[OutcomeLabel, list[UUID]] = {}
        self._tenant_index: dict[str, list[UUID]] = {}
        self._trust_index: dict[OutcomeTrustLevel, list[UUID]] = {}
        self._dsn = (
            dsn if dsn is not None else os.environ.get(DATABASE_URL_ENV, "")
        ).strip()
        self._disabled = not bool(self._dsn)

        if self._disabled:
            _logger.info(
                "OutcomeStore: %s not set; running in pure in-memory mode.",
                DATABASE_URL_ENV,
            )
        else:
            try:
                self._ensure_schema()
                self._hydrate_from_postgres()
            except Exception as exc:  # noqa: BLE001
                _logger.error(
                    "OutcomeStore: bootstrap failed: %s. "
                    "Falling back to in-memory mode.",
                    exc,
                )
                self._disabled = True

        if initial_outcomes is not None:
            for outcome in initial_outcomes:
                self.save(outcome)

    @property
    def is_durable(self) -> bool:
        return not self._disabled

    def save(self, outcome: OutcomeRecord) -> None:
        """
        Saves or replaces an outcome record.

        Re-saving the same outcome_id updates the stored record and moves it to
        the end of insertion order.
        """
        with self._lock:
            existing = self._by_id.get(outcome.outcome_id)
            if existing is not None:
                self._remove_from_indexes(existing)
                self._ordered_ids = [
                    stored_id
                    for stored_id in self._ordered_ids
                    if stored_id != outcome.outcome_id
                ]

            self._by_id[outcome.outcome_id] = outcome
            self._ordered_ids.append(outcome.outcome_id)
            self._add_to_indexes(outcome)
            self._persist_outcome(outcome)

    def get(self, outcome_id: UUID) -> OutcomeRecord | None:
        """Returns an outcome by outcome_id, or None if missing."""
        with self._lock:
            return self._by_id.get(outcome_id)

    def require(self, outcome_id: UUID) -> OutcomeRecord:
        """Returns an outcome by outcome_id or raises KeyError."""
        outcome = self.get(outcome_id)
        if outcome is None:
            raise KeyError(f"outcome not found: {outcome_id}")
        return outcome

    def list_all(self) -> tuple[OutcomeRecord, ...]:
        """Returns all stored outcomes in insertion order."""
        with self._lock:
            return tuple(self._by_id[outcome_id] for outcome_id in self._ordered_ids)

    def list_recent(self, limit: int = 50) -> tuple[OutcomeRecord, ...]:
        """Returns the most recently saved outcomes, newest first."""
        if limit <= 0:
            return tuple()

        with self._lock:
            selected_ids = list(reversed(self._ordered_ids[-limit:]))
            return tuple(self._by_id[outcome_id] for outcome_id in selected_ids)

    def list_for_decision(self, decision_id: UUID) -> tuple[OutcomeRecord, ...]:
        """Returns all outcomes associated with a decision_id, oldest first."""
        with self._lock:
            outcome_ids = tuple(self._decision_index.get(decision_id, ()))
            return tuple(self._by_id[outcome_id] for outcome_id in outcome_ids)

    def list_for_request(self, request_id: UUID) -> tuple[OutcomeRecord, ...]:
        """Returns all outcomes associated with a request_id, oldest first."""
        with self._lock:
            outcome_ids = tuple(self._request_index.get(request_id, ()))
            return tuple(self._by_id[outcome_id] for outcome_id in outcome_ids)

    def list_for_kind(self, outcome_kind: OutcomeKind) -> tuple[OutcomeRecord, ...]:
        """Returns all outcomes for a specific OutcomeKind, oldest first."""
        with self._lock:
            outcome_ids = tuple(self._kind_index.get(outcome_kind, ()))
            return tuple(self._by_id[outcome_id] for outcome_id in outcome_ids)

    def list_for_label(self, label: OutcomeLabel) -> tuple[OutcomeRecord, ...]:
        """Returns all outcomes for a specific OutcomeLabel, oldest first."""
        with self._lock:
            outcome_ids = tuple(self._label_index.get(label, ()))
            return tuple(self._by_id[outcome_id] for outcome_id in outcome_ids)

    def find(
        self,
        *,
        decision_id: UUID | None = None,
        request_id: UUID | None = None,
        outcome_kind: OutcomeKind | None = None,
        label: OutcomeLabel | None = None,
        verdict: Verdict | None = None,
        was_safe: bool | None = None,
        human_override: bool | None = None,
        reporter: str | None = None,
        limit: int | None = None,
    ) -> tuple[OutcomeRecord, ...]:
        """
        Returns outcomes matching the supplied filters.

        Results are newest first because that is the most useful default for
        operational inspection.
        """
        normalized_reporter = reporter.strip() if reporter is not None else None
        if normalized_reporter == "":
            raise ValueError("reporter filter must not be blank")

        with self._lock:
            matched: list[OutcomeRecord] = []

            for outcome_id in reversed(self._ordered_ids):
                outcome = self._by_id[outcome_id]

                if decision_id is not None and outcome.decision_id != decision_id:
                    continue

                if request_id is not None and outcome.request_id != request_id:
                    continue

                if outcome_kind is not None and outcome.outcome_kind != outcome_kind:
                    continue

                if label is not None and outcome.label != label:
                    continue

                if verdict is not None and outcome.verdict != verdict:
                    continue

                if was_safe is not None and outcome.was_safe != was_safe:
                    continue

                if human_override is not None and outcome.human_override != human_override:
                    continue

                if normalized_reporter is not None and outcome.reporter != normalized_reporter:
                    continue

                matched.append(outcome)

                if limit is not None and len(matched) >= limit:
                    break

            return tuple(matched)

    def delete(self, outcome_id: UUID) -> None:
        """Deletes a stored outcome by outcome_id."""
        with self._lock:
            outcome = self._by_id.get(outcome_id)
            if outcome is None:
                raise KeyError(f"outcome not found: {outcome_id}")

            self._remove_from_indexes(outcome)
            del self._by_id[outcome_id]
            self._ordered_ids = [
                stored_id
                for stored_id in self._ordered_ids
                if stored_id != outcome_id
            ]

    def clear(self) -> None:
        """Removes all stored outcomes and resets indexes."""
        with self._lock:
            self._by_id.clear()
            self._ordered_ids.clear()
            self._decision_index.clear()
            self._request_index.clear()
            self._kind_index.clear()
            self._label_index.clear()
            self._tenant_index.clear()
            self._trust_index.clear()
            self._persist_clear_all()

    def __len__(self) -> int:
        with self._lock:
            return len(self._by_id)

    def __contains__(self, outcome_id: object) -> bool:
        if not isinstance(outcome_id, UUID):
            return False
        with self._lock:
            return outcome_id in self._by_id

    def list_for_tenant(
        self,
        tenant_id: str,
        *,
        limit: int | None = None,
    ) -> tuple[OutcomeRecord, ...]:
        """Returns outcomes for a tenant, newest first."""
        with self._lock:
            outcome_ids = list(reversed(self._tenant_index.get(tenant_id, [])))
            if limit is not None:
                outcome_ids = outcome_ids[:limit]
            return tuple(self._by_id[oid] for oid in outcome_ids)

    def list_for_trust(
        self,
        trust_level: OutcomeTrustLevel,
        *,
        limit: int | None = None,
    ) -> tuple[OutcomeRecord, ...]:
        """Returns outcomes at a given trust level, newest first."""
        with self._lock:
            outcome_ids = list(reversed(self._trust_index.get(trust_level, [])))
            if limit is not None:
                outcome_ids = outcome_ids[:limit]
            return tuple(self._by_id[oid] for oid in outcome_ids)

    def list_calibration_eligible(
        self,
        *,
        tenant_id: str | None = None,
        policy_version: str | None = None,
        since: "datetime | None" = None,
        limit: int | None = None,
    ) -> tuple[OutcomeRecord, ...]:
        """
        Returns only VALIDATED + VERIFIED outcomes, optionally tenant-scoped,
        optionally restricted to a policy version, optionally restricted to
        recent records.

        This is the canonical entry point for the calibrator. Anything
        else risks calibrating on quarantined or raw data.
        """
        with self._lock:
            results: list[OutcomeRecord] = []
            for oid in reversed(self._ordered_ids):
                outcome = self._by_id[oid]
                if not outcome.trust_level.is_calibration_eligible:
                    continue
                if tenant_id is not None and outcome.tenant_id != tenant_id:
                    continue
                if (
                    policy_version is not None
                    and outcome.policy_version != policy_version
                ):
                    continue
                if since is not None and outcome.recorded_at < since:
                    continue
                results.append(outcome)
                if limit is not None and len(results) >= limit:
                    break
            return tuple(results)

    def quarantine_count(
        self, *, tenant_id: str | None = None
    ) -> int:
        """Counts quarantined outcomes, optionally tenant-scoped."""
        with self._lock:
            count = 0
            for oid in self._trust_index.get(OutcomeTrustLevel.QUARANTINED, []):
                outcome = self._by_id[oid]
                if tenant_id is not None and outcome.tenant_id != tenant_id:
                    continue
                count += 1
            return count

    def _add_to_indexes(self, outcome: OutcomeRecord) -> None:
        self._decision_index.setdefault(outcome.decision_id, []).append(outcome.outcome_id)
        self._request_index.setdefault(outcome.request_id, []).append(outcome.outcome_id)
        self._kind_index.setdefault(outcome.outcome_kind, []).append(outcome.outcome_id)
        self._label_index.setdefault(outcome.label, []).append(outcome.outcome_id)
        if outcome.tenant_id:
            self._tenant_index.setdefault(outcome.tenant_id, []).append(outcome.outcome_id)
        self._trust_index.setdefault(outcome.trust_level, []).append(outcome.outcome_id)

    def _remove_from_indexes(self, outcome: OutcomeRecord) -> None:
        self._remove_id_from_bucket(
            index=self._decision_index,
            key=outcome.decision_id,
            outcome_id=outcome.outcome_id,
        )
        self._remove_id_from_bucket(
            index=self._request_index,
            key=outcome.request_id,
            outcome_id=outcome.outcome_id,
        )
        self._remove_id_from_bucket(
            index=self._kind_index,
            key=outcome.outcome_kind,
            outcome_id=outcome.outcome_id,
        )
        self._remove_id_from_bucket(
            index=self._label_index,
            key=outcome.label,
            outcome_id=outcome.outcome_id,
        )
        if outcome.tenant_id:
            self._remove_id_from_bucket(
                index=self._tenant_index,
                key=outcome.tenant_id,
                outcome_id=outcome.outcome_id,
            )
        self._remove_id_from_bucket(
            index=self._trust_index,
            key=outcome.trust_level,
            outcome_id=outcome.outcome_id,
        )

    @staticmethod
    def _remove_id_from_bucket(
        *,
        index: dict[object, list[UUID]],
        key: object,
        outcome_id: UUID,
    ) -> None:
        bucket = index.get(key)
        if bucket is None:
            return

        updated_bucket = [stored_id for stored_id in bucket if stored_id != outcome_id]
        if updated_bucket:
            index[key] = updated_bucket
        else:
            del index[key]

    # ── postgres internals ──────────────────────────────────────────────

    def _ensure_schema(self) -> None:
        with psycopg.connect(self._dsn, autocommit=True) as conn:
            with conn.cursor() as cur:
                cur.execute(SCHEMA_SQL)

    def _hydrate_from_postgres(self) -> None:
        """Load all outcomes into the in-memory cache on startup."""
        with psycopg.connect(self._dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT outcome_id, payload
                      FROM tex_outcomes
                     ORDER BY recorded_at ASC
                    """
                )
                rows = cur.fetchall()
        loaded = 0
        for outcome_id, payload in rows:
            try:
                outcome = OutcomeRecord.model_validate(payload)
            except Exception as exc:  # noqa: BLE001
                _logger.error(
                    "OutcomeStore: failed to hydrate outcome %s: %s",
                    outcome_id, exc,
                )
                continue
            self._by_id[outcome.outcome_id] = outcome
            self._ordered_ids.append(outcome.outcome_id)
            self._add_to_indexes(outcome)
            loaded += 1
        if loaded:
            _logger.info(
                "OutcomeStore: hydrated %d outcomes from Postgres.", loaded,
            )

    def _persist_outcome(self, outcome: OutcomeRecord) -> None:
        if self._disabled:
            return
        try:
            payload = outcome.model_dump(mode="json")
            with psycopg.connect(self._dsn) as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO tex_outcomes (
                            outcome_id, decision_id, request_id,
                            tenant_id, policy_version,
                            verdict, outcome_kind, label,
                            trust_level, source_type, verification_method,
                            confidence_score, was_safe, human_override,
                            reporter, summary, recorded_at, payload
                        ) VALUES (
                            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                            %s, %s, %s, %s, %s, %s, %s, %s
                        )
                        ON CONFLICT (outcome_id) DO UPDATE SET
                            tenant_id           = EXCLUDED.tenant_id,
                            policy_version      = EXCLUDED.policy_version,
                            verdict             = EXCLUDED.verdict,
                            outcome_kind        = EXCLUDED.outcome_kind,
                            label               = EXCLUDED.label,
                            trust_level         = EXCLUDED.trust_level,
                            source_type         = EXCLUDED.source_type,
                            verification_method = EXCLUDED.verification_method,
                            confidence_score    = EXCLUDED.confidence_score,
                            was_safe            = EXCLUDED.was_safe,
                            human_override      = EXCLUDED.human_override,
                            reporter            = EXCLUDED.reporter,
                            summary             = EXCLUDED.summary,
                            recorded_at         = EXCLUDED.recorded_at,
                            payload             = EXCLUDED.payload
                        """,
                        (
                            str(outcome.outcome_id),
                            str(outcome.decision_id),
                            str(outcome.request_id),
                            outcome.tenant_id,
                            outcome.policy_version,
                            outcome.verdict.value,
                            outcome.outcome_kind.value,
                            outcome.label.value,
                            outcome.trust_level.value,
                            outcome.source_type.value,
                            outcome.verification_method.value,
                            outcome.confidence_score,
                            outcome.was_safe,
                            outcome.human_override,
                            outcome.reporter,
                            outcome.summary,
                            outcome.recorded_at,
                            Jsonb(payload),
                        ),
                    )
                conn.commit()
        except Exception as exc:  # noqa: BLE001
            _logger.error(
                "OutcomeStore: persist failed for %s: %s",
                outcome.outcome_id, exc,
            )

    def _persist_clear_all(self) -> None:
        if self._disabled:
            return
        try:
            with psycopg.connect(self._dsn) as conn:
                with conn.cursor() as cur:
                    cur.execute("DELETE FROM tex_outcomes")
                conn.commit()
        except Exception as exc:  # noqa: BLE001
            _logger.error("OutcomeStore: clear-all failed: %s", exc)
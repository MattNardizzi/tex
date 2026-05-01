"""
Reporter reputation system.

Tracks per-reporter accuracy over time and produces a weight that the
calibrator multiplies into outcome contributions. New reporters start
neutral; reporters whose labels repeatedly disagree with consensus or
ground truth lose weight; reporters with stable accuracy gain weight up
to a cap.

Design rules:

  - Weights are bounded in [floor, ceiling]. Default floor=0.05 means even
    a sanctioned reporter contributes a tiny non-zero amount until
    explicitly quarantined; default ceiling=1.5 means a top reporter cannot
    eclipse two median ones.
  - Reputation uses exponential decay: a disagreement two months ago
    counts much less than one yesterday. This is item 9 (time-decay).
  - Reputation does NOT touch labels. It only changes how much each label
    contributes to the trust-weighted summary the calibrator consumes.
  - All updates go through ``record_observation``. No ad-hoc writes.

This module is in-memory by default. The store interface is small enough
that a Postgres-backed implementation can drop in later without touching
the calibrator or the feedback loop.
"""

from __future__ import annotations

import logging
import math
import os
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from threading import RLock

import psycopg


_logger = logging.getLogger(__name__)

DATABASE_URL_ENV = "DATABASE_URL"

DEFAULT_HALF_LIFE = timedelta(days=14)
DEFAULT_FLOOR = 0.05
DEFAULT_CEILING = 1.5
DEFAULT_NEUTRAL_WEIGHT = 1.0
DEFAULT_MIN_OBSERVATIONS_BEFORE_DECAY = 5


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS tex_reporter_reputation (
    reporter                TEXT PRIMARY KEY,
    observations            INTEGER NOT NULL DEFAULT 0,
    agreements              INTEGER NOT NULL DEFAULT 0,
    disagreements           INTEGER NOT NULL DEFAULT 0,
    decayed_agreement       DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    decayed_disagreement    DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    last_event_at           TIMESTAMPTZ,
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);
"""


@dataclass(frozen=True, slots=True)
class ReporterReputation:
    """
    Aggregate reputation snapshot for one reporter.

    `effective_weight` is what the calibrator multiplies into the
    outcome's trust-tier weight. The other fields are exposed for
    dashboards and audit.
    """

    reporter: str
    observations: int
    agreements: int
    disagreements: int
    decayed_agreement_score: float
    decayed_disagreement_score: float
    last_seen_at: datetime | None
    effective_weight: float
    accuracy: float
    disagreement_rate: float


@dataclass(slots=True)
class _ReporterState:
    """
    Internal mutable state. Not exposed.
    """

    observations: int = 0
    agreements: int = 0
    disagreements: int = 0
    decayed_agreement: float = 0.0
    decayed_disagreement: float = 0.0
    last_event_at: datetime | None = None


class ReporterReputationStore:
    """
    In-memory reputation store with exponential time decay.

    Decay is applied lazily at observation time and at read time so we
    don't need a background sweeper. ``half_life`` controls how quickly
    historical behavior fades.
    """

    __slots__ = (
        "_lock",
        "_reporters",
        "_half_life",
        "_floor",
        "_ceiling",
        "_min_observations",
        "_clock",
        "_dsn",
        "_disabled",
    )

    def __init__(
        self,
        *,
        half_life: timedelta = DEFAULT_HALF_LIFE,
        floor: float = DEFAULT_FLOOR,
        ceiling: float = DEFAULT_CEILING,
        min_observations_before_decay: int = DEFAULT_MIN_OBSERVATIONS_BEFORE_DECAY,
        clock: callable | None = None,
        dsn: str | None = None,
    ) -> None:
        if half_life.total_seconds() <= 0:
            raise ValueError("half_life must be positive")
        if not 0.0 <= floor < ceiling:
            raise ValueError("floor must be in [0.0, ceiling)")
        if ceiling > 5.0:
            raise ValueError("ceiling must be <= 5.0 to keep weights bounded")
        if min_observations_before_decay < 0:
            raise ValueError("min_observations_before_decay must be >= 0")

        self._lock = RLock()
        self._reporters: dict[str, _ReporterState] = {}
        self._half_life = half_life
        self._floor = floor
        self._ceiling = ceiling
        self._min_observations = min_observations_before_decay
        self._clock = clock or (lambda: datetime.now(UTC))
        self._dsn = (
            dsn if dsn is not None else os.environ.get(DATABASE_URL_ENV, "")
        ).strip()
        self._disabled = not bool(self._dsn)

        if self._disabled:
            _logger.info(
                "ReporterReputationStore: %s not set; running in pure "
                "in-memory mode.",
                DATABASE_URL_ENV,
            )
        else:
            try:
                self._ensure_schema()
                self._hydrate_from_postgres()
            except Exception as exc:  # noqa: BLE001
                _logger.error(
                    "ReporterReputationStore: bootstrap failed: %s. "
                    "Falling back to in-memory mode.",
                    exc,
                )
                self._disabled = True

    def record_observation(
        self,
        *,
        reporter: str,
        agreed_with_consensus: bool,
        observed_at: datetime | None = None,
    ) -> None:
        """
        Record one accuracy observation for a reporter.

        ``agreed_with_consensus`` should reflect whether the reporter's label
        agrees with either ground truth or the system's settled consensus
        (multi-source agreement, audit sign-off). Pass False to mark a
        disagreement; the disagreement detector and replay validator both
        feed into this.
        """
        normalized = (reporter or "").strip()
        if not normalized:
            raise ValueError("reporter must be a non-blank string")

        now = observed_at or self._clock()
        with self._lock:
            state = self._reporters.setdefault(normalized, _ReporterState())
            self._apply_decay(state, now=now)
            state.observations += 1
            state.last_event_at = now
            if agreed_with_consensus:
                state.agreements += 1
                state.decayed_agreement += 1.0
            else:
                state.disagreements += 1
                state.decayed_disagreement += 1.0
            self._persist_state(reporter=normalized, state=state)

    def get(self, reporter: str) -> ReporterReputation:
        """Return the (snapshot) reputation for one reporter."""
        normalized = (reporter or "").strip()
        if not normalized:
            raise ValueError("reporter must be a non-blank string")

        now = self._clock()
        with self._lock:
            state = self._reporters.get(normalized)
            if state is None:
                return self._neutral_snapshot(normalized)
            self._apply_decay(state, now=now)
            return self._snapshot(reporter=normalized, state=state)

    def list_all(self) -> tuple[ReporterReputation, ...]:
        now = self._clock()
        with self._lock:
            for state in self._reporters.values():
                self._apply_decay(state, now=now)
            return tuple(
                self._snapshot(reporter=reporter, state=state)
                for reporter, state in self._reporters.items()
            )

    def weight_for(self, reporter: str | None) -> float:
        """
        Convenience: return only the effective weight, or neutral=1.0 when
        the reporter is unknown or blank.
        """
        if not reporter or not reporter.strip():
            return DEFAULT_NEUTRAL_WEIGHT
        return self.get(reporter).effective_weight

    def reset(self, reporter: str | None = None) -> None:
        with self._lock:
            if reporter is None:
                self._reporters.clear()
                self._persist_clear_all()
            else:
                key = reporter.strip()
                self._reporters.pop(key, None)
                self._persist_delete(reporter=key)

    # ── internals ─────────────────────────────────────────────────────────

    def _apply_decay(self, state: _ReporterState, *, now: datetime) -> None:
        if state.last_event_at is None:
            return
        elapsed = now - state.last_event_at
        if elapsed.total_seconds() <= 0:
            return
        if state.observations < self._min_observations:
            return
        # Exponential decay with the configured half-life.
        decay_factor = 0.5 ** (
            elapsed.total_seconds() / self._half_life.total_seconds()
        )
        state.decayed_agreement *= decay_factor
        state.decayed_disagreement *= decay_factor
        state.last_event_at = now

    def _snapshot(
        self,
        *,
        reporter: str,
        state: _ReporterState,
    ) -> ReporterReputation:
        observations = state.observations
        accuracy = (
            state.agreements / observations if observations > 0 else 1.0
        )
        disagreement_rate = (
            state.disagreements / observations if observations > 0 else 0.0
        )
        weight = self._compute_weight(state=state)
        return ReporterReputation(
            reporter=reporter,
            observations=observations,
            agreements=state.agreements,
            disagreements=state.disagreements,
            decayed_agreement_score=round(state.decayed_agreement, 4),
            decayed_disagreement_score=round(state.decayed_disagreement, 4),
            last_seen_at=state.last_event_at,
            effective_weight=round(weight, 4),
            accuracy=round(accuracy, 4),
            disagreement_rate=round(disagreement_rate, 4),
        )

    def _neutral_snapshot(self, reporter: str) -> ReporterReputation:
        return ReporterReputation(
            reporter=reporter,
            observations=0,
            agreements=0,
            disagreements=0,
            decayed_agreement_score=0.0,
            decayed_disagreement_score=0.0,
            last_seen_at=None,
            effective_weight=DEFAULT_NEUTRAL_WEIGHT,
            accuracy=1.0,
            disagreement_rate=0.0,
        )

    def _compute_weight(self, *, state: _ReporterState) -> float:
        """
        Map decayed agreement vs disagreement scores onto a bounded weight.

        Logic:
          - new reporters (under min_observations) get the neutral weight
          - the ratio of decayed agreements to total decayed events drives
            the weight, smoothed by a Laplace-like prior so small samples
            don't catapult to the ceiling
          - the result is clamped into [floor, ceiling]
        """
        if state.observations < self._min_observations:
            return DEFAULT_NEUTRAL_WEIGHT

        agreement = state.decayed_agreement
        disagreement = state.decayed_disagreement
        # Laplace smoothing with a small prior (treat each reporter as
        # having seen one neutral event).
        smoothed_agreement = agreement + 1.0
        total = agreement + disagreement + 2.0
        ratio = smoothed_agreement / total

        # Map ratio in [0,1] into [floor, ceiling]:
        # ratio == 0.5 -> neutral weight 1.0
        # ratio -> 1.0 climbs toward ceiling
        # ratio -> 0.0 falls toward floor
        if ratio >= 0.5:
            span = self._ceiling - DEFAULT_NEUTRAL_WEIGHT
            scaled = (ratio - 0.5) / 0.5
            weight = DEFAULT_NEUTRAL_WEIGHT + span * _smooth(scaled)
        else:
            span = DEFAULT_NEUTRAL_WEIGHT - self._floor
            scaled = (0.5 - ratio) / 0.5
            weight = DEFAULT_NEUTRAL_WEIGHT - span * _smooth(scaled)

        return max(self._floor, min(self._ceiling, weight))

    # ── postgres internals ────────────────────────────────────────────────

    def _ensure_schema(self) -> None:
        with psycopg.connect(self._dsn, autocommit=True) as conn:
            with conn.cursor() as cur:
                cur.execute(SCHEMA_SQL)

    def _hydrate_from_postgres(self) -> None:
        with psycopg.connect(self._dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT reporter, observations, agreements, disagreements,
                           decayed_agreement, decayed_disagreement, last_event_at
                      FROM tex_reporter_reputation
                    """
                )
                rows = cur.fetchall()
        for row in rows:
            (
                reporter,
                observations,
                agreements,
                disagreements,
                decayed_agreement,
                decayed_disagreement,
                last_event_at,
            ) = row
            self._reporters[reporter] = _ReporterState(
                observations=observations,
                agreements=agreements,
                disagreements=disagreements,
                decayed_agreement=float(decayed_agreement),
                decayed_disagreement=float(decayed_disagreement),
                last_event_at=last_event_at,
            )
        if rows:
            _logger.info(
                "ReporterReputationStore: hydrated %d reporters from Postgres.",
                len(rows),
            )

    def _persist_state(self, *, reporter: str, state: _ReporterState) -> None:
        if self._disabled:
            return
        try:
            with psycopg.connect(self._dsn) as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO tex_reporter_reputation (
                            reporter, observations, agreements, disagreements,
                            decayed_agreement, decayed_disagreement,
                            last_event_at, updated_at
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, now())
                        ON CONFLICT (reporter) DO UPDATE SET
                            observations         = EXCLUDED.observations,
                            agreements           = EXCLUDED.agreements,
                            disagreements        = EXCLUDED.disagreements,
                            decayed_agreement    = EXCLUDED.decayed_agreement,
                            decayed_disagreement = EXCLUDED.decayed_disagreement,
                            last_event_at        = EXCLUDED.last_event_at,
                            updated_at           = now()
                        """,
                        (
                            reporter,
                            state.observations,
                            state.agreements,
                            state.disagreements,
                            state.decayed_agreement,
                            state.decayed_disagreement,
                            state.last_event_at,
                        ),
                    )
                conn.commit()
        except Exception as exc:  # noqa: BLE001
            _logger.error(
                "ReporterReputationStore: persist failed for %s: %s",
                reporter, exc,
            )

    def _persist_delete(self, *, reporter: str) -> None:
        if self._disabled:
            return
        try:
            with psycopg.connect(self._dsn) as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "DELETE FROM tex_reporter_reputation WHERE reporter = %s",
                        (reporter,),
                    )
                conn.commit()
        except Exception as exc:  # noqa: BLE001
            _logger.error(
                "ReporterReputationStore: delete failed for %s: %s", reporter, exc,
            )

    def _persist_clear_all(self) -> None:
        if self._disabled:
            return
        try:
            with psycopg.connect(self._dsn) as conn:
                with conn.cursor() as cur:
                    cur.execute("DELETE FROM tex_reporter_reputation")
                conn.commit()
        except Exception as exc:  # noqa: BLE001
            _logger.error("ReporterReputationStore: clear-all failed: %s", exc)

    @property
    def is_durable(self) -> bool:
        return not self._disabled


def _smooth(x: float) -> float:
    """Sublinear smoothing to avoid extreme reactions to small ratio shifts."""
    if x <= 0.0:
        return 0.0
    if x >= 1.0:
        return 1.0
    return math.sqrt(x)


__all__ = [
    "DEFAULT_CEILING",
    "DEFAULT_FLOOR",
    "DEFAULT_HALF_LIFE",
    "DEFAULT_NEUTRAL_WEIGHT",
    "ReporterReputation",
    "ReporterReputationStore",
]

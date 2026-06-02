"""
Discovery-layer metrics.

Process-local counters that the scheduler and discovery service
update during scans. Surfaced via /v1/system/state under a
``metrics`` block and via /v1/discovery/metrics directly.

This is deliberately not a Prometheus client, not a StatsD client,
not OpenTelemetry. It's a minimal in-process tally so a deploy can
answer "did the scheduler actually run" and "what's the average
scan duration" without standing up a metrics backend. When Tex is
ready for an external metrics system, the meters here become the
emitting points.
"""

from __future__ import annotations

import threading
from collections import defaultdict
from datetime import UTC, datetime


class DiscoveryMetrics:
    """In-process metrics for the discovery layer."""

    __slots__ = (
        "_lock",
        "_started_at",
        "_scans_started",
        "_scans_completed",
        "_scans_failed",
        "_scans_idempotent_replays",
        "_lock_conflicts",
        "_total_candidates_seen",
        "_total_registered",
        "_total_drift_new",
        "_total_drift_changed",
        "_total_drift_disappeared",
        "_total_drift_silent_misses",
        "_total_drift_recovered",
        "_total_drift_reappeared",
        "_total_alerts_dispatched",
        "_total_snapshots_captured",
        "_total_scan_duration_seconds",
        "_per_connector_failures",
        "_per_connector_successes",
        "_last_scan_completed_at",
    )

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._started_at = datetime.now(UTC)
        self._scans_started = 0
        self._scans_completed = 0
        self._scans_failed = 0
        self._scans_idempotent_replays = 0
        self._lock_conflicts = 0
        self._total_candidates_seen = 0
        self._total_registered = 0
        self._total_drift_new = 0
        self._total_drift_changed = 0
        self._total_drift_disappeared = 0
        self._total_drift_silent_misses = 0
        self._total_drift_recovered = 0
        self._total_drift_reappeared = 0
        self._total_alerts_dispatched = 0
        self._total_snapshots_captured = 0
        self._total_scan_duration_seconds = 0.0
        self._per_connector_failures: dict[str, int] = defaultdict(int)
        self._per_connector_successes: dict[str, int] = defaultdict(int)
        self._last_scan_completed_at: float | None = None

    # ------------------------------------------------------------------ writes

    def record_scan_started(self) -> None:
        with self._lock:
            self._scans_started += 1

    def record_scan_completed(
        self, *, duration_seconds: float, candidates_seen: int, registered: int,
    ) -> None:
        with self._lock:
            self._scans_completed += 1
            self._total_scan_duration_seconds += float(duration_seconds or 0)
            self._total_candidates_seen += int(candidates_seen or 0)
            self._total_registered += int(registered or 0)
            self._last_scan_completed_at = datetime.now(UTC).timestamp()

    def record_scan_failed(self) -> None:
        with self._lock:
            self._scans_failed += 1

    def record_idempotent_replay(self) -> None:
        with self._lock:
            self._scans_idempotent_replays += 1

    def record_lock_conflict(self) -> None:
        with self._lock:
            self._lock_conflicts += 1

    def record_drift(
        self, *, new: int = 0, changed: int = 0, disappeared: int = 0,
        silent_misses: int = 0, recovered: int = 0, reappeared: int = 0,
    ) -> None:
        with self._lock:
            self._total_drift_new += int(new)
            self._total_drift_changed += int(changed)
            self._total_drift_disappeared += int(disappeared)
            self._total_drift_silent_misses += int(silent_misses)
            self._total_drift_recovered += int(recovered)
            self._total_drift_reappeared += int(reappeared)

    def record_alert_dispatched(self) -> None:
        with self._lock:
            self._total_alerts_dispatched += 1

    def record_snapshot_captured(self) -> None:
        with self._lock:
            self._total_snapshots_captured += 1

    def record_connector_result(self, *, name: str, succeeded: bool) -> None:
        with self._lock:
            if succeeded:
                self._per_connector_successes[name] += 1
            else:
                self._per_connector_failures[name] += 1

    # ------------------------------------------------------------------ reads

    def snapshot(self) -> dict:
        with self._lock:
            avg_duration = (
                self._total_scan_duration_seconds / self._scans_completed
                if self._scans_completed
                else 0.0
            )
            return {
                "started_at": self._started_at.isoformat(),
                "scans_started": self._scans_started,
                "scans_completed": self._scans_completed,
                "scans_failed": self._scans_failed,
                "scans_idempotent_replays": self._scans_idempotent_replays,
                "lock_conflicts": self._lock_conflicts,
                "total_candidates_seen": self._total_candidates_seen,
                "total_registered": self._total_registered,
                "drift": {
                    "new": self._total_drift_new,
                    "changed": self._total_drift_changed,
                    "disappeared": self._total_drift_disappeared,
                    "silent_misses": self._total_drift_silent_misses,
                    "recovered": self._total_drift_recovered,
                    "reappeared": self._total_drift_reappeared,
                },
                "alerts_dispatched": self._total_alerts_dispatched,
                "snapshots_captured": self._total_snapshots_captured,
                "average_scan_duration_seconds": round(avg_duration, 3),
                "last_scan_completed_at": self._last_scan_completed_at,
                "per_connector_successes": dict(self._per_connector_successes),
                "per_connector_failures": dict(self._per_connector_failures),
            }


__all__ = ["DiscoveryMetrics"]

"""
Background discovery scan scheduler with drift detection.

Runs ``DiscoveryService.scan(...)`` on a configurable interval against
a configurable list of tenants. After each scan, diffs the candidates
seen in this run against the candidates seen in the prior run for
the same tenant, and emits drift events for:

    NEW_AGENT          — first appearance of a reconciliation_key
    AGENT_CHANGED      — surface drift, lifecycle change, risk change
    AGENT_DISAPPEARED  — was present last run, gone this run

Each drift event passes through the configured ``AlertEngine`` so
threshold rules can fire to logs, webhooks, or Slack in real time.

Wired into FastAPI's lifespan so it starts when the app starts and
stops cleanly when the app stops.

The scheduler is intentionally simple. It is one daemon thread that
loops, sleeps, scans, diffs, alerts. It does not depend on Celery,
APScheduler, asyncio, or any other heavy machinery. Failure modes
are local: a bad scan logs and the loop continues; a slow webhook
runs on its own dispatch thread; an app shutdown signals via
``stop()`` and the daemon thread exits within one tick.

The scheduler is opt-in. With no env vars set, no scans happen and
the runtime behavior is identical to V14 (operator-triggered scans
only). When ``TEX_DISCOVERY_SCAN_INTERVAL_SECONDS`` is set, the
scheduler activates and scans every tenant in
``TEX_DISCOVERY_SCAN_TENANTS`` (comma-separated) at that interval.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from typing import Iterable
from uuid import UUID

from tex.discovery.alerts import AlertEngine
from tex.discovery.presence import PresenceTracker, TransitionEvent
from tex.discovery.service import DiscoveryScanResult, DiscoveryService, ScanInProgress
from tex.domain.discovery import (
    DiscoveryLedgerEntry,
    ReconciliationAction,
)
from tex.observability.discovery_metrics import DiscoveryMetrics
from tex.stores.drift_events import DriftEventKind, DriftEventStore

_logger = logging.getLogger(__name__)


# Env vars
INTERVAL_ENV = "TEX_DISCOVERY_SCAN_INTERVAL_SECONDS"
TENANTS_ENV = "TEX_DISCOVERY_SCAN_TENANTS"
TIMEOUT_ENV = "TEX_DISCOVERY_SCAN_TIMEOUT_SECONDS"

# Defaults: hourly scans, default tenant list.
DEFAULT_INTERVAL_SECONDS = 3_600
DEFAULT_TIMEOUT_SECONDS = 60.0

# Minimum interval guard: don't let an operator hammer external APIs
# by setting a 5-second interval.
MIN_INTERVAL_SECONDS = 30


class BackgroundScanScheduler:
    """
    Daemon-thread scheduler that triggers periodic discovery scans
    and emits drift events for what changed between runs.

    V16: closes the control loop — at the end of each cycle the
    scheduler can also capture a governance snapshot bound to the
    run via ``snapshot_capture_callable``. The callable takes a
    tenant_id + scan_run dict and returns the captured snapshot
    record; snapshot persistence is left to whatever store is wired
    on the runtime so the scheduler stays decoupled from the
    snapshot store's exact interface.
    """

    __slots__ = (
        "_service",
        "_drift_store",
        "_alert_engine",
        "_presence_tracker",
        "_snapshot_capture_callable",
        "_policy_version",
        "_metrics",
        "_interval_seconds",
        "_tenants",
        "_timeout_seconds",
        "_stop_event",
        "_thread",
        "_last_run_completed_at",
        "_last_run_summary",
        "_run_count",
        "_last_seen_by_tenant",
    )

    def __init__(
        self,
        *,
        service: DiscoveryService,
        drift_store: DriftEventStore | None = None,
        alert_engine: AlertEngine | None = None,
        presence_tracker: PresenceTracker | None = None,
        interval_seconds: int | None = None,
        tenants: Iterable[str] | None = None,
        timeout_seconds: float | None = None,
        snapshot_capture_callable=None,
        policy_version: str | None = None,
        metrics: DiscoveryMetrics | None = None,
    ) -> None:
        self._service = service
        self._drift_store = drift_store
        self._alert_engine = alert_engine
        self._presence_tracker = presence_tracker
        self._snapshot_capture_callable = snapshot_capture_callable
        self._policy_version = policy_version
        self._metrics = metrics
        self._interval_seconds = self._resolve_interval(interval_seconds)
        self._tenants = tuple(self._resolve_tenants(tenants))
        self._timeout_seconds = self._resolve_timeout(timeout_seconds)
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._last_run_completed_at: float | None = None
        self._last_run_summary: dict | None = None
        self._run_count = 0
        self._last_seen_by_tenant: dict[str, dict[str, dict]] = {}

    # ------------------------------------------------------------------ lifecycle

    def start(self) -> None:
        """Launch the background thread. Idempotent."""
        if self._thread is not None and self._thread.is_alive():
            return
        if not self._tenants:
            _logger.info(
                "BackgroundScanScheduler: no tenants configured; not starting."
            )
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run_loop,
            name="tex-discovery-scheduler",
            daemon=True,
        )
        self._thread.start()
        _logger.info(
            "BackgroundScanScheduler: started; interval=%ds, tenants=%s",
            self._interval_seconds,
            list(self._tenants),
        )

    def stop(self, *, join_timeout: float = 5.0) -> None:
        """Signal the loop to exit and wait briefly for it to finish."""
        self._stop_event.set()
        thread = self._thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=join_timeout)
        _logger.info("BackgroundScanScheduler: stopped")

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    @property
    def status(self) -> dict:
        """Snapshot of scheduler state. Used by the admin endpoint."""
        return {
            "running": self.is_running,
            "interval_seconds": self._interval_seconds,
            "tenants": list(self._tenants),
            "timeout_seconds": self._timeout_seconds,
            "run_count": self._run_count,
            "last_run_completed_at": self._last_run_completed_at,
            "last_run_summary": self._last_run_summary,
            "drift_durable": (
                self._drift_store.is_durable
                if self._drift_store is not None
                else False
            ),
            "alerts_enabled": (
                self._alert_engine.is_enabled
                if self._alert_engine is not None
                else False
            ),
            "alert_sinks": (
                self._alert_engine.sink_names
                if self._alert_engine is not None
                else []
            ),
            "presence_tracker_enabled": self._presence_tracker is not None,
            "presence_threshold": (
                self._presence_tracker.threshold
                if self._presence_tracker is not None
                else None
            ),
            "presence_durable": (
                self._presence_tracker.is_durable
                if self._presence_tracker is not None
                else False
            ),
        }

    def trigger_now(self) -> dict:
        """
        Run one scan cycle synchronously, outside the loop. Used by
        admin tooling and by tests so we can drive a deterministic
        scan without waiting for the interval.
        """
        return self._run_one_cycle()

    # ------------------------------------------------------------------ loop

    def _run_loop(self) -> None:
        """The actual worker. Sleeps, scans, sleeps, scans."""
        # Run once on startup so the first scan does not have to wait
        # an entire interval. This makes the "is the scheduler
        # working" check observable from a deploy.
        self._run_one_cycle()

        while not self._stop_event.is_set():
            # Sleep in short slices so stop() is responsive.
            slept = 0.0
            slice_seconds = 1.0
            while slept < self._interval_seconds and not self._stop_event.is_set():
                time.sleep(min(slice_seconds, self._interval_seconds - slept))
                slept += slice_seconds
            if self._stop_event.is_set():
                break
            self._run_one_cycle()

    def _run_one_cycle(self) -> dict:
        cycle_started = time.time()
        per_tenant_summaries: list[dict] = []
        for tenant_id in self._tenants:
            if self._metrics is not None:
                self._metrics.record_scan_started()
            try:
                run = self._service.scan(
                    tenant_id=tenant_id,
                    timeout_seconds=self._timeout_seconds,
                    trigger="scheduled",
                    policy_version=self._policy_version,
                )
                drift_counts = self._emit_drift_events(tenant_id=tenant_id, run=run)
                summary = run.summary
                snapshot_id: str | None = None
                if self._snapshot_capture_callable is not None:
                    try:
                        captured = self._snapshot_capture_callable(
                            tenant_id=tenant_id, run=run,
                        )
                        if isinstance(captured, dict):
                            snapshot_id = captured.get("snapshot_id")
                            if self._metrics is not None and snapshot_id:
                                self._metrics.record_snapshot_captured()
                    except Exception as exc:  # noqa: BLE001
                        _logger.warning(
                            "BackgroundScanScheduler: snapshot capture failed "
                            "for tenant=%s: %s",
                            tenant_id, exc,
                        )

                # Metrics: counters for every dimension we care about.
                if self._metrics is not None:
                    self._metrics.record_scan_completed(
                        duration_seconds=summary.duration_seconds,
                        candidates_seen=summary.candidates_seen,
                        registered=summary.registered_count,
                    )
                    self._metrics.record_drift(
                        new=drift_counts.get("new", 0),
                        changed=drift_counts.get("changed", 0),
                        disappeared=drift_counts.get("disappeared", 0),
                        silent_misses=drift_counts.get("silent_misses", 0),
                        recovered=drift_counts.get("recovered", 0),
                        reappeared=drift_counts.get("reappeared", 0),
                    )

                per_tenant_summaries.append(
                    {
                        "tenant_id": tenant_id,
                        "run_id": str(summary.run_id),
                        "scan_run_id": (
                            str(run.scan_run_id) if run.scan_run_id else None
                        ),
                        "ledger_seq_start": run.ledger_seq_start,
                        "ledger_seq_end": run.ledger_seq_end,
                        "registry_state_hash": run.registry_state_hash,
                        "snapshot_id": snapshot_id,
                        "candidates_seen": summary.candidates_seen,
                        "registered_count": summary.registered_count,
                        "updated_drift_count": summary.updated_drift_count,
                        "quarantined_count": summary.quarantined_count,
                        "held_count": summary.held_count,
                        "errors": list(summary.errors),
                        "drift": drift_counts,
                    }
                )
            except ScanInProgress as exc:
                if self._metrics is not None:
                    self._metrics.record_lock_conflict()
                _logger.info(
                    "BackgroundScanScheduler: skipping tenant=%s; another "
                    "scan in progress (run_id=%s)",
                    tenant_id, exc.holder_run_id,
                )
                per_tenant_summaries.append(
                    {"tenant_id": tenant_id, "skipped": "scan_in_progress"}
                )
            except Exception as exc:  # noqa: BLE001
                if self._metrics is not None:
                    self._metrics.record_scan_failed()
                _logger.exception(
                    "BackgroundScanScheduler: scan failed for tenant=%s: %s",
                    tenant_id,
                    exc,
                )
                per_tenant_summaries.append(
                    {"tenant_id": tenant_id, "error": str(exc)}
                )
        cycle_duration = time.time() - cycle_started
        self._last_run_completed_at = time.time()
        self._last_run_summary = {
            "duration_seconds": round(cycle_duration, 3),
            "tenants": per_tenant_summaries,
        }
        self._run_count += 1
        _logger.info(
            "BackgroundScanScheduler: cycle %d complete in %.2fs",
            self._run_count,
            cycle_duration,
        )
        return self._last_run_summary

    # ------------------------------------------------------------------ drift detection

    def _emit_drift_events(
        self,
        *,
        tenant_id: str,
        run: DiscoveryScanResult,
    ) -> dict[str, int]:
        """
        Diff this run's entries against the prior run's entries for
        the same tenant. Emit drift events for what's new, what
        changed, and what disappeared.
        """
        if self._drift_store is None:
            return {"new": 0, "changed": 0, "disappeared": 0}

        prior = self._last_seen_by_tenant.get(tenant_id, {})
        seen_now: dict[str, dict] = {}

        new_count = changed_count = disappeared_count = 0
        silent_miss_count = recovered_count = reappeared_count = 0
        scan_run_id = run.summary.run_id
        scan_run_id_str = str(scan_run_id) if scan_run_id else None

        for entry in run.entries:
            recon_key = entry.outcome.reconciliation_key
            digest = self._entry_digest(entry)
            seen_now[recon_key] = digest

            # Presence tracker observes "seen". This silently resets
            # missing counts and surfaces a REAPPEARED transition if
            # the key was previously confirmed-disappeared.
            transition_event = TransitionEvent.NO_EVENT
            if self._presence_tracker is not None:
                _, transition_event = self._presence_tracker.observe_seen(
                    tenant_id=tenant_id,
                    reconciliation_key=recon_key,
                    discovery_source=digest["source"],
                    scan_run_id=scan_run_id_str,
                )
                if transition_event is TransitionEvent.RECOVERED:
                    recovered_count += 1
                elif transition_event is TransitionEvent.REAPPEARED:
                    reappeared_count += 1

            previous = prior.get(recon_key)
            if previous is None:
                # First time we've seen this reconciliation_key under
                # this tenant. Note: a candidate that was registered
                # last run and unchanged this run does NOT come back
                # as new — both runs include it in seen_now/prior.
                event = self._drift_store.emit(
                    tenant_id=tenant_id,
                    kind=DriftEventKind.NEW_AGENT,
                    reconciliation_key=recon_key,
                    discovery_source=digest["source"],
                    agent_id=_uuid_or_none(digest.get("agent_id")),
                    severity="INFO",
                    summary=(
                        f"New agent observed via {digest['source']}: "
                        f"{digest.get('name') or recon_key}"
                    ),
                    details={
                        "name": digest.get("name"),
                        "risk_band": digest.get("risk_band"),
                        "auto_registered": digest.get("auto_registered"),
                        "action": digest.get("action"),
                        "presence_transition": str(transition_event),
                    },
                    scan_run_id=scan_run_id,
                )
                new_count += 1
                self._notify(event)
                continue

            if not _digests_equivalent(previous, digest):
                change_details = _changes_between(previous, digest)
                event = self._drift_store.emit(
                    tenant_id=tenant_id,
                    kind=DriftEventKind.AGENT_CHANGED,
                    reconciliation_key=recon_key,
                    discovery_source=digest["source"],
                    agent_id=_uuid_or_none(digest.get("agent_id")),
                    severity="WARN" if change_details.get("change_kind") == "capability_widened" else "INFO",
                    summary=(
                        f"Agent changed on {digest['source']}: "
                        f"{digest.get('name') or recon_key}"
                    ),
                    details={
                        "name": digest.get("name"),
                        **change_details,
                    },
                    scan_run_id=scan_run_id,
                )
                changed_count += 1
                self._notify(event)

        # Disappearance pass — now soft.
        # When a presence tracker is wired, missing keys advance through
        # the state machine; only the transition into CONFIRMED produces
        # an AGENT_DISAPPEARED drift event. Without a tracker we
        # preserve V15 behavior (immediate emission).
        for prior_key, prior_digest in prior.items():
            if prior_key in seen_now:
                continue

            should_emit_disappeared = True
            if self._presence_tracker is not None:
                _, miss_event = self._presence_tracker.observe_missing(
                    tenant_id=tenant_id,
                    reconciliation_key=prior_key,
                    discovery_source=prior_digest.get("source"),
                    scan_run_id=scan_run_id_str,
                )
                if miss_event is TransitionEvent.CONFIRMED_DISAPPEARED:
                    should_emit_disappeared = True
                elif miss_event is TransitionEvent.SILENT_MISS:
                    silent_miss_count += 1
                    should_emit_disappeared = False
                else:
                    should_emit_disappeared = False

            if not should_emit_disappeared:
                continue

            event = self._drift_store.emit(
                tenant_id=tenant_id,
                kind=DriftEventKind.AGENT_DISAPPEARED,
                reconciliation_key=prior_key,
                discovery_source=prior_digest.get("source"),
                agent_id=_uuid_or_none(prior_digest.get("agent_id")),
                severity="WARN",
                summary=(
                    f"Agent no longer observed via "
                    f"{prior_digest.get('source')}: "
                    f"{prior_digest.get('name') or prior_key}"
                ),
                details={
                    "name": prior_digest.get("name"),
                    "last_seen_revision": prior_digest.get("revision"),
                    "soft_disappearance": self._presence_tracker is not None,
                },
                scan_run_id=scan_run_id,
            )
            disappeared_count += 1
            self._notify(event)

        self._last_seen_by_tenant[tenant_id] = seen_now
        return {
            "new": new_count,
            "changed": changed_count,
            "disappeared": disappeared_count,
            "silent_misses": silent_miss_count,
            "recovered": recovered_count,
            "reappeared": reappeared_count,
        }

    @staticmethod
    def _entry_digest(entry: DiscoveryLedgerEntry) -> dict:
        """A small dict that captures just the fields we diff between runs."""
        candidate = entry.candidate
        outcome = entry.outcome
        return {
            "source": str(candidate.source),
            "name": candidate.name,
            "risk_band": str(candidate.risk_band),
            "tenant_id": candidate.tenant_id,
            "tools": list(candidate.capability_hints.inferred_tools),
            "channels": list(candidate.capability_hints.inferred_channels),
            "data_scopes": list(candidate.capability_hints.inferred_data_scopes),
            "surface_unbounded": candidate.capability_hints.surface_unbounded,
            "agent_id": str(outcome.resulting_agent_id) if outcome.resulting_agent_id else None,
            "auto_registered": outcome.action is ReconciliationAction.REGISTERED,
            "action": str(outcome.action),
        }

    def _notify(self, event) -> None:
        if self._alert_engine is None:
            return
        try:
            self._alert_engine.handle_drift_event(event)
            if self._metrics is not None:
                self._metrics.record_alert_dispatched()
        except Exception as exc:  # noqa: BLE001
            _logger.error("BackgroundScanScheduler: alert dispatch raised: %s", exc)

    # ------------------------------------------------------------------ resolution

    @staticmethod
    def _resolve_interval(explicit: int | None) -> int:
        if explicit is not None:
            return max(MIN_INTERVAL_SECONDS, int(explicit))
        raw = os.environ.get(INTERVAL_ENV, "").strip()
        if not raw:
            return DEFAULT_INTERVAL_SECONDS
        try:
            interval = int(raw)
        except ValueError:
            _logger.warning(
                "BackgroundScanScheduler: invalid %s=%r; using default %ds",
                INTERVAL_ENV,
                raw,
                DEFAULT_INTERVAL_SECONDS,
            )
            return DEFAULT_INTERVAL_SECONDS
        return max(MIN_INTERVAL_SECONDS, interval)

    @staticmethod
    def _resolve_tenants(explicit: Iterable[str] | None) -> list[str]:
        if explicit is not None:
            return [t.strip() for t in explicit if t and t.strip()]
        raw = os.environ.get(TENANTS_ENV, "").strip()
        if not raw:
            return []
        return [t.strip() for t in raw.split(",") if t.strip()]

    @staticmethod
    def _resolve_timeout(explicit: float | None) -> float:
        if explicit is not None:
            return float(explicit)
        raw = os.environ.get(TIMEOUT_ENV, "").strip()
        if not raw:
            return DEFAULT_TIMEOUT_SECONDS
        try:
            return float(raw)
        except ValueError:
            return DEFAULT_TIMEOUT_SECONDS


def _digests_equivalent(a: dict, b: dict) -> bool:
    """Compare two digests on the fields that matter."""
    fields = ("name", "risk_band", "tools", "channels", "data_scopes", "surface_unbounded", "action")
    return all(a.get(f) == b.get(f) for f in fields)


def _changes_between(prior: dict, current: dict) -> dict:
    """Produce a small structured summary of what changed."""
    added_tools = sorted(set(current.get("tools", [])) - set(prior.get("tools", [])))
    removed_tools = sorted(set(prior.get("tools", [])) - set(current.get("tools", [])))
    added_scopes = sorted(set(current.get("data_scopes", [])) - set(prior.get("data_scopes", [])))
    removed_scopes = sorted(set(prior.get("data_scopes", [])) - set(current.get("data_scopes", [])))

    change_kind = "metadata"
    if added_tools or added_scopes:
        change_kind = "capability_widened"
    elif removed_tools or removed_scopes:
        change_kind = "capability_narrowed"
    elif prior.get("risk_band") != current.get("risk_band"):
        change_kind = "risk_changed"

    return {
        "change_kind": change_kind,
        "added": added_tools + added_scopes,
        "removed": removed_tools + removed_scopes,
        "prior_risk_band": prior.get("risk_band"),
        "current_risk_band": current.get("risk_band"),
        "prior_action": prior.get("action"),
        "current_action": current.get("action"),
    }


def _uuid_or_none(value):
    if value is None:
        return None
    try:
        return UUID(str(value))
    except (ValueError, TypeError):
        return None


__all__ = ["BackgroundScanScheduler", "INTERVAL_ENV", "TENANTS_ENV", "TIMEOUT_ENV"]

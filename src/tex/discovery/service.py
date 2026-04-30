"""
Discovery service.

The DiscoveryService is the orchestrator that ties the discovery
layer together. It takes a list of connectors and, when invoked,

  1. Runs every connector's scan against the configured tenant.
  2. Looks up each candidate's reconciliation_key in a key→agent_id
     index built on top of the existing agent registry.
  3. Asks the ReconciliationEngine to decide what to do with each
     candidate.
  4. Applies the decision: registers new agents, updates capability
     surfaces, quarantines drifted agents.
  5. Writes one entry per outcome to the discovery ledger.
  6. Returns a DiscoveryScanRun summary.

The service is designed so connectors and the engine can be tested
independently of stores. Service-level tests cover the integration:
candidates flow through, registry mutations happen, ledger entries
land, summary counts are correct.

The service is platform-agnostic in the same way the rest of Tex is.
You wire mock connectors for the codebase's test suite, and live
connectors for production. The service does not know which is which.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from threading import RLock
from typing import Iterable
from uuid import UUID

from tex.discovery.connectors.base import (
    ConnectorContext,
    ConnectorError,
    DiscoveryConnector,
)
from tex.discovery.reconciliation import (
    ReconciliationDecision,
    ReconciliationEngine,
)
from tex.domain.agent import (
    AgentIdentity,
    AgentLifecycleStatus,
    CapabilitySurface,
)
from tex.domain.discovery import (
    CandidateAgent,
    DiscoveryLedgerEntry,
    DiscoveryScanRun,
    DiscoverySource,
    ReconciliationAction,
)
from tex.stores.agent_registry import InMemoryAgentRegistry
from tex.stores.connector_health import ConnectorHealthStore
from tex.stores.discovery_ledger import InMemoryDiscoveryLedger
from tex.stores.scan_runs import ScanLockHeld, ScanRunStore

_logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Reconciliation index — lookup of (source, tenant, external_id) → agent_id
# ---------------------------------------------------------------------------


class ReconciliationIndex:
    """
    Bidirectional index between reconciliation keys and registered
    agent_ids.

    The registry's primary key is the agent_id (a UUID Tex generates).
    Discovery operates on the platform-side identity tuple
    (source, tenant_id, external_id). The index lets the discovery
    service translate between them in O(1).

    The index is updated by the discovery service on every promotion
    and is also rebuilt from the registry on construction so an
    operator-registered agent (POST /v1/agents with a discovery_*
    metadata) is recognized by subsequent scans.
    """

    __slots__ = ("_lock", "_key_to_agent_id", "_agent_id_to_key")

    def __init__(
        self,
        *,
        registry: InMemoryAgentRegistry | None = None,
    ) -> None:
        self._lock = RLock()
        self._key_to_agent_id: dict[str, UUID] = {}
        self._agent_id_to_key: dict[UUID, str] = {}
        if registry is not None:
            self._bootstrap_from_registry(registry)

    def _bootstrap_from_registry(self, registry: InMemoryAgentRegistry) -> None:
        """
        Read every agent in the registry and, if its metadata carries
        discovery provenance, register the link in the index. This
        lets operators add agents manually with the discovery metadata
        and have the discovery layer treat them as "already known."
        """
        for agent in registry.list_all():
            key = _key_from_metadata(agent)
            if key is not None:
                self._key_to_agent_id[key] = agent.agent_id
                self._agent_id_to_key[agent.agent_id] = key

    def get_agent_id(self, key: str) -> UUID | None:
        with self._lock:
            return self._key_to_agent_id.get(key)

    def link(self, *, key: str, agent_id: UUID) -> None:
        with self._lock:
            self._key_to_agent_id[key] = agent_id
            self._agent_id_to_key[agent_id] = key

    def __contains__(self, key: str) -> bool:
        with self._lock:
            return key in self._key_to_agent_id

    def __len__(self) -> int:
        with self._lock:
            return len(self._key_to_agent_id)


def _key_from_metadata(agent: AgentIdentity) -> str | None:
    """
    Reconstruct a reconciliation key from an AgentIdentity's metadata.

    The reconciliation engine places ``discovery_source`` and
    ``discovery_external_id`` into the metadata of every auto-promoted
    agent. Operators can match this on manual registrations to opt in
    to discovery linkage; agents without these fields are not
    considered "discovered" and discovery scans treat them as new
    candidates if the platform reports them.
    """
    metadata = agent.metadata or {}
    source = metadata.get("discovery_source")
    external_id = metadata.get("discovery_external_id")
    if not isinstance(source, str) or not isinstance(external_id, str):
        return None
    return f"{source}:{agent.tenant_id}:{external_id.casefold()}"


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class DiscoveryScanResult:
    """
    Full result returned by `DiscoveryService.scan`.

    `summary` is the count rollup; `entries` is every ledger entry
    produced during this run, in the order they were appended.
    `scan_run_id` is the durable run row id (when a ScanRunStore is
    wired); other layers (snapshots, drift, /v1/system/state) bind
    against it. `ledger_seq_start`/`ledger_seq_end` are the inclusive
    range of ledger sequences this run produced — useful for snapshot
    binding and reconstructive audits.
    `registry_state_hash` is a content hash over the registry at the
    moment the scan completed; snapshots tied to this run can prove
    they were taken against this exact registry state.
    """

    summary: DiscoveryScanRun
    entries: tuple[DiscoveryLedgerEntry, ...]
    scan_run_id: UUID | None = None
    ledger_seq_start: int | None = None
    ledger_seq_end: int | None = None
    registry_state_hash: str | None = None
    policy_version: str | None = None


class ScanInProgress(RuntimeError):
    """
    Raised when a scan is requested for a tenant that already has a
    running scan AND the caller did not supply a matching idempotency
    key. The HTTP layer turns this into a 409 Conflict.
    """

    def __init__(self, *, tenant_id: str, holder_run_id: UUID) -> None:
        self.tenant_id = tenant_id
        self.holder_run_id = holder_run_id
        super().__init__(
            f"scan in progress for tenant={tenant_id} (run_id={holder_run_id})"
        )


class DiscoveryService:
    """
    Orchestrator for the discovery loop.

    Construction wires:
      - registry: where agents live
      - ledger: where discovery outcomes are appended
      - engine: the pure decision component
      - index: reconciliation key → agent_id map (built from registry)
      - connectors: the list of platform adapters to invoke

      Optional (added in this revision; preserve V15 behavior when omitted):
      - scan_run_store: durable scan-run + per-tenant lock + idempotency
      - health_store:   per-(tenant, connector) health tracking

    Discovery is operator-initiated: there is no background thread.
    The scan runs synchronously and returns a complete summary. The
    API layer exposes `POST /v1/discovery/scan` to trigger one.
    """

    __slots__ = (
        "_registry",
        "_ledger",
        "_engine",
        "_index",
        "_connectors",
        "_scan_run_store",
        "_health_store",
    )

    def __init__(
        self,
        *,
        registry: InMemoryAgentRegistry,
        ledger: InMemoryDiscoveryLedger,
        engine: ReconciliationEngine | None = None,
        index: ReconciliationIndex | None = None,
        connectors: Iterable[DiscoveryConnector] | None = None,
        scan_run_store: ScanRunStore | None = None,
        health_store: ConnectorHealthStore | None = None,
    ) -> None:
        self._registry = registry
        self._ledger = ledger
        self._engine = engine or ReconciliationEngine()
        self._index = index or ReconciliationIndex(registry=registry)
        self._connectors: list[DiscoveryConnector] = list(connectors or [])
        self._scan_run_store = scan_run_store
        self._health_store = health_store

    # ------------------------------------------------------------------ ops

    def register_connector(self, connector: DiscoveryConnector) -> None:
        self._connectors.append(connector)

    def list_connectors(self) -> tuple[DiscoveryConnector, ...]:
        return tuple(self._connectors)

    def index(self) -> ReconciliationIndex:
        return self._index

    # ------------------------------------------------------------------ scan

    def scan(
        self,
        *,
        tenant_id: str,
        timeout_seconds: float = 30.0,
        max_candidates_per_connector: int = 5_000,
        name_filter: str | None = None,
        trigger: str = "manual",
        idempotency_key: str | None = None,
        policy_version: str | None = None,
    ) -> DiscoveryScanResult:
        """
        Run a full discovery scan against every wired connector.

        Errors raised by a single connector are caught and recorded in
        the run summary; the scan continues with the remaining
        connectors. This matches the operational reality that one
        platform's auth being broken should not halt all discovery.

        When a ``ScanRunStore`` is wired, this method:
          * Acquires the per-tenant scan lock for the duration.
          * Honors idempotency: the same ``(tenant_id, idempotency_key)``
            pair returns a previously-completed run instead of starting
            a new one.
          * Records the durable run row including ledger seq range,
            registry-state hash, and policy_version.

        When no ScanRunStore is wired, behavior is identical to V15
        (synchronous scan, no lock, no durable run record).

        Raises ``ScanInProgress`` when the lock is held and the caller
        did not pass a matching idempotency_key.
        """

        # ---- Idempotency / lock acquisition ---------------------------------
        scan_run = None
        is_new_run = True
        if self._scan_run_store is not None:
            try:
                scan_run, is_new_run = self._scan_run_store.acquire(
                    tenant_id=tenant_id,
                    trigger=trigger,
                    idempotency_key=idempotency_key,
                )
            except ScanLockHeld as exc:
                raise ScanInProgress(
                    tenant_id=exc.tenant_id,
                    holder_run_id=exc.holder_run_id,
                ) from exc

            # Idempotent replay: a prior completed run for the same key.
            # Reconstruct a minimal DiscoveryScanResult from the stored
            # summary so downstream logic gets the same shape.
            if not is_new_run and scan_run.status.value != "running":
                return self._replay_completed_run(scan_run)

        # ---- Capture starting ledger sequence -------------------------------
        ledger_seq_start = len(self._ledger)

        started_at = datetime.now(UTC)
        sources_scanned: list[DiscoverySource] = []
        errors: list[str] = []
        outcomes_summary: dict[ReconciliationAction, int] = {}
        new_entries: list[DiscoveryLedgerEntry] = []
        candidates_seen = 0

        context = ConnectorContext(
            tenant_id=tenant_id,
            timeout_seconds=timeout_seconds,
            max_candidates=max_candidates_per_connector,
            name_filter=name_filter,
        )

        try:
            for connector in self._connectors:
                sources_scanned.append(connector.source)
                connector_candidates = 0
                connector_error: str | None = None
                try:
                    for candidate in connector.scan(context):
                        candidates_seen += 1
                        connector_candidates += 1
                        entry = self._handle_candidate(candidate)
                        new_entries.append(entry)
                        outcomes_summary[entry.outcome.action] = (
                            outcomes_summary.get(entry.outcome.action, 0) + 1
                        )
                except ConnectorError as exc:
                    connector_error = (
                        f"{connector.name} ({connector.source}): "
                        f"{type(exc).__name__}: {exc}"
                    )
                    errors.append(connector_error)
                except Exception as exc:  # defensive: must not break the run
                    connector_error = (
                        f"{connector.name} ({connector.source}): "
                        f"unexpected {type(exc).__name__}: {exc}"
                    )
                    errors.append(connector_error)

                # Record per-connector health if a store is wired.
                self._record_connector_health(
                    tenant_id=tenant_id,
                    connector=connector,
                    candidate_count=connector_candidates,
                    error=connector_error,
                    scan_run_id=scan_run.run_id if scan_run else None,
                )

                # Heartbeat the run after each connector so a stuck
                # connector cannot make us look dead to the lock store.
                if scan_run is not None and self._scan_run_store is not None:
                    self._scan_run_store.heartbeat(scan_run.run_id)

            completed_at = datetime.now(UTC)
            ledger_seq_end = len(self._ledger) - 1 if len(self._ledger) > ledger_seq_start else None

            summary_kwargs = {
                "started_at": started_at,
                "completed_at": completed_at,
                "sources_scanned": tuple(sources_scanned),
                "candidates_seen": candidates_seen,
                "registered_count": outcomes_summary.get(ReconciliationAction.REGISTERED, 0),
                "updated_drift_count": outcomes_summary.get(
                    ReconciliationAction.UPDATED_DRIFT, 0
                ),
                "quarantined_count": outcomes_summary.get(
                    ReconciliationAction.QUARANTINED_FOR_DRIFT, 0
                ),
                "no_op_count": (
                    outcomes_summary.get(ReconciliationAction.NO_OP_KNOWN_UNCHANGED, 0)
                    + outcomes_summary.get(ReconciliationAction.NO_OP_BELOW_THRESHOLD, 0)
                ),
                "held_count": (
                    outcomes_summary.get(ReconciliationAction.HELD_AMBIGUOUS, 0)
                    + outcomes_summary.get(ReconciliationAction.HELD_DUPLICATE, 0)
                ),
                "skipped_count": outcomes_summary.get(
                    ReconciliationAction.SKIPPED_REVOKED, 0
                ),
                "errors": tuple(errors),
            }
            # Bind the durable scan_run_id into the summary so callers
            # downstream see one canonical run id.
            if scan_run is not None:
                summary_kwargs["run_id"] = scan_run.run_id
            summary = DiscoveryScanRun(**summary_kwargs)

            registry_state_hash = self._compute_registry_state_hash()

            # Close the durable run row.
            if scan_run is not None and self._scan_run_store is not None:
                self._scan_run_store.complete(
                    scan_run.run_id,
                    ledger_seq_start=ledger_seq_start if new_entries else None,
                    ledger_seq_end=ledger_seq_end,
                    registry_state_hash=registry_state_hash,
                    policy_version=policy_version,
                    summary={
                        "candidates_seen": summary.candidates_seen,
                        "registered_count": summary.registered_count,
                        "updated_drift_count": summary.updated_drift_count,
                        "quarantined_count": summary.quarantined_count,
                        "no_op_count": summary.no_op_count,
                        "held_count": summary.held_count,
                        "skipped_count": summary.skipped_count,
                        "errors": list(summary.errors),
                        "duration_seconds": summary.duration_seconds,
                        "sources_scanned": [str(s) for s in summary.sources_scanned],
                    },
                )

            return DiscoveryScanResult(
                summary=summary,
                entries=tuple(new_entries),
                scan_run_id=scan_run.run_id if scan_run else None,
                ledger_seq_start=ledger_seq_start if new_entries else None,
                ledger_seq_end=ledger_seq_end,
                registry_state_hash=registry_state_hash,
                policy_version=policy_version,
            )

        except Exception as exc:
            # Hard failure that escaped the per-connector catch. Mark
            # the run failed so the lock releases.
            if scan_run is not None and self._scan_run_store is not None:
                self._scan_run_store.fail(
                    scan_run.run_id,
                    error=f"{type(exc).__name__}: {exc}",
                )
            raise

    # ------------------------------------------------------------------ helpers

    def _record_connector_health(
        self,
        *,
        tenant_id: str,
        connector: DiscoveryConnector,
        candidate_count: int,
        error: str | None,
        scan_run_id: UUID | None,
    ) -> None:
        if self._health_store is None:
            return
        run_id_str = str(scan_run_id) if scan_run_id else None
        try:
            if error is None:
                self._health_store.record_success(
                    tenant_id=tenant_id,
                    connector_name=connector.name,
                    discovery_source=str(connector.source),
                    candidate_count=candidate_count,
                    scan_run_id=run_id_str,
                )
            else:
                self._health_store.record_failure(
                    tenant_id=tenant_id,
                    connector_name=connector.name,
                    discovery_source=str(connector.source),
                    error=error,
                    scan_run_id=run_id_str,
                )
        except Exception as exc:  # noqa: BLE001
            _logger.warning(
                "DiscoveryService: failed to record connector health for %s: %s",
                connector.name, exc,
            )

    def _compute_registry_state_hash(self) -> str:
        """
        Stable content hash over the registry at scan-completion time.

        We hash a compact projection (agent_id + revision + lifecycle
        + capability_surface fingerprint) rather than the full
        AgentIdentity payload so the hash is cheap to compute and
        readable in diffs. Snapshots bound to this scan_run_id can
        reproduce the hash from the registry's history and prove they
        captured the exact same registry state.
        """
        projections = []
        for agent in sorted(
            self._registry.list_all(), key=lambda a: str(a.agent_id),
        ):
            projections.append({
                "agent_id": str(agent.agent_id),
                "revision": agent.revision,
                "tenant_id": agent.tenant_id,
                "lifecycle_status": str(agent.lifecycle_status),
                "trust_tier": str(agent.trust_tier),
            })
        payload = json.dumps(
            projections,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def _replay_completed_run(self, scan_run) -> DiscoveryScanResult:
        """
        Build a DiscoveryScanResult from a previously-completed run.

        Idempotency means the second POST with the same key gets the
        same answer rather than triggering a new scan. We hydrate the
        ledger entries from the recorded sequence range — this gives
        the caller the same data they would have seen on the original
        run.
        """
        s = scan_run.summary or {}
        all_entries = self._ledger.list_all()
        entries: tuple[DiscoveryLedgerEntry, ...] = tuple()
        if (
            scan_run.ledger_seq_start is not None
            and scan_run.ledger_seq_end is not None
        ):
            start = max(0, int(scan_run.ledger_seq_start))
            end = min(len(all_entries) - 1, int(scan_run.ledger_seq_end))
            if start <= end:
                entries = tuple(all_entries[start : end + 1])

        # Reconstruct the DiscoveryScanRun summary from the stored dict.
        sources_scanned = []
        for src_str in s.get("sources_scanned", []) or []:
            try:
                sources_scanned.append(DiscoverySource(src_str))
            except ValueError:
                continue

        summary = DiscoveryScanRun(
            run_id=scan_run.run_id,
            started_at=scan_run.started_at,
            completed_at=scan_run.completed_at or scan_run.started_at,
            sources_scanned=tuple(sources_scanned),
            candidates_seen=int(s.get("candidates_seen", 0)),
            registered_count=int(s.get("registered_count", 0)),
            updated_drift_count=int(s.get("updated_drift_count", 0)),
            quarantined_count=int(s.get("quarantined_count", 0)),
            no_op_count=int(s.get("no_op_count", 0)),
            held_count=int(s.get("held_count", 0)),
            skipped_count=int(s.get("skipped_count", 0)),
            errors=tuple(s.get("errors", []) or []),
        )
        return DiscoveryScanResult(
            summary=summary,
            entries=entries,
            scan_run_id=scan_run.run_id,
            ledger_seq_start=scan_run.ledger_seq_start,
            ledger_seq_end=scan_run.ledger_seq_end,
            registry_state_hash=scan_run.registry_state_hash,
            policy_version=scan_run.policy_version,
        )

    # ------------------------------------------------------------------ inner

    def _handle_candidate(self, candidate: CandidateAgent) -> DiscoveryLedgerEntry:
        """
        Run reconciliation for one candidate and apply the resulting
        side effects atomically (registry first, then ledger). The
        ledger append happens last so an operator querying the ledger
        is guaranteed every entry corresponds to a registry change
        already applied.
        """

        existing_agent_id = self._index.get_agent_id(candidate.reconciliation_key)
        existing = (
            self._registry.get(existing_agent_id) if existing_agent_id else None
        )

        decision = self._engine.decide(candidate=candidate, existing=existing)
        self._apply(decision)

        return self._ledger.append(
            candidate=candidate,
            outcome=decision.outcome,
        )

    def _apply(self, decision: ReconciliationDecision) -> None:
        """Apply a decision's side effects to the registry."""

        if decision.new_agent is not None:
            saved = self._registry.save(decision.new_agent)
            self._index.link(
                key=decision.outcome.reconciliation_key,
                agent_id=saved.agent_id,
            )
            return

        if (
            decision.update_capability_surface_for is not None
            and decision.new_capability_surface is not None
        ):
            existing = decision.update_capability_surface_for
            updated = existing.model_copy(
                update={"capability_surface": decision.new_capability_surface}
            )
            self._registry.save(updated)
            return

        if decision.quarantine_agent_id is not None:
            self._registry.set_lifecycle(
                decision.quarantine_agent_id.agent_id,
                AgentLifecycleStatus.QUARANTINED,
            )
            return

        # NO_OP / SKIPPED / HELD branches: nothing to apply to the registry.
        return

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
from tex.stores.discovery_ledger import InMemoryDiscoveryLedger


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
    Tests use `entries`; UI uses `summary`.
    """

    summary: DiscoveryScanRun
    entries: tuple[DiscoveryLedgerEntry, ...]


class DiscoveryService:
    """
    Orchestrator for the discovery loop.

    Construction wires:
      - registry: where agents live
      - ledger: where discovery outcomes are appended
      - engine: the pure decision component
      - index: reconciliation key → agent_id map (built from registry)
      - connectors: the list of platform adapters to invoke

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
    )

    def __init__(
        self,
        *,
        registry: InMemoryAgentRegistry,
        ledger: InMemoryDiscoveryLedger,
        engine: ReconciliationEngine | None = None,
        index: ReconciliationIndex | None = None,
        connectors: Iterable[DiscoveryConnector] | None = None,
    ) -> None:
        self._registry = registry
        self._ledger = ledger
        self._engine = engine or ReconciliationEngine()
        self._index = index or ReconciliationIndex(registry=registry)
        self._connectors: list[DiscoveryConnector] = list(connectors or [])

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
    ) -> DiscoveryScanResult:
        """
        Run a full discovery scan against every wired connector.

        Errors raised by a single connector are caught and recorded in
        the run summary; the scan continues with the remaining
        connectors. This matches the operational reality that one
        platform's auth being broken should not halt all discovery.
        """

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

        for connector in self._connectors:
            sources_scanned.append(connector.source)
            try:
                for candidate in connector.scan(context):
                    candidates_seen += 1
                    entry = self._handle_candidate(candidate)
                    new_entries.append(entry)
                    outcomes_summary[entry.outcome.action] = (
                        outcomes_summary.get(entry.outcome.action, 0) + 1
                    )
            except ConnectorError as exc:
                errors.append(
                    f"{connector.name} ({connector.source}): {type(exc).__name__}: "
                    f"{exc}"
                )
            except Exception as exc:  # defensive: must not break the run
                errors.append(
                    f"{connector.name} ({connector.source}): "
                    f"unexpected {type(exc).__name__}: {exc}"
                )

        completed_at = datetime.now(UTC)
        summary = DiscoveryScanRun(
            started_at=started_at,
            completed_at=completed_at,
            sources_scanned=tuple(sources_scanned),
            candidates_seen=candidates_seen,
            registered_count=outcomes_summary.get(ReconciliationAction.REGISTERED, 0),
            updated_drift_count=outcomes_summary.get(
                ReconciliationAction.UPDATED_DRIFT, 0
            ),
            quarantined_count=outcomes_summary.get(
                ReconciliationAction.QUARANTINED_FOR_DRIFT, 0
            ),
            no_op_count=(
                outcomes_summary.get(ReconciliationAction.NO_OP_KNOWN_UNCHANGED, 0)
                + outcomes_summary.get(ReconciliationAction.NO_OP_BELOW_THRESHOLD, 0)
            ),
            held_count=(
                outcomes_summary.get(ReconciliationAction.HELD_AMBIGUOUS, 0)
                + outcomes_summary.get(ReconciliationAction.HELD_DUPLICATE, 0)
            ),
            skipped_count=outcomes_summary.get(
                ReconciliationAction.SKIPPED_REVOKED, 0
            ),
            errors=tuple(errors),
        )

        return DiscoveryScanResult(summary=summary, entries=tuple(new_entries))

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

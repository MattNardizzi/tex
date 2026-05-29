from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import ValidationError

from tex.agent.suite import AgentEvaluationSuite
from tex.api.agent_routes import build_agent_router
from tex.api.discovery_routes import build_discovery_router
from tex.api.tenant_routes import build_tenant_router
from tex.api.guardrail import router as guardrail_router  # GUARDRAIL: canonical webhook
from tex.api.guardrail_adapters import router as guardrail_adapters_router  # GUARDRAIL: gateway adapters
from tex.api.guardrail_streaming import router as guardrail_streaming_router  # GUARDRAIL: SSE + async
from tex.api.mcp_server import router as mcp_router  # MCP: server interface
from tex.api.provenance_routes import build_provenance_router  # PROVENANCE: identity-by-behaviour
from tex.api.discovery_surface_routes import build_discovery_surface_router  # PROVENANCE: count-once voice
from tex.api.tee_routes import router as tee_router  # Thread 12: composite TEE attestation
from tex.api.vet_routes import router as vet_router  # Thread 13: VET Web Proofs + AID
from tex.api.zkprov_routes import router as zkprov_router  # Thread 14: ZKPROV training-data provenance
from tex.api.incident_routes import build_incident_router  # Thread 3: causal attribution
from tex.api.vigil_routes import build_vigil_router  # VIGIL: surprise-selected voice (/v1/vigil)
from tex.api.routes import build_api_router
from tex.commands.activate_policy import ActivatePolicyCommand
from tex.commands.calibrate_policy import CalibratePolicyCommand
from tex.commands.evaluate_action import EvaluateActionCommand
from tex.commands.export_bundle import ExportBundleCommand
from tex.commands.report_outcome import ReportOutcomeCommand
from tex.config import get_settings
from tex.contracts import BehavioralContract, ContractEnforcer
from tex.engine.contract_bridge import SessionEnforcerRegistry
from tex.provenance import build_default_provenance_engine  # PROVENANCE
from tex.provenance.delegation import SealedDelegationGraph  # PROVENANCE: delegation edges
from tex.provenance.feed import (  # PROVENANCE: continuous feed
    ContinuousProvenanceFeed,
    HeldDecisionSink,
)
from tex.discovery.connectors import (
    AwsBedrockConnector,
    CloudAuditConnector,
    GitHubConnector,
    KernelEbpfConnector,
    MCPServerConnector,
    MicrosoftGraphConnector,
    NetworkEgressConnector,
    OpenAIAssistantsLiveConnector,
    OpenAIConnector,
    SalesforceConnector,
    SlackConnector,
    SlackLiveConnector,
)
from tex.discovery.dormancy import DormancyController  # discovery: dormant-agent doctrine
from tex.discovery.ignition import IgnitionRegistry  # discovery: count-once
from tex.discovery.service import DiscoveryService
from tex.domain.evaluation import EvaluationRequest
from tex.domain.policy import PolicySnapshot
from tex.domain.retrieval import RetrievedEntity, RetrievedPolicyClause, RetrievedPrecedent
from tex.engine.pdp import PolicyDecisionPoint
from tex.evidence.exporter import EvidenceExporter
from tex.evidence.recorder import EvidenceRecorder
# Thread 5: C2PA emission + manifest mirror + digital-twin wiring.
from tex.evidence.c2pa_emitter import C2paEmitter
from tex.evidence.manifest_mirror import PostgresManifestMirror
from tex.ecosystem.state import EcosystemState
# Thread 7: EcosystemEngine integration. Collaborators are imported here
# at module load so the construction graph is explicit. None of these
# imports trigger the historical ``tex.events.crypto_provenance`` cycle
# because Thread 4 already broke that cycle in ``tex.ecosystem.engine``
# (the ``CryptoProvenance`` reference there is deferred to TYPE_CHECKING).
from tex.ecosystem.bridge import EcosystemBridge
from tex.ecosystem.engine import EcosystemEngine
from tex.events.crypto_provenance import CryptoProvenance
from tex.events._ecdsa_provider import default_signature_provider
from tex.events.ledger import InMemoryLedger
from tex.graph.projection import StateProjection
from tex.graph.temporal_kg import InMemoryTemporalKG
from tex.ontology import EntityTypeRegistry, EventTypeRegistry, OntologyValidator
from tex.systemic.digital_twin import EcosystemDigitalTwin
from tex.learning.calibrator import ThresholdCalibrator, build_default_calibrator
from tex.learning.calibration_safety import CalibrationSafetyGuard
from tex.learning.drift import PolicyDriftMonitor
from tex.learning.drift_classifier import DriftClassifier
from tex.learning.feedback_loop import FeedbackLoopOrchestrator
from tex.learning.observability import (
    CompositeLearningObserver,
    LearningAlertEngine,
    LoggingLearningObserver,
    MetricsLearningObserver,
)
from tex.learning.outcome_validator import OutcomeValidator
from tex.learning.poisoning_detector import PoisoningDetector
from tex.learning.replay import ReplayValidator
from tex.learning.reporter_reputation import ReporterReputationStore
from tex.policies.defaults import build_default_policy, build_strict_policy
from tex.retrieval.orchestrator import RetrievalOrchestrator
from tex.stores.action_ledger import InMemoryActionLedger
from tex.stores.agent_registry import InMemoryAgentRegistry
from tex.stores.calibration_proposal_store import CalibrationProposalStore
from tex.stores.decision_store import InMemoryDecisionStore
from tex.stores.discovery_ledger import InMemoryDiscoveryLedger
from tex.stores.entity_store import InMemoryEntityStore
from tex.stores.outcome_store import InMemoryOutcomeStore
from tex.stores.policy_store import InMemoryPolicyStore
from tex.stores.precedent_store import InMemoryPrecedentStore
from tex.stores.tenant_content_baseline import InMemoryTenantContentBaseline


DEFAULT_EVIDENCE_PATH = Path("var/tex/evidence/evidence.jsonl")
APP_TITLE = "Tex"
APP_VERSION = "0.1.0"

_logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class TexRuntime:
    """
    Fully wired in-process runtime for Tex.

    This is Tex's composition root. It keeps dependency wiring explicit and
    local instead of spreading startup behavior across modules and globals.
    """

    pdp: PolicyDecisionPoint
    calibrator: ThresholdCalibrator

    # Stores below may be backed by either in-memory or Postgres-backed
    # implementations depending on DATABASE_URL. The Postgres variants
    # are duck-typed against the InMemory ones; type hints below are
    # InMemory-typed for documentation only — the runtime treats both
    # identically. mypy is not run on this file with strict store
    # checking precisely because of this dual implementation.
    policy_store: InMemoryPolicyStore
    decision_store: InMemoryDecisionStore
    outcome_store: InMemoryOutcomeStore
    precedent_store: InMemoryPrecedentStore
    entity_store: InMemoryEntityStore

    agent_registry: InMemoryAgentRegistry
    action_ledger: InMemoryActionLedger
    tenant_baseline: InMemoryTenantContentBaseline
    agent_suite: AgentEvaluationSuite

    discovery_ledger: InMemoryDiscoveryLedger
    discovery_service: DiscoveryService

    evidence_recorder: EvidenceRecorder
    evidence_exporter: EvidenceExporter

    evaluate_action_command: EvaluateActionCommand
    report_outcome_command: ReportOutcomeCommand
    activate_policy_command: ActivatePolicyCommand
    calibrate_policy_command: CalibratePolicyCommand
    export_bundle_command: ExportBundleCommand

    # V15: durable persistence + drift detection + alerts. Optional so
    # the runtime composes cleanly with or without DATABASE_URL.
    governance_snapshot_store: Any = None
    drift_event_store: Any = None
    alert_engine: Any = None
    scan_scheduler: Any = None

    # V16: discovery hardening — scan-run lifecycle, per-tenant locking,
    # connector health, soft-disappearance state, in-process metrics.
    scan_run_store: Any = None
    connector_health_store: Any = None
    presence_tracker: Any = None
    discovery_metrics: Any = None

    # V17: Learning/Drift layer — production-grade calibration governance
    # with trust tiers, reporter reputation, poisoning detection, replay
    # validation, safety bounds, drift classification, and approval workflow.
    learning_orchestrator: Any = None
    proposal_store: Any = None
    reporter_reputation: Any = None
    outcome_validator: Any = None
    calibration_safety: Any = None
    replay_validator: Any = None
    drift_classifier: Any = None
    poisoning_detector: Any = None
    learning_metrics: Any = None
    learning_alert_engine: Any = None

    # V18: Unified memory orchestrator. Single source of truth for all
    # durable artefacts (decisions, inputs, policy snapshots, permits,
    # verifications, evidence chain mirror). The eval command writes
    # through this instead of poking individual stores.
    #
    # ``runtime.memory.decisions``  — same instance as ``runtime.decision_store``
    # ``runtime.memory.policies``   — same instance as ``runtime.policy_store``
    # ``runtime.memory.recorder``   — same instance as ``runtime.evidence_recorder``
    #
    # so existing callers keep working AND new callers (replay engine,
    # health endpoints, audit exporters) can use the unified API.
    memory: Any = None

    # Thread 5: C2PA emission + manifest mirror.
    # ----------------------------------------------------------------------
    # ``manifest_mirror`` is a ``PostgresManifestMirror`` that durably
    # stores every C2PA 2.4 manifest emitted on a PERMIT verdict that
    # carried an outbound artifact. The mirror no-ops cleanly when
    # ``DATABASE_URL`` is unset (the JSONL chain still anchors the
    # manifest hash, so the manifest is byte-identical-derivable
    # offline at re-sign time).
    #
    # The ``c2pa_routes`` GET handler at /v1/evidence/{record_id}/c2pa
    # resolves this from ``runtime.manifest_mirror``; a missing or
    # disabled mirror is reported as 503 to the caller per the
    # canonical c2pa_routes contract.
    manifest_mirror: Any = None

    # Thread 5: digital-twin wiring for /v1/ecosystem/twin/simulate.
    # ----------------------------------------------------------------------
    # ``ecosystem_twin`` is a long-lived ``EcosystemDigitalTwin`` instance
    # whose Koopman operator + conformal calibration buffer accumulate
    # across all twin invocations (each call ``fork_at(...)`` produces
    # a fully isolated child for the actual simulation, so the parent
    # is mutated only by the calibration feedback path).
    #
    # ``ecosystem_state_factory`` is a zero-arg callable that materializes
    # the *current* ``EcosystemState`` projection. The twin endpoint
    # invokes this on every request rather than holding a stale reference;
    # in pure in-memory mode the projection is computed live from
    # ``agent_registry`` + observed drift state, in Postgres mode the
    # projection still reads from the in-process stores (which the
    # discovery + drift loops keep current).
    ecosystem_twin: Any = None
    ecosystem_state_factory: Any = None

    # Thread 7: EcosystemEngine integration.
    # ----------------------------------------------------------------------
    # ``ecosystem_engine`` is the long-lived ``EcosystemEngine`` instance.
    # Its own ``_enabled`` attribute reads ``TEX_ECOSYSTEM`` at construction
    # time; if the flag is off, ``engine.evaluate()`` short-circuits to an
    # inert PERMIT in O(1) with no graph or ledger mutation. The engine is
    # therefore safe to construct unconditionally and pass to every
    # ``EvaluateActionCommand``.
    #
    # ``ecosystem_bridge`` wraps the engine and exposes
    # ``emit_verdict(routing_result=..., actor_entity_id=..., ...)`` so the
    # evaluate command can forward a six-layer ``RoutingResult`` without
    # knowing anything about ``ProposedEvent`` schema. When
    # ``TEX_ECOSYSTEM=0`` (the default), the engine's short-circuit
    # guarantees bit-for-bit identical behavior with the pre-Thread-7
    # response shape.
    ecosystem_engine: Any = None
    ecosystem_bridge: Any = None

    # PROVENANCE: behavioural identity engine + sealed transparency log.
    # ----------------------------------------------------------------------
    # ``provenance_engine`` proves who an agent is by what it does and seals
    # that identity into a signed, hash-chained log. It consumes the gate's
    # decision stream (the agent action ledger) and is the one discovery
    # primitive that survives credential rotation, rename, and the absence
    # of any self-declared identity. Built once here so the sealed log is a
    # single durable instance across the app lifecycle.
    provenance_engine: Any = None

    # PROVENANCE: continuous feed + held-decision sink + sealed delegation
    # graph, and the discovery dormancy controller + count-once ignition.
    # ----------------------------------------------------------------------
    # ``provenance_feed`` fires the engine off the gate's decision stream so
    # identity seals on its own, silently; ``held_decision_sink`` is the one
    # place a resolution that needs a human surfaces (the only thing that
    # earns the voice). ``delegation_graph`` seals who-delegates-to-whom so
    # the ``dormancy_controller`` can prove an idle agent is safe to sleep.
    # ``ignition_registry`` makes "Run discovery" speak exactly once.
    provenance_feed: Any = None
    held_decision_sink: Any = None
    delegation_graph: Any = None
    dormancy_controller: Any = None
    ignition_registry: Any = None


class InMemoryPolicyClauseStoreAdapter:
    """
    Thin retrieval adapter that projects policy snapshot data into grounding clauses.

    Tex does not need a separate policy-clause database yet. For local runtime,
    the active policy snapshot already contains enough structured material to
    create usable retrieval grounding:
    - blocked terms
    - sensitive entities
    - enabled recognizers
    - operator metadata

    This is deliberately lightweight and deterministic.
    """

    __slots__ = ()

    def retrieve_policy_clauses(
        self,
        *,
        policy: PolicySnapshot,
        request: EvaluationRequest,
        top_k: int,
    ) -> tuple[RetrievedPolicyClause, ...]:
        if top_k <= 0:
            return tuple()

        candidates: list[RetrievedPolicyClause] = []
        request_text = f"{request.action_type} {request.channel} {request.environment} {request.content}".casefold()

        rank = 1
        for term in policy.blocked_terms:
            relevance = 0.98 if term.casefold() in request_text else 0.72
            candidates.append(
                RetrievedPolicyClause(
                    clause_id=f"{policy.version}:blocked_term:{rank}",
                    policy_id=policy.policy_id,
                    policy_version=policy.version,
                    title="Blocked term restriction",
                    text=term,
                    channel=request.channel,
                    action_type=request.action_type,
                    relevance_score=relevance,
                    rank=rank,
                    metadata={
                        "source": "policy_snapshot.blocked_terms",
                        "blocked_term": term,
                    },
                )
            )
            rank += 1

        for entity in policy.sensitive_entities:
            relevance = 0.95 if entity.casefold() in request_text else 0.68
            candidates.append(
                RetrievedPolicyClause(
                    clause_id=f"{policy.version}:sensitive_entity:{rank}",
                    policy_id=policy.policy_id,
                    policy_version=policy.version,
                    title="Sensitive entity handling",
                    text=entity,
                    channel=request.channel,
                    action_type=request.action_type,
                    relevance_score=relevance,
                    rank=rank,
                    metadata={
                        "source": "policy_snapshot.sensitive_entities",
                        "sensitive_entity": entity,
                    },
                )
            )
            rank += 1

        for recognizer_name in policy.enabled_recognizers:
            relevance = 0.60
            if recognizer_name.casefold().replace("_", " ") in request_text:
                relevance = 0.82
            candidates.append(
                RetrievedPolicyClause(
                    clause_id=f"{policy.version}:recognizer:{rank}",
                    policy_id=policy.policy_id,
                    policy_version=policy.version,
                    title="Enabled recognizer policy",
                    text=recognizer_name.replace("_", " "),
                    channel=request.channel,
                    action_type=request.action_type,
                    relevance_score=relevance,
                    rank=rank,
                    metadata={
                        "source": "policy_snapshot.enabled_recognizers",
                        "recognizer": recognizer_name,
                    },
                )
            )
            rank += 1

        metadata_description = policy.metadata.get("description")
        if isinstance(metadata_description, str) and metadata_description.strip():
            candidates.append(
                RetrievedPolicyClause(
                    clause_id=f"{policy.version}:metadata:{rank}",
                    policy_id=policy.policy_id,
                    policy_version=policy.version,
                    title="Policy description",
                    text=metadata_description.strip(),
                    channel=request.channel,
                    action_type=request.action_type,
                    relevance_score=0.55,
                    rank=rank,
                    metadata={"source": "policy_snapshot.metadata.description"},
                )
            )

        ranked = sorted(
            candidates,
            key=lambda item: (-item.relevance_score, item.rank),
        )[:top_k]

        return tuple(
            item.model_copy(update={"rank": index})
            for index, item in enumerate(ranked, start=1)
        )


class InMemoryPrecedentStoreAdapter:
    """
    Thin adapter from the concrete in-memory precedent store to the retrieval protocol.
    """

    __slots__ = ("_store",)

    def __init__(self, store: InMemoryPrecedentStore) -> None:
        self._store = store

    def retrieve_precedents(
        self,
        *,
        request: EvaluationRequest,
        limit: int,
    ) -> tuple[RetrievedPrecedent, ...]:
        if limit <= 0:
            return tuple()

        return self._store.find_similar(
            action_type=request.action_type,
            channel=request.channel,
            environment=request.environment,
            recipient=request.recipient,
            limit=limit,
        )


class InMemoryEntityStoreAdapter:
    """
    Thin adapter that exposes the concrete in-memory entity store as the retrieval protocol.
    """

    __slots__ = ("_store",)

    def __init__(self, store: InMemoryEntityStore) -> None:
        self._store = store

    def retrieve_entities(
        self,
        *,
        request: EvaluationRequest,
        limit: int,
    ) -> tuple[RetrievedEntity, ...]:
        if limit <= 0:
            return tuple()

        return self._store.find_relevant(request=request, limit=limit)


def _build_default_contract_suite() -> tuple[BehavioralContract, ...]:
    """
    Build the default set of ``BehavioralContract``s for the Tex runtime.

    Returns the contracts as a tuple so the caller can pick the
    enforcement mode (session-scoped via ``SessionEnforcerRegistry`` or
    stateless via a single ``ContractEnforcer``). The contracts
    themselves are immutable, so the same tuple is safe to share across
    enforcer instances.

    One seed contract, with ``agent_id="*"`` so it fires on every request
    regardless of whether agent context is supplied. Tenants are expected
    to extend this suite via their own configuration; the seed exists to
    prove the wiring is live end-to-end and to give the integration test
    something hard-FORBID to assert against.

    Contract — ``content-no-api-keys`` (HARD GOVERNANCE)
        ``G(field:content~not_contains:sk-proj-)``
        Globally, content must not contain the literal "sk-proj-" — the
        canonical OpenAI project-key prefix. A single match short-circuits
        to FORBID.

    Why one seed contract instead of two
    ------------------------------------
    A second "recipient required for send_email" contract was prototyped
    as a soft-governance demo but was removed because the existing Tex
    SDK contract treats a recipient-less send_email as PERMIT in some
    workflows. The ``TestBehavioralContracts`` integration test class
    demonstrates the soft-violation → ABSTAIN path via a contract
    injected at test time.
    """
    no_api_keys = BehavioralContract.make(
        contract_id="content-no-api-keys",
        agent_id="*",
        description=(
            "Hard governance: content must never contain the canonical "
            "OpenAI project-key prefix 'sk-proj-'."
        ),
        hard_governance_ltl=(
            "G(field:content~not_contains:sk-proj-)",
        ),
        covered_event_kinds=("*",),
        severity_on_violation="block",
    )
    return (no_api_keys,)


# Kept for backwards compat with any caller that constructed an enforcer
# directly. New code should use _build_default_contract_suite() +
# SessionEnforcerRegistry instead.
def _build_default_contract_enforcer() -> ContractEnforcer:
    """Build the default stateless ``ContractEnforcer`` (legacy mode)."""
    return ContractEnforcer(contracts=_build_default_contract_suite())


def build_runtime(
    *,
    evidence_path: str | Path = DEFAULT_EVIDENCE_PATH,
) -> TexRuntime:
    """
    Build the Tex runtime composition with sensible defaults.

    This guarantees that:
    - retrieval is actually wired into the live PDP
    - default policies are seeded exactly once
    - default sensitive entities are seeded into the entity store
    - evidence path is normalized and directory-safe
    """
    normalized_evidence_path = Path(evidence_path)

    # ── Memory-system wiring (locked spec § "single source of truth") ──
    #
    # MemorySystem is the canonical entry point for every durable
    # artefact: decisions, full inputs, policy snapshots, permits,
    # verifications, and the Postgres mirror of the evidence chain.
    # Building it first means the rest of the runtime can route every
    # write through one orchestrator instead of poking individual
    # stores.
    #
    # When DATABASE_URL is set, MemorySystem's stores write through to
    # Postgres atomically. When unset, they fall back to in-memory mode
    # with a loud warning. Either way, the calling code is identical.
    database_configured = bool(os.environ.get("DATABASE_URL", "").strip())

    from tex.memory import MemorySystem

    memory = MemorySystem(evidence_path=normalized_evidence_path)

    # Decision and policy stores ARE the memory-system's stores. Two
    # parallel implementations (e.g. PostgresDecisionStore + DurableDecisionStore)
    # would write the same rows twice; we use one. Downstream consumers
    # (OutcomeValidator, PolicyDriftMonitor, FeedbackLoopOrchestrator,
    # ReportOutcomeCommand) duck-type against InMemoryDecisionStore /
    # InMemoryPolicyStore, and the durable variants are full drop-ins
    # for those APIs.
    decision_store = memory.decisions
    policy_store = memory.policies

    if database_configured:
        from tex.stores.action_ledger_postgres import PostgresActionLedger
        from tex.stores.agent_registry_postgres import PostgresAgentRegistry
        from tex.stores.discovery_ledger_postgres import PostgresDiscoveryLedger
        from tex.stores.precedent_store_postgres import PostgresPrecedentStore

        precedent_store = PostgresPrecedentStore()
        agent_registry = PostgresAgentRegistry()
        discovery_ledger = PostgresDiscoveryLedger()
        action_ledger = PostgresActionLedger()
    else:
        precedent_store = InMemoryPrecedentStore()
        agent_registry = InMemoryAgentRegistry()
        discovery_ledger = InMemoryDiscoveryLedger()
        action_ledger = InMemoryActionLedger()

    # OutcomeStore already has its own Postgres path (see outcome_store.py).
    outcome_store = InMemoryOutcomeStore()
    # EntityStore is a tiny lookup of seeded entities; durability is
    # not required because entities are re-seeded on every boot.
    entity_store = InMemoryEntityStore()
    # TenantBaseline is rebuilt from PERMITted decisions; in pure
    # in-memory mode it warms back up after the first few requests.
    tenant_baseline = InMemoryTenantContentBaseline()

    _seed_default_policies(policy_store)
    _seed_default_entities(policy_store=policy_store, entity_store=entity_store)

    # The runtime's evidence recorder IS the memory-system's recorder
    # (single writer for the JSONL chain). Its Postgres mirror is also
    # the memory-system's: tex_evidence_records, written via
    # MemorySystem.record_decision_with_policy. The legacy `tex_evidence`
    # mirror (PostgresEvidenceMirror) is kept attached for backward
    # compat with any operator dashboards that still query that table —
    # both mirrors are idempotent and cost-bounded.
    #
    # Thread 5: every recorder built here is wired with a ``C2paEmitter``
    # and a ``PostgresManifestMirror``. The emitter is invoked by the
    # recorder ONLY when a caller passes ``outbound_artifact=...`` AND a
    # complete ``C2paEmissionContext`` to ``record_decision(...)`` AND
    # the decision verdict is PERMIT. All three conditions are decided
    # by the caller, not by the recorder, so the existing 2,200+ tests
    # that simply record decisions without artifacts observe no change
    # in behavior. The mirror is unconditionally constructed because it
    # no-ops cleanly when ``DATABASE_URL`` is unset (see
    # ``PostgresManifestMirror.__init__`` line 114-120).
    manifest_mirror = PostgresManifestMirror()
    c2pa_emitter = C2paEmitter()

    legacy_evidence_mirror: Any = None
    if database_configured:
        from tex.evidence.postgres_mirror import PostgresEvidenceMirror

        legacy_evidence_mirror = PostgresEvidenceMirror()

    recorder = EvidenceRecorder(
        normalized_evidence_path,
        mirror=legacy_evidence_mirror,
        c2pa_emitter=c2pa_emitter,
        manifest_mirror=manifest_mirror,
    )
    # Re-point the memory system's recorder at the same instance so the
    # JSONL chain (and all Thread 5 emission wiring) is shared. The
    # MemorySystem's __post_init__ already constructed a vanilla
    # EvidenceRecorder; this overwrite is the single source-of-truth
    # promotion that lets MemorySystem.record_decision_with_policy
    # benefit from C2PA emission without changing its own constructor.
    memory.recorder = recorder

    exporter = EvidenceExporter(recorder)

    retrieval_orchestrator = RetrievalOrchestrator(
        policy_store=InMemoryPolicyClauseStoreAdapter(),
        precedent_store=InMemoryPrecedentStoreAdapter(precedent_store),
        entity_store=InMemoryEntityStoreAdapter(entity_store),
    )

    agent_suite = AgentEvaluationSuite(
        registry=agent_registry,
        ledger=action_ledger,
        tenant_baseline=tenant_baseline,
    )

    # ----- Discovery layer composition ------------------------------------
    #
    # Discovery is wired with mock connectors by default. Real production
    # deployments set the appropriate environment variables and the
    # matching live-API connector is used in place of the mock for that
    # source. Mocks are still wired for the other sources so the rest of
    # the discovery surface stays exercised.
    #
    #   TEX_DISCOVERY_OPENAI_API_KEY   → OpenAIAssistantsLiveConnector
    #   TEX_DISCOVERY_OPENAI_ORG       → optional, X-Organization header
    #   TEX_DISCOVERY_OPENAI_PROJECT   → optional, X-Project header
    #
    #   TEX_DISCOVERY_SLACK_TOKEN      → SlackLiveConnector
    #   TEX_DISCOVERY_SLACK_TEAM_ID    → optional, scope to one workspace
    #
    # ----- Behavioural provenance (built early so discovery + the gate
    # ----- can both feed the one sealed identity log) --------------------
    #
    # The engine reads the gate's decision stream (the action ledger) to
    # seal birth / sighting / re-identification / drift, and the discovery
    # path anchors a birth into the *same* log the instant it registers an
    # agent — so discovery and provenance are one flow, not two systems.
    # The signing key is generated here; production injects an HSM/keystore
    # key by building the ledger explicitly.
    provenance_engine = build_default_provenance_engine()
    held_decision_sink = HeldDecisionSink()
    delegation_graph = SealedDelegationGraph()
    provenance_feed = ContinuousProvenanceFeed(
        engine=provenance_engine,
        action_ledger=action_ledger,
        held_sink=held_decision_sink,
        delegation_graph=delegation_graph,
    )

    # Mock connectors start with empty record lists so a default boot
    # produces zero candidates. Live connectors start scanning real
    # tenants the moment they're wired. If a live connector raises a
    # ConnectorError mid-scan, the discovery service catches it and
    # records a structured error on the run — it never crashes the
    # runtime.
    discovery_service = DiscoveryService(
        registry=agent_registry,
        ledger=discovery_ledger,
        connectors=_build_discovery_connectors(),
    )

    # V15: governance snapshots, drift detection, real-time alerts,
    # and the background scheduler. All optional; when DATABASE_URL
    # is unset, snapshots/drift run in pure in-memory mode and the
    # scheduler is started only if TEX_DISCOVERY_SCAN_TENANTS is set.
    from tex.discovery.alerts import AlertEngine
    from tex.discovery.presence import PresenceTracker
    from tex.discovery.scheduler import BackgroundScanScheduler
    from tex.stores.connector_health import ConnectorHealthStore
    from tex.stores.drift_events import DriftEventStore
    from tex.stores.governance_snapshots import GovernanceSnapshotStore
    from tex.stores.scan_runs import ScanRunStore

    governance_snapshot_store = GovernanceSnapshotStore()
    drift_event_store = DriftEventStore()
    alert_engine = AlertEngine.from_environment()

    # V16: durable scan-run lifecycle, connector health, presence
    # tracking. All Postgres-write-through with in-memory fallback.
    scan_run_store = ScanRunStore()
    connector_health_store = ConnectorHealthStore()

    # Soft-disappearance threshold defaults to 3 (two grace passes
    # before CONFIRMED). Operators tune via env var when their
    # platform stability profile differs.
    presence_threshold = int(
        os.environ.get("TEX_DISCOVERY_PRESENCE_THRESHOLD", "3").strip() or "3"
    )
    presence_tracker = PresenceTracker(missing_threshold=presence_threshold)

    # V16 in-process metrics surface for the discovery control loop.
    from tex.observability.discovery_metrics import DiscoveryMetrics
    discovery_metrics = DiscoveryMetrics()

    # Bind the new stores into the discovery service so every scan
    # (manual or scheduled) gets idempotency, locking, and health
    # tracking automatically.
    discovery_service = DiscoveryService(
        registry=agent_registry,
        ledger=discovery_ledger,
        connectors=_build_discovery_connectors(),
        scan_run_store=scan_run_store,
        health_store=connector_health_store,
        provenance_engine=provenance_engine,
    )

    # Dormant-agent doctrine (§2): sleep what is provably safe in silence,
    # hold the uncertain as a genuine ABSTAIN, never auto-execute the
    # irreversible day-90 deletion. Idle threshold is the one open detail
    # the doctrine leaves; default fixed, override via env.
    _idle_days = int(os.environ.get("TEX_DORMANCY_IDLE_DAYS", "30").strip() or "30")
    from datetime import timedelta as _timedelta

    dormancy_controller = DormancyController(
        registry=agent_registry,
        action_ledger=action_ledger,
        provenance_engine=provenance_engine,
        held_sink=held_decision_sink,
        delegation_graph=delegation_graph,
        idle_threshold=_timedelta(days=_idle_days),
    )

    # Count-once ignition flag (§1): "Run discovery" said once per tenant.
    ignition_registry = IgnitionRegistry()

    # ---- V16 control-loop closure ---------------------------------
    # The scheduler can auto-capture a governance snapshot at the
    # end of every cycle, bound to that cycle's scan_run_id and the
    # registry state it produced. Tex's full control loop is then:
    #
    #   discovery scan → registry mutation → ledger append →
    #   drift detection → alerts → governance snapshot → evidence
    #
    # all on a hash-chained, signed audit trail.
    def _capture_snapshot_after_scan(*, tenant_id, run):
        try:
            from tex.api.agent_routes import _build_governance
            gov = _build_governance(
                registry=agent_registry,
                action_ledger=action_ledger,
                discovery_ledger=discovery_ledger,
            )
            return governance_snapshot_store.capture(
                governance_payload=gov.model_dump(mode="json"),
                label=f"auto:scheduled-scan:{tenant_id}",
                scan_run_id=str(run.scan_run_id) if run.scan_run_id else None,
                ledger_seq_start=run.ledger_seq_start,
                ledger_seq_end=run.ledger_seq_end,
                registry_state_hash=run.registry_state_hash,
                policy_version=run.policy_version,
                tenant_id=tenant_id,
            )
        except Exception as exc:  # noqa: BLE001
            _logger.warning(
                "auto-snapshot capture failed for tenant=%s: %s", tenant_id, exc,
            )
            return None

    scan_scheduler = BackgroundScanScheduler(
        service=discovery_service,
        drift_store=drift_event_store,
        alert_engine=alert_engine,
        presence_tracker=presence_tracker,
        snapshot_capture_callable=_capture_snapshot_after_scan,
        policy_version=os.environ.get(
            "TEX_DISCOVERY_SCAN_POLICY_VERSION", ""
        ).strip() or None,
        metrics=discovery_metrics,
    )

    # ── Thread 1 / 1.5: behavioral contracts (LTLf) wiring ────────────────
    # The default runtime ships a small, opt-out contract suite. Operators
    # can disable it with TEX_CONTRACTS_DISABLE=1 to bypass the contract
    # layer entirely. Two contract-layer modes are available:
    #
    #   * Session-scoped (default, Thread 1.5): per-(agent_id, session_id)
    #     enforcer instances with ledger-replay on session bootstrap.
    #     Honours the ABC paper's (p, δ, k)-satisfaction across requests.
    #   * Stateless (legacy, Thread 1): single global enforcer, no ledger
    #     replay. Set TEX_CONTRACTS_MODE=stateless to opt in.
    #
    # FRONTIER_DELTA_thread_1.md §6 and §11.
    contracts_disabled = os.environ.get(
        "TEX_CONTRACTS_DISABLE", ""
    ).strip().lower() in {"1", "true", "yes"}
    contracts_mode = os.environ.get(
        "TEX_CONTRACTS_MODE", "session_scoped"
    ).strip().lower()

    contract_enforcer: ContractEnforcer | None = None
    contract_session_registry: SessionEnforcerRegistry | None = None
    contract_action_ledger: object | None = None
    if not contracts_disabled:
        seeded_contracts = _build_default_contract_suite()
        if contracts_mode == "stateless":
            contract_enforcer = ContractEnforcer(contracts=seeded_contracts)
        else:
            contract_session_registry = SessionEnforcerRegistry(
                contracts=seeded_contracts,
            )
            contract_action_ledger = action_ledger

    pdp = PolicyDecisionPoint(
        retrieval_orchestrator=retrieval_orchestrator,
        agent_evaluator=agent_suite,
        contract_enforcer=contract_enforcer,
        contract_session_registry=contract_session_registry,
        contract_action_ledger=contract_action_ledger,
    )
    calibrator = build_default_calibrator()

    # ----- Thread 7: EcosystemEngine integration --------------------------
    #
    # Build the eight-step EcosystemEngine and its bridge. The engine itself
    # reads ``TEX_ECOSYSTEM`` at construction time (via
    # ``_read_flag_from_env``). When the flag is unset or != "1" — the
    # default — the engine's ``evaluate()`` short-circuits to an inert
    # PERMIT in O(1) with zero graph or ledger mutation. This is the
    # backward-compat guarantee: pre-Thread-7 deployments see byte-for-byte
    # identical responses regardless of whether the engine is constructed.
    #
    # When ``TEX_ECOSYSTEM=1``, the engine runs the full eight-step
    # pipeline (steps 1-7 wired; step 8 pending Thread 8) and the bridge
    # forwards every PDP ``RoutingResult`` through it. Axis scores are
    # folded into the ``EvaluationResponse.scores`` dict under the
    # ``ecosystem.*`` namespace (see ``EvaluateActionCommand`` for the
    # exact projection).
    #
    # Collaborator wiring decisions:
    #
    #   * ``InMemoryTemporalKG``: fresh instance per process. The graph
    #     accumulates events across the lifetime of the process — this is
    #     intentional and matches the canonical ``docs/ecosystem.md``
    #     constructor surface. Postgres-backed graph state is a Thread-9+
    #     concern.
    #   * ``InMemoryLedger``: signed with the same ECDSA-P256 keypair
    #     used by ``CryptoProvenance``, so the engine's ledger writes
    #     and the provenance signature verify against the same public
    #     key. Production deployments override the signing provider via
    #     ``TEX_SIGNATURE_DEFAULT`` (Thread 9+).
    #   * ``CryptoProvenance``: receives the same keypair so the signed
    #     ``Event`` records that flow into the ledger are verifiable by
    #     the ledger's own ``verifying_public_key``.
    #   * The engine accepts ``enabled=None`` so it reads the env flag
    #     directly. We do NOT pass ``enabled=True`` here — that would
    #     override operator intent.
    #
    # The bridge is always constructed. Its ``emit_verdict()`` is the
    # only entry the evaluate command knows about; the engine's
    # short-circuit on the disabled path makes the bridge a no-op-with-
    # telemetry when the flag is off.
    _ecosystem_signing_provider = default_signature_provider()
    _ecosystem_signing_keypair = _ecosystem_signing_provider.generate_keypair(
        "tex-ecosystem-engine"
    )
    _ecosystem_graph = InMemoryTemporalKG()
    _ecosystem_projection = StateProjection(graph=_ecosystem_graph)
    _ecosystem_ledger = InMemoryLedger(
        verifying_public_key=_ecosystem_signing_keypair.public_key,
        signing_provider=_ecosystem_signing_provider,
    )
    _ecosystem_provenance = CryptoProvenance(
        signing_key=_ecosystem_signing_keypair,
        signing_provider=_ecosystem_signing_provider,
    )
    _ecosystem_ontology = OntologyValidator(
        entity_registry=EntityTypeRegistry(),
        event_registry=EventTypeRegistry(),
        event_lookup=_ecosystem_ledger,
    )
    # ``enabled=None`` → engine reads TEX_ECOSYSTEM from env. Default off.
    ecosystem_engine = EcosystemEngine(
        ontology=_ecosystem_ontology,
        graph=_ecosystem_graph,
        projection=_ecosystem_projection,
        events=_ecosystem_ledger,
        provenance=_ecosystem_provenance,
        # Step-3 contract axis: reuse the stateless enforcer when one
        # was constructed; otherwise the session registry's enforcer
        # snapshot is not yet available at engine-construction time
        # (sessions are per-request), so we pass the stateless one or
        # ``None``. When ``None``, the engine reports
        # ``contract_violation_severity=0.0`` (no contracts evaluated).
        contracts=contract_enforcer,
    )
    ecosystem_bridge = EcosystemBridge(engine=ecosystem_engine)

    evaluate_action_command = EvaluateActionCommand(
        pdp=pdp,
        policy_store=policy_store,
        decision_store=decision_store,
        precedent_store=precedent_store,
        evidence_recorder=recorder,
        action_ledger=action_ledger,
        agent_registry=agent_registry,
        tenant_baseline=tenant_baseline,
        memory_system=memory,
        # Continuous provenance: identity re-seals off the hot path after
        # every action. Default None elsewhere keeps legacy callers intact.
        provenance_feed=provenance_feed,
        # Thread 7: ecosystem bridge for the optional eight-step pass.
        # The command calls ``bridge.emit_verdict(...)`` after PDP runs
        # and folds axis scores into the response only when
        # ``TEX_ECOSYSTEM=1``. With the flag off, the engine inside the
        # bridge short-circuits and the command path is bit-for-bit
        # identical to its pre-Thread-7 shape.
        ecosystem_bridge=ecosystem_bridge,
    )

    # ── V17: Learning/Drift layer ─────────────────────────────────────────
    # Built before report_outcome_command so the command can route through
    # the orchestrator (validator + reputation update on every ingest).
    proposal_store = CalibrationProposalStore()
    reporter_reputation = ReporterReputationStore()
    outcome_validator = OutcomeValidator(
        decisions=decision_store,
        priors=outcome_store,
    )
    calibration_safety = CalibrationSafetyGuard()
    replay_validator = ReplayValidator()
    drift_classifier = DriftClassifier()
    poisoning_detector = PoisoningDetector()
    drift_monitor_for_orchestrator = PolicyDriftMonitor(decision_store=decision_store)

    # Observability sinks: structured logs + in-memory metrics + alert engine.
    learning_metrics = MetricsLearningObserver()
    learning_observer = CompositeLearningObserver(
        [LoggingLearningObserver(), learning_metrics]
    )
    learning_alert_engine = LearningAlertEngine(metrics=learning_metrics)

    learning_orchestrator = FeedbackLoopOrchestrator(
        decisions=decision_store,
        outcomes=outcome_store,
        policies=policy_store,
        proposals=proposal_store,
        validator=outcome_validator,
        reputation=reporter_reputation,
        calibrator=calibrator,
        safety=calibration_safety,
        replay=replay_validator,
        drift_monitor=drift_monitor_for_orchestrator,
        drift_classifier=drift_classifier,
        poisoning_detector=poisoning_detector,
        observer=learning_observer,
    )

    report_outcome_command = ReportOutcomeCommand(
        decision_store=decision_store,
        outcome_store=outcome_store,
        evidence_recorder=recorder,
        orchestrator=learning_orchestrator,
    )

    activate_policy_command = ActivatePolicyCommand(
        policy_store=policy_store,
    )

    calibrate_policy_command = CalibratePolicyCommand(
        policy_store=policy_store,
        outcome_store=outcome_store,
        calibrator=calibrator,
    )

    export_bundle_command = ExportBundleCommand(
        exporter=exporter,
    )

    # ----- Thread 5: digital-twin wiring -----------------------------------
    #
    # Build a single long-lived ``EcosystemDigitalTwin``. We do NOT pass
    # a temporal-KG handle today: the InMemoryTemporalKG is wired only
    # inside the EcosystemEngine pipeline (Thread 7 will compose that),
    # and the twin's ``fork_at`` path tolerates ``graph=None`` — callers
    # supply an ``EcosystemState`` directly via the route's state
    # factory. The Koopman operator + conformal calibration buffer
    # accumulate across all invocations.
    ecosystem_twin = EcosystemDigitalTwin()

    # Per-request projection of the live ecosystem state.
    #
    # This is the smallest correct projection that lets the twin
    # endpoint return a meaningful trajectory on a real deployment:
    # active agent count is observed from the agent registry, the
    # rest of the axes (drift signals, compromise ratio, governance
    # graph id) default to neutral values until the corresponding
    # subsystems start writing through.
    #
    # The factory is intentionally side-effect-free and cheap: the
    # twin route invokes it per request, and we do not want a
    # database round trip on the hot path. The agent registry's
    # ``list_all()`` is an in-memory tuple snapshot under a single
    # RLock (see ``InMemoryAgentRegistry.list_all`` line 154-156),
    # so this is O(n_agents) memory bandwidth and zero I/O.
    _twin_state_factory_registry = agent_registry
    _twin_state_factory_action_ledger = action_ledger

    def _build_ecosystem_state() -> EcosystemState:
        from datetime import UTC as _UTC, datetime as _dt
        from hashlib import sha256 as _sha256

        from tex.domain.agent import AgentLifecycleStatus as _Status

        # Use the registry's snapshot — best-effort, never raises.
        try:
            all_agents = _twin_state_factory_registry.list_all()
        except Exception:  # noqa: BLE001
            all_agents = ()

        active = tuple(
            sorted(
                str(a.agent_id)
                for a in all_agents
                if a.lifecycle_status is _Status.ACTIVE
            )
        )

        # Capability surface projection. AgentIdentity carries a
        # CapabilitySurface; we project its grant identifiers into a
        # stable tuple. Empty when no agents are registered.
        active_capability_ids: tuple[str, ...] = ()
        active_tool_ids: tuple[str, ...] = ()
        try:
            caps: set[str] = set()
            tools: set[str] = set()
            for a in all_agents:
                if a.lifecycle_status is not _Status.ACTIVE:
                    continue
                surface = getattr(a, "capability_surface", None)
                if surface is None:
                    continue
                # CapabilitySurface model carries grants/tools as
                # tuples on the model; we tolerate the absence of
                # either attribute since older identity shapes may
                # not have them.
                grants = getattr(surface, "grants", ()) or ()
                for g in grants:
                    cap_id = getattr(g, "capability_id", None)
                    if cap_id is not None:
                        caps.add(str(cap_id))
                tool_list = getattr(surface, "tools", ()) or ()
                for t in tool_list:
                    tool_id = getattr(t, "tool_id", None) or getattr(t, "name", None)
                    if tool_id is not None:
                        tools.add(str(tool_id))
            active_capability_ids = tuple(sorted(caps))
            active_tool_ids = tuple(sorted(tools))
        except Exception:  # noqa: BLE001
            active_capability_ids = ()
            active_tool_ids = ()

        snapshot_at = _dt.now(_UTC)

        # Canonical state hash for replay verification. We hash the
        # tuple of stable ids in their sorted form so the same
        # underlying state produces the same hash regardless of
        # iteration order.
        h = _sha256()
        h.update(snapshot_at.isoformat().encode("ascii"))
        for aid in active:
            h.update(b"\x00")
            h.update(aid.encode("ascii"))
        h.update(b"\x01")
        for tid in active_tool_ids:
            h.update(tid.encode("ascii"))
            h.update(b"\x00")
        h.update(b"\x02")
        for cid in active_capability_ids:
            h.update(cid.encode("ascii"))
            h.update(b"\x00")

        return EcosystemState(
            snapshot_at=snapshot_at,
            state_hash=h.hexdigest(),
            active_agent_ids=active,
            active_tool_ids=active_tool_ids,
            active_capability_ids=active_capability_ids,
            active_governance_graph_id="tex-default-graph-v1",
            aggregate_drift_signals={},
            sliding_window_compromise_ratio=0.0,
        )

    # ----- Behavioural provenance ----------------------------------------
    #
    # The engine, its signed transparency log, the held-decision sink, the
    # sealed delegation graph, and the continuous feed were all built
    # earlier (before discovery) so the gate and discovery feed one log.
    # Start the feed's background sealing worker now that wiring is done.
    provenance_feed.start()

    return TexRuntime(
        pdp=pdp,
        calibrator=calibrator,
        policy_store=policy_store,
        decision_store=decision_store,
        outcome_store=outcome_store,
        precedent_store=precedent_store,
        entity_store=entity_store,
        agent_registry=agent_registry,
        action_ledger=action_ledger,
        tenant_baseline=tenant_baseline,
        agent_suite=agent_suite,
        discovery_ledger=discovery_ledger,
        discovery_service=discovery_service,
        evidence_recorder=recorder,
        evidence_exporter=exporter,
        evaluate_action_command=evaluate_action_command,
        report_outcome_command=report_outcome_command,
        activate_policy_command=activate_policy_command,
        calibrate_policy_command=calibrate_policy_command,
        export_bundle_command=export_bundle_command,
        governance_snapshot_store=governance_snapshot_store,
        drift_event_store=drift_event_store,
        alert_engine=alert_engine,
        scan_scheduler=scan_scheduler,
        scan_run_store=scan_run_store,
        connector_health_store=connector_health_store,
        presence_tracker=presence_tracker,
        discovery_metrics=discovery_metrics,
        learning_orchestrator=learning_orchestrator,
        proposal_store=proposal_store,
        reporter_reputation=reporter_reputation,
        outcome_validator=outcome_validator,
        calibration_safety=calibration_safety,
        replay_validator=replay_validator,
        drift_classifier=drift_classifier,
        poisoning_detector=poisoning_detector,
        learning_metrics=learning_metrics,
        learning_alert_engine=learning_alert_engine,
        memory=memory,
        # Thread 5
        manifest_mirror=manifest_mirror,
        ecosystem_twin=ecosystem_twin,
        ecosystem_state_factory=_build_ecosystem_state,
        # Thread 7
        ecosystem_engine=ecosystem_engine,
        ecosystem_bridge=ecosystem_bridge,
        # Provenance
        provenance_engine=provenance_engine,
        provenance_feed=provenance_feed,
        held_decision_sink=held_decision_sink,
        delegation_graph=delegation_graph,
        dormancy_controller=dormancy_controller,
        ignition_registry=ignition_registry,
    )


def create_app(
    *,
    runtime: TexRuntime | None = None,
    evidence_path: str | Path = DEFAULT_EVIDENCE_PATH,
) -> FastAPI:
    """
    Create and configure the FastAPI application for Tex.

    If no runtime is supplied, this builds the default in-process runtime.

    The first thing this function does is force a load of the Tex
    :class:`tex.config.Settings` so the fail-closed startup guards
    (``_validate_production_secrets``) fire before any runtime is
    constructed or any request is served. If the guard rejects the
    environment, a :class:`RuntimeError` is raised with a clear
    operator-facing remediation message — never a half-built app, never
    a stub-mode TEE quote silently entering an evidence bundle, never
    an evidence summary signed with the in-repo HMAC sentinel.
    """
    # Force settings load. Catches:
    #   * TEX_EVIDENCE_SUMMARY_SECRET missing/sentinel in production-like
    #     environments (HMAC key for evidence-bundle manifest signing).
    #   * TEX_TEE_ATTESTATION_MODE='test' in production-like environments
    #     (stub mode would emit non-attested evidence).
    #   * TEX_SEMANTIC_PROVIDER='openai' without OPENAI_API_KEY.
    #   * Any other Settings-level validation regression.
    # The lru_cache on get_settings means the cost is paid exactly once
    # per process.
    try:
        get_settings()
    except (ValidationError, ValueError) as exc:
        raise RuntimeError(
            "Tex refused to start: environment configuration failed "
            f"fail-closed validation.\n\n{exc}"
        ) from exc

    resolved_runtime = runtime or build_runtime(evidence_path=evidence_path)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        _attach_runtime_to_app(app, resolved_runtime)
        # V15: start the background discovery scheduler. ``start()`` is
        # idempotent and a no-op when no tenants are configured, so
        # local-dev boots stay quiet.
        scheduler = getattr(resolved_runtime, "scan_scheduler", None)
        if scheduler is not None:
            try:
                scheduler.start()
            except Exception as exc:  # pragma: no cover
                _logger.warning("discovery scheduler start failed: %s", exc)
        try:
            yield
        finally:
            # Tear down the scheduler on shutdown so the daemon
            # thread exits cleanly.
            if scheduler is not None:
                try:
                    scheduler.stop()
                except Exception as exc:  # pragma: no cover
                    _logger.warning("discovery scheduler stop failed: %s", exc)

    app = FastAPI(
        title=APP_TITLE,
        version=APP_VERSION,
        description=(
            "Tex is a retrieval-grounded, evidence-aware, abstention-capable "
            "content adjudication engine for AI actions."
        ),
        lifespan=lifespan,
    )

    _attach_runtime_to_app(app, resolved_runtime)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(build_api_router())
    app.include_router(build_incident_router())  # THREAD 3: CAUSAL ATTRIBUTION
    app.include_router(build_agent_router())  # AGENT GOVERNANCE
    app.include_router(build_tenant_router())  # V11: TENANT BASELINE
    app.include_router(build_discovery_router())  # V13: DISCOVERY
    # V15: governance history + drift + scheduler admin
    from tex.api.governance_history_routes import (
        build_drift_router,
        build_governance_history_router,
        build_scheduler_router,
    )
    app.include_router(build_governance_history_router())
    app.include_router(build_drift_router())
    app.include_router(build_scheduler_router())
    # V16: aggregate read endpoint
    from tex.api.system_state_routes import build_system_state_router
    app.include_router(build_system_state_router())
    app.include_router(build_vigil_router())  # VIGIL: /v1/vigil surprise-selected voice
    app.include_router(build_provenance_router())  # PROVENANCE: identity-by-behaviour, sealed
    app.include_router(build_discovery_surface_router())  # PROVENANCE: count-once voice + pull-only
    app.include_router(tee_router)  # THREAD 12: composite TEE attestation
    app.include_router(vet_router)  # THREAD 13: VET Web Proofs + AID
    app.include_router(zkprov_router)  # THREAD 14: ZKPROV training-data provenance

    # V17: Learning/Drift layer
    from tex.api.learning_routes import build_learning_router
    app.include_router(build_learning_router())
    app.include_router(guardrail_router)  # GUARDRAIL: canonical webhook
    app.include_router(guardrail_adapters_router)  # GUARDRAIL: gateway-native adapters
    app.include_router(guardrail_streaming_router)  # GUARDRAIL: SSE + async + chunk streaming
    app.include_router(mcp_router)  # MCP: server interface

    # Thread 5: C2PA Content Credentials endpoints
    from tex.api.c2pa_routes import router as c2pa_router
    app.include_router(c2pa_router)

    # Thread 9: Ecosystem digital-twin simulation endpoint.
    # The router is unconditionally registered; the endpoint itself
    # returns 503 unless ``app.state.ecosystem_twin`` and
    # ``app.state.ecosystem_state_factory`` are attached at startup.
    from tex.api.ecosystem_twin_routes import build_twin_router
    app.include_router(build_twin_router())

    @app.get("/", tags=["tex"], summary="Tex service metadata")
    def root() -> dict[str, object]:
        active_policy = resolved_runtime.policy_store.get_active()

        return {
            "service": APP_TITLE,
            "version": APP_VERSION,
            "status": "ok",
            "active_policy_version": active_policy.version if active_policy else None,
            "retrieval_enabled": True,
            "precedent_count": len(resolved_runtime.precedent_store.list_all()),
            "entity_count": len(resolved_runtime.entity_store.list_all()),
            "evidence_path": str(resolved_runtime.evidence_recorder.path),
            "integrations": {
                "canonical_guardrail": "POST /v1/guardrail",
                "guardrail_formats": "GET /v1/guardrail/formats",
                "streaming": {
                    "sse_progressive": "POST /v1/guardrail/stream",
                    "token_chunk": "POST /v1/guardrail/stream/chunk",
                },
                "async": {
                    "submit": "POST /v1/guardrail/async",
                    "poll": "GET /v1/guardrail/async/{decision_id}",
                },
                "gateway_adapters": {
                    "portkey": "POST /v1/guardrail/portkey",
                    "litellm": "POST /v1/guardrail/litellm",
                    "cloudflare": "POST /v1/guardrail/cloudflare",
                    "solo": "POST /v1/guardrail/solo",
                    "truefoundry": "POST /v1/guardrail/truefoundry",
                    "bedrock": "POST /v1/guardrail/bedrock",
                    "copilot_studio": "POST /v1/guardrail/copilot-studio",
                    "agentkit": "POST /v1/guardrail/agentkit",
                },
                "mcp_server": "POST /mcp",
            },
        }

    return app


def _attach_runtime_to_app(app: FastAPI, runtime: TexRuntime) -> None:
    """
    Publish the runtime and command stack into FastAPI app state.

    The route layer depends on these exact names.
    """
    app.state.runtime = runtime

    app.state.pdp = runtime.pdp
    app.state.calibrator = runtime.calibrator

    app.state.policy_store = runtime.policy_store
    app.state.decision_store = runtime.decision_store
    app.state.outcome_store = runtime.outcome_store
    app.state.precedent_store = runtime.precedent_store
    app.state.entity_store = runtime.entity_store

    app.state.agent_registry = runtime.agent_registry
    app.state.action_ledger = runtime.action_ledger
    app.state.tenant_baseline = runtime.tenant_baseline
    app.state.agent_suite = runtime.agent_suite

    app.state.discovery_ledger = runtime.discovery_ledger
    app.state.discovery_service = runtime.discovery_service

    # V15
    app.state.governance_snapshot_store = runtime.governance_snapshot_store
    app.state.drift_event_store = runtime.drift_event_store
    app.state.alert_engine = runtime.alert_engine
    app.state.scan_scheduler = runtime.scan_scheduler

    # V16
    app.state.scan_run_store = runtime.scan_run_store
    app.state.connector_health_store = runtime.connector_health_store
    app.state.presence_tracker = runtime.presence_tracker
    app.state.discovery_metrics = runtime.discovery_metrics

    app.state.evidence_recorder = runtime.evidence_recorder
    app.state.evidence_exporter = runtime.evidence_exporter

    app.state.evaluate_action_command = runtime.evaluate_action_command
    app.state.report_outcome_command = runtime.report_outcome_command
    app.state.activate_policy_command = runtime.activate_policy_command
    app.state.calibrate_policy_command = runtime.calibrate_policy_command
    app.state.export_bundle_command = runtime.export_bundle_command

    # V17: Learning/Drift layer
    app.state.learning_orchestrator = runtime.learning_orchestrator
    app.state.proposal_store = runtime.proposal_store
    app.state.reporter_reputation = runtime.reporter_reputation
    app.state.outcome_validator = runtime.outcome_validator
    app.state.calibration_safety = runtime.calibration_safety
    app.state.replay_validator = runtime.replay_validator
    app.state.drift_classifier = runtime.drift_classifier
    app.state.poisoning_detector = runtime.poisoning_detector
    app.state.learning_metrics = runtime.learning_metrics
    app.state.learning_alert_engine = runtime.learning_alert_engine

    # Thread 5: C2PA manifest mirror + digital twin + state factory.
    # ------------------------------------------------------------------
    # ``manifest_mirror`` is read from runtime.manifest_mirror by the
    # /v1/evidence/{record_id}/c2pa GET handler in c2pa_routes; we
    # ALSO publish it as app.state.manifest_mirror so the more direct
    # ``request.app.state.manifest_mirror`` access pattern works for
    # future routes that don't want to go through ``runtime``.
    app.state.manifest_mirror = runtime.manifest_mirror
    # ``ecosystem_twin`` and ``ecosystem_state_factory`` are the two
    # names ecosystem_twin_routes.simulate() reads from. Setting both
    # turns /v1/ecosystem/twin/simulate from a 503 into a working
    # endpoint that returns a conformal-covered fused-systemic-risk
    # trajectory on every call.
    app.state.ecosystem_twin = runtime.ecosystem_twin
    app.state.ecosystem_state_factory = runtime.ecosystem_state_factory

    # Thread 7: ecosystem engine + bridge.
    # ------------------------------------------------------------------
    # Published on app.state so future routes (incident attribution that
    # wants to consult the engine's graph, admin endpoints for the floor
    # store, etc.) can read them without dependency-injecting through
    # the runtime. The evaluate command already holds its own bridge
    # reference via constructor wiring; this is for additional consumers.
    app.state.ecosystem_engine = runtime.ecosystem_engine
    app.state.ecosystem_bridge = runtime.ecosystem_bridge

    # PROVENANCE: behavioural identity engine + sealed transparency log.
    # Read by /v1/provenance/* to resolve identity-by-behaviour and to let
    # any relying party verify the signed chain.
    app.state.provenance_engine = runtime.provenance_engine
    app.state.provenance_feed = runtime.provenance_feed
    app.state.held_decision_sink = runtime.held_decision_sink
    app.state.delegation_graph = runtime.delegation_graph
    app.state.dormancy_controller = runtime.dormancy_controller
    app.state.ignition_registry = runtime.ignition_registry

    # VIGIL: the selection layer's engine. Stateless-per-cycle in v1 (warms
    # the model of normal from ledger history each cycle). Attached here so
    # v2's live learner can later be injected at construction without
    # touching the route. /v1/vigil reads the six dimensions off app.state.
    # VIGIL: the selection layer's engine, now running the full ladder.
    # v2 live learner (accumulating model of normal), v3 preference/VoI
    # (calibrated speak threshold from resolved decisions), v4 expected free
    # energy (set-level policy selection with cause->symptom collapse), v5
    # causal port (sealed attribution + provability gate). Each is injected
    # here so the route never changes; /v1/vigil reads the six dimensions off
    # app.state and the engine consults every rung.
    from tex.vigil import VigilEngine, build_default_explainer
    from tex.vigil.causal import CausalAttributionPort
    from tex.vigil.efe import ExpectedFreeEnergySelector
    from tex.vigil.learning import DirichletNormalLearner
    from tex.vigil.preference import PreferenceModel

    _vigil_preference = PreferenceModel()
    # Warm the preference model from any resolved decisions already on hand,
    # so the calibrated threshold reflects this shop from the first cycle.
    try:
        _vigil_preference.learn_from_stores(
            getattr(app.state, "decision_store", None),
            getattr(app.state, "outcome_store", None),
        )
    except Exception:  # noqa: BLE001 — never block boot on calibration
        pass

    app.state.vigil_learner = DirichletNormalLearner()
    app.state.vigil_preference = _vigil_preference
    app.state.vigil_engine = VigilEngine(
        learner=app.state.vigil_learner,
        preference=_vigil_preference,
        efe_selector=ExpectedFreeEnergySelector(),
        causal_port=CausalAttributionPort(
            decision_store=getattr(app.state, "decision_store", None),
        ),
    )
    # VIGIL: the explanation layer (pull). Deterministic floor by default;
    # binds an LLM text provider only when TEX_SEMANTIC_PROVIDER='openai'
    # and a key is present. Never generates a claim — narrates sealed facts.
    app.state.vigil_explainer = build_default_explainer()


def _seed_default_policies(policy_store: InMemoryPolicyStore) -> None:
    """
    Load the baseline policy snapshots into the policy store exactly once.
    """
    default_policy = build_default_policy()
    strict_policy = build_strict_policy()

    if default_policy.version not in policy_store:
        policy_store.save(default_policy)

    if strict_policy.version not in policy_store:
        policy_store.save(strict_policy)


def _seed_default_entities(
    *,
    policy_store: InMemoryPolicyStore,
    entity_store: InMemoryEntityStore,
) -> None:
    """
    Seed the entity store from policy-defined sensitive entities.

    This keeps retrieval alive in local development without introducing a
    separate persistence layer before it is justified.
    """
    seen_names: set[str] = set()
    rank = 1

    for policy in policy_store.list_policies():
        for entity_name in policy.sensitive_entities:
            dedupe_key = entity_name.casefold()
            if dedupe_key in seen_names:
                continue
            seen_names.add(dedupe_key)

            entity_store.save(
                RetrievedEntity(
                    entity_id=f"{policy.version}:entity:{rank}",
                    entity_type="policy_sensitive_entity",
                    canonical_name=entity_name,
                    aliases=tuple(),
                    sensitivity="high",
                    description=(
                        "Seeded from policy.sensitive_entities for local retrieval grounding."
                    ),
                    relevance_score=0.90,
                    rank=rank,
                    metadata={
                        "source_policy_id": policy.policy_id,
                        "source_policy_version": policy.version,
                        "seeded_from": "policy_snapshot.sensitive_entities",
                    },
                )
            )
            rank += 1


def _build_discovery_connectors() -> list:
    """
    Construct the discovery connector list, preferring live connectors
    where credentials are present in the environment.

    Each entry follows the same rule:

      1. If the live env vars are set, instantiate the live connector.
         If construction itself raises (e.g. malformed token), log the
         error and fall back to the mock for that source so a single
         broken credential does not take down discovery.
      2. Otherwise, instantiate the mock connector.

    The discovery service does not care which is which — they both
    satisfy the ``DiscoveryConnector`` Protocol.
    """
    connectors: list = [
        MicrosoftGraphConnector(),
        SalesforceConnector(),
        AwsBedrockConnector(),
        GitHubConnector(),
        MCPServerConnector(),
    ]

    # OpenAI Assistants
    openai_key = os.environ.get("TEX_DISCOVERY_OPENAI_API_KEY", "").strip()
    if openai_key:
        try:
            connectors.append(
                OpenAIAssistantsLiveConnector(
                    api_key=openai_key,
                    organization=os.environ.get("TEX_DISCOVERY_OPENAI_ORG") or None,
                    project=os.environ.get("TEX_DISCOVERY_OPENAI_PROJECT") or None,
                )
            )
            _logger.info("discovery: OpenAI Assistants live connector wired")
        except Exception as exc:  # noqa: BLE001
            _logger.warning(
                "discovery: OpenAI live connector failed to construct (%s); "
                "falling back to mock",
                exc,
            )
            connectors.append(OpenAIConnector())
    else:
        connectors.append(OpenAIConnector())

    # Slack
    slack_token = os.environ.get("TEX_DISCOVERY_SLACK_TOKEN", "").strip()
    if slack_token:
        try:
            connectors.append(
                SlackLiveConnector(
                    token=slack_token,
                    team_id=os.environ.get("TEX_DISCOVERY_SLACK_TEAM_ID") or None,
                )
            )
            _logger.info("discovery: Slack live connector wired")
        except Exception as exc:  # noqa: BLE001
            _logger.warning(
                "discovery: Slack live connector failed to construct (%s); "
                "falling back to mock",
                exc,
            )
            connectors.append(SlackConnector())
    else:
        connectors.append(SlackConnector())

    return connectors


app = create_app()

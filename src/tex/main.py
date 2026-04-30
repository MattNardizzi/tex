from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from tex.agent.suite import AgentEvaluationSuite
from tex.api.arcade_leaderboard import router as arcade_leaderboard_router  # ARCADE
from tex.api.agent_routes import build_agent_router
from tex.api.discovery_routes import build_discovery_router
from tex.api.tenant_routes import build_tenant_router
from tex.api.guardrail import router as guardrail_router  # GUARDRAIL: canonical webhook
from tex.api.guardrail_adapters import router as guardrail_adapters_router  # GUARDRAIL: gateway adapters
from tex.api.guardrail_streaming import router as guardrail_streaming_router  # GUARDRAIL: SSE + async
from tex.api.leaderboard import router as leaderboard_router  # LEADERBOARD
from tex.api.mcp_server import router as mcp_router  # MCP: server interface
from tex.api.routes import build_api_router
from tex.commands.activate_policy import ActivatePolicyCommand
from tex.commands.calibrate_policy import CalibratePolicyCommand
from tex.commands.evaluate_action import EvaluateActionCommand
from tex.commands.export_bundle import ExportBundleCommand
from tex.commands.report_outcome import ReportOutcomeCommand
from tex.db import arcade_leaderboard_repo  # ARCADE
from tex.db import leaderboard_repo  # LEADERBOARD
from tex.discovery.connectors import (
    AwsBedrockConnector,
    GitHubConnector,
    MCPServerConnector,
    MicrosoftGraphConnector,
    OpenAIAssistantsLiveConnector,
    OpenAIConnector,
    SalesforceConnector,
    SlackConnector,
    SlackLiveConnector,
)
from tex.discovery.service import DiscoveryService
from tex.domain.evaluation import EvaluationRequest
from tex.domain.policy import PolicySnapshot
from tex.domain.retrieval import RetrievedEntity, RetrievedPolicyClause, RetrievedPrecedent
from tex.engine.pdp import PolicyDecisionPoint
from tex.evidence.exporter import EvidenceExporter
from tex.evidence.recorder import EvidenceRecorder
from tex.learning.calibrator import ThresholdCalibrator, build_default_calibrator
from tex.policies.defaults import build_default_policy, build_strict_policy
from tex.retrieval.orchestrator import RetrievalOrchestrator
from tex.stores.action_ledger import InMemoryActionLedger
from tex.stores.agent_registry import InMemoryAgentRegistry
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

    policy_store = InMemoryPolicyStore()
    decision_store = InMemoryDecisionStore()
    outcome_store = InMemoryOutcomeStore()
    precedent_store = InMemoryPrecedentStore()
    entity_store = InMemoryEntityStore()

    # V15: agent registry + discovery ledger now have durable
    # write-through-cache implementations. When DATABASE_URL is set
    # they persist every write to Postgres and bootstrap from there
    # on startup. When it's not set they degrade to pure in-memory
    # (V14 behavior). The runtime never raises on missing DB; it
    # logs a warning and continues.
    if os.environ.get("DATABASE_URL", "").strip():
        from tex.stores.agent_registry_postgres import PostgresAgentRegistry
        from tex.stores.discovery_ledger_postgres import PostgresDiscoveryLedger
        agent_registry = PostgresAgentRegistry()
        discovery_ledger = PostgresDiscoveryLedger()
    else:
        agent_registry = InMemoryAgentRegistry()
        discovery_ledger = InMemoryDiscoveryLedger()

    action_ledger = InMemoryActionLedger()
    tenant_baseline = InMemoryTenantContentBaseline()

    _seed_default_policies(policy_store)
    _seed_default_entities(policy_store=policy_store, entity_store=entity_store)

    recorder = EvidenceRecorder(normalized_evidence_path)
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
    )

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

    pdp = PolicyDecisionPoint(
        retrieval_orchestrator=retrieval_orchestrator,
        agent_evaluator=agent_suite,
    )
    calibrator = build_default_calibrator()

    evaluate_action_command = EvaluateActionCommand(
        pdp=pdp,
        policy_store=policy_store,
        decision_store=decision_store,
        precedent_store=precedent_store,
        evidence_recorder=recorder,
        action_ledger=action_ledger,
        agent_registry=agent_registry,
        tenant_baseline=tenant_baseline,
    )

    report_outcome_command = ReportOutcomeCommand(
        decision_store=decision_store,
        outcome_store=outcome_store,
        evidence_recorder=recorder,
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
    )


def create_app(
    *,
    runtime: TexRuntime | None = None,
    evidence_path: str | Path = DEFAULT_EVIDENCE_PATH,
) -> FastAPI:
    """
    Create and configure the FastAPI application for Tex.

    If no runtime is supplied, this builds the default in-process runtime.
    """
    resolved_runtime = runtime or build_runtime(evidence_path=evidence_path)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        _attach_runtime_to_app(app, resolved_runtime)
        # LEADERBOARD: best-effort schema init. Don't crash the app if DB
        # is misconfigured — just log it and keep the rest of Tex working.
        try:
            await leaderboard_repo.ensure_schema()
        except Exception as exc:  # pragma: no cover
            _logger.warning("leaderboard schema init failed: %s", exc)
        # ARCADE: same pattern — best-effort schema for the arcade leaderboard.
        try:
            await arcade_leaderboard_repo.ensure_schema()
        except Exception as exc:  # pragma: no cover
            _logger.warning("arcade leaderboard schema init failed: %s", exc)
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
    app.include_router(leaderboard_router)  # LEADERBOARD
    app.include_router(arcade_leaderboard_router)  # ARCADE
    app.include_router(guardrail_router)  # GUARDRAIL: canonical webhook
    app.include_router(guardrail_adapters_router)  # GUARDRAIL: gateway-native adapters
    app.include_router(guardrail_streaming_router)  # GUARDRAIL: SSE + async + chunk streaming
    app.include_router(mcp_router)  # MCP: server interface

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

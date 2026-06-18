# Tex Runtime Wiring Spine

**Scope:** `src/tex/main.py` (2017 lines), `src/tex/config.py`, `src/tex/ecosystem_config.py`, `src/tex/frontier_config.py`, `src/tex/runtime/`.
**Branch:** `feat/proof-carrying-gate` (HEAD `414acbe`).
**Method:** code-read + live boot verification (`PYTHONPATH=src python -c "import tex.main; app = tex.main.create_app()"`). Every claim is traced to `file:line`. Claims sourced only from comments/docstrings are labelled `(claim, unverified)`.

This is Tex's **composition root**. `main.py` builds one in-process `TexRuntime` dataclass and publishes its fields (plus a dozen extra collaborators) onto `app.state`. The route layer reads everything by exact name off `app.state`.

---

## 0. Live-boot ground truth

Booting the app with defaults (no `DATABASE_URL`, no env flags) yields:

- `TexRuntime` has **50 dataclass fields**.
- **Zero fields are `None` after a default build** — every `Any = None` field is populated on the in-memory path.
- `app.state.runtime_ready is True` (synchronous build; deferral does not trigger under the default boot — see §3.4).
- `memory.decisions is decision_store`, `memory.policies is policy_store`, `memory.recorder is evidence_recorder` — all **True** (store-aliasing holds; single writer per artefact).
- **133 routes** mounted.
- Extra `app.state` collaborators present: `standing_governance`, `standing_gate`, `vigil_engine`, `conduit_broker`, `conduit_chain`, `held_decision_provider`, vigil learner/preference/explainer.

Boot-time log lines confirm the in-memory fallbacks fire loudly: `DurableEvidenceStore`, `OutcomeStore`, `PostgresManifestMirror`, `GovernanceSnapshotStore`, `DriftEventStore`, `ScanRunStore`, `ConnectorHealthStore`, `PresenceTracker`, `CalibrationProposalStore`, `ReporterReputationStore` all log "DATABASE_URL not set". The evidence chain signer logs `CLASSICAL algorithm ecdsa-p256` with `ml-dsa-65` keygen running natively (`pyca-cryptography-native`) — so PQ keygen succeeds but the seal labels itself classical until an ML-DSA *signing* backend is present.

---

## 1. The `TexRuntime` dataclass (main.py:130–287)

`@dataclass(frozen=True, slots=True)`. **Required** fields have a concrete type and no default (must be passed at construction). **Conditional** fields are typed `Any = None`. Per the live boot, all 50 are populated by `build_runtime()`'s default path; the `Any = None` typing means "optional for *other* constructors of the dataclass," not "left unset by `build_runtime`."

### Required fields (no default — always passed)

| # | Field | Type | Line |
|---|-------|------|------|
| 1 | `pdp` | `PolicyDecisionPoint` | 139 |
| 2 | `calibrator` | `ThresholdCalibrator` | 140 |
| 3 | `policy_store` | `InMemoryPolicyStore` (duck-typed; may be durable) | 148 |
| 4 | `decision_store` | `InMemoryDecisionStore` (duck-typed) | 149 |
| 5 | `outcome_store` | `InMemoryOutcomeStore` | 150 |
| 6 | `precedent_store` | `InMemoryPrecedentStore` (duck-typed) | 151 |
| 7 | `entity_store` | `InMemoryEntityStore` | 152 |
| 8 | `agent_registry` | `InMemoryAgentRegistry` (duck-typed) | 154 |
| 9 | `action_ledger` | `InMemoryActionLedger` (duck-typed) | 155 |
| 10 | `tenant_baseline` | `InMemoryTenantContentBaseline` | 156 |
| 11 | `agent_suite` | `AgentEvaluationSuite` | 157 |
| 12 | `discovery_ledger` | `InMemoryDiscoveryLedger` (duck-typed) | 159 |
| 13 | `discovery_service` | `DiscoveryService` | 160 |
| 14 | `evidence_recorder` | `EvidenceRecorder` | 162 |
| 15 | `evidence_exporter` | `EvidenceExporter` | 163 |
| 16 | `evaluate_action_command` | `EvaluateActionCommand` | 165 |
| 17 | `report_outcome_command` | `ReportOutcomeCommand` | 166 |
| 18 | `activate_policy_command` | `ActivatePolicyCommand` | 167 |
| 19 | `calibrate_policy_command` | `CalibratePolicyCommand` | 168 |
| 20 | `export_bundle_command` | `ExportBundleCommand` | 169 |

> Note on the type hints (main.py:142–147): stores are hinted as the `InMemory*` variants for documentation only. When `DATABASE_URL` is set, `build_runtime` substitutes Postgres-backed duck-typed drop-ins for `precedent_store`, `agent_registry`, `discovery_ledger`, `action_ledger` (main.py:562–571). `policy_store`/`decision_store` are always the `MemorySystem`'s durable stores.

### Conditional fields (`Any = None` — populated by default path; line of declaration)

| Group | Fields (declaration line) |
|-------|----------------------------|
| V15 persistence/drift/alerts | `governance_snapshot_store` (173), `drift_event_store` (174), `alert_engine` (175), `scan_scheduler` (176) |
| V16 discovery hardening | `scan_run_store` (180), `connector_health_store` (181), `presence_tracker` (182), `discovery_metrics` (183) |
| V17 learning/drift | `learning_orchestrator` (188), `proposal_store` (189), `reporter_reputation` (190), `outcome_validator` (191), `calibration_safety` (192), `replay_validator` (193), `drift_classifier` (194), `poisoning_detector` (195), `learning_metrics` (196), `learning_alert_engine` (197) |
| V18 unified memory | `memory` (210) — `MemorySystem`, the single source of truth; its `.decisions`/`.policies`/`.recorder` are the same instances as fields 4/3/14 |
| Thread 5 C2PA | `manifest_mirror` (225) — `PostgresManifestMirror`, no-ops without `DATABASE_URL` |
| Thread 5 digital twin | `ecosystem_twin` (242) — `EcosystemDigitalTwin`; `ecosystem_state_factory` (243) — zero-arg callable returning live `EcosystemState` |
| Thread 7 ecosystem | `ecosystem_engine` (261) — `EcosystemEngine` (self-gates on `TEX_ECOSYSTEM`); `ecosystem_bridge` (262) — `EcosystemBridge` |
| Provenance | `provenance_engine` (272), `provenance_feed` (283), `held_decision_sink` (284), `delegation_graph` (285), `dormancy_controller` (286), `ignition_registry` (287) |

---

## 2. `build_runtime()` boot sequence (main.py:519–1233)

Signature: `build_runtime(*, evidence_path=DEFAULT_EVIDENCE_PATH) -> TexRuntime`. `DEFAULT_EVIDENCE_PATH = Path("var/tex/evidence/evidence.jsonl")` (main.py:123).

Components in **construction order**, with their dependencies and any gate:

| Order | Built (var) | Line | Constructor deps | Gate / conditional |
|-------|-------------|------|------------------|--------------------|
| 1 | `normalized_evidence_path` | 532 | `Path(evidence_path)` | — |
| 2 | `database_configured` | 546 | `bool(os.environ["DATABASE_URL"])` | **reads `DATABASE_URL`** |
| 3 | `memory = MemorySystem(...)` | 550 | `evidence_path` (lazy import line 548) | builds durable stores; in-memory fallback if no `DATABASE_URL` |
| 4 | `decision_store = memory.decisions` | 559 | alias | — |
| 5 | `policy_store = memory.policies` | 560 | alias | — |
| 6 | `precedent_store / agent_registry / discovery_ledger / action_ledger` | 562–576 | — | **if `database_configured`** → Postgres variants (568–571); else InMemory (573–576) |
| 7 | `outcome_store = InMemoryOutcomeStore()` | 579 | — | (its own Postgres path is internal) |
| 8 | `entity_store = InMemoryEntityStore()` | 582 | — | re-seeded every boot |
| 9 | `tenant_baseline = InMemoryTenantContentBaseline()` | 585 | — | — |
| 10 | `_seed_default_policies(policy_store)` | 587 | — | see §4 |
| 11 | `_seed_default_entities(...)` | 588 | policy_store, entity_store | see §4 |
| 12 | `manifest_mirror = PostgresManifestMirror()` | 608 | — | unconditional; no-ops without `DATABASE_URL` |
| 13 | `c2pa_emitter = C2paEmitter()` | 609 | — | — |
| 14 | `legacy_evidence_mirror` | 611–615 | — | **if `database_configured`** → `PostgresEvidenceMirror()`; else `None` |
| 15 | `evidence_chain_signer` | 624 | `build_evidence_chain_signer(key_dir=...)` | reads `TEX_EVIDENCE_KEY_DIR` (default `var/tex/keys`); ML-DSA if backend present else ECDSA-P256 |
| 16 | `recorder = EvidenceRecorder(...)` | 628 | path, `mirror=legacy`, `c2pa_emitter`, `manifest_mirror`, `chain_signer` | — |
| 17 | `memory.recorder = recorder` | 641 | re-point | promotes the C2PA-wired recorder onto `MemorySystem` |
| 18 | `exporter = EvidenceExporter(recorder)` | 643 | recorder | — |
| 19 | `retrieval_orchestrator` | 645 | 3 adapters: `InMemoryPolicyClauseStoreAdapter`, `InMemoryPrecedentStoreAdapter(precedent_store)`, `InMemoryEntityStoreAdapter(entity_store)` | — |
| 20 | `agent_suite = AgentEvaluationSuite(...)` | 651 | registry, ledger, tenant_baseline | — |
| 21 | `provenance_engine = build_default_provenance_engine()` | 681 | fresh signed `SealedFactLedger` (key generated at construction; provenance/__init__.py:85) | built **early** so discovery + gate feed one log |
| 22 | `provenance_engine.rebuild_from_ledger()` | 688 | — | event-sourcing rehydrate (no-op on fresh ledger) |
| 23 | `held_decision_sink = HeldDecisionSink()` | 689 | — | — |
| 24 | `delegation_graph = SealedDelegationGraph()` | 690 | — | — |
| 25 | `provenance_feed = ContinuousProvenanceFeed(...)` | 691 | engine, action_ledger, held_sink, delegation_graph | **not started yet** (started at line 1177) |
| 26 | `discovery_service` (first build) | 704 | registry, ledger, `connectors=_build_discovery_connectors()` | **immediately rebuilt at 746** — see note |
| 27 | V15 imports + `governance_snapshot_store` | 722 | `GovernanceSnapshotStore()` | in-memory without DB |
| 28 | `drift_event_store = DriftEventStore()` | 723 | — | — |
| 29 | `alert_engine = AlertEngine.from_environment()` | 724 | env | reads alert env (Slack/webhook config inside) |
| 30 | `scan_run_store = ScanRunStore()` | 728 | — | — |
| 31 | `connector_health_store = ConnectorHealthStore()` | 729 | — | — |
| 32 | `presence_tracker = PresenceTracker(missing_threshold=...)` | 737 | — | reads `TEX_DISCOVERY_PRESENCE_THRESHOLD` (default 3, line 734) |
| 33 | `discovery_metrics = DiscoveryMetrics()` | 741 | — | — |
| 34 | `discovery_service` (FINAL build) | 746 | registry, ledger, `connectors=_build_discovery_connectors()`, scan_run_store, health_store, provenance_engine, held_sink | **shadows the line-704 instance** — only this one reaches the runtime |
| 35 | `dormancy_controller = DormancyController(...)` | 763 | registry, action_ledger, provenance_engine, held_sink, delegation_graph, idle_threshold | reads `TEX_DORMANCY_IDLE_DAYS` (default 30, line 760) |
| 36 | `ignition_registry = IgnitionRegistry()` | 773 | — | — |
| 37 | `_capture_snapshot_after_scan` closure | 784 | — | callback for scheduler |
| 38 | `scan_scheduler = BackgroundScanScheduler(...)` | 808 | service, drift_store, alert_engine, presence_tracker, snapshot callable, policy_version, metrics, dormancy_controller | `policy_version` reads `TEX_DISCOVERY_SCAN_POLICY_VERSION` (814) |
| 39 | `scan_scheduler.enroll_tenant(demo)` | 826–830 | — | reads `TEX_DISCOVERY_DEMO_TENANT` (default `"demo"`); enrolled only if non-empty |
| 40 | contracts wiring | 844–862 | — | reads `TEX_CONTRACTS_DISABLE`, `TEX_CONTRACTS_MODE` — see §2.1 |
| 41 | `decision_ledger` | 870–873 | `SealedFactLedger()` **iff** `TEX_SEAL_DECISIONS` truthy; else `None` | **GATE: `TEX_SEAL_DECISIONS`** (default OFF → `None`) |
| 42 | `build_gix_checkpoint_publisher(decision_ledger)` | 874 | decision_ledger | returns `None` unless `decision_ledger` AND `TEX_GIX_WITNESS=1` (inert by default; gix.py:663) |
| 43 | `pdp = PolicyDecisionPoint(...)` | 876 | retrieval_orchestrator, agent_suite, contract_enforcer, contract_session_registry, contract_action_ledger, **decision_ledger** | — |
| 44 | `calibrator = build_default_calibrator()` | 884 | — | — |
| 45 | Thread-7 ecosystem collaborators | 926–944 | signing provider/keypair, `InMemoryTemporalKG`, `StateProjection`, `InMemoryLedger`, `CryptoProvenance`, `OntologyValidator` | always constructed |
| 46 | `ecosystem_engine = EcosystemEngine(...)` | 946 | ontology, graph, projection, events, provenance, `contracts=contract_enforcer` | **`enabled=None` → engine self-reads `TEX_ECOSYSTEM`** (default off → O(1) inert PERMIT) |
| 47 | `ecosystem_bridge = EcosystemBridge(engine=...)` | 960 | engine | always built |
| 48 | `evaluate_action_command = EvaluateActionCommand(...)` | 962 | pdp, policy_store, decision_store, precedent_store, evidence_recorder, action_ledger, agent_registry, tenant_baseline, memory_system, provenance_feed, ecosystem_bridge | — |
| 49 | `proposal_store = CalibrationProposalStore()` | 987 | — | V17 |
| 50 | `reporter_reputation = ReporterReputationStore()` | 988 | — | — |
| 51 | `outcome_validator = OutcomeValidator(...)` | 989 | decisions=decision_store, priors=outcome_store | — |
| 52 | `calibration_safety = CalibrationSafetyGuard()` | 993 | — | — |
| 53 | `replay_validator = ReplayValidator()` | 994 | — | — |
| 54 | `drift_classifier = DriftClassifier()` | 995 | — | — |
| 55 | `poisoning_detector = PoisoningDetector()` | 996 | — | — |
| 56 | `drift_monitor_for_orchestrator = PolicyDriftMonitor(...)` | 997 | decision_store | local var (not a runtime field) |
| 57 | `learning_metrics = MetricsLearningObserver()` | 1000 | — | — |
| 58 | `learning_observer = CompositeLearningObserver([...])` | 1001 | LoggingLearningObserver + learning_metrics | local var |
| 59 | `learning_alert_engine = LearningAlertEngine(metrics=...)` | 1004 | learning_metrics | — |
| 60 | `learning_orchestrator = FeedbackLoopOrchestrator(...)` | 1006 | decisions, outcomes, policies, proposals, validator, reputation, calibrator, safety, replay, drift_monitor, drift_classifier, poisoning_detector, observer, sufficiency_gate=`EvidenceSufficiency()`, ope_evaluator=`OffPolicyEvaluator()` | — |
| 61 | `learning_trigger = AnytimeValidCalibrationTrigger(...)` | 1030 | orchestrator, proposals | — |
| 62 | `learning_orchestrator.set_trigger(learning_trigger)` | 1034 | — | breaks back-reference cycle |
| 63 | `report_outcome_command = ReportOutcomeCommand(...)` | 1036 | decision_store, outcome_store, evidence_recorder, orchestrator | — |
| 64 | `activate_policy_command = ActivatePolicyCommand(...)` | 1043 | policy_store | — |
| 65 | `calibrate_policy_command = CalibratePolicyCommand(...)` | 1047 | policy_store, outcome_store, calibrator | — |
| 66 | `export_bundle_command = ExportBundleCommand(exporter)` | 1053 | exporter | — |
| 67 | `ecosystem_twin = EcosystemDigitalTwin()` | 1066 | — (no graph handle passed) | — |
| 68 | `_build_ecosystem_state` closure | 1086 | captures agent_registry, action_ledger | the `ecosystem_state_factory` runtime field |
| 69 | `provenance_feed.start()` | 1177 | — | **spawns daemon worker thread** (feed.py:233–236) |
| 70 | `return TexRuntime(...)` | 1179–1233 | all of the above | — |

### 2.1 Contract-layer wiring (main.py:844–862)

- `TEX_CONTRACTS_DISABLE` ∈ {1,true,yes} → both `contract_enforcer` and `contract_session_registry` stay `None`; contract layer bypassed entirely.
- Else seed suite = `_build_default_contract_suite()` (one contract — see §4).
  - `TEX_CONTRACTS_MODE=stateless` → `contract_enforcer = ContractEnforcer(...)`, `contract_session_registry = None`.
  - Default (`session_scoped`) → `contract_session_registry = SessionEnforcerRegistry(...)`, `contract_action_ledger = action_ledger`, `contract_enforcer = None`.
- These feed the PDP at lines 879–881. The `ecosystem_engine` reuses `contract_enforcer` (line 958); in default session-scoped mode that is `None`, so the engine's contract axis reports `0.0` (claim in comment 956-957, consistent with code).

### 2.2 Note on the double `DiscoveryService` build

`discovery_service` is constructed **twice** (line 704 and line 746). The first instance (704) is immediately overwritten by the second (746), which adds `scan_run_store`, `health_store`, `provenance_engine`, `held_sink`. Only the second reaches `TexRuntime` and `app.state`. The first is dead allocation — both call `_build_discovery_connectors()`, so connectors are built twice on every boot. **Flag: minor wasted work / dead instance.**

### 2.3 Decision-sealing / proof-carrying-gate spine (this branch)

The proof-carrying-gate work (branch `feat/proof-carrying-gate`, commits `ca22ed0` Phase 0, `414acbe` Phase 1) is **NOT wired in `main.py`**. The seam from `build_runtime` is the single `decision_ledger` (line 873), gated on `TEX_SEAL_DECISIONS`, passed into the PDP (line 882). Inside the PDP, the attempt/decision/transcript/enforcement seals all key off `self._decision_ledger` (`pdp.py:236`, `261`, `435`, `537`) and are **inert no-ops when that ledger is `None`** — i.e. the entire seal spine is off by default. The enforcement-seal implementation lives at `src/tex/enforcement/seal.py` → `src/tex/provenance/enforcement_seal.py`; it is reached from the enforcement/PDP layer, not from the composition root. **So `TEX_SEAL_DECISIONS=1` is the master switch that activates the whole proof-carrying spine.**

---

## 3. `create_app()` + attach + warmup/lifespan (main.py:1309–1583)

### 3.1 Fail-closed settings load (1338–1344)

First action: `get_settings()` inside `try/except (ValidationError, ValueError)` → re-raised as `RuntimeError`. This forces `Settings._validate_production_secrets` (config.py:230) to fire **before** any runtime is built: in production-like envs it rejects the sentinel `TEX_EVIDENCE_SUMMARY_SECRET` and `TEX_TEE_ATTESTATION_MODE=test`. `get_settings` is `@lru_cache(maxsize=1)` (config.py:311) so the cost is paid once.

### 3.2 Runtime resolution (1349–1358)

- `defer_runtime` defaults to `runtime is None and _should_defer_runtime()`.
- If `runtime` passed in → use it. Elif `defer_runtime` → `resolved_runtime = None`. Else → `build_runtime(evidence_path=...)` **synchronously**.

### 3.3 Lifespan (1372–1413)

`@asynccontextmanager lifespan`:
- **Synchronous path** (`resolved_runtime is not None`): `_attach_runtime_to_app(app, resolved_runtime)`, set `runtime_ready = True`, `_start_scheduler(...)`.
- **Deferred path** (`resolved_runtime is None`): set `runtime_ready = False`, `runtime_error = None`; spawn a **daemon `threading.Thread`** named `tex-runtime-build` (1397) that calls `build_runtime` off the event loop, attaches it, starts the scheduler, and finally flips `runtime_ready = True` (gate opens last, line 1391). Failures are caught and stored in `app.state.runtime_error`.
- On shutdown (`finally`): resolves scheduler from local var or `app.state.runtime.scan_scheduler` and calls `.stop()`.

### 3.4 `_should_defer_runtime()` (1236–1260) — **BUG, deferral is effectively dead**

```python
override = os.environ.get("TEX_DEFER_RUNTIME")
if override is not None:
    return override.strip().lower() in {"1","true","yes","on"}
if "pytest" in sys.modules:
    return False
try:
    return get_settings().is_production_like()   # <-- line 1258
except Exception:
    return False
```

`config.py:204` declares `is_production_like` as a **`@property`** returning `bool`. Line 1258 calls it as a method `()`, which raises `TypeError: 'bool' object is not callable` (verified live). That `TypeError` is swallowed by the bare `except Exception` → returns `False`. **Net effect: unless `TEX_DEFER_RUNTIME` is explicitly set, deferral NEVER engages — even in a production-like environment.** The whole `_WarmupGateMiddleware` + background-build path is reachable only via the explicit env override. This contradicts the docstring ("Deferral is enabled ONLY for a real production-like server boot") — the auto-detect branch is dead. **Flag: real bug.**

### 3.5 Eager attach (1425–1435)

Outside lifespan, if `resolved_runtime is not None`, `_attach_runtime_to_app` is called again (eager) so a `TestClient(create_app())` *without* entering the lifespan still sees a fully wired app. If deferred, `runtime_ready = False` and `_WarmupGateMiddleware` is added (1435).

### 3.6 `_WarmupGateMiddleware` (1263–1306)

Pure-ASGI middleware, **mounted only in deferred mode**. While `app.state.runtime_ready` is falsy, it answers real routes with `503` (`warming` or `error` body) and a `retry-after: 5` header. Pass-through exact paths: `/health`, `/`. Pass-through prefixes: `/docs`, `/openapi`, `/redoc`. Once `runtime_ready` flips true, it is a transparent pass-through (does not buffer SSE bodies).

### 3.7 Middleware + router mount order (1437–1535)

1. `configure_cors(app)` (1439) — `tex.api.cors`, never wildcard-origins-with-credentials; reads `TEX_CORS_ALLOW_ORIGINS`.
2. Routers via `include_router` in this order (1441–1529):
   `build_api_router`, `build_incident_router`, `build_agent_router`, `build_tenant_router`, `build_discovery_router`, `build_governance_history_router`, `build_drift_router`, `build_scheduler_router`, `build_system_state_router`, `build_vigil_router`, `build_voice_router`, `build_provenance_router`, `build_discovery_surface_router`, `build_conduit_router`, `build_governance_standing_router`, `tee_router`, `vet_router`, `zkprov_router`, `build_learning_router`, `guardrail_router`, `guardrail_adapters_router`, `guardrail_streaming_router`, `mcp_router`, `c2pa_router`, `build_twin_router`.
3. **Conduit broker wiring (1468–1500)** — happens *during* router mounting: builds `ConduitProvenanceChain` (reads `TEX_CONDUIT_ORIGIN`), sets `app.state.conduit_chain`, builds `ConnectBroker(strategies=[EntraConnectStrategy(transport_factory=_entra_transport_factory)], chain=...)`, sets `app.state.conduit_broker`. `_entra_transport_factory` reads `TEX_CONDUIT_ENTRA_CLIENT_ID` / `TEX_CONDUIT_ENTRA_CLIENT_SECRET` lazily and raises `NotImplementedError` if absent (1481).
4. `install_metrics(app)` (1535) — top-level OpenMetrics `GET /metrics` (+ optional OTLP push), `tex.observability.metrics`.
5. `@app.get("/")` root handler (1537) — answers `warming`/`error` when runtime not yet attached, else service metadata.

CORS is added before routers but FastAPI applies middleware as the **outermost** layer regardless; in deferred mode `_WarmupGateMiddleware` is added before CORS (1435) so it wraps outside CORS.

### 3.8 `_attach_runtime_to_app()` (1586–1799) — publishes runtime onto `app.state`

Sets `app.state.runtime` then mirrors every runtime field onto `app.state` by the exact names the route layer expects (1594–1672): pdp, calibrator, the five stores, agent_registry, action_ledger, tenant_baseline, agent_suite, discovery_ledger/service, V15 (governance_snapshot_store, drift_event_store, alert_engine, scan_scheduler), V16 (scan_run_store, connector_health_store, presence_tracker, discovery_metrics), evidence recorder/exporter, the five commands, V17 learning stack, Thread-5 manifest_mirror + ecosystem_twin + state_factory, Thread-7 engine + bridge, provenance engine/feed/held_sink/delegation_graph/dormancy_controller/ignition_registry.

It **also constructs additional collaborators here** (not in `build_runtime`):
- **Conduit connector registration** (1615–1639): registers `ConduitConnectionsConnector` onto `runtime.discovery_service` with a lazy `_conduit_lookup` reading `app.state.conduit_broker` at scan time. Wrapped in `try/except` (additive; never blocks boot).
- `app.state.held_decision_provider` (1720) = `CompositeHeldProvider([HeldDecisionVigilProvider(held_sink), CalibrationProposalVigilProvider(proposal_store)])` — decision-first composition.
- `app.state.standing_governance` (1739) = `StandingGovernance(agent_registry, evaluate_command, held_sink, provenance_engine)` — fail-closed PEP-facing decision surface for `/v1/govern`.
- `app.state.standing_gate` (1756) = `build_standing_gate(standing_governance)` — in-process enforcement gate.
- VIGIL stack (1769–1799): `vigil_preference = PreferenceModel()` (warmed from decision/outcome stores, 1779), `app.state.vigil_learner = DirichletNormalLearner()`, `app.state.vigil_preference`, `app.state.vigil_engine = VigilEngine(learner, preference, efe_selector=ExpectedFreeEnergySelector(), causal_port=CausalAttributionPort(decision_store))`, `app.state.vigil_explainer = build_default_explainer()` (binds LLM only when `TEX_SEMANTIC_PROVIDER='openai'` + key present).

> Consequence: `standing_governance`, `standing_gate`, `held_decision_provider`, and the VIGIL engine are **not** `TexRuntime` fields — they exist only on `app.state` and only after `_attach_runtime_to_app`. A caller holding a bare `TexRuntime` (e.g. CLI commands) does not get them.

---

## 4. Seed + connector helpers

### `_seed_default_policies(policy_store)` (1802–1813)
Saves `build_default_policy()` and `build_strict_policy()` (from `tex.policies.defaults`) into the store, each only if its `version` is not already present (idempotent).

### `_seed_default_entities(policy_store, entity_store)` (1816–1856)
Walks `policy_store.list_policies()`, and for each `policy.sensitive_entities` name (deduped case-insensitively) saves a `RetrievedEntity` of type `policy_sensitive_entity`, sensitivity `"high"`, `relevance_score=0.90`, tagged with source policy id/version. Keeps retrieval grounding alive without a separate persistence layer.

### `_build_default_contract_suite()` (464–508)
Returns a **single** `BehavioralContract` — `content-no-api-keys` (HARD GOVERNANCE), LTL `G(field:content~not_contains:sk-proj-)`, `agent_id="*"`, `severity_on_violation="block"`. One seed contract; a prototyped second "recipient required" contract was removed (docstring 486-493). `_build_default_contract_enforcer()` (514–516) is a legacy wrapper kept for back-compat.

### `_build_discovery_connectors()` (1859–2013)
Three-way data-source resolution:
- **`TEX_SANDBOX=1`** (1881) → returns `build_sandbox_connectors()` (tex.sim) and stops.
- Otherwise base mocks always built (1899): `MicrosoftGraphConnector`, `SalesforceConnector`, `AwsBedrockConnector`, `GitHubConnector`, `MCPServerConnector`.
- **Entra consent-graph root** (1912–1949): if `TEX_DISCOVERY_ENTRA_TENANT_ID` + `_CLIENT_ID` + `_CLIENT_SECRET` all set → `EntraConsentGraphConnector(LiveGraphTransport(...))`, falling back to a `FixtureGraphTransport(entra_pages())` on construction error. Else → fixture transport; demo seed pages used unless `TEX_DISCOVERY_DEMO_SEED ∈ {0,false,no,off}` (1892).
- **OCSF audit root** (1955–1968): `OcsfAuditConnector` fed by `cloudtrail_records()` demo seed (or empty if seed suppressed). `TEX_DISCOVERY_AUDIT_QUERY` only logs that a live reader is deployment-supplied (the live reader is an unimplemented seam, claim 1960-1962).
- **OpenAI** (1971–1990): `TEX_DISCOVERY_OPENAI_API_KEY` → `OpenAIAssistantsLiveConnector` (+ `TEX_DISCOVERY_OPENAI_ORG/PROJECT`), fallback to mock `OpenAIConnector` on error or absence.
- **Slack** (1993–2011): `TEX_DISCOVERY_SLACK_TOKEN` → `SlackLiveConnector` (+ `TEX_DISCOVERY_SLACK_TEAM_ID`), fallback to mock `SlackConnector`.

`KernelEbpfConnector`, `CloudAuditConnector`, `NetworkEgressConnector` are imported at module top (main.py:49–62) but **not instantiated** in `_build_discovery_connectors`. **Flag: imported-but-unused discovery connectors.**

---

## 5. WIRING MANIFEST — every `TexRuntime` field

`Populated?` answers: is it set by `build_runtime`'s **default in-memory path** (live-verified: all 50 non-None). "conditional impl" = always set, but the concrete class swaps on a gate.

| Field | Populated | Set at line | Gate / notes |
|-------|-----------|-------------|--------------|
| `pdp` | yes | 876→1180 | always; receives `decision_ledger` (None unless `TEX_SEAL_DECISIONS`) |
| `calibrator` | yes | 884→1181 | `build_default_calibrator()` |
| `policy_store` | yes (conditional impl) | 560→1182 | = `memory.policies`; durable when `DATABASE_URL` |
| `decision_store` | yes (conditional impl) | 559→1183 | = `memory.decisions`; durable when `DATABASE_URL` |
| `outcome_store` | yes | 579→1184 | InMemory (own internal PG path) |
| `precedent_store` | yes (conditional impl) | 568/573→1185 | Postgres if `DATABASE_URL` else InMemory |
| `entity_store` | yes | 582→1186 | always InMemory; re-seeded each boot |
| `agent_registry` | yes (conditional impl) | 569/574→1187 | Postgres if `DATABASE_URL` else InMemory |
| `action_ledger` | yes (conditional impl) | 571/576→1188 | Postgres if `DATABASE_URL` else InMemory |
| `tenant_baseline` | yes | 585→1189 | InMemory |
| `agent_suite` | yes | 651→1190 | — |
| `discovery_ledger` | yes (conditional impl) | 570/575→1191 | Postgres if `DATABASE_URL` else InMemory |
| `discovery_service` | yes | 746→1192 | **second** build (704 shadowed); + conduit connector at attach |
| `evidence_recorder` | yes | 628→1193 | shared with `memory.recorder` (line 641) |
| `evidence_exporter` | yes | 643→1194 | — |
| `evaluate_action_command` | yes | 962→1195 | — |
| `report_outcome_command` | yes | 1036→1196 | — |
| `activate_policy_command` | yes | 1043→1197 | — |
| `calibrate_policy_command` | yes | 1047→1198 | — |
| `export_bundle_command` | yes | 1053→1199 | — |
| `governance_snapshot_store` | yes | 722→1200 | in-memory without `DATABASE_URL` |
| `drift_event_store` | yes | 723→1201 | in-memory without `DATABASE_URL` |
| `alert_engine` | yes | 724→1202 | `AlertEngine.from_environment()` |
| `scan_scheduler` | yes | 808→1203 | started in lifespan; `enroll_tenant(demo)` unless `TEX_DISCOVERY_DEMO_TENANT=""` |
| `scan_run_store` | yes | 728→1204 | — |
| `connector_health_store` | yes | 729→1205 | — |
| `presence_tracker` | yes | 737→1206 | `TEX_DISCOVERY_PRESENCE_THRESHOLD` (def 3) |
| `discovery_metrics` | yes | 741→1207 | — |
| `learning_orchestrator` | yes | 1006→1208 | trigger bound at 1034 |
| `proposal_store` | yes | 987→1209 | — |
| `reporter_reputation` | yes | 988→1210 | — |
| `outcome_validator` | yes | 989→1211 | — |
| `calibration_safety` | yes | 993→1212 | — |
| `replay_validator` | yes | 994→1213 | — |
| `drift_classifier` | yes | 995→1214 | — |
| `poisoning_detector` | yes | 996→1215 | — |
| `learning_metrics` | yes | 1000→1216 | — |
| `learning_alert_engine` | yes | 1004→1217 | — |
| `memory` | yes | 550→1218 | `MemorySystem`; aliases stores/recorder |
| `manifest_mirror` | yes | 608→1220 | no-ops without `DATABASE_URL` |
| `ecosystem_twin` | yes | 1066→1221 | — |
| `ecosystem_state_factory` | yes | 1086→1222 | closure over registry+ledger |
| `ecosystem_engine` | yes | 946→1224 | **self-gates on `TEX_ECOSYSTEM`** (inert PERMIT when off) |
| `ecosystem_bridge` | yes | 960→1225 | always; no-op when engine disabled |
| `provenance_engine` | yes | 681→1227 | — |
| `provenance_feed` | yes | 691→1228 | **`.start()` spawns daemon thread at 1177** |
| `held_decision_sink` | yes | 689→1229 | — |
| `delegation_graph` | yes | 690→1230 | — |
| `dormancy_controller` | yes | 763→1231 | `TEX_DORMANCY_IDLE_DAYS` (def 30) |
| `ignition_registry` | yes | 773→1232 | — |

**Never-unset summary:** there is no field that `build_runtime` leaves `None`. The `Any = None` typing is a *constructor-signature* affordance (the dataclass can be built without them in other code paths / tests), not a runtime gap. The only things that change behavior are: (a) `DATABASE_URL` swapping store implementations, (b) `TEX_ECOSYSTEM` self-disabling the ecosystem engine, (c) `TEX_SEAL_DECISIONS` deciding whether the PDP gets a real `decision_ledger`, (d) contract/discovery env flags.

---

## 6. Config & feature-flag modules

### `config.py` — `Settings` (pydantic-settings)
Env-driven via `TEX_*` aliases. Notable: `app_env` (default `development`), `tee_attestation_mode` (default `production`), `evidence_summary_secret` (`SecretStr`, default `None`), semantic provider/model config. `is_production_like` is a **property** (204) — `app_env` not in `{dev,development,test,testing,local}`. `_validate_production_secrets` (230) fail-closes on the sentinel HMAC secret and on `tee_attestation_mode=test` in production-like envs. `get_settings` is lru-cached (311).

### `ecosystem_config.py` — `EcosystemFlags`
Canonical flag parser `is_flag_on(name)` = **strict** `os.environ.get(name) == "1"` (43). `EcosystemFlags.from_env()` reads `TEX_ECOSYSTEM`, `_ONTOLOGY`, `_GRAPH`, `_EVENTS`, `_CAUSAL`, `_INSTITUTIONAL`, `_DRIFT`, `_INTERVENTION`, `_CONTRACTS`, `_SYSTEMIC`. The engine reads `TEX_ECOSYSTEM_SYSTEMIC` on each `evaluate()` via this same parser (claim 9-14, consistent). **Not imported by `main.py`** — the ecosystem engine reads flags itself.

### `frontier_config.py` — `FrontierFlags`
`_flag(name)` = `os.environ.get(name,"0")=="1"`. 12 `TEX_FRONTIER_*` flags (pqcrypto, c2pa, receipts, zkprov, nanozk, tee, vet, runtime, governance, interop, compliance, pitch). "Default: all flags off." **Not imported by `main.py`** — these gate scaffolded modules elsewhere.

---

## 7. `src/tex/runtime/` package — ORPHAN from this spine

`src/tex/runtime/` is the **Execution Governance / runtime-defense layer** (`__layer__ = 4`), five subpackages: `planguard/`, `clawguard/`, `agentarmor/`, `mage/`, `mcpshield/`. The package `__init__.py` exports nothing (`__all__ = []`).

- **`main.py` never imports `tex.runtime.*`.** Verified: no reference to `tex.runtime.{planguard,clawguard,mage,mcpshield,agentarmor}` anywhere outside the package itself, except via the **specialist layer** (`src/tex/specialists/{planguard,clawguard,agentarmor,mage,mcpshield}_specialist.py`).
- Those specialists are wired into the **PDP**, not the composition root: `pdp.py:205` builds `build_default_specialist_suite()`. So the runtime-defense modules are reachable from the running app **indirectly** (request → PDP → specialist suite → runtime defense), gated by whichever flags the specialist suite honors — **not** by `build_runtime`.
- Relative to the `main.py` composition spine this directory is **orphan** (no edge from `build_runtime`/`create_app`); relative to the whole app it is **INDIRECT** via the PDP specialist suite.

---

## 8. Flags

1. **`_should_defer_runtime` is broken (main.py:1258).** Calls `get_settings().is_production_like()` but it is a `@property` → `TypeError`, swallowed by bare `except` → always `False`. Auto-deferral never engages; only `TEX_DEFER_RUNTIME=1` activates the warmup-gate/background-build path. Contradicts the docstring.
2. **Double `DiscoveryService` construction (704 + 746).** First instance is dead; `_build_discovery_connectors()` runs twice per boot.
3. **Imported-but-unused connectors.** `KernelEbpfConnector`, `CloudAuditConnector`, `NetworkEgressConnector` imported (main.py:49-62) but never instantiated by `_build_discovery_connectors`.
4. **Proof-carrying-gate spine is OFF by default.** The branch's headline feature (`enforcement_seal` / decision sealing) only activates with `TEX_SEAL_DECISIONS=1`; default boot seals nothing (PDP `decision_ledger=None`, all seal calls inert). This matches the conservative-default design but means a default boot does not exercise the new gate.
5. **`tex.runtime/` defense layer is not in this spine.** Wired only through `tex.specialists.*` into the PDP, not through `build_runtime`. Audit it under the specialist/PDP spine, not the runtime composition root.
6. **`app.state`-only collaborators.** `standing_governance`, `standing_gate`, `held_decision_provider`, full VIGIL stack are built in `_attach_runtime_to_app`, not in `TexRuntime`. A bare-`TexRuntime` consumer (CLI) lacks them.
7. **Ecosystem/Frontier flag modules unused by `main.py`.** `ecosystem_config.py` and `frontier_config.py` are not imported by the composition root; the ecosystem engine self-reads its flag.

# Subsystem Dossier: `tex.api` — the HTTP API surface

> Scope: `/Users/matthewnardizzi/dev/tex/src/tex/api/` (30 files, 14,408 lines).
> Branch: `feat/proof-carrying-gate`. All claims below are code-verified.
> Run/import checks use `PYTHONPATH=/Users/matthewnardizzi/dev/tex/src`.

---

## Overview

`tex.api` is the **external execution surface** of Tex: the FastAPI routers, request/response
DTOs, API-key auth, CORS, rate-limiting, and adapter shims through which the world drives the
Tex governance runtime. It contains **no business logic of its own** — every route resolves a
component off `request.app.state` (populated by `tex.main._attach_runtime_to_app`) or off a
module-level domain helper, and delegates. The unit is the thinnest possible seam between HTTP
and the six-layer brain.

**Verified wiring**: booting `tex.main.create_app()` registers **133 routes** (including
FastAPI's own `/docs`, `/redoc`, `/openapi.json`, and `/metrics` from
`tex.observability.metrics`). The application-authored routes number **~118** across **22
router objects** assembled in `tex.api` plus the incident/twin/c2pa/guardrail/mcp module-level
routers. Every router is mounted **unconditionally** in `create_app`
(`src/tex/main.py:1441-1535`); there is no feature-flag gate on router registration — runtime
*readiness* is gated by `_WarmupGateMiddleware` only in the deferred-build path
(`src/tex/main.py:1435`), and individual routes 503 when their `app.state` dependency is absent.

The docstring in `routes.py:1-2` claims "22 routers ... ~80 endpoints". **The router count is
right; the endpoint count is an undercount** — the live surface is ~118 app-authored routes
(see File Inventory + the boot enumeration). Labeled `(stale doc)` in Notable Findings.

---

## File Inventory

| File | Lines | Role |
|------|------:|------|
| `__init__.py` | 11 | Layer marker only (`__layer_kind__='cross_cutting_http'`). No routes. |
| `routes.py` | 659 | Core router (no prefix): `/health`, `/evaluate`, decision replay/seal, evidence bundle/export, policy activate/calibrate/drift, outcomes. Defines `build_api_router()`. |
| `auth.py` | 514 | API-key auth: `authenticate_request`, `RequireScope`, `RequireTenantMatch`, `enforce_tenant_match`, `TexPrincipal`. No routes (the `@router.post` strings in it are docstring examples). |
| `schemas.py` | 1294 | All core Pydantic DTOs + `to_domain()`/`from_command_result()` converters for evaluate/outcome/policy/export/attribution. No routes. |
| `agent_routes.py` | 1401 | `/v1/agents/*` agent-governance registry CRUD, ledger, baseline, systemic-risk, governance matrix. `build_agent_router()`. |
| `discovery_routes.py` | 609 | `/v1/discovery/*` scan/connectors/ledger/scan_runs/findings/metrics. `build_discovery_router()`. |
| `discovery_surface_routes.py` | 349 | `/v1/surface/discovery/*` count-once "voice" surface (status/ignite/reset/count/delta/owner/coverage/held). `build_discovery_surface_router()`. |
| `governance_history_routes.py` | 818 | THREE routers: `/v1/agents/governance/*` snapshots+chain, `/v1/discovery/drift/*`, `/v1/discovery/scheduler/*`. `build_governance_history_router/_drift_router/_scheduler_router`. |
| `governance_standing_routes.py` | 133 | `/v1/govern/*` PEP decision surface (decide/posture/forbid-set). `build_governance_standing_router()`. |
| `learning_routes.py` | 805 | `/v1/learning/*` calibration proposals lifecycle, reputation, metrics, alerts, health. `build_learning_router()`. |
| `incident_routes.py` | 900 | `/v1/incidents/{decision_id}/attribute` causal attribution + SCITT signing. `build_incident_router()` (module-level `_router`). |
| `tenant_routes.py` | 139 | `/v1/tenants/{tenant_id}/baseline`. `build_tenant_router()`. |
| `system_state_routes.py` | 380 | `/v1/system/state` aggregate read. `build_system_state_router()`. |
| `vigil_routes.py` | 456 | `/v1/vigil`, `/v1/vigil/stream` (SSE), `/v1/vigil/explain`. `build_vigil_router()`. |
| `voice_routes.py` | 207 | `/v1/voice/token`, `/v1/ask`, `/v1/speak`, `/v1/speak/timed`. `build_voice_router()`. |
| `provenance_routes.py` | 167 | `/v1/provenance/*` observe/identity/reidentify/ledger(+verify). `build_provenance_router()`. |
| `conduit_routes.py` | 240 | `/v1/surface/conduit/connect/entra/{start,callback}` directory connect (Entra OAuth). `build_conduit_router()`. |
| `c2pa_routes.py` | 483 | `/v1/evidence/{record_id}/c2pa`, `/v1/c2pa/verify` Content Credentials. Module-level `router`. |
| `tee_routes.py` | 268 | `/v1/tee/verify`, `/v1/tee/status` composite TDX+GPU attestation. Module-level `router`. |
| `vet_routes.py` | 657 | `/v1/vet/*` AID lifecycle, Web Proofs, Txn-Tokens, SCITT. 15 routes. Module-level `router`. |
| `zkprov_routes.py` | 673 | `/v1/zkprov/*` training-data provenance proofs (commit/prove/verify/aggregate/narrow/proof/health). Module-level `router`. |
| `ecosystem_twin_routes.py` | 204 | `/v1/ecosystem/twin/simulate` counterfactual digital-twin sim. `build_twin_router()` (module-level `_router`). |
| `mcp_server.py` | 376 | `/mcp` JSON-RPC 2.0 MCP server (POST dispatch + GET discovery). Module-level `router`. |
| `guardrail.py` | 902 | `/v1/guardrail` canonical webhook + `/v1/guardrail/formats`. Module-level `router`. |
| `guardrail_adapters.py` | 520 | `/v1/guardrail/{portkey,litellm,cloudflare,solo,truefoundry,bedrock,copilot-studio,agentkit}` gateway shims. Module-level `router`. |
| `guardrail_streaming.py` | 543 | `/v1/guardrail/{async,async/{id},stream,stream/chunk}` async + SSE + chunk streaming. Module-level `router`. |
| `outcome_autoseal.py` | 351 | `capture_resolution_outcome()` — mints an OutcomeRecord when a held decision is sealed. Called from `routes.seal_human_resolution`. No routes. |
| `runtime_store.py` | 123 | `TTLStore` + singletons `async_results`, `stream_sessions` for async/streaming guardrail state. No routes. |
| `rate_limit.py` | 105 | `IPRateLimiter` (fixed-window per-IP) + `enforce()`. Used by `/v1/discovery/scan`. No routes. |
| `cors.py` | 121 | `configure_cors()`/`resolve_cors_policy()` — wildcard-never-with-credentials invariant. No routes. |

---

## Internal Architecture

### Assembly (who builds the app)
`tex.main.create_app()` (`src/tex/main.py:1309`) constructs the `FastAPI` app, installs CORS
(`configure_cors`, `src/tex/main.py:1439`), then `include_router`s every router
(`src/tex/main.py:1441-1535`). `_attach_runtime_to_app` (called at `src/tex/main.py:1428`,
body around `:1592-1799`) wires the runtime onto `app.state`. Two construction modes:
- **Eager** (`resolved_runtime is not None`): `build_runtime()` runs synchronously at
  `create_app()` time (`src/tex/main.py:1358`); `app.state.runtime_ready = True` immediately
  (`:1429`).
- **Deferred** (`TEX_DEFER_RUNTIME`-style path): a background thread builds the runtime
  (`src/tex/main.py:1386-1398`) and `_WarmupGateMiddleware` (`:1435`) 503s real routes until
  `app.state.runtime_ready` flips true (`:1391`).

### Two dependency-resolution patterns
1. **`app.state` resolvers** (most routers). Each router defines private `_resolve_*` helpers
   that `getattr(request.app.state, "<name>", None)` and 503 when absent. Examples:
   `routes._require_app_state_attr` (`routes.py:635`), `agent_routes._resolve_registry`
   (`agent_routes.py:456`), `discovery_routes._resolve_service` (`discovery_routes.py:592`),
   `governance_standing_routes._governance` (`governance_standing_routes.py:50`).
2. **Module-level domain singletons** (vet, zkprov, voice). `vet_routes` uses
   `default_registry()` and `default_transparency_service()` from `tex.vet.*`; `zkprov_routes`
   uses a lru-cached `_store()` returning `PostgresProvenanceProofStore()`
   (`zkprov_routes.py:120`); `voice_routes` uses module-level `grant`/`voice_ask`. These do NOT
   touch `app.state`.

### Core router (`routes.py`)
- `POST /evaluate` → `EvaluateActionCommand.execute()` via `_get_evaluate_action_command`
  (`routes.py:124,581`). DTO `EvaluateRequestDTO.to_domain()` → `EvaluationRequest`; result
  rendered via `EvaluateResponseDTO.from_command_result` (`routes.py:145`).
- `GET /decisions/{id}/replay` → `app.state.decision_store.get()` (`routes.py:169-177`).
- `GET /decisions/{id}/evidence-bundle` → `app.state.evidence_exporter.build_slice_bundle()`
  with the `prior_link_witness` inclusion-proof pattern (`routes.py:211-225`).
- `POST /decisions/{id}/seal` → `app.state.evidence_recorder.record_human_resolution()` then
  `outcome_autoseal.capture_resolution_outcome()` (`routes.py:295,343`). This is the
  "human-resolved ABSTAIN → calibration outcome" flywheel seam.
- `GET /policies/{v}/drift` → `PolicyDriftMonitor(decision_store).report()` (`routes.py:376`).
- `POST /outcomes`, `/policies/activate`, `/policies/calibrate`, `/evidence/export` → the
  matching `*Command` off `app.state` (`routes.py:404,442,482,526`).

Protocol guards (`SupportsExecuteEvaluate` etc., `routes.py:32-96`) `isinstance`-check the
`app.state` object against a `runtime_checkable` Protocol before use and 500 on mismatch
(`_assert_protocol`, `routes.py:647`).

### Guardrail family (the commercial integration surface)
- `guardrail.py` `POST /v1/guardrail` normalizes any gateway payload
  (`GuardrailWebhookRequest`) into an `EvaluationRequest` via `_to_evaluation_request` and
  delegates to the SAME `EvaluateActionCommand` (`guardrail.py:818,825`). Output shape is
  selected by `?format=`/`X-Tex-Format` from `_RENDERERS[GuardrailFormat]`
  (`guardrail.py:851`).
- `guardrail_adapters.py` — 8 vendor shims (Portkey, LiteLLM, Cloudflare, Solo.io,
  TrueFoundry, Bedrock, Copilot Studio, AgentKit). Each rewrites the vendor body into the
  canonical `GuardrailWebhookRequest`, calls `_evaluate(...)` (which calls the same command),
  and renders the vendor-native verdict shape (`guardrail_adapters.py:163-447`). These are
  real translators, not stubs — but the docstrings on copilot-studio/agentkit say "Layer 3
  stub" referring to the *vendor maturity*, while the code path is live.
- `guardrail_streaming.py` — `POST /v1/guardrail/async` (202 + BackgroundTasks, result stashed
  in `runtime_store.async_results` TTLStore), `GET /v1/guardrail/async/{id}` poll, `POST
  /stream` (SSE `started/verdict/error/done` frames), `POST /stream/chunk` (incremental
  re-evaluation gated by `_REEVAL_THRESHOLD_CHARS=80`/`_HARD_REEVAL_INTERVAL_CHARS=400`,
  `guardrail_streaming.py:386-387`).
- `mcp_server.py` — `POST /mcp` JSON-RPC 2.0 dispatch (`initialize`/`tools/list`/`tools/call`/
  `ping`). `tools/call` builds a `GuardrailWebhookRequest` and runs the same
  `EvaluateActionCommand` (`mcp_server.py:255-258`). `GET /mcp` returns server discovery.

**Convergence point**: `/evaluate`, all 8 adapters, `/v1/guardrail`, `/v1/guardrail/async`,
`/v1/guardrail/stream*`, and MCP `tools/call` ALL funnel into one
`EvaluateActionCommand.execute()` (`src/tex/commands/evaluate_action.py:187`, real PDP logic —
resolves policy, runs `self._pdp.evaluate`, persists decision, writes ledger/evidence).

### Standing governance / discovery surface (the "one voice" doctrine)
- `governance_standing_routes` `POST /v1/govern/decide` → `app.state.standing_governance.decide(...)`
  returning `outcome.to_jsonable()` whose load-bearing field is `released`
  (`governance_standing_routes.py:80-92`). `/posture` and `/forbid-set` are read surfaces.
- `discovery_surface_routes` implements the "spoken/object" doctrine: `/ignite` runs a full
  scan, enrolls the tenant into the scheduler, activates `standing_governance` for the tenant,
  and speaks exactly one humanized count line (`discovery_surface_routes.py:182-224`).
  `/count`, `/delta`, `/owner`, `/coverage`, `/held` are pull-only.

### Auth model (`auth.py`)
- `authenticate_request` (`auth.py:212`) parses `Authorization: Bearer` or `X-Tex-API-Key`,
  constant-time-compares against `TEX_API_KEYS` env, returns a `TexPrincipal`
  (fingerprint+tenant+scopes). **Fail-closed in production**: with no keys configured AND
  (`TEX_REQUIRE_AUTH=1` OR a production `TEX_APP_ENV`) it 401s (`auth.py:233-244`). The
  anonymous-all-scopes principal (`auth.py:122`, `has_scope` returns True for anonymous,
  `auth.py:100-104`) is reachable ONLY in non-production with auth not required.
- `RequireScope(scope)` (`auth.py:273`) is the per-route scope gate; `RequireTenantMatch`
  (`auth.py:372`) is a pre-handler BOLA guard reading tenant from body/query;
  `enforce_tenant_match` (`auth.py:308`) is the single tenant-isolation policy all three
  delegate to. `SCOPE_CROSS_TENANT="admin:cross_tenant"` (`auth.py:84`) bypasses tenant binding.

---

## Public API (what other code imports from `tex.api`)

Imported by `tex.main` (`src/tex/main.py:16-32`):
`build_agent_router`, `configure_cors`, `build_discovery_router`, `build_tenant_router`,
`router as guardrail_router`, `router as guardrail_adapters_router`, `router as
guardrail_streaming_router`, `router as mcp_router`, `build_provenance_router`,
`build_discovery_surface_router`, `router as tee_router`, `router as vet_router`, `router as
zkprov_router`, `build_incident_router`, `build_vigil_router`, `build_voice_router`,
`build_api_router`. Lazily (inside `create_app`): `build_governance_history_router`,
`build_drift_router`, `build_scheduler_router`, `build_system_state_router`,
`build_conduit_router`, `build_governance_standing_router`, `build_learning_router`,
`c2pa_routes.router`, `build_twin_router`.

Other internal importers (verified by grep over `src/tex`):
- `tex.observability.metrics` imports nothing from api but installs `/metrics` onto the same app.
- `tex.api.system_state_routes` imports `_build_governance`, `_resolve_*` from
  `tex.api.agent_routes` (`system_state_routes.py:214`) — cross-router reuse.
- `tex.api.auth` symbols (`RequireScope`, `authenticate_request`, `enforce_tenant_match`,
  `TexPrincipal`, `RequireTenantMatch`, `SCOPE_CROSS_TENANT`) are imported by nearly every
  router file. `enforce_tenant_match_optional` is the opt-in variant used by routes that don't
  require Tex auth (e.g. c2pa).
- `tex.api.outcome_autoseal.capture_resolution_outcome` imported by `routes.py:10`.
- `tex.api.runtime_store.{async_results,stream_sessions}` imported by `guardrail_streaming.py`.

`tex.api.__init__` exports only the layer markers (`__layer__`, `__layer_kind__`).

---

## Wiring

### IN — live call paths from `tex.main.create_app`
Every router is reachable. The canonical path:
`uvicorn → tex.main:app` (`src/tex/main.py:2016 app = create_app()`) →
`create_app` (`:1309`) → `app.include_router(build_api_router())` (`:1441`) →
`routes.router` → `POST /evaluate` → `EvaluateActionCommand.execute`
(`src/tex/commands/evaluate_action.py:187`).

Representative per-router live paths (file:line of the `include_router`):
- `routes` — `src/tex/main.py:1441`
- `incident_routes` — `:1442` → `/v1/incidents/{id}/attribute` → `compute_attribution` +
  `mint_signed_statement` (`incident_routes.py:660,705`)
- `agent_routes` — `:1443` → `app.state.agent_registry`/`action_ledger` (`:1603-1604`)
- `tenant_routes` — `:1444`
- `discovery_routes` — `:1445` → `app.state.discovery_service` (`:1609`)
- `governance_history/drift/scheduler` — `:1452-1454`
- `system_state_routes` — `:1457`
- `vigil_routes` — `:1458` → `app.state.vigil_engine` (`:1788`)
- `voice_routes` — `:1459`
- `provenance_routes` — `:1460` → `app.state.provenance_engine` (`:1703`)
- `discovery_surface_routes` — `:1461` → `app.state.ignition_registry`/`standing_governance`
- `conduit_routes` — `:1500`; broker built+attached at `:1496` (`app.state.conduit_broker`)
- `governance_standing_routes` — `:1507` → `app.state.standing_governance` (`:1739`)
- `tee_routes` — `:1508`; `vet_routes` — `:1509`; `zkprov_routes` — `:1510`
- `learning_routes` — `:1514` → `app.state.learning_orchestrator` (`:1663`)
- `guardrail` / `guardrail_adapters` / `guardrail_streaming` — `:1515-1517` →
  `app.state.evaluate_action_command` (`:1656`)
- `mcp_server` — `:1518`
- `c2pa_routes` — `:1522` → `runtime.manifest_mirror` (`:1681`)
- `ecosystem_twin_routes` — `:1529` → `app.state.ecosystem_twin`/`ecosystem_state_factory`
  (`:1687-1688`)

`wired_status = LIVE` for the unit: all 22+ routers are mounted unconditionally and the app
boots (verified — `create_app()` returns and enumerates 133 routes).

### Live call path (single end-to-end trace)
`POST /v1/guardrail` → `guardrail.guardrail_evaluate` (`guardrail.py:788`) →
`_to_evaluation_request` → `_get_evaluate_action_command(request)` returns
`app.state.evaluate_action_command` (`guardrail.py:872`) →
`EvaluateActionCommand.execute(EvaluationRequest)`
(`src/tex/commands/evaluate_action.py:187`) → `self._pdp.evaluate(...)` (the six-layer brain)
→ decision persisted to `app.state.decision_store`, evidence chained, response rendered by the
selected `GuardrailFormat` renderer.

### OUT — dependencies of `tex.api`
Tex subsystems (imported across the routers): `tex.commands.*` (evaluate/report/activate/
calibrate/export), `tex.learning.*` (drift, health, orchestrator, classify),
`tex.domain.*` (decision/outcome/verdict/discovery/agent identities),
`tex.discovery.*` (service, conduit broker, graph_transport, scheduler),
`tex.governance.standing` (`StandingGovernance`), `tex.provenance.*`,
`tex.vet.*` (aid, web_proof, txn_token, scitt), `tex.zkprov.*` (commitment, manifest, proof,
recursive, scitt_arp, backends), `tex.tee.*` (verify_attestation, capability probes),
`tex.c2pa.*`, `tex.pqcrypto.algorithm_agility` (signature providers / ML-DSA),
`tex.sim`/`tex.ecosystem` (digital twin), `tex.stores.*` (postgres-capable stores),
`tex.observability` (`emit_event`), `tex.causal` (`compute_attribution`).

External libs: `fastapi`, `pydantic`, `starlette` (StreamingResponse/run_in_threadpool),
stdlib (`hmac`, `hashlib`, `base64`, `json`, `zipfile`, `io`, `threading`,
`concurrent.futures`, `urllib.parse`, `functools.lru_cache`).

---

## Implementation Reality

**REAL (substantive logic, not stubs):**
- All 118 app-authored routes are wired to live components and the app boots with the full
  runtime attached. No route handler is a `pass`/`NotImplementedError` placeholder.
- `EvaluateActionCommand.execute` is real (`src/tex/commands/evaluate_action.py:187+`:
  resolves policy, runs PDP, validates alignment, persists decision).
- `auth.py` constant-time key matching via `hmac.compare_digest` (`auth.py:256`); fail-closed
  production posture is real and exercised.
- `cors.py` enforces the wildcard-never-with-credentials invariant with a real env resolver
  (`cors.py:71-101`).
- `incident_routes` SCITT signing is real: `mint_signed_statement` + `record_attribution`
  hash-chain into the evidence ledger (`incident_routes.py:705,750`).
- `tee_routes /verify` calls real `verify_attestation` and returns fail-closed `ok=False` on
  failure rather than raising (`tee_routes.py:205,188-193`).
- `vet_routes`/`zkprov_routes` call real crypto: ML-DSA signature providers via
  `get_signature_provider` (`vet_routes.py:406-409`), `register_decision`/`verify_*`
  (`vet_routes.py:548,573`), `issue_commitment`/`aggregate_proofs`/`narrow_proof`
  (`zkprov_routes.py:317,492`). Boot log confirms a live ML-DSA-65 keygen
  (`pyca-cryptography-native` backend).

**GUARDED / DEGRADED-BY-DESIGN (intentional fail-honest paths, NOT hollow stubs):**
- `zkprov /issue-commitment` 400s unless `use_deterministic_test_ca=True`
  (`zkprov_routes.py:300-311`) — the production HSM CA flow is deliberately not wired; the
  Ed25519 test CA is labeled "tests/demos only, never regulator-grade." This is an explicit
  guard, not a silent fallback.
- `vet /notarize` returns `is_stub` reflecting `proof.mode is WebProofMode.STUB`
  (`vet_routes.py:368`) — the stub mode is surfaced to the caller, never hidden.
- `conduit` Entra transport factory raises `NotImplementedError("Entra app credentials not
  configured")` when `TEX_CONDUIT_ENTRA_CLIENT_*` env is absent
  (`src/tex/main.py:1481`); `/connect/entra/start` then returns `configured:false` with an
  honest step list rather than a broken redirect (`conduit_routes.py:145-155`).
- `ecosystem_twin /simulate` 503s unless `app.state.ecosystem_twin` and `ecosystem_state_factory`
  are attached (`ecosystem_twin_routes.py:121,142`).
- `c2pa` routes 503 when the manifest mirror is not configured (no `DATABASE_URL`)
  (`c2pa_routes.py:128-135`).
- `voice /speak/timed` 503s when ElevenLabs isn't configured (`voice_routes.py:196-200`);
  `/voice/token` 503s when the gateway secret is absent (`voice_routes.py:116-120`).

**Persistence-degraded by default in dev**: nearly every store logs "DATABASE_URL not set —
in-memory" on boot (decision/policy/outcome/governance/drift/scan_run/connector_health/
proposal/reputation stores). Durability is real when `DATABASE_URL` is set; in-memory
otherwise. This is the durable-vs-volatile boundary, not a stub.

**No dead code of note within `tex.api`**: the `@router.post(...)` strings inside `auth.py`
(lines 279/389/399) are docstring USAGE examples, not registered routes (verified — they live
inside class docstrings; the boot enumeration shows no `/admin/policies/activate`). Flagged so
a future audit doesn't mistake them for an unmounted admin route.

---

## Technology / SOTA

- **FastAPI + Pydantic v2** DTOs with `to_domain()`/`from_command_result()` converters
  isolating the wire schema from the domain model (`schemas.py`).
- **Scoped API-key RBAC** with constant-time comparison and per-route `RequireScope` +
  dependency-enforced tenant isolation (OWASP API #1 / BOLA defense, `auth.py`).
- **Server-Sent Events (SSE)** for one-way push: `/v1/vigil/stream` and `/v1/guardrail/stream`
  with `id:`/`event:`/heartbeat frames, `run_in_threadpool` offload to protect the single event
  loop (`vigil_routes.py:362-412`, `guardrail_streaming.py:302-338`).
- **JSON-RPC 2.0 MCP server** (`/mcp`) — Model Context Protocol transport over HTTP
  (`mcp_server.py`).
- **Post-quantum signatures** (ML-DSA-65 / Dilithium) via `tex.pqcrypto.algorithm_agility` in
  vet/zkprov/incident routes; **SCITT** signed-statement transparency (COSE_Sign1, Merkle
  inclusion proofs) in incident + vet; **C2PA** Content Credentials (COSE_Sign1 over CBOR
  claim) in c2pa_routes; **composite TDX+NVIDIA-GPU TEE** attestation (AR4SI trustworthiness
  vector per draft-ietf-rats-ear) in tee_routes; **Halo2-IPA / Poseidon2** ZK training-data
  provenance in zkprov_routes; **zkTLS / TLSNotary-style Web Proofs** in vet_routes.
- **Hash-chained evidence bundles** with `prior_link_witness` inclusion proofs (CT/Rekor-style)
  exported from `/decisions/{id}/evidence-bundle` and the signed-zip snapshot bundle
  (`routes.py:196-209`, `governance_history_routes.py:467-625`).
- **OAuth admin-consent flow** (Microsoft Entra one-click) with a popup `postMessage` close
  page (`conduit_routes.py:93-122`).
- **Idempotency-Key** support + per-tenant locking + fixed-window IP rate limiting on discovery
  scan (`discovery_routes.py:311-356`, `rate_limit.py`).

---

## Persistence

`tex.api` owns **two in-memory stores of its own**, both `TTLStore`
(`runtime_store.py`):
- `async_results` (1h TTL) — async guardrail evaluation results polled at
  `GET /v1/guardrail/async/{id}`.
- `stream_sessions` (5min TTL) — streaming-chunk session buffers for `/stream/chunk`.
Plus `rate_limit.IPRateLimiter._buckets` (in-process fixed-window) and
`outcome_autoseal._executor` (a long-lived 2-worker `ThreadPoolExecutor`, `outcome_autoseal.py:81`).

All other persistence is **borrowed** from `app.state.*` runtime stores (decision/outcome/
policy/evidence/agent/discovery/governance/drift/proposal/reputation/manifest), which are
Postgres-durable when `DATABASE_URL` is set and in-memory otherwise (boot logs confirm
in-memory in the default dev run). The `conduit_broker` connection state is explicitly
in-process / single-worker (acknowledged limitation, `conduit_routes.py:26-28`,
`src/tex/main.py:1466-1467`).

---

## Notable Findings

1. **(stale doc) Endpoint count is undercounted.** `routes.py:1-2` claims "~80 endpoints"; the
   live app registers **133 routes total**, of which ~118 are app-authored (the rest are
   FastAPI's `/docs`,`/redoc`,`/openapi.json` and `/metrics`). The "22 routers" claim is
   accurate. Verified by booting `create_app()` and enumerating `app.routes`.

2. **Docstring "Layer 3 stub" on adapters is misleading.** `adapter_copilot_studio` /
   `adapter_agentkit` docstrings say "Layer 3 stub" (`guardrail_adapters.py:364,402`), but the
   code is a real, live translator delegating to the same `EvaluateActionCommand`. The "stub"
   refers to vendor-integration maturity, not a hollow handler. Worth relabeling.

3. **`auth.py` contains route-decorator strings that are NOT routes.** Lines 279/389/399 are
   inside class docstrings as usage examples. A naive grep for `@router.post` flags them; they
   register nothing (no `/admin/policies/activate` in the boot enumeration). No real admin
   route exists for policy activation under that path — `/policies/activate` (core router,
   `routes.py:435`) is the real one.

4. **One funnel, many doors.** `/evaluate`, `/v1/guardrail`, all 8 vendor adapters, async/
   stream/chunk, and MCP `tools/call` ALL converge on a single `EvaluateActionCommand.execute`.
   This is a genuine architectural strength (one decision path, one evidence chain) — and a
   single point whose correctness the entire commercial surface depends on.

5. **Production CA flow for zkprov is intentionally unbuilt.** `/v1/zkprov/issue-commitment`
   hard-400s unless the deterministic Ed25519 test CA is requested
   (`zkprov_routes.py:300-311`). The regulator-grade HSM key-id path is a documented TODO, not
   a hidden stub — but it means the *commitment-issuance* endpoint is demo-only today, while
   verify/aggregate/narrow are real.

6. **`system_state_routes` reaches into `agent_routes` private helpers.** It imports
   `_build_governance`, `_resolve_registry`, `_resolve_ledger`, `_resolve_discovery_ledger`
   from `tex.api.agent_routes` (`system_state_routes.py:214`). Cross-router coupling on
   underscore-private names — works, but fragile.

7. **`tenant_routes` reaches into store internals under lock.** `get_tenant_baseline` reads
   `store._signatures` / `store._recipient_domains` directly inside `store._lock`
   (`tenant_routes.py:118-130`), with an inline `# noqa: SLF001` admitting it. The author flags
   it as "the only place outside the store that reaches in." Real leakage of store internals
   into the HTTP layer.

8. **CORS default is credentialed-but-loopback-scoped.** Unset `TEX_CORS_ALLOW_ORIGINS`
   defaults to `localhost:3000`/`127.0.0.1:3000` WITH credentials (`cors.py:84-85`). Safe (inert
   off-loopback) but means a production deployment that forgets to set origins serves NO
   cross-origin browser clients rather than failing loudly. Documented intent, not a bug.

9. **`/v1/incidents/.../attribute` is read-only-but-writes-evidence.** It writes exactly one
   `record_attribution` evidence row per call (`incident_routes.py:750`); a caller hitting it
   repeatedly grows the evidence chain. Not a leak, but worth noting it is not idempotent on
   the ledger.

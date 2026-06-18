# Subsystem Dossier — `observability` (Observability & Metrics)

> Scope: `/Users/matthewnardizzi/dev/tex/src/tex/observability/`
> Branch: `feat/proof-carrying-gate`
> Spine classification: `observability=LIVE`. **Confirmed LIVE — but only in part.** Two of the four modules are fully wired into the running app; a large slice of `telemetry.py` and all of `governance_span.py` are **not** reachable from the running app (dead / test-only). See Notable Findings.
> All file:line references verified against code (not docstrings) on this branch.

---

## Overview

`observability` is Tex's monitoring layer (self-declared `__layer__ = 3`, `__layer_kind__ = 'monitoring'`, `observability/__init__.py:9-10`). It is the 2nd-most-imported subsystem (~102 import sites) — but that import count is **almost entirely one symbol**: `emit_event` (and secondarily `get_logger`) from `telemetry.py`. The unit provides four distinct, loosely-coupled surfaces:

1. **`telemetry.py`** — structured JSON logging + `emit_event()` (the pervasively-imported function), plus an *unused* request-scoped ASGI middleware, context-var binders, and in-process counters.
2. **`metrics.py`** — the top-level Prometheus/OpenMetrics `GET /metrics` exposition aggregator + HTTP-observation ASGI middleware + optional OTLP push bridge. Wired live via `install_metrics(app)`.
3. **`discovery_metrics.py`** — `DiscoveryMetrics`, process-local counters for the discovery scan loop. Wired live (written by the scheduler, read by `/v1/discovery/metrics` and `/metrics`).
4. **`governance_span.py`** — renders an `EcosystemVerdict` to a GAAT-compatible OpenTelemetry attribute dict. **Test-only**; no production caller.

The unit takes **zero new hard third-party dependencies** for its verified surface: all Prometheus text is hand-rendered. OpenTelemetry SDK is an *optional* dependency (`requirements-otel.txt`, confirmed present) gated behind an env flag.

---

## File Inventory

| File | Lines | Role |
|------|-------|------|
| `__init__.py` | 11 | Layer marker only (`__layer__=3`, `__layer_kind__='monitoring'`). No exports. |
| `telemetry.py` | 474 | Structured JSON logging (`JsonLogFormatter`), `emit_event()` (the 102-import workhorse), `get_logger()`, request-id/decision-id/policy-version context-vars + binders, in-process `TelemetryState` counters, `TelemetryMiddleware` ASGI middleware, `instrument_app()`. **Only `emit_event`/`get_logger` are live; the middleware/binders/counters are dead code.** |
| `metrics.py` | 471 | Top-level Prometheus `GET /metrics` aggregator. `HttpMetrics` (thread-safe HTTP counters), `MetricsMiddleware` (pure-observation ASGI), `render_metrics()` exposition, `install_metrics(app)` wiring point, optional `_maybe_start_otlp_exporter` OTLP push bridge. **Live** via `main.py:1535`. |
| `discovery_metrics.py` | 163 | `DiscoveryMetrics` — process-local, RLock-guarded counters for discovery scans (scans started/completed/failed, drift counts, per-connector success/failure, avg scan duration). **Live** (scheduler writes, API reads). |
| `governance_span.py` | 122 | `verdict_to_otel_attributes()` — renders an `EcosystemVerdict` into a GAAT-compatible (arxiv 2604.05119, claim-unverified) OTel span-attribute dict; `GAAT_ACTION_TABLE`, `GAAT_SPAN_SCHEMA_VERSION`. **Test-only** — no production caller. |

Total: 1241 lines across 4 substantive `.py` files (+ empty `__init__`).

---

## Internal Architecture

### `telemetry.py` — structured logging + events (partly dead)

**Live core (the 102-import path):**

- `JsonLogFormatter(logging.Formatter)` (`telemetry.py:122-153`) — emits one JSON object per record: `timestamp`, `level`, `logger`, `service="tex"`, `message`, plus context fields `request_id`/`decision_id`/`policy_version` pulled from context-vars (`telemetry.py:137-139`), an optional `event` name (`:142-144`), and arbitrary `fields` coerced JSON-safe (`:146-148`). Drops `None` values and sorts keys (`:153`).
- `configure_logging(...)` (`telemetry.py:156-178`) — sets level, `propagate=False`, replaces handlers with a single `StreamHandler(sys.stdout)` using `JsonLogFormatter`. Idempotent-safe (clears handlers first, `:175`).
- `get_logger(name="tex")` (`telemetry.py:181-185`) — returns the named logger; **lazily calls `configure_logging` if the logger has no handlers** (`:183-184`). This is the path that actually installs the JSON formatter at runtime.
- `emit_event(event, *, level, logger, message, **fields)` (`telemetry.py:255-279`) — the workhorse. Normalizes the event name, resolves a logger via `get_logger()` if none passed (`:270`), and logs with `extra={"event":..., "fields": _coerce_jsonable_mapping(fields)}`. **This is the symbol imported ~100×.**
- JSON coercion helpers: `_coerce_jsonable_mapping` / `_coerce_jsonable` (`telemetry.py:420-471`) — depth-bounded (`_DEFAULT_MAX_JSON_DEPTH=8`, `:28`) recursive coercion of scalars/datetimes/mappings/sequences; falls back to `str()` for unknown types (`:471`); returns `"<max_depth_exceeded>"` past depth (`:438`).

**Verified runtime behavior:** importing and calling `get_logger()` produces a `tex` logger with exactly one handler whose formatter is `JsonLogFormatter`, `propagate=False` (confirmed by executing the module). So **structured JSON logging is genuinely live** at runtime through the `emit_event → get_logger → configure_logging` lazy path — even though the explicit `configure_logging`/`instrument_app` entrypoints are never called by the app.

**Dead / unwired core (verified zero references anywhere in repo, incl. tests):**

- Context-vars `_REQUEST_ID_CTX` / `_DECISION_ID_CTX` / `_POLICY_VERSION_CTX` (`telemetry.py:18-23`) and their getters `get_request_id/decision_id/policy_version` (`:188-197`) — the getters *are* read by `JsonLogFormatter` (`:137-139`), so they always return `None` in practice because nothing ever sets them.
- Binders `bind_request_id` / `bind_decision_id` / `bind_policy_version` / `bind_telemetry_context` (`telemetry.py:200-252`) — **0 callers** (grep across `src` + `tests`).
- `TelemetryState` + module-singleton `_STATE` (`telemetry.py:69-119`), and the write API `record_request/record_evaluation/record_outcome`, plus public wrappers `mark_evaluation_recorded` (`:282`), `mark_outcome_recorded` (`:286`), `telemetry_snapshot` (`:290`) — **0 callers**. The only thing that would increment these counters is `TelemetryMiddleware`, which is never installed; so the counters are permanently zero.
- `TelemetrySnapshot` dataclass (`telemetry.py:31-66`) — only produced by `TelemetryState.snapshot()`, itself uncalled.
- `TelemetryMiddleware` (`telemetry.py:294-382`) — a full request-scoped middleware that would bind `request_id`, time the request, emit `http.request.completed`/`http.request.failed` events, append an `x-request-id` response header, and increment `_STATE`. **0 install sites** (`app.add_middleware(TelemetryMiddleware, ...)` appears nowhere).
- `instrument_app(app, ...)` (`telemetry.py:385-399`) — would attach `TelemetryMiddleware` and publish `app.state.telemetry_logger/telemetry_snapshot/emit_telemetry_event`. **0 callers** — `main.py` never calls it.

### `metrics.py` — top-level Prometheus exposition (live)

Data flow: `install_metrics(app)` → attaches `MetricsMiddleware` + `/metrics` router; on each scrape `render_metrics(app, http)` composes live surfaces off `app.state`.

- `HttpMetrics` (`metrics.py:70-118`) — `__slots__`, `RLock`-guarded, process-local. Tracks `(method, status_class) → count` (`:86`), `method → summed_seconds` (`:88`), `in_flight` gauge, and process start time. `_status_class` (`:58-67`) buckets into `1xx..5xx` to **bound label cardinality** (no per-path labels — explicit design choice, `:54-55`). `snapshot()` (`:111-118`) returns a copy under lock.
- `MetricsMiddleware(ASGIApp)` (`metrics.py:121-166`) — pure-observation: wraps `send` to capture the response status (`:142-145`), increments/decrements in-flight, and `observe()`s method/status/duration on both the success and exception paths (re-raising on exception so behavior is unchanged, `:150-158`). Adds **no headers**, no per-request log — explicitly safe to attach unconditionally (`:122-127`).
- `render_metrics(app, http)` (`metrics.py:176-228`) — hand-renders Prometheus text-exposition. Emits: `tex_build_info` (gauge w/ version label, `:186-188`), `tex_process_uptime_seconds`, `tex_http_requests_total` (counter, method×status), `tex_http_request_duration_seconds_sum`, `tex_http_requests_in_flight` (gauge). Then splices in three defensively-read surfaces:
  - `_render_durability` (`:231-269`) — `tex_database_configured` (from `DATABASE_URL` env, `:234-237`); per-store + overall memory durability via `memory.health()` resolved off `app.state.memory` *or* `app.state.runtime.memory` (`:241-260`); `tex_evidence_chain_head_present` from `app.state.evidence_recorder._last_record_hash` (`:263-268`).
  - `_render_discovery` (`:296-311`) — flattens `app.state.discovery_metrics.snapshot()` into `tex_discovery{metric="..."}` gauges via `_flatten_numeric` (`:332-342`).
  - `_render_learning` (`:314-329`) — splices the raw text from `app.state.learning_metrics.prometheus_text()` (the learning layer's own exposition, `tex.learning.observability.MetricsLearningObserver.prometheus_text` at `learning/observability.py:148`).
  - **Every surface is read defensively** — a missing/broken one is skipped with a `_logger.debug` and never a 500 on the scrape path (`:249-250`, `:303-304`, `:324-325`).
- `_iter_store_durability` (`metrics.py:271-293`) — tolerant shape reader: tries `as_dict()`/`to_dict()` then falls back to scanning `*_durable` boolean attributes.
- `_escape` (`metrics.py:345-346`) — escapes `\`, `"`, newline for label values.
- `build_metrics_router(http)` (`metrics.py:352-361`) — `APIRouter` with `GET /metrics` (`include_in_schema=False`, `:356`) returning `PROMETHEUS_CONTENT_TYPE` (`text/plain; version=0.0.4`, `:52`).
- `install_metrics(app)` (`metrics.py:364-384`) — the **single wiring point**: adds middleware, includes router, sets `app.state.http_metrics`, best-effort starts the OTLP exporter (wrapped in try/except, fail-open, `:380-383`). Returns the `HttpMetrics`.
- `_maybe_start_otlp_exporter(app, http)` (`metrics.py:387-461`) — OTLP push bridge, double-gated: returns immediately unless `OTEL_EXPORTER_OTLP_ENDPOINT` is set (`:401-403`) AND the OTel SDK imports (`:405-426`, falls back gRPC→HTTP exporter). Builds a `MeterProvider` with a `PeriodicExportingMetricReader` (interval from `TEX_METRICS_OTLP_INTERVAL_SECONDS`, default 30s, `:428-431`) and registers four observable instruments (uptime gauge, in-flight gauge, requests counter, db-configured gauge) backed by callbacks reading the same `HttpMetrics` (`:441-459`). Self-labelled `UNVERIFIED-AT-RUNTIME` (`:396-399`).

### `discovery_metrics.py` — discovery scan counters (live)

- `DiscoveryMetrics` (`discovery_metrics.py:23-160`) — `__slots__`, `threading.RLock`-guarded process-local counters. Writes: `record_scan_started/completed/failed` (`:75-91`), `record_idempotent_replay` (`:93`), `record_lock_conflict` (`:97`), `record_drift(new/changed/disappeared/silent_misses/recovered/reappeared)` (`:101-111`), `record_alert_dispatched` (`:113`), `record_snapshot_captured` (`:117`), `record_connector_result(name, succeeded)` (`:121-126`, populates `defaultdict(int)` per-connector success/failure maps). `snapshot()` (`:130-160`) returns a nested dict including a computed `average_scan_duration_seconds` (`:132-136`, guards divide-by-zero) and `last_scan_completed_at` timestamp. Explicitly *not* a Prometheus/StatsD/OTel client (docstring `:8-13`).

### `governance_span.py` — GAAT OTel attributes (test-only)

- `verdict_to_otel_attributes(verdict, ...)` (`governance_span.py:48-110`) — pure function mapping an `EcosystemVerdict` (imported from `tex.ecosystem.verdict`, `:41`) into a flat attribute dict: OTel resource attrs (`service.name`, `service.namespace`), `tex.governance.schema_version`, GAAT core (`governance.decision`, `governance.enforcement_level`, `governance.viability_index`), Tex six-axis decomposition (`tex.axis.*` from `verdict.axis_scores`), and trace-correlation envelope fields (state hashes, evidence record id, issued_at as ISO). Optionally merges caller-supplied `additional` (`:108-109`). Emits **attribute dicts only — no hard `opentelemetry-api` dependency** (docstring `:11-14`, confirmed: no otel import in this file).
- `GAAT_ACTION_TABLE` (`governance_span.py:116-122`) — static `L0_allow→ALLOW … L4_quarantine→QUARANTINE` reference map.

---

## Public API

Exported / imported symbols (verified by `__all__` and grep of call-sites):

**`telemetry.py`** (`__all__` is implicit; live exports):
- `emit_event(event, *, level, logger, message, **fields)` — **the one heavily-used symbol** (~100 import sites).
- `get_logger(name="tex") -> logging.Logger` — used by ~12 sites (often alongside `emit_event`).
- *(Exported but unused in production:* `configure_logging`, `instrument_app`, `TelemetryMiddleware`, `telemetry_snapshot`, `mark_evaluation_recorded`, `mark_outcome_recorded`, `bind_request_id`, `bind_decision_id`, `bind_policy_version`, `bind_telemetry_context`, `get_request_id/decision_id/policy_version`, `JsonLogFormatter`, `TelemetryState`, `TelemetrySnapshot`.*)*

**`metrics.py`** (`__all__` at `:464-471`): `PROMETHEUS_CONTENT_TYPE`, `HttpMetrics`, `MetricsMiddleware`, `build_metrics_router`, `install_metrics`, `render_metrics`. Production caller uses only `install_metrics`.

**`discovery_metrics.py`** (`__all__ = ["DiscoveryMetrics"]`, `:163`): `DiscoveryMetrics`.

**`governance_span.py`**: `verdict_to_otel_attributes`, `GAAT_ACTION_TABLE`, `GAAT_SPAN_SCHEMA_VERSION`. Consumed only by tests.

**`__init__.py`**: `__layer__`, `__layer_kind__`.

---

## Wiring

### Wiring In (who imports this unit)

- `emit_event` — imported by ~100 modules across `c2pa`, `causal`, `compliance`, `contracts`, `drift`, `ecosystem`, `events`, `graph`, `institutional`, `intervention`, `ontology`, `pcas`, `pqcrypto`, `receipts`, `runtime/*`, `specialists/*`, `systemic`, and live API routes (`api/ecosystem_twin_routes.py:66`, `api/incident_routes.py:122`). This is the bulk of the 102 import count.
- `get_logger` — co-imported by ~12 sites (`runtime/agentarmor/*`, `runtime/clawguard/*`, `runtime/mage/*`, `runtime/mcpshield/*`, `runtime/planguard/*`, `specialists/llm_bridge.py:48`, `specialists/llm_dispatch.py:64`).
- `DiscoveryMetrics` — imported by `discovery/scheduler.py:49` and `main.py:740`.
- `install_metrics` — imported by `main.py:1534`.
- `verdict_to_otel_attributes` / `GAAT_ACTION_TABLE` / `GAAT_SPAN_SCHEMA_VERSION` — imported **only** by `tests/ecosystem/test_viability_p3_gaat.py:41-44`.

### Live call path (from `create_app` / `build_runtime`)

**Metrics (`/metrics`) — LIVE:**
`tex.main:create_app` → `metrics.py` import at `main.py:1534` → `install_metrics(app)` at `main.py:1535`. `install_metrics` (`metrics.py:364`) attaches `MetricsMiddleware`, includes `build_metrics_router` (`GET /metrics`), sets `app.state.http_metrics`, and best-effort-starts OTLP. Every HTTP request flows through `MetricsMiddleware.__call__`; `GET /metrics` invokes `render_metrics` (`metrics.py:357-359`).

**DiscoveryMetrics — LIVE:**
`tex.main:build_runtime` constructs `DiscoveryMetrics()` at `main.py:740-741`, passes it to the scheduler at `main.py:817` (`metrics=discovery_metrics`) and into the runtime at `main.py:1207`. `_attach_runtime_to_app` publishes `app.state.discovery_metrics = runtime.discovery_metrics` (`main.py:1651`).
- **Writes:** `discovery/scheduler.py` calls `record_scan_started` (`:270`), `record_snapshot_captured` (`:290`), `record_scan_completed` (`:300`), `record_drift` (`:305`), `record_lock_conflict` (`:336`), `record_scan_failed` (`:347`), `record_alert_dispatched` (`:569`). The scheduler is started at `main.py:1369` (`scheduler.start()` in the lifespan, idempotent no-op without tenants).
- **Reads:** `api/discovery_routes.py:579-582` (`GET /v1/discovery/metrics` → `metrics.snapshot()`) and `metrics.render_metrics._render_discovery` (`metrics.py:296-311`).

**Structured logging (`emit_event` / JSON formatter) — LIVE (lazy):**
Any of the ~100 importers calling `emit_event(...)` → `get_logger()` (`telemetry.py:270`) → `configure_logging()` on first use (`telemetry.py:183-184`) → installs `JsonLogFormatter` on the `tex` logger. Verified at runtime: the resulting logger has a single `JsonLogFormatter` handler. So JSON structured logs ship even though `configure_logging`/`instrument_app` are never explicitly invoked.

**`wired_status` = MIXED.** Metrics endpoint + DiscoveryMetrics + `emit_event`/JSON logging are LIVE. The `telemetry.py` request middleware/context binders/counters and all of `governance_span.py` are NOT reachable from the running app.

### Wiring Out (dependencies of this unit)

- **Internal Tex deps:**
  - `governance_span.py` → `tex.ecosystem.verdict.EcosystemVerdict` (`:41`) — the only intra-Tex import in the unit.
  - `metrics.py` reads (duck-typed, no import) off `app.state`: `discovery_metrics`, `learning_metrics` (→ `tex.learning.observability.MetricsLearningObserver.prometheus_text`), `memory`/`runtime.memory` (`MemoryHealth`), `evidence_recorder`.
- **External libraries:**
  - `fastapi` (`APIRouter`, `FastAPI`, `Request`, `Response`) — `metrics.py:46`.
  - `starlette.types` (ASGI types) — `metrics.py:47`, `telemetry.py:15`.
  - stdlib: `logging`, `json`, `os`, `sys`, `time`, `threading`/`RLock`, `contextvars`, `contextlib`, `dataclasses`, `datetime`, `collections.defaultdict`, `uuid`.
  - **Optional:** `opentelemetry-{api,sdk,exporter-otlp-*}` — imported only inside `_maybe_start_otlp_exporter` (`metrics.py:406-418`), behind the `OTEL_EXPORTER_OTLP_ENDPOINT` gate. Declared in `requirements-otel.txt` (confirmed present), not a hard dep.

---

## Implementation Reality

**REAL, runs by default:**
- `metrics.py` Prometheus exposition — fully real, hand-rendered text, no stubs. Live via `install_metrics`. Defensive surface composition is genuine try/except, not placeholder.
- `HttpMetrics` / `MetricsMiddleware` — real thread-safe counters with bounded label cardinality. Live.
- `DiscoveryMetrics` — real RLock-guarded counters; written by the live scheduler, read by a live route.
- `telemetry.emit_event` + `JsonLogFormatter` + JSON coercion — real and live (lazy formatter install verified at runtime).
- `governance_span.verdict_to_otel_attributes` — real, complete pure function (no stub), but only exercised by a test.

**No stubs in scope:** grep for `NotImplementedError | TODO | FIXME | placeholder | pass`-only bodies returned **NONE** across all four files. There is no hollow-stub crypto/zk/tee here (out of scope for this unit anyway).

**REAL-but-DEAD (present, complete, never invoked in production):**
- `telemetry.TelemetryMiddleware` + `instrument_app` + `TelemetryState`/`_STATE` + counter API (`mark_evaluation_recorded`, `mark_outcome_recorded`, `telemetry_snapshot`, `record_request/evaluation/outcome`) + context-var binders (`bind_*`) — verified **0 references** across `src` and `tests`. Code is fully implemented but unwired. The `_STATE` counters are therefore permanently zero, and `get_request_id/decision_id/policy_version` always return `None` (so the JSON log always omits those context fields).

**OPTIONAL / UNVERIFIED-AT-RUNTIME (self-labelled):**
- `_maybe_start_otlp_exporter` (`metrics.py:387-461`) — real OTLP push implementation, but gated behind `OTEL_EXPORTER_OTLP_ENDPOINT` + optional SDK presence; not installed in the test env, so never exercised by the suite (self-flagged at `:396-399`). This is a genuine-impl-with-graceful-fallback (fail-open) path, not a stub.

---

## Technology / SOTA

- **OpenMetrics / Prometheus text-exposition format v0.0.4** — hand-rendered, no `prometheus_client` dependency (`metrics.py:52`, `:172-228`). Deliberate single-process design (single uvicorn worker → no `PROMETHEUS_MULTIPROC_DIR`), documented as a known limitation if multi-worker (claim in docstring `metrics.py:18-25`, plausible, not independently verified against deploy config).
- **OpenTelemetry OTLP push** — observable gauges/counters via `MeterProvider` + `PeriodicExportingMetricReader`, gRPC-with-HTTP-fallback exporter selection (`metrics.py:411-418`). Optional bridge.
- **GAAT (Governance-Aware Agent Telemetry)** — `governance_span.py` claims compatibility with "arxiv 2604.05119, Apr 6 2026, Apple" and "OpenTelemetry Semantic Conventions v1.32" (docstring `:6-9`, `:33-34`). **(claim, unverified)** — these citations cannot be verified from code; what IS real is the attribute-dict shape and the L0..L4 action table. The cited paper/date is in the future relative to most of the codebase and should be treated as aspirational labelling.
- **Bounded-cardinality metrics** — status bucketed to `1xx..5xx` classes, no per-path labels (`metrics.py:54-67`) — a real anti-cardinality-explosion design pattern.
- **Structured JSON logging** with `contextvars`-based trace correlation (request/decision/policy) — standard ASGI structured-logging pattern, though the propagation half is dead.
- **ASGI middleware** (pure-observation pattern), `__slots__` + `RLock` concurrency primitives throughout.

---

## Persistence

**Entirely in-memory / process-local. No durable storage in this unit.**
- `HttpMetrics`, `DiscoveryMetrics`, `TelemetryState` are all process-local counters guarded by `RLock`; they reset on restart and do not aggregate across workers/replicas (explicit limitations: `telemetry.py:36-43`, `metrics.py:18-25`, `discovery_metrics.py:7-13`).
- The unit *reads* durability signals from elsewhere (`DATABASE_URL` env, `memory.health()`, `evidence_recorder._last_record_hash`) to *report* them in `/metrics`, but stores nothing itself (`metrics.py:231-268`).
- Durable export, if any, is external: Prometheus scrape (pull) or OTLP push to a configured endpoint.

---

## Notable Findings

1. **Most of `telemetry.py` is dead code.** The entire request-scoped telemetry stack — `TelemetryMiddleware`, `instrument_app`, the `_STATE`/`TelemetryState` counter API (`mark_evaluation_recorded`, `mark_outcome_recorded`, `telemetry_snapshot`), and every context-var binder (`bind_request_id/decision_id/policy_version/telemetry_context`) — has **0 references** anywhere in `src` or `tests` (verified by exhaustive grep). Only `emit_event` and `get_logger` are live. The 102-import headline number is real but reflects one function, not the module.

2. **Consequence: request/decision/policy correlation never populates.** `JsonLogFormatter` reads `get_request_id()/get_decision_id()/get_policy_version()` (`telemetry.py:137-139`), but nothing ever sets those context-vars (the only setters are the dead binders / dead middleware). So every structured log line silently drops these fields. The JSON-logging *capability* is live; the *trace-correlation* feature it advertises is not.

3. **`governance_span.py` is test-only (effectively orphan in production).** `verdict_to_otel_attributes` and `GAAT_ACTION_TABLE` are imported solely by `tests/ecosystem/test_viability_p3_gaat.py`. No production code renders verdicts to OTel spans. The `metrics.py` module docstring even references it ("`governance_span` renders OpenTelemetry-compatible span attributes", `metrics.py:8`) but nothing in the live path calls it.

4. **GAAT citation is unverifiable and forward-dated.** `governance_span.py:6-9,33-34` cites "arxiv 2604.05119, Apr 6 2026, Apple". This is a docstring claim with no code consequence and cannot be confirmed; label it **(claim, unverified)**. The functional code (attribute shape, L0..L4 table) is real regardless.

5. **`metrics.py` is the genuine deliverable and is solidly built.** It is fail-open on every composed surface (memory/discovery/learning/evidence all wrapped in try/except → debug log, never a 500 on `/metrics`), bounds label cardinality, and adds no hard dependency. This matches its docstring honesty section (`metrics.py:4-35`) — one of the rare cases where the docstring's self-assessment checks out against the code.

6. **OTLP push is real but unexercised.** `_maybe_start_otlp_exporter` is a complete implementation guarded by env + optional-SDK; self-labelled `UNVERIFIED-AT-RUNTIME` (`metrics.py:396-399`). Not a stub, but no test covers it and the SDK isn't installed by default. Honest labelling.

7. **No `prometheus_client` / `opentelemetry` hard dependency for the verified surface** — the Prometheus text is hand-written (`metrics.py:172-228`), confirming the docstring's "zero new hard dependencies" claim (`metrics.py:13`).

8. **`__init__.py` exports nothing functional** — only the architectural layer marker. All real imports target the submodules directly (`tex.observability.telemetry`, `.metrics`, `.discovery_metrics`, `.governance_span`).

9. **Spine said `observability=LIVE`; refined verdict is MIXED.** Two modules + one function (`emit_event`) are LIVE; `telemetry.py`'s middleware/binders/counters are dead; `governance_span.py` is test-only. The aggregate is correctly "live" at the subsystem-reachability level, but the inside is half dead/unwired — worth flagging for the bible's accuracy.

# Layer 3 — Monitoring / Observability

> **Working doc.** The "is something wrong right now" layer.

## What this layer does

Continuously watches the inventory and the decision stream and surfaces signals: scheduled scans, alerts when something changes, presence tracking (an agent that was there yesterday and isn't today), drift detection, and OpenTelemetry spans for every PDP decision.

This is the layer that turns Tex from "we know what's there" into "we know what's changing."

## Packages in scope

Layer 3 is the most spread-out layer in the codebase. The pieces live across packages because monitoring is inherently cross-cutting on the *write* side (every layer emits signals) but its *concentration* is here:

| Package | Files | Lines | Role |
|---|---|---|---|
| `src/tex/observability/` | 4 | ~771 | Telemetry + discovery metrics |
| `src/tex/discovery/scheduler.py` | 1 | (part of discovery/) | Background scan scheduling |
| `src/tex/discovery/alerts.py` | 1 | (part of discovery/) | Alert emission on inventory change |
| `src/tex/discovery/presence.py` | 1 | (part of discovery/) | Presence state machine |
| `src/tex/learning/drift.py` | 1 | (part of learning/) | Outcome / behavioral drift |

## Key files

### Telemetry
- `src/tex/observability/telemetry.py` — OpenTelemetry-compatible span emission for every PDP decision (start of evaluation → end → finding count → final score → verdict)
- `src/tex/observability/discovery_metrics.py` — Prometheus-style counters/gauges for discovery scans
- `src/tex/observability/governance_span.py` — OTel GAAT span attributes (**TEST_ONLY** — implemented but not invoked)

### Scheduler
- `src/tex/discovery/scheduler.py` — `DiscoveryScheduler` class. Runs on FastAPI lifespan. Reads `TEX_DISCOVERY_SCAN_TENANTS` env var (comma-separated tenant IDs) and scans each on a cycle.

### Alerts
- `src/tex/discovery/alerts.py` — emits structured alerts when an agent appears, disappears, or changes capabilities
- `src/tex/api/connector_health_routes.py` — health endpoints

### Presence
- `src/tex/discovery/presence.py` — three-state machine (CONFIRMED_PRESENT → SOFT_DISAPPEARED → CONFIRMED_MISSING). Threshold tunable via `TEX_DISCOVERY_PRESENCE_THRESHOLD`.

### Drift
- `src/tex/learning/drift.py` — drift detection over outcome/decision streams. Wired into `/v1/agents/drift/{kind}` route.

### HTTP
- `GET /v1/agents/scheduler/status` + `/run` + `/start` + `/stop`
- `GET /v1/agents/drift/{kind}`
- `GET /v1/discovery/connectors/health`
- `GET /v1/learning/metrics` + `/metrics/prometheus` + `/alerts` + `/health`
- `GET /health`

## Current state

✅ Solid:
- Scheduler runs on FastAPI lifespan
- Alerts emit on every inventory delta
- Presence tracking with configurable soft-disappearance threshold
- Drift detection wired through learning/
- OpenTelemetry spans on every PDP decision
- Prometheus-compatible metrics endpoint

⚠ Watch:
- `observability/governance_span.py` is TEST_ONLY — implemented but not actually emitted at runtime. Wiring it into `ecosystem/engine.py` is the upgrade.
- No alerting destination integration (PagerDuty, Slack, OpsGenie, webhook). Alerts are stored, not pushed.
- No SLO/SLA tracking. Could compute "% of decisions returning verdict within 50ms" and surface as a metric.

## Improvement vectors

### 1. Push-based alert destinations (high impact, low effort)
Today alerts are stored in the ledger and visible at `/v1/learning/alerts`. Adding webhook/Slack/PagerDuty push would make Layer 3 actionable. Pattern: configurable destination per tenant, fan-out on alert emission.

### 2. Wire `governance_span.py` (medium impact, low effort)
122 lines of OpenTelemetry GAAT span attributes that aren't emitted. Hook into `ecosystem/engine.py` after each of the 8 steps to emit a typed span. Gives downstream OTel consumers full visibility into ecosystem-engine behavior.

### 3. SLO tracking (medium impact, medium effort)
Compute and surface:
- p50/p95/p99 latency per stream
- Verdict distribution drift (rolling 24h)
- Specialist confidence distribution (a specialist whose confidence collapses over time signals model rot)
- Per-agent decision-rate drift

### 4. Real-time anomaly detection (high impact, high effort)
The `drift/` package has the machinery (CUSUM, isolation forest, conformal bands). Currently only "outcome drift" and "behavioral drift" are wired into the agent governance endpoint. Wiring it into the decision stream for predictive anomaly alerts is the next step.

### 5. Cross-tenant pattern detection
A coordinated attack hitting multiple tenants in parallel is invisible per-tenant but obvious across tenants. With strict tenant isolation guarantees this is delicate, but feasible if done as aggregated counts (no per-tenant data leakage).

## Constraints

- Telemetry must never block the decision path. Span emission is fire-and-forget; failure to emit must never short-circuit a PDP evaluation.
- Alerts must be hash-chained into the discovery ledger so that an alert with no corresponding evidence is impossible.
- Scheduler runs MUST be per-tenant. Never read or scan across tenant boundaries.
- All metrics must be tenant-scoped. Global counters across tenants are forbidden in production routes (development only).

## Testing

```bash
pytest tests/test_scheduler.py tests/test_presence.py tests/test_drift_events.py tests/test_connector_health.py tests/test_latency_and_drift.py tests/test_alert_engine.py
```

## Cross-layer touch points

- **Reads from Layer 1** — inventory deltas drive alerts
- **Reads from Layer 4** — decision stream drives telemetry, drift, anomaly detection
- **Reads from Layer 6** — outcome stream drives drift
- **Writes to Layer 5** — alerts and metrics are part of the evidence record

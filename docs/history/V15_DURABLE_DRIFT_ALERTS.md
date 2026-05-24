# V15 — Durable Discovery, Drift Detection, Real-Time Alerts

## What changed

V14 left discovery as a powerful but **passive** layer:
- in-memory only — discovery state evaporated on restart
- operator-triggered scans only — no continuous monitoring
- governance was a snapshot of "right now" with no history
- evidence export was a hash + signature, not a regulator artifact
- no notifications — drift was silent unless someone happened to look

V15 closes those five gaps. Discovery is now **durable**, **continuous**,
**hash-chained**, **regulator-shaped**, and **alarmed** in real time.

## What shipped

### 1. Forensic infrastructure (Postgres write-through)

Two new stores match the existing in-memory APIs exactly — every
caller in the runtime keeps working:

- `tex/stores/agent_registry_postgres.py` — `PostgresAgentRegistry`
- `tex/stores/discovery_ledger_postgres.py` — `PostgresDiscoveryLedger`

Both follow the same pattern:

```
reads   → in-memory (microseconds, no I/O)
writes  → in-memory THEN synchronous Postgres flush (one round trip)
startup → bootstrap from Postgres into in-memory
```

The choice to keep the API synchronous is deliberate. The PDP, the
agent suite, the evaluate-action command, the evidence recorder are
all sync. Converting them to async to satisfy a discovery-layer
durability requirement would have been a multi-week refactor with
high blast radius. Instead the registry/ledger run a synchronous
Postgres flush behind the existing API. Reads — which happen on
every evaluation — never touch Postgres.

**Audit fields on every revision row** (the part that turns "storage"
into forensic infrastructure):
- `record_hash` + `previous_hash` — per-agent hash chain
- `payload_sha256` — content hash for tamper detection
- `policy_version` — which policy was active when the write happened
- `snapshot_id` — which governance snapshot this correlates to
- `write_source` — `evaluate_action`, `discovery_scan`, `manual`, etc.

Hash chain is per-agent. Each revision links to the previous
revision's `record_hash` for that `agent_id`. `verify_agent_chain()`
replays the agent's history and recomputes the hashes; tampering
breaks the chain.

The chain head is restored from Postgres on startup so it continues
correctly across restarts.

**Audit context API:**

```python
registry.set_audit_context(
    policy_version="v9.2.1",
    snapshot_id=snapshot_id,
    write_source="evaluate_action",
)
# every save() that follows is stamped with these fields
```

Wired into `EvaluateActionCommand.execute()` in a try/finally — every
save during adjudication carries policy_version provenance, and the
context clears at the end of the command.

### 2. Drift-detection scheduler

`tex/discovery/scheduler.py` — `BackgroundScanScheduler` runs on a
daemon thread, scans every configured tenant on a configurable
interval, and **diffs** scan N+1 against scan N to emit:

- `NEW_AGENT` — first time we observed this reconciliation_key
- `AGENT_CHANGED` — surface drift, lifecycle change, risk band change
- `AGENT_DISAPPEARED` — present last scan, gone this one

Only `AGENT_DISAPPEARED` requires the scheduler — the discovery
service itself is candidate-driven, so an agent that stops appearing
in connector results is invisible to it. The scheduler's diff layer
catches that.

Capability widening is detected by comparing the prior scan's
`(tools, channels, data_scopes, surface_unbounded)` against the
current scan's. If the current scan has any tools or scopes the prior
scan did not, the change is tagged `capability_widened`.

`trigger_now()` runs one cycle synchronously for tests and admin use.

### 3. Drift event store

`tex/stores/drift_events.py` — `DriftEventStore` is an append-only
log with the same write-through-Postgres pattern. Bounded ring
buffer in memory (`cache_limit=1000` default), full history in
Postgres. Indexed by tenant_id, kind, and reconciliation_key for
fast filtering.

### 4. Hash-chained governance snapshots

`tex/stores/governance_snapshots.py` — `GovernanceSnapshotStore`
captures the full governance response (counts + per-agent matrix +
coverage_root + signature) and adds:

- `snapshot_hash` — SHA-256 over the canonical snapshot payload
- `previous_snapshot_hash` — chain field
- `governed_pct` / `ungoverned_pct` — derived ratios
- `critical_ungoverned` — pre-extracted slice for fast UI access

Each capture chains to the previous capture, forming a verifiable
governance history. `verify_chain()` walks oldest → newest, recomputes
each `snapshot_hash`, and confirms the chain is unbroken. Returns
`{"intact": bool, "checked": int, "break_at_index": int | null}`.

### 5. Regulator-grade evidence bundle

`store.export_evidence_bundle()` upgraded to produce a self-contained
bundle suitable for regulator handoff:

```
{
  "schema_version": "tex.governance.evidence/1",
  "snapshot": { snapshot_id, captured_at, label, snapshot_hash, previous_snapshot_hash },
  "counts": { total, governed, ungoverned, partial, unknown, ... pcts },
  "critical_ungoverned": [ ... ],
  "coverage_root_sha256": "...",
  "signature_hmac_sha256": "...",
  "governance_response": { full agent matrix },
  "drift_events": [ ... events tied to this window ],
  "discovery_ledger_root": "...",
  "registry_chain_proof": { agent_id: { revisions, chain_intact } },
  "policy_versions_present": [ "v1.0", "v1.1", ... ],
  "manifest": {
    "bundle_sha256": "...",
    "manifest_signature_hmac_sha256": "...",
    "signed_at": "..."
  }
}
```

The manifest signature is HMAC-SHA256 over the bundle hash using
`TEX_EVIDENCE_SUMMARY_SECRET`. A regulator can verify both:
1. **Integrity** — re-derive `bundle_sha256` from the JSON, confirm match.
2. **Provenance** — verify the HMAC signature against Tex's public key.

### 6. Real-time alert engine

`tex/discovery/alerts.py` — `AlertEngine` subscribes to drift events
and dispatches matching alerts to one or more sinks:

- `LogSink` — always on; logs at WARNING with structured JSON
- `WebhookSink` — when `TEX_ALERT_WEBHOOK_URL` is set
- `SlackSink` — when `TEX_ALERT_SLACK_WEBHOOK_URL` is set

Three default rules:

| Rule | Severity | Fires when |
|------|----------|------------|
| `ungoverned_high_risk_appeared` | CRITICAL | `NEW_AGENT` + `risk_band` ∈ {HIGH, CRITICAL} + not auto-registered |
| `agent_disappeared` | WARN | `AGENT_DISAPPEARED` (any agent) |
| `capability_surface_widened` | WARN | `AGENT_CHANGED` + `change_kind == capability_widened` |

Sink dispatch fires on a daemon worker thread — a slow webhook
cannot stall the alert loop or the next scan cycle. A failing sink
does not block the others.

**Design constraint:** this is a detection engine, not a response
engine. It tells you what changed. It does not auto-quarantine,
auto-revoke, or auto-mitigate. Those decisions belong to operators
(or to the policy layer, which already has its own gates). Conflating
detection with response is what turns a useful tool into one that
nobody trusts to enable in production.

## New HTTP endpoints

```
POST /v1/agents/governance/snapshot                                    capture a snapshot now
GET  /v1/agents/governance/snapshots                                   list recent snapshots
GET  /v1/agents/governance/snapshots/{id}                              fetch one
GET  /v1/agents/governance/snapshots/{id}/evidence_bundle              regulator export
GET  /v1/agents/governance/chain/verify                                verify the snapshot chain

GET  /v1/discovery/drift                                               recent drift events
GET  /v1/discovery/drift/{kind}                                        filter by NEW_AGENT | AGENT_CHANGED | AGENT_DISAPPEARED

GET  /v1/discovery/scheduler/status                                    scheduler health + last-run summary
POST /v1/discovery/scheduler/run                                       trigger one cycle synchronously
POST /v1/discovery/scheduler/start                                     start (idempotent)
POST /v1/discovery/scheduler/stop                                      stop
```

## Environment variables (cumulative for V13–V15)

```
DATABASE_URL                              Postgres connection
TEX_EVIDENCE_SUMMARY_SECRET               HMAC signing secret
TEX_DISCOVERY_OPENAI_API_KEY              live OpenAI Assistants connector
TEX_DISCOVERY_OPENAI_ORG                  optional
TEX_DISCOVERY_OPENAI_PROJECT              optional
TEX_DISCOVERY_SLACK_TOKEN                 live Slack connector
TEX_DISCOVERY_SLACK_TEAM_ID               optional

# V15
TEX_DISCOVERY_SCAN_INTERVAL_SECONDS       scheduler interval (default 3600, min 30)
TEX_DISCOVERY_SCAN_TENANTS                comma-separated tenant list (empty = scheduler off)
TEX_DISCOVERY_SCAN_TIMEOUT_SECONDS        per-scan timeout (default 60)
TEX_ALERTS_DISABLED                       1 to disable alerting entirely
TEX_ALERT_WEBHOOK_URL                     generic JSON webhook sink
TEX_ALERT_SLACK_WEBHOOK_URL               Slack incoming webhook sink

TEX_DB_POOL_MIN                           asyncpg pool min (default 2)
TEX_DB_POOL_MAX                           asyncpg pool max (default 20)
```

## Failure modes

| Condition | Behavior |
|-----------|----------|
| `DATABASE_URL` not set | Stores degrade to pure in-memory. Logs a warning. App stays up. |
| Postgres unreachable mid-write | Write succeeds in memory, logs error, queues for replay via `replay_pending()`. Reads stay correct. |
| Schema missing on first connection | `ensure_schema()` runs `CREATE TABLE IF NOT EXISTS` + `ADD COLUMN IF NOT EXISTS`. Idempotent and safe. |
| Discovery ledger chain broken on bootstrap | Logs an error at ERROR level. Operator gets a structured signal that tampering is suspected. App stays up. |
| Scan fails on one tenant | Logged. Other tenants still scan. Scheduler keeps running. |
| Webhook sink slow / down | Worker thread absorbs the delay. Other sinks unaffected. Next cycle unaffected. |
| Scheduler interval below 30s | Clamped to 30s. (Don't hammer external APIs.) |

## What's still in-memory only

- `action_ledger` — adjudication outcomes are still in-process. Postgres
  durability for the action ledger is a V16 candidate but was out of
  scope here; the registry + discovery ledger were the priority because
  they're the source of truth for who-is-an-agent.
- `decision_store`, `outcome_store`, `precedent_store`, `entity_store`,
  `policy_store` — adjudication-side stores. Same reasoning.
- `tenant_baseline` — derived state, can be rebuilt from action_ledger.

## What's still TODO post-V15

- UI for the governance matrix (the API surface is now ready for it)
- Postgres for action_ledger so adjudication history survives restarts
- Per-tenant alert rule overrides (current rules are global)
- Webhook receipt verification (currently fire-and-forget)

## Test counts

V14 baseline: 470
V15 added:    78
**Total:      548**

V15 test suites:
- `test_postgres_registry.py` — 12 (hash chain, audit context)
- `test_postgres_discovery_ledger.py` — 5 (fallback, chain integrity)
- `test_governance_snapshots.py` — 16 (capture, chain, evidence bundle)
- `test_drift_events.py` — 9 (emit, filter, ring buffer)
- `test_alert_engine.py` — 14 (rules, sinks, resilience)
- `test_scheduler.py` — 8 (lifecycle, drift detection, alerting)
- `test_governance_history_routes.py` — 14 (HTTP)

All run against the in-memory fallback. The Postgres path is exercised
at deploy time on Render.

## Pitch line update

V14: *"Other platforms tell you what agents exist. Tex tells you which of those agents are actually under governance — and proves it."*

V15: *"Other platforms tell you what agents exist. Tex tells you which of those agents are actually under governance, what changed since yesterday, alerts you when a high-risk one slips out of control, and hands a regulator a signed bundle proving every word of it."*

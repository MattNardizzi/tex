# Layer 1 — Discovery / Inventory

> **Working doc.** If you're a Claude instance working on Layer 1, this is what you need.
> Read `LAYERS.md` and `ARCHITECTURE.md` first if you haven't.

## What this layer does

Scans customer platforms to inventory every AI agent that exists across their environment. Produces durable findings in a discovery ledger. Reconciles findings across multiple scans. Tracks presence over time (CONFIRMED_PRESENT → SOFT_DISAPPEARED → CONFIRMED_MISSING).

This is the **first thing a customer experiences** — Tex can't govern agents it doesn't know about.

## Packages in scope

| Package | Files | Lines | Status |
|---|---|---|---|
| `src/tex/discovery/` | 17 | ~4,620 | WIRED |

Plus the discovery HTTP surface in `src/tex/api/discovery_routes.py` (cross-cutting).

## Key files

### Entry points
- `src/tex/discovery/service.py` — the orchestrator. Receives a scan request, dispatches to connectors, reconciles results, writes the ledger.
- `src/tex/discovery/scheduler.py` — background scheduler that runs scans on a cycle.
- `src/tex/discovery/reconciliation.py` — merges findings across scans.
- `src/tex/discovery/presence.py` — presence tracking (the three states above).
- `src/tex/discovery/alerts.py` — alert emission when something changes.

### Connectors (the per-platform code)
| Connector | File | Live or Mock |
|---|---|---|
| OpenAI Assistants | `connectors/openai_live.py` (`OpenAIConnector`) | **LIVE** when `TEX_DISCOVERY_OPENAI_API_KEY` set |
| OpenAI Assistants (mock) | `connectors/openai_assistants.py` (`OpenAIAssistantsLiveConnector` — name is misleading, it's a mock) | Mock |
| Slack | `connectors/slack_live.py` | **LIVE** when `TEX_DISCOVERY_SLACK_TOKEN` set |
| AWS Bedrock | `connectors/aws_bedrock.py` | Mock |
| GitHub | `connectors/github.py` | Mock |
| Microsoft Graph | `connectors/microsoft_graph.py` | Mock |
| Salesforce | `connectors/salesforce.py` | Mock |
| MCP servers | `connectors/mcp_servers.py` | Mock |

### Storage
- `src/tex/stores/discovery_ledger.py` (InMemory) and `discovery_ledger_postgres.py` (Postgres) — durable storage of findings.

### Domain models
- `src/tex/domain/discovery.py` — `DiscoveryFinding`, `ConnectorHealth`, `ScanRun`, presence states.

### HTTP
All discovery endpoints in `src/tex/api/discovery_routes.py`. Examples:
- `POST /v1/discovery/scan`
- `GET /v1/discovery/connectors` + `/health`
- `GET /v1/discovery/ledger` + `/verify`
- `GET /v1/discovery/scan_runs` + `/{run_id}`
- `GET /v1/discovery/findings/{key}`
- `GET /v1/discovery/agent/{id}`
- `GET /v1/discovery/metrics`

## Current state

✅ Solid:
- 8 connector types implemented
- 2 live (OpenAI + Slack); 6 mock
- Reconciliation across scans (handles agent ID changes, name changes, capability changes)
- Presence tracking with soft-disappearance threshold (`TEX_DISCOVERY_PRESENCE_THRESHOLD`, default 3)
- Scheduler for periodic background scans (`TEX_DISCOVERY_SCAN_TENANTS`)
- Discovery ledger durability (in-memory + Postgres)
- Per-tenant baselines

⚠ Watch:
- The mock vs live connector naming is inverted (`OpenAIAssistantsLiveConnector` is the mock, `OpenAIConnector` is live). See `audit/contradictions/CONTRADICTIONS.md` §13.
- 6 of 8 connectors are mock — go-live cost is implementing the real API calls for AWS, GitHub, Microsoft, Salesforce, MCP.

## Improvement vectors (where to push to be state-of-the-art)

### 1. More live connectors (high impact, high effort)
Implement live versions of the 6 mock connectors. Priority order based on customer demand:
- **AWS Bedrock** — large enterprise base. Use `boto3.client('bedrock-agent')`.
- **GitHub** — agent code lives here; use GitHub Apps API.
- **Microsoft Graph** — Copilot Studio / Power Platform agents.
- **Salesforce** — Einstein agents.
- **MCP servers** — list of registered MCP servers at a customer; arguably the most differentiated.

### 2. Real-time discovery (medium impact, medium effort)
Today scheduler-driven. Push toward webhook-driven for platforms that support it (Slack events API, GitHub webhooks, Salesforce platform events). Cuts mean-time-to-discovery from minutes to seconds.

### 3. Cross-platform agent identity (high impact, high effort)
When the same logical agent appears in OpenAI Assistants + GitHub + Slack, currently treated as three findings. A reconciliation upgrade that joins them on identity (DID, signed agent card per A2A v1.2) would be a real moat. Tied to `_pending/interop/a2a/`.

### 4. Discovery for emerging frameworks
LangGraph, AutoGen, CrewAI, Letta, Inworld. Many customers run these; today not discovered.

### 5. Anomaly detection in inventory deltas
A new agent appearing with unusual capabilities, an old agent suddenly gaining sensitive scopes — fire a Layer 3 alert.

## Constraints

- All connectors must implement `BaseConnector` protocol (see `src/tex/discovery/base.py` if it exists, otherwise pattern from `openai_live.py`).
- Every finding must be hash-chained into the discovery ledger; do not write a finding that bypasses the ledger.
- Never log API tokens or secrets retrieved from customer platforms — pass through to the secret manager, not to logs.
- Tenant isolation is mandatory: a scan for tenant A must never read or return data from tenant B.

## Testing

Tests live in `tests/test_discovery_*.py` (15 files) and `tests/test_postgres_discovery_ledger.py`. Run with:

```bash
pytest tests/test_discovery_*.py
```

`test_live_connectors_harness.py` runs the live connectors against real credentials when present (skip-by-default in CI).

## Cross-layer touch points

- **Writes to Layer 2** — discovery findings populate `agent_registry` so the agent_evaluator can find them.
- **Writes to Layer 3** — emits alerts on agent appearance/disappearance.
- **Writes to Layer 5** — every finding is also recorded in the discovery ledger which is part of the broader evidence story.

When changing Layer 1, double-check those touch points don't regress.

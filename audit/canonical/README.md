# Tex

AI agent governance and evidence platform. Decides whether agent actions should `PERMIT` / `ABSTAIN` / `FORBID` and records every decision into a hash-chained audit log.

## What it is

A FastAPI service (`src/tex/main.py`) exposing 22 routers (~80 HTTP endpoints). The core capability is the Policy Decision Point (`src/tex/engine/pdp.py`) which runs each request through eight named stages:

```
deterministic_recognizers
  → policy_retrieval
  → agent_governance_streams   (identity + capability + behavioral)
  → specialist_judges          (17 specialists)
  → semantic_judge             (LLM with deterministic fallback)
  → behavioral_contracts       (LTLf temporal logic)
  → routing                    (weighted fusion of all signals)
  → decision_materialization   (persist Decision + write evidence record)
```

Hard contract violations short-circuit to `FORBID` before routing. Soft violations feed the router as findings with an uncertainty flag.

## The six architectural layers

| Layer | Code home |
|---|---|
| 1. Discovery | `src/tex/discovery/` |
| 2. Identity | `src/tex/agent/` + `stores/agent_registry*.py` + `api/agent_routes.py` |
| 3. Monitoring | `discovery/scheduler.py` + `discovery/alerts.py` + `discovery/presence.py` + `learning/drift.py` + `observability/telemetry.py` |
| 4. Execution Governance | `engine/` + `specialists/` (the active path); `governance/path_policy`, `governance/kernel_mcp`, `governance/stpa_specs` exist with tests but are not wired into the runtime |
| 5. Evidence | `evidence/` + `memory/` + `c2pa/` + `vet/` (Web Proof integration glue is test-only) + `zkprov/` + `tee/` |
| 6. Learning | `learning/` |

## Running locally

```bash
pip install -e ".[dev]"
uvicorn tex.main:app --reload --port 8000

# Smoke tests
python scripts/smoke_e2e.py
python scripts/smoke_guardrail.py
```

### Environment

Dev:
```bash
TEX_APP_ENV=development
TEX_DEBUG=1
```

Production:
```bash
TEX_APP_ENV=production
TEX_EVIDENCE_SUMMARY_SECRET=$(python -c 'import secrets; print(secrets.token_urlsafe(32))')
TEX_TEE_ATTESTATION_MODE=production
TEX_REQUIRE_AUTH=1
DATABASE_URL=postgres://...                  # optional; runtime falls back to in-memory

# Optional LLM judge
TEX_SEMANTIC_PROVIDER=openai
OPENAI_API_KEY=sk-...
TEX_SEMANTIC_MODEL=gpt-5-mini
TEX_SEMANTIC_REASONING_EFFORT=minimal

# Optional live discovery connectors (mock by default)
TEX_DISCOVERY_OPENAI_API_KEY=...
TEX_DISCOVERY_SLACK_TOKEN=...
```

`config.py` enforces fail-closed guards: in production-like envs (`TEX_APP_ENV` outside the dev/test allowlist), it refuses to boot if `TEX_EVIDENCE_SUMMARY_SECRET` is missing/sentinel or if `TEX_TEE_ATTESTATION_MODE=test`.

## HTTP endpoints

All endpoint paths are registered in `src/tex/main.py` lines 1168–1221.

### Core evaluation
- `POST /v1/evaluate`
- `GET /v1/decisions/{id}/replay`
- `GET /v1/decisions/{id}/evidence-bundle`
- `POST /v1/outcomes`
- `POST /v1/policies/{version}/activate`
- `POST /v1/policies/calibrate`
- `POST /v1/evidence/export`
- `GET /v1/policies/{version}/drift`

### Gateway integration
- `POST /v1/guardrail` — canonical webhook
- `POST /v1/guardrail/{format}` — format dispatcher
- `GET /v1/guardrail/formats`
- `POST /v1/guardrail/async` + `GET /v1/guardrail/async/{decision_id}`
- `POST /v1/guardrail/stream` (SSE) + `POST /v1/guardrail/stream/chunk`
- `POST /v1/guardrail/adapters/{portkey|litellm|cloudflare|solo|truefoundry|bedrock|copilot-studio|agentkit}`
- `POST /mcp` (JSON-RPC MCP server)

### Discovery
- `POST /v1/discovery/scan`
- `GET /v1/discovery/connectors` + `/v1/discovery/connectors/health`
- `GET /v1/discovery/ledger` + `/v1/discovery/ledger/verify`
- `GET /v1/discovery/scan_runs` + `/v1/discovery/scan_runs/{run_id}`
- `GET /v1/discovery/findings/{reconciliation_key:path}`
- `GET /v1/discovery/agent/{agent_id}`
- `GET /v1/discovery/metrics`

### Agent governance
- `GET/POST /v1/agents` + `GET/PATCH /v1/agents/{id}`
- `POST /v1/agents/{id}/lifecycle`
- `GET /v1/agents/{id}/evidence_summary` + `/history` + `/ledger` + `/baseline`
- `GET /v1/agents/governance`
- `GET /v1/agents/systemic-risks`

### Snapshots / drift / scheduler
- `POST /v1/agents/governance/snapshot`
- `GET /v1/agents/governance/snapshots` + `/{id}` + `/{id}/evidence_bundle[.zip]`
- `GET /v1/agents/governance/chain/verify`
- `GET /v1/agents/drift/{kind}`
- `GET/POST /v1/agents/scheduler/{status|run|start|stop}`

### Learning
- `POST /v1/learning/proposals` + `/approve` + `/reject` + `/rollback` + `/audit`
- `GET /v1/learning/proposals` + `/{id}`
- `GET /v1/learning/reputation` + `/{reporter}`
- `GET /v1/learning/metrics` + `/metrics/prometheus` + `/alerts` + `/health`

### Evidence-grade
- `GET /v1/evidence/{record_id}/c2pa`
- `POST /v1/c2pa/verify`
- `POST /v1/tee/verify` + `GET /v1/tee/status`
- `POST /v1/vet/{issue-aid|verify-aid|present-aid|verify-presentation|notarize|verify-web-proof|issue-txn-token|verify-txn-token}`
- `POST /v1/vet/scitt/{register-decision|verify-transparent|arp-reconcile}` + `GET /v1/vet/scitt/{receipt/{id}|ts-status}`
- `POST /v1/zkprov/{issue-commitment|prove|verify|aggregate|narrow}` + `GET /v1/zkprov/{proof/{hash}|health}`

### Exports
- `POST /v1/exports/{vp-marketing|ciso|insurer}`

### Other
- `POST /v1/incidents/{decision_id}/attribute`
- `POST /v1/ecosystem/twin/simulate`
- `GET /v1/system/state`
- `GET /v1/tenants/{tenant_id}/baseline`
- `GET /leaderboard` + `POST /leaderboard/submit`
- `GET /arcade/leaderboard` + `POST /arcade/leaderboard/submit`
- `GET /health`

## Project layout

```
tex/
├── src/tex/          # all runtime code — 462 .py files, ~211k lines
├── tests/            # 219 test files, ~67.9k lines
├── scripts/          # demos + smoke tests + audit navigator
├── sdks/python/      # tex-guardrail Python SDK
├── cpsa_models/      # CPSA formal-methods model of evidence cosign protocol
├── vendor/mithril/   # vendored Rust threshold-signature library
├── audit/            # full audit (canonical/, contradictions/, orphans/)
├── ARCHITECTURE.md
├── README.md
└── pyproject.toml
```

## Audit

See `audit/EXECUTIVE_SUMMARY.md` for the headline numbers and `audit/orphans/ORPHAN_REGISTRY.md` for the file-by-file truth-from-code analysis of which files are wired, tested-only, or fully unreferenced.

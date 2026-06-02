# Tex — Canonical Architecture

> All claims in this document are verified from the source code by `grep` and AST parsing.
> No claims from any prior documentation file were used as input.
> Generated: 2026-05-27

---

## What Tex is

A FastAPI service that decides whether AI-agent actions should `PERMIT` / `ABSTAIN` / `FORBID`, records every decision into a cryptographically chained evidence log, and exposes 22 routers (~80 HTTP endpoints) covering the full lifecycle.

**Composition root:** `src/tex/main.py` builds a `TexRuntime` (a frozen dataclass holding every constructed singleton) and registers all routers with the FastAPI app.

## The PDP evaluation pipeline (the engine)

`src/tex/engine/pdp.py` runs each `EvaluationRequest` through the following sequence. The names below come directly from the `evaluation_order` list in `pdp.py` (lines 602-611):

1. `deterministic_recognizers` — regex/rule pre-gate (`deterministic/gate.py`)
2. `policy_retrieval` — RAG grounding (`retrieval/orchestrator.py`)
3. `agent_governance_streams` — three sub-streams: identity, capability, behavioral (`agent/`)
4. `specialist_judges` — 17 specialist judges (`specialists/judges.py`)
5. `semantic_judge` — LLM judge with deterministic fallback (`semantic/analyzer.py`)
6. `behavioral_contracts` — LTLf temporal-logic contracts (`contracts/` via `engine/contract_bridge.py`)
7. `routing` — weighted fusion of all signals (`engine/router.py`)
8. `decision_materialization` — materialize and persist the `Decision`

`pdp.py:719` describes the agent layer as the "**seven-stream contract**": identity + capability + behavioral are three streams that join the four content streams (deterministic, retrieval, specialists, semantic). When fused, that's seven signal streams plus policy criticality.

Behavioral-contract hard violations short-circuit to `FORBID` before routing. Soft violations are passed to the router as findings with an uncertainty flag.

## The six architectural layers

Independent of the PDP pipeline (which is about *how* one decision is computed), the system has six architectural layers:

| # | Layer | Code home |
|---|---|---|
| 1 | **Discovery / Inventory** | `src/tex/discovery/` |
| 2 | **Identity / Access** | `src/tex/agent/`, `stores/agent_registry*.py`, `api/agent_routes.py` |
| 3 | **Monitoring / Observability** | `discovery/scheduler.py`, `discovery/alerts.py`, `discovery/presence.py`, `learning/drift.py`, `observability/telemetry.py` |
| 4 | **Execution Governance** | `engine/`, `specialists/` (core wired); `governance/path_policy`, `governance/kernel_mcp`, `governance/stpa_specs` (tested, not invoked at runtime) |
| 5 | **Evidence** | `evidence/`, `memory/`, `c2pa/`, `vet/` (integration glue is test-only), `zkprov/`, `tee/` |
| 6 | **Learning** | `learning/` |

## The ecosystem engine (Thread 7)

`src/tex/ecosystem/engine.py` runs an eight-step pipeline that wraps the PDP. Per the docstring (lines 8-16):

1. ontology check
2. graph projection
3. contract check (P1 stub)
4. governance graph LTS (P1 stub)
5. causal attribution (P1 stub)
6. drift detection (P1 stub)
7. systemic risk (P2 stub)
8. intervention select (P2 stub)

The engine and bridge are wired into `commands/evaluate_action.py`. Steps 1 and 2 fire. Steps 3-8 reference their respective packages (`contracts/`, `institutional/`, `causal/`, `drift/`, `systemic/`, `intervention/`) — the integration is wired, but the deep stubs in those packages are gated as P1/P2 work.

## Package map

| Package | Files | Lines | Verdict |
|---|---|---|---|
| `api/` | 25 | 13,367 | WIRED — 22 routers |
| `specialists/` | 24 | 9,754 | WIRED — 17 judges plus shared infrastructure |
| `stores/` | 20 | 6,955 | WIRED |
| `c2pa/` | 17 | 6,113 | WIRED |
| `nanozk/` | 13 | 6,026 | WIRED |
| `governance/` | 20 | 5,506 | Mixed: `private_data_exec/ifc` WIRED; `path_policy`, `kernel_mcp`, `stpa_specs` TEST_ONLY |
| `pqcrypto/` | 17 | 4,896 | Mixed: `algorithm_agility` WIRED with lazy dispatch; 6 modules TEST_AND_SCRIPT_ONLY |
| `vet/` | 11 | 5,370 | Mixed: 8 modules WIRED via routes; `integration.py` and `sd_jwt_vc.py` TEST_ONLY |
| `causal/` | 13 | 5,218 | WIRED via `api/incident_routes.py` and `ecosystem/engine.py` |
| `domain/` | 21 | 5,081 | WIRED — pure model layer (~236 import sites) |
| `learning/` | 13 | 4,688 | WIRED |
| `discovery/` | 17 | 4,620 | WIRED |
| `zkprov/` | 10 | 4,259 | WIRED |
| `evidence/` | 11 | 4,058 | WIRED |
| `runtime/` | 17 | 3,452 | WIRED via 5 specialists |
| `systemic/` | 9 | 3,152 | WIRED via ecosystem engine + twin route |
| `memory/` | 10 | 3,049 | WIRED |
| `institutional/` | 8 | 2,869 | WIRED via ecosystem engine |
| `drift/` | 7 | 2,734 | WIRED via ecosystem engine |
| `tee/` | 6 | 2,690 | WIRED |
| `pcas/` | 13 | 2,656 | WIRED via `specialists/pcas_specialist.py` |
| `intervention/` | 7 | 2,450 | WIRED via ecosystem engine |
| `ecosystem/` | 8 | 2,432 | WIRED |
| `contracts/` | 6 | 2,390 | WIRED via `engine/contract_bridge.py` |
| `engine/` | 4 | 2,369 | WIRED — the PDP |
| `semantic/` | 6 | 2,081 | WIRED |
| `compliance/` | 20 | 1,952 | TEST_ONLY at runtime (tested in `tests/frontier/`, never invoked by main.py) |
| `commands/` | 6 | 1,714 | WIRED |
| `enforcement/` | 7 | 1,691 | TEST_ONLY (never invoked by main.py) |
| `pitch/` | 7 | 1,440 | WIRED |
| `deterministic/` | 3 | 1,258 | WIRED |
| `ontology/` | 8 | 1,206 | Mixed: 3 entries WIRED; 4 sub-ontologies TEST_ONLY |
| `graph/` | 8 | 1,178 | Mixed: in-memory WIRED; rustworkx/postgres/janusgraph backends TEST_ONLY or FULL_ORPHAN |
| `camel/` | 7 | 1,005 | WIRED via `specialists/camel_specialist.py` |
| `events/` | 8 | 957 | Mixed: mostly WIRED; `quorum_shard.py` FULL_ORPHAN |
| `adversarial/` | 3 | 947 | TEST_AND_SCRIPT_ONLY (fuzz harness — correct state) |
| `safeflow/` | 5 | 892 | TEST_ONLY |
| `observability/` | 4 | 759 | Mixed: 2 WIRED; `governance_span.py` TEST_ONLY |
| `bench/` | 5 | 736 | TEST_ONLY (benchmark harness — correct state) |
| `db/` | 4 | 629 | WIRED |
| `receipts/` | 5 | 697 | WIRED via `pitch/insurer_export.py` |
| `policies/` | 2 | 361 | WIRED |
| `retrieval/` | 2 | 224 | WIRED |
| `proofs/` | 1 | 27 | FULL_ORPHAN (empty placeholder) |
| `_pending/` | 13 | 229 | FULL_ORPHAN (intentional parked stubs) |

## Configuration

### Required for production startup

| Variable | Purpose |
|---|---|
| `TEX_APP_ENV` | Any value outside `{dev, development, test, testing, local}` triggers fail-closed guards in `config.py` |
| `TEX_EVIDENCE_SUMMARY_SECRET` | HMAC-SHA256 key for evidence signing. Boot refuses if missing or equal to the sentinel `"dev-only-change-me"` in production |
| `TEX_TEE_ATTESTATION_MODE` | Must be `production` outside non-production envs |

### Optional

| Variable | Purpose |
|---|---|
| `DATABASE_URL` | When set, swaps `PostgresActionLedger`, `PostgresAgentRegistry`, `PostgresDiscoveryLedger`, `PostgresPrecedentStore` into the runtime; decisions/policies/evidence go through `tex.memory.MemorySystem`'s durable stores |
| `TEX_SEMANTIC_PROVIDER` | `openai` to enable LLM judge; unset to use deterministic fallback |
| `TEX_SEMANTIC_MODEL` | Default `gpt-5-mini` |
| `TEX_SEMANTIC_REASONING_EFFORT` | One of `minimal`, `low`, `medium`, `high`, `none`, `xhigh` |
| `OPENAI_API_KEY` / `OPENAI_BASE_URL` / `OPENAI_ORG_ID` / `OPENAI_PROJECT_ID` | OpenAI client config |
| `TEX_DISCOVERY_OPENAI_API_KEY` | Enables `OpenAIConnector` (live OpenAI Assistants discovery) |
| `TEX_DISCOVERY_SLACK_TOKEN` | Enables `SlackLiveConnector` |
| `TEX_DISCOVERY_PRESENCE_THRESHOLD` | Soft-disappearance threshold (default 3) |
| `TEX_DISCOVERY_SCAN_TENANTS` | Comma-separated tenant IDs for background scheduler |
| `TEX_REQUIRE_AUTH` | `1` to require API keys |

### Verifiable code references

| Claim | Evidence |
|---|---|
| Fail-closed production secret guard | `config.py:_validate_production_secrets` |
| Fail-closed TEE attestation guard | `config.py:_validate_production_secrets` |
| Lazy PQ provider dispatch | `pqcrypto/algorithm_agility.py:get_signature_provider` |
| Postgres branching | `main.py:519-527` |
| Memory orchestrator promotion | `main.py:504-510` |
| 22 routers registered | `main.py:1168-1221` |
| Eight-step ecosystem pipeline | `ecosystem/engine.py:8-16` |
| Seven-stream agent contract | `engine/pdp.py:719` |

## What works end-to-end

- The seven-stream PDP evaluation
- The hash-chained JSONL evidence log + Postgres mirror + slice export + chain verification
- Discovery scans against OpenAI Assistants and Slack (live) + 5 mock platforms (AWS Bedrock, GitHub, Microsoft Graph, Salesforce, MCP servers)
- The learning loop (outcome reporting → reputation update → calibration proposal → human approval → policy activation)
- C2PA Content Credentials emission on PERMIT-with-outbound-artifact
- The 17 specialist judges
- The eight-step ecosystem engine (steps 1-2 firing; 3-8 wired but P1/P2 stubs)
- 80 HTTP endpoints across 22 routers
- Python SDK with `@gate` decorator

## What is tested but not invoked by the runtime

These packages have passing tests but no caller in the runtime pipeline. See `audit/orphans/ORPHAN_REGISTRY.md` for the full list.

- `enforcement/` (1,691 lines) — TexGate, framework adapters, ASGI proxy
- `compliance/` emitters (1,768 lines) — EU AI Act, FTC, California, Colorado, NY
- `governance/{kernel_mcp, path_policy, stpa_specs}` (2,727 lines) — MCP syscall gate, LTLf path policies, STPA hazard manifests
- `safeflow/` (892 lines) — transactional execution with WAL
- `vet/integration.py` (241 lines) — Web Proof attachment hook
- Six post-quantum crypto modules (~2,185 lines) — talus_tee, hqc, ml_kem, composite_cms, threshold_ml_dsa, evidence_quorum
- Four ontology sub-files (~525 lines) — airo, governance_ontology, interaction_ontology, role_ontology
- `graph/rustworkx_backend.py` (217 lines) — alternative graph backend
- `observability/governance_span.py` (122 lines) — OpenTelemetry GAAT span attributes

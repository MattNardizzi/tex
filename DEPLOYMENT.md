# Tex — Production Deployment Guide

This document describes how to deploy Tex into a production
environment. The default target in this repo is Render (the
existing service is at `tex-2far.onrender.com`), but every step
applies to any container platform — Render, Fly, ECS, Cloud Run,
or a hand-rolled VM.

---

## 1. Prerequisites

- Python 3.12+
- A Postgres 14+ database
- Sufficient secret storage to hold API keys, OpenAI keys,
  evidence HMAC secret, and the `DATABASE_URL`

---

## 2. Required environment variables

These MUST be set in production. Boot is allowed but heavily
warning-tagged when any is missing.

| Variable | Why it matters |
|---|---|
| `DATABASE_URL` | Without this, every durable store runs in-memory and decisions/evidence/agents disappear on restart. |
| `TEX_REQUIRE_AUTH=1` | Forces the auth layer to refuse every route that does not present a valid key. |
| `TEX_API_KEYS` | Comma-separated `<key>:<tenant>:<scopes>` triples (see `.env.example`). At minimum one tenant key + one admin key. |
| `TEX_EVIDENCE_HMAC_SECRET` | Signs exported evidence bundles. Must be stable across deploys; rotation requires a re-signing job. |

These SHOULD be set:

| Variable | Why |
|---|---|
| `OPENAI_API_KEY` | Without this, the semantic layer falls back to a heuristic keyword matcher that is correct but less accurate. |
| `TEX_SEMANTIC_MODEL` | Defaults to `gpt-4o-mini`. Set explicitly so model choice is visible in logs. |
| `TEX_DISCOVERY_OPENAI_API_KEY` / `TEX_DISCOVERY_SLACK_TOKEN` | Wire the live discovery connectors. Without these, only the mock connectors fire. |
| `TEX_CORS_ALLOW_ORIGINS` | Lock down to your frontend origin(s). Default `*` is dev-only. |

---

## 3. Postgres bootstrap

Tex creates every table it needs via idempotent `CREATE TABLE IF
NOT EXISTS` statements at startup. There is no separate migration
step. The first boot against an empty database creates all
schemas; subsequent boots see them already present.

The tables Tex creates:

| Table | Owner |
|---|---|
| `tex_decisions` | `decision_store_postgres` |
| `tex_policies` | `policy_store_postgres` |
| `tex_precedents` | `precedent_store_postgres` |
| `tex_action_ledger` | `action_ledger_postgres` |
| `tex_agent_registry` | `agent_registry_postgres` |
| `tex_discovery_ledger` | `discovery_ledger_postgres` |
| `tex_outcomes` | `outcome_store` |
| `tex_evidence` | `evidence/postgres_mirror` |
| `tex_governance_snapshots` | `governance_snapshots` |
| `tex_drift_events` | `drift_events` |
| `tex_scan_runs` | `scan_runs` |
| `tex_connector_health` | `connector_health` |
| `tex_calibration_proposals` | `calibration_proposal_store` |
| `tex_leaderboard` / `tex_arcade_leaderboard` | `db/leaderboard_repo`, `db/arcade_leaderboard_repo` |

Backups: standard Postgres logical backups are sufficient. The
hash-chained evidence table (`tex_evidence`) is append-only by the
application; Postgres-level RBAC should grant only INSERT and
SELECT on that table to the application role. DELETE is reserved
for the operator-initiated retention job and should be issued by
a separate role.

---

## 4. Auth posture

Production posture is `TEX_REQUIRE_AUTH=1`. With this set:

- Every route requires a valid `Authorization: Bearer <key>` or
  `X-Tex-API-Key: <key>` header.
- `/health` stays open as a liveness probe.
- `/mcp` (GET) and `/v1/guardrail/formats` stay open as discovery
  metadata endpoints.
- The leaderboard endpoints stay open by design — they are
  public game endpoints with their own decision-ID-based anti-cheat.

Scopes are enforced per-route. Common scope assignments:

| Use case | Scope set |
|---|---|
| Tenant-scoped service account that calls `/evaluate` and reads its own data | default scopes (`decision:write`, `decision:read`, `evidence:read`, `policy:read`, `agent:read`, `discovery:read`, `learning:read`, `tenant:read`, `outcome:write`) |
| Policy operator | default + `policy:write` |
| Calibration approver | default + `learning:write`, `learning:approve` |
| Internal admin (cross-tenant) | default + `admin:cross_tenant` + `policy:write` + `agent:write` + `learning:approve` |

Cross-tenant reads/writes are blocked unless the key carries
`admin:cross_tenant`. The `tenant_routes`, `discovery_routes`,
and `learning_routes` enforce this via `enforce_tenant_match`.

---

## 5. Evidence integrity

Evidence has two synchronized stores:

1. **JSONL hash chain on disk** — `var/tex/evidence/evidence.jsonl`
   by default. This is the source of truth for the chain. Every
   record links to its predecessor by SHA-256.
2. **Postgres mirror** — `tex_evidence` table. Tenant-partitioned,
   indexed by `(tenant_id, chain_seq)`, append-only. Mirror
   failures NEVER block the JSONL write — there is a regression
   test (`test_mirror_failure_does_not_corrupt_jsonl_chain`) that
   enforces this.

On a Render container, the JSONL filesystem is ephemeral. For
durability, either:

- Mount a persistent volume at `var/tex/evidence/`, OR
- Rely on the Postgres mirror as the durable store and treat the
  JSONL as a per-instance scratch chain.

Retention: `PostgresEvidenceMirror.apply_retention(tenant_id,
keep_days)` deletes rows older than `keep_days`. The retention
floor is hard-coded to 30 days; tighter retention requires an
explicit code change. Wire this into a daily cron under an admin
service account; do not expose it as an HTTP route.

---

## 6. Learning / drift gate

The feedback loop NEVER auto-applies a calibration proposal. The
orchestrator's `apply_proposal` requires a keyword-only `approver`
argument with no default. There is no environment flag, header,
or shortcut that bypasses this. The guard tests:

- `test_orchestrator_apply_proposal_requires_explicit_approver`
- `test_no_auto_apply_codepaths_in_learning_layer`

These will fail CI immediately if anyone introduces an
auto-apply path.

The HTTP surface mirrors this:

- `POST /v1/learning/proposals` — gated on `learning:write`
- `POST /v1/learning/proposals/{id}/approve` — gated on `learning:approve`
- `POST /v1/learning/proposals/{id}/reject` — gated on `learning:approve`
- `POST /v1/learning/proposals/{id}/rollback` — gated on `learning:approve`

---

## 7. Connector readiness

The OpenAI Assistants and Slack live connectors handle the
following error modes without crashing the discovery service:

| Mode | Behavior |
|---|---|
| 401 / 403 | `ConnectorError` with the upstream code |
| 429 | `ConnectorError` (HTTP) or `ConnectorTimeout` (Slack body-level) |
| 500 | `ConnectorError` with status preserved |
| Network timeout | `ConnectorTimeout` |
| Malformed JSON | `ConnectorError` |
| Missing admin scope (Slack) | Degrades silently — bots emitted with empty scopes |

Test coverage is in `tests/test_live_connectors_harness.py` (21
tests). For verification against real credentials, wire a smoke
runner in `scripts/connector_smoke.py` and run it on a schedule
in your environment — do not include real-credential tests in CI.

---

## 8. Render-specific notes

The existing deployment runs on Render (`tex-2far.onrender.com`)
with the following service configuration:

- **Build command:** `pip install -r requirements.txt`
- **Start command:** `uvicorn tex.main:create_app --factory --host 0.0.0.0 --port $PORT`
- **Postgres:** Render Postgres add-on attached as `DATABASE_URL`
- **Health check path:** `/health`

Render container filesystem is ephemeral, so evidence durability
relies on the Postgres mirror; the JSONL is a per-instance chain
that resets on restart. This is acceptable because the mirror is
the durable store; the JSONL is the verification source for that
single instance's chain.

---

## 9. Operational runbook

| Symptom | First check |
|---|---|
| Decisions disappear after restart | `DATABASE_URL` set? Check boot logs for `running in pure in-memory mode` warnings. |
| 401 on every route | `TEX_REQUIRE_AUTH=1` but `TEX_API_KEYS` is empty. Set keys or unset require-auth. |
| 403 with "tenant not accessible" | Key is scoped to a different tenant. Use a key with `admin:cross_tenant` or scope to the tenant. |
| Semantic layer returning low-confidence | `OPENAI_API_KEY` unset → falling back to heuristic. |
| Discovery scan completes with empty errors but no candidates | Live connector key absent → mock connector ran with empty fixtures. |
| Evidence chain verification fails | JSONL was edited or replayed out-of-order. Compare against `tex_evidence` mirror to find the divergence point. |

---

## 10. What this guide does NOT cover

- High-availability multi-instance deployment
- Read-replica routing for `decision_store` reads
- Dedicated retention service
- Per-tenant rate limiting
- SOC2 audit trail tooling

These are roadmap items, not current-release features. Document
the constraint with the buyer; do not promise capabilities the
runtime does not have.

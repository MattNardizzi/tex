# V18 — Production readiness pass

This release closes the seven production-readiness gaps that were
locked in at the start of this build cycle. Every item below is a
real code change with test coverage proving it works.

---

## 1. Durable persistence on every store

Added Postgres-backed write-through-cache implementations matching
the existing `agent_registry_postgres` pattern:

- `tex/stores/decision_store_postgres.py` — `tex_decisions` table,
  tenant-partitioned, indexed by `(tenant_id, decided_at DESC)`.
- `tex/stores/policy_store_postgres.py` — `tex_policies` table,
  activation-flush is one transaction so two policies cannot both
  be active simultaneously.
- `tex/stores/precedent_store_postgres.py` — `tex_precedents` table,
  metadata projection of decisions used by the retrieval orchestrator.
- `tex/stores/action_ledger_postgres.py` — `tex_action_ledger` table,
  append-only, per-agent bounded deque preserved in memory.
- `tex/db/connection.py` — shared DSN resolution + safe-for-log
  password masking + `with_connection` helper.

Wiring: `main.py` switches every store to its Postgres variant
when `DATABASE_URL` is set. When unset, the runtime falls back to
in-memory and logs one warning per store.

The Postgres variants are duck-typed against the in-memory ones,
so the rest of the runtime (PDP, commands, evaluators) treats them
identically.

---

## 2. Authentication and tenant isolation on every route

Replaced `tex/api/auth.py` with a scope-aware implementation:

- **Production posture:** `TEX_REQUIRE_AUTH=1` forces every route
  to require a valid key. `/health`, `/mcp` (GET), and
  `/v1/guardrail/formats` stay open as documented liveness/discovery
  probes. The leaderboards stay open by design (game endpoints with
  decision-ID-based anti-cheat).
- **Scoped keys:** `TEX_API_KEYS` parses
  `<key>[:<tenant>[:<scope>+<scope>+...]]`. Default scope set
  covers read+write on the per-tenant surface. `admin:cross_tenant`
  is reserved for internal admin keys.
- **`RequireScope` dependency:** every mutating route declares the
  scope it requires (`decision:write`, `policy:write`,
  `learning:approve`, `agent:write`, etc).
- **`enforce_tenant_match`:** routes that take a `tenant_id` in the
  path/query reject cross-tenant access unless the key has
  `admin:cross_tenant`.

Routers updated to use the new auth surface:

| Router | Before | After |
|---|---|---|
| `agent_routes.py` | 0/11 authed | 11/11 authed; mutating routes also gated on `agent:write` |
| `learning_routes.py` | 0/13 authed | 13/13 authed; create/approve/reject/rollback gated on explicit scopes |
| `routes.py` | 0/9 authed | 8/9 authed (`/health` open by design); each gated on the right scope |
| `tenant_routes.py` | 0/1 authed | 1/1 authed + cross-tenant guard |
| `discovery_routes.py` | 6/10 authed | 10/10 authed (router-level dependency) |

---

## 3. Evidence durable storage

Added `tex/evidence/postgres_mirror.py`:

- `tex_evidence` table — append-only, tenant-partitioned, indexed
  by `(tenant_id, chain_seq)`, full hash-chain fields preserved.
- Retention policy: `apply_retention(tenant_id, keep_days)` with a
  hard 30-day floor enforced in code. Wire to a daily cron behind
  an admin role.
- Mirror failures NEVER block the JSONL chain. `EvidenceRecorder`
  swallows mirror exceptions and continues. There is a regression
  test (`test_mirror_failure_does_not_corrupt_jsonl_chain`).

The JSONL chain remains the source of truth. The Postgres mirror
is the durable, tenant-partitioned, retention-aware store. On
ephemeral filesystems (Render), the mirror IS the durable store
and the JSONL is per-instance.

---

## 4. Learning / drift remains approval-gated

Verified the `FeedbackLoopOrchestrator.apply_proposal` signature
already requires a keyword-only `approver` with no default. Added
two guard tests:

- `test_orchestrator_apply_proposal_requires_explicit_approver` —
  inspects the function signature and fails if `approver` ever
  becomes optional.
- `test_no_auto_apply_codepaths_in_learning_layer` — greps the
  entire `tex/learning/` tree for `auto_apply`, `auto_approve`, and
  `auto_activate` substrings. If anyone ever introduces one, this
  test fails until it is explicitly removed.

HTTP routes for approve/reject/rollback are gated on the
`learning:approve` scope.

---

## 5. Verifiable test pass count

- Root cause of the prior hang: `requirements.txt` listed `asyncpg`
  but not `psycopg[binary]`, even though every Postgres-backed
  store uses `psycopg`. With the dependency missing, every test
  module that imports `main.py` failed at collection time and the
  test runner appeared to hang.
- `requirements.txt` now includes both drivers with comments
  explaining why each is needed.
- `Makefile` provides `make test` (verbose) and `make test-quiet`
  (CI-friendly). The expected pass count is **720 in ~22s** from
  a clean install.

---

## 6. Deployment readiness

- `.env.example` — was empty; now documents every variable Tex
  reads, with rationale for production posture.
- `README.md` — was 6 characters; now describes architecture,
  quickstart, honest test count, production readiness summary.
- `DEPLOYMENT.md` — new. Covers required env vars, Postgres
  bootstrap, auth posture, evidence integrity, learning gate,
  connector readiness, Render specifics, and operational runbook.
- `Makefile` — new. `make test` is the canonical pass-count
  command.

---

## 7. Live connector test harness

Added `tests/test_live_connectors_harness.py` (21 tests) covering
the full failure matrix for OpenAI Assistants and Slack live
connectors:

- 401 unauthorized → `ConnectorError`
- 403 insufficient scope → `ConnectorError`
- 429 rate-limited → `ConnectorError` (HTTP) / `ConnectorTimeout`
  (Slack body-level with `retry_after`)
- 500 upstream failure → `ConnectorError` preserving status
- network timeout → `ConnectorTimeout`
- malformed JSON → `ConnectorError`
- empty page → zero candidates, no exception
- Slack admin-scope missing → degrades silently to scopeless
  candidates, never raises
- happy path → produces well-formed candidates with risk-band
  classification

These tests patch `urllib.request.urlopen` inside each connector
module, so they run without real credentials and never hit the
network.

---

## Test count

| Phase | Count |
|---|---|
| V14.3 baseline (pre-V18) | 689 |
| V18 production-readiness suite | +10 |
| V18 live-connector harness | +21 |
| **V18 total** | **720** |

```
$ make test
...
720 passed in ~22s
```

---

## Files added in V18

```
src/tex/db/connection.py
src/tex/stores/decision_store_postgres.py
src/tex/stores/policy_store_postgres.py
src/tex/stores/precedent_store_postgres.py
src/tex/stores/action_ledger_postgres.py
src/tex/evidence/postgres_mirror.py
tests/test_v18_production_readiness.py
tests/test_live_connectors_harness.py
DEPLOYMENT.md
Makefile
```

## Files changed in V18

```
src/tex/api/auth.py             — scope-aware, require-auth, tenant-match
src/tex/api/agent_routes.py     — router-level auth + agent:write scopes
src/tex/api/learning_routes.py  — router-level auth + learning:approve scopes
src/tex/api/routes.py           — per-route scope gates
src/tex/api/tenant_routes.py    — auth + cross-tenant guard
src/tex/api/discovery_routes.py — router-level auth
src/tex/evidence/recorder.py    — accepts a mirror, swallows mirror errors
src/tex/main.py                 — wires Postgres stores when DATABASE_URL set
requirements.txt                — adds psycopg[binary]
.env.example                    — documents every variable
README.md                       — real content
tests/test_integration_layer.py — auth required on replay
```

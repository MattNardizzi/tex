# Cross-cutting — Persistence

> **Working doc.** stores/, db/, graph/.

## What this concern covers

Durability. Every read/write to Postgres, every in-memory store, every graph backend lives here. The layered code talks to interfaces; the implementations live in this concern.

## Packages in scope

| Package | Files | Lines | Status |
|---|---|---|---|
| `src/tex/stores/` | 20 | 6,970 | WIRED |
| `src/tex/db/` | 4 | 640 | WIRED |
| `src/tex/graph/` | 8 | 1,188 | Mixed — in-memory WIRED; rustworkx TEST_ONLY; postgres+janusgraph FULL_ORPHAN |

## The store pattern

Every store has TWO implementations:
1. **InMemory** — used in dev/test and when `DATABASE_URL` is unset
2. **Postgres** — used in production when `DATABASE_URL` is set

`main.py:519-527` does the swap at startup.

Stores in scope:

| Store | InMemory file | Postgres file | What it holds |
|---|---|---|---|
| Action ledger | `action_ledger.py` | `action_ledger_postgres.py` | Every action proposed by an agent |
| Agent registry | `agent_registry.py` | `agent_registry_postgres.py` | Per-tenant agent records |
| Discovery ledger | `discovery_ledger.py` | `discovery_ledger_postgres.py` | All discovery findings |
| Precedent store | `precedent_store.py` | `precedent_store_postgres.py` | Past decisions for retrieval |
| Scan run store | `scan_run_store.py` | `scan_run_store_postgres.py` | Discovery scheduler bookkeeping |
| Alert store | `alert_store.py` | `alert_store_postgres.py` | Inventory alerts |
| Policy snapshot store | `policy_snapshot_store.py` | (via `memory/policy_store.py`) | Policy versions |
| Reputation store | `reputation_store.py` | `reputation_store_postgres.py` | Reporter reputation |

Plus `memory/` has its own durable stores for decisions and policies (the V18 unified path — `DurableDecisionStore`, `DurablePolicyStore`).

## db/ — shared infrastructure

- `src/tex/db/connection.py` — Postgres connection pool used by leaderboard repos
- `src/tex/db/leaderboard_repo.py` — Tex Arena leaderboard
- `src/tex/db/arcade_leaderboard_repo.py` — arcade game leaderboard
- `src/tex/db/_migrations/` — schema migrations

Three independent connection-management approaches coexist: `db/connection.py`, `memory/_db.py`, and each `*_postgres.py` opens its own pool. Not breaking but a consolidation candidate.

## graph/ — temporal knowledge graph backends

| File | Status | Notes |
|---|---|---|
| `graph/temporal_kg.py` | WIRED | `InMemoryTemporalKG` — the default. Used by ecosystem engine step 2. |
| `graph/rustworkx_backend.py` | TEST_ONLY | Faster alternative — 5-50× faster than networkx per its docstring. Not selected. |
| `graph/postgres_backend.py` | FULL_ORPHAN | 25-line stub |
| `graph/janusgraph_backend.py` | FULL_ORPHAN | 14-line stub |

## Current state

✅ Solid:
- Clean InMemory/Postgres swap pattern
- Per-tenant scoping enforced at the store level
- All stores write-through to hash-chained ledgers where appropriate
- Migrations checked into `_migrations/`

⚠ Watch:
- The `rustworkx` backend is built and tested but never selected. Adding an env-var gate (`TEX_GRAPH_BACKEND=rustworkx`) is one PR.
- Two graph backend stubs (`postgres_backend.py`, `janusgraph_backend.py`) signal future work that hasn't happened.
- The three independent DB-connection approaches are a small but real maintenance burden.

## Improvement vectors

### 1. Activate rustworkx backend (low effort, real perf gain)
Add `TEX_GRAPH_BACKEND` env var. Default `inmemory`; allow `rustworkx`. Lazy import to avoid the dependency hit when not selected.

### 2. Unify Postgres connection management (medium impact, medium effort)
Consolidate `db/connection.py`, `memory/_db.py`, and per-store pool creation into one connection factory. Fewer pools, simpler tuning.

### 3. Pgvector for retrieval (high impact, high effort)
Today `retrieval/orchestrator.py` does keyword + structural matching against `precedent_store`. Adding pgvector embeddings for semantic precedent retrieval would substantially upgrade Stream 2.

### 4. Read replicas (medium impact, low effort)
Tex reads >> writes for most endpoints. Adding read-replica routing for the heavy GET paths (`/v1/agents`, `/v1/discovery/ledger`, evidence bundles) reduces primary load.

### 5. Tiered storage for evidence (medium impact, medium effort)
Hot evidence in Postgres; cold evidence (>90 days) in object storage with on-demand rehydration. Cost optimization for long-retention customers.

### 6. Complete or remove graph backend stubs (cleanup)
`postgres_backend.py` and `janusgraph_backend.py` are 14-25 line stubs. Either implement or move to `_pending/`.

## Constraints

- **Every Postgres write must be transactional**. Use the connection's `with conn.transaction():` pattern.
- **Hash chains MUST be written under a lock**. Concurrent writes to the same chain risk hash conflicts. Use SELECT FOR UPDATE on the chain head.
- **Tenant isolation at the store level**. Every query must filter by `tenant_id`. There's no global access path.
- **Migrations are forward-only**. No DOWN migrations in `_migrations/`. To roll back, write a new UP that reverses.
- **No application-level joins**. If you find yourself fetching from two stores and joining in Python, write a Postgres view or a dedicated store method.

## Testing

```bash
pytest tests/test_postgres_registry.py tests/test_postgres_discovery_ledger.py tests/test_memory_system.py
```

The full test suite exercises both InMemory and Postgres paths via fixtures in `tests/conftest.py`.

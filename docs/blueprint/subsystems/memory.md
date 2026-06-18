# Subsystem Dossier — `memory`

**Path:** `/Users/matthewnardizzi/dev/tex/src/tex/memory/`
**Branch:** `feat/proof-carrying-gate`
**Self-declared layer:** Layer 5 / `evidence` (`src/tex/memory/__init__.py:46-47`)
**Reachability:** `LIVE` (confirmed below)

---

## Overview

`tex.memory` is Tex's **system of record** — the durable persistence layer for every artifact a Policy Decision Point (PDP) evaluation produces: the decision verdict, the full original request input, the active policy snapshot, action permits, permit-verification attempts, and a Postgres mirror of the append-only evidence chain.

It is **NOT** an "AI memory" in the episodic/vector/embedding sense. There is **no vector DB, no embeddings, no streaming bus, no episodic recall**. The design explicitly forbids them (`system.py:31-33`: *"§ 9 Avoid: no vector DB, no streaming bus, no second SoR. Postgres is the only durable store."*) — and the code confirms this: every store is a **write-through cache over Postgres** (psycopg, synchronous) with a **graceful in-memory fallback** when `DATABASE_URL` is unset. The single "memory" primitive is a **relational ledger** (6 tables) plus a **tamper-evident JSONL hash chain** (owned by `tex.evidence`, mirrored here).

The kind of memory, precisely:
- **Decision ledger** (`tex_decisions`) — hot, indexed verdict records.
- **Input ledger** (`tex_decision_inputs`) — cold, full request bytes for replay.
- **Policy-snapshot ledger** (`tex_policy_snapshots`) — versioned configs for deterministic replay.
- **Permit / verification ledger** (`tex_permits`, `tex_verifications`) — single-use signed tokens + audit of every verification attempt.
- **Evidence mirror** (`tex_evidence_records`) — CRUD-queryable replica of the hash chain.
- **Replay engine** — re-runs an evaluator against the stored input under the stored policy and diffs the result.

The `runtime.memory` field (referenced in the task) is `TexRuntime.memory` (`src/tex/main.py:210`), populated with a single `MemorySystem` instance in `build_runtime` (`src/tex/main.py:548-550`). `memory.decisions` and `memory.policies` ARE the runtime's `decision_store`/`policy_store` (`main.py:559-560`), and `memory.recorder` is re-pointed at the runtime's shared `EvidenceRecorder` (`main.py:641`).

---

## File Inventory

| File | Lines | Role |
|------|------:|------|
| `__init__.py` | 102 | Public API surface; re-exports the 18 public symbols; declares `__layer__=5`, `__layer_kind__='evidence'`. |
| `_db.py` | 186 | Shared Postgres connection helpers: `connect()` (autocommit), `connect_tx()` (transactional), `database_url()`, `apply_migration()`, `ensure_memory_schema()`. Sync psycopg, connect/statement/lock timeouts. |
| `system.py` | 411 | `MemorySystem` facade + `MemoryHealth`. Wires all 6 stores + recorder; canonical write paths `record_decision`, `record_decision_with_policy` (atomic 1-tx), `record_outcome`, permit/verification helpers, read helpers, `health()`. |
| `decision_store.py` | 458 | `DurableDecisionStore` — write-through Postgres `tex_decisions` over an in-memory `InMemoryDecisionStore` cache; hydrates last 5000 on boot; `save_in_tx` for atomic path; `_payload_fingerprint`. |
| `decision_input_store.py` | 356 | `DecisionInputStore` + `StoredDecisionInput` — durable full-request payloads in `tex_decision_inputs`; dict-backed cache; `save`/`save_in_tx`/`link_to_decision`; SHA-256 of input. |
| `policy_snapshot_store.py` | 452 | `DurablePolicyStore` — write-through `tex_policy_snapshots` over `InMemoryPolicyStore`; `activate()` atomic flag-flip; **gated by selfgov governor** on every mutation. |
| `permit_store.py` | 384 | `PermitStore` + `StoredPermit` + `PermitNotFoundError` — durable signed permits in `tex_permits`; `issue`/`consume`/`revoke`; dual index by id + nonce; DB-level nonce-uniqueness. |
| `verification_store.py` | 231 | `VerificationStore` + `StoredVerification` + `VerificationResult` (StrEnum) — append-only `tex_verifications` log; bounded in-memory recent ring (default 1000). |
| `evidence_store.py` | 273 | `DurableEvidenceStore` + `StoredEvidenceRecord` — INSERT-only Postgres mirror of the evidence chain (`tex_evidence_records`); `mirror_record` (idempotent on `record_hash`), `mirror_chain` (verifies first). |
| `replay.py` | 244 | `MemoryReplayEngine` + `ReplayResult`/`ReplayDivergence`/`ReplayMissingArtifactError` — 5-step replay: load decision+input+policy → re-evaluate → diff fingerprint/verdict/confidence/score. |

Total: **3,097 lines**, 10 `.py` files. No `__pycache__` content counted.

---

## Internal Architecture

### Data flow (the canonical write)

`MemorySystem.record_decision_with_policy` (`system.py:181-278`) is the spine of the unit:

```
record_decision_with_policy(decision, full_input, policy, evidence_metadata)
  ├─ if DATABASE_URL unset (in-memory):           system.py:244-253
  │     decisions.save(decision)                  → DurableDecisionStore.save
  │     inputs.save(request_id, full_input, …)    → DecisionInputStore.save
  │     policies.save(policy)                      → DurablePolicyStore.save
  │
  ├─ else (durable, ONE Postgres transaction):    system.py:254-264
  │     with connect_tx() as conn, conn.cursor():  (_db.py:106-143)
  │        decisions.save_in_tx(decision, cur)
  │        inputs.save_in_tx(…request_id, full_input, decision_id, cur)
  │        policies.save_in_tx(policy, cur)
  │     # commit-or-rollback owned by connect_tx
  │
  ├─ recorder.record_decision(decision, metadata)  system.py:268-270  (JSONL append, post-commit)
  └─ evidence_mirror.mirror_record(evidence, kind="decision", aggregate_id=decision.decision_id)
                                                   system.py:273-277  (Postgres mirror, idempotent)
```

The three relational rows (decision, input, policy snapshot) are written in **one transaction** so partial writes are impossible (`connect_tx` commits on clean exit, rolls back on exception — `_db.py:130-138`). The JSONL chain is appended **after** the tx commits because the `EvidenceRecorder` is the single writer for the chain and is the authoritative source of evidence (`system.py:209-216`). The mirror is `ON CONFLICT (record_hash) DO NOTHING` (`evidence_store.py:128`), so re-mirroring is a no-op.

`record_decision` (`system.py:138-179`) is the **non-atomic legacy variant** — it `save()`s each store separately (no shared transaction), then appends + mirrors. The atomic `record_decision_with_policy` is the one the live runtime uses.

### The write-through-cache pattern (shared by all 5 read/write stores)

Every store follows an identical contract (the cleanest example is `DurableDecisionStore.save`, `decision_store.py:138-148`):

```
save(x):
  if postgres_enabled: _write_postgres(x)   # write DB first; raise on failure
  cache.save(x)                              # update in-memory cache only after
  cache_version += 1
```

- **Construction** (`decision_store.py:100-134`): reads `database_url()`; if unset → `_postgres_enabled=False` + loud warning, pure in-memory. If set → `ensure_memory_schema()` (idempotent migration), then `_hydrate_cache()` pulls the most recent rows (5000 for decisions/inputs, 2000 for policies, 1000 for verifications) so a restart never loses durable history.
- **Reads** are cache-first (`decision_store.py:190-191` returns straight from `self._cache`); some stores additionally read-through to Postgres on a cache miss (`decision_input_store.py:234-241`, `permit_store.py:254-266`, `policy_snapshot_store.py:216-227`).
- **`save_in_tx`** variants (`decision_store.py:150-168`, `decision_input_store.py:140-196`, `policy_snapshot_store.py:105-139`) take a caller-owned cursor and only emit SQL + bump the cache; the transaction boundary is owned by `MemorySystem`/`connect_tx`.
- **`is_durable`** property on every store returns `_postgres_enabled` — aggregated by `MemorySystem.health()`.
- **`cache_version`** monotonic counter (`decision_store.py:251-256`, `policy_snapshot_store.py:304-311`) — documented as the foundation for *future* LISTEN/NOTIFY cross-process invalidation; **not currently consumed by any reader** (no live caller compares it; single-process is the only safe deployment for cross-process staleness — `decision_store.py:109-114`).

### Per-store specifics

- **`DurableDecisionStore`** delegates the cache to `tex.stores.decision_store.InMemoryDecisionStore` and is a documented **drop-in superset** of it (duck-typed, no ABC — `decision_store.py:91-98`). `_payload_fingerprint` (`decision_store.py:71-88`) is a stable SHA-256 over `{request_id, action_type, channel, environment, content_sha256, policy_version}`. `_json_safe` (`decision_store.py:49-68`) coerces pydantic/enum/uuid/datetime trees to JSON for `Jsonb` columns. Upsert is `ON CONFLICT (decision_id) DO UPDATE` (re-evaluation overwrites the verdict — `decision_store.py:364-381`).

- **`DecisionInputStore`** keeps full request bytes separate from the verdict so the decisions table stays compact and inputs can be evicted independently (`decision_input_store.py:8-14`). Joined by `request_id`. `decision_id` link is optional at save and patched later by `link_to_decision` (`decision_input_store.py:198-230`). Validates `full_input` is a `dict` before any SQL (`decision_input_store.py:119-120, 158-159`).

- **`DurablePolicyStore`** wraps `tex.stores.policy_store.InMemoryPolicyStore`. **Notable:** every mutation (`save`, `save_in_tx`, `activate`, `delete`, `clear`) is gated through `tex.selfgov.governor.gate_controller_mutation(...)` (`policy_snapshot_store.py:98, 112, 153, 179, 206`) — if the self-governance gate denies, the write is silently skipped (returns without persisting). `activate()` (`policy_snapshot_store.py:141-170`) deactivates the whole policy family then activates one version in a single connection (`_activate_postgres`, `policy_snapshot_store.py:353-396`); DB enforces "at most one active per (tenant, policy_id)" via a partial unique index. Many `hasattr(self._cache, …)` guards (`policy_snapshot_store.py:230, 239, 248, 264, 275, 282`) defensively forward to the cache only if the method exists.

- **`PermitStore`** persists signed permits; the actual HMAC mint lives elsewhere (`permit_store.py:18-21` points at `tex.enforcement.permit`). Dual cache: `_by_id` + `_by_nonce` (`permit_store.py:83-84`). `issue` validates non-empty nonce/signature and tz-aware expiry (`permit_store.py:120-125`). `consume` (`permit_store.py:149-200`) is idempotent via `COALESCE(consumed_at, …)`. DB-level unique index on `(tenant_id, nonce)` makes double-spend a constraint violation, not a race (`permit_store.py:13-16`). `StoredPermit.is_active` checks revoked/consumed/expiry (`permit_store.py:57-63`).

- **`VerificationStore`** is **append-only** — one row per verification attempt (`tex_verifications`), distinct from the permit's mutable lifecycle (`verification_store.py:8-20`). It does **not** enforce single-use (that's `PermitStore`'s `consumed_at` + nonce index); it's purely the forensic trail. In-memory recent ring bounded to `cache_size` (default 1000, `verification_store.py:127-129`). `VerificationResult` is a `StrEnum`: VALID/EXPIRED/REVOKED/REUSED/INVALID_SIG/NOT_FOUND (`verification_store.py:40-48`).

- **`DurableEvidenceStore`** is **INSERT-only** by design — no UPDATE/DELETE path (`evidence_store.py:20-25`). `mirror_record` is idempotent on `record_hash` (`evidence_store.py:128`). `mirror_chain` (`evidence_store.py:151-178`) calls `tex.evidence.chain.verify_evidence_chain` first and **refuses to mirror an invalid chain** (raises). The JSONL file is the source of truth; the table is a queryable mirror for "show all FORBID outcomes from tenant X in 30 days" style audits (`evidence_store.py:13-18`).

- **`MemoryReplayEngine`** (`replay.py:116-244`) implements the 5-step replay: load decision (`replay.py:145`), load input by `request_id` (`replay.py:151`), load policy snapshot by `policy_version` (`replay.py:157`) — each raises `ReplayMissingArtifactError` if absent — then calls an **injected** `_Evaluator` protocol (`replay.py:45-60`) and `_compare`s (`replay.py:172-244`) on `determinism_fingerprint`, `verdict`, `confidence` (tol 1e-6), `final_score` (tol 1e-6). The engine is decoupled from the orchestrator on purpose (`replay.py:9-15`) — the evaluator is injected so tests can stub it.

---

## Public API

Exported from `tex.memory` (`__init__.py:77-102`):

| Symbol | Kind | Source |
|--------|------|--------|
| `MemorySystem` | facade class (entry point) | `system.py:92` |
| `MemoryHealth` | frozen dataclass | `system.py:65` |
| `DurableDecisionStore` | store | `decision_store.py:91` |
| `DecisionInputStore`, `StoredDecisionInput` | store + record | `decision_input_store.py:63, 51` |
| `DurablePolicyStore` | store | `policy_snapshot_store.py:51` |
| `PermitStore`, `StoredPermit`, `PermitNotFoundError` | store + record + error | `permit_store.py:70, 44, 66` |
| `VerificationStore`, `StoredVerification`, `VerificationResult` | store + record + StrEnum | `verification_store.py:67, 55, 40` |
| `DurableEvidenceStore`, `StoredEvidenceRecord` | store + record | `evidence_store.py:66, 50` |
| `MemoryReplayEngine`, `ReplayResult`, `ReplayDivergence`, `ReplayMissingArtifactError` | replay | `replay.py:116, 70, 63, 109` |

Also `__layer__`, `__layer_kind__` (`__init__.py:46-47`). The package docstring instructs all consumers to import from `tex.memory` and never reach into individual store modules (`__init__.py:10-12`).

`_db.py` helpers (`connect`, `connect_tx`, `database_url`, `ensure_memory_schema`, `apply_migration`) are **not** re-exported but are imported internally by every store and by `system.py`.

---

## Wiring

### Wired status: **LIVE** (with an important internal split — see below)

The unit is reachable from the running FastAPI app via the decision-evaluation path. **However, within the unit, only a subset of the surface is on a live call path.**

### Live call path (decision write — the primary path)

```
POST /v1/guardrail (and streaming/MCP/adapter variants)
  src/tex/api/guardrail.py:825          command = _get_evaluate_action_command(request)
  src/tex/api/guardrail.py:828          result = command.execute(domain_request)
    └─ EvaluateActionCommand.execute
        src/tex/commands/evaluate_action.py:241   if self._memory_system is not None:
        src/tex/commands/evaluate_action.py:246   evidence_record = self._memory_system.record_decision_with_policy(...)
            └─ tex.memory.system.MemorySystem.record_decision_with_policy   (system.py:181)
```

The `memory_system` slot is wired in `build_runtime`:
```
src/tex/main.py:548-550   from tex.memory import MemorySystem; memory = MemorySystem(evidence_path=…)
src/tex/main.py:559-560   decision_store = memory.decisions; policy_store = memory.policies
src/tex/main.py:641       memory.recorder = recorder        # share the C2PA/PQ-signed recorder
src/tex/main.py:962-971   EvaluateActionCommand(..., memory_system=memory)
src/tex/main.py:1218      TexRuntime(..., memory=memory)     # runtime.memory field
```
`_get_evaluate_action_command` resolves it off `app.state.evaluate_action_command` (`guardrail.py:872-882`). This is the **`runtime.memory` field** the task asked about.

### Live call path (health — secondary path)

```
GET /metrics
  src/tex/observability/metrics.py:357   metrics(request) -> render_metrics(...)
  src/tex/observability/metrics.py:176   render_metrics -> _render_durability(out, app)
  src/tex/observability/metrics.py:241-248  memory = runtime.memory; health = memory.health()
    └─ tex.memory.system.MemorySystem.health()   (system.py:393)
  installed via src/tex/main.py:1534-1535  install_metrics(app)
```
This is a live consumer of `MemorySystem.health()` and the per-store `is_durable` flags, exported as `tex_memory_durable` / `tex_store_durable` Prometheus gauges.

### Live within the unit, by symbol

- **LIVE**: `MemorySystem` (constructed in runtime), `MemorySystem.record_decision_with_policy` (eval path), `MemorySystem.health` (metrics path); and therefore `DurableDecisionStore`, `DecisionInputStore`, `DurablePolicyStore`, `DurableEvidenceStore`, `EvidenceRecorder` mirror writes, `_db.connect_tx`/`connect`/`ensure_memory_schema`. The policy store also flows into `_seed_default_policies` / `ActivatePolicyCommand` etc. as `policy_store`.
- **CONSTRUCTED-but-UNCALLED (DEMO/TEST-ONLY within the unit)**:
  - `MemoryReplayEngine` — the **only** non-test importers are `tests/test_memory_system.py` and `tests/test_runtime_memory_integration.py`. The `feedback_loop.py:535` `self._replay.replay(...)` is a **different class** (`tex.learning.replay.ReplayValidator`, imported at `learning/feedback_loop.py:69`), **not** `tex.memory.replay.MemoryReplayEngine`. No production code constructs `MemoryReplayEngine`.
  - `PermitStore` + `VerificationStore` are **constructed** by `MemorySystem.__post_init__` (`system.py:131-132`) so they are instantiated at runtime, but `MemorySystem.issue_permit` / `verify_permit` / `link_permit_to_decision` have **no live caller** — the only caller is `tests/test_memory_system.py`. (The runtime's actual permit/HMAC enforcement lives in `tex.enforcement`/`tex.pcas`, not through these MemorySystem helpers on this branch.)
  - `MemorySystem.record_decision` (non-atomic) and `record_outcome` — no live caller for the MemorySystem variants (the eval path uses `record_decision_with_policy`; outcome recording goes through `EvidenceRecorder.record_outcome` directly via `commands/report_outcome.py:157` and `api/outcome_autoseal.py:225`).

So: the **subsystem is LIVE** (its core stores carry every production decision write and its health feeds `/metrics`), but **replay, permits, and verifications are instantiated-yet-dormant** on this branch — wired into the facade, exercised only by tests.

### Wiring In (importers of `tex.memory`)

Only **one** non-test module imports `tex.memory`: `src/tex/main.py:548`. The metrics consumer (`observability/metrics.py`) reaches `MemorySystem` **indirectly** via `runtime.memory` (duck-typed, no import). This is by design — `main.py` is the single composition root; everything else receives stores by injection (`decision_store`, `policy_store`, `memory_system=…`).

### Wiring Out (dependencies)

Internal tex subsystems:
- `tex.domain` — `Decision`, `EvidenceRecord`, `OutcomeRecord`, `PolicySnapshot`, `Verdict` (`system.py:45-48`, `decision_store.py:37-38`, `replay.py:35-37`).
- `tex.evidence` — `EvidenceRecorder` (`system.py:49`), `verify_evidence_chain` (`evidence_store.py:40`), `tex.evidence.chain`.
- `tex.stores` — `InMemoryDecisionStore` (`decision_store.py:40`), `InMemoryPolicyStore` (`policy_snapshot_store.py:37`) as the cache layer.
- `tex.selfgov.governor` — `gate_controller_mutation` + `describe_policy_*` (`policy_snapshot_store.py:30-36`). Policy writes are governance-gated.
- `tex.db.migrations/001_memory_system.sql` — the master schema (`_db.py:61, 186`).

External libraries:
- **`psycopg`** (psycopg3) — sync driver; `psycopg.connect`, `psycopg.Error`, `psycopg.types.json.Jsonb` (`_db.py:38`, used in every store).
- stdlib: `hashlib` (SHA-256 fingerprints), `json`, `threading.RLock`/`Lock`, `dataclasses`, `enum.StrEnum`, `uuid`, `datetime`, `contextlib.contextmanager`, `pathlib`.

No async, no ORM, no vector/embedding/ML library anywhere in the unit.

---

## Implementation Reality

**Verdict: REAL.** This is a genuine, working durable-persistence layer with real SQL, real transactions, and a coherent in-memory fallback. There are **no** `NotImplementedError`, `TODO`, `FIXME`, or `raise NotImplementedError` stubs in any of the 10 files (grep-clean). No `pass`-only placeholder methods.

Evidence of real logic:
- **Real transactional write**: `connect_tx` (`_db.py:106-143`) is a true `autocommit=False` connection with commit-on-success / rollback-on-exception; the eval path drives it through three `save_in_tx` calls in one cursor (`system.py:255-264`).
- **Real SQL** with parameterized statements, `ON CONFLICT` upserts, partial unique indexes, idempotent migrations (`_UPSERT_SQL` decision_store.py:341-381; policy activate transaction policy_snapshot_store.py:353-396; mirror INSERT evidence_store.py:120-129).
- **Real connection hardening**: `connect_timeout`, `statement_timeout`, `lock_timeout` applied as libpq options (`_db.py:47-57, 93-95`) to keep a single-worker FastAPI service from wedging on a contended/connection-capped Postgres.
- **Real hashing**: SHA-256 input/config/payload fingerprints (`decision_input_store.py:46-48`, `policy_snapshot_store.py:46-48`, `decision_store.py:71-88`).
- **Real replay diff**: numeric tolerance comparison with structured divergence reporting (`replay.py:172-244`).
- **Verified at import**: constructing `MemorySystem(evidence_path=…)` with no `DATABASE_URL` succeeds, emits the documented per-store fallback warnings, and `health().durable == False`. With `DATABASE_URL`, every store would flip to write-through.

Graceful fallback (not a stub): every store checks `database_url()` and, when unset, runs **pure in-memory** with a loud warning (`decision_store.py:116-120`, etc.). The in-memory path is fully functional for local dev / tests; it simply loses durability on restart. The fallback is **the default** in any environment without `DATABASE_URL`.

Dormant-but-real (see Wiring): `MemoryReplayEngine`, permit, and verification machinery are complete, real implementations — they are just not on a production call path on this branch (test-only callers).

---

## Technology / SOTA

- **Pattern: write-through cache over a relational system of record.** Postgres is authoritative; an in-process hot cache serves reads. Classic, deliberately un-exotic (the docstring explicitly rejects vector DBs and event buses, `system.py:31-33`).
- **Transactional atomicity** for the decision+input+policy triple via a single psycopg transaction (`system.py:254-264`, `_db.py:106-143`).
- **Tamper-evident audit chain**: each evidence record is hash-linked to its predecessor (chain owned by `tex.evidence.recorder`/`chain`); this unit mirrors it into a queryable table and verifies the chain before bulk-mirroring (`evidence_store.py:151-178`).
- **Idempotency primitives**: `ON CONFLICT (record_hash) DO NOTHING` (mirror), `ON CONFLICT (decision_id/request_id/policy_version) DO UPDATE` (upserts), `COALESCE(consumed_at,…)` (idempotent consume), process-level migration guard (`_db.py:64-65, 158-160`).
- **Single-use token enforcement at the DB layer**: unique `(tenant_id, nonce)` index turns double-spend into a constraint violation instead of an application race (`permit_store.py:13-16`).
- **Deterministic replay** with fingerprint-first comparison so a divergence localizes to the right layer (`replay.py:18-26, 180-191`).
- **Self-governance gate** on policy mutations (`policy_snapshot_store.py:98` etc.) — a governance hook intercepts every policy write/activate/delete.
- **Connection-budget engineering** for a constrained single-worker host (Render Starter, 100-connection cap): short-lived per-write autocommit connections, no pool, hard timeouts (`_db.py:20-57`).

No ML, no cryptographic novelty inside this unit itself (the PQ/composite signing happens in the `EvidenceRecorder` it shares, not here).

---

## Persistence

**Durable (Postgres) when `DATABASE_URL` is set; in-memory otherwise.** State lives in 6 tables defined by `src/tex/db/migrations/001_memory_system.sql` (idempotent, re-run on every deploy):

| Table | Written by | Notes |
|-------|-----------|-------|
| `tex_decisions` | `DurableDecisionStore` | PK `decision_id`; indexes on `request_id`, `(tenant_id, decided_at)`, `(verdict, decided_at)`, `(policy_version, …)`, `content_sha256`. JSONB columns for scores/findings/reasons/asi_findings/retrieval_context/metadata/latency. (`001_…sql:22-67`) |
| `tex_decision_inputs` | `DecisionInputStore` | Full request payload (JSONB) + `input_sha256`, joined to decisions by `request_id`. (`001_…sql:74-86`) |
| `tex_policy_snapshots` | `DurablePolicyStore` | Versioned configs (JSONB) + `config_sha256`; **partial unique index** enforcing one active per `(tenant_id, policy_id)`. (`001_…sql:93-112`) |
| `tex_permits` | `PermitStore` | Signed permits; unique `(tenant_id, nonce)`. (`001_…sql:119-137`) |
| `tex_verifications` | `VerificationStore` | Append-only verification attempts. (`001_…sql:144-158`) |
| `tex_evidence_records` | `DurableEvidenceStore` | INSERT-only mirror; `sequence_number BIGSERIAL`; unique on `record_hash`. (`001_…sql:165-187`) |

In-memory caches (lost on restart): `InMemoryDecisionStore`, `InMemoryPolicyStore`, dict caches (`_by_id`/`_by_nonce`/`_cache`), and a bounded verification ring. On boot with a DB, each store hydrates its cache from Postgres (decisions/inputs ≤5000, policies ≤2000, permits ≤5000, verifications ≤1000). The **JSONL evidence chain** (`./data/evidence.jsonl` by default, `system.py:102-104`) is a separate file-backed durable artifact owned by `tex.evidence`, not this unit, and survives independently of Postgres.

---

## Notable Findings

1. **"Memory" here is a relational ledger, not AI memory.** There is no episodic store, no vector index, no embeddings, no retrieval-by-similarity. The docstring's "§9 Avoid: no vector DB, no streaming bus, no second SoR" (`system.py:31-33`) is honored in code — Postgres + JSONL only. Anyone expecting an LLM "memory" subsystem should look at `tex.retrieval` instead; this is the **system-of-record / audit ledger**.

2. **Replay, permits, and verifications are wired-but-dormant on this branch.** `MemoryReplayEngine`, `MemorySystem.issue_permit`/`verify_permit`/`link_permit_to_decision`, and `MemorySystem.record_decision`/`record_outcome` have **no production caller** — their only callers are `tests/test_memory_system.py` / `tests/test_runtime_memory_integration.py`. `PermitStore` and `VerificationStore` are *constructed* in every runtime (`system.py:131-132`) but never *exercised* through the facade in production. The subsystem is LIVE because of its decision/input/policy/health paths, not these.

3. **`feedback_loop.py` does NOT use this unit's replay engine** — a likely point of confusion. `learning/feedback_loop.py:535` calls `self._replay.replay(...)`, but `self._replay` is a `tex.learning.replay.ReplayValidator` (`feedback_loop.py:69`), an entirely separate replay implementation. The memory unit's `MemoryReplayEngine` is unused in production.

4. **`cache_version` is aspirational.** Both `DurableDecisionStore.cache_version` and `DurablePolicyStore.cache_version` are documented as the foundation for "future LISTEN/NOTIFY based invalidation" (`decision_store.py:109-114`, `policy_snapshot_store.py:304-311`) but **no reader consumes the counter** — under a multi-worker deployment, caches can silently drift. The code even warns that only single-process deployments are drift-free. This is a real, documented limitation, not a bug, but worth flagging for any horizontal-scale plan.

5. **Policy writes are silently governance-gated.** `DurablePolicyStore.save/save_in_tx/activate/delete/clear` short-circuit (return without persisting) if `gate_controller_mutation(...)` denies (`policy_snapshot_store.py:98-99, 112-113, 153-154, 179-180, 206-207`). A denied save returns `None` with no exception — a caller cannot tell from the return value that the write was suppressed. Cross-check needed against `tex.selfgov` to confirm the gate is permissive by default (the memory MEMORY.md note flags "inert governance" as a known overstatement area; that gate's actual strictness lives in `selfgov`, outside this unit).

6. **`save_in_tx` mutates the cache even if the surrounding tx rolls back.** Explicitly documented (`decision_store.py:150-168`, `system.py:222-232`): if the orchestrator's transaction fails after a `save_in_tx`, the in-memory cache holds an entry that never committed to Postgres until the next `reload()`. The docstring claims tests assert this trade-off; the mitigation is that a rollback always raises and callers `reload()` on retry. A genuine consistency caveat, honestly documented.

7. **Two evidence mirrors coexist.** This unit's `DurableEvidenceStore` writes `tex_evidence_records`; the runtime *also* attaches a legacy `PostgresEvidenceMirror` (`main.py:611-615, 630`) writing the older `tex_evidence` table for backward-compat dashboards. Both are idempotent and cost-bounded (`main.py:590-596`). Not a contradiction, but a redundancy worth knowing.

8. **Docstrings are accurate here** — unusually for this codebase. The "§" spec references in `system.py` map cleanly onto the actual transaction structure, the `_db.py` connection-budget rationale matches the timeouts in code, and the "INSERT-only" / "append-only" claims are enforced (no UPDATE/DELETE paths exist for the evidence/verification tables). I found no overstatement *within* this unit's code vs. its comments; the only gaps are the dormant-symbol wiring (findings 2–3) which the docstrings imply are used more broadly than they are.

9. **No abstract base classes** — the durable stores are duck-typed drop-in supersets of the `InMemory*` stores (`decision_store.py:91-98`). This is intentional and load-bearing: the runtime swaps durable for in-memory transparently, and downstream consumers (`OutcomeValidator`, `PolicyDriftMonitor`, eval command) never know which they got (`main.py:552-558`).

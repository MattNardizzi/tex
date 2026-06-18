# Subsystem Dossier: `tex.stores` (Persistence Stores)

> Branch: `feat/proof-carrying-gate`. All paths absolute under `/Users/matthewnardizzi/dev/tex`.
> Verified by reading every `.py` in `src/tex/stores/` and grepping call-sites. Claims sourced from `.md`/docstrings are labelled `(claim, unverified)`.

---

## Overview

`tex.stores` is the **cross-cutting persistence layer** for Tex. It holds 21 modules: a set of pure **in-memory adapters** (policy, decision, entity, precedent, action-ledger, agent-registry, discovery-ledger, tenant-content-baseline) and a parallel set of **durable backends** that follow one consistent design — a **synchronous write-through cache**: reads served from an in-memory structure (microsecond, no I/O), writes flushed synchronously to Postgres after the in-memory write, and on startup the cache is hydrated/bootstrapped from Postgres. When `DATABASE_URL` is unset (or Postgres is unreachable at boot), every durable store **degrades to pure in-memory and logs a warning** — never crashes.

The unit declares itself as a persistence layer marker:
- `src/tex/stores/__init__.py:9-10` — `__layer__ = None`, `__layer_kind__ = 'cross_cutting_persistence'`.

There are **three architectural shapes** in this unit:
1. **Pure in-memory stores** — no Postgres at all (`decision_store`, `entity_store`, `precedent_store`, `agent_registry`, `discovery_ledger`, `policy_store`, `action_ledger`, `tenant_content_baseline`).
2. **Self-contained hybrid stores** — own their Postgres path inline (in-memory cache + `psycopg` flush in the same file): `outcome_store`, `drift_events`, `connector_health`, `governance_snapshots`, `scan_runs`, `calibration_proposal_store`.
3. **`*_postgres` durable wrappers** — wrap a pure in-memory store as the cache and add a Postgres write-through via the shared `tex.db.connection` helper: `action_ledger_postgres`, `agent_registry_postgres`, `discovery_ledger_postgres`, `precedent_store_postgres`, `provenance_proofs_postgres`, `behavioral_provenance_ledger_postgres`.

**Wired status: `MIXED`.** Most stores are LIVE through `tex.main:build_runtime`. The decision/policy in-memory stores are LIVE *indirectly* (wrapped by `tex.memory`'s durable stores). One module — `behavioral_provenance_ledger_postgres.py` — is **DEMO_TEST_ONLY / ORPHAN** (referenced only by one test).

---

## File Inventory

| File | Lines | Shape | Role (one line) |
|---|---|---|---|
| `__init__.py` | 11 | — | Layer marker only (`__layer_kind__='cross_cutting_persistence'`); no exports. |
| `decision_store.py` | 178 | in-mem | `InMemoryDecisionStore`: decisions by `decision_id`/`request_id`, ordered list, metadata `find()`. |
| `policy_store.py` | 230 | in-mem | `InMemoryPolicyStore`: versioned `PolicySnapshot`s, activate/deactivate, gated by self-gov. |
| `entity_store.py` | 205 | in-mem | `InMemoryEntityStore`: sensitive entities by normalized name, lexical `find_matching()`. |
| `precedent_store.py` | 339 | in-mem | `InMemoryPrecedentStore`: projects `Decision`→`RetrievedPrecedent`, metadata `find_similar()`. |
| `agent_registry.py` | 186 | in-mem | `InMemoryAgentRegistry`: agent identities with monotonic revisions + lifecycle, gated. |
| `action_ledger.py` | 222 | in-mem | `InMemoryActionLedger`: per-agent bounded deque, computes `BehavioralBaseline`. |
| `discovery_ledger.py` | 201 | in-mem | `InMemoryDiscoveryLedger`: SHA-256 hash-chained append-only discovery outcomes + `verify_chain()`. |
| `tenant_content_baseline.py` | 254 | in-mem | `InMemoryTenantContentBaseline`: per-(tenant,action) ring buffer of PERMIT content signatures + Jaccard novelty. |
| `outcome_store.py` | 553 | hybrid | `InMemoryOutcomeStore`: outcome records w/ 6 indexes; inline Postgres write-through (`tex_outcomes`). |
| `drift_events.py` | 362 | hybrid | `DriftEventStore`: append-only drift log, ring-buffer cache + inline Postgres (`tex_drift_events`). |
| `connector_health.py` | 351 | hybrid | `ConnectorHealthStore`: per-(tenant,connector) health upsert, derived status, inline Postgres. |
| `governance_snapshots.py` | 724 | hybrid | `GovernanceSnapshotStore`: chained governance snapshots + regulator evidence-bundle export, inline Postgres. |
| `scan_runs.py` | 669 | hybrid | `ScanRunStore`: per-tenant scan lock + idempotency + durable run records, inline Postgres (partial unique idx). |
| `calibration_proposal_store.py` | 596 | hybrid | `CalibrationProposalStore`: proposal lifecycle FSM + audit-trail table, inline Postgres. |
| `action_ledger_postgres.py` | 276 | wrapper | `PostgresActionLedger`: wraps `InMemoryActionLedger`, write-through to `tex_action_ledger`. |
| `agent_registry_postgres.py` | 697 | wrapper | `PostgresAgentRegistry`: wraps registry; per-agent hash chain + audit columns; resync queue. |
| `discovery_ledger_postgres.py` | 301 | wrapper | `PostgresDiscoveryLedger`: wraps discovery ledger; re-verifies chain on bootstrap; resync queue. |
| `precedent_store_postgres.py` | 252 | wrapper | `PostgresPrecedentStore`: wraps precedent store, write-through to `tex_precedents`. |
| `provenance_proofs_postgres.py` | 383 | wrapper | `PostgresProvenanceProofStore` (+ private in-mem fallback): ZKPROV proof envelopes (`tex_provenance_proofs`). |
| `behavioral_provenance_ledger_postgres.py` | 302 | wrapper | `PostgresBehavioralProvenanceLedger`: signed provenance ledger mirror. **ORPHAN — test-only.** |

External helper used by 4 wrappers (out of scope but cited): `src/tex/db/connection.py` (129 lines) — `resolve_dsn`, `with_connection`, `safe_dsn_for_log`, statement/lock-timeout + `connect_timeout` enforcement.

---

## Internal Architecture

### Pure in-memory stores

**`InMemoryDecisionStore`** (`decision_store.py:11`) — three structures under `RLock`: `_by_id` (`UUID→Decision`), `_ordered_ids` (save order), `_by_request_id` (`request_id→decision_id`). `save()` re-orders on re-save (`decision_store.py:47-60`); `find()` (`:103-145`) is a reverse-scan metadata filter (verdict/policy_version/channel/environment/action_type); `list_recent()` newest-first.

**`InMemoryPolicyStore`** (`policy_store.py:16`) — `_by_version`, `_ordered_versions`, `_versions_by_policy_id`. Notable: **every mutating method is gated through the reflexive self-governor** — `save` (`:54`), `activate` (`:155`), `delete` (`:182`), `clear` (`:197`) call `gate_controller_mutation(lambda: describe_policy_*(...))`; when the gate denies, the method returns/no-ops rather than raising (`:54-55`). `activate()` produces *replacement* immutable snapshots via `model_copy` because `PolicySnapshot` is immutable (`:169-171`). `get_active()` scans newest-first for `is_active` (`:135-138`).

**`InMemoryEntityStore`** (`entity_store.py:9`) — `_by_key` keyed by `casefold()`-normalized canonical name (`:183-187`). `find_matching()` (`:86`) is **lexical substring matching** over canonical name + aliases against normalized text — explicitly "intentionally simple … without premature complexity" (`:97-98`); no vector/semantic index.

**`InMemoryPrecedentStore`** (`precedent_store.py:12`) — stores raw `Decision` objects; `_to_precedent()` (`:262`) projects to `RetrievedPrecedent`. `find_similar()` (`:100`) is exact-metadata filtering, newest-first, with `_compute_relevance_score()` (`:218`) = (matched filters / possible filters), clamped to `[0.1, 1.0]`. `retrieve_precedents()` (`:167`) adapts to the `tex.retrieval.orchestrator.PrecedentStore` protocol. `_extract_matched_policy_clause_ids()` (`:301`) is "best-effort" because "the decision model does not currently guarantee a single canonical field" (`:303-305`) — a real heuristic over `retrieval_context`/`metadata`.

**`InMemoryAgentRegistry`** (`agent_registry.py:35`) — `_by_id` (current revision) + `_history` (all revisions in order). `save()` forces revision=1 on first registration (`:77-84`), else `revision = existing.revision + 1` with refreshed `updated_at` and preserved `registered_at` (`:88-98`). `set_lifecycle()` (`:100`) produces a new revision on transition. `require_evaluable()` (`:144`) raises `AgentRevoked` for REVOKED agents; PENDING/ACTIVE/QUARANTINED resolve. Custom exceptions: `AgentNotFoundError`, `AgentRevoked` (`:27,:31`). **Gated** via `describe_agent_save`/`describe_lifecycle` (`:70,:111`).

**`InMemoryActionLedger`** (`action_ledger.py:24`) — `_by_agent: dict[UUID, deque]` with `maxlen=per_agent_limit` (default 5000, `action_ledger.py:44,67`) → bounded memory, oldest rolls out. `_global_order` keeps cross-agent order for fleet analytics. The substantive logic is `compute_baseline()` (`:119`): a pure, deterministic reduction over the last `window` (default 200) entries computing permit/abstain/forbid rates, action/channel/recipient-domain distributions, mean final score, capability-violation rate, and a **forbid streak** (contiguous trailing FORBIDs, `:178-183`). `_extract_recipient_domain()` (`:209`) parses `email@domain` / `scheme://host` forms.

**`InMemoryDiscoveryLedger`** (`discovery_ledger.py:37`) — **append-only SHA-256 hash chain**. `append()` (`:64`) computes `payload_sha256 = sha256(stable_json(candidate+outcome))` and `record_hash = sha256(stable_json({payload_sha256, previous_hash}))` (`:88-97`). `verify_chain()` (`:142`) replays and recomputes every record's payload hash and link, returning False on any mismatch — tamper-evident. Indexed by `reconciliation_key` and `resulting_agent_id`. `_stable_json` uses `sort_keys=True, separators=(",",":")` for canonical hashing (`:190`).

**`InMemoryTenantContentBaseline`** (`tenant_content_baseline.py:51`) — per-`(tenant,action_type)` bounded deque of `ContentSignatureRecord` (default cap 1000, `:88`) + a recipient-domain counter dict. `lookup()` (`:123`) computes max/mean `signature_jaccard_similarity` over the window and `novelty_score = 1 - max_similarity` (`:190`), flags `cold_start` when `sample_size < 30` (`:48,:183`). Records only PERMIT content (caller's responsibility, doc + `:97-105`) — deliberately not re-validating verdict to avoid coupling to the Decision domain.

### Self-contained hybrid stores (in-memory cache + inline Postgres)

All six share a structure: module-level `SCHEMA_SQL` (`CREATE TABLE IF NOT EXISTS … + indexes`), constructor reads `DATABASE_URL`, sets `self._disabled = not bool(dsn)`, calls `_ensure_schema()` + a hydrate/bootstrap on success, falls back to in-memory on any exception. All expose `@property is_durable -> not self._disabled`.

**`InMemoryOutcomeStore`** (`outcome_store.py:63`) — six in-memory indexes (decision/request/kind/label/tenant/trust) over `_by_id`. Postgres path (`tex_outcomes`, `:23-60`) flushes full JSONB payload + denormalized columns on `save()` via `_persist_outcome()` upsert (`:480`); hydrates all rows on boot (`_hydrate_from_postgres`, `:449`). `list_calibration_eligible()` (`:334`) is the canonical calibrator entry — filters `trust_level.is_calibration_eligible` (VALIDATED+VERIFIED) plus tenant/policy/since. Note: the class name is `InMemory*` but it is genuinely durable when configured (`:63-77` docstring says class name preserved for back-compat).

**`DriftEventStore`** (`drift_events.py:137`) — `DriftEventKind` enum (NEW_AGENT/AGENT_CHANGED/AGENT_DISAPPEARED, `:50`), lightweight `DriftEvent` (`__slots__`, `:85`). Ring-buffer cache (`maxlen=cache_limit`, default 1000). `emit()` (`:181`) appends + flushes; `query_history()` (`:239`) hits Postgres for deeper reads, falling back to the buffer.

**`ConnectorHealthStore`** (`connector_health.py:136`) — keyed `(tenant,connector)`; `record_success`/`record_failure` upsert (`:174,:202`); `consecutive_failures` increments on failure, resets on success. `ConnectorHealth.status` (`:107`) is **derived on read** (0 fail→HEALTHY, 1-2→DEGRADED, 3+→OFFLINE, never-seen→UNKNOWN) so threshold changes need no migration (doc `:24-26`).

**`GovernanceSnapshotStore`** (`governance_snapshots.py:97`) — the largest module. `capture()` (`:162`) builds an immutable snapshot record from a serialized `GovernanceResponse`, computes a **chained `snapshot_hash`** over counts + coverage root + V16 scan-binding metadata + `previous_snapshot_hash` (`:216-234`). `export_evidence_bundle()` (`:323`) assembles a self-contained regulator bundle with per-section SHA-256 hashes + an **HMAC-SHA256 manifest signature** (`:443-455`); secret resolved via `tex.config.get_settings().get_evidence_summary_secret()` (`:438-440`, fail-closed). `verify_chain()` (`:634`) replays oldest→newest recomputing each `snapshot_hash`. `OrderedDict` FIFO-evicts past `cache_limit` (default 200).

**`ScanRunStore`** (`scan_runs.py:185`) — the discovery concurrency spine. `acquire()` (`:241`) implements **idempotency** (return existing run for repeat `idempotency_key`) and a **per-tenant lock**: in memory via `_active_by_tenant`, in Postgres via a partial unique index `tex_scan_runs_tenant_active_idx … WHERE status='running'` (`:94-95`). On DB `UniqueViolation` it reloads the live holder and raises `ScanLockHeld` (`:305-318`). Stale locks (heartbeat older than `DEFAULT_LOCK_STALE_SECONDS=1800`) are reclaimed (`:272-286,:477`). `heartbeat`/`complete`/`fail` manage lifecycle.

**`CalibrationProposalStore`** (`calibration_proposal_store.py:113`) — a **lifecycle FSM** enforcing valid transitions PENDING→APPROVED/REJECTED→APPLIED→ROLLED_BACK (+EXPIRED). Each transition method (`approve`/`reject`/`mark_applied`/`mark_rolled_back`/`mark_expired`, `:243-391`) validates the current status and raises `InvalidProposalTransitionError` otherwise; produces a `model_copy` update. Two tables: `tex_calibration_proposals` (state) + `tex_calibration_proposal_events` (append-only audit trail, `:99-109`). `list_audit_trail()` (`:547`) reads the event table — **returns `[]` in pure in-memory mode** because no in-memory mirror of the event log is kept (`:557-558`).

### `*_postgres` durable wrappers

These compose (do not subclass) a pure in-memory store as `self._cache` and add a write-through. Four of them route Postgres through the shared `tex.db.connection.with_connection` (which enforces `connect_timeout`, `statement_timeout`, `lock_timeout`); two (`agent_registry_postgres`, `discovery_ledger_postgres`) call `psycopg.connect` directly.

**`PostgresActionLedger`** (`action_ledger_postgres.py:99`) — `self._cache = InMemoryActionLedger`; reads delegate straight to the cache (baseline path stays microsecond-fast, `:163-186`). `append()` writes cache then `_flush_one()` INSERT … `ON CONFLICT DO NOTHING` (append-only, `:213`). `_resolve_tenant()` (`:82`) parses tenant from `session_id` prefix `tenant:<id>:…`. Bootstrap replays up to `per_agent_limit*1000` rows oldest-first (`:237-255`).

**`PostgresAgentRegistry`** (`agent_registry_postgres.py:130`) — richest wrapper. Adds a **per-agent hash chain** (`record_hash` links to prior revision's hash, `_compute_audit_for`, `:449-480`), audit context (`policy_version`/`snapshot_id`/`write_source` via `set_audit_context`, `:197`), a **resync queue** `_pending_resync` with `replay_pending()` (`:298`) for writes that failed when Postgres was briefly down, and `verify_agent_chain()` (`:326`) for tamper detection. `_flush_save()` (`:502`) marks prior revisions `is_current=FALSE` then upserts the new revision with all audit columns. Bootstrap reaches into `self._cache._lock/_history/_by_id` directly to preserve on-disk revision numbers (`:433-441`).

**`PostgresDiscoveryLedger`** (`discovery_ledger_postgres.py:64`) — wraps `InMemoryDiscoveryLedger`; `append` delegates chain computation to the cache then flushes. Bootstrap re-runs `verify_chain()` and **logs an error if the restored chain is broken** (`:234-240`) — tamper-evident across restarts. Resync queue + `replay_pending()` (`:166`).

**`PostgresPrecedentStore`** (`precedent_store_postgres.py:63`) — wraps `InMemoryPrecedentStore`; all reads (`find_similar`/`retrieve_precedents`) delegate to cache; writes flush to `tex_precedents` JSONB. `_resolve_tenant()` (`:56`) reads `decision.metadata["tenant"]`.

**`PostgresProvenanceProofStore`** (`provenance_proofs_postgres.py:159`) — stores ZKPROV `ProvenanceProof` envelopes keyed by `proof_envelope_sha256` (`tex_provenance_proofs`, `:69-92`). Has its **own** private `_InMemoryProvenanceProofStore` (`:95`) as the cache/fallback (the only wrapper that defines its own in-mem class rather than reusing a sibling). `is_regulator_grade(proof.backend)` cached at insert (`:121,:321`). Reads (`get`/`find_by_decision`/`find_by_commitment`) hit the cache only.

**`PostgresBehavioralProvenanceLedger`** (`behavioral_provenance_ledger_postgres.py:64`) — wraps `tex.provenance.ledger.BehavioralProvenanceLedger`, mirroring a **signed** (per-entry ECDSA over `record_hash`) ledger to `tex_provenance_ledger`. On bootstrap it re-runs BOTH `verify_chain()` (integrity) and `verify_signatures()` (authenticity) and logs an error on failure (`:287-302`). Signing key must be re-injected at construction for signatures to verify post-restart (`:77-89`). **This module is not wired into the running app (see Wiring).**

---

## Public API

Symbols imported by code outside the unit (verified via grep, see Wiring In):

| Symbol | Module | Importers |
|---|---|---|
| `InMemoryDecisionStore` | `decision_store` | `memory.decision_store`, `learning.feedback_loop`, `learning.drift`, `commands.*` |
| `InMemoryPolicyStore` | `policy_store` | `memory.policy_snapshot_store`, `learning.feedback_loop`, `commands.*`, `capstone.flow` |
| `InMemoryEntityStore` | `entity_store` | `main` |
| `InMemoryPrecedentStore` | `precedent_store` | `main`, `commands.evaluate_action`, `precedent_store_postgres` |
| `InMemoryAgentRegistry`, `AgentNotFoundError`, `AgentRevoked` | `agent_registry` | `main`, `agent.suite`, `discovery.service`, `api.agent_routes`, `agent_registry_postgres` |
| `InMemoryActionLedger` | `action_ledger` | `main`, `agent.suite`, `agent.behavioral_evaluator`, `api.agent_routes`, `action_ledger_postgres` |
| `InMemoryDiscoveryLedger` | `discovery_ledger` | `main`, `discovery.service`, `discovery_ledger_postgres` |
| `InMemoryTenantContentBaseline` | `tenant_content_baseline` | `main`, `agent.suite`, `agent.behavioral_evaluator`, `api.tenant_routes`, `commands.evaluate_action` |
| `InMemoryOutcomeStore` | `outcome_store` | `main`, `learning.feedback_loop`, `commands.report_outcome`, `commands.calibrate_policy` |
| `CalibrationProposalStore`, `InvalidProposalTransitionError`, `ProposalNotFoundError` | `calibration_proposal_store` | `main`, `learning.feedback_loop`, `api.learning_routes` |
| `DriftEventStore`, `DriftEvent`, `DriftEventKind` | `drift_events` | `main`, `discovery.scheduler`, `discovery.alerts`, `api.governance_history_routes` |
| `ConnectorHealthStore` | `connector_health` | `main`, `discovery.service` |
| `GovernanceSnapshotStore` | `governance_snapshots` | `main` |
| `ScanRunStore`, `ScanLockHeld` | `scan_runs` | `main`, `discovery.service` |
| `PostgresActionLedger` / `PostgresAgentRegistry` / `PostgresDiscoveryLedger` / `PostgresPrecedentStore` | `*_postgres` | `main` (DB-configured branch only) |
| `PostgresProvenanceProofStore` | `provenance_proofs_postgres` | `api.zkprov_routes` |
| `PostgresBehavioralProvenanceLedger` | `behavioral_provenance_ledger_postgres` | **tests only** (`tests/test_discovery_witness_layer.py:479`) |

`__init__.py` exports nothing but `__layer__`/`__layer_kind__`; all imports are module-direct.

---

## Wiring

### Wiring In (who imports the unit)

Grep `grep -rn "from tex.stores" src/tex` (excluding the unit and tests) shows the hub is `src/tex/main.py`. Two indirection points:
- `src/tex/memory/decision_store.py:40,107` — `DurableDecisionStore` wraps `InMemoryDecisionStore` as its `_cache`.
- `src/tex/memory/policy_snapshot_store.py:37,51` — `DurablePolicyStore` wraps `InMemoryPolicyStore`.

### Live call path (from `tex.main`)

`create_app` (`main.py:1309`) → calls `build_runtime(...)` (`main.py:1358`, also background-built `:1386-1398`). Inside `build_runtime` (defined `main.py:519`):

- `database_configured = bool(os.environ["DATABASE_URL"])` (`main.py:546`).
- **Decision/policy stores are the memory system's stores**: `decision_store = memory.decisions` / `policy_store = memory.policies` (`main.py:559-560`), where `memory.decisions` is `DurableDecisionStore` (`memory/system.py:107,128`) wrapping `InMemoryDecisionStore`, and `memory.policies` is `DurablePolicyStore` (`memory/system.py:109,130`) wrapping `InMemoryPolicyStore`. → those two in-memory stores are **LIVE but INDIRECT** (never instantiated directly in build_runtime; reached through the memory wrappers).
- **DB-conditional swap** (`main.py:562-576`): when configured, `precedent_store=PostgresPrecedentStore()`, `agent_registry=PostgresAgentRegistry()`, `discovery_ledger=PostgresDiscoveryLedger()`, `action_ledger=PostgresActionLedger()`; otherwise the `InMemory*` equivalents.
- **Always-constructed**: `outcome_store=InMemoryOutcomeStore()` (`:579`, has its own Postgres path), `entity_store=InMemoryEntityStore()` (`:582`), `tenant_baseline=InMemoryTenantContentBaseline()` (`:585`).
- **Discovery/governance hybrids** (`main.py:722-729`): `GovernanceSnapshotStore()`, `DriftEventStore()`, `ScanRunStore()`, `ConnectorHealthStore()`.
- **Calibration**: `proposal_store = CalibrationProposalStore()` (`main.py:987`).

All of these are packed into the `TexRuntime` dataclass (`main.py:1184-1212`, fields declared `:150-181`) and then surfaced on FastAPI app state:
- `app.state.outcome_store/precedent_store/entity_store/tenant_baseline` (`main.py:1599-1605`)
- `app.state.governance_snapshot_store/drift_event_store/scan_run_store/connector_health_store` (`main.py:1642-1649`)
- `agent_registry`/`action_ledger`/`discovery_ledger` consumed by `AgentEvaluationSuite` (`main.py:651-655`), `DiscoveryService` (`:704-708`), `ContinuousProvenanceFeed` (`:691-696`), the evaluate-action command (`:966-970`), and the governance snapshot capture closure (`:789-792`).

`PostgresProvenanceProofStore` is LIVE via a different path: `api/zkprov_routes.py:62` imports it, `_store()` (`:121-122`) constructs it per-call, and routes call `_store().save/get` (`:398,602,641`). The router is registered: `app.include_router(zkprov_router)` (`main.py:1510`).

→ **Net wired_status: `MIXED`** — most LIVE (direct via build_runtime/app.state or via zkprov route); decision/policy in-mem stores LIVE-INDIRECT (memory wrappers); `PostgresBehavioralProvenanceLedger` ORPHAN.

### The ORPHAN

`grep -rn "PostgresBehavioralProvenanceLedger" .` across the whole repo returns hits only inside its own file and `tests/test_discovery_witness_layer.py:479-483`. The live provenance ledger used by `build_default_provenance_engine` (`provenance/__init__.py:85`, called at `main.py:681`) is the in-memory `BehavioralProvenanceLedger` from `tex.provenance.ledger` — **not** the stores wrapper. So `behavioral_provenance_ledger_postgres.py` is **DEMO_TEST_ONLY / ORPHAN** from the running app's perspective: the durable mirror exists and is real, but nothing in `build_runtime`/routes constructs it.

### Wiring Out (dependencies)

**Internal tex subsystems:** `tex.domain.*` (policy, decision, verdict, agent, retrieval, outcome, outcome_trust, discovery, tenant_baseline, calibration_proposal) — the value objects every store persists. `tex.selfgov.governor` (policy_store + agent_registry mutation gating). `tex.config.get_settings` (governance evidence-bundle HMAC secret, lazy import `governance_snapshots.py:439`). `tex.db.connection` (4 wrappers). `tex.pqcrypto.algorithm_agility`, `tex.provenance.ledger`, `tex.provenance.models` (behavioral provenance wrapper). `tex.zkprov.proof`, `tex.zkprov.backends` (proof store).

**External libraries:** `psycopg` (v3) + `psycopg.types.json.Jsonb` (all durable stores); `hashlib`/`hmac`/`json` (hash chains, HMAC, canonical JSON); stdlib `threading.RLock`, `collections.deque/Counter/OrderedDict`, `datetime`, `uuid`, `enum.StrEnum`. No ORM (raw SQL). No connection pool yet (`db/connection.py:18-24` notes fresh short-lived connection per write, pool is a future one-file change).

---

## Implementation Reality

**REAL logic (no stubs):**
- Hash chains are genuine and self-consistent: `discovery_ledger.append/verify_chain` (`:64,:142`), `governance_snapshots.capture/verify_chain` (`:162,:634`), `agent_registry_postgres` per-agent chain (`:449,:326`). All use canonical `sort_keys`/tight-separator JSON before `sha256`.
- The behavioral baseline (`action_ledger.compute_baseline`, `:119`) is a full, deterministic statistical reduction — not a placeholder.
- The scan-run **per-tenant lock + idempotency** is enforced at two layers: in-memory dict AND a Postgres partial unique index, with real `UniqueViolation` handling and stale-lock reclaim (`scan_runs.py:94-102,:272-318,:477`).
- The calibration FSM rejects invalid transitions with real guards (`calibration_proposal_store.py:255,291,324,357,382`).
- HMAC manifest signing in the evidence bundle is real `hmac.new(secret, …, sha256)` with fail-closed secret resolution (`governance_snapshots.py:438-448`).
- The self-governor gate is real (default inert returns `allowed=True`, bindable to deny) — `gate_controller_mutation` (`selfgov/governor.py:464`); the policy/agent stores' calls are live chokepoints, not no-ops.

**Graceful fallbacks (REAL, not hollow):**
- Every durable store degrades to in-memory when `DATABASE_URL` is unset OR schema bootstrap raises, logging a warning and setting `_disabled=True` (verified at runtime: `is_durable==False` for outcome/drift/calibration with no DSN). Examples: `outcome_store.py:113-128`, `drift_events.py:162-177`, `governance_snapshots.py:132-149`, `agent_registry_postgres.py:167-184`. This is a real fallback path, not a stub.
- Per-write Postgres failures are caught and logged (write-survives-in-memory); the registry/discovery/provenance wrappers additionally **queue failed writes** in `_pending_resync` for `replay_pending()` (`agent_registry_postgres.py:298`, `discovery_ledger_postgres.py:166`, `behavioral_provenance_ledger_postgres.py:166`).

**Limitations / honest-simple paths (flagged, not stubs):**
- `InMemoryEntityStore.find_matching` and `InMemoryPrecedentStore.find_similar` are **lexical/metadata only**, explicitly "not semantic" (`entity_store.py:96-98`, `precedent_store.py:115-120,:233-235`). Working code, deliberately un-fancy.
- `CalibrationProposalStore.list_audit_trail` returns `[]` in pure in-memory mode (`:557-558`) — by design, the event log is durable-only.
- `db/connection.py` has **no connection pool** (one connection per write) — acknowledged as acceptable under current load (`:18-24`).

**No `NotImplementedError`, no `TODO`-blocked paths, no `pass`-only methods** were found in this unit. (`grep` for `NotImplementedError`/`raise NotImplemented` across `src/tex/stores/` = 0 hits.)

---

## Technology / SOTA

- **Tamper-evident hash-linked ledgers** (SHA-256, `prev_hash`-chained, canonical JSON) — discovery ledger, governance snapshot chain, per-agent registry revision chain. The pattern mirrors a transparency log / append-only Merkle-ish chain (linear, not a tree).
- **Signed transparency log** — behavioral provenance ledger carries per-entry ECDSA signatures verified on restore (`behavioral_provenance_ledger_postgres.py:10-17,287-302`). Signature provider abstracted via `tex.pqcrypto.algorithm_agility` (PQ-agile).
- **Write-through cache (cache-aside on read, write-through on write)** with synchronous flush + boot-time hydration — the unit's dominant pattern, deliberately synchronous to match Tex's synchronous runtime (rationale in `agent_registry_postgres.py:8-23`).
- **Distributed-lock-via-DB-constraint** — scan-run per-tenant lock realized as a Postgres partial unique index plus a heartbeat/stale-reclaim protocol (`scan_runs.py`).
- **MinHash/Jaccard novelty** — tenant content baseline uses banded signatures + `signature_jaccard_similarity` for "novel content for this tenant" (`tenant_content_baseline.py:166-190`).
- **HMAC-SHA256 evidence manifests** with per-section hashes for independent regulator verification (`governance_snapshots.py:410-455`).
- **Optimistic-immutability via `model_copy`** — Pydantic immutable domain objects updated by replacement (policy activation, agent revisions, proposal transitions).
- **libpq hardening** — `connect_timeout` + `statement_timeout` + `lock_timeout` on every connection to prevent a hung DB from wedging the single-worker service (`db/connection.py:40-56`).

---

## Persistence

| Store | In-memory? | Durable backend | Table(s) | Survives restart? |
|---|---|---|---|---|
| decision (in-mem) | yes | — (durable wrapper lives in `tex.memory`) | — | only via `DurableDecisionStore` |
| policy (in-mem) | yes | — (durable wrapper lives in `tex.memory`) | — | only via `DurablePolicyStore` |
| entity | yes | none (re-seeded each boot, `main.py:580-582`) | — | no |
| precedent | yes | `PostgresPrecedentStore` | `tex_precedents` | when DB configured |
| agent_registry | yes | `PostgresAgentRegistry` | `tex_agent_registry` | when DB configured |
| action_ledger | yes | `PostgresActionLedger` | `tex_action_ledger` | when DB configured |
| discovery_ledger | yes | `PostgresDiscoveryLedger` | `tex_discovery_ledger` | when DB configured |
| tenant_baseline | yes | none (warms up from PERMITs, `main.py:583-585`) | — | no (rebuilt) |
| outcome | yes (cache) | inline | `tex_outcomes` | when DB configured |
| drift_events | yes (ring) | inline | `tex_drift_events` | when DB configured |
| connector_health | yes | inline | `tex_connector_health` | when DB configured |
| governance_snapshots | yes (LRU) | inline | `tex_governance_snapshots` | when DB configured |
| scan_runs | yes (cache) | inline | `tex_scan_runs` (+ partial unique indexes) | when DB configured |
| calibration_proposal | yes (cache) | inline | `tex_calibration_proposals`, `tex_calibration_proposal_events` | when DB configured |
| provenance_proofs | yes | `PostgresProvenanceProofStore` | `tex_provenance_proofs` | when DB configured |
| behavioral_provenance (ORPHAN) | yes | wrapper | `tex_provenance_ledger` | n/a — not wired |

**State location:** with no `DATABASE_URL`, ALL state is process-local Python objects (RAM) and is lost on restart — verified by `is_durable==False` at runtime. With `DATABASE_URL` set, durable stores write through to Postgres and reconstruct caches on boot. Schemas are created idempotently (`CREATE TABLE IF NOT EXISTS` + `ADD COLUMN IF NOT EXISTS` backfills) on first connection — no migration tool. **The single configuration switch for the entire unit's durability is the `DATABASE_URL` env var.**

---

## Notable Findings

1. **One ORPHAN module.** `behavioral_provenance_ledger_postgres.py` (`PostgresBehavioralProvenanceLedger`) is real and well-built (signed chain re-verification on restore) but is referenced **only by `tests/test_discovery_witness_layer.py:479`**. The live provenance engine (`provenance/__init__.py:85`, `main.py:681`) uses the in-memory `BehavioralProvenanceLedger` instead. Its docstring claims "Drop-in mirror … following the exact write-through pattern the discovery and action ledgers use" — true as code, but the mirror is **never instantiated in production**, so durable behavioral provenance is currently unrealized in the running app. (Surprise / dead-in-app code.)

2. **Naming contradiction: `InMemoryOutcomeStore` is durable.** The class named `InMemory*` (`outcome_store.py:63`) actually has a full Postgres write-through path; the name is kept "for backward compatibility with existing callers" (`:73-77`). A reader trusting the name would wrongly assume it cannot persist. The docstring is honest about this; the name is misleading.

3. **Decision/policy stores are LIVE only through `tex.memory`.** `build_runtime` never constructs `InMemoryDecisionStore`/`InMemoryPolicyStore` directly — it uses `memory.decisions`/`memory.policies` (`main.py:559-560`), which are `DurableDecisionStore`/`DurablePolicyStore` wrapping the in-memory ones. So the spine classification `stores=LIVE` is correct, but for these two modules the live path is indirect via the memory subsystem, not the stores unit itself.

4. **Most durable stores bypass the shared connection helper.** Only **3** stores route through `tex.db.connection.with_connection` and thus get the `connect_timeout`/`statement_timeout`/`lock_timeout` hardening (`db/connection.py:108-114`): `action_ledger_postgres.py`, `precedent_store_postgres.py`, `provenance_proofs_postgres.py`. The other **9** call `psycopg.connect(self._dsn, …)` directly and do NOT get that hardening: `agent_registry_postgres.py` (`:373,391,402,503`), `discovery_ledger_postgres.py` (`:190,195,264`), and all six inline-hybrid stores (`outcome_store`, `drift_events`, `connector_health`, `governance_snapshots`, `scan_runs`, `calibration_proposal_store`), plus the orphan `behavioral_provenance_ledger_postgres`. This is a latent inconsistency given the helper's stated purpose ("the only place stores should call `psycopg.connect`", `db/connection.py:98-99`). The 9 direct callers can hang their worker thread on a slow/locked DB — exactly the multi-minute-outage failure mode `db/connection.py:46-56` was written to prevent. (Flag: timeout hardening applied to only 3 of 12 durable stores.)

5. **Bootstrap reaches into private internals of sibling caches.** `agent_registry_postgres._bootstrap_from_postgres` (`:433-441`), `discovery_ledger_postgres._bootstrap_from_postgres` (`:207-228`), `behavioral_provenance_ledger_postgres._bootstrap_from_postgres` (`:257-285`), and `provenance_proofs_postgres._bootstrap_from_postgres` (`:351-377`) write directly into `self._cache._lock` / `._entries` / `._by_*` (marked `# noqa: SLF001`). Deliberate (preserves on-disk sequence/revision numbers) but tightly couples each wrapper to its cache's internal layout.

6. **`provenance_proofs_postgres` schema is created without autocommit.** `_ensure_schema` (`:269-273`) opens `with_connection(self._dsn)` (non-autocommit) and `conn.commit()`s, whereas every other store's `_ensure_schema` uses `autocommit=True`. Functionally fine (it commits), just inconsistent with the unit's convention.

7. **No `NotImplementedError`/TODO/placeholder anywhere in the unit** — the implementation reality is genuinely high. The only "intentionally simple" paths (lexical entity match, metadata precedent ranking) are working code with documented limitations, not stubs.

8. **Durability is all-or-nothing per env var.** There is no per-store durability toggle; `DATABASE_URL` flips the entire unit. A deployment that sets it gets durability across every hybrid/wrapper store at once; an unset deployment silently runs entirely in RAM (with warnings). This matters operationally: a production deploy that forgets `DATABASE_URL` loses agent registry, ledgers, snapshots, scan-run locks, and outcomes on every restart, with only log-warning signal.

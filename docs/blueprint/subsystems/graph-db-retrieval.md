# Subsystem Dossier: Graph, DB, Retrieval

> Scope: `src/tex/graph/`, `src/tex/db/`, `src/tex/retrieval/`
> Branch: `feat/proof-carrying-gate`
> Method: code-read + import/call-site tracing. Every load-bearing claim is cited `file:line`. Docstring/`.md` claims are labelled "(claim, unverified)" unless confirmed in code.

---

## Overview

Three small but distinct cross-cutting units:

1. **`graph/`** — an in-memory **temporal knowledge graph** (TKG) backbone over `networkx.MultiDiGraph`. Nodes are typed entities with append-only versioned attribute snapshots; edges are typed temporal events with upstream lineage. Provides deterministic, reproducible `state_hash(at)`, time-travel reads (`get_entity_at`), neighborhood queries, path/causal-ancestor queries, an `EcosystemState` projection, and a conditional rustworkx fast-path for BFS. This is the persistent ecosystem-state substrate the `EcosystemEngine` writes to.

2. **`db/`** — a thin shared **Postgres connection helper** (`connection.py`) used by the `tex.stores.*_postgres` and `tex.evidence.*_postgres` write-through mirrors. DSN resolution, password-masked logging, a `with_connection` context manager with mandatory connect/statement/lock timeouts, and a "is DB configured?" probe. No ORM, no pool (yet), no graph code lives here.

3. **`retrieval/`** — a lean, **contract-first RAG-grounding orchestrator** (`orchestrator.py`). Defines three store `Protocol`s (policy-clause / precedent / entity), fans out to whichever are wired, normalizes any failure into a warning string, and packs results into a `RetrievalContext`. The real stores are wired in `tex.main`; NoOp stores are the dev default.

**Wiring summary:**
- `graph` (TKG + projection): **LIVE** — instantiated in `build_runtime` (`main.py:930-931`), written by `EcosystemEngine`. But the *graph-mutating* path is gated behind `TEX_ECOSYSTEM=1` (default **off**), so on a default deploy the graph is constructed and `state_hash`-queried but never accreted with events.
- `db.connection`: **LIVE** (indirectly) — imported by 5 Postgres stores/mirrors that `build_runtime` constructs.
- `retrieval.orchestrator`: **LIVE** — wired into the PDP (`main.py:645-649, 876-877`), invoked on every `/v1/guardrail`-class evaluation. Policy-clause + precedent grounding work; **entity grounding is silently broken by a keyword-argument mismatch** (see Notable Findings).
- `graph.query.GraphQuery`, `graph.rustworkx_backend`, and `InMemoryTemporalKG.neighbors()` are **TEST-ONLY / ORPHAN in production** — no non-test importer.

---

## File Inventory

| File | LoC | Role |
|------|----:|------|
| `graph/__init__.py` | 43 | Package marker + re-exports `TemporalKnowledgeGraph`, `InMemoryTemporalKG`, `StateProjection`, `GraphQuery`. `__layer__=None`, `__layer_kind__='cross_cutting_persistence'`. |
| `graph/temporal_kg.py` | 547 | Core: `TemporalKnowledgeGraph` Protocol + `InMemoryTemporalKG` (networkx-backed TKG), `_StoredEvent`, canonical state-hash, pure helpers. |
| `graph/projection.py` | 107 | `StateProjection.project_at(at)` → `EcosystemState` snapshot by partitioning entities by kind; computes `state_hash`. |
| `graph/query.py` | 188 | `GraphQuery.find_paths` (bounded BFS over typed edges) + `causal_ancestors` (upstream-lineage BFS). Pure-read. **Test-only importer.** |
| `graph/rustworkx_backend.py` | 218 | Optional Rust-backed BFS/reachability (`available()`, `bfs_descendants`, `reachable_pairs`) with networkx fallback. **Test-only importer.** |
| `graph/exceptions.py` | 47 | `GraphMutationError` hierarchy (Unknown{Actor,Target,Entity,Event}, MissingUpstream, DuplicateEventId, NaiveDatetime, EntityAlreadyExists). |
| `db/__init__.py` | 12 | Package marker only. `__layer__=None`, `__layer_kind__='cross_cutting_persistence'`. |
| `db/connection.py` | 128 | `resolve_dsn`, `safe_dsn_for_log`, `with_connection` ctx mgr (timeouts), `is_database_configured`. The single psycopg.connect chokepoint. |
| `retrieval/__init__.py` | 11 | Package marker. `__layer__=4`, `__layer_kind__='execution_governance'`. |
| `retrieval/orchestrator.py` | 224 | `RetrievalOrchestrator` + 3 store Protocols + 3 NoOp stores + `build_noop_retrieval_orchestrator()`. |

Total in scope: **1525 LoC** across 10 files.

---

## Internal Architecture

### graph/temporal_kg.py — `InMemoryTemporalKG`

The backbone. Three internal stores (`__init__`, `temporal_kg.py:92-103`):
- `self._graph: nx.MultiDiGraph` — nodes = entities (carry immutable `kind`), edges = events keyed by `event_id` (so parallel events between the same actor→target are distinct).
- `self._versions: dict[str, list[(datetime, attrs_snapshot)]]` — per-entity **append-only version timeline**, full snapshots (not deltas), insertion-ordered by timestamp for O(log n) bisect reads.
- `self._events_by_id: dict[str, _StoredEvent]` — id→event for fast lineage walks and duplicate detection.

**Writes:**
- `add_entity` (`temporal_kg.py:107-180`): type-validates inputs; requires a tz-aware `registered_at` in `attrs` (`_ensure_aware`, line 144); freezes attrs via `_freeze` (line 146). First add locks `kind` on the node (line 151). Re-add enforces (a) `kind` immutability (raises `ValueError`, line 158) and (b) monotone-advancing timestamp (line 164), then **merges** new attrs over the prior snapshot (delta-merge, lines 168-171) and appends a new version. Emits `graph.kg.entity_added` (line 174).
- `add_event` (`temporal_kg.py:182-277`): type-validates; coerces tz-aware timestamp; rejects duplicate `event_id` (`DuplicateEventIdError`, line 228); validates `actor` registered (`UnknownActorError`, 232), `target` registered if given (`UnknownTargetError`, 236), and **every upstream id already stored** (`MissingUpstreamEventError`, 241 — the same pre-existence invariant the events ledger enforces). Pure-emission events (`target is None`) become **self-edges** (`edge_target = ... or actor`, line 246) so they stay graph-walkable. Stores both the nx edge and a `_StoredEvent`. Emits `graph.kg.event_appended` (269).

**Reads:**
- `get_entity_at(entity_id, at)` (`temporal_kg.py:281-300`): bisect_right over the timeline timestamps (line 296), returns a defensive copy of the rightmost snapshot ≤ `at`, or `None` if not yet registered. This is the time-travel primitive.
- `neighbors(entity_id, *, edge_kinds, within)` (`temporal_kg.py:302-347`): in+out edges, filtered by edge-kind set and a closed temporal window; deduplicated self-edges; sorted by `(timestamp, event_id)` for stable diffing. Returns tuples of `_edge_record` dicts.
- `state_hash(at)` (`temporal_kg.py:349-373`): canonical SHA-256 over `_canonical_state_at`. The empty-graph hash is pinned (docstring + `STATE_HASH_SCHEMA_VERSION="1"`, line 67) and reproducible across processes.
- `_canonical_state_at(at)` (`temporal_kg.py:377-414`): builds `{"schema_version", "entities":[...], "events":[...]}` with `schema_version` first; entities sorted by id, events sorted by `(timestamp, id)`; events with `ts > at` excluded; pipes through `canonical_sha256`.

**Determinism plumbing — `_freeze` / `_dt_to_iso` (`temporal_kg.py:481-515`):** Every stored attrs/payload dict is round-tripped through `canonical_json` (RFC-8785-subset canonicalizer from `tex.events._canonical`). This (a) **rejects unsupported types up front** — floats, sets, custom objects, naive datetimes — and (b) produces an owned, immutable copy. Aware datetimes are pre-coerced to UTC ISO strings (`_dt_to_iso`, 498) because the canonicalizer rejects datetimes outright. `_ensure_aware` (470) rejects naive datetimes with `NaiveDatetimeError`.

`_StoredEvent` (`temporal_kg.py:443-465`) is a `__slots__`-based internal record (not a public dataclass). Internal accessors `_underlying_graph`, `_has_event`, `_get_event`, `_has_entity`, `_entities`, `_entity_kind` (lines 417-438) expose the graph to `GraphQuery`/`StateProjection` without leaking the raw nx object.

### graph/projection.py — `StateProjection`

`project_at(at)` (`projection.py:46-107`): calls `graph.state_hash(at)` (line 58), then iterates `graph._entities()`, fetches each snapshot via `get_entity_at`, partitions by `kind` into `agent`/`tool`/`capability` lists and tracks the latest `governance_graph` entity (last-write-wins by sorted id, lines 76-80). Sorts the id lists, builds an `EcosystemState` (`tex.ecosystem.state`) with `aggregate_drift_signals={}` and `sliding_window_compromise_ratio=0.0` (P0 defaults — drift/compromise are explicitly P1/P2 stubs, lines 95-96). `active_governance_graph_id` falls back to sentinel `"unknown"` (line 37). Emits `graph.projection.computed` (99).

### graph/query.py — `GraphQuery` (test-only)

- `find_paths(*, from_entity, to_entity, edge_kinds, max_depth=8, within)` (`query.py:38-108`): bounded BFS where each frontier item is the path-so-far; enforces simple paths (`if dst in path: continue`, line 91); applies edge-kind + temporal-window filter via `_edge_passes` (176). Returns all simple paths up to `max_depth` in BFS order.
- `causal_ancestors(*, event_id, depth=8)` (`query.py:110-171`): BFS over `_StoredEvent.upstream` lineage, deduplicated, excludes the start event, defensively skips upstream ids that don't resolve (line 158 — guards against a future eventually-consistent Postgres backend). Raises `UnknownEventError` for unknown start.

### graph/rustworkx_backend.py — optional fast traversal (test-only)

Conditional import (`rustworkx_backend.py:48-54`): `_RUSTWORKX_AVAILABLE` flag. `available()` (57) reports it. `_RxView` (67) + `_build_rx_view` (81) mirror an nx graph into a `rx.PyDiGraph`, storing the edge `kind` string as the rustworkx edge weight so kind-filtering works without `get_edge_data` (which would collapse parallel edges in a MultiDiGraph — see the inline note, lines 197-201). `bfs_descendants` (102) dispatches `_rx_bfs` vs `_nx_bfs`; `reachable_pairs` (120) is the cartesian closure. The rustworkx full-reachability path uses `rx.descendants` (184). **The `_rx_*` paths are `# pragma: no cover` — only exercised if rustworkx is installed.**

### db/connection.py

- `resolve_dsn(dsn=None)` (`connection.py:59-68`): explicit arg or `DATABASE_URL` env; returns `""` when unset (callers treat empty as in-memory mode).
- `safe_dsn_for_log(dsn)` (71-87): masks the password (`user:secret@` → `user:***@`).
- `with_connection(dsn, *, autocommit=False)` (90-114): the **single** `psycopg.connect` chokepoint. Mandatory `connect_timeout=_CONNECT_TIMEOUT_S` (default 5s, env `TEX_DB_CONNECT_TIMEOUT`) plus libpq `options` injecting `statement_timeout` (default 15000ms) and `lock_timeout` (default 5000ms) — `_PG_OPTIONS` (line 56). The module docstring (lines 46-56) explains these guard against a single-worker outage where a hung connect/lock pins worker threads until the pool exhausts.
- `is_database_configured()` (117-119): truthiness of `resolve_dsn()`.

No pool yet — docstring (lines 19-25, claim re: future `psycopg_pool.ConnectionPool`) confirmed as not implemented; stores open a fresh short-lived connection per write.

### retrieval/orchestrator.py

- Three `Protocol`s: `PolicyClauseStore` (`retrieve_policy_clauses(*, policy, request, top_k)`), `PrecedentStore` (`retrieve_precedents(*, request, limit)`), `EntityStore` (`retrieve_entities(*, request, policy, top_k)`) — `orchestrator.py:15-50`.
- `RetrievalOrchestrator` (53-173): holds optional stores; `retrieve(*, request, policy)` (77-111) fans out to the three private helpers, accumulating `warnings`, and returns a `RetrievalContext` (`tex.domain.retrieval`) with metadata `{policy_version, retrieval_top_k, precedent_lookback_limit}`. Each helper (`_retrieve_policy_clauses` 113, `_retrieve_precedents` 134, `_retrieve_entities` 154) returns `()` + appends a `*_store_unavailable` warning when the store is `None`, and wraps the call in `try/except Exception` → `*_retrieval_failed:{ExcType}` warning. **This broad catch is what masks the live entity bug.**
- Three NoOp stores (176-211) returning `()`, and `build_noop_retrieval_orchestrator()` (214-222) wiring them.

The `top_k`/`limit` plumbing comes from `policy.retrieval_top_k` and `policy.precedent_lookback_limit` (`orchestrator.py:127, 148, 169`).

---

## Public API

**graph (via `tex.graph.__init__`):** `TemporalKnowledgeGraph` (Protocol), `InMemoryTemporalKG`, `StateProjection`, `GraphQuery`.
Direct module imports in use: `tex.graph.temporal_kg.InMemoryTemporalKG`, `tex.graph.projection.StateProjection`, `tex.graph.exceptions.{GraphMutationError, UnknownActorError}`.
`graph.rustworkx_backend`: `available`, `bfs_descendants`, `reachable_pairs` (`__all__`, line 214).

**db (`tex.db.connection`):** `DATABASE_URL_ENV`, `resolve_dsn`, `safe_dsn_for_log`, `with_connection`, `is_database_configured` (`__all__`, `connection.py:122-128`).

**retrieval (`tex.retrieval.orchestrator`):** `RetrievalOrchestrator`, `build_noop_retrieval_orchestrator`, the three Protocols, the three NoOp stores.

---

## Wiring

### Wiring — In

**graph:**
- `tex.main:87-88` imports `StateProjection`, `InMemoryTemporalKG`; constructs `_ecosystem_graph = InMemoryTemporalKG()` and `_ecosystem_projection = StateProjection(graph=_ecosystem_graph)` in `build_runtime` (`main.py:930-931`), passed into `EcosystemEngine(graph=..., projection=...)` (`main.py:948-949`).
- `tex.ecosystem.engine:85-86` imports `GraphMutationError, UnknownActorError, StateProjection`; `engine:111` lazily imports `InMemoryTemporalKG` (deferred to break a circular import — comment at `engine.py:104-111`).
- `tex.systemic.digital_twin:59` imports `InMemoryTemporalKG` and uses `state_hash`/`get_entity_at`/`_entities` — **but** `main.py:1066` constructs `EcosystemDigitalTwin()` with `graph=None`; the twin's `fork_at`/`simulate` path tolerates `graph is None` (`digital_twin.py:623`, returns `state_hash="ecosystem_no_graph"`). So the live twin route never touches the TKG.
- `tex.pcas.graph.adapter:8` and `tex.causal._provenance_graph:33` reference `tex.graph.temporal_kg` **in docstrings only** — `pcas/graph/adapter.py` imports nothing from `tex.graph`, and `causal/_provenance_graph.py` builds its own `networkx.DiGraph` (`_provenance_graph.py:46,156`).
- `GraphQuery`, `rustworkx_backend`, and `InMemoryTemporalKG.neighbors()`: **only** imported/called from `tests/` (`tests/ecosystem/test_graph_temporal_kg.py`, `tests/frontier_thread_12/test_rustworkx.py`). No production importer.

**db.connection:** imported by `evidence/manifest_mirror.py:47`, `evidence/postgres_mirror.py:49`, `stores/action_ledger_postgres.py:40`, `stores/precedent_store_postgres.py:29`, `stores/provenance_proofs_postgres.py:57` — all of which `build_runtime` constructs. Calls confirmed: e.g. `with_connection(self._dsn, ...)` at `action_ledger_postgres.py:191/198/246`, `postgres_mirror.py:158/209/...`.

**retrieval:** imported by `engine/pdp.py:61` and `main.py:110`. `main.py:645-649` builds the live orchestrator with three real adapters; `main.py:876-877` passes it into `PolicyDecisionPoint(retrieval_orchestrator=...)`. `stores/precedent_store.py:177` references the `PrecedentStore` protocol (docstring/typing).

### Wiring — Live call path

**retrieval (genuinely LIVE on the request hot path):**
```
HTTP POST /v1/guardrail (and siblings)            api/routes.py (handler -> _get_evaluate_action_command, routes.py:124/581-582)
  -> EvaluateActionCommand.execute                commands/evaluate_action.py
    -> PolicyDecisionPoint.evaluate(...)          engine/pdp.py:270-275
        retrieval_context = self._retrieval_orchestrator.retrieve(request=..., policy=...)
          -> RetrievalOrchestrator.retrieve        retrieval/orchestrator.py:77
            -> InMemoryPolicyClauseStoreAdapter / InMemoryPrecedentStoreAdapter / InMemoryEntityStoreAdapter   (main.py:290/414/442)
```
The orchestrator is constructed in `build_runtime` (`main.py:645`) and attached to the PDP (`main.py:876-877`); the PDP is on `app.state.pdp` (`main.py:1594`). `pdp.py:201-202` defaults to `build_noop_retrieval_orchestrator()` only if none is injected — in the real app the wired one is used. **Verdict: LIVE.**

**graph (LIVE construction; mutation gated):**
```
build_runtime (main.py:930) -> InMemoryTemporalKG()  +  StateProjection (931)
  -> EcosystemEngine(graph, projection) (main.py:946-959)
  -> EcosystemBridge(engine) (main.py:960), passed to EvaluateActionCommand(ecosystem_bridge=...) (main.py:981, 1225)

per-request:  EvaluateActionCommand.execute
  -> bridge.emit_verdict(...)        evaluate_action.py:999  (called unconditionally when bridge wired)
    -> EcosystemEngine.evaluate      ecosystem/bridge.py:182
       if not self._enabled: short-circuit  (engine.py:488-503, returns "ecosystem governance disabled (TEX_ECOSYSTEM=0)")
       else: projection.project_at + graph.add_event + graph.state_hash   (engine.py:530, 1171, 1205)
```
`EcosystemEngine._enabled` defaults to `is_flag_on("TEX_ECOSYSTEM")` = `os.environ.get("TEX_ECOSYSTEM") == "1"` (`ecosystem_config.py:43`, `engine.py:159/345`). **Default off.** So in a default deployment the graph object is live and reachable but receives **no `add_event`/`add_entity` writes** on the request path; only `state_hash` of an empty graph would ever be computed. **Verdict: graph = LIVE-but-conditional (writes require `TEX_ECOSYSTEM=1`).**

**db.connection (LIVE indirectly):** each Postgres store/mirror is built in `build_runtime`; on construction it calls `resolve_dsn` and either logs "in-memory mode" (no `DATABASE_URL`) or ensures schema. With `DATABASE_URL` set, `with_connection` is on the write path of the action ledger, evidence mirror, precedent store, and provenance proofs. **Verdict: LIVE (active only when `DATABASE_URL` is set; otherwise the helper resolves to `""` and stores run in-memory).**

### Wiring — Out (dependencies)

**graph →** `networkx` (external); `tex.events._canonical` (`canonical_json`, `canonical_sha256`); `tex.observability.telemetry.emit_event`; `tex.ecosystem.state.EcosystemState` (projection only); `rustworkx` (external, optional). The `tex.ecosystem` dependency from `projection.py` is what creates the **circular import** (see Findings).

**db →** `psycopg` (external), `os`, `logging`, `contextlib`. Zero intra-tex deps.

**retrieval →** `tex.domain.evaluation.EvaluationRequest`, `tex.domain.policy.PolicySnapshot`, `tex.domain.retrieval.{RetrievalContext, RetrievedEntity, RetrievedPolicyClause, RetrievedPrecedent}`. No external libs. (The concrete adapters live in `tex.main` and pull `tex.stores.precedent_store` / `tex.stores.entity_store`.)

---

## Implementation Reality

| Component | Reality |
|---|---|
| `InMemoryTemporalKG` (writes, time-travel, neighbors, state_hash) | **REAL.** Full validation, append-only versioning, bisect time-travel, canonical hashing. No stubs in the read/write core. |
| `StateProjection.project_at` | **REAL** for entity partitioning + state_hash. `aggregate_drift_signals={}` and `sliding_window_compromise_ratio=0.0` are **explicit P1/P2 defaults**, not bugs (`projection.py:95-96`). |
| `GraphQuery` | **REAL** logic, but **dead in production** (test-only importer). |
| `rustworkx_backend` | **REAL** conditional impl with a genuine networkx fallback; `available()` returns False unless rustworkx is installed. `_rx_*` paths are `# pragma: no cover`. **Dead in production** (test-only importer). Default-active path is the pure-networkx fallback. |
| `db.connection` | **REAL.** Every function is substantive. No pool (acknowledged, not stubbed). |
| `RetrievalOrchestrator` + policy-clause adapter | **REAL.** `InMemoryPolicyClauseStoreAdapter` (`main.py:290-411`) projects blocked terms, sensitive entities, enabled recognizers, and policy description into ranked `RetrievedPolicyClause`s with substring-based relevance scoring. Precedent adapter delegates to a real `InMemoryPrecedentStore.find_similar`. |
| **Entity grounding (live path)** | **BROKEN AT RUNTIME.** See Findings. The orchestrator calls `entity_store.retrieve_entities(request=..., policy=..., top_k=...)` (`orchestrator.py:166-170`) but the wired `InMemoryEntityStoreAdapter.retrieve_entities` is declared `(*, request, limit)` (`main.py:452-461`). Runtime raises `TypeError: ... unexpected keyword argument 'policy'`, swallowed into a `entity_retrieval_failed:TypeError` warning. Entities are always empty in the live runtime. |
| NoOp stores / `build_noop_retrieval_orchestrator` | **REAL** (intentional empty defaults). |

**TODO/stub markers found (none are NotImplementedError):**
- `temporal_kg.py` has many `TODO(P0): ... [done]` markers (e.g. lines 119, 196-197, 286, 313, 353) — all annotated `[done]`. Genuine forward-looking `TODO(P1)`/`TODO(P2)` (pgvector column line 120/198, drift signals line 354, RFC-8785 number serialization line 355) are unimplemented but clearly labelled.
- No `NotImplementedError`, no bare `pass`-only bodies, no `raise NotImplementedError` anywhere in scope.

---

## Technology

- **Temporal/property graph** over `networkx.MultiDiGraph` — append-only events as edges, versioned entity snapshots, time-travel via `bisect`. Docstring cites **Zep / Graphiti** temporal-aware KG and **arxiv 2602.05665** (Graph-based Agent Memory) as references (`temporal_kg.py:37-39`) — *(citations, unverified)*.
- **Deterministic canonical hashing** — SHA-256 over an RFC-8785-subset canonical JSON (`tex.events._canonical`), float-rejecting, schema-versioned, with a pinned empty-graph hash. This is the reproducibility/audit primitive.
- **rustworkx (Rust-backed) optional acceleration** for BFS/reachability with a transparent networkx fallback; edge-kind carried as the rustworkx edge weight to survive MultiDiGraph parallel edges (`rustworkx_backend.py:197-201`). Docstring claims 5-50× speedups and "first published rustworkx integration for an agent governance reference monitor" (`rustworkx_backend.py:11-14, 37-39`) — *(marketing claims, unverified)*.
- **libpq hardening** — mandatory `connect_timeout` + `statement_timeout` + `lock_timeout` to prevent a single-worker wedge (`connection.py:44-56, 108-114`). Sound operational engineering.
- **Contract-first RAG** — `Protocol`-based store contracts, fail-soft warning accumulation, policy-snapshot-as-corpus projection. Deliberately *not* a vector/embedding RAG (no pgvector wired here; pgvector is a `TODO(P1)` in the TKG docstring).

---

## Persistence

- **graph:** purely **in-memory**. `_graph`, `_versions`, `_events_by_id` are process-lifetime Python objects (`temporal_kg.py:95-103`). `main.py:905-909` confirms "fresh instance per process … Postgres-backed graph state is a Thread-9+ concern" — no durable graph backend exists. State is lost on restart.
- **db.connection:** the durability *enabler* but stateless itself. Durable state lives in Postgres **only when `DATABASE_URL` is set**; the stores that use it are write-through caches (in-memory authoritative + synchronous Postgres flush, per `connection.py:1-9` docstring). With no `DATABASE_URL`, everything is in-memory and logs "in-memory mode" at startup (observed in import smoke test).
- **retrieval:** **stateless** orchestrator. The precedent/entity adapters read from in-memory stores (`InMemoryPrecedentStore`, `InMemoryEntityStore`); the policy-clause adapter holds no state (`__slots__ = ()`, `main.py:305`) and projects from the live `PolicySnapshot` each call. No retrieval index is persisted.

---

## Notable Findings

1. **Entity retrieval is silently dead in the live runtime (keyword-arg mismatch).** `RetrievalOrchestrator._retrieve_entities` calls `retrieve_entities(request=..., policy=..., top_k=...)` (`orchestrator.py:166-170`), but the wired adapter `InMemoryEntityStoreAdapter.retrieve_entities` is `(*, request, limit)` (`main.py:452-461`). Verified at runtime: `TypeError: InMemoryEntityStoreAdapter.retrieve_entities() got an unexpected keyword argument 'policy'`. The broad `except Exception` (`orchestrator.py:171`) downgrades it to a `entity_retrieval_failed:TypeError` warning, so the request still succeeds — but the PDP **never receives entity grounding** in production. The `EntityStore` Protocol itself declares `(*, request, policy, top_k)` (`orchestrator.py:43-50`), so the *protocol* and the *adapter* disagree; the orchestrator follows the protocol, the wiring violates it. The tests in `tests/test_retrieval.py` use this same buggy adapter (line 17/32) but only assert structural well-formedness (`hasattr`, `isinstance ... tuple`, lines 53-69) and never that entities are non-empty — so the bug is invisible to the suite.

2. **`tex.graph` is not directly importable due to a circular import.** `import tex.graph` fails: `graph/__init__.py:35` → `projection.py:27` (`from tex.ecosystem.state import EcosystemState`) → `tex.ecosystem.__init__` → `bridge` → `engine` → `engine.py:86 from tex.graph.projection import StateProjection` (partially initialized) → `ImportError`. It only resolves when `tex.ecosystem` is imported first, which `tex.main` happens to do. `engine.py:104-111` already defers its `InMemoryTemporalKG` import to dodge a related cycle. Fragile: any code that does a bare `from tex.graph import ...` before `tex.ecosystem` is loaded will crash. Confirmed by smoke test (direct import fails; ecosystem-first ordering succeeds).

3. **Graph writes are gated off by default.** The TKG is "LIVE" by reachability but only accretes events when `TEX_ECOSYSTEM=1` (`engine.py:345/488`, `ecosystem_config.py:43`). On a stock deploy the graph stays empty; `add_event`/`add_entity` are never reached via the request path. The spine classification `graph=LIVE` is true for *construction and reachability* but overstates *operational use* — worth flagging against any claim that the temporal KG is actively recording ecosystem events in production.

4. **The digital twin never uses the TKG it's typed against.** `digital_twin.py:59,252` types/accepts an `InMemoryTemporalKG`, and its `_compute_state_hash` path calls `graph.state_hash` (`digital_twin.py:641`), but `main.py:1066` constructs `EcosystemDigitalTwin()` with **no graph** (comment 1059-1065: "We do NOT pass a temporal-KG handle today"). The twin route falls back to `state_hash="ecosystem_no_graph"` (`digital_twin.py:626`). So the twin↔graph integration is wired in types but inert at runtime.

5. **`GraphQuery` and `rustworkx_backend` are production-dead.** Despite substantive, correct implementations (find_paths, causal_ancestors, Rust BFS), the **only** importers are tests. `causal_ancestors` overlaps conceptually with `tex.causal._provenance_graph` (which built its own independent `networkx.DiGraph`, `_provenance_graph.py:156, 249`) — there are two separate graph/lineage implementations and the causal one, not the `graph/` one, is what's wired. The `tex.graph` lineage code is effectively a parallel, unused track.

6. **Docstring vs reality (graph/__init__.py).** The package docstring claims "in-memory backend wired; rustworkx/postgres/janusgraph backends test-only or orphan" (`__init__.py:2`) — this is **accurate and confirmed** (a rare case where the docstring matches: rustworkx test-only, no Postgres/JanusGraph backend exists at all in scope).

7. **No connection pool, by design.** `connection.py:19-25` claims a pool is a future one-file change. Confirmed unimplemented (every store opens a fresh per-write connection). Not a bug, but a scaling ceiling the docstring is honest about.

8. **Marketing claims in `rustworkx_backend.py`** ("first published rustworkx integration for an agent governance reference monitor", "no agent-governance product uses it; Microsoft Agent Governance Toolkit still ships networkx", `rustworkx_backend.py:11-14, 37-39`) are unverifiable competitive assertions embedded in a module that isn't even wired into the running app. Label as (claim, unverified).

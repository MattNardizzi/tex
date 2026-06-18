# Tex Mechanical Reachability / Import Graph

> Ground-truth static reachability of every subsystem under `src/tex/`.
> Built by AST-parsing all 636 `.py` files and BFS-ing the import edges from the
> live entrypoints. NOT from docstrings/markdown. Branch: `feat/proof-carrying-gate`.
> Generated 2026-06-18. Modules: 636. Subsystems: 57.

## Method

- **LIVE entrypoints (seeds):** `tex.main` (contains `create_app` at main.py:1309 and
  `build_runtime` at main.py:519, including all function-local imports) UNION every module
  under `tex.api.*` (routers mounted by `create_app`).
- A subsystem is **LIVE** iff at least one of its modules is in the transitive import
  closure (BFS) of those seeds. **INDIRECT** = not live, but imported by another (non-live)
  subsystem. **DEMO_TEST_ONLY** = imported only from `tests/`, `scripts/`, `demos/`.
  **ORPHAN** = zero importers anywhere.
- Edge resolution fix applied: `from pkg import submodule` resolves to the *submodule
  `pkg.submodule`* when it exists on disk (Python imports the submodule even when the
  package `__init__` does not re-export it). Without this fix `voice` was falsely ORPHANed.
- Sanity: `import tex.main` succeeds; `create_app`/`build_runtime` present. reach(main)=418,
  reach(api)=419, reach(main|api)=419 of 636 modules.

## Classification table

| subsystem | #files | #src-importers | from-main? | from-api? | status | one-line evidence |
|---|---|---|---|---|---|---|
| `_pending` | 33 | 0 | no | no | **ORPHAN** | zero importers anywhere in src/tests/scripts |
| `_root (tex.main, config.py, ecosystem_config.py, frontier_config.py)` | 62 | 47 | YES | YES | **LIVE** | reachable; e.g. tex.api.incident_routes -> tex.nanozk |
| `adversarial` | 7 | 4 | no | no | **INDIRECT** | imported only by non-live subsystems: _root,capstone |
| `agent` | 4 | 2 | YES | YES | **LIVE** | reachable; e.g. tex.engine.pdp -> tex.agent.behavioral_evaluator |
| `api` | 29 | 4 | YES | YES | **LIVE** | reachable; e.g. tex.main -> tex.api.governance_history_routes |
| `bench` | 13 | 6 | no | no | **INDIRECT** | imported only by non-live subsystems: adversarial,capstone,voice |
| `c2pa` | 16 | 8 | YES | YES | **LIVE** | reachable; e.g. tex.evidence.scitt_statement -> tex.c2pa._cbor |
| `camel` | 6 | 5 | YES | YES | **LIVE** | reachable; e.g. tex.specialists.camel_specialist -> tex.camel.policy |
| `capstone` | 5 | 1 | no | no | **INDIRECT** | imported only by non-live subsystems: _root |
| `causal` | 12 | 3 | YES | YES | **LIVE** | reachable; e.g. tex.api.incident_routes -> tex.causal.attribution_engine |
| `commands` | 5 | 5 | YES | YES | **LIVE** | reachable; e.g. tex.enforcement.transport -> tex.commands.evaluate_action |
| `compliance` | 13 | 0 | no | no | **DEMO_TEST_ONLY** | imported only by tests/ (2 files); no src importer |
| `contracts` | 8 | 8 | YES | YES | **LIVE** | reachable; e.g. tex.engine.pdp -> tex.contracts.runtime_enforcement |
| `db` | 1 | 5 | YES | YES | **LIVE** | reachable; e.g. tex.evidence.postgres_mirror -> tex.db.connection |
| `deterministic` | 3 | 7 | YES | YES | **LIVE** | reachable; e.g. tex.engine.pdp -> tex.deterministic.gate |
| `discovery` | 52 | 7 | YES | YES | **LIVE** | reachable; e.g. tex.sim.connectors -> tex.discovery.connectors.entra_consent_graph |
| `domain` | 22 | 175 | YES | YES | **LIVE** | reachable; e.g. tex.enforcement.transport -> tex.domain.evaluation |
| `drift` | 7 | 5 | YES | YES | **LIVE** | reachable; e.g. tex.learning.trigger -> tex.drift._anytime_valid |
| `ecosystem` | 7 | 21 | YES | YES | **LIVE** | reachable; e.g. tex.ontology.validator -> tex.ecosystem.proposed_event |
| `enforcement` | 7 | 3 | YES | YES | **LIVE** | reachable; e.g. tex.main -> tex.enforcement.standing_transport |
| `engine` | 11 | 17 | YES | YES | **LIVE** | reachable; e.g. tex.ecosystem.bridge -> tex.engine.router |
| `events` | 6 | 23 | YES | YES | **LIVE** | reachable; e.g. tex.institutional.governance_log -> tex.events._ecdsa_provider |
| `evidence` | 12 | 19 | YES | YES | **LIVE** | reachable; e.g. tex.api.incident_routes -> tex.evidence.attribution_zk |
| `gateway` | 3 | 1 | YES | YES | **LIVE** | reachable; e.g. tex.api.voice_routes -> tex.gateway.grant |
| `governance` | 20 | 7 | YES | YES | **LIVE** | reachable; e.g. tex.contracts.rv4_path -> tex.governance.path_policy.ltlf |
| `graph` | 5 | 4 | YES | YES | **LIVE** | reachable; e.g. tex.main -> tex.graph.projection |
| `institutional` | 7 | 2 | YES | YES | **LIVE** | reachable; e.g. tex.ecosystem.engine -> tex.institutional.subagent_inheritance |
| `interchange` | 5 | 8 | YES | YES | **LIVE** | reachable; e.g. tex.main -> tex.interchange.gix |
| `intervention` | 6 | 2 | YES | YES | **LIVE** | reachable; e.g. tex.ecosystem.engine -> tex.intervention.restorative |
| `learning` | 15 | 8 | YES | YES | **LIVE** | reachable; e.g. tex.api.routes -> tex.learning.drift |
| `memory` | 9 | 1 | YES | YES | **LIVE** | reachable; e.g. tex.memory -> tex.memory.system |
| `nanozk` | 12 | 1 | YES | YES | **LIVE** | reachable; e.g. tex.nanozk -> tex.nanozk.poseidon_chain |
| `observability` | 4 | 100 | YES | YES | **LIVE** | reachable; e.g. tex.intervention.restorative -> tex.observability.telemetry |
| `ontology` | 7 | 5 | YES | YES | **LIVE** | reachable; e.g. tex.ecosystem.bridge -> tex.ontology.event_types |
| `operator` | 4 | 0 | no | no | **ORPHAN** | zero importers anywhere in src/tests/scripts |
| `pcas` | 12 | 2 | YES | YES | **LIVE** | reachable; e.g. tex.specialists.pcas_specialist -> tex.pcas.graph.adapter |
| `pep` | 3 | 0 | no | no | **ORPHAN** | zero importers anywhere in src/tests/scripts |
| `policies` | 1 | 3 | YES | YES | **LIVE** | reachable; e.g. tex.main -> tex.policies.defaults |
| `pqcrypto` | 19 | 42 | YES | YES | **LIVE** | reachable; e.g. tex.api.incident_routes -> tex.pqcrypto.algorithm_agility |
| `provenance` | 14 | 19 | YES | YES | **LIVE** | reachable; e.g. tex.engine.pdp -> tex.provenance.attempt_seal |
| `receipts` | 4 | 2 | no | no | **INDIRECT** | imported only by non-live subsystems: _pending,_root |
| `retrieval` | 1 | 2 | YES | YES | **LIVE** | reachable; e.g. tex.engine.pdp -> tex.retrieval.orchestrator |
| `runtime` | 16 | 5 | YES | YES | **LIVE** | reachable; e.g. tex.specialists.clawguard_specialist -> tex.runtime.clawguard.boundary_enforcer |
| `safeflow` | 4 | 1 | no | no | **INDIRECT** | imported only by non-live subsystems: _root |
| `selfgov` | 1 | 9 | YES | YES | **LIVE** | reachable; e.g. tex.learning.feedback_loop -> tex.selfgov.governor |
| `semantic` | 5 | 6 | YES | YES | **LIVE** | reachable; e.g. tex.engine.pdp -> tex.semantic.schema |
| `sim` | 13 | 2 | YES | YES | **LIVE** | reachable; e.g. tex.main -> tex.sim.connectors |
| `specialists` | 25 | 7 | YES | YES | **LIVE** | reachable; e.g. tex.engine.pdp -> tex.specialists.judges |
| `stores` | 20 | 20 | YES | YES | **LIVE** | reachable; e.g. tex.learning.feedback_loop -> tex.stores.calibration_proposal_store |
| `systemic` | 8 | 4 | YES | YES | **LIVE** | reachable; e.g. tex.engine.pdp -> tex.systemic.probguard |
| `tee` | 7 | 5 | YES | YES | **LIVE** | reachable; e.g. tex.api.tee_routes -> tex.tee.h100_attestation |
| `verifier` | 3 | 1 | no | no | **INDIRECT** | imported only by non-live subsystems: _root |
| `vet` | 10 | 2 | YES | YES | **LIVE** | reachable; e.g. tex.api.vet_routes -> tex.vet.web_proofs |
| `vigil` | 14 | 3 | YES | YES | **LIVE** | reachable; e.g. tex.voice.answer_forms -> tex.vigil.utterances |
| `voice` | 6 | 7 | YES | YES | **LIVE** | reachable; e.g. tex.api.voice_routes -> tex.voice.voice_ask |
| `zkpdp` | 1 | 4 | no | no | **INDIRECT** | imported only by non-live subsystems: _root,capstone |
| `zkprov` | 11 | 6 | YES | YES | **LIVE** | reachable; e.g. tex.api.zkprov_routes -> tex.zkprov.backends |

**Totals:** LIVE=46, INDIRECT=7, DEMO_TEST_ONLY=1, ORPHAN=3 (of 57 subsystems incl. `_root`).

## The non-live cluster (resolves the "how many are wired" confusion)

Exactly **8 of the ~57 subsystems are NOT reachable** from the running app:

- **ORPHAN (3)** — zero importers anywhere (`grep` confirms no `from tex.X` outside the package):
  - `_pending` (33 files) — staging area: pitch decks, a2a interop, alt api routes. Self-contained island.
  - `operator` (4 files) — k8s-style controller/webhook/scope with its own `__main__`; nothing imports it.
  - `pep` (3 files) — standalone Policy Enforcement Point proxy + `__main__`; the LIVE in-process gate is
    `enforcement.standing_transport`, NOT this `pep/` package.
- **INDIRECT / DEMO (5)** — only reachable through the non-live `capstone` composition layer or tests:
  - `capstone` (5) — end-to-end composition/tamper harness; imported only by `scripts/capstone_demo.py` + tests.
  - `adversarial` (7), `bench` (13) — fuzzers / benchmark corpora; pulled in by `capstone` + scripts/tests.
  - `zkpdp` (1, `arbiter`) — pulled in by `capstone` + tests only; no live importer.
  - `receipts` (4), `safeflow` (4), `verifier` (3) — self-contained packages whose only importers are
    their own `__init__`/`__main__`, `_pending`, or `tests/` (`compliance` likewise: tests-only).

Everything else (49 subsystems) is genuinely on a call path from `create_app`/`build_runtime` or an `api/` router.

## Directed import-edge summary

### Most depended-on subsystems (by # of distinct importing subsystems)

- **`domain`** <- 34 subsystems
- **`observability`** <- 24 subsystems
- **`_root`** <- 22 subsystems
- **`pqcrypto`** <- 16 subsystems
- **`ecosystem`** <- 14 subsystems
- **`events`** <- 13 subsystems
- **`provenance`** <- 13 subsystems
- **`engine`** <- 11 subsystems
- **`evidence`** <- 9 subsystems
- **`selfgov`** <- 8 subsystems
- **`stores`** <- 8 subsystems
- **`contracts`** <- 6 subsystems
- **`governance`** <- 6 subsystems
- **`zkprov`** <- 6 subsystems

`domain` is the universal vocabulary (verdicts, policy, evaluation dataclasses); `observability`
is the universal telemetry sink; `pqcrypto` is the shared crypto spine; `provenance`/`events`/
`evidence` form the sealing core. These four-ish hubs are the load-bearing center of the graph.

### Top weighted edges (src -> dst : # of file-level import edges)

- `discovery` -> `domain` : 56
- `specialists` -> `domain` : 48
- `engine` -> `domain` : 36
- `learning` -> `domain` : 35
- `_root` -> `api` : 24
- `api` -> `domain` : 22
- `stores` -> `domain` : 21
- `_root` -> `discovery` : 18
- `agent` -> `domain` : 18
- `_root` -> `stores` : 18
- `provenance` -> `domain` : 15
- `pqcrypto` -> `observability` : 14
- `specialists` -> `observability` : 14
- `_root` -> `c2pa` : 13
- `_root` -> `learning` : 13
- `capstone` -> `voice` : 12
- `commands` -> `domain` : 12
- `_root` -> `nanozk` : 12

### Cycles (mutual subsystem dependencies)

The graph is heavily cyclic at the subsystem level (a single conceptual core split across folders).
Notable 2-cycles (mutual deps), most via shared dataclasses and back-references:

`interchange` <-> `provenance`, `deterministic` <-> `domain`, `api` <-> `_root`, `governance` <-> `_root`, `ecosystem` <-> `observability`, `ecosystem` <-> `engine`, `ecosystem` <-> `ontology`, `pqcrypto` <-> `_root`, `sim` <-> `_root`, `learning` <-> `domain`, `provenance` <-> `pqcrypto`, `adversarial` <-> `_root`, `institutional` <-> `ecosystem`, `_root` <-> `selfgov`, `pqcrypto` <-> `events`, `provenance` <-> `enforcement`, `c2pa` <-> `_root`, `engine` <-> `systemic`, `engine` <-> `deterministic`, `engine` <-> `pqcrypto`, `engine` <-> `provenance`, `engine` <-> `contracts`, `ecosystem` <-> `events`, `evidence` <-> `_root`, `specialists` <-> `domain`, `_root` <-> `systemic`, `engine` <-> `_root`, `_root` <-> `zkprov`, `tee` <-> `_root`, `_root` <-> `vigil`, `_root` <-> `stores`, `_root` <-> `ecosystem`, `_root` <-> `commands`, `drift` <-> `ecosystem`, `ecosystem` <-> `graph`, `semantic` <-> `domain`

The densest knot is around **`engine`** (mutual with `deterministic`, `provenance`, `systemic`,
`contracts`, `pqcrypto`, `_root`) and **`ecosystem`** (mutual with `ontology`, `engine`,
`observability`, `events`, `graph`, `institutional`, `drift`) — these are the two integration hubs.

## Crypto / ZK reality check (real vs hollow)

All on a LIVE path, and REAL (graceful-fallback, not hollow stubs) per code inspection:

- `pqcrypto/ml_dsa.py` — real backend cascade: pyca `cryptography` ML-DSA -> `liboqs` -> **fail-closed**
  `RuntimeError` when no native lib (ml_dsa.py:233-263). The 15 `NotImplementedError` hits are
  abstract-base / unregistered-algorithm guards, not hollow bodies.
- `pqcrypto/ml_kem.py:356` — `NotImplementedError` is a provider-registry guard ("No KEM provider
  registered"), i.e. fail-closed, not a stub.
- `nanozk`, `zkprov`, `tee`, `verifier` — **0** `NotImplementedError`. `c2pa` has 5 (interface guards).
- These match the audit ground-truth: the offline-verifiable evidence/crypto spine is real.

## Flags (wiring nuances worth knowing)

- **Proof-carrying-gate seal not yet on the live path.** `enforcement.standing_transport`
  (the standing-governance gate) IS wired at `main.py:1754-1756`. But the Phase-0 seal modules
  `enforcement/seal.py` and `provenance/enforcement_seal.py` are **NOT reachable** from main/api
  (live=False). So the `enforcement` subsystem is LIVE, but its proof-carrying *seal* file is not
  yet invoked by the running app on this branch.
- **`voice` is LIVE but only via one edge:** `api/voice_routes.py:41 from tex.voice import voice_ask`,
  router mounted at `main.py:1459`. The voice package `__init__` is empty (`__all__=[]`), so
  naive import-graph tools that don't resolve submodules will falsely report `voice` as ORPHAN.
- **`sim` is LIVE** only through a function-local import in `build_runtime`
  (`main.py:1882 from tex.sim.connectors import build_sandbox_connectors`) — sandbox-connector path.
- **`db` (1 file)** is LIVE via `evidence`/`stores` Postgres mirrors, but Postgres is opt-in
  (DATABASE_URL); default run is in-memory, so the live import exists but the code path is dormant.

## Full file enumeration (every .py, with live flag)

Legend: `[L]`=on live path, `[.]`=not reachable from main/api.

### `_pending` — ORPHAN (33 files)
- `[.]` `_pending.api` — [Architecture: Pending] — API routes parked alongside their layer code.
- `[.]` `_pending.api.pitch_routes` — Thread 4 — Layer 5 Export HTTP Routes
- `[.]` `_pending.compliance` — [Architecture: Pending] — compliance jurisdictions that are scaffolded but not yet impleme
- `[.]` `_pending.compliance.naic` — [Architecture: Pending] — NAIC (insurance) compliance stubs.
- `[.]` `_pending.compliance.naic.cyber_rider` — Cyber Insurance AI Rider Documentation.
- `[.]` `_pending.compliance.naic.model_bulletin` — NAIC Model Bulletin on AI alignment.
- `[.]` `_pending.compliance.nist` — [Architecture: Pending] — NIST compliance stubs.
- `[.]` `_pending.compliance.nist.agent_standards` — NIST AI Agent Standards Initiative (February 2026) alignment.
- `[.]` `_pending.compliance.nist.ai_rmf` — NIST AI Risk Management Framework alignment.
- `[.]` `_pending.events` — [Architecture: Pending] — events extension stubs that aren't wired.
- `[.]` `_pending.events.quorum_shard` — Quorum-replicated ledger shards.
- `[.]` `_pending.graph` — [Architecture: Pending] — graph backend stubs that aren't wired.
- `[.]` `_pending.graph.janusgraph_backend` — JanusGraph backend stub.
- `[.]` `_pending.graph.postgres_backend` — Postgres + pgvector temporal knowledge graph backend.
- `[.]` `_pending.interop` — Interop Layer
- `[.]` `_pending.interop.a2a` — A2A (Agent-to-Agent) Protocol Integration.
- `[.]` `_pending.interop.a2a.bus_listener` — A2A Bus Listener.
- `[.]` `_pending.interop.a2a.signed_agent_card` — A2A Signed Agent Cards.
- `[.]` `_pending.interop.microsoft` — Microsoft Agent Governance Toolkit — integration stub.
- `[.]` `_pending.interop.microsoft.policy_bundle_exporter` — Export Tex policies to Microsoft Agent Governance Toolkit format.
- `[.]` `_pending.interop.nist` — NIST AI Agent Standards Initiative — alignment.
- `[.]` `_pending.interop.nist.self_assessment` — NIST AI Agent Standards self-assessment artifact emitter.
- `[.]` `_pending.interop.okta` — Okta for AI Agents — integration stub.
- `[.]` `_pending.interop.okta.agent_identity_sync` — Sync Okta agent identities into Tex.
- `[.]` `_pending.interop.ping` — Ping Agent Gateway — integration stub.
- `[.]` `_pending.interop.ping.verdict_publisher` — Publish Tex verdicts to Ping Agent Gateway.
- `[.]` `_pending.pitch` — [Architecture: Layer 5 (Evidence)] — audience-specific evidence exports — VP Marketing, CI
- `[.]` `_pending.pitch._compliance_corpus` — Curated regulatory corpus used by the dual-ICP dossier surfaces.
- `[.]` `_pending.pitch._intel` — Deterministic intelligence helpers used by both VP-Marketing and CISO
- `[.]` `_pending.pitch.ciso` — CISO pitch surface.
- `[.]` `_pending.pitch.insurer_export` — Insurer-Verifiable Evidence Packet.
- `[.]` `_pending.pitch.verifier` — Independent verifier for the insurer evidence packet.
- `[.]` `_pending.pitch.vp_marketing` — VP Marketing / Head of Brand pitch surface.

### `_root` — LIVE (62 files)
- `[.]` `tex` — 
- `[.]` `_pending` — [Architecture: Pending] — parked work — interop stubs for A2A, Okta, Microsoft, NIST, Ping
- `[.]` `adversarial` — [Architecture: Tooling] — fuzz testing harness — runs AgentDojo, MCPSafeBench, AgentLAB, S
- `[.]` `agent` — [Architecture: Layer 2 (Identity)] — agent identity, capability, and behavioral evaluators
- `[L]` `api` — [Architecture: Cross-cutting (HTTP)] — 22 routers spanning all six layers — ~80 endpoints
- `[.]` `bench` — [Architecture: Tooling] — AgentDojo benchmark harness — invokable as `python -m tex.bench.
- `[L]` `c2pa` — [Architecture: Layer 5 (Evidence)] — C2PA Content Credentials emission for PERMIT-with-out
- `[.]` `camel` — [Architecture: Layer 4 (Execution Governance)] — CamEL capability-based interpreter invoke
- `[.]` `capstone` — Tex capstone composition — one sealed verdict object, offline-verifiable,
- `[.]` `causal` — [Architecture: Layer 4 (Execution Governance)] — causal attribution engine for incidents —
- `[.]` `commands` — [Architecture: Layer 4 (Execution Governance)] — use-case command handlers — evaluate, out
- `[.]` `compliance` — [Architecture: Layer 5 (Evidence)] — regulatory evidence emitters — EU AI Act, FTC, Califo
- `[L]` `config` — 
- `[L]` `contracts` — [Architecture: Layer 4 (Execution Governance)] — LTLf behavioral contracts that gate the P
- `[.]` `db` — [Architecture: Cross-cutting (Persistence)] — shared Postgres connection management and le
- `[.]` `deterministic` — [Architecture: Layer 4 (Execution Governance)] — regex/rule deterministic gate — Stream 1 
- `[.]` `discovery` — [Architecture: Layer 1 (Discovery)] — scan tenants for AI agents across OpenAI, Slack, AWS
- `[.]` `domain` — [Architecture: Cross-cutting (Domain model)] — Pydantic models for EvaluationRequest, Deci
- `[.]` `drift` — [Architecture: Layer 4 (Execution Governance)] — drift detection — wired via ecosystem eng
- `[.]` `ecosystem` — [Architecture: Layer 4 (Execution Governance)] — eight-step ecosystem engine that wraps th
- `[L]` `ecosystem_config` — Ecosystem-layer feature flags.
- `[.]` `enforcement` — [Architecture: Layer 4 (Execution Governance)] — TexGate, @tex_gated decorator, framework 
- `[.]` `engine` — [Architecture: Layer 4 (Execution Governance)] — the Policy Decision Point — runs the seve
- `[.]` `events` — [Architecture: Layer 5 (Evidence)] — append-only event ledger with ECDSA-P256 signature pr
- `[L]` `evidence` — [Architecture: Layer 5 (Evidence)] — the canonical hash-chained evidence chain (JSONL + Po
- `[.]` `frontier_config` — Frontier-stack feature-flag configuration.
- `[L]` `gateway` — [Architecture: Cross-cutting (Voice infrastructure)] — Tex's self-hosted speech gateway.
- `[.]` `governance` — [Architecture: Layer 4 (Execution Governance)] — deeper governance subpackages — path_poli
- `[.]` `graph` — [Architecture: Cross-cutting (Persistence)] — temporal knowledge graph — in-memory backend
- `[.]` `institutional` — [Architecture: Layer 4 (Execution Governance)] — governance LTS — wired via ecosystem engi
- `[.]` `interchange` — Inter-org governance interchange (Wave 2 / L6) — GIX.
- `[.]` `intervention` — [Architecture: Layer 4 (Execution Governance)] — intervention selection — wired via ecosys
- `[.]` `learning` — [Architecture: Layer 6 (Learning)] — outcome validation, reporter reputation, calibration 
- `[L]` `main` — 
- `[L]` `memory` — [Architecture: Layer 5 (Evidence)] — V18 unified durable store — DurableDecisionStore, Dur
- `[L]` `nanozk` — ==================== DEACTIVATED PLACEHOLDER (research-early) ====================
- `[L]` `observability` — [Architecture: Layer 3 (Monitoring)] — OpenTelemetry telemetry and discovery metrics
- `[L]` `ontology` — [Architecture: Layer 4 (Execution Governance)] — entity/event ontology validator used by t
- `[.]` `operator` — tex.operator — auto-deploy and auto-enroll for the PEP, the ambient way.
- `[.]` `pcas` — [Architecture: Layer 4 (Execution Governance)] — PCAS Datalog policy compiler invoked by s
- `[.]` `pep` — tex.pep — Policy Enforcement Points.
- `[.]` `policies` — [Architecture: Layer 4 (Execution Governance)] — default policy snapshots
- `[L]` `pqcrypto` — [Architecture: Layer 5 (Evidence)] — post-quantum signing infrastructure — ML-DSA primary 
- `[.]` `proofs` — [Architecture: Empty placeholder] — reserved for future proof types — no code yet
- `[L]` `provenance` — tex.provenance — identity by behaviour, sealed as proof.
- `[.]` `receipts` — [Architecture: Layer 5 (Evidence)] — HMAC tool receipts emitted alongside evidence records
- `[.]` `retrieval` — [Architecture: Layer 4 (Execution Governance)] — RAG grounding for policy clauses, entitie
- `[.]` `runtime` — [Architecture: Layer 4 (Execution Governance)] — runtime defense modules invoked by their 
- `[.]` `safeflow` — [Architecture: Layer 4 (Execution Governance)] — transactional execution with WAL — built 
- `[.]` `selfgov` — Reflexive self-governance (Wave 2 / L5) — Tex governing its OWN controller
- `[.]` `semantic` — [Architecture: Layer 4 (Execution Governance)] — LLM judge with deterministic fallback — S
- `[L]` `sim` — tex.sim — the Tex sandbox simulator.
- `[L]` `specialists` — [Architecture: Layer 4 (Execution Governance)] — 17 specialist judges that contribute risk
- `[.]` `stores` — [Architecture: Cross-cutting (Persistence)] — InMemory and Postgres implementations of eve
- `[.]` `systemic` — [Architecture: Layer 4 (Execution Governance)] — systemic risk and digital-twin simulation
- `[L]` `tee` — [Architecture: Layer 5 (Evidence)] — TEE attestation composition — Intel TDX + NVIDIA H100
- `[.]` `verifier` — tex.verifier — the standalone offline verdict checker.
- `[.]` `vet` — [Architecture: Layer 5 (Evidence)] — Verifiable Evidence Trail — Web Proofs, AID, SCITT, S
- `[L]` `vigil` — [Architecture: Cross-cutting (Vigil cognition)] — the layer that decides
- `[L]` `voice` — [Architecture: Cross-cutting (Voice cognition)] — the grounded spoken-answer cascade.
- `[.]` `zkpdp` — zkPDP (Wave 2 / L1) — proof-carrying verdict over the arbitration relation.
- `[L]` `zkprov` — [Architecture: Layer 5 (Evidence)] — zero-knowledge dataset and inference provenance proof

### `adversarial` — INDIRECT (7 files)
- `[.]` `adversarial.__main__` — CI entrypoint for the adaptive red-team harness.
- `[.]` `adversarial.adaptive` — Adaptive red-team harness — "the attacker moves second."
- `[.]` `adversarial.adaptive_seeds` — Adapters and a default seed corpus for the adaptive red-team harness.
- `[.]` `adversarial.completeness` — Adversary-exposure certificate over an attacker-moves-second campaign.
- `[.]` `adversarial.fixtures` — Adversarial Fixture Library.
- `[.]` `adversarial.fuzz_runner` — Fuzz Runner.
- `[.]` `adversarial.seal` — Seal an adaptive red-team campaign into the evidence chain.

### `agent` — LIVE (4 files)
- `[L]` `agent.behavioral_evaluator` — Behavioral evaluation stream.
- `[L]` `agent.capability_evaluator` — Capability evaluation stream.
- `[L]` `agent.identity_evaluator` — Identity evaluation stream.
- `[L]` `agent.suite` — Agent evaluation suite.

### `api` — LIVE (29 files)
- `[L]` `api.agent_routes` — Agent governance HTTP routes.
- `[L]` `api.auth` — API-key authentication for Tex's external integration surface.
- `[L]` `api.c2pa_routes` — C2PA Content Credentials HTTP surface (Thread 5).
- `[L]` `api.conduit_routes` — Conduit connect routes — the "Connect your directory" front door.
- `[L]` `api.cors` — CORS configuration for the Tex API.
- `[L]` `api.discovery_routes` — Discovery HTTP routes.
- `[L]` `api.discovery_surface_routes` — /v1/surface/discovery — the thin voice projection of discovery.
- `[L]` `api.ecosystem_twin_routes` — Twin simulation endpoint — POST /v1/ecosystem/twin/simulate.
- `[L]` `api.governance_history_routes` — V15 governance/observability HTTP routes.
- `[L]` `api.governance_standing_routes` — /v1/govern — the PEP-facing decision surface for standing governance.
- `[L]` `api.guardrail` — Canonical guardrail webhook surface for Tex.
- `[L]` `api.guardrail_adapters` — Layer 2 - native-shape gateway adapter routes.
- `[L]` `api.guardrail_streaming` — Streaming and async evaluation endpoints for Tex.
- `[L]` `api.incident_routes` — Incident attribution endpoint — POST /v1/incidents/{decision_id}/attribute.
- `[L]` `api.learning_routes` — HTTP routes for the V17 Learning/Drift layer.
- `[L]` `api.mcp_server` — Layer 4 - MCP server interface for Tex.
- `[L]` `api.outcome_autoseal` — Auto-seal a human resolution into a labeled, ingested OutcomeRecord.
- `[L]` `api.provenance_routes` — /v1/provenance — the behavioural provenance surface.
- `[L]` `api.rate_limit` — In-memory rate limiter for public leaderboard endpoints.
- `[L]` `api.routes` — 
- `[L]` `api.runtime_store` — In-memory TTL store for async evaluation results and streaming sessions.
- `[L]` `api.schemas` — 
- `[L]` `api.system_state_routes` — System state endpoint.
- `[L]` `api.tee_routes` — ``/v1/tee`` API surface for composite TEE attestation (Thread 12).
- `[L]` `api.tenant_routes` — Tenant content baseline HTTP routes.
- `[L]` `api.vet_routes` — ``/v1/vet`` API surface for Thread 13.
- `[L]` `api.vigil_routes` — GET /v1/vigil — Tex choosing what to say.
- `[L]` `api.voice_routes` — The voice surface — ``/v1/voice/token``, ``/v1/ask``, ``/v1/speak``.
- `[L]` `api.zkprov_routes` — ``/v1/zkprov`` API surface — Thread 14.

### `bench` — INDIRECT (13 files)
- `[.]` `bench.agentdojo` — AgentDojo evaluation harness for Tex.
- `[.]` `bench.agentdojo.__main__` — CLI: ``python -m tex.bench.agentdojo``.
- `[.]` `bench.agentdojo.harness` — AgentDojo task harness.
- `[.]` `bench.agentdojo.pipeline_defense` — TexPipelineDefense — exposes the Tex PDP as an AgentDojo
- `[.]` `bench.evidence_bundle` — Offline evidence bundle — the court-exhibit core.
- `[.]` `bench.forge_target` — The mechanical forge target — the single dare-agnostic entry the public dare
- `[.]` `bench.honest_decline` — The Honest-Decline demo — Tex refuses, and names the fact it is missing.
- `[.]` `bench.replay_trial` — The Replay Trial — Tex's flagship proof-of-superiority demo.
- `[.]` `bench.wave2_corpus` — Wave 2 / M0b — the calibration-corpus harness (ROADMAP.md:241-244).
- `[.]` `bench.wave2_corpus.builders` — Wave 2 / M0b — deterministic synthetic builders for the three consumer contracts.
- `[.]` `bench.wave2_corpus.field_trial` — Wave 2 / M0b — the FIELD neighborhood trial (separate entry point, by design).
- `[.]` `bench.wave2_corpus.loaders` — Wave 2 / M0b — corpus artifact I/O and the kind gate.
- `[.]` `bench.wave2_corpus.provenance` — Wave 2 / M0b — sealed corpus provenance: the anti-honor-system gate.

### `c2pa` — LIVE (16 files)
- `[L]` `c2pa._canonical_claim` — Canonicalization of a C2PA claim for hashing and signing.
- `[L]` `c2pa._cbor` — Minimal deterministic CBOR encoder/decoder for COSE_Sign1.
- `[L]` `c2pa._cose_alg` — COSE algorithm identifier mapping for the C2PA signer/verifier.
- `[L]` `c2pa.attestation` — Hardware-attestation binding for C2PA manifests (Thread 6, Gap 2).
- `[L]` `c2pa.cosign_context_tree` — Merkle context tree for the cosign signing input (Thread 6, Gap 3).
- `[L]` `c2pa.cosign_verifier` — ``tex.evidence_cosign`` verifier — Thread 5.
- `[L]` `c2pa.cpsa_shapes` — CPSA shapes loader + verifier (Thread 6, Gap 3).
- `[L]` `c2pa.durable_credentials` — Durable Content Credentials — multi-layer image marking per C2PA Trust
- `[L]` `c2pa.evidence_emission` — Evidence emission orchestrator — Thread 5 wiring layer.
- `[L]` `c2pa.manifest` — C2PA manifest data model.
- `[L]` `c2pa.ocsp` — OCSP (RFC 6960) stapling for C2PA Content Credentials.
- `[L]` `c2pa.sherman_2026_defenses` — Defenses against the six attack classes documented in Sherman et al.,
- `[L]` `c2pa.signer` — C2PA manifest signer.
- `[L]` `c2pa.timestamp` — RFC 3161 Time-Stamp Authority (TSA) v2 timestamps for C2PA.
- `[L]` `c2pa.verifier` — C2PA manifest verifier.
- `[L]` `c2pa.watermark` — Text watermark detection — Thread 6 (Durable Content Credentials).

### `camel` — LIVE (6 files)
- `[L]` `camel.capability` — CaMeL capability lattice — FIDES dual-axis (integrity × confidentiality).
- `[L]` `camel.interpreter` — CaMeL capability-tracking interpreter.
- `[L]` `camel.plan` — CaMeL plan AST.
- `[L]` `camel.policy` — CaMeL tool policy.
- `[L]` `camel.q_llm` — CaMeL Quarantined-LLM (Q-LLM) interface.
- `[L]` `camel.value` — CaMeL capability-tagged value.

### `capstone` — INDIRECT (5 files)
- `[.]` `capstone.compose` — Capstone composer — takes one driven epoch and emits the sealed bundle dir.
- `[.]` `capstone.flow` — Capstone flow — drives one mixed epoch through a REAL ledger-wired PDP and
- `[.]` `capstone.manifest` — The capstone verdict object — one sealed manifest binding one decision to all
- `[.]` `capstone.tamper` — Capstone tamper matrix — ATTACK SIMULATION ONLY (tests/demo, never a
- `[.]` `capstone.verify` — Offline capstone verifier — files + pins in, named checks out.

### `causal` — LIVE (12 files)
- `[.]` `causal._denial_record` — Denial record — the in-memory representation of a denied tool call,
- `[L]` `causal._hcg` — Hierarchical Causal Graph node + edge types.
- `[L]` `causal._integrity` — Integrity lattice for ARM trust propagation.
- `[L]` `causal._otar` — OTAR parsing — Observation/Thought/Action/Result tuples per CHIEF §4.1.1.
- `[.]` `causal._provenance_graph` — ARM provenance graph.
- `[.]` `causal.arm` — ARM — Agentic Reference Monitor (arxiv 2604.04035, Chinaei, April 2026).
- `[L]` `causal.attribution_engine` — Attribution engine — orchestrates graph + prefill + Shapley over a stored Decision.
- `[L]` `causal.chief` — CHIEF — Hierarchical Causal Graph (arxiv 2602.23701).
- `[L]` `causal.conformal_attribution` — Conformal Agent Error Attribution — uncertainty-aware attribution layer.
- `[L]` `causal.counterfactual` — Counterfactual screener — CHIEF §4.3 progressive causal screening.
- `[L]` `causal.lsh_shapley` — LSH-Shapley blame distribution for per-agent attribution.
- `[L]` `causal.prefill_signals` — Prefill-stage SLM signal extractor for attribution ranking.

### `commands` — LIVE (5 files)
- `[L]` `commands.activate_policy` — 
- `[L]` `commands.calibrate_policy` — 
- `[L]` `commands.evaluate_action` — 
- `[L]` `commands.export_bundle` — 
- `[L]` `commands.report_outcome` — 

### `compliance` — DEMO_TEST_ONLY (13 files)
- `[.]` `compliance._common` — Shared machinery for compliance evidence emitters.
- `[.]` `compliance.eu_ai_act` — EU AI Act compliance bindings.
- `[.]` `compliance.eu_ai_act.article_17` — EU AI Act Article 17: Quality Management System (QMS).
- `[.]` `compliance.eu_ai_act.article_26` — EU AI Act Article 26: Deployer Obligations for High-Risk AI Systems.
- `[.]` `compliance.eu_ai_act.article_50` — EU AI Act Article 50: Transparency for AI-Generated Content.
- `[.]` `compliance.ftc` — FTC compliance bindings.
- `[.]` `compliance.ftc.policy_statement` — FTC §5 AI Substantiation Packet.
- `[.]` `compliance.state` — US state AI law compliance bindings.
- `[.]` `compliance.state.california_ab853_capture` — California AB 853 — Capture Device Manufacturer obligations.
- `[.]` `compliance.state.california_ab853_platforms` — California AB 853 — Large Online Platform obligations.
- `[.]` `compliance.state.california_sb942` — California SB 942 — California AI Transparency Act (CAITA), as amended by
- `[.]` `compliance.state.colorado_ai_act` — Colorado AI Act — SB 24-205, as delayed by SB25B-004.
- `[.]` `compliance.state.new_york_ai_disclosure` — New York AI Advertising Disclosure Law — General Business Law § 1700-A.

### `contracts` — LIVE (8 files)
- `[L]` `contracts._atoms` — Atom resolver for behavioral-contract LTL atoms.
- `[L]` `contracts._ltl` — Mini LTLf evaluator with RV-LTL 4-valued semantics.
- `[L]` `contracts.action_class` — Action-class reversibility × blast-radius structural floor (Wave 2, leap L4).
- `[L]` `contracts.contract` — Behavioral contract specification.
- `[L]` `contracts.rule_of_two` — Rule-of-Two structural contract.
- `[L]` `contracts.runtime_enforcement` — Runtime contract enforcer.
- `[L]` `contracts.rv4_path` — RV4 path-policy bridge — split LTLf path-policy violations into FORBID vs HOLD.
- `[L]` `contracts.violation` — Contract violation record.

### `db` — LIVE (1 files)
- `[L]` `db.connection` — Shared Postgres connection helper for Tex's write-through-cache stores.

### `deterministic` — LIVE (3 files)
- `[L]` `deterministic.cadence` — Autonomous-attack action-cadence circuit-breaker.
- `[L]` `deterministic.gate` — 
- `[L]` `deterministic.recognizers` — 

### `discovery` — LIVE (52 files)
- `[L]` `discovery.alerts` — Real-time alert engine.
- `[.]` `discovery.conduit` — tex-conduit — one read-only "Connect your directory" capability.
- `[L]` `discovery.conduit.broker` — Connect broker — the four-state machine behind the one button.
- `[L]` `discovery.conduit.connector` — The one shared consent-graph connector, parameterized by a ProviderProfile.
- `[.]` `discovery.conduit.evidence_fold` — EvidenceFold — guarded, additive enrichment that never resolves identity.
- `[L]` `discovery.conduit.grant` — DirectoryGrant — the frozen record of exactly what read-only access a customer
- `[L]` `discovery.conduit.live_connector` — ConduitConnectionsConnector — map a CONNECTED tenant's real directory.
- `[.]` `discovery.conduit.profiles` — Per-provider ProviderProfile declarations for the conduit consent-graph connector.
- `[L]` `discovery.conduit.profiles.entra_profile` — Entra (Microsoft Graph) ProviderProfile — the reference profile.
- `[.]` `discovery.conduit.profiles.google_profile` — Google ProviderProfiles — Workspace (DWD) and GCP IAM, the two-grant pair.
- `[.]` `discovery.conduit.profiles.okta_profile` — Okta ProviderProfile — the cross-IdP neutrality proof.
- `[.]` `discovery.conduit.profiles.ping_profile` — Ping ProviderProfile — PingFederate / PingOne OAuth clients.
- `[.]` `discovery.conduit.providers` — Per-provider connect strategies — the only place the divergent authorization dances live.
- `[L]` `discovery.conduit.providers.base` — ConnectStrategy — the contract behind the one "Connect your directory" button.
- `[L]` `discovery.conduit.providers.entra` — Entra connect strategy — the genuinely one-click case.
- `[.]` `discovery.conduit.providers.google` — Google connect strategies — TWO grants, never one click.
- `[.]` `discovery.conduit.providers.okta` — Okta connect strategy — honestly multi-step.
- `[.]` `discovery.conduit.providers.ping` — Ping connect strategy — per-deployment service-account config.
- `[.]` `discovery.conduit.risk_dictionary` — Cross-provider critical-scope dictionary — a maintained, standing asset.
- `[L]` `discovery.conduit.seal` — Conduit seal engine — seal the grant, seal the inventory, catch the drift.
- `[.]` `discovery.conduit.shadow` — ShadowCorrelator — net-new cross-namespace correlation.
- `[.]` `discovery.conduit.tiers` — Opt-in provenance tiers — configuration, never a launch dependency.
- `[.]` `discovery.conduit.transport` — Per-provider transports behind the unchanged GraphTransport Protocol.
- `[.]` `discovery.conduit.transport.google_transport` — Google transports — Workspace + GCP, behind the unchanged GraphTransport.
- `[.]` `discovery.conduit.transport.okta_transport` — Okta transport — Okta ``/api/v1`` behind the unchanged ``GraphTransport``
- `[.]` `discovery.conduit.transport.ping_transport` — Ping transport — PingFederate / PingOne behind the unchanged GraphTransport.
- `[L]` `discovery.connectors` — Tex discovery connectors.
- `[L]` `discovery.connectors.aws_bedrock` — Mock connector for AWS Bedrock agents and knowledge bases.
- `[L]` `discovery.connectors.base` — Connector framework for Tex's discovery layer.
- `[L]` `discovery.connectors.cloud_audit` — Cloud-audit connector — agentless, tamper-resistant discovery.
- `[L]` `discovery.connectors.cloud_audit_ocsf` — OCSF audit connector — the agentless, tamper-resistant catch.
- `[L]` `discovery.connectors.entra_consent_graph` — Entra consent-graph connector — the IdP root, made real.
- `[L]` `discovery.connectors.github` — Mock connector for GitHub Copilot installations and AI-bot apps.
- `[L]` `discovery.connectors.kernel_ebpf` — Kernel-eBPF connector — the signal the workload cannot reach.
- `[L]` `discovery.connectors.mcp_server` — Mock connector for MCP servers and the agents that connect to them.
- `[L]` `discovery.connectors.microsoft_graph` — Mock connector for Microsoft 365 / Copilot Studio agents.
- `[L]` `discovery.connectors.network_egress` — Network-egress connector — the headless agent nothing else lists.
- `[L]` `discovery.connectors.openai_assistants` — Mock connector for OpenAI Assistants / Custom GPTs / Agents.
- `[L]` `discovery.connectors.openai_live` — Live OpenAI Assistants connector.
- `[L]` `discovery.connectors.salesforce` — Mock connector for Salesforce Agentforce / Einstein AI agents.
- `[L]` `discovery.connectors.slack` — Mock connector for Slack workspaces.
- `[L]` `discovery.connectors.slack_live` — Live Slack connector.
- `[L]` `discovery.consent_graph` — Consent graph — the IdP estate as a graph, not a list.
- `[L]` `discovery.demo_seed` — Demo seed — a believable estate for the live roots to fall back to.
- `[L]` `discovery.dormancy` — Dormancy controller — the dormant-agent doctrine, in code.
- `[L]` `discovery.graph_transport` — Graph transport — the one read-only seam to the identity provider.
- `[L]` `discovery.ignition` — Ignition registry — "Run discovery" said once, and only once.
- `[L]` `discovery.ocsf` — OCSF normalization — one schema for every audit plane.
- `[L]` `discovery.presence` — Soft-disappearance state machine.
- `[L]` `discovery.reconciliation` — Reconciliation engine.
- `[L]` `discovery.scheduler` — Background discovery scan scheduler with drift detection.
- `[L]` `discovery.service` — Discovery service.

### `domain` — LIVE (22 files)
- `[L]` `domain.abstention_certificate` — The Abstention Certificate — a structured receipt sealed with every ABSTAIN.
- `[L]` `domain.agent` — Agent governance domain models.
- `[L]` `domain.agent_signal` — Result schemas for Tex's agent-governance evaluation streams.
- `[L]` `domain.asi_builder` — Build structured OWASP ASI findings from raw Tex pipeline signals.
- `[L]` `domain.asi_finding` — OWASP Top 10 for Agentic Applications (ASI) structured findings.
- `[L]` `domain.calibration_proposal` — Calibration proposal domain object.
- `[L]` `domain.decision` — 
- `[L]` `domain.determinism` — Determinism fingerprint for a single Tex evaluation.
- `[L]` `domain.discovery` — Discovery domain models.
- `[L]` `domain.evaluation` — 
- `[L]` `domain.evidence` — 
- `[L]` `domain.finding` — 
- `[L]` `domain.latency` — Per-layer latency breakdown for a single Tex evaluation.
- `[L]` `domain.outcome` — 
- `[L]` `domain.outcome_trust` — Outcome trust hierarchy and source classification.
- `[L]` `domain.owasp_asi` — OWASP Top 10 for Agentic Applications 2026 (ASI) mapping.
- `[L]` `domain.policy` — 
- `[L]` `domain.retrieval` — 
- `[L]` `domain.severity` — 
- `[L]` `domain.signal_trust` — Signal trust tier — the admissibility grade of a discovery signal.
- `[L]` `domain.tenant_baseline` — Tenant-scope content baseline domain models.
- `[L]` `domain.verdict` — 

### `drift` — LIVE (7 files)
- `[L]` `drift._anytime_valid` — Anytime-valid risk certificate for streaming drift detection.
- `[L]` `drift._bocpd` — Bayesian Online Change Point Detection (BOCPD) — private numerical core.
- `[L]` `drift._cusum` — Adaptive CUSUM detector — secondary change-point detector.
- `[L]` `drift.change_point` — Distributional change-point detector.
- `[.]` `drift.emergent_norm` — Emergent norm tracer.
- `[L]` `drift.evidence_adapter` — Wire the existing anytime-valid drift e-process to the sealed evidence type.
- `[L]` `drift.signal_registry` — Drift signal registry.

### `ecosystem` — LIVE (7 files)
- `[L]` `ecosystem._attestation` — Ecosystem-state attestation envelope.
- `[L]` `ecosystem._window` — RFC 9162 (Certificate Transparency v2) Merkle tree helpers.
- `[L]` `ecosystem.bridge` — Bridge between the existing six-layer router and the ecosystem engine.
- `[L]` `ecosystem.engine` — EcosystemEngine — primary entrypoint for ecosystem governance.
- `[L]` `ecosystem.proposed_event` — ProposedEvent — the input to EcosystemEngine.evaluate.
- `[L]` `ecosystem.state` — EcosystemState — read-only snapshot of the ecosystem at a point in time.
- `[L]` `ecosystem.verdict` — Ecosystem-level verdict.

### `enforcement` — LIVE (7 files)
- `[.]` `enforcement.adapters` — Framework adapters for Tex enforcement.
- `[L]` `enforcement.errors` — Typed errors raised by the enforcement layer.
- `[L]` `enforcement.events` — Structured audit events emitted by every gated execution.
- `[L]` `enforcement.gate` — TexGate — the core enforcement primitive.
- `[.]` `enforcement.seal` — Proof-carrying action gating — seal every gate allow/deny into the ledger.
- `[L]` `enforcement.standing_transport` — The in-process enforcement point, routed through the standing PDP.
- `[L]` `enforcement.transport` — Transports the gate uses to reach Tex.

### `engine` — LIVE (11 files)
- `[L]` `engine.abstention_certificate` — Builder for the Abstention Certificate (engine layer).
- `[L]` `engine.contract_bridge` — Contract bridge — adapts the PDP request shape to the ContractEnforcer
- `[L]` `engine.crc_gate` — Conformal Risk Control (CRC) verdict gate.
- `[L]` `engine.credal_hold` — L8 — Credal-conformal hold + EPIG resolver (Wave 2, frontier certificate).
- `[L]` `engine.hold` — The Hold — Tex's abstention, made first-class.
- `[L]` `engine.path_policy_bridge` — Path-policy bridge.
- `[L]` `engine.pdp` — 
- `[L]` `engine.risk_spine` — L9 — the live multiplicative e-value spine (Wave 2, first-green on-ramp).
- `[L]` `engine.router` — 
- `[L]` `engine.verdict_certificate` — Wave 2 / L12 — the verdict certificate: counterfactual robustness + QIF, split & honest.
- `[L]` `engine.verdict_transcript` — Canonical verdict transcript + monotonicity witness.

### `events` — LIVE (6 files)
- `[L]` `events._canonical` — RFC 8785 (JSON Canonicalization Scheme) helpers for ledger record hashing.
- `[L]` `events._ecdsa_provider` — ECDSA-P256 signature provider (default for the events ledger).
- `[L]` `events.crypto_provenance` — Cryptographic provenance attachment.
- `[L]` `events.event` — Event — the persisted ledger record.
- `[L]` `events.exceptions` — Exception hierarchy for the events ledger.
- `[L]` `events.ledger` — Append-only event ledger.

### `evidence` — LIVE (12 files)
- `[L]` `evidence.attribution_zk` — PTV-shaped Groth16 attestation envelope for attribution computations.
- `[L]` `evidence.c2pa_emitter` — Lightweight emitter façade for the ``EvidenceRecorder`` Thread-5 wiring.
- `[L]` `evidence.chain` — 
- `[L]` `evidence.exporter` — 
- `[L]` `evidence.manifest_mirror` — Postgres-backed C2PA manifest mirror (Thread 5).
- `[.]` `evidence.negative_knowledge` — Negative-knowledge certificate (Wave 2 / L3) — verifiable non-membership over a
- `[L]` `evidence.postgres_mirror` — Postgres-backed evidence mirror.
- `[L]` `evidence.recorder` — 
- `[L]` `evidence.scitt_cose_alg` — COSE algorithm identifier mapping for SCITT Signed Statements.
- `[L]` `evidence.scitt_statement` — SCITT-shaped Signed Statement builder for Tex evidence.
- `[L]` `evidence.seal` — [Architecture: Layer 5 (Evidence)] — the post-quantum seal over the chain.
- `[L]` `evidence.tee_binding` — TEE attestation binding for Tex attribution statements.

### `gateway` — LIVE (3 files)
- `[L]` `gateway.backends` — [Architecture: Voice infrastructure] — pluggable STT / TTS backends.
- `[L]` `gateway.grant` — [Architecture: Voice infrastructure] — the short-lived recognizer grant.
- `[.]` `gateway.voice_gateway` — [Architecture: Voice infrastructure] — the streaming recognizer WebSocket.

### `governance` — LIVE (20 files)
- `[.]` `governance.kernel_mcp` — Kernel-Level / Syscall-Style MCP Governance.
- `[.]` `governance.kernel_mcp.capability` — MCP capability tokens.
- `[.]` `governance.kernel_mcp.syscall_gate` — MCP syscall gate.
- `[.]` `governance.path_policy` — Runtime Governance via Policies on Paths.
- `[L]` `governance.path_policy.checker` — Path policy runtime checker.
- `[L]` `governance.path_policy.ltlf` — Finite-trace Linear Temporal Logic (LTLf) evaluator for path policies.
- `[L]` `governance.path_policy.policy` — Path policy specification language.
- `[.]` `governance.private_data_exec` — Private-Data Execution Environment.
- `[L]` `governance.private_data_exec.ifc` — Information-Flow Control sub-layer for Tex.
- `[L]` `governance.private_data_exec.ifc.ci_norms` — Contextual Integrity norm metadata for IFC enforcement.
- `[L]` `governance.private_data_exec.ifc.classifier` — Classify Tex request fields into IFC labels.
- `[L]` `governance.private_data_exec.ifc.engine` — IFC engine: orchestrates classification, provenance graph, NeuroTaint
- `[L]` `governance.private_data_exec.ifc.lattice` — Integrity lattice and FIDES-style product lattice for IFC enforcement.
- `[L]` `governance.private_data_exec.ifc.memory` — NeuroTaint cross-session memory stream.
- `[L]` `governance.private_data_exec.ifc.provenance` — ARM-style provenance graph with counterfactual edges.
- `[.]` `governance.private_data_exec.sandbox` — Private-data sandbox.
- `[L]` `governance.standing` — Standing governance — the live PDP that switches on the instant ignition
- `[.]` `governance.stpa_specs` — STPA (System-Theoretic Process Analysis) Hazard Specifications.
- `[.]` `governance.stpa_specs.hazard_model` — STPA hazard model.
- `[.]` `governance.stpa_specs.manifest` — STPA manifest YAML loader + coverage matrix builder.

### `graph` — LIVE (5 files)
- `[L]` `graph.exceptions` — Exception hierarchy for the temporal knowledge graph.
- `[L]` `graph.projection` — StateProjection — derive an EcosystemState snapshot from the graph.
- `[.]` `graph.query` — GraphQuery — high-level query helpers used by the engine pipeline.
- `[.]` `graph.rustworkx_backend` — rustworkx graph backend.
- `[L]` `graph.temporal_kg` — Temporal knowledge graph backbone.

### `institutional` — LIVE (7 files)
- `[L]` `institutional._pq_signing` — Post-quantum signing provider resolver for the institutional layer.
- `[.]` `institutional.controller` — Governance Controller.
- `[L]` `institutional.governance_graph` — Governance graph.
- `[L]` `institutional.governance_log` — Cryptographically-keyed, append-only governance log.
- `[L]` `institutional.oracle` — Governance Oracle.
- `[L]` `institutional.sanctions` — Sanctions and restorative paths.
- `[L]` `institutional.subagent_inheritance` — Subagent state inheritance for the institutional governance layer.

### `interchange` — LIVE (5 files)
- `[.]` `interchange._local_tsa` — A self-issued RFC 3161 Time-Stamp Authority — for OFFLINE DEMO / DEV / TEST ONLY.
- `[L]` `interchange.external_anchor` — External anchor (moat / provable-age) — bind a gix checkpoint tree-head to an
- `[L]` `interchange.gix` — GIX (Wave 2 / L6) — a transparency-log view over sealed governance verdicts.
- `[.]` `interchange.gix_merge` — gix_merge (Wave 2 / L6) — authenticated federated mean-merge of cross-org
- `[.]` `interchange.gix_witness` — gix_witness (Wave 2 / L6) — C2SP tlog-witness cosigning semantics, in-tree.

### `intervention` — LIVE (6 files)
- `[L]` `intervention.bounded_compromise` — Bounded-compromise calculator.
- `[L]` `intervention.engine` — Intervention engine.
- `[L]` `intervention.eradication` — Eradication rule synthesizer (AIR §3 eradication phase).
- `[L]` `intervention.kinds` — Intervention kinds.
- `[.]` `intervention.neyman_pearson` — Neyman-Pearson multi-monitor selection (Thread 8.1 frontier #3).
- `[L]` `intervention.restorative` — Restorative-path executor.

### `learning` — LIVE (15 files)
- `[L]` `learning.calibration_safety` — Calibration safety bounds and rate limiting.
- `[L]` `learning.calibrator` — 
- `[L]` `learning.drift` — Policy-drift detection for Tex.
- `[L]` `learning.drift_classifier` — Drift classification.
- `[L]` `learning.feedback_loop` — Feedback loop orchestrator.
- `[L]` `learning.health` — Calibration health score.
- `[L]` `learning.observability` — Learning-layer observability.
- `[L]` `learning.ope` — Off-policy evaluation with an anytime-valid confidence sequence.
- `[L]` `learning.outcome_validator` — Outcome validation: REPORTED → VALIDATED / QUARANTINED.
- `[L]` `learning.outcomes` — 
- `[L]` `learning.poisoning_detector` — Adversarial / poisoning detection.
- `[L]` `learning.replay` — Replay-based validation for calibration proposals.
- `[L]` `learning.reporter_reputation` — Reporter reputation system.
- `[L]` `learning.sufficiency` — Evidence-sufficiency / decision-readiness gate for calibration.
- `[L]` `learning.trigger` — Anytime-valid calibration trigger.

### `memory` — LIVE (9 files)
- `[L]` `memory._db` — Shared Postgres connection helpers for the memory layer.
- `[L]` `memory.decision_input_store` — Durable store for full original request inputs.
- `[L]` `memory.decision_store` — Postgres-backed durable decision store.
- `[L]` `memory.evidence_store` — Postgres mirror of the append-only evidence chain.
- `[L]` `memory.permit_store` — Durable permit store.
- `[L]` `memory.policy_snapshot_store` — Postgres-backed durable policy snapshot store.
- `[L]` `memory.replay` — Memory replay engine — locked spec § 6.
- `[L]` `memory.system` — MemorySystem — the unified entry point for Tex's memory layer.
- `[L]` `memory.verification_store` — Durable verification log.

### `nanozk` — LIVE (12 files)
- `[L]` `nanozk.deepprove_backend` — ==================== DEACTIVATED PLACEHOLDER (research-early) ====================
- `[L]` `nanozk.fisher_guided` — ==================== DEACTIVATED PLACEHOLDER (research-early) ====================
- `[L]` `nanozk.gauge_zkp` — ==================== DEACTIVATED PLACEHOLDER (research-early) ====================
- `[L]` `nanozk.latticefold_plus` — ==================== DEACTIVATED PLACEHOLDER (research-early) ====================
- `[L]` `nanozk.layerwise_prover` — ==================== DEACTIVATED PLACEHOLDER (research-early) ====================
- `[L]` `nanozk.logup_star` — ==================== DEACTIVATED PLACEHOLDER (research-early) ====================
- `[L]` `nanozk.mira_parallel` — ==================== DEACTIVATED PLACEHOLDER (research-early) ====================
- `[L]` `nanozk.nonlinearity_lookup` — ==================== DEACTIVATED PLACEHOLDER (research-early) ====================
- `[L]` `nanozk.poseidon_chain` — ==================== DEACTIVATED PLACEHOLDER (research-early) ====================
- `[L]` `nanozk.sublinear_space` — ==================== DEACTIVATED PLACEHOLDER (research-early) ====================
- `[L]` `nanozk.v3db` — ==================== DEACTIVATED PLACEHOLDER (research-early) ====================
- `[L]` `nanozk.veil_wrapper` — ==================== DEACTIVATED PLACEHOLDER (research-early) ====================

### `observability` — LIVE (4 files)
- `[L]` `observability.discovery_metrics` — Discovery-layer metrics.
- `[.]` `observability.governance_span` — OpenTelemetry-compatible governance span attributes for ecosystem
- `[L]` `observability.metrics` — [Architecture: Layer 3 (Monitoring)] — top-level OpenMetrics / Prometheus export.
- `[L]` `observability.telemetry` — 

### `ontology` — LIVE (7 files)
- `[.]` `ontology.airo` — AIRO (AI Risk Ontology) bindings.
- `[L]` `ontology.entity_types` — Typed entities in the Tex ecosystem.
- `[L]` `ontology.event_types` — Typed events in the Tex ecosystem.
- `[.]` `ontology.governance_ontology` — Governance ontology — what regulatory bounds apply.
- `[.]` `ontology.interaction_ontology` — Interaction ontology — how actors coordinate.
- `[.]` `ontology.role_ontology` — Role ontology — how domain actors reason.
- `[L]` `ontology.validator` — Ontology validator.

### `operator` — ORPHAN (4 files)
- `[.]` `operator.__main__` — Run the Tex operator:
- `[.]` `operator.controller` — EnrollmentController — watches namespaces and keeps the EnrollmentScope true.
- `[.]` `operator.scope` — EnrollmentScope — the live source of truth for what is governed.
- `[.]` `operator.webhook` — SidecarInjector — the MutatingAdmissionWebhook that auto-enrolls every new pod.

### `pcas` — LIVE (12 files)
- `[.]` `pcas.graph` — PCAS dependency-graph adapters over Tex's temporal KG + IFC provenance.
- `[L]` `pcas.graph.adapter` — PCAS dependency-graph adapter.
- `[.]` `pcas.language` — PCAS policy language: lex, parse, stratify.
- `[L]` `pcas.language.ast` — PCAS policy-language AST.
- `[L]` `pcas.language.lexer` — PCAS policy-language lexer.
- `[L]` `pcas.language.parser` — PCAS recursive-descent parser.
- `[L]` `pcas.language.stratify` — PCAS stratifier.
- `[L]` `pcas.monitor` — PCAS reference monitor.
- `[.]` `pcas.runtime` — PCAS policy runtime: relations, evaluator, helper FFI.
- `[L]` `pcas.runtime.evaluator` — PCAS semi-naive bottom-up Datalog evaluator with stratified negation.
- `[L]` `pcas.runtime.helpers` — PCAS helper-function registry.
- `[L]` `pcas.runtime.relation` — PCAS runtime relations.

### `pep` — ORPHAN (3 files)
- `[.]` `pep.__main__` — Run the transparent enforcement proxy as a sidecar:
- `[.]` `pep.decision_client` — The PEP's client to the PDP.
- `[.]` `pep.proxy` — The transparent enforcement proxy — the userspace data-plane PEP.

### `policies` — LIVE (1 files)
- `[L]` `policies.defaults` — 

### `pqcrypto` — LIVE (19 files)
- `[.]` `pqcrypto._backend_probe` — Fail-closed RUNTIME-DEPENDENT backend probes — Wave 2 **M0c** (``track/wave2-probes``).
- `[L]` `pqcrypto._ed25519_provider` — Ed25519 (RFC 8032) signature provider.
- `[L]` `pqcrypto.algorithm_agility` — Algorithm-agile signature abstraction.
- `[L]` `pqcrypto.blake3_ml_dsa` — ML-DSA-B (BLAKE3-accelerated ML-DSA) signature provider.
- `[.]` `pqcrypto.code_signing` — Post-quantum code signing for Tex software releases and skill manifests.
- `[.]` `pqcrypto.composite_cms` — ASN.1 DER serialization for Composite ML-DSA signatures per
- `[L]` `pqcrypto.composite_ml_dsa` — Composite ML-DSA signatures per draft-ietf-lamps-pq-composite-sigs-18.
- `[.]` `pqcrypto.evidence_chain_signer` — Drop-in signing extension for the existing `tex.evidence.chain` module.
- `[.]` `pqcrypto.evidence_quorum` — Quorum signing for the highest-stakes Tex evidence records.
- `[.]` `pqcrypto.hqc` — HQC (Hamming Quasi-Cyclic) KEM provider — NIST 4th-round additional selection.
- `[L]` `pqcrypto.hybrid` — Hybrid signature provider for transition-period defense in depth.
- `[.]` `pqcrypto.lms` — LMS (Leighton-Micali Signatures) per NIST SP 800-208 / RFC 8554.
- `[L]` `pqcrypto.ml_dsa` — ML-DSA (NIST FIPS 204) signature provider — production-grade.
- `[.]` `pqcrypto.ml_kem` — ML-KEM (NIST FIPS 203) key encapsulation provider — production-grade.
- `[L]` `pqcrypto.pq_durability` — PQ-maturity-gated live signer — Wave 2 leap **L10** (``track/wave2-pqlive``).
- `[L]` `pqcrypto.quorum_ml_dsa` — Quorum ML-DSA — k-of-n quorum certificate over ML-DSA signatures.
- `[L]` `pqcrypto.slh_dsa` — SLH-DSA (NIST FIPS 205) hash-based signature provider.
- `[.]` `pqcrypto.talus_tee` — TALUS-TEE — 1-round-online threshold ML-DSA with TEE attestation.
- `[.]` `pqcrypto.threshold_ml_dsa` — Genuine threshold ML-DSA via the Mithril scheme (ePrint 2026/013).

### `provenance` — LIVE (14 files)
- `[L]` `provenance.attempt_seal` — ATTEMPT-sealing hook (Wave 2 / seam track) — seal one ``SealedFact(ATTEMPT)``
- `[.]` `provenance.bundle` — Offline evidence bundle + standalone verifier — the court-exhibit core.
- `[L]` `provenance.decision_seal` — DECISION-sealing seam (Wave 2 / M0) — seal one typed ``SealedFact(DECISION)`` per verdict.
- `[L]` `provenance.delegation` — Sealed delegation graph — the agent-to-agent dark zone, witnessed.
- `[L]` `provenance.distance` — Behavioural distance — graded confidence, never a bare claim.
- `[.]` `provenance.enforcement_seal` — ENFORCEMENT-sealing seam — seal one ``SealedFact(ENFORCEMENT)`` per gated action.
- `[L]` `provenance.engine` — Behavioural provenance engine — the identity-by-behaviour primitive.
- `[L]` `provenance.feed` — Continuous provenance feed — the primitive made alive.
- `[L]` `provenance.intent` — Declared-vs-observed intent — alignment as a sealed, deterministic grade.
- `[L]` `provenance.ledger` — Behavioural provenance ledger — Certificate Transparency for agents.
- `[L]` `provenance.models` — Provenance domain models — the sealed records and resolutions.
- `[L]` `provenance.seal_envelope` — Crypto-agile dual-signature sealer — the post-quantum seal for the ledgers.
- `[L]` `provenance.signature` — Behavioural signature — proving who an agent is by what it does.
- `[L]` `provenance.transcript_seal` — Verdict-transcript sealing seam — seal one ``SealedFact(VERDICT_TRANSCRIPT)`` per

### `receipts` — INDIRECT (4 files)
- `[.]` `receipts.epistemic_source` — Epistemic source taxonomy for LLM claims.
- `[.]` `receipts.receipt` — Tool execution receipt data model.
- `[.]` `receipts.runtime` — Receipt issuer and verifier (NabaOS).
- `[.]` `receipts.store` — Receipt persistence layer.

### `retrieval` — LIVE (1 files)
- `[L]` `retrieval.orchestrator` — 

### `runtime` — LIVE (16 files)
- `[.]` `runtime.agentarmor` — AgentArmor: Program Analysis on Agent Runtime Traces.
- `[.]` `runtime.agentarmor.graph_constructor` — AgentArmor Graph Constructor.
- `[L]` `runtime.agentarmor.property_registry` — AgentArmor Property Registry.
- `[L]` `runtime.agentarmor.type_system` — AgentArmor Type System.
- `[.]` `runtime.clawguard` — ClawGuard: Runtime Security Framework for Tool-Augmented LLM Agents.
- `[L]` `runtime.clawguard.boundary_enforcer` — Tool-call boundary enforcer.
- `[L]` `runtime.clawguard.rule_set` — ClawGuard rule sets.
- `[.]` `runtime.mage` — MAGE: Memory As Guardrail Enforcement.
- `[.]` `runtime.mage.risk_assessor` — MAGE Pre-Action Risk Assessor (Judge).
- `[L]` `runtime.mage.shadow_memory` — MAGE Shadow Memory.
- `[.]` `runtime.mcpshield` — MCPShield: Formal Verification for MCP Tool Calls.
- `[L]` `runtime.mcpshield.lts_model` — MCPShield Labeled Transition System.
- `[L]` `runtime.mcpshield.verifier` — MCPShield Property Verifier.
- `[.]` `runtime.planguard` — PlanGuard: Defending Agents against Indirect Prompt Injection via
- `[L]` `runtime.planguard.intent_verifier` — Hierarchical Intent Verifier.
- `[L]` `runtime.planguard.isolated_planner` — Isolated Planner.

### `safeflow` — INDIRECT (4 files)
- `[.]` `safeflow.executor` — SAFEFLOW transactional executor.
- `[.]` `safeflow.rollback` — SAFEFLOW inverse-operation registry.
- `[.]` `safeflow.transaction` — SAFEFLOW transaction model.
- `[.]` `safeflow.wal` — SAFEFLOW write-ahead log.

### `selfgov` — LIVE (1 files)
- `[L]` `selfgov.governor` — Reflexive self-governance gate (Wave 2 / L5) — Tex's OWN controller mutations

### `semantic` — LIVE (5 files)
- `[L]` `semantic.analyzer` — 
- `[L]` `semantic.fallback` — 
- `[L]` `semantic.openai` — 
- `[L]` `semantic.prompt` — 
- `[L]` `semantic.schema` — 

### `sim` — LIVE (13 files)
- `[.]` `sim.__main__` — tex.sim CLI.
- `[.]` `sim.actions` — actions.py — the things agents do, authored to draw *real* verdicts.
- `[L]` `sim.archetype` — archetype.py — the shape of a real enterprise, so the synthetic estate is a
- `[.]` `sim.behavior` — behavior.py — the estate, alive.
- `[.]` `sim.client` — client.py — the simulator's wire to a running Tex backend.
- `[L]` `sim.connectors` — connectors.py — wire the synthetic estate into the real discovery pipeline.
- `[L]` `sim.estate` — estate.py — the synthetic estate generator.
- `[.]` `sim.live` — live.py — the estate, alive over wall-clock time.
- `[.]` `sim.oracle` — oracle.py — where it breaks.
- `[.]` `sim.report` — report.py — the ten-second read.
- `[.]` `sim.runner` — runner.py — orchestrate a scenario end to end against a running Tex backend.
- `[.]` `sim.scenarios` — scenarios.py — the named tiers.
- `[.]` `sim.tests.test_sim_contract` — Contract tests for tex.sim — these keep the mirror honest as Tex evolves.

### `specialists` — LIVE (25 files)
- `[L]` `specialists.agentarmor_specialist` — AgentArmor Specialist Judge.
- `[L]` `specialists.argus_specialist` — ARGUS Specialist Judge.
- `[L]` `specialists.attriguard_specialist` — AttriGuard Specialist Judge.
- `[L]` `specialists.base` — 
- `[L]` `specialists.camel_specialist` — CamelSpecialist — exposes CaMeL capability-tracking decisions to the PDP.
- `[L]` `specialists.clawguard_specialist` — ClawGuard Specialist Judge.
- `[L]` `specialists.conformal_escalation` — Specialist Conformal Escalation Gate.
- `[L]` `specialists.fusion` — Cross-Specialist Fusion Layer.
- `[L]` `specialists.human_review` — Five Eyes-Aligned Human Review Escalation.
- `[L]` `specialists.ifc_specialist` — Information-Flow Control Specialist.
- `[L]` `specialists.judges` — 
- `[L]` `specialists.llm_bridge` — Specialist LLM Bridge.
- `[L]` `specialists.llm_dispatch` — Specialist LLM Dispatch.
- `[L]` `specialists.mage_specialist` — MAGE Specialist Judge.
- `[L]` `specialists.mcp_injection_specialist` — MCP Injection Specialist Judge.
- `[L]` `specialists.mcpshield_specialist` — MCPShield Specialist Judge.
- `[L]` `specialists.melon_specialist` — MELON adapter — masked-evaluation defense against indirect prompt
- `[L]` `specialists.metaguard` — Metaguard — deterministic deny/caution signatures for Tex's OWN controller
- `[L]` `specialists.owasp_skills_top10_specialist` — OWASP Agentic Skills Top 10 Specialist Judge.
- `[L]` `specialists.pcas_specialist` — PcasSpecialist — exposes the PCAS reference monitor in the PDP suite.
- `[L]` `specialists.planguard_specialist` — PlanGuard Specialist Judge.
- `[L]` `specialists.secalign_specialist` — SecAlign adapter — preference-aligned defense.
- `[L]` `specialists.structural_floor` — Structural FORBID floor.
- `[L]` `specialists.struq_specialist` — StruQ adapter — structured-query defense.
- `[L]` `specialists.vigil_specialist` — VIGIL Specialist Judge.

### `stores` — LIVE (20 files)
- `[L]` `stores.action_ledger` — In-memory action ledger.
- `[L]` `stores.action_ledger_postgres` — Postgres-backed action ledger.
- `[L]` `stores.agent_registry` — In-memory agent registry.
- `[L]` `stores.agent_registry_postgres` — Postgres-backed agent registry.
- `[.]` `stores.behavioral_provenance_ledger_postgres` — Postgres-backed behavioural provenance ledger.
- `[L]` `stores.calibration_proposal_store` — Calibration proposal store.
- `[L]` `stores.connector_health` — Connector health store.
- `[L]` `stores.decision_store` — 
- `[L]` `stores.discovery_ledger` — Append-only hash-chained discovery ledger.
- `[L]` `stores.discovery_ledger_postgres` — Postgres-backed discovery ledger.
- `[L]` `stores.drift_events` — Drift event store.
- `[L]` `stores.entity_store` — 
- `[L]` `stores.governance_snapshots` — Governance snapshot store.
- `[L]` `stores.outcome_store` — 
- `[L]` `stores.policy_store` — 
- `[L]` `stores.precedent_store` — 
- `[L]` `stores.precedent_store_postgres` — Postgres-backed precedent store.
- `[L]` `stores.provenance_proofs_postgres` — Postgres-backed durable store for ZKPROV proofs.
- `[L]` `stores.scan_runs` — Scan-run store: per-tenant locking, idempotency, durable run records.
- `[L]` `stores.tenant_content_baseline` — In-memory tenant content baseline.

### `systemic` — LIVE (8 files)
- `[L]` `systemic._conformal` — Anytime-valid conformal risk control for trajectory uncertainty.
- `[L]` `systemic._koopman` — Koopman lift + linear advance for the ecosystem digital twin.
- `[L]` `systemic._sccal` — SCCAL — Semantic-Geometric Coupled-dynamics Cascading-risk AuditIng Layer.
- `[L]` `systemic.cascade_predictor` — Cascade predictor.
- `[L]` `systemic.digital_twin` — Ecosystem digital twin.
- `[L]` `systemic.probguard` — ProbGuard-style probabilistic runtime monitoring for systemic risk.
- `[.]` `systemic.risk_evaluator` — Systemic risk evaluator.
- `[L]` `systemic.trajectory` — Frozen Pydantic v2 models for digital-twin trajectories and cascade

### `tee` — LIVE (7 files)
- `[.]` `tee._mode_probe` — Confidential-VM / TDX mode probe — Wave 2 **M0c** (``track/wave2-probes``).
- `[L]` `tee.attestation_client` — Composite TEE attestation client (Intel Trust Authority + NVIDIA GPU).
- `[L]` `tee.composite` — Composite CPU+GPU TEE attestation envelope and EAT-AI claims (Thread 12 TEE).
- `[L]` `tee.h100_attestation` — NVIDIA H100/H200/B200/B300 GPU attestation evidence collector.
- `[L]` `tee.sota_2026` — Tex Thread 12+ — May-2026 bleeding-edge SOTA augmentations.
- `[L]` `tee.tdx_attestation` — Intel TDX (Trust Domain Extensions) attestation evidence collector.
- `[.]` `tee.verdict_binding` — L2 — Proof-of-Guardrail: verdict-bound composite attestation.

### `verifier` — INDIRECT (3 files)
- `[.]` `verifier.__main__` — CLI: independently verify a sealed Tex verdict bundle, offline.
- `[.]` `verifier.check` — Standalone offline verdict checker — the smallest trusted computing base.
- `[.]` `verifier.export` — Producer-side bridge: mint a portable verdict bundle from a live Tex ledger.

### `vet` — LIVE (10 files)
- `[L]` `vet.agent_identity_document` — Agent Identity Document (AID) — W3C VC 2.0 with selective disclosure.
- `[L]` `vet.aivs_micro` — AIVS-Micro — 200-byte attestation stub for continuous monitoring.
- `[.]` `vet.integration` — VET integration hook for the ``/v1/guardrail`` evidence path.
- `[L]` `vet.ptv_attestation` — PTV (Prove-Transform-Verify) attestation for agent identity.
- `[L]` `vet.registry` — Agent Identity Document registry.
- `[L]` `vet.scitt` — SCITT — Supply Chain Integrity, Transparency, and Trust for Tex.
- `[.]` `vet.sd_jwt_vc` — SD-JWT VC — Selective-Disclosure JWT Verifiable Credential + SD-Card.
- `[L]` `vet.selective_disclosure` — Selective-disclosure primitive for the Agent Identity Document.
- `[L]` `vet.txn_tokens` — OAuth 2.0 Transaction Tokens for Agents.
- `[L]` `vet.web_proofs` — Web Proofs — TLS session notarization for third-party AI API calls.

### `vigil` — LIVE (14 files)
- `[L]` `vigil._openai_explainer` — [Architecture: Cross-cutting (Vigil cognition)] — optional OpenAI transport
- `[L]` `vigil.calibration_provider` — [Architecture: Cross-cutting (Vigil cognition)] — the calibration-hold provider.
- `[L]` `vigil.causal` — [Architecture: Cross-cutting (Vigil cognition)] — v5 CAUSAL MODEL.
- `[L]` `vigil.conjugate` — [Architecture: Cross-cutting (Vigil cognition)] — closed-form Bayesian surprise.
- `[L]` `vigil.dimensions` — [Architecture: Cross-cutting (Vigil cognition)] — the six dimensions, read.
- `[L]` `vigil.efe` — [Architecture: Cross-cutting (Vigil cognition)] — v4 EXPECTED FREE ENERGY.
- `[L]` `vigil.engine` — [Architecture: Cross-cutting (Vigil cognition)] — the engine.
- `[L]` `vigil.explainer` — [Architecture: Cross-cutting (Vigil cognition)] — the explanation layer.
- `[L]` `vigil.held_provider` — [Architecture: Cross-cutting (Vigil cognition)] — the held-decision provider.
- `[L]` `vigil.learning` — [Architecture: Cross-cutting (Vigil cognition)] — v2 LIVE LEARNER.
- `[L]` `vigil.normal` — [Architecture: Cross-cutting (Vigil cognition)] — the model of normal.
- `[L]` `vigil.preference` — [Architecture: Cross-cutting (Vigil cognition)] — v3 PREFERENCE / VALUE-OF-INFORMATION.
- `[L]` `vigil.selector` — [Architecture: Cross-cutting (Vigil cognition)] — the selector.
- `[L]` `vigil.utterances` — [Architecture: Cross-cutting (Vigil cognition)] — authored utterance forms.

### `voice` — LIVE (6 files)
- `[L]` `voice.answer_forms` — [Architecture: Voice cognition] — the authored answer registry.
- `[L]` `voice.attestation` — [Architecture: Layer 5 (Evidence)] — the voice-attestation chain.
- `[.]` `voice.entailment_cert` — [Architecture: Voice cognition / Layer 5 (Evidence)] — Wave 2 L11, the SEAL HALF.
- `[L]` `voice.intent` — [Architecture: Voice cognition] — deterministic intent routing for ``/v1/ask``.
- `[L]` `voice.voice_ask` — [Architecture: Voice cognition] — the ``/v1/ask`` grounding pipeline.
- `[L]` `voice.voice_gate` — [Architecture: Voice cognition] — the faithfulness gate on the spoken answer.

### `zkpdp` — INDIRECT (1 files)
- `[.]` `zkpdp.arbiter` — zkPDP arbiter (Wave 2 / L1) — proof-carrying verdict over the ARBITRATION RELATION.

### `zkprov` — LIVE (11 files)
- `[L]` `zkprov.backends` — Pluggable ZK-proof backend dispatcher for ZKPROV.
- `[L]` `zkprov.commitment` — Dataset commitment scheme — Poseidon2 Merkle + ML-DSA-65 CA signature.
- `[L]` `zkprov.integration` — ZKPROV integration hook for the ``/v1/guardrail`` evidence path.
- `[L]` `zkprov.manifest` — Dataset manifest with EU AI Act Article 53(1)(d) TDS Template binding.
- `[L]` `zkprov.proof` — ZKPROV proof generation and verification.
- `[L]` `zkprov.receipts` — NABAOS-style epistemic receipts for provenance hot path.
- `[L]` `zkprov.recursive` — Recursive aggregation of ZKPROV proofs (VFT element 4).
- `[L]` `zkprov.sampler` — Verifiable index-hiding batch sampler — VFT element 2.
- `[L]` `zkprov.schnorr_group` — Self-contained discrete-log Σ-protocol toolkit (Pedersen + Fiat–Shamir).
- `[L]` `zkprov.scitt_arp` — SCITT ARP — Attestation Reconciliation Protocol integration.
- `[L]` `zkprov.zk_fuse` — Zero-knowledge proof of the PDP decision-relation **fuse kernel**.

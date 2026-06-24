# THE TEX BLUEPRINT — the definitive, code-verified map of the whole system

> **This is the bible.** It was produced by reading the actual source of every module under
> `src/tex/` (636 Python files, ~293K lines) and tracing real imports and call-sites — **not**
> docstrings, README claims, or prior-thread assertions. Every load-bearing claim is cited to
> `file:line`. Where a claim could only be sourced from a comment/markdown it is labelled
> `(claim, unverified)`.
>
> **Branch:** `feat/proof-carrying-gate` · **Generated:** 2026-06-18 · **Boot entrypoint:** `uvicorn tex.main:app`
>
> **If you are a future thread: read this file first, then the dossier you need. Do not re-derive the
> wiring from docstrings — that is exactly what produced the "20 vs 46 subsystems" confusion this
> document exists to end.** The numbers here come from a static AST import-graph + live boot probes.

---

## 0. How this corpus is organized

```
docs/blueprint/
├── README.md                  ← you are here: the master synthesis + reconciled truth
├── _spine/
│   ├── runtime-wiring.md       ← full boot sequence: every TexRuntime field, where it's built, what gates it
│   └── reachability.md         ← static import-graph: every subsystem + every .py tagged live / not-live
├── _traces/                    ← six end-to-end adversarial verifications (try-to-refute, then verdict)
│   ├── action-eval-e2e.md       (brain↔body merge + receipt)          → PARTIAL
│   ├── discovery-conduit-e2e.md (connect a directory → decision)       → CONFIRMED
│   ├── evidence-proof-e2e.md    (offline-verifiable bundle, no trust)  → CONFIRMED
│   ├── learning-flywheel-e2e.md (outcome/abstain → recalibration)      → CONFIRMED
│   ├── crypto-anchor-e2e.md     (PQ-sign + hash-chain + ext. anchor)   → PARTIAL
│   └── completeness-critic.md   (what's contradictory / missing)       → PARTIAL→reconciled here
└── subsystems/                 ← 40 deep-read dossiers, one per subsystem cluster (code-cited)
```

Read order for a newcomer: **§1 (what Tex is) → §2 (the loop) → §3 (boot) → §4 (the reconciled inventory) → §5 (flag matrix) → §6 (data flows) → §7 (technology) → §8 (what's NOT wired).** Then open the dossier for whatever you're touching.

---

## 1. What Tex is (grounded in the code)

**The vision:** Tex is sovereign cognition for AI actions — *"the first voice of AI."* One platform, one
voice, a white screen that stays silent until an agent action needs a human decision. When it speaks, the
proof is a **receipt**: an offline-verifiable record that the action was governed.

**What the code actually is, in one sentence:** Tex is a **Policy Decision Point + Policy Enforcement
Point for AI-agent actions** — it discovers the agents in your directory, evaluates each action they
attempt against policy (PERMIT / ABSTAIN / FORBID), enforces that verdict, seals a cryptographic receipt
of the decision, and feeds human-resolved outcomes back into its own calibration.

That is a real, running FastAPI service. Booting it (`uvicorn tex.main:app`, default config) yields a
**fully-wired runtime with 50 populated subsystems and ~130 HTTP routes** — verified live, see §3. The
"is it actually wired?" anxiety from prior threads is answered definitively in §4: **almost all of it is
wired; the nuance is which parts are flag-gated OFF by default** (§5).

### The architecture in four layers (Tex's own mental model: Discover → Decide → Prove → Learn)

| Loop stage | What it does | Primary subsystems (code) | Tex's internal layer tag |
|---|---|---|---|
| **DISCOVER** | Connect a customer directory, find every AI agent, track presence/dormancy | `discovery` (+ `discovery.conduit`), `agent`, `ontology` | Layer 1 (Discovery), Layer 2 (Identity) |
| **DECIDE** | Evaluate an action → verdict, via a multi-specialist PDP brain + an enforcement body | `engine` (PDP), `specialists`, `deterministic`, `contracts`, `semantic`, `governance`, `ecosystem`, `enforcement`, `commands` | Layer 3 (Monitoring), Layer 4 (Execution Governance) |
| **PROVE** | Seal a tamper-evident, post-quantum-signed, offline-verifiable receipt | `evidence`, `provenance`, `events`, `pqcrypto`, `c2pa`, `tee`, `zkprov`, `interchange` (anchor) | Layer 5 (Evidence) |
| **LEARN** | Vet human-resolved outcomes, recalibrate thresholds under safety gates | `learning`, `drift`, `vet`, `causal`, `selfgov` | Layer 6 (Learning) |

Cross-cutting under all four: `domain` (the shared vocabulary — imported by 34 subsystems), `observability`
(telemetry — imported by 24), `stores`/`memory`/`db` (persistence), `api` (the HTTP surface), `vigil`/`voice`/`gateway` (the speaking/UI cognition).

### The execution layer (Brain + Body) — what it actually does

Tex **does** block — it enforces in **two planes** (conflating them is the #1 source of overclaim):

- **Brain — the PDP (live on Render `tex-web` by default, no flag).** Every action hits `POST /v1/govern/decide` → `StandingGovernance.decide()`, returning a real **PERMIT / ABSTAIN / FORBID** with inline deterministic floors that fire *before* any probabilistic vote: a **Tier-1 FORBID floor** (unsealed identity / non-governable lifecycle / out-of-capability-surface), a **DIFC `SECRET ↛ EGRESS` hard-deny** that wins even when other specialists vote PERMIT (decidable non-interference + a re-checkable witness), **opaque/undecodable content → ABSTAIN** (never content-blind PERMIT), and a **structural FORBID floor** for every deterministic-deny signature. Every deep decision writes an **always-on, hash-chained, post-quantum-signed evidence record** — no flag.
- **Body — the PEP (built + proven; deploy in front of the agent fleet, *not* on Render).** A transparent egress proxy (`python -m tex.pep`) that **refuses any not-released action inline (403, never forwarded)**, plus opt-in: an emission gate (re-asserts the permitted tool subset), content-bound single-use permits, sealed terminal-outcome receipts, attested identity, cross-tenant binding, a credential broker (mints single-use action-scoped creds, strips standing creds), and kernel-pinned destinations. Below it, an **eBPF kernel floor** (5 programs — inline fast-block of known-FORBID destinations + redirect-to-proxy, verified in-kernel on Linux) and **born-in-a-box k8s admission** (sidecar injector + validating-deny webhook + in-apiserver policy + cosign + gVisor, proven on a `kind` cluster).
- **The ceiling (physics, not debt):** the most it can ever do is **complete mediation + proof** on the path it sits in — it cannot govern a credential the agent already holds, a directly-wired actuator, covert channels, or the undecidable "is this harmful" (which only ever resolves to ABSTAIN). Inventory ≠ enforcement; the Body enforces only once it is deployed in the agents' path.

> **Full detail** — every call path, every flag, what is live vs flag-gated vs deploy-gated vs deliberately-not-built, and how to verify it yourself — **is in [`execution.md`](../../execution.md)** (repo root). That file is the authoritative execution-layer map; the above is the one-screen summary.

---

## 2. The closed loop, end-to-end (and how much of it is real)

The four E2E traces in `_traces/` followed real call chains hop-by-hop. Verdicts:

```
                 ┌────────────────────────────────────────────────────────────────┐
   DISCOVER ─────┤ POST /v1/surface/conduit/connect/entra/start  (one-click consent)│  CONFIRMED (Entra)
                 │  → ConnectBroker: REQUESTED→CONSENTED→PROBED→SEALED              │  Okta/Google/Ping
                 │  → LiveGraphTransport (real OAuth2 + paging)                     │  coded but not wired
                 │  → ProviderConsentGraphConnector extracts agents                 │
                 │  → ReconciliationEngine promotes → shared agent_registry ────────┼──┐
                 └────────────────────────────────────────────────────────────────┘  │
                                                                                       ▼
                 ┌────────────────────────────────────────────────────────────────┐
   DECIDE   ─────┤ POST /evaluate  OR  POST /v1/govern/decide                       │  blocking CONFIRMED
                 │  → EvaluateActionCommand.execute                                 │  receipt PARTIAL
                 │  → PolicyDecisionPoint.evaluate  (engine/pdp.py:243)             │  (flag-gated, §5)
                 │     deterministic gate → specialists (17 judges) → contracts     │
                 │     → semantic → governance/ecosystem → Verdict                  │
                 │  → released = (verdict==PERMIT); FORBID/ABSTAIN → held           │
                 └───────────────────────────────┬────────────────────────────────┘
                                                  ▼
                 ┌────────────────────────────────────────────────────────────────┐
   PROVE    ─────┤ seal_enforcement_decision(ledger, ...)  [if TEX_SEAL_DECISIONS] │  crypto CONFIRMED
                 │  → SealedFactLedger.append_sequenced                             │  wired-but-default-OFF
                 │     SHA-256 hash-chain + ECDSA-P256 + ML-DSA-65 dual-sign        │  external anchor PARTIAL
                 │  → EvidenceRecorder also chains every decision (PQ-signed)       │
                 │  → EvidenceExporter.build_slice_bundle → offline-verifiable      │  ← proven with ZERO
                 └───────────────────────────────┬────────────────────────────────┘     tex imports
                                                  ▼
                 ┌────────────────────────────────────────────────────────────────┐
   LEARN    ─────┤ POST /decisions/{id}/seal  (human approve/hold/refuse)          │  CONFIRMED
                 │  → capture_resolution_outcome (TEX_AUTOSEAL_OUTCOME, default ON) │
                 │  → orchestrator.ingest_outcome → OutcomeValidator (10 checks)    │
                 │     → trust gate: only VALIDATED/VERIFIED reach calibration      │
                 │  → AnytimeValidCalibrationTrigger (e-process) → propose()        │
                 │     → sufficiency/poisoning/drift/safety/replay/OPE gates        │
                 │  → PENDING proposal → human-approved → calibrator recalibrates ──┼──┐
                 └────────────────────────────────────────────────────────────────┘  │
                            ▲                                                          │
                            └──────────  thresholds updated, loop closes  ────────────┘
```

**Bottom line of the loop:** the structure is real and wired end-to-end. The two PARTIAL verdicts are both
the *same* nuance — the **cryptographic receipt/seal is built, correct, and live-wired but ships
default-OFF** (`TEX_SEAL_DECISIONS` unset). Flip that one flag and the PROVE leg activates. Blocking,
discovery, evidence-bundle export, and the learning flywheel are all live on a default boot.

---

## 3. The composition root & boot (from `_spine/runtime-wiring.md`)

- **Entry:** `src/tex/main.py:2016` `app = create_app()`; production runs `uvicorn tex.main:app`.
- **Assembly:** `build_runtime()` (`main.py:519–1233`) instantiates **one `TexRuntime` dataclass** —
  `@dataclass(frozen=True, slots=True)`, **50 fields**, in a fixed 70-step order — then
  `_attach_runtime_to_app()` (`main.py:1586`) publishes every field onto `app.state` by exact name and
  builds a dozen extra `app.state`-only collaborators (standing governance, standing gate, VIGIL stack,
  conduit broker).
- **Live-boot ground truth (verified, default config, no `DATABASE_URL`, no flags):**
  - **All 50 `TexRuntime` fields are non-`None`.** The `Any = None` typing is a constructor affordance, not
    a runtime gap. Nothing is left unwired on the default in-memory path.
  - **133 routes mounted** across **25 routers**.
  - Store-aliasing holds (`memory.decisions is decision_store`, etc.) — single writer per artifact.
  - A daemon `provenance_feed` worker thread starts; real ML-DSA-65 keygen runs natively (`pyca-cryptography`).

### What changes behavior at boot (only four things)
1. `DATABASE_URL` → swaps in-memory stores for Postgres-backed drop-ins (durability).
2. `TEX_ECOSYSTEM` → activates the 8-step ecosystem engine (else it self-disables to an O(1) inert PERMIT).
3. `TEX_SEAL_DECISIONS` → gives the PDP a real `decision_ledger` (else `None` → all seals are no-ops).
4. Contract/discovery env flags (mode, connectors). Everything else is always built.

### Three real boot-time bugs/quirks found (worth fixing, none fatal)
1. **`_should_defer_runtime()` is dead code** (`main.py:1258`): it calls `get_settings().is_production_like()`
   but `is_production_like` is a `@property` (`config.py:204`) → `TypeError`, swallowed by a bare `except` →
   always returns `False`. **Auto-deferral never engages**; the `_WarmupGateMiddleware` + background-build
   path is reachable only by setting `TEX_DEFER_RUNTIME=1` by hand. Contradicts its own docstring.
2. **`DiscoveryService` is built twice** (`main.py:704` and `746`); the first instance is immediately
   shadowed, so `_build_discovery_connectors()` runs twice per boot. Dead allocation.
3. **Imported-but-unused connectors:** `KernelEbpfConnector`, `CloudAuditConnector`, `NetworkEgressConnector`
   are imported at `main.py:49–62` but never instantiated by `_build_discovery_connectors`.

---

## 4. THE RECONCILED SUBSYSTEM INVENTORY (the definitive answer to "what's wired")

> **Why two numbers existed.** The static reachability table (`_spine/reachability.md`) classifies at
> **package grain**: a subsystem is "LIVE" if *≥1 of its files* is in the import closure of `tex.main` /
> `tex.api`. That gives **LIVE=46, INDIRECT=7, DEMO_TEST_ONLY=1, ORPHAN=3** (of 57 incl. `_root`). The
> per-subsystem dossiers then re-checked at **file grain** and **downgraded several** packages whose only
> live edge runs through test/demo code, or whose live file is inert by default. **This table adopts the
> dossier (file-grain) corrections** — it is the authority; where it differs from `reachability.md`, this
> wins.

**Status legend:**
- 🟢 **LIVE-ACTIVE** — on the default-boot call path and doing real work out of the box.
- 🟡 **LIVE-DORMANT** — wired into the running app but inert until a flag/binding is set (§5).
- 🟠 **LIVE-PARTIAL** — package reachable, but a material sub-tree of files is dead/test-only.
- 🔵 **DEMO/TEST-ONLY** — real code, but only reachable from `tests/`, `scripts/`, or the non-live `capstone` harness.
- ⚪ **ORPHAN** — zero importers anywhere.

### 4.1 DISCOVER + IDENTITY layer

| Subsystem | Files | Status | What it is (verified) | Dossier |
|---|---|---|---|---|
| `discovery` | 52 | 🟢 LIVE-ACTIVE | Connect-your-directory conduit + 14 connectors (Entra/OpenAI/Slack live, others mock), scan scheduler, reconciliation, dormancy/presence, discovery ledger. Entra path runtime-proven. | [discovery.md](subsystems/discovery.md) |
| `agent` | 4 | 🟢 LIVE-ACTIVE | Identity/capability/behavioral evaluation streams + `AgentEvaluationSuite`; feeds the PDP. | [agent.md](subsystems/agent.md) |
| `ontology` | 7 | 🟠 LIVE-PARTIAL | Entity/event type registries (live as construction inputs); `OntologyValidator` only fires under `TEX_ECOSYSTEM`. | [systemic-ontology.md](subsystems/systemic-ontology.md) |

### 4.2 DECIDE layer (the brain = PDP, the body = enforcement)

| Subsystem | Files | Status | What it is (verified) | Dossier |
|---|---|---|---|---|
| `engine` | 11 | 🟢 LIVE-ACTIVE | The Policy Decision Point (`pdp.py`) + the Hold (first-class ABSTAIN), risk-spine e-values, CRC gate, credal-conformal hold, verdict transcript/certificate. The core brain. | [engine.md](subsystems/engine.md) |
| `specialists` | 25 | 🟢 LIVE-ACTIVE | 17 specialist "judges" that each contribute a risk signal to the PDP (incl. the `runtime/` defense modules — planguard/clawguard/agentarmor/mage/mcpshield — wired here, not in main). | [specialists.md](subsystems/specialists.md) |
| `deterministic` | 3 | 🟢 LIVE-ACTIVE | Stream-1 regex/rule gate + autonomous-attack cadence circuit-breaker. First line of the PDP. | [contracts.md](subsystems/contracts.md) |
| `contracts` | 8 | 🟢 LIVE-ACTIVE | LTLf behavioral contracts (RV-LTL 4-valued), Rule-of-Two, action-class reversibility×blast-radius floor, runtime enforcer. | [contracts.md](subsystems/contracts.md) |
| `semantic` | 5 | 🟢 LIVE-ACTIVE | LLM judge with deterministic fallback (Stream-2); binds OpenAI only when `TEX_SEMANTIC_PROVIDER=openai`. | [semantic.md](subsystems/semantic.md) |
| `governance` | 20 | 🟠 LIVE-PARTIAL | `path_policy` (LTLf path checker) + `private_data_exec.ifc` (information-flow control / NeuroTaint) are LIVE; `kernel_mcp` + `stpa` (~8 files, ~2,100 LOC) reach no running path. | [governance.md](subsystems/governance.md) |
| `enforcement` | 7 | 🟡 LIVE-DORMANT (seal) | `TexGate`, `standing_transport` (the live in-process PEP) ARE wired (`main.py:1754`); the proof-carrying `seal.py` half is NOT attached on the live path (observer never passed — §8). | [enforcement-pep.md](subsystems/enforcement-pep.md) |
| `commands` | 5 | 🟢 LIVE-ACTIVE | The 5 CQRS entry verbs: `evaluate_action` (POST `/evaluate`), `report_outcome` (`/outcomes`), `activate_policy`, `calibrate_policy`, `export_bundle`. The app's actual API actions. | [commands.md](subsystems/commands.md) |
| `ecosystem` | 7 | 🟡 LIVE-DORMANT | 8-step ecosystem governance engine + bridge. Built always, but `enabled` self-reads `TEX_ECOSYSTEM` (default off → inert PERMIT, advisory-only even when on). | [ecosystem-interchange.md](subsystems/ecosystem-interchange.md) |
| `camel` | 6 | 🟢 LIVE-ACTIVE | CaMeL capability-tracking interpreter (FIDES dual-axis integrity×confidentiality), Q-LLM, tool policy; reached via `camel_specialist`. | [camel-gateway.md](subsystems/camel-gateway.md) |
| `pcas` | 12 | 🟢 LIVE-ACTIVE | PCAS Datalog policy compiler, invoked via `pcas_specialist`. | [pcas-proofs.md](subsystems/pcas-proofs.md) |
| `retrieval` | 1 | 🟢 LIVE-ACTIVE | RAG grounding orchestrator (policy clauses/entities/precedents) feeding the PDP. | [graph-db-retrieval.md](subsystems/graph-db-retrieval.md) |
| `intervention` | 6 | 🟡 LIVE-DORMANT | Restorative intervention selection; wired via the ecosystem engine (so gated with it). | [intervention.md](subsystems/intervention.md) |
| `institutional` | 7 | 🟡 LIVE-DORMANT | Governance LTS / subagent inheritance; wired via the ecosystem engine. | [compliance-institutional.md](subsystems/compliance-institutional.md) |
| `systemic` | 8 | 🟠 LIVE-PARTIAL | `probguard` is reachable from the PDP; the `SystemicRiskEvaluator` scorer is constructed with `systemic=None` in main and gated on `TEX_ECOSYSTEM_SYSTEMIC` → inert by default. | [systemic-ontology.md](subsystems/systemic-ontology.md) |
| `runtime` | 16 | 🟢 LIVE-ACTIVE (indirect) | Execution-defense layer (planguard/clawguard/agentarmor/mage/mcpshield). Orphan from `main.py`; LIVE via the specialist suite into the PDP. | [runtime.md](subsystems/runtime.md) |
| `drift` | 7 | 🟢 LIVE-ACTIVE | Anytime-valid drift e-process, BOCPD, adaptive CUSUM, change-point detector. Used by the learning trigger and scheduler. | [drift.md](subsystems/drift.md) |
| `causal` | 12 | 🟢 LIVE-ACTIVE | Incident attribution: CHIEF hierarchical causal graph, ARM agentic reference monitor, LSH-Shapley blame, conformal attribution. Via `/v1/incidents/.../attribute`. | [causal.md](subsystems/causal.md) |

### 4.3 PROVE layer (evidence + crypto + provenance spine)

| Subsystem | Files | Status | What it is (verified) | Dossier |
|---|---|---|---|---|
| `evidence` | 12 | 🟢 LIVE-ACTIVE | The canonical hash-chained evidence chain (JSONL + Postgres mirror), recorder/exporter, SCITT signed statements, PQ seal, TEE binding, ZK attribution envelope. Bundles are offline-verifiable (proven). | [evidence.md](subsystems/evidence.md) |
| `provenance` | 14 | 🟢 LIVE-ACTIVE | `SealedFactLedger` (the sealed-fact spine: ECDSA+ML-DSA dual-sign, per-identity gap detection), continuous provenance feed, enforcement/decision/attempt seals, delegation graph. | [provenance.md](subsystems/provenance.md) |
| `events` | 6 | 🟢 LIVE-ACTIVE | Append-only ledger primitives: RFC 8785 canonical JSON, ECDSA-P256 provider, crypto provenance. The shared signing substrate. | [events-receipts.md](subsystems/events-receipts.md) |
| `pqcrypto` | 19 | 🟢 LIVE-ACTIVE | Post-quantum spine (16 importers): ML-DSA-65 primary (native→liboqs→fail-closed), ML-KEM, algorithm-agility dispatcher. Real FIPS-204 sizes verified. | [pqcrypto.md](subsystems/pqcrypto.md) |
| `c2pa` | 16 | 🟢 LIVE-ACTIVE | C2PA Content Credentials: COSE_Sign1/CBOR, manifest signer/verifier, RFC-3161 TSA, OCSP, durable watermarks, hardware-attestation binding. | [c2pa.md](subsystems/c2pa.md) |
| `tee` | 7 | 🟢 LIVE-ACTIVE | Composite TEE attestation (Intel TDX + NVIDIA H100); `/v1/tee`. Production vs test mode via `TEX_TEE_ATTESTATION_MODE`. | [tee-verifier.md](subsystems/tee-verifier.md) |
| `zkprov` | 11 | 🟢 LIVE-ACTIVE | Zero-knowledge dataset/inference provenance proofs; `/v1/zkprov`. 0 `NotImplementedError`. | [zkprov-zkpdp.md](subsystems/zkprov-zkpdp.md) |
| `nanozk` | 12 | 🟡 LIVE-DORMANT | Poseidon-chain ZK primitives. Reachable but the package header self-labels **"DEACTIVATED PLACEHOLDER (research-early)."** Treat as not-yet-load-bearing. | [nanozk.md](subsystems/nanozk.md) |
| `interchange` | 5 | 🟢 LIVE-ACTIVE | GIX inter-org governance interchange + the external RFC-3161 anchor verifier (real freetsa token on disk). Anchoring auto-wiring is double-flag-gated (§5). | [ecosystem-interchange.md](subsystems/ecosystem-interchange.md) |
| `memory` | 9 | 🟢 LIVE-ACTIVE | V18 unified durable store (`MemorySystem`): the single source of truth aliasing decision/policy/recorder stores. | [memory.md](subsystems/memory.md) |
| `vet` | 10 | 🟢 LIVE-ACTIVE | Verifiable Evidence Trail — Web Proofs, AID, SCITT; `/v1/vet`. | [vet.md](subsystems/vet.md) |

### 4.4 LEARN layer

| Subsystem | Files | Status | What it is (verified) | Dossier |
|---|---|---|---|---|
| `learning` | 15 | 🟢 LIVE-ACTIVE | `FeedbackLoopOrchestrator`: ingest→validate→reputation→propose under sufficiency/poisoning/drift/safety/replay/OPE gates; anytime-valid calibration trigger. Closes the loop (proven). | [learning.md](subsystems/learning.md) |
| `selfgov` | 1 | 🟡 LIVE-DORMANT | Reflexive self-governance — gates Tex's own controller mutations. Call-sites are live in 6 modules; the governor is **never bound in production** (only `capstone` binds it) → passthrough by default. Contains the `CONTROLLER_MUTATION_CENSUS` (Tex's own machine-checked wired/dead map). | [selfgov.md](subsystems/selfgov.md) |

### 4.5 Cross-cutting (vocabulary, persistence, surface, cognition)

| Subsystem | Files | Status | What it is (verified) | Dossier |
|---|---|---|---|---|
| `domain` | 22 | 🟢 LIVE-ACTIVE | The universal vocabulary (imported by 34 subsystems): EvaluationRequest, Decision, Verdict, Outcome, Policy, abstention certificate, OWASP-ASI findings, trust tiers. | [domain.md](subsystems/domain.md) |
| `observability` | 4 | 🟢 LIVE-ACTIVE | OpenTelemetry telemetry + discovery metrics (imported by 24 subsystems). The universal sink. | [observability.md](subsystems/observability.md) |
| `stores` | 20 | 🟠 LIVE-PARTIAL | In-memory + Postgres impls of every store (policy/decision/outcome/precedent/entity/ledger/...). One file (`behavioral_provenance_ledger_postgres.py`) is orphan/test-only. | [stores.md](subsystems/stores.md) |
| `db` | 1 | 🟢 LIVE-ACTIVE (dormant path) | Shared Postgres connection helper; live import, but the code path is dormant unless `DATABASE_URL` is set. | [graph-db-retrieval.md](subsystems/graph-db-retrieval.md) |
| `graph` | 5 | 🟢 LIVE-ACTIVE | Temporal knowledge graph (in-memory) + delegation graph projection. | [graph-db-retrieval.md](subsystems/graph-db-retrieval.md) |
| `api` | 29 | 🟢 LIVE-ACTIVE | 25 routers / ~130 routes spanning all layers: `/evaluate`, `/v1/govern`, `/v1/surface/conduit`, `/v1/surface/discovery`, `/decisions/.../seal`, `/v1/learning`, `/v1/vigil`, `/v1/voice`, `/v1/tee`, `/v1/vet`, `/v1/zkprov`, guardrail + MCP surfaces. | [api.md](subsystems/api.md) |
| `vigil` | 14 | 🟢 LIVE-ACTIVE | "What Tex chooses to say": `VigilEngine` (Dirichlet-Normal learner, expected-free-energy selector, causal-attribution port), held-decision provider; `/v1/vigil`. | [vigil.md](subsystems/vigil.md) |
| `voice` | 6 | 🟢 LIVE-ACTIVE (muted) | Grounded spoken-answer cascade; `/v1/voice`, `/v1/ask`. Routes live; speaking gated by `VOICE_ENABLED` (currently muted per product decision). | [voice.md](subsystems/voice.md) |
| `gateway` | 3 | 🟢 LIVE-ACTIVE | Self-hosted speech gateway (pluggable STT/TTS, short-lived recognizer grant). | [camel-gateway.md](subsystems/camel-gateway.md) |
| `policies` | 1 | 🟢 LIVE-ACTIVE | `policies.defaults` — the seed policies (`build_default_policy`/`build_strict_policy`) the app boots with. | [contracts.md](subsystems/contracts.md) |
| `sim` | 13 | 🟢 LIVE-ACTIVE | The Tex sandbox simulator. **`python -m tex.sim live reference` is the actual Render `startCommand`** (render.yaml), and `TEX_SANDBOX=1` routes discovery to sim connectors. | [sim-bench-capstone.md](subsystems/sim-bench-capstone.md) |

### 4.6 NOT on the live path (orphan / demo / test-only — real code, not reachable from the running app)

| Subsystem | Files | Status | What it is + why it's off-path | Dossier |
|---|---|---|---|---|
| `_pending` | 33 | ⚪ ORPHAN | Staging island: A2A/Okta/Microsoft/NIST/Ping interop stubs, pitch decks, alt API routes, NAIC/EU-AI-Act compliance scaffolds. Zero importers. | [pending.md](subsystems/pending.md) |
| `operator` | 4 | ⚪ ORPHAN | k8s-style auto-deploy/auto-enroll controller for the PEP (Helm-wired, Python-orphan). | [enforcement-pep.md](subsystems/enforcement-pep.md) |
| `pep` | 3 | ⚪ ORPHAN | Standalone PEP proxy + `__main__` (k8s data-plane). The LIVE in-process gate is `enforcement.standing_transport`, NOT this package. | [enforcement-pep.md](subsystems/enforcement-pep.md) |
| `capstone` | 5 | 🔵 DEMO/TEST | End-to-end sealed-bundle composition/tamper harness; only `scripts/capstone_demo.py` + tests import it. (It IS the one place the reflexive governor is bound.) | [sim-bench-capstone.md](subsystems/sim-bench-capstone.md) |
| `adversarial` | 7 | 🔵 DEMO/TEST | Adaptive red-team / fuzz harness ("attacker moves second"); pulled in by capstone + scripts/tests. | [adversarial.md](subsystems/adversarial.md) |
| `bench` | 13 | 🔵 DEMO/TEST | AgentDojo harness, replay-trial, honest-decline demo, evidence-bundle court-exhibit core, Wave-2 corpus. | [sim-bench-capstone.md](subsystems/sim-bench-capstone.md) |
| `compliance` | 13 | 🔵 DEMO/TEST | EU AI Act / FTC / CA / CO / NY regulatory evidence emitters. Imported only by tests. (`selfgov`'s census formally marks this dead.) | [compliance-institutional.md](subsystems/compliance-institutional.md) |
| `receipts` | 4 | 🔵 DEMO/TEST | HMAC tool receipts; only non-self importer is the orphan `_pending.pitch`. | [events-receipts.md](subsystems/events-receipts.md) |
| `safeflow` | 4 | 🔵 DEMO/TEST | Transactional execution with WAL; only importers are a test + an out-of-tree audit list. | [enforcement-pep.md](subsystems/enforcement-pep.md) |
| `verifier` | 3 | 🔵 DEMO/TEST | Standalone offline verdict checker; only its own `__init__`/`__main__` + tests. | [tee-verifier.md](subsystems/tee-verifier.md) |
| `zkpdp` | 1 | 🔵 DEMO/TEST | Proof-carrying verdict over the arbitration relation; only capstone + tests. | [zkprov-zkpdp.md](subsystems/zkprov-zkpdp.md) |
| `proofs` | 1 | ⚪ EMPTY | Reserved placeholder; no code. | — |

### 4.7 The definitive count

- **49 of 57 subsystems are genuinely on a call path** from `create_app`/`build_runtime` or an `api/` router.
- **8 are NOT reachable** from the running app: 3 ORPHAN (`_pending`, `operator`, `pep`) + 5 that are only
  reachable through the non-live `capstone` harness or tests (`capstone`, `adversarial`, `bench`, `zkpdp`,
  plus `compliance` tests-only; `receipts`/`safeflow`/`verifier` similarly self-/test-only). Plus `proofs` (empty).
- Of the ~49 wired, **~38 are LIVE-ACTIVE on a default boot**; the rest are **LIVE-DORMANT** (flag/binding-gated,
  §5) or **LIVE-PARTIAL** (package live, sub-tree dead).
- **So the honest one-liner: "almost the entire system is wired; a handful of advanced surfaces are
  intentionally flag-gated OFF by default, and ~8 packages are staging/demo/test-only."** The old "only a
  dozen are wired" claim was wrong (it under-counted by reading docstrings); the "46 wired" claim was right
  at package grain but over-counted active behavior (it didn't subtract the flag-gated and dead-subtree parts).

---

## 5. THE FLAG → ACTIVATION MATRIX (the keystone — what you must set to make the advertised system real)

Tex ships **safe-by-default**: the advanced cryptographic/governance surfaces are real but OFF until opted in.
This matrix is the single source of truth for which switch turns which capability live.

| Env flag | Default | What it activates | Where (file:line) |
|---|---|---|---|
| `TEX_SEAL_DECISIONS` | **OFF** | **The whole proof-carrying-seal spine.** Gives the PDP a real `SealedFactLedger`; enables decision + enforcement receipts on `/v1/govern/decide`. Without it every seal is a no-op. | `main.py:870-873,882`; `governance_standing_routes.py:96-99` |
| `TEX_GIX_WITNESS` | **OFF** | GIX checkpoint publisher that feeds sealed record-hashes to the anchor job (requires `TEX_SEAL_DECISIONS` too). | `interchange/gix.py:663-687`; `main.py:874` |
| `TEX_EVIDENCE_ANCHOR_ENABLE` | **OFF** | The daily external RFC-3161 (freetsa) anchoring job for tree-heads. | `scripts/anchor_checkpoint.py:153-155` |
| `TEX_ECOSYSTEM` | **OFF** | The 8-step ecosystem governance engine (else inert O(1) PERMIT). Also brings `intervention`/`institutional` alive. | `ecosystem/engine.py`; `main.py:946` |
| `TEX_ECOSYSTEM_SYSTEMIC` | **OFF** | The systemic-risk scorer — **but** `main.py:946` constructs the engine with no `systemic=` arg, so the scorer stays `None` even with the flag. (Needs a code change to fully activate.) | `ecosystem/engine.py:211,858` |
| `DATABASE_URL` | unset → in-memory | Swaps in Postgres-backed precedent/agent/ledger/discovery stores + evidence/manifest mirrors (durability). | `main.py:546,562-571` |
| `TEX_AUTOSEAL_OUTCOME` | **ON** | Auto-captures human resolutions into the learning loop (the flywheel's fuel). One of the few default-ON advanced features. | `api/outcome_autoseal.py:84-87` |
| `TEX_CONTRACTS_DISABLE` / `TEX_CONTRACTS_MODE` | enabled / `session_scoped` | Behavioral-contract enforcement on/off and stateless-vs-session. | `main.py:844-862` |
| `TEX_DISCOVERY_ENTRA_*` / `_OPENAI_*` / `_SLACK_*` | unset → mock/fixture | Live discovery connectors (real API reads) instead of demo fixtures. | `main.py:1912-2011` |
| `TEX_CONDUIT_ENTRA_CLIENT_ID` / `_SECRET` | unset → consent-only | Live Microsoft Graph transport for the one-click conduit (else `/start` returns `configured:false`). | `main.py:1481-1496` |
| `TEX_SANDBOX` | OFF | Routes discovery to the sim's sandbox connectors. | `main.py:1881` |
| `TEX_SEMANTIC_PROVIDER=openai` | unset → deterministic | Binds the LLM semantic judge + the VIGIL explainer (else deterministic fallback). | `_attach_runtime_to_app` (VIGIL), `semantic/` |
| `TEX_TEE_ATTESTATION_MODE` | `production` | TEE attestation mode; `test` is rejected in production-like envs by the fail-closed settings guard. | `config.py:230` |
| `TEX_DEFER_RUNTIME` | OFF | Background-build + warmup-gate boot (the ONLY way to engage deferral — auto-detect is broken, §3). | `main.py:1236-1260` |
| `VOICE_ENABLED` | muted | Whether the voice layer actually speaks (routes always mount). | `voice/` |
| reflexive governor **binding** | unbound | (Not an env flag — a programmatic `bind`.) Activates `selfgov` gating of Tex's own controller mutations. Only `capstone/flow.py:312` binds it; never bound in production. | `selfgov/governor.py` |
| `TEX_FRONTIER_*` (12 flags) | all OFF | Gate scaffolded frontier modules (pqcrypto/c2pa/receipts/zkprov/nanozk/tee/vet/runtime/governance/interop/compliance/pitch). Not read by `main.py`. | `frontier_config.py` |

**The product-critical subset:** to run the full "discover → decide → **prove with a sealed receipt** → learn"
story end-to-end you must set at minimum **`TEX_SEAL_DECISIONS=1`** (and `DATABASE_URL` for a bounded,
durable ledger). Discovery, deciding/blocking, evidence-bundle export, and learning already work without any flags.

---

## 6. Cross-cutting data flows (the four verified call chains, condensed with cites)

**6.1 Action evaluation (DECIDE + PROVE)** — *`_traces/action-eval-e2e.md`*
`POST /v1/govern/decide` (`governance_standing_routes.py:73`) → `StandingGovernance.decide` (`standing.py:322`) →
`EvaluateActionCommand.execute` (`evaluate_action.py:187`) → `PolicyDecisionPoint.evaluate` (`pdp.py:243`):
deterministic gate → 17 specialist judges → contracts (LTLf) → semantic → governance/ecosystem → `Verdict`.
`released = verdict==PERMIT`; FORBID/ABSTAIN/structural-floor → `released=False` (genuine block, flag-independent).
If `app.state.decision_ledger` is non-None → `seal_enforcement_decision` → `SealedFactLedger.append_sequenced`
(SHA-256 chain + ECDSA-P256 + ML-DSA-65). **Block: always live. Receipt: `TEX_SEAL_DECISIONS` only.**

**6.2 Connect a directory (DISCOVER)** — *`_traces/discovery-conduit-e2e.md`* — **CONFIRMED, runtime-proven**
`/v1/surface/conduit/connect/entra/start` → `ConnectBroker` state machine (REQUESTED→CONSENTED→PROBED→SEALED)
→ `LiveGraphTransport` (real OAuth2 client-credentials + `@odata.nextLink` paging + 429 backoff) →
`ProviderConsentGraphConnector` extracts `CandidateAgent`s with blast-radius/risk → `ReconciliationEngine`
promotes to a real `AgentIdentity` → **the same `agent_registry`** that `EvaluateActionCommand` reads at decision
time (`evaluate_action.py:399`). A discovered agent is governed the instant it acts. *Only Entra is registered in
the live broker; Okta/Google/Ping are real code on the shelf.*

**6.3 Offline-verifiable evidence (PROVE)** — *`_traces/evidence-proof-e2e.md`* — **CONFIRMED, strongest result**
`EvidenceRecorder.record_decision` PQ-signs each payload *before* hashing, then SHA-256 hash-chains it.
`EvidenceExporter.build_slice_bundle` emits a CT-style inclusion witness. **Proven with a script that asserts
`"tex" not in sys.modules`**: integrity recomputed with pure stdlib; authorship verified against an out-of-band
pinned key with the `cryptography` lib only; a re-signed PERMIT forgery was **rejected with `InvalidSignature`**.
Integrity needs no trust; authorship needs only a standard public-key pin. This is the genuine moat.

**6.4 Learning flywheel (LEARN)** — *`_traces/learning-flywheel-e2e.md`* — **CONFIRMED**
`POST /decisions/{id}/seal` (human approve/hold/refuse) → `capture_resolution_outcome` (default ON) →
`orchestrator.ingest_outcome` → `OutcomeValidator` (10 checks; failures → QUARANTINED) → trust gate
(`is_calibration_eligible` ⇒ VALIDATED/VERIFIED only reach the calibrator) → `AnytimeValidCalibrationTrigger`
(λ-grid mixture e-value, Ville's inequality) → `propose()` behind sufficiency/poisoning/drift-freeze/
safety-guard/replay/OPE gates → PENDING proposal → **human-approved** → `calibrator.apply_recommendation` →
`policies.activate(new_version)`. The vetting gate has real teeth; application is unconditionally human-gated.

---

## 7. Technology & state-of-the-art catalog (what's actually in the code)

**Cryptography & proofs**
- Post-quantum signatures: **ML-DSA-65** (FIPS 204) via pyca/cryptography native → liboqs → fail-closed (`pqcrypto/ml_dsa.py`); **ML-KEM** key encapsulation. Verified real key/sig sizes (pubkey 1952 B, sig 3309 B).
- Classical: **ECDSA-P256** (SECP256R1/SHA-256, `events/_ecdsa_provider.py`), **Ed25519** (signed notes / agent credentials).
- **Dual-signing** envelope (`CryptoAgileSealer`): same record_hash signed ECDSA + ML-DSA, crypto-agile.
- **SHA-256 hash-chains** with per-identity monotonic sequencing → missing receipts are detectable gaps (`provenance/ledger.py`).
- **RFC 8785** JSON Canonicalization (deterministic hashing); **RFC 9162** Certificate-Transparency-v2 Merkle trees + inclusion proofs.
- **RFC 3161** TSA timestamping with full CMS signature verification against a pinned cert (`interchange/external_anchor.py`); a real freetsa.org token is committed in `anchors/`.
- **C2PA Content Credentials**: COSE_Sign1, deterministic CBOR, OCSP stapling, durable watermarks, hardware-attestation binding (`c2pa/`).
- **SCITT** signed statements; **Groth16** ZK attestation envelope for attribution (`evidence/attribution_zk.py`); **Poseidon-chain** ZK (`nanozk`, deactivated); ZK provenance backends (`zkprov`).
- **TEE attestation**: Intel TDX + NVIDIA H100 composite (`tee/`).

**Decision theory & verification**
- **LTLf** (finite-trace Linear Temporal Logic) behavioral contracts with **RV-LTL 4-valued** runtime semantics (`contracts/_ltl.py`, `governance/path_policy/ltlf.py`).
- **Rule-of-Two** structural contract; **action-class** reversibility × blast-radius floor.
- **Conformal Risk Control (CRC)** verdict gate; **credal-conformal hold + EPIG** resolver; **multiplicative e-value risk spine** (`engine/`).
- First-class **ABSTAIN / the Hold** with a sealed **Abstention Certificate**.
- **CaMeL** capability-tracking dual-LLM interpreter with **FIDES** integrity×confidentiality lattice (`camel/`); **Quarantined-LLM**.
- **Information-Flow Control** with Contextual-Integrity norms + **NeuroTaint** cross-session memory + ARM-style provenance (`governance/private_data_exec/ifc/`).
- **PCAS Datalog** policy compiler.

**Statistics & learning**
- **Anytime-valid** sequential testing: λ-grid mixture e-values, **Ville's inequality** p-values (`drift/_anytime_valid.py`).
- **BOCPD** (Bayesian Online Change-Point Detection) + **adaptive CUSUM** (`drift/`).
- **Off-Policy Evaluation** with anytime-valid upper bounds on counterfactual unsafe-release rate.
- **Calibration safety**: hard floors/ceilings, per-cycle delta clips, 24h cumulative budget, abstain-band preservation.
- **Reporter reputation**: exponential time-decay (14d half-life), bounded weights; **poisoning detector** (reporter clustering / label-shift).
- **Dirichlet-Normal** active-inference learner + **Expected-Free-Energy** selection in VIGIL (what to say).

**Causal attribution**
- **CHIEF** hierarchical causal graph; **ARM** (Agentic Reference Monitor); **LSH-Shapley** blame distribution; **conformal** error attribution; OTAR (Observation/Thought/Action/Result) parsing.

**Platform**
- Python 3 / FastAPI / Starlette ASGI / uvicorn; pydantic-settings (fail-closed prod secret validation); frozen-slots dataclasses; daemon worker threads; optional Postgres write-through-cache; OpenTelemetry / OpenMetrics.

---

## 8. The honest gaps & sharp edges (read before you trust a marketing line)

1. **The proof-carrying gate (this branch's headline) is real, tested, and live-wired — but default-OFF and
   not attached via the observer abstraction.** Two facts: (a) `TEX_SEAL_DECISIONS` defaults off →
   `decision_ledger=None` → seals are no-ops; (b) `build_standing_gate(app.state.standing_governance)` is
   called at `main.py:1761` **with no `observer=`**, so the in-process `SealingGateObserver`/
   `build_proof_carrying_gate` path is never exercised in the running app (only in tests/scripts). To make the
   gate emit per-decision receipts on the live path: set `TEX_SEAL_DECISIONS=1` (covers `/v1/govern/decide`),
   and to seal the in-process `TexGate` pass a `SealingGateObserver` into `build_standing_gate`.
2. **External time-anchoring is "next-phase" for the sealed-fact ledger.** The committed real freetsa token
   anchors the **gix decision-log** (`origin=tex.local/gix-decision-log`), not a demonstrated `SealedFactLedger`
   chain; the latter's real-TSA anchoring is library-complete but flag-gated and only exercised against a local
   throwaway TSA in selftests. Honestly self-labelled `RESEARCH_SOLID` / `research-early` in code.
3. **The ecosystem engine and systemic-risk scorer are inert by default**, and the systemic scorer needs a code
   change (pass `systemic=` at `main.py:946`) on top of `TEX_ECOSYSTEM_SYSTEMIC` to do anything.
4. **`selfgov` reflexive governance is wired but never bound in production** — its safety property is not in
   force on a default deploy; only the capstone demo binds it. (The module is unusually self-honest about this.)
5. **Two store implementations are durable only with `DATABASE_URL`** — the default in-memory ledger is unbounded;
   that's the stated reason decision-sealing ships off.
6. **`nanozk` self-labels "DEACTIVATED PLACEHOLDER."** Don't cite it as a live capability yet.
7. **Inside "LIVE" packages, some sub-trees are dead:** `governance/kernel_mcp` + `governance/stpa` (~2,100 LOC),
   one `stores` postgres file. LIVE at package grain ≠ every file runs.
8. **Multi-worker caveat:** the conduit broker's connection state is in-process (a dict); a multi-worker
   deployment loses start→callback continuity. Fine for single-worker / TestClient.

`selfgov`'s in-code `CONTROLLER_MUTATION_CENSUS` (`governor.py:232-273`, 36 entries: 18 WIRED / 10 COVERED_VIA /
8 EXCLUDED) is Tex's own machine-checked corroboration of much of the above — and it formally marks
`nanozk` / `compliance` / `_pending` as *"dead code… tested but not wired."* See [selfgov.md](subsystems/selfgov.md).

---

## 9. Dossier index (the deep detail — every cited claim lives here)

**Spine:** [runtime-wiring](_spine/runtime-wiring.md) · [reachability](_spine/reachability.md)
**Traces:** [action-eval](_traces/action-eval-e2e.md) · [discovery-conduit](_traces/discovery-conduit-e2e.md) · [evidence-proof](_traces/evidence-proof-e2e.md) · [learning-flywheel](_traces/learning-flywheel-e2e.md) · [crypto-anchor](_traces/crypto-anchor-e2e.md) · [completeness-critic](_traces/completeness-critic.md)

**Subsystem dossiers (40):**
[domain](subsystems/domain.md) · [engine](subsystems/engine.md) · [specialists](subsystems/specialists.md) · [contracts](subsystems/contracts.md) (+deterministic/policies) · [semantic](subsystems/semantic.md) · [governance](subsystems/governance.md) · [enforcement-pep](subsystems/enforcement-pep.md) (+pep/safeflow/operator) · [commands](subsystems/commands.md) · [ecosystem-interchange](subsystems/ecosystem-interchange.md) · [intervention](subsystems/intervention.md) (+commands/operator) · [pcas-proofs](subsystems/pcas-proofs.md) · [systemic-ontology](subsystems/systemic-ontology.md) · [camel-gateway](subsystems/camel-gateway.md) · [runtime](subsystems/runtime.md) · [causal](subsystems/causal.md) · [drift](subsystems/drift.md)
[discovery](subsystems/discovery.md) · [agent](subsystems/agent.md)
[evidence](subsystems/evidence.md) · [provenance](subsystems/provenance.md) · [events-receipts](subsystems/events-receipts.md) · [pqcrypto](subsystems/pqcrypto.md) · [c2pa](subsystems/c2pa.md) · [tee-verifier](subsystems/tee-verifier.md) · [zkprov-zkpdp](subsystems/zkprov-zkpdp.md) · [nanozk](subsystems/nanozk.md) · [memory](subsystems/memory.md) · [vet](subsystems/vet.md)
[learning](subsystems/learning.md) · [selfgov](subsystems/selfgov.md)
[observability](subsystems/observability.md) · [stores](subsystems/stores.md) · [graph-db-retrieval](subsystems/graph-db-retrieval.md) · [api](subsystems/api.md) · [vigil](subsystems/vigil.md) · [voice](subsystems/voice.md) · [compliance-institutional](subsystems/compliance-institutional.md) · [sim-bench-capstone](subsystems/sim-bench-capstone.md) · [adversarial](subsystems/adversarial.md) · [pending](subsystems/pending.md)

---

*Method note: 46 agents read the source over ~80 minutes (6.2M tokens), then a reconciliation pass cross-checked
every load-bearing contradiction against live code + boot probes. Where the package-grain reachability table and
the file-grain dossiers disagreed, this README adopts the file-grain (dossier) truth. If you change the wiring,
update §4/§5 here and the affected dossier — this is the document future threads will trust.*

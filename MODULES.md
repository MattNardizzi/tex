# MODULES

One card per **Tier A** and **Tier B** subpackage. Tier C is summarized in `TIER_OWNERSHIP.md`.

Each card:
- **Purpose**: what this package does in one sentence.
- **Key files**: the 3–6 files that matter when something breaks.
- **Public interface**: what callers actually use.
- **Verify**: the smallest command that proves the package still works.
- **Depends on / depended on by**: the import edges, so you know the blast radius.

---

# Tier A — Product Core

---

## `engine/` — PDP, router, contract bridge

**Purpose.** The decision pipeline. Receives `EvaluateActionRequest`, runs the six-layer pipeline (deterministic → retrieval → specialists → semantic → router → evidence), returns a `Decision` with verdict.

**Key files:**
- `engine/pdp.py` — Policy Decision Point entry, the main orchestrator
- `engine/router.py` — verdict aggregation across specialists
- `engine/contract_bridge.py` — bridges behavioral contracts into the pipeline
- `engine/__init__.py` — wires the pipeline

**Public interface.** Called by `commands/evaluate_action.py`. Returns `domain.Decision`.

**Verify:**
```bash
pytest tests/test_streaming_layer.py tests/specialists -q
```
Plus a single live evaluation: `POST /v1/guardrail/portkey` with a BEC payload — verdict should fire FORBID.

**Depends on:** `domain`, `specialists`, `semantic`, `retrieval`, `deterministic`, `evidence`, `contracts`, `stores`.

**Depended on by:** `api`, `commands`. If `engine/` breaks, the product is broken.

---

## `specialists/` — The judge layer

**Purpose.** 24 specialist judges that score actions on individual dimensions (prompt injection, BEC, data exfil, capability creep, identity spoofing, etc.). Each returns a structured score with rationale.

**Key files:**
- `specialists/_base.py` — `Specialist` interface and `SpecialistScore` dataclass
- `specialists/argus_specialist.py`, `attriguard_specialist.py`, `agentarmor_specialist.py` — the core three
- `specialists/clawguard_specialist.py`, `planguard_specialist.py`, `mcpshield_specialist.py`, `mage_specialist.py` — OWASP-style runtime guards
- `specialists/human_review.py` — escalation path
- `specialists/__init__.py` — registry of all specialists

**Public interface.** Each specialist exposes `evaluate(request) -> SpecialistScore`. The engine calls them in parallel.

**Verify:**
```bash
pytest tests/specialists tests/runtime -q
```

**Depends on:** `domain`, `semantic` (for LLM-backed specialists), `learning` (for calibration).

**Depended on by:** `engine`. Adding a new specialist requires registering it in `__init__.py`.

**Known issue:** see `KNOWN_BUGS.md` #4 — specialist judges have a fabricated-institutional-authority bypass (decision_id c447f14b).

---

## `agent/` — Identity, capability, behavioral evaluators

**Purpose.** The "fused agent governance" streams 5–7 (added after thread 10). Evaluates the agent itself: who is it claiming to be, what capabilities does it claim, what behavioral pattern does it exhibit.

**Key files:**
- `agent/identity_evaluator.py` — agent identity scoring
- `agent/capability_evaluator.py` — declared vs. observed capability check
- `agent/behavioral_evaluator.py` — behavioral pattern scoring
- `agent/fusion.py` — fuses the three streams into the engine

**Public interface.** Three evaluators with `evaluate(request) -> AgentScore`. Fused at the engine layer alongside the 4 content streams.

**Verify:**
```bash
pytest tests/test_agent_governance.py -q
```

**Depends on:** `domain`, `stores` (for identity registry).

**Depended on by:** `engine`. This is what makes Tex's 7-stream architecture different from Noma/Zenity.

---

## `commands/` — CQRS write commands

**Purpose.** The write path. All state changes go through one of: `evaluate_action`, `report_outcome`, `register_agent`, `attest_capability`. Each is a single function with audit-grade input validation.

**Key files:**
- `commands/evaluate_action.py` — the hot path, calls into engine
- `commands/report_outcome.py` — feedback ingestion for learning
- `commands/register_agent.py` — agent registry write
- `commands/attest_capability.py` — capability attestation write

**Public interface.** Called by `api/routes.py` and `api/agent_routes.py`. Returns `Decision` or `CommandResult`.

**Verify:**
```bash
pytest tests/test_api.py -q
```

**Depends on:** `engine`, `domain`, `stores`, `evidence`.

**Depended on by:** `api`. Any change here is API-visible.

---

## `domain/` — Typed contracts

**Purpose.** The shared vocabulary. Every cross-package data type lives here: `Decision`, `EvidenceRecord`, `PolicySnapshot`, `SpecialistScore`, `AgentClaim`, etc. Frozen dataclasses. **This is the most-imported package in the repo.**

**Key files:**
- `domain/decision.py` — `Decision`, verdict enum, decision IDs
- `domain/evidence.py` — `EvidenceRecord`, chain link types
- `domain/agent.py` — `AgentIdentity`, `CapabilityClaim`
- `domain/policy.py` — `PolicySnapshot`, policy IDs
- `domain/__init__.py` — re-exports

**Public interface.** Imported by 36 of 202 test files. Changing a type here is a **breaking change** across the codebase.

**Verify:** Tier A audit slice. Run the full Tier A test suite from `TIER_OWNERSHIP.md`.

**Depends on:** nothing inside `tex/`. Should stay that way.

**Depended on by:** everything. Touch with care.

---

## `evidence/` — Recorder, chain, exporter

**Purpose.** The append-only signed audit chain. Every decision produces an `EvidenceRecord` linked to the previous one by hash. Exporter produces bundles for `/decisions/{id}/evidence-bundle`.

**Key files:**
- `evidence/recorder.py` — appends records during evaluation
- `evidence/chain.py` — hash-linked chain construction + verification
- `evidence/exporter.py` — bundle export for buyer-facing endpoints
- `evidence/__init__.py`

**Public interface.** `record(decision) -> EvidenceRecord`, `export_bundle(decision_id) -> EvidenceBundle`.

**Verify:**
```bash
pytest tests/test_v16_hardening.py tests/frontier/test_attestation.py -q
```

**Depends on:** `domain`, `stores`, `pqcrypto` (for ML-DSA signing).

**Depended on by:** `engine`, `api`, `pitch`.

**Known issue:** see `KNOWN_BUGS.md` #5 — `/decisions/{id}/evidence-bundle` returns `is_chain_valid: False` on single-record slices.

---

## `retrieval/` — Retrieval layer

**Purpose.** The R in RAG. Pulls relevant prior decisions, known threat patterns, and policy context for the engine to use as evaluation input.

**Key files:** `retrieval/retriever.py`, `retrieval/__init__.py` (only 2 files, 224 LOC).

**Public interface.** `retrieve(query) -> RetrievalResult`.

**Verify:**
```bash
pytest tests/test_retrieval.py -q
```

**Depends on:** `domain`, `stores`.

**Depended on by:** `engine`.

---

## `semantic/` — LLM semantic scoring

**Purpose.** The LLM-backed scoring layer. Calls OpenAI (or fallback heuristics) to produce per-dimension semantic scores. **This is the layer that silently fell back to heuristics in the past — see CORRECTIONS_NEEDED.md.** Environment variables for OPENAI model and reasoning_effort matter here.

**Key files:**
- `semantic/scorer.py` — main scoring entry
- `semantic/prompts.py` — prompt templates per dimension
- `semantic/fallback.py` — heuristic fallback path

**Public interface.** `score(request, dimensions) -> SemanticScores`.

**Verify:** integration through `engine`. Run Tier A slice. Confirm via debug log that semantic scores are non-fallback in production.

**Depends on:** `domain`. External: OpenAI API.

**Depended on by:** `engine`, several specialists.

---

## `deterministic/` — Deterministic rule layer

**Purpose.** Hard rule matches (regex, keyword, structural) that fire before the LLM is even called. Fast deny path.

**Key files:** `deterministic/rules.py`, `deterministic/__init__.py`.

**Public interface.** `evaluate(request) -> DeterministicResult`.

**Verify:**
```bash
pytest tests/test_deterministic.py -q
```

**Depends on:** `domain`.

**Depended on by:** `engine`. This runs first in the six-layer pipeline.

---

## `contracts/` — Behavioral contracts + runtime enforcer

**Purpose.** Lets a tenant declare LTL-style behavioral contracts ("agent X may not send email after action Y") and enforces them at runtime. The "behavioral" stream of the 7-stream architecture.

**Key files:**
- `contracts/contract.py` — `BehavioralContract` dataclass + LTL parser
- `contracts/enforcer.py` — `ContractEnforcer` runtime check
- `contracts/recovery.py` — `RecoveryDispatcher` for violations
- `contracts/ltl.py` — `LTLFormula`, parser

**Public interface.** `__all__` exports 10 symbols including `BehavioralContract`, `ContractEnforcer`, `ComplianceScores`, `RecoveryDispatcher`.

**Verify:**
```bash
pytest tests/contracts -q
```

**Depends on:** `domain`, `events` (for emission).

**Depended on by:** `engine` (via `contract_bridge`), `agent`.

---

## `learning/` — Calibration governance

**Purpose.** The feedback loop. Ingests `report_outcome` calls, computes proposed calibration adjustments, gates them through a safety check before applying. **Sensitive — touches scoring weights.**

**Key files:**
- `learning/feedback.py` — feedback loop ingestion
- `learning/calibration.py` — calibration math
- `learning/safety.py` — gates dangerous calibration moves
- `learning/proposal_store.py` — pending proposal queue
- `learning/reputation.py` — reporter reputation weighting

**Public interface.** `submit_feedback(report) -> ProposalResult`, `apply_calibration(proposal_id)`.

**Verify:**
```bash
pytest tests/test_calibration_safety.py tests/test_feedback_loop.py \
       tests/test_calibration_proposal_store.py tests/test_reporter_reputation.py -q
```

**Depends on:** `domain`, `stores`, `observability`.

**Depended on by:** `api/learning_routes.py`, `specialists` (calibration affects scoring).

---

## `memory/` — Memory system public API

**Purpose.** Persistent memory for the system. `MemorySystem` is the public API; `Durable*Store` are the backing implementations.

**Key files:**
- `memory/system.py` — `MemorySystem` facade
- `memory/health.py` — `MemoryHealth` probes
- `memory/stores.py` (or `__init__.py` re-exports) — `DurableDecisionStore`, `DurablePolicyStore`, `PermitStore`

**Public interface.** 18 exports including `MemorySystem`, `MemoryHealth`, `DurableDecisionStore`, `DurablePolicyStore`, `PermitStore`, `StoredPermit`.

**Verify:** covered through API + governance tests. Run Tier A slice.

**Depends on:** `domain`, `stores`, `db`.

**Depended on by:** `engine`, `api`, `commands`.

**Known issue:** see `KNOWN_BUGS.md` #3 — `DurablePolicyStore.list_all()` calls a non-existent inner method.

---

## `stores/` — In-memory + Postgres stores

**Purpose.** 22 files of storage backends. Every stateful object (decisions, policies, permits, snapshots, connector health, drift events, evidence records) has a store here. In-memory implementations are canonical; Postgres adapters are layered on top.

**Key files:**
- `stores/decision_store.py`
- `stores/policy_store.py`
- `stores/snapshot_store.py`
- `stores/connector_health_store.py`
- `stores/drift_event_store.py`

**Public interface.** Each store exposes `put`, `get`, `list_*`, `delete` methods. Used through `memory/`.

**Verify:**
```bash
pytest tests/test_governance_snapshots.py tests/test_drift_events.py \
       tests/test_connector_health.py -q
```

**Depends on:** `domain`, `db`.

**Depended on by:** `memory`, `commands`, `engine`, `learning`.

---

## `governance/` — Governance core

**Purpose.** Information-flow control, kernel MCP, path policy, private data execution, STPA specs. The four subpackages Matthew recently completed at 94% coverage.

**Key files:**
- `governance/ifc/` — information-flow control (lattice, classifier, engine, memory)
- `governance/kernel_mcp/` — kernel MCP path policy
- `governance/path_policy/` — path policy primitives
- `governance/private_data/` — private data execution gates
- `governance/stpa/` — STPA hazard specs

**Public interface.** Called by `engine` for pre-decision governance checks and by `api/governance_history_routes.py` for buyer-facing history.

**Verify:**
```bash
pytest tests/governance -q
```

**Depends on:** `domain`, `events`, `stores`.

**Depended on by:** `engine`, `api`.

**Known issue:** see `KNOWN_BUGS.md` #1 — broken parametrize at `tests/governance/test_kernel_mcp.py:351`.

---

## `api/` (Tier A subset — `auth.py`, `routes.py`, `guardrail.py`, `schemas.py`)

**Purpose.** Core API surface: authentication, primary routes, the `/v1/guardrail/*` entry, request/response schemas. Tier A because all customer integrations land here.

**Key files:**
- `api/auth.py` — bearer + tenant auth
- `api/routes.py` — primary routes
- `api/guardrail.py` — `/v1/guardrail` entry
- `api/schemas.py` — Pydantic request/response models

**Public interface.** HTTP endpoints. See `INTEGRATIONS.md` for the documented surface.

**Verify:**
```bash
pytest tests/test_api.py tests/test_learning_auth_resolver.py -q
```

**Depends on:** `commands`, `engine`, `domain`.

**Depended on by:** all customer integrations. **The rest of `api/` is Tier B — see below.**

---

# Tier B — Buyer-facing Surfaces

---

## `pitch/` — Buyer-facing pitch surfaces

**Purpose.** Generates the buyer-shaped artifacts that bind a slice of the
Tex evidence chain into a packet a specific audience (CISO, VP Marketing,
underwriter, regulator) recognizes. Three primary outputs: VP Marketing
brand-safety dossier, CISO MCP risk dossier, insurer evidence packet.

**Key files:**
- `pitch/vp_marketing.py` — VP Marketing brand-safety dossier (~199 LOC, real)
- `pitch/ciso.py` — CISO MCP risk dossier (~196 LOC, real)
- `pitch/insurer_export.py` — signed multi-artifact evidence packet (~344 LOC, real)
- `pitch/verifier.py` — offline verifier for the insurer packet (~257 LOC, real)
- `pitch/__init__.py` — exports `build_brand_safety_dossier`, `build_mcp_risk_dossier`, `build_insurer_evidence_packet`, `verify_insurer_evidence_packet` plus 14 supporting types

**Public interface.** 18 exports; main entry points are the three `build_*`
functions and the `verify_insurer_evidence_packet` round-trip helper.

**Verify:**
```bash
pytest tests/frontier/test_pitch.py -q
```

Plus an end-to-end round-trip check: build a packet, sign it, verify it
offline against the embedded public key. Audit Claude ran this and
confirmed it produces a real ECDSA-P256-signed packet that verifies cleanly.

**Depends on:** `evidence`, `domain`, `c2pa`, `pqcrypto`.

**Status:** **the capabilities work end-to-end.** The packet builders run,
sign, and round-trip through their verifiers. The P0 TODO markers in
these files are predominantly `[done]` tracking-marks left after the work
was completed, not open holes — this was a misclassification in earlier
inventories. See `STUB_REGISTRY.md` for the current accurate count.

**What's actually missing (not in the code, but in the wiring):** none
of these `build_*` functions is exposed as an HTTP route yet. A buyer
demo currently requires running a Python script. Wiring three routes
under `/v1/exports/{vp-marketing,ciso,insurer}` is a one-day fix.

**Known issue:** see `KNOWN_BUGS.md` #4 — circular import on fresh
interpreter. Works after `create_app()` resolves load order; breaks
in a standalone CLI or demo script.

---

## `api/` (Tier B subset — adapters, MCP server, surface routes)

**Purpose.** Adapter and route layer. Each adapter normalizes a third-party guardrail wire format into the internal `Decision` flow.

**Key files:**
- `api/guardrail_adapters.py` — Portkey, LiteLLM, Cloudflare AI Gateway, Solo, TrueFoundry, Bedrock Agents
- `api/mcp_server.py` — MCP server entry
- `api/agent_routes.py` — agent identity / capability routes
- `api/learning_routes.py` — feedback loop routes
- `api/governance_history_routes.py` — buyer-facing governance history
- `api/discovery_routes.py` — discovery surface
- `api/tenant_routes.py` — tenant management
- `api/c2pa_routes.py`, `tee_routes.py`, `vet_routes.py`, `zkprov_routes.py` — differentiation routes

**Public interface.** HTTP. Each adapter is a `POST` endpoint at `/v1/guardrail/<vendor>`.

**Verify:** wire-format smoke test for the affected adapter. Example for Portkey:
```bash
curl -X POST http://localhost:8000/v1/guardrail/portkey \
  -H "Authorization: Bearer $TEX_API_KEY" \
  -H "Content-Type: application/json" \
  -d @tests/fixtures/portkey_bec_payload.json
```
Expect verdict `FORBID` for the BEC fixture, `PERMIT` for the benign fixture.

Also:
```bash
pytest tests/test_api.py tests/test_governance_history_routes.py \
       tests/test_discovery_routes.py tests/test_c2pa_http_routes.py \
       tests/vet/test_vet_routes.py tests/zkprov/test_routes.py -q
```

**Depends on:** Tier A `api/` core, `commands`, `discovery`, `pitch`, `c2pa`, `tee`, `vet`, `zkprov`.

**Depended on by:** customers.

---

## `discovery/` — Connectors + reconciliation

**Purpose.** Pulls agent inventory from external sources (Slack connector, etc.), reconciles them against the registered agent set, raises alerts on drift.

**Key files:**
- `discovery/service.py` — `DiscoveryService` entry
- `discovery/reconciliation.py` — `ReconciliationEngine`, `ReconciliationIndex`
- `discovery/connectors/` — per-vendor connectors (Slack, etc.)
- `discovery/alerts.py` — alert engine

**Public interface.** 7 exports including `DiscoveryService`, `ReconciliationEngine`, `AUTO_REGISTER_THRESHOLD`, `QUARANTINE_DRIFT_THRESHOLD`.

**Verify:**
```bash
pytest tests/test_discovery_service.py tests/test_discovery_routes.py \
       tests/test_discovery_slack_connector.py tests/test_alert_engine.py \
       tests/test_discovery_fusion_integration.py -q
```

**Depends on:** `domain`, `stores`, `events`.

**Depended on by:** `api/discovery_routes.py`.

---

## `sdks/python/tex_guardrail/` — Customer-facing Python SDK

**Purpose.** Python client SDK that wraps the `/v1/guardrail/*` endpoints. What customers import in their code.

**Key files:** `sdks/python/tex_guardrail/client.py`, `__init__.py`.

**Public interface.** `TexGuardrail(api_key=...).evaluate(...)`.

**Verify:** integration test against running server.

**Depends on:** standard HTTP client (httpx).

**Depended on by:** customers' production code. **Breaking changes here break customer integrations.**

---

# Notes for adding a new module card

When you finish a Tier D stub and it gets promoted to B or C:

1. Add its row to `TIER_OWNERSHIP.md` under the new tier.
2. If Tier A or B, add a full card to this file.
3. If Tier C, just add the row to `TIER_OWNERSHIP.md`.
4. Remove its entry from `STUB_REGISTRY.md`.
5. Run `python scripts/audit.py --rebuild-data` to refresh the audit data file.

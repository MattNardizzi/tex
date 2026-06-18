# Subsystem Dossier: Compliance · Institutional · Self-Governance

**Scope:** `src/tex/compliance/`, `src/tex/institutional/`, `src/tex/selfgov/`
**Branch:** `feat/proof-carrying-gate`
**Method:** code-read and grep-traced, not docstring-trusted. Every load-bearing claim cites `file:line`. Claims sourced only from comments/docstrings/`.md` files are labelled **(claim, unverified)**.

---

## Overview

Three distinct units share this dossier because they cluster around "governance/compliance," but they are architecturally and reachability-wise very different:

1. **`compliance/`** — A family of pure-function "regulatory evidence emitters" (EU AI Act Art. 17/26/50, FTC §5, California SB 942/AB 853, Colorado AI Act, NY GBL §1700-A). Each emits a frozen pydantic/dataclass payload; the P0 statutes additionally bind a signed C2PA manifest, sign it, and append a `POLICY_DECISION` event to an `InMemoryLedger`. **Wired status: DEMO_TEST_ONLY** — no `src/tex/**` module outside `compliance/` imports it; only three `tests/frontier/` files do. The `selfgov` census itself labels `compliance` as "dead code per CLAUDE.md — tested but not wired" (`src/tex/selfgov/governor.py:272`).

2. **`institutional/`** — A labelled-transition-system (LTS) governance engine: a public `GovernanceGraph` manifest (states/transitions/sanctions/restorative paths with two SHA-256 digests), a programmatic `GovernanceOracle` (collusion-signal detector S1–S4, no LLM), a `GovernanceController` (manifest interpreter with cooldown gating), a separately-keyed signed `GovernanceLog`, subagent-state inheritance, and a PQ-signing-provider selector. **Wired status: MIXED** — its classes are imported and constructed by the LIVE `tex.ecosystem.engine.EcosystemEngine` (reachable from `tex.main`), BUT the institutional governance path is gated behind `self._oracle is not None`, and `tex/main.py` constructs the engine **without** an `oracle=` argument. So in the default production runtime the institutional layer is a structural pass-through (axis score 1.0); it becomes live logic only when an operator wires an oracle/graph.

3. **`selfgov/`** — A reflexive self-governance gate (`gate_controller_mutation`) that routes Tex's own controller mutations (policy writes/activations, agent lifecycle, proposal apply/rollback, in-process key material) through the real `PolicyDecisionPoint` plus a deterministic `metaguard` composition, sealing each outcome as a `SealedFact(ENFORCEMENT)`. **Wired status: LIVE-but-INERT** — `gate_controller_mutation` calls are physically embedded at ~20 LIVE chokepoint method definitions (policy stores, agent registry, feedback loop, c2pa signer, evidence seal, standing governance), but the gate is **inert until bound** and the ONLY caller of `bind_reflexive_governor` is `capstone/flow.py` (not reachable from `tex.main` or any API route). So the gate runs on every production mutation but takes its zero-cost `_UNGATED` fast path (binding is `None`). The module's own docstring states this honestly: "Production today does not bind it" (`src/tex/selfgov/governor.py:36-37`).

---

## File Inventory

### `src/tex/compliance/`

| File | LOC | Role |
|---|---|---|
| `__init__.py` | 33 | Layer marker (`__layer__=5`, `evidence`); empty `__all__`; docstring says "tested, not invoked at runtime". |
| `_common.py` | 518 | Shared machinery: `ComplianceFramework` enum, `ComplianceEvidenceRecord` (signed, hash-anchored), per-statute pydantic payload schemas (Art.50, SB942, FTC), and `_emit_evidence` (build→sign→ledger-append). The substance of the P0 path. |
| `eu_ai_act/__init__.py` | 2 | Package docstring stub. |
| `eu_ai_act/article_17.py` | 164 | QMS (§17(1)(a)–(k)) evidence packet via dataclasses; emits telemetry only (no ledger). |
| `eu_ai_act/article_26.py` | 171 | Deployer-obligation packet (§26); fail-closed validation (≥1 oversight assignee, ≥6-month retention, ≤72h incident SLA); telemetry only. |
| `eu_ai_act/article_50.py` | 210 | P0 transparency-marking evidence; C2PA-bound, signed, ledgered via `_emit_evidence`. |
| `ftc/__init__.py` | 2 | Package docstring stub. |
| `ftc/policy_statement.py` | 186 | P0 FTC §5 substantiation packet; C2PA-bound, signed, ledgered. |
| `state/__init__.py` | 2 | Package docstring stub. |
| `state/california_sb942.py` | 204 | P0 SB 942 latent-disclosure evidence; C2PA-bound, signed, ledgered. |
| `state/california_ab853_capture.py` | 55 | **STUB** — `emit_capture_device_evidence()` raises `NotImplementedError` (`:55`). Effective 2028. |
| `state/california_ab853_platforms.py` | 68 | **STUB** — `emit_large_online_platform_evidence()` and `emit_genai_hosting_platform_evidence()` both raise `NotImplementedError` (`:55`, `:68`). Effective 2027. |
| `state/colorado_ai_act.py` | 147 | Colorado AI Act §6-1-1703 deployer packet (dataclass + validation); telemetry only. |
| `state/new_york_ai_disclosure.py` | 145 | NY GBL §1700-A synthetic-performer disclosure (dataclass + validation); telemetry only. |

### `src/tex/institutional/`

| File | LOC | Role |
|---|---|---|
| `__init__.py` | 89 | Layer marker (`__layer__=4`, `execution_governance`); re-exports the full public surface. |
| `_pq_signing.py` | 172 | `select_institutional_signing_provider()` — runtime selection chain BLAKE3-ML-DSA-65 → ML-DSA-65 → Hybrid → ECDSA-P256, probing liboqs availability; emits telemetry naming the choice. |
| `controller.py` | 434 | `GovernanceController` (manifest interpreter), `ControllerDecision`, `ControllerOutcome` enum; edge-existence + cooldown gating; emits decisions to log. |
| `governance_graph.py` | 918 | `GovernanceGraph` LTS manifest (states/transitions/sanctions/paths), parsing, topology validation, two SHA-256 digests; `LegalState`, `LegalTransition`, `CANONICAL_COURNOT_STATES`. Largest file. |
| `governance_log.py` | 328 | `GovernanceLog` — append-only, separately-keyed signed log wrapping an `InMemoryLedger`; records observations + decisions with paired sanction/restoration streams; chain verification. |
| `oracle.py` | 517 | `GovernanceOracle` — programmatic S1–S4 collusion-signal detector; `collusion_tier`, `OracleCase`, `OracleObservation`, `OracleSignal`; `evaluate_transition` legality oracle. |
| `sanctions.py` | 193 | `Sanction` / `RestorativePath` dataclasses + `validate_sanction` / `validate_restorative_path`; the sanction-ladder model. |
| `subagent_inheritance.py` | 228 | `resolve_effective_state` — pure read-only spawn-chain walk computing most-restrictive inherited institutional state; `CANONICAL_RESTRICTIVENESS`. |

### `src/tex/selfgov/`

| File | LOC | Role |
|---|---|---|
| `__init__.py` | 28 | Layer marker (`__layer__=5`, `self_governance`); re-exports governor surface. |
| `governor.py` | 1018 | The reflexive gate: `gate_controller_mutation`, `bind/unbind_reflexive_governor`, `compose_gate_verdict`, the `CONTROLLER_MUTATION_CENSUS`, `DEPLOY_FROZEN_STRATUM`, `GOVERNOR_FROZEN_POLICY`, and ~10 `describe_*` descriptor builders. |

---

## Internal Architecture

### Compliance

**Two emission shapes coexist:**

- **Heavy P0 shape** (Art.50, FTC §5, SB942): a single shared engine `_emit_evidence` (`_common.py:341-502`):
  1. optional frontier-flag gate (`_common.py:391-400`, default off — raises only if `enforce_frontier_flag=True` and `FrontierFlags.from_env().compliance` is off).
  2. `content_hash` is required to be a 64-char lowercase SHA-256 hex (`_common.py:401-404`).
  3. `_validate_manifest_binding` (`_common.py:309-338`) rejects unsigned manifests (`manifest.signature_b64 is None`) and enforces `manifest.claim.instance_id == claimed_manifest_id`.
  4. builds a `ProposedEvent(event_kind=POLICY_DECISION)` and calls `ledger.append_proposed(...)` (`_common.py:434-447`).
  5. **Hash chaining trick** (`_common.py:455-468`): the compliance `record_hash` is computed *after* the append so it can include the ledger event's `event_id`/`sequence_number`/`record_hash`; the compliance record's `signature_b64` is the ledger event's already-computed `pq_signature_b64` (`_common.py:468`) — i.e. it *re-exports* the ledger's signature rather than signing fresh bytes. The docstring's "acceptance criterion (a) — record is signed" is satisfied transitively (`_common.py:464-467`).
  6. returns `EmittedEvidence(record, ledger_event)` (`_common.py:502`).
- **Light shape** (Art.17, Art.26, Colorado, NY): pure construction of a frozen dataclass payload + `emit_event(...)` telemetry. No C2PA binding, no signing, no ledger. E.g. `emit_article_26_evidence` (`article_26.py:76-164`) has substantial fail-closed validation but only returns a dataclass.

`ComplianceEvidenceRecord.canonical_record_input` (`_common.py:94-118`) deliberately excludes `signature_b64`/`record_hash` from the hashed surface, mirroring `Event.canonical_record_input`. Determinism contract documented at `_common.py:364-389` (record_hash is byte-stable given pinned ids; ECDSA signatures are non-deterministic).

### Institutional

**Data flow (when an oracle is wired):** `EcosystemState` (carries pre-aggregated drift scalars) → `GovernanceOracle.observe_state` (thresholds S1–S4, opens `OracleCase`) and/or `GovernanceOracle.evaluate_transition` (legality lookup) → `GovernanceController.enforce` (edge existence → cooldown gate → outcome selection → state transition) → `GovernanceLog.record_decision` (signs + appends). `subagent_inheritance.resolve_effective_state` supplies the effective `from_state` before the oracle is consulted.

- **`GovernanceGraph`** (`governance_graph.py:172-522`): frozen dataclass built only via `from_dict`/`from_json`/`from_yaml`. `_validate_topology` (`:692-797`) enforces edge-key regex `^<RULE_ID>:<from>-><to>$` (`:62-64`), edge-key uniqueness, state-reference resolution, sanction/path resolution, and **(from_state, triggered_by) uniqueness** so Controller dispatch is unambiguous (`:780-789`). Two digests: `manifest_semantic_sha256` over canonical content (`_semantic_digest_input`, `:805-892`) and `manifest_file_sha256` over raw bytes (`:333-341`). Float quantisation to milli-int (`_coerce_jsonable`, `:895-918`) to satisfy the events canonicaliser's "no floats" rule. **Lazy import** of `tex.events._canonical` inside `from_dict` (`:326`) to dodge a documented `tex.events`↔`tex.ecosystem` circular at module load. YAML support lazily imports PyYAML, raising a clear error if absent (`:403-409`).
- **`GovernanceOracle`** (`oracle.py:205-518`): no LLM; reads scalars from `state.aggregate_drift_signals`. `_evaluate_one` (`:459-504`) does simple `value >= threshold` for S1/S3/S4 and a **stateful consecutive-rounds streak** for S2 variance-collapse (`:474-491`, in-memory `self._s2_streaks`). `collusion_tier` (`:164-197`) implements the paper's Table-1 tier ladder. `evaluate_transition` (`:380-453`) returns `(is_legal, sanction_id)`: no edge → `(False, None)`; edge with sanction → `(False, sanction_id)`; clean edge → `(True, None)`.
- **`GovernanceController`** (`controller.py:118-435`): holds an in-memory cooldown registry `self._cooldowns[(actor, edge_key)] = round` (`:150`) and per-actor states `self._actor_states` (`:155`). `enforce` (`:180-359`) is the core: edge existence (BLOCKED if none, `:246-259`), cooldown gate (BLOCKED if on cooldown, still logged — the paper's "244 denied requests" discipline, `:264-288`), then outcome = REMEDIATE / SANCTION / ALLOW via `effective_sanction_id()` and `restorative_path_id`. Applies the state transition (`:332`) and schedules cooldown. `_record_and_return` emits telemetry and, if a ledger is present, calls `self._ledger.record_decision(...)` defensively (`:415-423`).
- **`GovernanceLog`** (`governance_log.py:55-304`): owns its OWN `InMemoryLedger` + `CryptoProvenance` keyed by a distinct `signing_key_id` (the "independent audit channel" design, `:13-25`). `record_decision` appends the primary `governance_graph_transition` event plus a paired `sanction_applied`/`restorative_path_triggered` event for downstream stream filtering (`:196-226`). `_canonicalise_payload` (`:307-328`) coerces floats→milli-int, datetimes→ISO, enums→value. `verify_chain` delegates to the inner ledger (`:229-241`).
- **`subagent_inheritance.resolve_effective_state`** (`subagent_inheritance.py:129-221`): pure read-only walk of the `spawned_by` attribute chain via `graph.get_entity_at`, bounded at depth 32 (`:187`), with a visited-set cycle guard that emits telemetry on cycle (`:194-202`). Returns the most-restrictive state per `CANONICAL_RESTRICTIVENESS` (`:81-87`: active/credited=0, warning=1, fined=2, suspended=3).
- **`_pq_signing.select_institutional_signing_provider`** (`_pq_signing.py:111-169`): tries the chain in order, **probing** the ML-DSA family with an actual `generate_keypair("_pq_probe")` because `get_signature_provider` returns a provider even when liboqs is missing (`:104-108`); ECDSA-P256 is taken on faith as a hard dependency (`:95-98`). Always returns a usable provider; raises only in the "impossible" all-failed case (`:166-169`).

### Self-Governance

- **`gate_controller_mutation`** (`governor.py:464-513`): the single chokepoint API. Fast path: `if _BINDING is None: return _UNGATED` (`:483-485`) — zero-cost inert default. Accepts a **zero-arg callable** so the descriptor is never built on the unbound hot path (`:471`, all chokepoints pass `lambda:`). Any internal error → fail-closed FORBID + seal, never raises (`:489-513`).
- **`_gate_bound`** (`governor.py:516-640`): the real ruling pipeline:
  1. `evaluate_metaguard(descriptor)` (`:519`); `mg.no_change` → unsealed PERMIT (`:524-528`).
  2. **No-regress backstop** (`:534-549`): any gated mutation while `_EVAL_DEPTH > 0` (a mutation attempted *during* a gate's own PDP eval) → deterministic FORBID, sealed. This is the anti-recursion guard, backed by a `ContextVar` (`:348`).
  3. deterministic fast passes (`:554-584`): `stage_write` / `new_registration` → unsealed PERMIT; `protective_pass` (mutation toward caution) → sealed PERMIT.
  4. **Full ruling** (`:586-640`): increments `_EVAL_DEPTH`, calls the SAME `binding.pdp.evaluate(request=_build_request(descriptor), policy=binding.policy)`, then `compose_gate_verdict`.
- **`compose_gate_verdict`** (`governor.py:643-654`): monotone — `mg.floor` → FORBID; `mg.caution` + PDP PERMIT → ABSTAIN; otherwise the PDP verdict. Metaguard can only LOWER, never raise (mirrors `structural_floor.py`).
- **`_build_request`** (`governor.py:665-689`): wraps the mutation as an `EvaluationRequest(action_type="controller_mutation", channel="selfgov")`; for irreversible classes (POLICY_DELETE/CLEAR/KEY_MUTATION) it attaches `metadata["action_class"] = IRREVERSIBLE×TENANT` (`:678-681`) — honest: TENANT blast does NOT fire the L4 IRREVERSIBLE×PUBLIC floor.
- **`_seal_enforcement`** (`governor.py:692-744`): builds a `SealedFact(kind=ENFORCEMENT, maturity=RESEARCH_EARLY)` whose claim text *explicitly disclaims* "verdict correctness NOT proven; mutation-surface completeness NOT proven" (`:719-721`); appends to `binding.ledger`; a seal failure logs and degrades to "not sealed" (`:736-744`).
- **`bind_reflexive_governor`** (`governor.py:352-403`): stores a global `_Binding(pdp, policy, ledger, token)`; rebinding while bound is the one deliberate **raise** (fail-open avoidance, `:368-380`). `unbind` denies a foreign token by returning `False` and sealing (`:413-420`). `GOVERNOR_FROZEN_POLICY` (`:157-164`) is a code constant with `minimum_confidence=0.0` (deliberate: PDP confidence on descriptor JSON is uncalibrated ~0.58, so a confidence gate would ABSTAIN-deny everything; the deny power lives in metaguard).
- **`metaguard.evaluate_metaguard`** (`src/tex/specialists/metaguard.py:240`, 371 LOC) is a real deterministic rule engine, not a stub: it floors governor-self-target mutations (`metaguard.py:259-275`) and computes weakening/widening axes (`weakening_axes:135`, `widened_dimensions:177`).

---

## Public API

**`tex.compliance`** exports nothing at package level (`__init__.py:33` `__all__ = []`). Consumers import per-statute factories directly:
- `_common`: `ComplianceEvidenceRecord`, `ComplianceFramework`, `EmittedEvidence`, the payload schemas, `_emit_evidence` (private but used by sibling modules).
- `eu_ai_act.article_50`: `emit_article_50_evidence`, `article_50_payload_schema`.
- `eu_ai_act.article_17`/`article_26`: `emit_article_17_evidence`/`emit_article_26_evidence` (+ dataclasses).
- `ftc.policy_statement`: `emit_ftc_substantiation_packet`, `ftc_payload_schema`.
- `state.*`: `emit_sb942_disclosure`, `emit_co_ai_evidence`, `emit_ny_disclosure`, plus the two `NotImplementedError` stubs.

**`tex.institutional`** (`__init__.py:35-89`) exports: `GovernanceGraph`, `GovernanceGraphValidationError`, `LegalState`, `LegalTransition`, `CANONICAL_COURNOT_STATES`, `Sanction`, `RestorativePath`, `GovernanceOracle`, `GovernanceController`, `ControllerDecision`, `ControllerOutcome`, `OracleCase`, `OracleObservation`, `OracleSignal`, the four `SIGNAL_*` ids, `collusion_tier`, `GovernanceLog`. Plus the non-`__all__` `_pq_signing.select_institutional_signing_provider` and `subagent_inheritance.resolve_effective_state` consumed by the engine.

**`tex.selfgov`** (`__init__.py:13-28` / `governor.py:993-1018`) exports the gate API: `gate_controller_mutation`, `bind/unbind/bound_reflexive_governor`, `reflexive_governor_bound`, `compose_gate_verdict`, `GateOutcome`, `MutationDescriptor`, `MutationSite`, `CONTROLLER_MUTATION_CENSUS`, `DEPLOY_FROZEN_STRATUM`, `GOVERNOR_FROZEN_POLICY`, and the `describe_*` builders.

---

## Wiring

### Wiring In

**Compliance — DEMO_TEST_ONLY.** Grep across `src/tex` for `tex.compliance` returns ZERO non-test importers. Only `tests/frontier/test_compliance.py`, `tests/frontier/test_compliance_new_jurisdictions.py`, `tests/frontier/test_scaffolding_imports.py` import it. There is no call path from `tex.main`/`build_runtime` or any `api/` route. The `selfgov` census independently classifies it dead (`governor.py:272`).

**Institutional — imported by the LIVE engine, but dormant by default config.** Importers (`src/tex/ecosystem/engine.py`):
- `:117-119` (TYPE_CHECKING) and runtime lazy imports `:319-322` (`_pq_signing`, `governance_log`), `:640-642` (`subagent_inheritance`).
- The engine constructs a default `GovernanceLog` only `if self._oracle is not None and governance_log is None` (`engine.py:318-343`), via `select_institutional_signing_provider()`.
- Step-4 governance legality runs only `if self._oracle is not None` (`engine.py:639`), calling `resolve_effective_state` then `self._oracle.evaluate_transition`.

Also imported by `intervention/*` and `drift/*` (mostly docstring/type references; `intervention/engine.py:140` types a ledger param as `GovernanceLog | None`).

**Self-governance — embedded at LIVE chokepoints (but inert).** `gate_controller_mutation` call sites that are genuinely live (grep-confirmed):
- `src/tex/stores/policy_store.py:54,155,182,197` (save/activate/delete/clear).
- `src/tex/memory/policy_snapshot_store.py:98,112,153,179,206` (the production `DurablePolicyStore`, `main.py:557` `policy_store = memory.policies` per census note).
- `src/tex/stores/agent_registry.py:70,111` (save / set_lifecycle).
- `src/tex/learning/feedback_loop.py:662,732` (apply/rollback proposal).
- `src/tex/c2pa/signer.py:108,116,126` (key material).
- `src/tex/evidence/seal.py:209` (`_persist_key`, lazy import).
- `src/tex/governance/standing.py:233` (StandingGovernance.activate).

### Live Call Path

**Institutional (classes are LIVE-reachable):**
`tex.main.build_runtime` (`main.py:946`) constructs `EcosystemEngine(...)` → wrapped by `EcosystemBridge(engine=...)` (`main.py:960`) → passed as `ecosystem_bridge=` into `EvaluateActionCommand` (`main.py:982`) → that command is resolved on the LIVE guardrail route (`src/tex/api/guardrail.py:48`, `guardrail_adapters.py:76`, `guardrail_streaming.py:179`). On each evaluation the command calls `bridge.emit_verdict(...)` (`bridge.py:156-182`) → `self._engine.evaluate(proposed)` → engine step 4.

**BUT the institutional governance logic is dormant by default:** `EcosystemEngine.__init__` accepts `oracle`/`governance_graph` defaulting to `None` (`engine.py:213-235`), and `main.py:946-958` passes NEITHER. With `self._oracle is None`, step 4 returns `governance_graph_legality = 1.0` pass-through (`engine.py:638`). Additionally the whole `evaluate` short-circuits to inert PERMIT unless `TEX_ECOSYSTEM=1` (`bridge.py:170-172`, `engine.py` `_ENV_FLAG_NAME = "TEX_ECOSYSTEM"` at `:312`). Net: institutional code is import-live and constructible-live, but the oracle/controller/log/subagent-inheritance logic executes only under operator opt-in (env flag + oracle wiring). **Verdict: MIXED / INDIRECT-by-default.**

**Self-governance (gate is LIVE-but-INERT):** the `gate_controller_mutation` calls run on every production policy/agent/key mutation, but `_BINDING is None` because the ONLY caller of `bind_reflexive_governor` is `src/tex/capstone/flow.py:312` (`with bound_reflexive_governor(...)`), and `capstone` is imported by NOTHING in `src/tex` outside itself and is NOT on any API route (grep-confirmed empty). `tex/main.py` contains zero references to `selfgov`/`bind_reflexive_governor`. So every live gate call returns `_UNGATED` (`governor.py:324-327, 485`). **Verdict: LIVE-but-INERT (the capability is wired and opt-in; it is NOT governing by default).**

### Wiring Out

- **Compliance →** `tex.c2pa.manifest` (C2paManifest), `tex.events` (`_canonical`, `_ecdsa_provider.signature_algorithm_for`, `crypto_provenance`, `event`, `ledger.InMemoryLedger`), `tex.ecosystem.proposed_event`, `tex.ontology.event_types.EventKind`, `tex.observability.telemetry`, `tex.frontier_config.FrontierFlags` (lazy), and `pydantic`. Light modules depend only on `tex.observability.telemetry` + stdlib `dataclasses/datetime`.
- **Institutional →** `tex.ecosystem.state.EcosystemState` (oracle), `tex.ecosystem.proposed_event` (log), `tex.events` (`_canonical`, `_ecdsa_provider`, `crypto_provenance`, `ledger`; all lazy to avoid circular), `tex.pqcrypto.algorithm_agility` (`SignatureProvider`, `SignatureAlgorithm`, `get_signature_provider`), `tex.observability.telemetry`, `pydantic`, lazy `yaml`/`hashlib`.
- **Self-governance →** `tex.domain` (`EvaluationRequest`, `EvidenceMaturity`, `PolicySnapshot`, `Verdict`), `tex.provenance.models` (`SealedFact`, `SealedFactKind`, `SealedFactRecord`), `tex.specialists.metaguard` (the rule engine + mutation-class constants), stdlib `hashlib/json/threading/contextvars`. Duck-typed deps (not imported): the bound `pdp` and `ledger`.

---

## Implementation Reality

| Element | Reality |
|---|---|
| `compliance/_common._emit_evidence` | **REAL.** Validates hash format, manifest signature + instance-id binding, builds a real `POLICY_DECISION` event, real ledger append, real signature re-export. Not invoked in production, but the logic is complete (`_common.py:341-502`). |
| `compliance/article_50`, `ftc`, `sb942` | **REAL** thin wrappers over `_emit_evidence`. |
| `compliance/article_17`, `article_26`, `colorado`, `new_york` | **REAL but lighter** — validation + dataclass + telemetry; deliberately no signing/ledger (telemetry-only emitters). |
| `compliance/california_ab853_capture.py` | **STUB** — `raise NotImplementedError("AB 853 capture device evidence")` (`:55`). |
| `compliance/california_ab853_platforms.py` | **STUB** — two `NotImplementedError` (`:55`, `:68`). |
| Institutional `GovernanceGraph` / `Oracle` / `Controller` / `GovernanceLog` / `sanctions` / `subagent_inheritance` | **REAL.** Full validation, real hashing, real signed ledger append, real cooldown/streak state machines. No NotImplementedError anywhere in `institutional/`. The `TODO(P1)` markers in `controller.enforce` (`:214-217`) and `oracle.observe_state` (`:302-305`)/`evaluate_transition` (`:407-410`) are **stale** — the docstring lists them as future work but the code below them already implements that work (the `enforce` body actually consults the graph, gates cooldown, and records to ledger; the oracle bodies do evaluate signals). Flag: docstring TODOs contradict implemented code. |
| Institutional state-mutation across rounds | **NOT implemented by the engine** — the per-actor `institutional_states` map is read but the engine "does NOT mutate this map today" (claim at `engine.py:228-235`, code-consistent: only `GovernanceController._actor_states` mutates, and the engine does not run the controller). |
| `_pq_signing` selection | **REAL graceful-fallback.** Genuine liboqs probe via `generate_keypair("_pq_probe")` (`:104-108`); BLAKE3-ML-DSA-65 / ML-DSA-65 / Hybrid / ECDSA-P256 all resolve through the real `tex.pqcrypto.algorithm_agility` dispatcher (enums confirmed at `algorithm_agility.py:40-80`). On a host without liboqs it falls to **ECDSA-P256 (real, via `cryptography`)** — not a hollow stub. |
| `selfgov.gate_controller_mutation` + `_gate_bound` + `metaguard` | **REAL.** Full PDP routing, monotone composition, no-regress ContextVar backstop, ENFORCEMENT sealing. `metaguard` (371 LOC) is a real deterministic engine. The gate is honest about being **inert until bound** and about its uncalibrated discriminating power (`governor.py:41-44`). |
| `selfgov` self-honesty | The module names its own limits in code constants: `DEPLOY_FROZEN_STRATUM` (`:169-215`) and the EXCLUDED census rows (`:264-273`). The sealed claim text disclaims correctness/completeness (`:719-721`). This is unusually honest scaffolding, not overstated. |

---

## Technology / SOTA

- **Cryptographic provenance chain:** SHA-256 canonical-JSON hashing (RFC-8785-style, "no floats" → milli-int quantisation), ECDSA-P256 default with an **algorithm-agility** path to ML-DSA-65 / BLAKE3-ML-DSA-65 / hybrid ML-DSA+Ed25519 (FIPS 204 / FIPS 186-5). Two-digest manifest scheme (semantic vs file).
- **Institutional AI / LTS governance:** the graph is a formal labelled transition system G=(Q,E,δ); collusion detection via HHI (Σsᵢ²), cross-firm dispersion CV, and a 5-tier severity ladder — all programmatic, no LLM (the design cites arxiv 2601.10599 / 2601.11369 — **claim, unverified** as to empirical results). ABDICO rule-id edge-key convention. Sanction ladder (warning/fine/suspension/credit) with Pigouvian-correction framing (pS ≥ Δπ).
- **C2PA Content Credentials** as the disclosure substrate for EU AI Act Art. 50 / SB 942 / NY (IPTC `trainedAlgorithmicMedia` digitalSourceType).
- **Reflexive (meta-circular) governance:** self-mutations ruled by the same production PDP; monotone floor/caution composition; ContextVar-based anti-recursion backstop; deploy-frozen two-level stratum; capability-token binding.
- **Subagent-spawn compromise defense** (most-restrictive-state inheritance over a `spawned_by` chain) — design cites arxiv 2605.08460 (**claim, unverified**).

---

## Persistence

**Everything in scope is in-memory / ephemeral.**

- Compliance P0 records append to a caller-supplied `InMemoryLedger` (`_common.py:46`); no durable store. Light emitters return frozen objects only.
- `GovernanceLog` owns a fresh `InMemoryLedger` per instance (`governance_log.py:120-123`) keyed by an in-process keypair (auto-generated if not supplied). No DB persistence.
- `GovernanceController` cooldown registry and actor-state map are plain in-memory dicts (`controller.py:150,155`). `GovernanceOracle` S2 streaks are in-memory (`oracle.py:251`).
- `selfgov` seals to whatever `SealedFactLedger` is passed to `bind_reflexive_governor(ledger=...)` — durability is the ledger's concern, not the gate's; and since nothing binds it in production, nothing is sealed in production today.
- `_pq_signing` selection is performed per call (the engine calls it once at oracle-construction time); no cached state beyond the returned provider object.

---

## Notable Findings

1. **Compliance is genuinely dead code at runtime (DEMO_TEST_ONLY).** Confirmed by grep (no non-test importer) and corroborated by the `selfgov` census (`governor.py:272`). The package `__init__.py:2` even admits "tested, not invoked at runtime." The P0 emission engine is fully built; it simply has no live caller. Overstatement risk: any pitch claiming Tex "emits EU AI Act / FTC compliance receipts in production" is **not** supported — the wiring is absent.

2. **Institutional is LIVE-imported but DORMANT-by-default.** The classes are reachable from `tex.main` via the engine/bridge/command/guardrail-route chain, so the spine-pass "LIVE" label is defensible at the *import* level. But the governance logic only executes when (a) `TEX_ECOSYSTEM=1` AND (b) an `oracle`/`governance_graph` is passed to the engine — and `main.py:946-958` passes neither. So the institutional LTS is a structural pass-through (`engine.py:638`, axis 1.0) in the shipped default. This is the single most important nuance: **import-live ≠ logic-live.**

3. **Stale `TODO(P1)` docstrings contradict implemented code.** `GovernanceController.enforce` (`controller.py:214-217`) and `GovernanceOracle.observe_state`/`evaluate_transition` (`oracle.py:302-305, 407-410`) carry `TODO(P1)` lists describing work that the code immediately below already performs. The `governance_log.py` TODOs even annotate themselves "— DONE" inline (`:79-83, 154, 178`). Trust the code, not the TODOs.

4. **Self-governance gate is wired into ~20 live chokepoints but never bound in production.** This is the inverse of compliance: the call sites ARE on the hot path (every policy write / agent lifecycle flip / key mutation calls the gate), but the gate is in its inert `_UNGATED` branch because the sole binder is the non-live `capstone/flow.py:312`. The module says so plainly (`governor.py:36-37`: "Production today does not bind it"). Honest, but means "Tex reflexively governs its own mutations" is a **capability, not a running behavior**, today.

5. **`selfgov` is unusually self-honest scaffolding.** Rare among the codebase: the sealed ENFORCEMENT claim text actively disclaims its own proof obligations ("verdict correctness NOT proven; mutation-surface completeness NOT proven", `governor.py:719-721`), and the residual gaps are enumerated as code constants (`DEPLOY_FROZEN_STRATUM`, EXCLUDED census rows). No overstatement detected in this module.

6. **Compliance signing is a re-export, not a second signature.** The compliance `ComplianceEvidenceRecord.signature_b64` is literally the bound ledger event's `pq_signature_b64` (`_common.py:468`), not an independent signature over the compliance record. The record_hash binds the compliance record to the ledger event, and the ledger event's signature transitively authenticates it. This is a sound design but worth noting: "the compliance record is signed" is true only via the ledger anchor, not by a dedicated compliance-layer key.

7. **Crypto is real graceful-fallback, not stub.** `_pq_signing` performs an actual liboqs probe and falls to ECDSA-P256 backed by the hard `cryptography` dependency. Zero `NotImplementedError` in `institutional/`. This matches the spine-pass crypto-reality note.

8. **Two AB 853 modules are explicit future-dated stubs** (`california_ab853_capture.py:55`, `california_ab853_platforms.py:55,68`) — `NotImplementedError` with effective dates 2027/2028. Correctly labelled as stubs in their own docstrings ("NOT YET EFFECTIVE ... exists as a stub").

9. **All arxiv-citation empirical claims are unverified.** The collusion-tier reduction figures (3.1→1.8, Cohen's d=1.28), the "244 denied requests," and the subagent-inheritance attack class are docstring claims sourced to arxiv 2601.10599 / 2601.11369 / 2605.08460. The *code* implements the mechanisms; the *quoted results* are **(claim, unverified)** — they are not reproduced or tested in-repo.

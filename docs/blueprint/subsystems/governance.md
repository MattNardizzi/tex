# Governance Subsystem Dossier

**Scope:** `/Users/matthewnardizzi/dev/tex/src/tex/governance/` (21 `.py` files, 6,421 LOC)
**Branch:** `feat/proof-carrying-gate`
**Architectural layer:** Layer 4 — Execution Governance (`governance/__init__.py:33`, `__layer__ = 4`, `__layer_kind__ = 'execution_governance'`)

> All claims below are verified against code. Any claim sourced only from a docstring/comment is labelled "(claim, unverified)". File:line references are absolute under `/Users/matthewnardizzi/dev/tex`.

---

## Overview

The `governance` package is **not one coherent runtime** — it is a top-level `__init__.py` that exports nothing (`__all__ = []`, `governance/__init__.py:36`) plus **two distinct live spines and three dormant scaffolds**:

1. **`standing.py` — the live PDP** (`StandingGovernance`). A two-tier policy-decision point: a microsecond structural floor (fail-closed identity/capability check) and a deep adjudication tier that delegates to the real six-layer `EvaluateActionCommand`. This is the brain behind the `/v1/govern` HTTP route and the in-process enforcement gate. **WIRED LIVE** from `tex.main.build_runtime` and an `api/` route.

2. **`private_data_exec/ifc/` — the live IFC enforcement stack** (ARM provenance graph + FIDES product lattice + NeuroTaint cross-session taint + CA-CI contextual-integrity norms + Rule-of-Two trifecta). **WIRED LIVE** into the PDP via `tex.specialists.ifc_specialist.IfcSpecialist`, which is in the default specialist suite the engine runs on every request.

3. **`path_policy/` — the LTLf path-policy checker + RV4 four-valued classifier.** **WIRED LIVE (opt-in)** into the engine via `tex.engine.path_policy_bridge`; the RV4 classifier is additionally consumed by `tex.contracts.rv4_path`.

4. **`kernel_mcp/` — MCP "syscall" gate** (six-layer pipeline, SSRF guard, secret scanner, capability tokens). **DEMO/TEST-ONLY**: no production `src/` consumer; only tests import it.

5. **`stpa_specs/` — STPA hazard-model YAML loader + coverage matrix.** **DEMO/TEST-ONLY**: no production `src/` consumer; the package's own `__init__.py:23` labels it "(test-only)".

6. **`private_data_exec/sandbox.py` — GAAP-style private-data exec sandbox** (`exec()`-based, with an explicit self-described "NOT a security boundary" caveat). **DEMO/TEST-ONLY**: no production `src/` consumer.

The package therefore splits cleanly into **LIVE** (`standing.py`, `private_data_exec/ifc/*`, `path_policy/*`) and **DEMO_TEST_ONLY** (`kernel_mcp/*`, `stpa_specs/*`, `private_data_exec/sandbox.py`). The spine pass's `governance=LIVE` is correct *for the package as a whole* but masks that ~40% of its files (kernel_mcp + stpa + sandbox = 8 files, ~2,100 LOC) reach no running code path.

---

## File Inventory

| File | LOC | Status | Role |
|------|----:|--------|------|
| `governance/__init__.py` | 36 | n/a | Layer marker only; exports nothing (`__all__ = []`). Docstring describes the 4 subpackages. |
| `governance/standing.py` | 631 | **LIVE** | `StandingGovernance` two-tier PDP: structural floor + deep adjudication; `DecisionOutcome`, `GovernedPosture`. The brain behind `/v1/govern`. |
| `path_policy/__init__.py` | 46 | LIVE | Re-exports `PathPolicy`, `CallablePolicy`, `PathPolicyChecker`, `PathStep`, `PolicyFn`, `PathPolicySeverity`. |
| `path_policy/policy.py` | 146 | LIVE | Dataclasses: `PathPolicy` (LTLf + severity), `CallablePolicy` (π_j fn), `PathStep` type alias, severity vocab. |
| `path_policy/checker.py` | 351 | LIVE | `PathPolicyChecker` — sliding-window runtime checker; composes violation probs `v_i = 1 − Π(1 − π_j)`; emits telemetry. |
| `path_policy/ltlf.py` | 734 | LIVE | Dependency-free LTLf tokenizer/parser/evaluator **plus** the RV4 four-valued (RV-LTL) sound permanent-violation classifier. |
| `private_data_exec/__init__.py` | 45 | DEMO/TEST | Re-exports the GAAP sandbox API (`PrivateDataSandbox`, `PermissionDatabase`, …). |
| `private_data_exec/sandbox.py` | 523 | **DEMO/TEST** | GAAP `exec()`-based private-data sandbox + taint wrapper + disclosure log. Self-flagged "NOT a security boundary". |
| `private_data_exec/ifc/__init__.py` | 117 | **LIVE** | Re-exports the IFC stack; docstring marks it "P0 — wired into the live PDP via IfcSpecialist". |
| `private_data_exec/ifc/lattice.py` | 368 | **LIVE** | `IntegrityLevel` (5-level ARM), `ConfidentialityLevel` (4-level), `CapacityType` (FIDES), `IfcLabel` (product lattice). |
| `private_data_exec/ifc/provenance.py` | 485 | **LIVE** | `ProvenanceGraph` — ARM 4-node/4-edge graph, MinTrust, counterfactual-chain BFS, SHA-256 fingerprint. |
| `private_data_exec/ifc/classifier.py` | 360 | **LIVE** | Maps `EvaluationRequest` + `RetrievalContext` → labeled sources; sink detection; CI-norm extraction. |
| `private_data_exec/ifc/engine.py` | 500 | **LIVE** | `IfcEngine.evaluate` — orchestrates all IFC checks into one `IfcVerdict` with a risk score. |
| `private_data_exec/ifc/ci_norms.py` | 174 | **LIVE** | `CiNorm` (CA-CI six-tuple), `CiNormRegistry`, `TransmissionPrinciple`. |
| `private_data_exec/ifc/memory.py` | 181 | **LIVE** | `MemoryStream` — NeuroTaint cross-session, capacity-bounded LRU, TTL-evicting, thread-safe. |
| `kernel_mcp/__init__.py` | 49 | DEMO/TEST | Re-exports MCP gate API. |
| `kernel_mcp/capability.py` | 165 | DEMO/TEST | `McpCapability`, `CapabilitySet`, `TrustTier` (4-tier), `tier_rank`/`tier_meets`. |
| `kernel_mcp/syscall_gate.py` | 771 | DEMO/TEST | `McpSyscallGate` — six-layer pipeline, SSRF guard (CVE-2026-44232 IPv6 classes), secret scanner, SHA-256 audit chain. |
| `stpa_specs/__init__.py` | 73 | DEMO/TEST | Re-exports STPA artifacts + manifest loader. |
| `stpa_specs/hazard_model.py` | 176 | DEMO/TEST | STPA dataclasses (Loss/Hazard/UCA/LossScenario + Doshi-2026 extensions). |
| `stpa_specs/manifest.py` | 490 | DEMO/TEST | Pydantic YAML manifest loader, cross-ref validation, UCA→module coverage matrix. |

---

## Internal Architecture

### 1. `standing.py` — the live two-tier PDP

**`StandingGovernance`** (`standing.py:186`) is constructed once at runtime with four injected dependencies (`standing.py:197-215`): `agent_registry`, `evaluate_command` (the deep PDP command), `held_sink` (ABSTAIN → human), `provenance_engine`. State is per-tenant activation timestamps in a lock-guarded dict (`self._active`, `standing.py:215`).

**Lifecycle:**
- `activate(tenant)` (`standing.py:219`): switched on per tenant when ignition seals the inventory. Before mutating it passes through a **reflexive self-governance gate** — `gate_controller_mutation(lambda: describe_standing_activate(tid))` (`standing.py:233`, importing from `tex.selfgov.governor`, confirmed present at `selfgov/governor.py:464,912`). Denial returns the live posture without mutating (deliberate: the only caller swallows exceptions, `standing.py:230-234`).
- `posture(tenant)` (`standing.py:245`): reads the registry live and counts `observed` vs `governed` (sealed + running) agents → `GovernedPosture`.

**Decision path — `decide(...)`** (`standing.py:261`) is the single entry every PEP calls:
- **Tier 1 — structural floor** (`standing.py:284-308`), fail-closed:
  - `_resolve_agent` (`standing.py:547`): by UUID first (tenant-scoped), then by external id / name. Unknown agent → `_forbid_floor` (the "absence of a proof is a forbid", `standing.py:287-293`).
  - Not governable (`SLEEPING`/`REVOKED`/`QUARANTINED`, `_NON_ACTING_STATUSES` at `standing.py:100`) → FORBID (`standing.py:295-299`).
  - Outside the agent's sealed `capability_surface` → FORBID (`_within_surface`, `standing.py:599-624`). Note: missing surface checks are treated **permissively** at the floor and deferred to deep adjudication (`standing.py:600-610`).
- **Tier 2 — deep adjudication** (`_adjudicate_deep`, `standing.py:367`): builds a `tex.domain.evaluation.EvaluationRequest` (`standing.py:379-392`) and calls `self._evaluate.execute(request)`. **If `evaluate_command` is None, it fails closed** rather than releasing on the floor alone (`standing.py:312-320`). Any exception in the deep engine → FORBID (`standing.py:394-399`).
  - `PERMIT` → `DecisionOutcome(released=True, tier="deep")` carrying the raw deep `response` for the gate (`standing.py:406-416`).
  - `ABSTAIN` → extracts the Layer-4 Hold (`_extract_hold`, reads `metadata['pdp']['hold']`, `standing.py:524-545`), pushes a `tex.provenance.feed.HeldDecision` into the held sink (`_raise_hold`, `standing.py:492-522`), and returns `released=False, held=True`. **Hold-surfacing failures are swallowed** so a ruling never breaks (`standing.py:521-522`).
  - Anything else (FORBID / unknown) → fail closed (`standing.py:467-477`).

**`decide_for_request(request, tenant)`** (`standing.py:333`) is the in-process PEP bridge: extracts fields off an `EvaluationRequest`/gate request and routes through `decide`, applying the floor + capability confinement + ABSTAIN-to-voice that a direct deep-command call would skip.

**Data classes:** `DecisionOutcome` (`standing.py:103`, frozen/slots, `to_jsonable` at `:126` deliberately drops the in-process `response`); `GovernedPosture` (`standing.py:139`) whose `.spoken` property (`standing.py:159-172`) produces the operator-facing sentence ("I'm ruling on N agents…").

### 2. `private_data_exec/ifc/` — the live IFC enforcement stack

This is the algorithmically richest part of the package and the one that runs on every PDP request.

**`lattice.py`** defines the type algebra:
- `IntegrityLevel` (`lattice.py:46`): 5-level `IntEnum` `TOOL_DESC(0) < TOOL_UNTRUSTED(1) < TOOL_TRUSTED(2) < USER_INPUT(3) < SYS_INSTR(4)`. `join` is **min** (conservative MinTrust, empty→SYS_INSTR, `lattice.py:81-98`). `is_untrusted` ≡ `<= TOOL_UNTRUSTED`.
- `ConfidentialityLevel` (`lattice.py:115`): 4-level `PUBLIC..RESTRICTED`; `join` is **max** (`lattice.py:135-146`); `is_sensitive` ≡ `>= CONFIDENTIAL`.
- `CapacityType` (`lattice.py:163`): FIDES output-capacity `BOOL(0)..TEXT(5)`; `declassifies` ≡ `<= ENUM` (`lattice.py:187-190`).
- `IfcLabel` (`lattice.py:198`, frozen pydantic): the propagating triple. `join` floors integrity, climbs confidentiality, keeps the higher (less-safe) capacity (`lattice.py:239-254`). `is_flow_violation` ≡ untrusted-integrity ∧ sensitive-confidentiality (`lattice.py:256-266`). `may_declassify` ≡ low capacity (`lattice.py:268-271`). Five named `LABEL_*` constants (`lattice.py:326-354`).

**`provenance.py`** — `ProvenanceGraph` (`provenance.py:135`), one per request:
- 4 node kinds (`NodeKind`, `provenance.py:72`: CALL/DATA/DATA_FIELD/DENIED_ACTION) and 4 edge kinds (`EdgeKind`, `provenance.py:81`: DIRECT_OUTPUT/INPUT_TO/FIELD_OF/COUNTERFACTUAL).
- `add_call` (`provenance.py:161`) auto-links a COUNTERFACTUAL edge from any parked `DeniedAction` (ARM Algorithm 1), then clears the parked list (`provenance.py:186-193`).
- `min_trust` / `max_sensitivity` / `effective_label` (`provenance.py:303-353`): reverse-edge BFS over ancestors (`_ancestors`, `provenance.py:459-478`, which **deliberately skips COUNTERFACTUAL edges** — those are causal, not data-flow).
- `has_counterfactual_chain` (`provenance.py:357`): BFS tracking whether a COUNTERFACTUAL edge has been crossed; reaching a `DENIED_ACTION` after crossing one = causality-laundering detected. `counterfactual_denials` (`provenance.py:390`) returns the offending denial node ids.
- `fingerprint` (`provenance.py:422`): deterministic SHA-256 over sorted (kind,name,label) nodes + sorted (src,tgt,kind) edges.

**`classifier.py`** maps a request to labeled sources (`classify_request`, `classifier.py:146`): primary content → USER_INPUT (or downgraded via `metadata["content_origin"]`/`untrusted_source`); policy clauses → SYS_INSTR; entities → TOOL_TRUSTED (confidentiality from the entity's asserted sensitivity); operator-marked untrusted sources → TOOL_UNTRUSTED. `classify_content` (`classifier.py:138`) is a **lexical** confidentiality classifier (15 regex hints, `classifier.py:96-116`). `SINK_ACTION_TYPES` (`classifier.py:73`) is a 12-entry frozenset of external-communication actions. `extract_ci_norm` (`classifier.py:293`) builds the CA-CI six-tuple from request fields/metadata.

**`ci_norms.py`** — `CiNorm` (`ci_norms.py:64`, frozen pydantic, casefold-normalized fields). `matches` is **strict six-tuple equality** (`ci_norms.py:123-139`). `CiNormRegistry.is_permitted` (`ci_norms.py:165`) ≡ any-norm match; empty registry = advisory (see engine gating below).

**`memory.py`** — `MemoryStream` (`memory.py:68`): thread-safe (single `Lock`), capacity-bounded (default 256) LRU `OrderedDict` keyed `(session_key, content_hash)`, with optional 24h TTL eviction (`_evict_expired_locked`, `memory.py:154-168`). `record`/`lookup`/`session_items`/`clear`. A module-global `DEFAULT_MEMORY_STREAM` (`memory.py:174`) exists but the IfcSpecialist constructs its own (see Wiring).

**`engine.py`** — `IfcEngine.evaluate` (`engine.py:163`) runs the 10-step deterministic pipeline:
1. classify → sources; 2. build graph + DATA nodes; 3. NeuroTaint lookup → extra DATA nodes; 4. materialize `DeniedAction` nodes from `metadata["recent_denials"]`; 5. materialize the proposed CALL node + INPUT_TO edges; then six checks (`engine.py:248-404`):
   - **(a) MinTrust floor** — sink with `effective_label.integrity < min_trust_floor` → `MIN_TRUST_FLOOR` (`engine.py:256-272`).
   - **(b) Counterfactual chain** → `CAUSALITY_LAUNDERING` (`engine.py:276-290`).
   - **(c) FIDES dual-axis** — `is_flow_violation` unless `may_declassify` → `FLOW_INTEGRITY` (`engine.py:293-320`).
   - **(d) CA-CI** — only enforced when the registry is non-empty (`engine.py:324`); mismatch → `CI_NORM_VIOLATION`.
   - **(e) NeuroTaint cross-session** — untrusted carried items → `NEUROTAINT_CROSS_SESSION` (`engine.py:350-372`).
   - **(f) Rule of Two trifecta** — untrusted-input ∧ private-data ∧ external-action → `RULE_OF_TWO_TRIFECTA` (`engine.py:377-404`).
   Then records untrusted sources into `MemoryStream` (`engine.py:408-419`) and returns `IfcVerdict`. `IfcVerdict.risk_score` (`engine.py:114-137`) aggregates per-violation weights via complement-of-product, clamped to `[0.05, 1.0]`.

### 3. `path_policy/` — LTLf path policies + RV4

- `policy.py`: `PathPolicy` (`policy.py:58`, LTLf string + severity `block|warn|audit`), `CallablePolicy` (`policy.py:108`, deterministic `π_j(A, P_i, s*, Σ)`), `PathStep = (state, action, observation)` (`policy.py:95`).
- `checker.py`: `PathPolicyChecker` (`checker.py:76`) keeps a `deque(maxlen=256)` sliding window. `check` (`checker.py:158`) appends the candidate as the final trace position, evaluates each compiled LTLf formula (violation ≡ formula FALSE → `π_j=1.0`, `checker.py:207-214`) and each callable, composes `v_i = 1 − Π(1 − π_j)` (`checker.py:292-303`). **Fail-closed**: malformed formula at construction → `"INVALID"` marker → perpetual block (`checker.py:116-126, 204-206`); callable exception → `π_j=1.0` (`checker.py:233-241`); out-of-range scores clamped + logged (`checker.py:305-331`). `allowed` ≡ no `block`-severity policy fired.
- `ltlf.py`: a **real, dependency-free LTLf engine** — tokenizer (`_tokenize`, `:97`), recursive-descent parser with precedence (`_parse`, `:165`), and `_eval_at` (`:374`) implementing finite-trace semantics for `G/F/X/U` + boolean ops. Atoms support `tool=`, `state.x`, `action.x`, `obs.x` with `= != >= <= > <` comparators.
  - **RV4 / RV-LTL four-valued classifier** (`ltlf.py:469-734`): `evaluate_rv4` returns `RV4Verdict` (PERMANENTLY_SATISFIED / CURRENTLY_SATISFIED / CURRENTLY_VIOLATED / PERMANENTLY_VIOLATED). It is built on two mutually-recursive **sound over-approximations** `_can_become_true` / `_can_become_false` (`ltlf.py:558-711`), so `not _can_become_true(...)` is a *proof of impossibility* → the only thing that earns the permanent ⊥ FORBID verdict. CURRENTLY_VIOLATED (recoverable) maps to ABSTAIN. This is the doctrinally-correct "FORBID demands a proof; uncertainty → ABSTAIN" mapping (`ltlf.py:496-514`). Verified at runtime: `evaluate_rv4('G(tool=external_send -> F(tool=human_approval))', [send])` → `currently_violated` (recoverable, not a fabricated forbid).

### 4. `kernel_mcp/` (DEMO/TEST) — MCP six-layer gate

`McpSyscallGate.check` (`syscall_gate.py:457`) runs six layers in fixed order: L1 schema (`:564`), L2 trust-tier + capability match (`:485-514`), L3 token-bucket rate limit (`:635`), L4 prompt-injection regex + outbound-secret scan + SSRF guard (`:652`), L5 pluggable semantic gate (default allow; fail-closed variant `_fail_closed_semantic_gate` at `:377`), L6 constitutional principles (`:673`). It maintains an **in-memory SHA-256 hash-chained audit log** (`_record_audit`, `:716-748`; genesis = 64 zeros, `:444`). The SSRF guard (`_ssrf_check_url`, `:231`) checks literal hosts, IP literals, and **resolves all A+AAAA records** against a comprehensive blocklist including IPv6 bypass classes (`_BLOCKED_NETWORKS`, `:189-217`). Capability tokens (`capability.py`) are 4-tier (`System>AiNative>AiEnhanced>Classic`).

### 5. `stpa_specs/` (DEMO/TEST) — STPA hazard model

Classical STPA dataclasses + Doshi-2026 extensions (`hazard_model.py`). `manifest.py` loads/validates a YAML manifest into a frozen pydantic `StpaManifest` (`:70`) with full cross-reference validation that aggregates all errors (`load_manifest`, `:97-218`), and `build_coverage_matrix` (`:437`) walks two chains (LossScenario mitigations + Hazard→Requirement→Specification enforcement modules) to compute per-UCA coverage and the **uncovered set**.

### 6. `private_data_exec/sandbox.py` (DEMO/TEST) — GAAP sandbox

`PrivateDataSandbox.execute_with_user_data` (`sandbox.py:336`) runs an agent-supplied **string program via `exec()`** in a namespace with a curated `__builtins__` (`sandbox.py:455-484`), a taint-propagating `_Tainted` wrapper (`sandbox.py:167`), an auto-tainting `_DataView` (`sandbox.py:251`), and an `egress()` helper that permission-checks + records disclosures. **The module's own docstring (`sandbox.py:34-43`) and a TODO (`sandbox.py:360-363`) explicitly state this is NOT a security boundary** and is defeatable.

---

## Public API

Symbols other code imports from this unit:

- **From `tex.governance.standing`** (LIVE): `StandingGovernance`, `DecisionOutcome`, `GovernedPosture` (`standing.py:88-92`).
- **From `tex.governance.private_data_exec.ifc`** (LIVE): `IfcEngine`, `IfcVerdict`, `IfcViolation`, `CiNormRegistry`, `MemoryStream` (the subset imported by `specialists/ifc_specialist.py:57-64`); the full surface is in `ifc/__init__.py:78-117` (labels, `ProvenanceGraph`, `CiNorm`, classifier fns, `IfcLabel`, etc.).
- **From `tex.governance.private_data_exec.ifc.lattice`** (LIVE, cross-cut): `ConfidentialityLevel` is imported by `tex.camel.capability` (`camel/capability.py:25,104`).
- **From `tex.governance.private_data_exec.ifc.provenance`** (LIVE): `ProvenanceGraph` is referenced by `tex.pcas.graph.adapter` (`pcas/graph/adapter.py:11,233`).
- **From `tex.governance.path_policy.checker` / `.policy`** (LIVE): `PathPolicyChecker`, `PathPolicy`, `PathStep` imported by `tex.engine.path_policy_bridge` (`engine/path_policy_bridge.py:64-65`).
- **From `tex.governance.path_policy.ltlf`** (LIVE): `evaluate_rv4` + RV4 symbols imported by `tex.contracts.rv4_path` (`contracts/rv4_path.py:46-52`).
- **From `tex.governance.kernel_mcp` / `stpa_specs` / `private_data_exec` (sandbox)**: imported **only by tests** (see Wiring).

The top-level `tex.governance` package exports nothing (`__all__ = []`).

---

## Wiring

### In — who imports these symbols

| Public symbol | Importer (file:line) | Status |
|---------------|----------------------|--------|
| `StandingGovernance` | `main.py:1737` (build_runtime), `api/governance_standing_routes.py:7`, `enforcement/standing_transport.py:35`, `enforcement/seal.py:32`, `pep/__main__.py:43`, `pep/decision_client.py` | LIVE |
| `IfcEngine`/`IfcVerdict`/`IfcViolation`/`CiNormRegistry`/`MemoryStream` | `specialists/ifc_specialist.py:57-64` | LIVE |
| `ifc.lattice.ConfidentialityLevel` | `camel/capability.py:25,104` | LIVE (cross-cut) |
| `ifc.provenance.ProvenanceGraph` | `pcas/graph/adapter.py:11,233` | LIVE (cross-cut) |
| `PathPolicyChecker`/`PathPolicy`/`PathStep` | `engine/path_policy_bridge.py:64-65` | LIVE (opt-in) |
| `path_policy.ltlf.evaluate_rv4` (+ RV4) | `contracts/rv4_path.py:46-52` | LIVE |
| `McpSyscallGate`/`kernel_mcp.*` | `tests/governance/test_kernel_mcp.py`, `tests/governance/test_bug4_stripe_key_regression.py`, `tests/frontier/test_scaffolding_imports.py` | **TEST-ONLY** |
| `StpaManifest`/`load_manifest`/`stpa_specs.*` | `tests/governance/test_stpa.py`, `tests/frontier/test_scaffolding_imports.py` | **TEST-ONLY** |
| `PrivateDataSandbox`/`private_data_exec.sandbox` | `tests/governance/test_private_data_exec.py`, `tests/frontier/test_scaffolding_imports.py` | **TEST-ONLY** |

A repo-wide grep confirms **no production `src/` module outside `governance/` imports `kernel_mcp`, `stpa_specs`, or the GAAP `sandbox`** (`grep -rln 'McpSyscallGate|kernel_mcp|stpa_specs|StpaManifest|PrivateDataSandbox' src/ | grep -v governance/` → empty).

### Live call paths (traced, with file:line)

**Path A — Standing PDP via the `/v1/govern` HTTP route (LIVE):**
```
tex.main.create_app
  → app.include_router(build_governance_standing_router())        main.py:1506-1507
      → POST /v1/govern/decide                                    api/governance_standing_routes.py:69-92
          → gov = request.app.state.standing_governance           api/governance_standing_routes.py:50-51
          → gov.decide(...)                                       api/governance_standing_routes.py:80
              → StandingGovernance.decide                         standing.py:261
                  → _adjudicate_deep → self._evaluate.execute     standing.py:393  (the deep six-layer PDP)
```
`app.state.standing_governance` is constructed in `build_runtime` at `main.py:1739-1744` with the real registry, `evaluate_action_command`, held sink, and provenance engine.

**Path B — Standing PDP via the in-process enforcement gate (LIVE):**
```
build_runtime                                                     main.py:1754-1756
  → build_standing_gate(app.state.standing_governance)           enforcement/standing_transport.py:113
      → StandingGovernanceTransport(governance)                  enforcement/standing_transport.py:69
          → governance.decide_for_request(...)                   standing.py:333
```

**Path C — IFC stack via the specialist suite (LIVE, runs on every request):**
```
tex.engine.pdp.PdpEngine.__init__
  → self._specialist_suite = build_default_specialist_suite()    engine/pdp.py:205
      → IfcSpecialist()                                          specialists/judges.py:389
PdpEngine.evaluate
  → self._specialist_suite.evaluate(...)                         engine/pdp.py:289
      → IfcSpecialist owns IfcEngine                             specialists/ifc_specialist.py:176-180
          → self._engine.evaluate(...)                           specialists/ifc_specialist.py:188
              → IfcEngine.evaluate (full IFC pipeline)           private_data_exec/ifc/engine.py:163
PdpEngine._build_decision_metadata
  → get_ifc_labels_cache() attaches metadata['ifc_labels']       engine/pdp.py:71, 1076
```

**Path D — Path policies via the engine bridge (LIVE, opt-in per request):**
```
tex.engine.pdp.PdpEngine.evaluate
  → evaluate_path_policies_for_request(request=request)          engine/pdp.py:326
      → builds PathPolicyChecker (opt-in via metadata["path_policy"])  engine/path_policy_bridge.py:216
          → PathPolicyChecker.check → ltlf.evaluate_compiled     path_policy/checker.py:213
  → block→FORBID floor, warn→PERMIT→ABSTAIN, audit→findings      engine/pdp.py:320-324, 729, 769
```
Returns `NEUTRAL_PATH_OUTCOME` (zero cost) when `metadata["path_policy"]` is absent (`engine/path_policy_bridge.py:122`), so it is **dormant unless explicitly opted in**.

**Reflexive self-governance:** `StandingGovernance.activate` gates its own mutation through `tex.selfgov.governor.gate_controller_mutation` / `describe_standing_activate` (`standing.py:86, 233`; targets confirmed at `selfgov/governor.py:464,912`, and `selfgov/governor.py:914` registers the surface `"governance.standing.StandingGovernance.activate"`).

### Out — dependencies

**Internal tex subsystems consumed:**
- `standing.py` → `tex.domain.verdict.Verdict` (`:85`), `tex.selfgov.governor` (`:86`), `tex.domain.evaluation.EvaluationRequest` (lazy, `:379`), `tex.provenance.feed.HeldDecision` (lazy, `:507`).
- `ifc/engine.py` → `tex.domain.evaluation.EvaluationRequest`, `tex.domain.retrieval.RetrievalContext` (`:45-46`), the sibling IFC modules, `tex.observability.telemetry` (`:73`).
- `ifc/classifier.py` → `tex.domain.evaluation`, `tex.domain.retrieval` (`:55-56`).
- `path_policy/checker.py`, `path_policy/manifest.py`, `kernel_mcp/syscall_gate.py`, `private_data_exec/sandbox.py` → `tex.observability.telemetry`.
- `kernel_mcp/capability.py` → (docstring only) references `tex.pqcrypto.algorithm_agility` for signatures, but **does not import it**; the gate only checks the signature field is non-empty (claim, partly unverified — no actual signature verification in code).

**External libraries:**
- `pydantic` (v2): `ifc/lattice.py`, `ifc/ci_norms.py`, `stpa_specs/manifest.py`.
- `pyyaml` (lazy import, `stpa_specs/manifest.py:230-236`): raises an actionable error if absent.
- stdlib only elsewhere: `ipaddress`, `socket`, `urllib.parse`, `re`, `json`, `hashlib`, `threading`, `collections.deque/OrderedDict`, `dataclasses`, `enum`, `datetime`, `uuid`.

No native crypto / TEE / ZK libraries are used in this package — the only cryptographic primitive is **`hashlib.sha256`** (provenance fingerprint, kernel_mcp audit chain, classifier content hashes). There is no fallback path because there is no native dependency to fall back from.

---

## Implementation Reality

**REAL, substantive logic (not stubs):**
- `standing.py` — fully implemented two-tier PDP with genuine fail-closed branches at every unresolved path. No TODO/NotImplemented/pass-only. Verified importable and the gate logic is concrete.
- `path_policy/ltlf.py` — a **complete, working LTLf parser+evaluator** and a **non-trivial sound RV4 classifier**. Runtime-verified: `evaluate_rv4` returns `currently_violated` for the canonical external-send-without-approval trace. The soundness claim is testable (docstring cites `tests/governance/test_ltlf_rv4.py` brute-force extension enumeration, `ltlf.py:514` — claim, not re-verified here).
- `path_policy/checker.py` — real composition formula, real fail-closed handling.
- `ifc/*` — all five mechanisms (ARM graph + MinTrust BFS, FIDES product lattice, NeuroTaint LRU, CA-CI matcher, Rule-of-Two) are concretely implemented and deterministic. `IfcEngine.evaluate` has no stubs.
- `kernel_mcp/syscall_gate.py` — real six-layer pipeline, real SSRF resolver, real regex scanners, real SHA-256 audit chain. (Live status aside, the code is real.)
- `stpa_specs/manifest.py` — real pydantic validation + cross-ref + coverage-matrix graph walk.

**Stubs / no-ops / explicit caveats (flagged):**
- **`kernel_mcp` Layer 5 default is a NO-OP allow** — `_default_semantic_gate` returns `allow=True` (`syscall_gate.py:372-374`). It only fails closed if `require_semantic_gate=True` is configured (`syscall_gate.py:445-450`). The "kernel-resident logit gate (ProbeLogits)" from the paper is **not implemented** — it is a pluggable hook with an allow-by-default default (claim in `syscall_gate.py:23-25` that the five non-inference layers are "implemented faithfully" is accurate; Layer 5 is explicitly a hook).
- **`kernel_mcp` audit chain is in-memory only** with a self-declared TODO: Blake3 + durable on-disk chain "is a TODO" (`syscall_gate.py:46-48, 725-728`). Hashing is SHA-256, not the paper's Blake3.
- **`kernel_mcp` capability signatures are not verified** — `issuer_signature_b64` is checked only for non-emptiness; no actual ML-DSA/ECDSA verification exists (`capability.py:94-98`).
- **`private_data_exec/sandbox.py` is an `exec()`-based MVP, explicitly NOT a security boundary** (`sandbox.py:34-43`, TODO at `:360-363`). The `_Tainted` wrapper is acknowledged "NOT a complete IFC implementation" (`sandbox.py:178-181`). Real isolation (RestrictedPython/subprocess/WASM/TEE) is deferred.
- **CA-CI norm enforcement is advisory by default** — only enforced when the operator registry is non-empty (`ifc/engine.py:324`, `ci_norms.py:153-159`); the empty-registry "fail-closed" framing in the docstring is **overridden in practice** to advisory (see Notable Findings).
- No `NotImplementedError` anywhere in the package (grep-confirmed: the spine pass reports 0 guards for governance, consistent).

---

## Technology / SOTA

The package is a catalogue of 2024-2026 agent-governance research, implemented rather than cited:

- **Runtime Governance on Paths** (Kaptein/Khan/Podstavnychy, arXiv:2603.16586) — `path_policy/*`. LTLf is Tex's own encoding choice on top of the paper's violation-probability framing (`path_policy/ltlf.py:11-15`, honestly disclosed).
- **RV-LTL four-valued runtime verification** (Bauer/Leucker/Schallhart, ACM TOSEM 2011) — the RV4 classifier in `ltlf.py`, with a **sound over-approximation** for the permanent-violation verdict (the load-bearing soundness property for FORBID).
- **ARM / Causality Laundering** (Chinaei, arXiv:2604.04035) — `ifc/provenance.py` counterfactual edges + chain query.
- **FIDES product lattice** (Costa et al., arXiv:2505.23643) — `ifc/lattice.py` (label × capacity, declassification of low-capacity outputs).
- **NeuroTaint cross-session taint** (arXiv:2604.23374) — `ifc/memory.py`.
- **CA-CI contextual integrity** (Roemmich/Martin/Schaub IEEE S&P 2026; Nissenbaum 2004) — `ifc/ci_norms.py` six-tuple.
- **Rule of Two / lethal trifecta** (Meta Oct 2025; Willison 2025) — `ifc/engine.py` check (f).
- **Governed MCP** (Son, arXiv:2604.16870) — `kernel_mcp/*` six-layer pipeline (Layer 5 logit gate unimplemented).
- **STPA** (Leveson handbook 2018; Doshi et al. ICSE-NIER 2026 arXiv:2601.08012) — `stpa_specs/*`.
- **GAAP** (Stanley et al., arXiv:2604.19657) — `private_data_exec/sandbox.py`.
- **CVE-2026-44232** IPv6 SSRF bypass classes — encoded in `kernel_mcp/syscall_gate.py:189-217` (claim about the CVE is unverifiable from code, but the blocklist itself is real and comprehensive).

Design patterns: frozen `@dataclass(slots=True)` / frozen pydantic for value objects; PEP/PDP separation; conservative-join lattice algebra; fail-closed defaults throughout; deterministic SHA-256 fingerprints; sliding-window + token-bucket; LRU+TTL caches.

---

## Persistence

**Everything in this package is in-memory / ephemeral.** No durable store, no DB, no disk writes.

- `StandingGovernance._active` — in-memory per-tenant timestamps (`standing.py:215`); reads the registry live each call. Its *durable* outputs (sealed evidence, held decisions) are produced by the injected `evaluate_command` / `held_sink` / `provenance_engine`, which live in **other** subsystems — `standing.py` persists nothing itself.
- `MemoryStream` — in-memory LRU, capacity 256, 24h TTL (`memory.py:81-95`); docstring explicitly says "does NOT need to be durable" (`memory.py:74-79`).
- `ProvenanceGraph` — per-request, discarded after the verdict (`provenance.py:139-147`).
- `McpSyscallGate._audit_chain` — in-memory list; durable Blake3 chain is a TODO (`syscall_gate.py:441, 46-48`).
- `PathPolicyChecker._history` — in-memory `deque(maxlen=256)` (`checker.py:102`).
- GAAP `DisclosureLog` / `PermissionDatabase` — in-memory dataclasses (`sandbox.py:78-139`).
- `StpaManifest` — built from YAML at load; the YAML file on disk is the only persistence, and the loader is test-only.

---

## Notable Findings

1. **`kernel_mcp`, `stpa_specs`, and the GAAP `sandbox` are dead in production.** Despite the package `__init__.py` docstring presenting all four subpackages as governance layers, three of them (≈2,100 LOC, ~40% of the package) have **no production `src/` importer** — only tests reach them. The package's own `__init__.py:2` is honest about `stpa_specs` being "(test-only)" but presents `kernel_mcp` and `private_data_exec` (sandbox) without that caveat. The spine pass's `governance=LIVE` is true only because `standing.py` + `ifc/` carry the package; it should not be read as "all of governance is live."

2. **`kernel_mcp` Layer 5 (the paper's headline "logit-based safety primitive") is unimplemented** — the default semantic gate is `allow=True` (`syscall_gate.py:372-374`). The module docstring is candid that Tex "cannot reproduce Anima OS's ring-0 placement" and ships a pluggable hook (`syscall_gate.py:18-25`), but a reader skimming the package overview ("Six-layer pipeline … kernel-resident logit gate") could overstate what runs. Combined with #1, the kernel_mcp gate is real code that nothing calls.

3. **`kernel_mcp` capability signatures are decorative.** `issuer_signature_b64` is only checked for non-emptiness; there is no signature verification anywhere (`capability.py:94-98`). The docstring's "unforgeable token" (`capability.py:7`) is **not enforced** in code — forgery is prevented only by the caller not lying about the field. (Moot given #1, but a clear docstring/code gap.)

4. **CA-CI's "fail-closed" docstring is contradicted by the engine.** `CiNormRegistry` docstring says an empty registry "corresponds to fail-closed CI enforcement: with no norms permitted, every flow violates CI" (`ci_norms.py:153-156`), but `IfcEngine.evaluate` **only enforces CI when the registry is non-empty** (`engine.py:324`: "empty registry = advisory"). The docstring then partly walks this back ("currently runs CI in advisory mode … when the registry is empty"). Net: the stricter sentence in the docstring is misleading; the code is advisory-by-default. This is the constitution's "fail-closed default for novel signals" applied as *don't fire on absence*, which is defensible but the opposite of what "fail-closed" usually means.

5. **The sandbox's `exec()` is the single sharpest security caveat in the package — and it is honestly flagged.** `sandbox.py:34-43` and the TODO at `:360-363` make clear it is defeatable and "MUST replace the exec with a real isolation boundary." No overstatement here; the risk is that it's exported as `PrivateDataSandbox` (`private_data_exec/__init__.py`) with a confident name. Test-only today, so no live exposure.

6. **`standing.py` is genuinely well-built and matches its doctrine.** The fail-closed lower bound is real at every branch (unknown agent, non-governable, no deep command, deep raise, non-PERMIT verdict all return FORBID), the ABSTAIN→held-sink path carries the Layer-4 Hold, and the reflexive self-governance gate on `activate` is wired to a real `selfgov.governor` surface. This is the strongest file in the package and the docstring's claims hold up under code reading.

7. **`MemoryStream._evict_expired_locked` is O(n) on every put/lookup** (`memory.py:154-168`) — it deliberately scans all items rather than early-exiting (the comment explains FIFO reordering after re-touch makes early-exit unsafe). Correct, but a quiet O(n) on the hot path; bounded by capacity 256 so acceptable.

8. **`DEFAULT_MEMORY_STREAM` global is effectively unused in production.** The IfcSpecialist constructs its own `MemoryStream` (`specialists/ifc_specialist.py:176`), so the module-global at `memory.py:174` is a convenience that no live path consumes — minor dead-ish surface.

9. **RV4 soundness is the package's most important correctness property** and it is implemented with care (`ltlf.py:558-711`), including a documented off-by-one fix (`max(i, n)` vs `n` in the `F`/`G` branches, `ltlf.py:618-622, 689-695`). The U-operator in `_can_become_false` deliberately over-approximates to True (`ltlf.py:706-709`) to keep `U` out of the permanently-satisfied verdict — the safe direction for a FORBID gate. This is the right conservative bias and is documented.

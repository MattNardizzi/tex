# Subsystem Dossier — Behavioral Contracts, Policies, Deterministic Eval

**Scope dirs:** `src/tex/contracts/`, `src/tex/policies/`, `src/tex/deterministic/`
**Branch:** `feat/proof-carrying-gate`
**Layer:** Layer 4 — Execution Governance (declared in every `__init__.py`; e.g. `contracts/__init__.py:43`, `policies/__init__.py:9`, `deterministic/__init__.py:9`)
**Wired status:** **LIVE** (all three packages reach the running PDP — see Wiring).

> Method note: every claim below was confirmed by reading the code and tracing imports/call-sites with grep. Docstring/`.md` assertions are labelled "(claim, unverified)" where I could not confirm them in code.

---

## Overview

Three cooperating packages that together form the deterministic, paraphrase-proof half of Tex's Policy Decision Point (PDP):

1. **`deterministic/`** — Stream 1 of the PDP: a fast regex/rule recognizer gate (`DeterministicGate`) plus a stateful action-cadence circuit-breaker (`cadence.py`). Runs first on every `PolicyDecisionPoint.evaluate` call (`engine/pdp.py:264`).

2. **`policies/`** — Default and strict `PolicySnapshot` factories (`defaults.py`). These configure which recognizers are enabled, blocked terms, sensitive entities, criticality maps, fusion weights, and the permit/forbid thresholds the whole PDP reads. Seeded into the runtime at `main.py:1806-1807`.

3. **`contracts/`** — Two distinct families:
   - **LTLf behavioral contracts** (`contract.py`, `_ltl.py`, `_atoms.py`, `runtime_enforcement.py`, `violation.py`): a vendored mini finite-trace LTL evaluator with RV-LTL 4-valued semantics, used by `ContractEnforcer` to gate per-agent commitments. Reaches the PDP via `engine/contract_bridge.py` (`pdp.py:311`).
   - **Structural FORBID contracts** (`action_class.py`, `rule_of_two.py`, `rv4_path.py`): deterministic, label-driven floors that feed `specialists.structural_floor.detect_structural_floor` (`pdp.py:339`). These never read a probabilistic score — they can only raise caution.

The unifying doctrine, stated repeatedly in the docstrings and confirmed in code: **a FORBID must rest on a structural proof; uncertainty resolves to ABSTAIN; a signal may only ever lower a verdict (PERMIT → ABSTAIN → FORBID), never raise it.**

---

## File Inventory

| File | Lines | Role |
|---|---|---|
| `contracts/__init__.py` | 73 | Public surface; re-exports `BehavioralContract`, `ContractEnforcer`, `ComplianceScores`, `RecoveryDispatcher`, `all_active_contracts`, `ContractViolation`, `LTLFormula`, `LTLParseError`, `RVVerdict`, `ContractContext`. Sets `__layer__=4`. |
| `contracts/_ltl.py` | 657 | Vendored mini LTLf evaluator: AST, tokenizer, recursive-descent parser, finite-trace evaluator (`_eval_ltlf`), RV-LTL 4-valued verdict (`RVVerdict`, `_is_definite`). stdlib-only. |
| `contracts/_atoms.py` | 399 | Atom resolver bridging opaque LTL atoms to a predicate DSL (`field:`/`state:`/`drift:`/`kind:`/`capability:`/`actor:`/`upstream:`) over a `ContractContext` (proposed event + `EcosystemState`). 14 ContractSpec-style operators. |
| `contracts/contract.py` | 252 | `BehavioralContract` frozen dataclass (the ABC 6-tuple), `.make()` builder, `parsed_formulas()`, `applies_to()`, `_ParsedFormulas` AST bundle. |
| `contracts/runtime_enforcement.py` | 919 | `ContractEnforcer` — per-turn pre/post checks, soft-recovery window bookkeeping, compliance scores (C_hard/C_soft), reliability index Θ, ledger emission, telemetry. `ComplianceScores`, `RecoveryDispatcher`, `all_active_contracts`. |
| `contracts/violation.py` | 100 | `ContractViolation` frozen dataclass — one detection record. |
| `contracts/action_class.py` | 809 | Reversibility × BlastRadius join-semilattice FORBID floor; `evaluate_action_class`, `classify_action_class`, `ActionClassCertificate` (RCPS Hoeffding-Bentkus under-classification bound), seeded synthetic corpora. |
| `contracts/rule_of_two.py` | 267 | Meta "Agents Rule of Two" / lethal-trifecta structural floor; `evaluate_rule_of_two`, `classify_rule_of_two`, derives buckets from FIDES capability labels. |
| `contracts/rv4_path.py` | 225 | Bridges path-policy LTLf violations into FORBID (permanent bad prefix) vs ABSTAIN (recoverable) via the 4-valued `governance.path_policy.ltlf` classifier. |
| `policies/__init__.py` | 11 | Layer marker only (`__layer__=4`). |
| `policies/defaults.py` | 367 | `default_policy_snapshot` / `strict_policy_snapshot` (+ `build_default_policy`/`build_strict_policy`); blocked-term lists, sensitive entities, criticality maps, fusion weights, thresholds. |
| `deterministic/__init__.py` | 11 | Layer marker only (`__layer__=4`). |
| `deterministic/gate.py` | 143 | `DeterministicGate` + `DeterministicGateResult`; runs policy-enabled recognizers, dedupes findings, computes hard-block reasons. `build_default_deterministic_gate`. |
| `deterministic/cadence.py` | 659 | Action-cadence circuit-breaker: `CadenceConfig` (env-tunable), `ActionCadenceTracker` (thread-safe sliding window, request_id-idempotent), `apply_cadence_hold` (PERMIT→ABSTAIN), `assess_for_floor` (HARD→FORBID), module singleton. |
| `deterministic/recognizers.py` | 1185 | 14 recognizers: blocked terms, sensitive entities, secret leak, PII, unauthorized commitment, monetary transfer, urgency, external sharing, destructive/bypass, memory instruction, authority impersonation, jailbreak persona (8 families), invisible-Unicode, action-cadence. `default_recognizers()`. |

**Totals:** contracts 3,701 LOC, policies 378 LOC, deterministic 1,998 LOC.

---

## Internal Architecture

### 1. The LTLf evaluator (`_ltl.py`)

A self-contained, stdlib-only finite-trace LTL engine. Vendored deliberately to avoid the MONA C tool (ltlf2dfa) and the lydia Docker image (logaut) (`_ltl.py:11-15`, claim about requirements.txt unverified but the vendoring is real).

- **AST** (`_ltl.py:105-180`): frozen `slots` dataclasses — `_Const`, `_Atom`, `_Not`, `_And`, `_Or`, `_Implies`, `_Next` (strong), `_WeakNext`, `_Globally`, `_Eventually`, `_BoundedEventually` (the `F<=k` operator), `_Until`.
- **Tokenizer** (`_tokenize`, `_ltl.py:216-274`): hand-written. `_ATOM_CHARS` (`:195`) deliberately admits `. : = < > ! - / @ ~ ,` so DSL atoms like `field:output.pii_detected==false` ride inside a single LTL atom token. Special-cases `->` (implies) and `F<=N` (bounded-eventually with an integer bound).
- **Parser** (`_Parser`, `_ltl.py:282-402`): recursive descent, precedence (low→high) implies → or → and → until → unary(`not X Xw G F F<=k`) → primary. Implies is right-associative; the rest left.
- **Evaluator** (`_eval_ltlf`, `_ltl.py:518-592`): textbook LTLf semantics. `X` is strong (false at end, `:558`); `Xw` weak (true at end, `:563`); `G`/`F` are bounded scans over `[pos, n)`; `F<=k` scans `[pos, min(pos+k, n-1)]` (`:579`); `U` is the standard exists-j formulation. Atoms past end-of-trace return `False` — the explicitly conservative choice for safety properties (`:534-538`).
- **RV-LTL verdict** (`rv_verdict`, `_ltl.py:477-510`): combines a boolean eval with a `_is_definite` heuristic (`:595-649`) to project into `PERMANENTLY_SATISFIED / CURRENTLY_SATISFIED / CURRENTLY_VIOLATED / PERMANENTLY_VIOLATED`. The definiteness heuristic is deliberately conservative ("not definite" default) and carries an explicit `TODO(P2)` to tighten via Büchi-style monitorability (`:498`, `:616`). **The contracts enforcer never uses `rv_verdict`** — it uses only `evaluate_finite` (binary). `RVVerdict` is exported for future callers; it is genuinely live only as a re-export. (Note: a *separate* 4-valued classifier, `governance.path_policy.ltlf.RV4Verdict`, is what `rv4_path.py` actually uses — see §4.)

### 2. The atom resolver (`_atoms.py`)

`ContractContext` (`:91`) bundles `proposed_event: ProposedEvent`, `state: EcosystemState`, and an `event_window`. `make_resolver(context)` (`:317`) returns a closure resolving each atom namespace:

- `kind:` → `proposed_event.event_kind == literal` (`:332`)
- `actor:` → `proposed_event.actor_entity_id` (`:335`)
- `capability:` → membership in `state.active_capability_ids` (`:338`)
- `upstream:` → membership in `proposed_event.upstream_event_ids` (`:343`)
- `field:` → dotted-path lookup into `proposed_event.payload` then `_compare` (`:348`)
- `state:` → builds a flat mirror dict of `EcosystemState` then path-lookup (`:352-368`)
- `drift:` → `state.aggregate_drift_signals.get(path)` (`:370`)

`_parse_atom` (`:145`) splits atom into (namespace, path, op, literal); bare atoms (no `:`) become `state:<atom>==true` (`:151`). `_compare` (`:196`) implements the 14 operators — `==,!=,>,>=,<,<=,~in,~not_in,~contains,~not_contains,~matches` (re.search), `~between`, `~exists` — with numeric coercion preferred and string fallback (`:233-271`). All field/dependency references verified: `ProposedEvent` carries `event_kind/actor_entity_id/payload/upstream_event_ids/proposed_at` (`ecosystem/proposed_event.py:22-28`).

`trace_for(context)` (`:386`) returns a **one-element** trace carrying `{"_event_payload": ...}`. The trace element is in fact unused by the resolver (the closure reads `context` directly), so contract LTL is evaluated over a single position — sufficient for ABC invariant-response patterns, with the multi-step path left as future work (`:325`, `:387-399`).

### 3. `BehavioralContract` (`contract.py`) and the enforcer (`runtime_enforcement.py`)

**`BehavioralContract`** (`contract.py:73`) is the ABC 6-tuple `C=(P,I_hard,I_soft,G_hard,G_soft,R)` stored as LTL **strings** (cheap, picklable). `invariants_ltl` is the back-compat alias for hard-invariants; `postcondition_ltl` is a legacy non-ABC field that degrades to a single check (`:91-92`). `.make()` (`:121`) parses every formula at construction so malformed LTL raises `LTLParseError` synchronously. `__post_init__` (`:168`) enforces `delta_tolerance∈[0,1]`, `satisfaction_p∈[0,1]`, `recovery_window_k≥0`, non-empty `covered_event_kinds`. `applies_to` (`:226`) implements wildcard matching on `agent_id`/`event_kind`. The `(p,δ,k)` parameters are stored but, in this layer, **only `recovery_window_k` is consumed** (it sets the soft-recovery deadline in the enforcer) — `delta_tolerance`/`satisfaction_p` are carried for a future SPRT certifier (`contract.py:31-33`, claim of a future `tex.contracts.certification` is **unverified — no such module exists**, see Findings).

**`ContractEnforcer`** (`runtime_enforcement.py:99`):
- Construction (`:116`) requires ≥1 contract, enforces `(ledger is None) == (provenance is None)`, rejects duplicate `contract_id`, and pre-parses every formula into `self._parsed` (`:142`).
- State: `_step_index` (StepShield counter), `_soft_pending` (recovery deadlines keyed by `(agent_id, contract_id, kind, formula_idx)`), `_violations` list, and `_c_hard_history`/`_c_soft_history`.
- `check_pre` / `check_post` (`:194`, `:238`) both delegate to `_check` (`:407`). Returns `(is_satisfied, violated_contract_ids)` where `is_satisfied=False` iff a **hard** clause (precondition/hard-invariant/hard-governance, or post-execution postcondition) failed; soft violations do not clear it.
- `_check` data flow: builds `ContractContext` → resolver → one-element trace → selects active contracts via `applies_to` → for each clause class evaluates `f.evaluate_finite(trace, resolver)` → records violations → updates per-step C_hard/C_soft → sweeps expired soft-recovery deadlines (`:564`) → emits `contracts.check.completed` telemetry (`:566`).
- **Soft-recovery semantics** are the genuinely novel runtime piece. `_handle_soft_violation` (`:582`) registers a deadline at `step + recovery_window_k` and emits a `warn`-severity violation only on **first** detection (idempotent — `:603`). `_discharge_recovery` (`:629`) cancels a pending entry **only if** recovery happened within the window, else it leaves it for the sweep; on success it **mutates the stored violation** in place (rebuilds the frozen record with `recovered_at_step` set, `:661-675`). `_sweep_expired_recoveries` (`:686`) escalates any past-deadline soft violation into a fresh `is_soft=False`, `severity="block"` record (`:714-725`).
- `_record` (`:738`): severity = override (escalation) else contract severity for hard, else `"warn"` for soft (`:759-766`). `compliance_gap = 1/total_constraint_count` (`:771`). **Ledger emission happens before recovery dispatch** so the signed record survives a dispatcher exception (`:792-810`). The recovery dispatcher fires only for soft violations or `sanction`-severity hard ones (`:828`).
- `_append_to_ledger` (`:842`) builds a `policy_decision` `ProposedEvent` and calls `self._ledger.append_proposed(proposed, provenance=...)`. Floats coerced to milli-units (`compliance_gap_milli`, `:862`) — the documented determinism contract (`:846-853`). `ledger`/`provenance` are duck-typed `Any` (same convention as `ChangePointDetector`).
- `compliance_scores` (`:272`) computes C_hard/C_soft without recording (ABC §3.3 Def 3.6). `reliability_index` (`:339`) computes Θ as a weighted blend of mean C_hard, soft-compliance-gap, recovery effectiveness, and a hard-coded stress term `S=1.0` — with two explicit `TODO(P2)` markers that the drift and stress components are stand-ins (`:361-366`, `:399`).

**`ContractViolation`** (`violation.py:48`): frozen record with `violated_clause`, `clause_ltl` (replay), `step_index` (StepShield), `severity`, `compliance_gap`, soft-recovery bookkeeping (`recovery_deadline_step`/`recovered_at_step`), and an optional `ledger_event_id`.

### 4. Structural FORBID contracts

These are **not** LTLf-enforcer contracts; they are pure label-driven classifiers feeding the structural floor.

**`action_class.py`** — Reversibility × BlastRadius lattice. Two `IntEnum` join-semilattices (`Reversibility`, `BlastRadius`, `:140`/`:165`) with `UNKNOWN` as a fail-closed top member and `join = max`. `classify_action_class(rev, blast)` (`:232`) is the fixed cell map: `FORBID` iff `is_irreversible AND is_public`, `ABSTAIN` iff exactly one dangerous axis, else `NEUTRAL`. `_join_steps` (`:247`) takes the worst-step join over declared steps; a missing/unparseable axis fails closed to `UNKNOWN` (`_coerce_rev`/`_coerce_blast`, `:201`/`:218`). `evaluate_action_class(request)` (`:353`) reads **only** `request.metadata["action_class"]` and is a zero-cost no-op when absent. Only the FORBID cell is wired to the floor this wave (`:91-98`, confirmed in §Wiring).
  - The `ActionClassCertificate` (`:389`) is an offline RCPS bound on the floor's under-classification rate using `engine.crc_gate.hoeffding_bentkus_ucb` (verified real at `engine/crc_gate.py:398`). `certify_action_class` (`:547`) computes the Hoeffding-Bentkus UCB; **`certified` flips True only for a `field` corpus whose UCB clears alpha** (`:590`) — synthetic corpora compute-but-abstain. The shipped default `ACTION_CLASS_CERT = certify_action_class([])` (`:617`) is inert (`enabled=False, certified=False`). Seeded synthetic corpus builders (`build_action_class_corpus`, `build_certifiable_action_class_corpus`, `:684`/`:730`) use a deliberately **anti-circular** sampler (`_sample_action_class_case`, `:636`): ground truth is a latent `(rev_true, blast_true)`, declared features pass through a separate mis-declaration channel, so the under-classification rate is genuinely non-zero. Both builders carry anti-vacuity tripwires (`:721`, `:781`).

**`rule_of_two.py`** — Meta "Agents Rule of Two" / lethal-trifecta. `classify_rule_of_two(raw)` (`:192`) fires FORBID iff all three buckets `(untrusted_input AND sensitive_access AND state_change)` hold **and** `human_oversight` is False (Meta's escape hatch, `:214`). Buckets can be declared explicitly (booleans win) or derived: `_derive_from_capabilities` (`:143`) reads FIDES `CapabilityLevel`/`ConfidentialityLevel` from `tex.camel.capability` (verified `is_sensitive` = `>= CONFIDENTIAL` at `camel/capability.py:97-15`; `UNTRUSTED` at `:86`). `_as_bool` (`:128`) is deliberately conservative (fail-to-"not-proven"), the explicit dual of `action_class._coerce_rev`'s fail-closed posture. Zero-cost no-op without `metadata["rule_of_two"]`.

**`rv4_path.py`** — Splits LTLf path-policy violations into FORBID (permanent bad prefix) vs ABSTAIN (recoverable). Uses the **other** 4-valued classifier: `governance.path_policy.ltlf.{compile_formula, evaluate_rv4_compiled, RV4Verdict, LtlfParseError}` (`:46-51`, imports verified). `classify(request)` (`:146`) builds a trace from `metadata["rv4_path_policies"]` (`_build_trace`, `:120`), compiles each formula, and classifies: `PERMANENTLY_VIOLATED` → permanent → FORBID; `CURRENTLY_VIOLATED` → recoverable → ABSTAIN. **A parse error is treated as recoverable/ABSTAIN, never a fabricated FORBID** (`:177-189`) — the fail-closed-without-over-blocking posture. Zero-cost no-op when absent.

### 5. `policies/defaults.py`

Pure factory module. `_DEFAULT_ENABLED_RECOGNIZERS` (`:15`) lists 14 recognizer names (matching `default_recognizers()`, including `action_cadence`). `_DEFAULT_BLOCKED_TERMS` (`:39`) is a 7-entry conservative list; `_STRICT_BLOCKED_TERMS` (`:59`) extends it to ~60 entries. Criticality maps for action/channel/environment (`:145-179`), specialist thresholds, and fusion weights. `default_policy_snapshot`/`strict_policy_snapshot` (`:263`/`:287`) build a `tex.domain.policy.PolicySnapshot`; the strict snapshot is **inactive by default** (`is_active=False`, `:293`) with lower permit/forbid bars (`:251-252`). Note `_DEFAULT_FUSION_WEIGHTS == _STRICT_FUSION_WEIGHTS` (`:195` vs `:205`) — identical (see Findings).

### 6. `deterministic/gate.py` + `recognizers.py`

`DeterministicGate.evaluate` (`gate.py:68`) filters recognizers to those in `policy.enabled_recognizers`, runs each `.scan(request)`, dedupes (`gate.py:99`), and computes hard-block reasons via `policy.blocks_severity(finding.severity)` (`gate.py:133`). `DeterministicGateResult.suggested_verdict` maps blocked→FORBID, any-findings→ABSTAIN, else None (`gate.py:47-52`).

`recognizers.py` implements the `Recognizer` Protocol (`:16`). Most extend `BaseRegexRecognizer` (`:25`) which iterates `re.finditer` and emits one `Finding` per match. Notable substantive recognizers:
- **`MonetaryTransferRecognizer`** (`:223`) — ~12 patterns for wire/ACH/SWIFT/crypto/BEC change-of-payee/abbreviated-amount money movement; CRITICAL.
- **`JailbreakPersonaRecognizer`** (`:520`) — 8 categorized families (`instruction_override`, `dan_family`, `persona_swap`, `system_prompt_shape`, `temporal_confusion`, `many_shot_priming`, `fictional_frame`, `safety_disable`); WARNING (deliberately not FORBID, to avoid demo-killing false positives, `:557-562`). Overrides `patterns`/`scan` to tag each finding with `jailbreak_family`.
- **`InvisibleUnicodeRecognizer`** (`:832`) — not regex; scans codepoints for Unicode Tag Block (U+E0000–E007F), variation-selector supplement (U+E0100–E01EF), VS base (density ≥3), bidi overrides, and zero-width density (≥4). Decodes the hidden payload (`_decode_tag_block`, `_decode_variation_selector_supplement`) into `decoded_preview` for audit. CRITICAL.
- **`ActionCadenceRecognizer`** (`:1098`) — thin stateful face over the cadence tracker; runs **last** in `default_recognizers()` (`:1185`) so it observes the action exactly once after content scans.

### 7. `deterministic/cadence.py`

`ActionCadenceTracker` (`:295`) is the stateful core: a lock-guarded sliding window per `(tenant, agent identity)` keyed string (`_derive_key`, `:464`). `assess(request)` (`:321`) is **request_id-idempotent** — memoized per request_id, and the window insert checks `request_id` membership so the same action is never double-counted (`:359`). The window clock is `request.requested_at` (edge timestamp, not wall-clock, `:450`) so it is reproducible in tests. State is bounded by three LRU caps (`max_window_entries`, `max_tracked_keys`, `max_memo_entries`). `CadenceConfig.from_env` (`:143`) reads `TEX_CADENCE_*` env vars with fail-safe defaults and **clamps `hard >= soft`** so the breaker can never FORBID before it ABSTAINs (`:166-167`).

Two rails, both monotone-lowering:
- `apply_cadence_hold(base, request)` (`:574`) — **only** touches a `Verdict.PERMIT` (`:594`), demotes to ABSTAIN on a fired assessment, rebuilds the `RoutingResult` immutably. Soft rail.
- `assess_for_floor(request)` (`:565`) — reads the shared process singleton (`default_cadence_tracker`, `:535`) so the structural floor sees the same observation the recognizer made. HARD rail.

The module singleton is lazily built from env on first use and resettable for tests (`_reset_default_cadence_tracker`, `:557`). The docstring's "Approach A vs B" CORE-change note (`:48-68`) accurately describes the chosen single-singleton-with-memoization design.

---

## Public API

**`contracts/__init__.py` exports** (`:57-73`): `BehavioralContract`, `ContractEnforcer`, `ComplianceScores`, `RecoveryDispatcher`, `all_active_contracts`, `ContractViolation`, `LTLFormula`, `LTLParseError`, `RVVerdict`, `ContractContext`. The submodules `contracts.action_class`, `contracts.rule_of_two`, `contracts.rv4_path` are imported directly by callers (not re-exported from `__init__`).

**`policies/defaults.py`**: `default_policy_snapshot`, `strict_policy_snapshot`, `build_default_policy`, `build_strict_policy`, plus `DEFAULT_POLICY_ID`/`STRICT_POLICY_ID` and version constants.

**`deterministic/gate.py`**: `DeterministicGate`, `DeterministicGateResult`, `build_default_deterministic_gate`.
**`deterministic/recognizers.py`**: `Recognizer` (Protocol), the 14 recognizer classes, `default_recognizers`.
**`deterministic/cadence.py`**: `CadenceLevel`, `CadenceConfig`, `CadenceAssessment`, `ActionCadenceTracker`, `default_cadence_tracker`, `configure_default_cadence_tracker`, `assess_for_floor`, `apply_cadence_hold`, `CADENCE_HOLD_FLAG`.

---

## Wiring

### In (who imports the public symbols)

Confirmed by grep across `src/tex` (excluding the packages themselves):

| Importer | Symbols | Status |
|---|---|---|
| `engine/contract_bridge.py:89-91` | `BehavioralContract`, `ContractEnforcer`, `ContractViolation` | LIVE bridge |
| `engine/pdp.py:9` | `ContractEnforcer` | LIVE |
| `engine/pdp.py:10` | `apply_cadence_hold` | LIVE |
| `engine/pdp.py:11-14` | `DeterministicGate`, `DeterministicGateResult`, `build_default_deterministic_gate` | LIVE |
| `main.py:39` | `BehavioralContract`, `ContractEnforcer` | LIVE composition root |
| `main.py:109` | `build_default_policy`, `build_strict_policy` | LIVE |
| `specialists/structural_floor.py:56-68` | `rv4_path`, `action_class.*`, `rule_of_two.*`, `cadence.{CadenceLevel,assess_for_floor}` | LIVE floor |
| `domain/asi_builder.py:25`, `domain/determinism.py:21`, `engine/router.py:7` | `DeterministicGateResult` | LIVE (result type) |
| `systemic/probguard.py:539` | `rv4_path` (lazy import) | INDIRECT |
| `capstone/compose.py:47` | `ACTION_CLASS_CERT`, `evaluate_action_class` | INDIRECT (audit composition) |
| `bench/wave2_corpus/{builders,loaders}.py` | action_class corpus/cert helpers | INDIRECT (bench) |

### Live call path

**Deterministic gate (always runs):**
`tex.main:build_runtime` → `PolicyDecisionPoint(...)` (`main.py:876`) constructs `self._deterministic_gate = build_default_deterministic_gate()` (`pdp.py:198`) → `PolicyDecisionPoint.evaluate()` → `self._deterministic_gate.evaluate(request, policy)` (**`pdp.py:264`**) → `DeterministicGate.evaluate` (`gate.py:68`) → each recognizer's `.scan`.

**Policy snapshots:** `main.py:1806-1807` calls `build_default_policy()`/`build_strict_policy()` and seeds them into the policy store; the PDP reads `policy.enabled_recognizers`, `.blocked_terms`, `.permit_threshold`, etc. on every evaluate.

**LTLf behavioral contracts:** `main.py:854-862` builds `_build_default_contract_suite()` (one seed contract `content-no-api-keys`, `main.py:495-507`) and wires either a stateless `ContractEnforcer` or a session-scoped `SessionEnforcerRegistry` (default `session_scoped`, env `TEX_CONTRACTS_MODE`/`TEX_CONTRACTS_DISABLE`, `main.py:844-849`) into the PDP (`main.py:879-881`). On evaluate: `pdp.py:311` → `evaluate_contracts_for_request(...)` (`contract_bridge.py:454`) → `active_enforcer.check_pre(...)` (`contract_bridge.py:548`) → `ContractEnforcer._check`. The live request's content reaches the contract via `_build_proposed_event` which puts `request.content` into `payload["content"]` (`contract_bridge.py`), so the seed contract `G(field:content~not_contains:sk-proj-)` evaluates against real content. Hard contract violations short-circuit to FORBID before the router (`pdp.py:302-316` docstring; confirmed the bridge returns hard-violation outcome consumed by the floor).

**Structural FORBID contracts:** `pdp.py:339` → `detect_structural_floor(request, ...)` (`structural_floor.py`) → `_action_class_deny` (`structural_floor.py:218-230`, calls `evaluate_action_class`), `_rule_of_two_deny` (`:208`, calls `evaluate_rule_of_two`), `rv4_path.classify` (`:273`), and `assess_for_floor` HARD check (`:255-256`). A fired floor short-circuits to FORBID (`pdp.py:346`, `structural_floor.short_circuited_to_forbid`).

**Cadence soft hold:** `pdp.py:418` → `apply_cadence_hold(base=routing_result, request=request)` after the router (PERMIT→ABSTAIN only). The same `ActionCadenceRecognizer` observed the action earlier in the gate, and the floor's `assess_for_floor` and this hold all share the one process singleton.

### Out (dependencies)

**Internal tex subsystems:**
- `contracts._atoms` → `tex.ecosystem.proposed_event.ProposedEvent`, `tex.ecosystem.state.EcosystemState`
- `contracts.runtime_enforcement` → `tex.observability.telemetry.emit_event` (verified at `observability/telemetry.py:255`), `tex.ecosystem.*`
- `contracts.action_class` → `tex.engine.crc_gate.hoeffding_bentkus_ucb`, `pydantic`
- `contracts.rule_of_two` → `tex.camel.capability.{CapabilityLevel, ConfidentialityLevel}`
- `contracts.rv4_path` → `tex.governance.path_policy.ltlf.*`, `tex.governance.path_policy.policy.PathStep`
- `policies.defaults` → `tex.domain.policy.PolicySnapshot`, `tex.domain.severity.Severity`
- `deterministic.gate` → `tex.deterministic.recognizers.*`, `tex.domain.{evaluation,finding,policy,severity,verdict}`
- `deterministic.cadence` → lazy `tex.domain.verdict.Verdict`, `tex.domain.finding.Finding`, `tex.engine.router.RoutingResult` (lazy to avoid an import cycle, `cadence.py:589-603`)
- `deterministic.recognizers` → `tex.deterministic.cadence.*`, `tex.domain.{evaluation,finding,severity}`

**External libraries:** `pydantic` (action_class certificate, gate result), `re` (recognizers, atoms), `hashlib` (cell-map version), `uuid`, `threading`, `collections.{OrderedDict,deque}`, plus stdlib only for the LTL engine. No native crypto/zk/tee libraries in this unit. The only "crypto-adjacent" dependency is the RCPS Hoeffding-Bentkus bound (pure math in `crc_gate`) and ledger signing via the injected `provenance` duck-type (not implemented here).

---

## Implementation Reality

**REAL, substantive logic (not stubs):**
- The LTLf evaluator is a complete, working finite-trace LTL engine — tokenizer, parser, and evaluator all implemented; verified by `import` + the fact that `BehavioralContract.make` parses at construction. No `NotImplementedError`/`pass`-only bodies.
- The `ContractEnforcer` soft-recovery window machinery is fully implemented including escalation-on-expiry and in-place violation mutation. Two prior `TODO(P1)` items are annotated **DONE** in the docstrings (`runtime_enforcement.py:224-228`, `:255-258`) and the corresponding code (`_sweep_expired_recoveries`, postcondition handling) is present.
- The structural contracts (`action_class`, `rule_of_two`, `rv4_path`) are real classifiers with real fail-closed/fail-open coercion logic, exercised by the live floor.
- All 14 recognizers have real patterns/logic; the invisible-Unicode decoder genuinely reverses tag-block and variation-selector encodings.
- The cadence tracker is a real thread-safe sliding-window rate limiter with idempotency and LRU bounds.
- The RCPS certificate math (`hoeffding_bentkus_ucb`) is real and reused, not reimplemented.

**Stubs / placeholders / honest-incomplete:**
- `_ltl._is_definite` is an explicitly-heuristic, conservative approximation with `TODO(P2): tighter monitorability` (`_ltl.py:498`, `:616-618`). It is correct-but-loose, not a stub. **But it is also dead for the contracts use case** — the enforcer never calls `rv_verdict`.
- `ContractEnforcer.reliability_index` ships a "simplified" Θ: the drift term is proxied by soft-compliance-gap and the stress term is hard-coded `S=1.0`, with two `TODO(P2)` markers (`runtime_enforcement.py:361-366`, `:399`). Honest partial.
- `_atoms`: the ABC `expr` (sandboxed arithmetic) operator is intentionally **not** supported with a `TODO(P2)` (`_atoms.py:66-69`).
- `ACTION_CLASS_CERT` is shipped **inert** (`certified=False`, no corpus) by design (`action_class.py:615-617`); the certifier refuses to certify any non-`field` corpus. This is honest under-promising, not a bug.

**No hollow crypto/zk/tee in this unit.** The only certificate is a statistical (RCPS) bound, computed honestly.

---

## Technology / SOTA

- **LTLf (finite-trace LTL)** per De Giacomo & Vardi 2013 with strong/weak next; **RV-LTL 4-valued runtime verification** per Bauer/Leucker/Schallhart 2011; **bounded-eventually `F<=k`** for the ABC recovery window. References cited in `_ltl.py:47-55`.
- **AgentAssert / ABC behavioral contracts** — the 6-tuple `C=(P,I_hard,I_soft,G_hard,G_soft,R)`, `(p,δ,k)`-satisfaction, per-step compliance scores C_hard/C_soft, reliability index Θ. Cited as arXiv 2602.22302 (Bhardwaj 2026) throughout `contract.py`/`runtime_enforcement.py`. **(claim, unverified — paper IDs not checked against any source; treat as design framing.)**
- **Join-semilattice / FIDES capability lattice** patterns (action_class, rule_of_two) — `join = max`, fail-closed top.
- **Meta "Agents Rule of Two" / lethal trifecta** (Willison) — `rule_of_two.py`.
- **RCPS (Risk-Controlling Prediction Sets), Hoeffding-Bentkus UCB** — Bates/Angelopoulos/Lei/Malik/Jordan JACM 2021, arXiv:2101.02703, reused via `crc_gate` (`action_class.py:76-82`).
- **2026 jailbreak / Unicode-smuggling taxonomy** synthesized into regex families (recognizers; many vendor advisories cited).
- **Anthropic Nov-2025 autonomous-attack disclosure** as motivation for the cadence circuit-breaker (`cadence.py:10-20`).
- **Design patterns:** Protocol-based recognizer registry, frozen `slots` dataclasses everywhere, dependency injection of ledger/provenance/tracker, lazy module singleton, env-config fail-safe, monotone-lowering invariant discipline.

---

## Persistence

**Entirely in-memory across this unit.** No durable storage is owned here:
- `ContractEnforcer` keeps `_violations`, `_soft_pending`, and compliance histories in instance memory. Durability is delegated: when wired with a `ledger`+`provenance`, violations are appended to an injected ledger (`_append_to_ledger`, `runtime_enforcement.py:874`). In the live runtime the session-scoped path can replay an `action_ledger` window to seed recovery state (`contract_bridge.py:512-528`), but the contracts unit itself stores nothing on disk.
- The session-scoped `SessionEnforcerRegistry` (in `engine/contract_bridge.py`, out of scope) holds per-session enforcers in memory.
- `ActionCadenceTracker` holds all window/memo state in memory, bounded by LRU caps; it is process-lifetime and reset per test.
- `BehavioralContract`, `PolicySnapshot`, recognizer pattern tables, and the action-class cell map are immutable in-memory values. The default contract suite is hard-coded (`main.py:495`). Policy snapshots get `created_at` timestamps but are constructed fresh each boot.

---

## Notable Findings

1. **`tex.contracts.certification` (the promised SPRT certifier) does not exist.** The `(p,δ,k)` fields (`delta_tolerance`, `satisfaction_p`) on `BehavioralContract` are stored but never consumed by any code — only `recovery_window_k` is used. The docstrings repeatedly forward-reference a future certifier (`contract.py:31-33`, `_ltl.py:31-32`, `:498`). Verified: grep finds no `certification` module under `contracts/`. **Dead/unused fields + aspirational docstrings.**

2. **`RVVerdict` / `rv_verdict` / `_is_definite` are effectively dead for the contracts use case.** The enforcer collapses to the binary `evaluate_finite` and never invokes the 4-valued path. `RVVerdict` is exported but only as a public surface for the non-existent certifier. The actual 4-valued logic used live (rv4_path) is the **separate** `governance.path_policy.ltlf.RV4Verdict` — a naming collision worth flagging: two different 4-valued LTL verdict types coexist (`contracts._ltl.RVVerdict` vs `governance.path_policy.ltlf.RV4Verdict`).

3. **Default and strict fusion weights are byte-identical.** `_DEFAULT_FUSION_WEIGHTS` (`defaults.py:195-203`) equals `_STRICT_FUSION_WEIGHTS` (`:205-213`). The strict policy differs only in thresholds, blocked terms, and sensitive entities — the "more aggressive specialist escalation" claim (`defaults.py:296-298` docstring) is realized via thresholds, not weights. Minor overstatement; likely intentional copy.

4. **The seed contract suite is a single demonstrator.** Production runtime ships exactly one contract (`content-no-api-keys`, `main.py:495-508`). The docstring is honest that this exists "to prove the wiring is live end-to-end" (`main.py:476-478`). The rich (p,δ,k) ABC machinery is therefore real but barely exercised by default — most of its power awaits tenant-supplied contracts.

5. **Two distinct meanings of "contract" share the namespace.** `contracts/` houses both LTLf *behavioral* contracts (enforcer path, via contract_bridge) and *structural* contracts (action_class/rule_of_two/rv4_path, via structural_floor). They have no code in common and reach the PDP by different routes. The package docstring (`contracts/__init__.py`) describes only the LTLf family; the structural trio is undocumented at package level. Not a bug, but a navigation hazard.

6. **`action_class` certificate is never read at runtime — confirmed, matching the docstring.** Grep shows `ACTION_CLASS_CERT` is consumed only by `capstone/compose.py:441` (audit composition, which asserts it must be `certified=False`) and the bench corpus loaders. The live floor (`_action_class_deny`) reads only `outcome.action_class`. The "the runtime floor NEVER reads this object" claim (`action_class.py:391-392`) is verified true.

7. **Strict policy is inactive by default** (`strict_policy_snapshot(..., is_active=False)`, `defaults.py:293`). It is constructed at boot (`main.py:1807`) but only the default policy is active unless explicitly switched. Worth noting for anyone expecting the ~60-term strict blocklist to be on.

8. **Cadence thresholds are self-described as `research-early`** (`cadence.py:80-86`, `:118-120`) — sane project defaults, not calibrated. The mechanism is production-shaped; the numbers are not. Honest labeling.

9. **`engine/contract_bridge.py:65-72` documents a real semantic gap:** replayed historical events store `content_sha256`, not raw content, so contracts whose atoms read `field:content~contains:...` over *past* events will not match (only the live request's content is available). Contracts intended to fire over history must restrict themselves to hashed/preserved fields. Correctly documented, a genuine constraint on the (p,δ,k) replay path.

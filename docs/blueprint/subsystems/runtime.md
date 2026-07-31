# Subsystem Dossier: `runtime` — Runtime Defense Layer

> Scope: `/Users/matthewnardizzi/dev/tex/src/tex/runtime/`
> Branch: `feat/proof-carrying-gate`
> Verified by reading every `.py` file in scope and tracing imports/call-sites across `src/tex`.
> All evidence is code-cited with absolute `file:line`.

---

## Overview

`tex.runtime` is **not** the process/lifecycle "runtime services" implied by the
task brief (there is **no** `dormancy_controller`, `ignition_registry`, or
`presence_tracker` anywhere in this tree — see *Notable Findings #1*). What
actually lives here is the **Runtime Defense Layer**: five complementary,
paper-derived runtime security engines for tool-augmented LLM agents, each
defending a different injection/abuse surface, composed defense-in-depth. The
package docstring labels it *Layer 4 (Execution Governance)*
(`src/tex/runtime/__init__.py:1-2,36-37`).

The five engines (each a sub-package):

| Engine | Defends | Reference cited in code |
|---|---|---|
| `clawguard/` | Tool-call boundary enforcement (cmd/file/net deny-by-default + secret redaction) | arxiv 2604.11790 (`clawguard/__init__.py:4`) |
| `planguard/` | Indirect prompt injection via planning-consistency verification | arxiv 2604.10134 (`planguard/__init__.py:5`) |
| `agentarmor/` | Static program analysis (CFG/DFG/PDG + information-flow type system) over agent traces | arxiv 2508.01249 (`agentarmor/__init__.py:3`) |
| `mage/` | Long-horizon / multi-turn threats via a safety-curated "shadow memory" + pre-action risk judge | arxiv 2605.03228 (`mage/__init__.py:4`) |
| `mcpshield/` | Formal verification of MCP tool calls as a Labeled Transition System (4 security properties) | arxiv 2604.05969 (`mcpshield/__init__.py:3`, note: `lts_model.py:5` cites the same number) |

**Wiring summary:** All five are **LIVE**. Each engine is wrapped by a matching
specialist in `tex/specialists/*_specialist.py`, those specialists are members of
the default specialist suite (`tex/specialists/judges.py:366-372`), the suite is
instantiated inside `PolicyDecisionPoint` (`tex/engine/pdp.py:205`), the PDP is
built by `build_runtime()` (`tex/main.py:877`), and the PDP's `evaluate()` is
called on the live `POST /v1/guardrail` route via `EvaluateActionCommand.execute`
(`tex/api/guardrail.py:784` → `tex/commands/evaluate_action.py:214`). Full path
in *Wiring → Live call path*.

**Reality:** The engines are **REAL** algorithmic implementations (lattice
information-flow, networkx graph IR, regex rule engines, SHA-256 hash integrity,
LTS reachability monitors), not hollow stubs. Every "TODO" found is a *stale
scaffolding marker sitting above already-implemented code* (see *Implementation
Reality*). The one genuine logic defect found: in ClawGuard's default
`check_call` path, **input sanitization runs before rule evaluation, so the
`secret_*` deny rules are masked and never fire** (verified at runtime — see
*Notable Findings #2*).

---

## File Inventory

17 `.py` files (excluding `__pycache__`).

| File | Lines | Role |
|---|---:|---|
| `runtime/__init__.py` | 39 | Layer-4 marker (`__layer__=4`); docstring index of the 5 engines. `__all__ = []` (no re-exports at package root). |
| `runtime/agentarmor/__init__.py` | 66 | Re-exports the AgentArmor public API (graph IR, registries, type system). |
| `runtime/agentarmor/graph_constructor.py` | 292 | Builds CFG/DFG/PDG networkx DiGraphs from a runtime trace; taint-linking observations→later params. |
| `runtime/agentarmor/property_registry.py` | 295 | Confidentiality/Integrity/Trust lattices + lattice ops; Tool/Data registries; heuristic scanners; PDG annotator. |
| `runtime/agentarmor/type_system.py` | 258 | 3-stage type assign→infer→check; information-flow violation detection over the PDG. |
| `runtime/clawguard/__init__.py` | 50 | Re-exports the ClawGuard public API. |
| `runtime/clawguard/boundary_enforcer.py` | 472 | Sanitizer + rule evaluator + boundary enforcer; the deny/allow/ambiguous decision pipeline. |
| `runtime/clawguard/rule_set.py` | 402 | Rule/RuleSet models; 11 default baseline deny rules; 5 default redaction patterns; offline task-rule induction. |
| `runtime/mage/__init__.py` | 41 | Re-exports the MAGE public API. |
| `runtime/mage/risk_assessor.py` | 214 | Pre-action risk judge `J`; offline deterministic + pluggable LLM judge; 4-stage risk logic. |
| `runtime/mage/shadow_memory.py` | 228 | Append-only, monotonic-turn shadow memory `M`; TTL-decayed keyword-relevance distillation. |
| `runtime/mcpshield/__init__.py` | 53 | Re-exports the MCPShield public API. |
| `runtime/mcpshield/lts_model.py` | 194 | LTS data model (SecurityLabel lattice, ToolDefinition w/ SHA-256, TrustDomain, Transition, LtsModel). |
| `runtime/mcpshield/verifier.py` | 319 | The 4 property checkers (tool integrity, data confinement, privilege boundedness, context isolation) + counterexample paths. |
| `runtime/planguard/__init__.py` | 41 | Re-exports the PlanGuard public API. |
| `runtime/planguard/intent_verifier.py` | 247 | Hierarchical Stage-I/Stage-II verifier; deterministic + pluggable LLM intent check. |
| `runtime/planguard/isolated_planner.py` | 251 | Isolated planner `P(I,T)→S_ref`; deterministic verb/regex matcher + pluggable LLM planner; ReferencePlan model. |

---

## Internal Architecture

### 1. ClawGuard — tool-call boundary enforcement (`clawguard/`)

**Data model (`rule_set.py`):**
- `RuleDomain` ∈ {CMD, FILE, NET} (`rule_set.py:42-47`); `RuleAction` ∈ {DENY, ALLOW} (`:50-54`); `Verdict` ∈ {ALLOW, DENY, AMBIGUOUS} (`:57-62`).
- `Rule` is a frozen pydantic model with `rule_id`, `domain`, `action`, `pattern` (regex) (`:65-76`).
- `BaseRuleSet.default()` returns `_DEFAULT_BASELINE_RULES` (`:103`), an 11-rule tuple (`:178-300`) covering: `rm -rf` of root (`:181-194`), curl/wget-pipe-shell (`:195-202`), `.ssh` writes (`:205-212`), RFC1918/loopback/link-local/multicast nets incl. `localhost` (`:216-237`), `/etc/{shadow,passwd,sudoers,...}` reads (`:240-247`), a **deny-nothing sentinel** for outbound-allowlist (`pattern=r"(?!.*)$"`, `:254-266`), AWS/OpenAI/GitHub secret patterns (`:268-291`), and a `sudo`/`chmod +s`/`chown root` deny (`:292-299`).
- `TaskRuleSet.induce_from_objective()` (`:115-158`) is the **offline** path: regex-extracts explicitly-named domains (`_DOMAIN_PATTERN`, `:361-365`) and file paths (`_PATH_PATTERN`, `:369-371`) from the user instruction and emits ALLOW rules. A paper-faithful `induce_from_objective_llm` is *referenced in the docstring* (`:128`) but **does not exist** in this file (see *Notable Findings #4*).
- `get_default_sanitization_patterns()` (`:350-351`) returns 5 redaction patterns (`:315-347`): AWS key, OpenAI key, GitHub token, generic Bearer, SSH private-key block.

**Enforcement pipeline (`boundary_enforcer.py`):**
- `ContentSanitizer.sanitize()` (`:81-103`) recursively walks dict/list/str and applies redaction patterns, returning `(clean_value, fired_pattern_names)`.
- `RuleEvaluator.evaluate()` (`:168-196`) implements most-restrictive-wins: per-value `_evaluate_value` (`:198-220`) with **blacklist priority** (a DENY match short-circuits the rule loop, `:209-211`). Mode `deny_only` (default, `:153`) returns ALLOW for unmatched values; mode `strict` returns AMBIGUOUS for unmatched. CMD-domain obfuscation (`_looks_obfuscated`, `:126-127` over `_OBFUSCATION_PATTERNS`, `:109-123`) downgrades to AMBIGUOUS.
- `ToolCallBoundaryEnforcer.check_call()` (`:257-351`) is the hot path: **(1)** sanitize input (`:272`), **(2)** project into domains via `_build_attributes` (`:273`, `:357-441`), **(3)** evaluate (`:274-276`), **(4)** DENY → audit + return `(False, "deny:...")`; AMBIGUOUS → route to `approval_handler` else deny-by-default (`:291-340`); ALLOW → `(True, None)`.
- `_build_attributes` (`:357-441`): every string is added to the CMD domain (so command-injection patterns match even inside URLs/paths), and *additionally* routed to NET (`://`, IPv4, TLD/`localhost`) and/or FILE (`/`,`~`,`./`,`/.ssh`) domains. This multi-domain routing realizes Eq. 7 most-restrictive-wins.

**Internal data flow:** `tool_input → sanitize (S_in) → _build_attributes → RuleEvaluator(base∪task) → Verdict → (deny | approval | allow)`. `sanitize_output` (`:353-355`) exposes S_out separately for callers that drive execution. **Critical ordering bug**: because S_in runs first, the `secret_*` CMD deny rules see already-redacted text and cannot fire — see *Notable Findings #2*.

### 2. PlanGuard — planning-consistency verification (`planguard/`)

**Isolated planner (`isolated_planner.py`):** `IsolatedPlanner.derive_reference_plan(instruction)` (`:152-205`) produces a `ReferencePlan` (frozen set of `Action`, `:99-125`) using **only** `(instruction, catalog)` — architecturally isolated from tool outputs (`:131-139`). LLM backend is pluggable (`llm_planner`, `:176-196`); deterministic fallback `_deterministic_plan` (`:207-224`) matches tool `verbs` via word-boundary regex (`_verb_match`, `:226-231`) and extracts params via per-tool `param_extractors` regexes (`:233-241`). `Action` is hashable (sorted `(key,value)` tuple, `:84-93`) so `a ∈ S_ref` set-membership works.

**Intent verifier (`intent_verifier.py`):** `IntentVerifier.verify_with_reasoning()` (`:86-167`) is paper Algorithm 1:
- Stage I Case 1: exact `candidate ∈ reference_plan.actions` → pass (`:100-102`).
- Stage I Case 2: `tool_name ∉ allowed_tools` → block as Type-I unauthorized tool (`:105-115`).
- Stage I Case 3 → Stage II: pluggable `intent_llm` (`:118-148`) else deterministic `_deterministic_intent_check` (`:169-198`), which approves only *formatting* variance (`_close_param_match` + `_normalize_str` strips whitespace/`_`/`-`, `:226-247`) and blocks if reasoning matches `_MALICIOUS_REASONING_MARKERS` (exfil/attacker/ignore-prior/override/credentials/bypass, `:210-217`).

### 3. AgentArmor — program analysis over traces (`agentarmor/`)

**Graph IR (`graph_constructor.py`):** `GraphConstructor.build_pdg(trace_events)` (`:105-246`) consumes `TraceEvent`s (`:65-76`) and builds three networkx DiGraphs (`GraphIR`, `:79-92`): **CFG** (temporal control edges + DECOMPOSE edges from a Thought node to its ToolName/ToolParam children, `:153-179`), **DFG** (data edges ToolName/ToolParam→Tool, Tool→Observation, and observation→later-param taint links via `_references` substring heuristic, `:181-218,281-292`), and **PDG** = union with composite `kind` labels (`:223-235`). Node IDs are deterministic `n{step:03d}_{kind}_{disc}` (`:248-274`). Emits `agentarmor.graph.built` telemetry (`:237-244`).

**Property registry (`property_registry.py`):** Three enums form lattices: `Confidentiality` (Bell-LaPadula, PUBLIC<INTERNAL<CONFIDENTIAL<SECRET, `:53-65`), `Integrity` (Biba, HIGH>MEDIUM>LOW, `:67-78`), `TrustLevel` (TRUSTED<UNTRUSTED<TAINTED, `:40-51`). Lattice ops: `conf_join` (LUB, `:96-98`), `int_meet` (GLB, `:101-103`), `trust_join` (`:106-108`). `default_tool_scanner` (`:167-194`) maps tool-name/description fragments to a `Capability` (EXEC>NETWORK>WRITE>READ priority). `default_data_scanner` (`:197-226`) defaults `external`→UNTRUSTED/PUBLIC/LOW, `user`→TRUSTED/INTERNAL/MEDIUM, `agent`→TRUSTED/PUBLIC/HIGH. `PropertyRegistry.annotate(pdg)` (`:252-287`) mutates the PDG in place, attaching capability+confidentiality+integrity+trust to nodes.

**Type system (`type_system.py`):** `TypeSystem.check_detailed()` (`:86-102`) runs assign (`:107-116`) → infer → check. `_infer_types` (`:121-166`) propagates along DATA edges only, in topological order (cycle fallback by `step`, `:143-147`), applying `trust_join`/`conf_join`/`int_meet` from predecessors. `_check` (`:171-245`) emits `TypeViolation`s (`:55-65`) for: `untrusted_to_exec` (non-TRUSTED → EXEC tool, `:189-198`), `confidential_to_network` (SECRET/CONFIDENTIAL → NETWORK tool, `:200-211`), `integrity_downgrade` (LOW input into a HIGH-declared tool, `:213-226`), and intra-node `literal_param_tainted` (opt-in `rule_type=="must_be_literal"`, `:231-245`).

### 4. MAGE — shadow memory + pre-action risk judge (`mage/`)

**Shadow memory (`shadow_memory.py`):** `ShadowMemory` (`:100-228`) is **append-only** with strictly-monotonic `turn_index` enforced (`:136-143`) — to keep it as auditable post-mortem evidence (`:23-26`). `distill_for_action_check()` (`:163-223`) prefers a pluggable `llm_distiller` (`:183-200`) else the offline path: score each entry's relevance (`keyword_overlap_scorer`, Jaccard over tokens, `:74-97`), multiply by exponential TTL decay (`exp(-decay·age)`, default half-life 16 turns, `:131,202-209`), weight by `0.5+0.5·risk_score`, threshold-drop, sort, top-`max_returned` (`:204-214`). `ShadowMemoryEntry` (`:43-58`) validates `turn_index≥0` and `risk_score∈[0,1]`.

**Pre-action judge (`risk_assessor.py`):** `PreActionRiskAssessor.assess(candidate_action)` (`:106-200`) prefers a pluggable `judge_callable` (paper's `J_θ`, `:122-139`) else a 4-stage deterministic path: **(1)** `_REASONING_SMELL` / `_OBFUSCATION` regexes on the action text → reject (`:144-153`, patterns `:47-67`); **(2)** cross-turn signal — any distilled entry from `external`/`observation` source with `risk_score ≥ single_signal_threshold(0.7)` → reject (`:157-168`); **(3)** cumulative dilution-weighted risk `Σ risk/(1+i) ≥ cum_threshold(0.6)` → reject (`:172-179`); **(4)** exfil sink (`_EXFIL_SINKS`, `:70-74`) coincident with any prior external/tainted observation → reject (`:182-191`).

### 5. MCPShield — formal LTS verification (`mcpshield/`)

**LTS model (`lts_model.py`):** `SecurityLabel` 4-level lattice with `label_dominates` (`:56-73`). `ToolDefinition` (`:95-112`) carries `approval_hash_hex` and a static `hash_definition` = **SHA-256** (`:106-112`; deliberately not liboqs, to keep the runtime layer dependency-light). `TrustDomain` (`:115-129`), `DataValue` (`:131-138`), `Transition` (`:140-156`), and `LtsModel` (`:158-195`) with lookup helpers `domain_of_server/tool`, `tool`.

**Verifier (`verifier.py`):** `verify_property(model, property_ltl=...)` (`:73-110`) dispatches via `PROPERTY_ALIASES` (`:61-70`; unknown name raises `ValueError`, `:84-88`) to four checkers, each returning `(ok, counterexample_path)`:
- `_check_tool_integrity` (`:116-141`): re-hash the runtime tool blob, compare to `approval_hash_hex`.
- `_check_data_confinement` (`:147-200`): reachability over `(state, current_max_label)`; policy parses `max_label=<level>` (`_max_allowed_label`, `:203-210`).
- `_check_privilege_boundedness` (`:216-246`): `requested ⊆ (declared_perms ∩ agent_caps)`; `_coerce_capset` normalizes inputs (`:249-264`).
- `_check_context_isolation` (`:270-308`): cross-domain data use requires a prior `cross_domain` transition with `authorized=True`.

---

## Public API

Package root `tex.runtime` exports nothing (`__all__ = []`, `__init__.py:39`); consumers import from the sub-package `__init__`s.

- **`tex.runtime.agentarmor`** (`agentarmor/__init__.py:44-66`): `GraphConstructor`, `GraphIR`, `TraceEvent`, `NodeKind`, `EdgeKind`, `PropertyRegistry`, `ToolRegistry`, `DataRegistry`, `ToolSpec`, `DataSpec`, `Capability`, `Confidentiality`, `Integrity`, `TrustLevel`, `conf_join`, `int_meet`, `trust_join`, `default_tool_scanner`, `default_data_scanner`, `TypeSystem`, `TypeViolation`.
- **`tex.runtime.clawguard`** (`clawguard/__init__.py:38-50`): `ToolCallBoundaryEnforcer`, `RuleEvaluator`, `ContentSanitizer`, `SanitizedCall`, `ApprovalHandler`, `BaseRuleSet`, `TaskRuleSet`, `Rule`, `RuleAction`, `RuleDomain`, `Verdict`. (Module also exports `get_default_sanitization_patterns`, `emit_rule_event` from `rule_set.py:393-402`.)
- **`tex.runtime.mage`** (`mage/__init__.py:34-41`): `PreActionRiskAssessor`, `JudgeCallable`, `ShadowMemory`, `ShadowMemoryEntry`, `RelevanceScorer`, `keyword_overlap_scorer`.
- **`tex.runtime.mcpshield`** (`mcpshield/__init__.py:41-53`): `LtsModel`, `ToolDefinition`, `Transition`, `TrustDomain`, `TrustBoundary`, `DataValue`, `SecurityLabel`, `Capability`, `label_dominates`, `verify_property`, `PROPERTY_ALIASES`.
- **`tex.runtime.planguard`** (`planguard/__init__.py:32-41`): `IsolatedPlanner`, `IntentVerifier`, `ReferencePlan`, `Action`, `ToolCatalog`, `ToolSpec`, `LLMPlannerCallable`, `IntentLLMCallable`.

---

## Wiring

### In (who imports the runtime engines)

Verified by `grep -rn "tex.runtime" src/tex` (excluding the package itself). The **only** importers are the five matching specialists:

- `src/tex/specialists/agentarmor_specialist.py:63-64` → `property_registry.TrustLevel`, `type_system.{TypeSystem,TypeViolation}`.
- `src/tex/specialists/clawguard_specialist.py:58-64` → `boundary_enforcer.ToolCallBoundaryEnforcer`, `rule_set.{BaseRuleSet,TaskRuleSet,...}`.
- `src/tex/specialists/mage_specialist.py:65` → `shadow_memory.{ShadowMemory,ShadowMemoryEntry}`.
- `src/tex/specialists/mcpshield_specialist.py:70-71` → `lts_model.LtsModel`, `verifier.verify_property`.
- `src/tex/specialists/planguard_specialist.py:47` → `intent_verifier.IntentVerifier`.

(Tests also import directly: `tests/runtime/test_{clawguard,planguard,mage,mcpshield,agentarmor}.py` and `tests/specialists/test_*_specialist.py`.)

### Live call path (running app → runtime engine)

Confirmed end-to-end, each hop cited:

1. **Route**: `POST /v1/guardrail` — `guardrail_evaluate` in `src/tex/api/guardrail.py:784-795` (the canonical gateway-agnostic guardrail webhook).
2. **Command**: the route drives `EvaluateActionCommand` (imported `guardrail.py:48`); `EvaluateActionCommand.execute` calls `self._pdp.evaluate(...)` at `src/tex/commands/evaluate_action.py:214`.
3. **PDP**: `PolicyDecisionPoint.evaluate` (`src/tex/engine/pdp.py:243`) calls `self._specialist_suite.evaluate(...)` at `src/tex/engine/pdp.py:289`.
4. **Suite**: `self._specialist_suite` defaults to `build_default_specialist_suite()` (`src/tex/engine/pdp.py:205`), which instantiates `ClawGuardSpecialist()`, `McpShieldSpecialist()`, `PlanGuardSpecialist()`, `MageSpecialist()`, `AgentArmorSpecialist()` (`src/tex/specialists/judges.py:366-372`).
5. **Specialist → engine**: e.g. `ClawGuardSpecialist.evaluate` calls `enforcer.check_call(...)` (`src/tex/specialists/clawguard_specialist.py:275-276`) on a `ToolCallBoundaryEnforcer` built from `BaseRuleSet`/`TaskRuleSet` (`:372-397`).
6. **Build**: the PDP is constructed in `build_runtime()` at `src/tex/main.py:877` (`pdp = PolicyDecisionPoint(...)`), which `create_app()` attaches to the live app (`src/tex/main.py:1358,1428,1586-1606`).

Runtime smoke test (PYTHONPATH=src) confirms live behavior: ClawGuard denies `rm -rf /` (`base.cmd.deny.rm_rf_root`), denies `~/.ssh/authorized_keys` writes (`base.file.deny.ssh_write`), allows `ls -la`.

**`wired_status = LIVE`** — no feature flag gates the suite; `build_default_specialist_suite()` is unconditional (the specialists are always constructed). Spine-pass classification `runtime=LIVE` is **confirmed**.

> Note on indirection: the specialists are the only callers, and they wrap the
> engines. So the engines are LIVE through a thin specialist adapter — there is
> no path that calls the runtime engines *without* going through a specialist.

### Out (what runtime depends on)

- **Internal `tex` deps**: only `tex.observability.telemetry.{emit_event,get_logger}` — imported by every substantive file (e.g. `graph_constructor.py:40`, `boundary_enforcer.py:41`, `rule_set.py:37`, `risk_assessor.py:37`, `shadow_memory.py:38`, `verifier.py:49`, `intent_verifier.py:30`, `isolated_planner.py:38`). The type_system also imports from sibling `property_registry` (`type_system.py:42-50`). **No cross-engine coupling** — each engine keeps its own lattice copy by design (`lts_model.py:50-53`, `risk_assessor.py:43-46`).
- **External libraries**: `networkx` (AgentArmor graph IR only: `graph_constructor.py:37`, `property_registry.py:32`, `type_system.py:39`); `pydantic` (`BaseModel`/`ConfigDict`/`Field` across clawguard, planguard, agentarmor); stdlib `re`, `hashlib` (MCPShield SHA-256), `math` (MAGE decay), `datetime`, `enum`, `dataclasses`, `logging`. **No native crypto/TEE/ZK libraries** — MCPShield deliberately uses stdlib `hashlib.sha256` (`lts_model.py:106-112`).

---

## Implementation Reality

**Verdict: REAL.** All five engines contain substantive, executable algorithmic
logic. There are **zero** `NotImplementedError`, zero `pass`-only stubs, and zero
hollow placeholder returns in scope (verified by reading every file).

What real logic looks like, by engine:
- **ClawGuard**: 11 compiled regex deny rules + 5 redaction patterns, an actual most-restrictive-wins evaluator with blacklist-priority short-circuit (`boundary_enforcer.py:198-220`), three-valued verdicts with a real approval-handler branch. Runtime-verified to deny `rm -rf /`, `.ssh` writes, and allow benign commands.
- **PlanGuard**: real set-membership Stage-I check + a working deterministic Stage-II `_close_param_match`/normalize logic (`intent_verifier.py:226-247`) and reasoning-smell regexes.
- **AgentArmor**: real networkx CFG/DFG/PDG construction with cross-turn taint linking and a topological-order lattice information-flow propagation + 4 violation classes.
- **MAGE**: real append-only monotonic memory, TTL exponential decay, Jaccard relevance, 4-stage cumulative risk aggregation.
- **MCPShield**: real SHA-256 integrity check, label-monitor reachability, capability-envelope subset check, cross-domain authorization tracking, all producing counterexample paths.

**Pluggable LLM vs. offline fallback (by design, the offline path runs by default):**
- PlanGuard planner: `llm_planner` else deterministic verb/regex (`isolated_planner.py:176-205`).
- PlanGuard intent: `intent_llm` else deterministic (`intent_verifier.py:118-167`).
- MAGE judge: `judge_callable` else 4-stage offline (`risk_assessor.py:122-200`).
- MAGE distill: `llm_distiller` else keyword/TTL offline (`shadow_memory.py:183-223`).
- AgentArmor scanners: `default_tool_scanner`/`default_data_scanner` lexical heuristics in place of the paper's LLM scanner (`property_registry.py:167-226`).
In every case the LLM path is wrapped in `try/except` with a logged fall-through to the deterministic path — graceful degradation, not a stub.

**Stale scaffolding markers (TODOs above already-implemented code) — overstatement risk, not missing logic:**
- `boundary_enforcer.py:263-271`: `check_call` has `TODO(P0): apply base rules first ...` immediately followed by a docstring line *"Status: implemented per arxiv 2604.11790 §III-A pipeline"* — and the body is implemented.
- `rule_set.py:91-103` (`BaseRuleSet.default`) and `:118-130` (`induce_from_objective`): `TODO(P0)` lists followed by `Status: implemented`.
- `intent_verifier.py:73-78` and `isolated_planner.py:159-165`: `TODO(P1)` followed by `Status: implemented`.
These TODOs are **misleading leftovers**; the code under them is real. Flagged so an auditor does not mistake the markers for missing implementation.

---

## Technology / SOTA

- **Information-flow control**: dual lattice model — Bell-LaPadula confidentiality (join/LUB) + Biba integrity (meet/GLB) + a trust lattice; static taint propagation over a program-dependence graph (AgentArmor `type_system.py`).
- **Program analysis on agent traces**: CFG/DFG/PDG intermediate representation built with `networkx`, with node decomposition (Thought→ToolName+ToolParam) and cross-turn observation→param taint edges (AgentArmor `graph_constructor.py`).
- **Formal methods**: Labeled Transition System with trust-boundary annotations; four decidable security properties checked by finite reachability / monitor automata; counterexample-path extraction (MCPShield `verifier.py`).
- **Cryptographic integrity**: SHA-256 (FIPS 180-4) tool-definition hashing at approval time vs. invocation time (MCPShield `lts_model.py:106-112`) — a real hash-equality integrity gate, deliberately stdlib-only.
- **Deny-by-default policy engine**: three-domain (cmd/file/net) blacklist/whitelist with most-restrictive-wins aggregation, secret redaction, and obfuscation detection (ClawGuard).
- **Memory-as-guardrail**: append-only shadow memory with exponential TTL decay + Jaccard keyword relevance + dilution-weighted cumulative risk — a systems-security "shadow stack" analogy applied to long-horizon LLM safety (MAGE).
- **Planning-consistency IPI defense**: an isolated planner that never sees tool output, producing a contamination-free reference action set for downstream consistency checking (PlanGuard).
- **Design patterns**: strategy/dependency-injection for every LLM hook with deterministic fallback; frozen pydantic value objects; pure functions for lattice ops; structured telemetry via `emit_event` on every decision.

---

## Persistence

**Entirely in-memory; no database, no disk, no durable state.** None of the five
engines import `tex.db`, `tex.stores`, any ORM, or open files.

- ClawGuard rule sets / sanitizer patterns are immutable in-process tuples (`rule_set.py:178,315`); the enforcer holds no mutable state beyond pre-compiled regexes (`boundary_enforcer.py:163-166`).
- AgentArmor builds graphs per call and returns them; registries (`ToolRegistry`/`DataRegistry`) are in-memory dicts (`property_registry.py:135-164`) with **no persistence** — they live only as long as a `PropertyRegistry` instance.
- MAGE `ShadowMemory` holds a `list[ShadowMemoryEntry]` in `self._entries` (`shadow_memory.py:128`); append-only and **lost on process restart**. The "auditable evidence" framing (`:23-26`) is an in-RAM invariant only — it is **not** sealed to any durable ledger from within this unit.
- MCPShield `LtsModel` is a frozen dataclass passed in by the caller; the verifier is stateless (`verifier.py`).
- PlanGuard `ReferencePlan`/`ToolCatalog` are frozen pydantic objects passed per call; planners/verifiers are stateless.

Any durability (e.g. sealing a ClawGuard denial into the SealedFactLedger) would
have to happen in the *specialist/PDP* layer, not here. This unit only emits
telemetry events; it does not write evidence records.

---

## Notable Findings

1. **Task-brief mismatch (factual correction).** The brief describes this unit as
   "Runtime-level services, dormancy_controller, ignition_registry,
   presence_tracker." **None of those files/concepts exist** anywhere under
   `src/tex/runtime/` (or, by grep, anywhere in `src/tex`). The actual `tex.runtime`
   is the **Runtime Defense Layer** (5 agent-security engines). The dossier
   documents what the code actually is.

2. **Logic defect — sanitization masks the secret deny rules (verified at
   runtime).** In `ToolCallBoundaryEnforcer.check_call`, `S_in` sanitization runs
   *before* rule evaluation (`boundary_enforcer.py:272` then `:274`). The default
   sanitizer redacts AWS/OpenAI/GitHub/Bearer/SSH secrets to placeholders
   (`rule_set.py:315-347`), so by the time `RuleEvaluator` runs, the
   `base.cmd.deny.secret_{aws,openai,github}` rules (`rule_set.py:268-291`) can
   never match the original token. Runtime-confirmed: `check_call(tool_name='post',
   tool_input={'body':'AKIAIOSFODNN7EXAMPLE'})` returns **`(True, None)` — ALLOWED**
   (redactions fired: `['aws_access_key']`), whereas calling `RuleEvaluator`
   directly on the un-redacted value returns `Verdict.DENY base.cmd.deny.secret_aws`.
   Net effect: the secret-exfiltration **deny** rules are effectively dead code on
   the default path — secrets are scrubbed (good for exfil prevention) but the
   call is **not blocked or flagged as a denial** (the paper's intent is that an
   outbound secret should *block*, not silently sanitize). This is a real
   contradiction between the documented six-rule deny contract (`rule_set.py:91-102`,
   `:267-291`) and observed behavior.

3. **Bug — `ContentSanitizer(patterns=())` does not disable sanitization.**
   `__init__` uses `self._patterns = patterns or get_default_sanitization_patterns()`
   (`boundary_enforcer.py:79`). An explicitly-passed empty tuple is falsy, so it
   silently falls back to the *default* patterns. A caller trying to construct a
   no-op sanitizer gets full default redaction instead. Verified at runtime
   (`sanitize({'body':'AKIA...'})` with `patterns=()` still redacts).

4. **Docstring references a method that does not exist.**
   `TaskRuleSet.induce_from_objective`'s docstring says *"The LLM-induction path
   lives in `induce_from_objective_llm`"* (`rule_set.py:128`), but **no
   `induce_from_objective_llm` is defined** in `rule_set.py` (grep-confirmed: only
   `induce_from_objective` and `confirm` exist). Overstatement; the LLM path is not
   present in this file.

5. **`base.net.deny.non_allowlisted_default` is an intentional no-op sentinel.**
   Its pattern is `r"(?!.*)$"` which matches nothing (`rule_set.py:254-266`,
   `severity="warn"`). This is documented as a deployment hook, not active
   enforcement — so the advertised "Rule 5: outbound to non-allowlisted domains"
   does **nothing** by default. Correctly self-described, but worth flagging that
   the egress-allowlist is *off by default*.

6. **Cited arxiv IDs are likely fabricated / future-dated.** The docstrings cite
   arxiv numbers like `2604.11790` (ClawGuard), `2604.10134` (PlanGuard),
   `2605.03228` (MAGE), `2604.05969` (MCPShield) with 2026 dates and named authors
   (e.g. "Cisco co-author, May 4 2026"). The numeric prefixes (`2604`, `2605`) do
   not correspond to real arxiv year-month codes (which would be `26xx` only from
   2026). These are **claims, unverified** — treat the performance figures (e.g.
   "ASR 72.8% → 0%", "95.75% TPR") as **unverified marketing claims copied into
   docstrings**, not measured in this repo. The *algorithms* are real; the
   *benchmark numbers* are not reproduced here.

7. **`MCPShield __init__` docstring cites a different arxiv number than its
   module.** `mcpshield/__init__.py:3` says `arxiv 2604.05969` while the package
   summary in `runtime/__init__.py:24` describes MCPShield without an arxiv id and
   `lts_model.py:5` also says `2604.05969`. Minor inconsistency; both point at the
   same (unverified) reference.

8. **Defense-in-depth duplication is intentional, not dead code.** Each engine
   keeps its *own* copy of attack-signal regexes and security lattices rather than
   sharing a registry (`risk_assessor.py:43-46` and `lts_model.py:50-53` both state
   this explicitly: "no single registry change can disable all checks"). So the
   apparent duplication between MAGE/PlanGuard/ClawGuard reasoning-smell patterns is
   a deliberate design choice for fault isolation.

9. **No durable evidence sealing from within the unit.** Despite MAGE's docstring
   framing shadow memory as "auditable evidence for post-mortem investigation"
   (`shadow_memory.py:23-26`), the state is purely in-RAM and lost on restart;
   nothing here writes to the SealedFactLedger or any store. Evidence sealing, if
   any, is the responsibility of the PDP/specialist layer above.

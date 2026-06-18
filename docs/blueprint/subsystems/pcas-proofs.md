# Subsystem Dossier: PCAS Proof-Carrying Structures (`pcas`, `proofs`)

Scope: `/Users/matthewnardizzi/dev/tex/src/tex/pcas/**` and `/Users/matthewnardizzi/dev/tex/src/tex/proofs/**`.
Branch: `feat/proof-carrying-gate`. All evidence cited as `file:line`. Verified by reading code, tracing imports/call-sites with grep, and executing the runtime under `PYTHONPATH=/Users/matthewnardizzi/dev/tex/src`.

---

## Overview

The `pcas` package is a **complete, hand-rolled, pure-Python Datalog engine** — lexer → recursive-descent parser → typed AST → stratifier → semi-naive bottom-up evaluator with stratified negation → reference monitor — used as a **policy compiler / reference monitor for agentic actions**. It compiles a Datalog-derived policy language once, then per-action materializes an EDB (extensional database) from a dependency graph, injects the candidate action, runs the fixpoint to closure, and reads `@authorize`/`@deny` head facts to emit a three-state verdict `{PERMIT, ABSTAIN, FORBID}` (deny-wins, fail-closed). The engine is **REAL** — it parses, stratifies (rejecting recursion-through-negation), evaluates recursion and negation correctly, and runs sub-millisecond on small graphs (measured ~0.2–0.5 ms in a live run).

The `proofs` package is **NOT Python**: the `__init__.py` is a 37-line pure docstring/placeholder (`__layer_kind__ = 'empty_placeholder'`, `__layer__ = None`) and the only real artifact is a single Lean 4 file, `non_interference.lean`, that is **never built by CI, never imported, and unreferenced by any running code**. It is a publication/review artifact.

**Relationship to the Proof-Carrying Action Gate:** PCAS is one of the **specialist judges** that feeds the PDP (Policy Decision Point). It is wired LIVE into the running app via `PcasSpecialist` → `default_specialist_judges()` → `SpecialistSuite` → `PolicyDecisionPoint`. **PCAS itself does NOT seal anything** — it has zero references to `enforcement_seal` / `SealedFact` / the proof-carrying gate machinery (verified: `grep` for those symbols inside `pcas/` returns empty). The "proof-carrying" sealing is downstream in the PDP/provenance layer; PCAS contributes the deterministic Datalog verdict that the gate can then seal.

---

## File Inventory

| File | Lines | Role |
|------|------:|------|
| `src/tex/pcas/__init__.py` | 152 | Package façade: re-exports AST / lexer / parser / stratify / runtime / adapter / monitor symbols; `__layer__=4` (execution governance). Docstring-heavy (arxiv 2602.16708 framing). |
| `src/tex/pcas/language/__init__.py` | 1 | Empty package marker. |
| `src/tex/pcas/language/ast.py` | 291 | Typed Pydantic-v2 AST: `Variable`, `Constant`, `Atom`, `NegatedAtom`, `HelperCall`, `Rule`, `Program`. All `frozen=True, extra='forbid'`. Floats forbidden by canonical-JSON contract. |
| `src/tex/pcas/language/lexer.py` | 349 | Hand-rolled finite-state tokenizer with 1-indexed line/col, `%` line + `/* */` block comments, string escapes, signed-int heuristic, `@authorize`/`@deny` annotations. Raises structured `LexerError`. |
| `src/tex/pcas/language/parser.py` | 191 | Recursive-descent parser → `Program`. `parse_program()` one-shot convenience. Parse errors fatal (fail-closed). |
| `src/tex/pcas/language/stratify.py` | 309 | Helper disambiguation, Apt-Blair-Walker safety/range-restriction check, predicate dependency graph, **iterative Tarjan SCC**, rejection of recursion-through-negation, stratum ordering. |
| `src/tex/pcas/runtime/__init__.py` | 1 | Empty package marker. |
| `src/tex/pcas/runtime/relation.py` | 186 | `Fact` (Pydantic) + `Relation` (plain class): immutable `frozenset`-backed typed multiset with lazy column-index cache for joins. |
| `src/tex/pcas/runtime/evaluator.py` | 447 | Semi-naive bottom-up evaluator with stratified negation; per-rule join/helper/negation pipeline; `MAX_ITERATIONS=1024` safety cap; module-level `_join_atom`/`_filter_negated`/`_ground_atom`. |
| `src/tex/pcas/runtime/helpers.py` | 180 | Helper registry + 7 built-ins (`equals`, `not_equals`, `greater`, `less`, `has_substring`, `starts_with`, `json_extract`). Predicate vs function helper kinds. |
| `src/tex/pcas/graph/__init__.py` | 1 | Empty package marker. |
| `src/tex/pcas/graph/adapter.py` | 310 | `DependencyGraphView` (8 Pydantic node/edge views) + `DependencyGraphAdapter.to_edb()` projection; `from_ifc_provenance()` duck-typed bridge to the IFC provenance graph. |
| `src/tex/pcas/monitor.py` | 248 | `PcasMonitor` reference monitor: parse+stratify once at construction; `authorize(action, graph)` → `PolicyDecision`. Fail-closed on any load/eval error. |
| `src/tex/proofs/__init__.py` | 37 | **Placeholder only.** Docstring describing the Lean file; `__layer__=None`, `__layer_kind__='empty_placeholder'`. No code. |
| `src/tex/proofs/non_interference.lean` | 238 | Lean 4 / Mathlib4 proof of FIDES capability-lattice monotonicity → abstract non-interference. **Not a `.py` file; not built/imported by anything.** |

Totals: 13 `.py` files (2 packages have substance: `pcas` core; `proofs` is inert) + 1 `.lean` file. `pcas` Python LOC ≈ 2666; `proofs` Python LOC = 37.

---

## Internal Architecture

### Language front-end

**AST (`language/ast.py`)** — everything is a frozen Pydantic v2 model.
- `Variable` (ast.py:57) validates upper-case-or-`_` start; `is_anonymous` (ast.py:81) flags `_`-prefixed names that cannot bind across atoms.
- `Constant` (ast.py:90) accepts only `str | int | bool`; `_no_floats` validator (ast.py:100) rejects floats ("forbidden by canonical-JSON contract"). `Term = Variable | Constant` (ast.py:122).
- `Atom` (ast.py:130) requires lowercase predicate (ast.py:146); `NegatedAtom` (ast.py:172) wraps an `Atom`; `HelperCall` (ast.py:186) is produced post-parse by the stratifier. `BodyElement = Atom | NegatedAtom | HelperCall` (ast.py:207).
- `RuleAnnotation = Literal["authorize","deny","rule"]` (ast.py:215). `Rule` (ast.py:218) exposes `is_fact` (empty body), and partitions body into `body_positive_atoms`/`body_negated_atoms`/`body_helpers` (ast.py:243-252).
- `Program` (ast.py:255) exposes `head_predicates`, `authorize_predicates`, `deny_predicates` (ast.py:263-277) — the monitor reads the latter two.

**Lexer (`language/lexer.py`)** — `Lexer.tokens()` (lexer.py:111) is a single linear scan producing a `tuple[Token,...]` ending in `EOF`. Handles whitespace, `%` line comments (lexer.py:134), non-nesting `/* */` block comments with unterminated detection (lexer.py:138-158), punctuation, `:-` (lexer.py:189), annotations `@authorize`/`@deny` (lexer.py:208-228), double-quoted strings with `\" \\ \n \t \r` escapes and newline/unterminated guards (lexer.py:231-295), and a **context-sensitive signed-integer heuristic**: a leading `-` is only part of an integer if the previous token is `LPAREN` or `COMMA` (lexer.py:298-303). Idempotent (no consumed state between calls, lexer.py:99).

**Parser (`language/parser.py`)** — `Parser.parse()` (parser.py:101) loops `_parse_rule` (parser.py:109): optional annotation → head atom → optional `:-` body → mandatory `.`. `_parse_body_element` (parser.py:138) handles `not atom`; positive atoms vs helper calls are left ambiguous here and disambiguated later by the stratifier (parser.py:143-145). `_parse_term` (parser.py:164) only accepts `IDENT` (→ `Variable`), `STRING`/`INTEGER`/`BOOL` (→ `Constant`); bare zero-arg atoms as terms are rejected. `parse_program(source, name)` (parser.py:185) = lex + parse.

### Stratifier (`language/stratify.py`) — three jobs, in order

1. **Helper disambiguation** (`_disambiguate_body`, stratify.py:57): any positive `Atom` whose predicate ∈ helper registry is rewritten to `HelperCall`; a *negated* helper is rejected (stratify.py:72-76).
2. **Safety / range-restriction** (`_check_safety`, stratify.py:101): every head variable, every negated-atom variable, and every helper-call variable must occur in a positive body atom (Apt-Blair-Walker). Anonymous head vars rejected (stratify.py:114). This is the precondition that makes negation-by-failure and finite evaluation sound.
3. **Stratification** (`stratify`, stratify.py:267): builds `_PredicateGraph` (stratify.py:172) with positive and negative edges, runs an **iterative (non-recursive, explicit-stack) Tarjan SCC** (`_tarjan_sccs`, stratify.py:192), then `_check_no_negative_cycles` (stratify.py:245) raises `StratificationError` if any SCC (including a self-loop) contains a negative edge. Tarjan returns SCCs in reverse-topological (leaves-first) order, which is exactly the order the evaluator needs so a stratum's dependencies are fully materialized first; each SCC becomes a `Stratum` (stratify.py:297).

**Verified self-edge / negative-cycle detection works** (test `test_stratify_rejects_recursion_through_negation` passes; live run shows correct stratum ordering 0→8 in the smoke test).

### Runtime relations (`runtime/relation.py`)

`Relation` (relation.py:53) is a plain (non-Pydantic) class backed by a `frozenset[tuple[FactValue,...]]` for cheap set-difference (semi-naive delta) and `__eq__`/`__hash__` over (name, arity, facts). Constructor validates lowercase name, non-negative arity, exact arity per fact, and `str|int|bool` value type (relation.py:72-92). Mutators are **immutable**: `with_facts` (relation.py:143) returns a new union relation; `replace` (relation.py:148) returns a fresh set. `lookup(columns, values)` (relation.py:154) uses a **lazily-built, cached per-column-set hash index** (`_build_index`, relation.py:176) — the join accelerator. `Fact` (relation.py:32) is a thin Pydantic tuple wrapper used only at API boundaries.

### Evaluator (`runtime/evaluator.py`) — the engine

`Evaluator.__init__` (evaluator.py:89) calls `stratify(program, helper_names)` once, then builds an arity table from all atom occurrences (evaluator.py:103-115), raising `EvaluationError` on inconsistent arity. `evaluate(edb)` (evaluator.py:131) is **pure / stateless per call** (safe to reuse across requests):
1. Seeds `facts` from the EDB with arity validation (evaluator.py:139-145).
2. Ensures every program predicate has an (empty if needed) relation so lookups never `KeyError` (evaluator.py:150-152).
3. Seeds unconditional fact-rules (empty body) up front; non-ground fact head → `EvaluationError` (evaluator.py:156-163).
4. Runs each stratum in order via `_evaluate_stratum`.

`_evaluate_stratum` (evaluator.py:173) is a **semi-naive fixpoint**: each round derives all rule heads, de-dups against current facts, commits only genuinely new facts, and terminates when no predicate gains a fact. Hard cap `MAX_ITERATIONS=1024` (evaluator.py:74, raised at 181) bounds pathological policies. Emits `pcas.evaluator.stratum_complete` telemetry (evaluator.py:211).

`_derive(rule, facts)` (evaluator.py:220) is the per-rule pipeline:
1. Join positive atoms in declaration order via `_join_atom` (evaluator.py:364) — for each candidate substitution, it constrains the index by already-bound columns, fetches candidate facts, then re-checks repeated-variable / constant consistency in-atom (evaluator.py:395-416).
2. `_apply_helpers` (evaluator.py:253): predicate helpers act as guards (drop row unless `fn(*args)` truthy; exceptions → False, sandboxed at evaluator.py:284); function helpers bind the trailing argument to `fn(inputs)` (variable → bind; constant → equality check; anonymous → pass) (evaluator.py:288-319). Arity mismatch → `EvaluationError` (evaluator.py:269).
3. `_filter_negated` (evaluator.py:420): each negated atom is ground (safety guaranteed) and the row is dropped iff the ground tuple is present; an absent relation makes `not(X)` trivially true (evaluator.py:436-438).
4. `_ground_atom` (evaluator.py:346) substitutes the head and emits the fact tuple.

### Graph adapter (`graph/adapter.py`)

`DependencyGraphView` (adapter.py:130) is a single frozen Pydantic container of 8 typed node/edge tuples (actions, messages, tool_calls, data, denied, edges, roles, approvals). `DependencyGraphAdapter.to_edb()` (adapter.py:205) projects it into a `dict[str, Relation]` using fixed `EDB_ARITIES` (adapter.py:194) and emits `pcas.graph.edb_built` telemetry (adapter.py:221). Per the docstring contract (adapter.py:33-37), `derived_from/2` is deliberately **not** in the EDB — it is computed inside policies via the recursive transitive-closure idiom. `from_ifc_provenance(prov)` (adapter.py:229) is a **defensive duck-typed bridge**: it `getattr`-introspects a provenance graph's `nodes`/`edges` (Call→action, Data→data, DeniedAction→denied) and returns an empty view if the structure is absent. The hash-not-content design keeps every value inside `str|int|bool`.

### Monitor (`monitor.py`) — the front door

`PcasMonitor.__init__` (monitor.py:97) parses + stratifies the policy **once**; on any `LexerError|ParseError|StratificationError|EvaluationError` it stores `_load_error`, emits `pcas.monitor.load_failed`, and leaves `_evaluator=None` (monitor.py:103-112). `authorize(action, graph)` (monitor.py:128):
1. If load failed → immediate `FORBID` with `policy_load_error` (monitor.py:134-144) — **fail-closed by construction**.
2. Builds the EDB from the graph (monitor.py:146), injects the candidate as a synthetic `pending_action/4` relation (monitor.py:150-161), and **also mirrors it into `action/4`** so existing rules over `action` see it (monitor.py:164-172).
3. Runs `evaluate`; `EvaluationError` → `FORBID` with `evaluation_error` (monitor.py:174-186).
4. Scans `program.authorize_predicates` / `deny_predicates` for closure facts whose first column == `action_id` (monitor.py:195-211).
5. Verdict: **deny present → FORBID; else authorize present → PERMIT; else ABSTAIN** (monitor.py:213-219) — deny-wins, fail-closed. Emits `pcas.monitor.decided` (monitor.py:223) and returns a frozen `PolicyDecision` (monitor.py:231) with reasons, matched facts, and `elapsed_ms`.

**Data flow (one adjudication):** `CandidateAction` + `DependencyGraphView` → `adapter.to_edb` → inject `pending_action`+`action` → `Evaluator.evaluate` (stratified semi-naive fixpoint over `Relation` indexes, helpers, negation) → scan `@authorize`/`@deny` heads → `PolicyDecision{verdict, reasons, facts, elapsed_ms}`.

---

## Public API

Re-exported from `tex.pcas` (`__init__.py:84-152`):
- **AST**: `Atom`, `Constant`, `HelperCall`, `NegatedAtom`, `Program`, `Rule`, `RuleAnnotation`, `Term`, `Variable`.
- **Front-end**: `Lexer`, `LexerError`, `Token`, `TokenKind`, `Parser`, `ParseError`, `parse_program`, `StratificationError`, `Stratum`, `stratify`.
- **Runtime**: `EvaluationError`, `Evaluator`, `HELPER_REGISTRY`, `HelperFunction`, `register_helper`, `Fact`, `Relation`.
- **Adapter**: `DependencyGraphAdapter` (and from the module directly: `DependencyGraphView`, the 8 `Graph*View`/edge models).
- **Monitor**: `AuthorizationVerdict`, `PcasMonitor`, `PolicyDecision` (and `CandidateAction` from the module).

The **only symbols actually consumed externally** are `DependencyGraphAdapter`, `DependencyGraphView`, `AuthorizationVerdict`, `CandidateAction`, `PcasMonitor`, `PolicyDecision` — all imported by `specialists/pcas_specialist.py:48-54`.

`tex.proofs` public surface: only `__layer__` / `__layer_kind__` module attributes (proofs/__init__.py:36-37). No callable API.

---

## Wiring

### Wiring In (who imports PCAS)

Exactly one external consumer (verified by `grep -rn "tex\.pcas" --include=*.py` excluding `pcas/` itself): **`src/tex/specialists/pcas_specialist.py`** imports `DependencyGraphAdapter`, `DependencyGraphView` (pcas_specialist.py:48) and `AuthorizationVerdict`, `CandidateAction`, `PcasMonitor`, `PolicyDecision` (pcas_specialist.py:49-54).

`PcasSpecialist` (pcas_specialist.py:107) satisfies the `SpecialistJudge` Protocol (base.py:227-247): same `name: str` and keyword-only `evaluate(*, request, retrieval_context) -> SpecialistResult` signature. It resolves the policy at construction (explicit source > `policy_path` > `TEX_PCAS_POLICY_PATH` env file > `_DEFAULT_POLICY` toxic-flow program at pcas_specialist.py:58-104) and holds one `PcasMonitor` (pcas_specialist.py:135). Per request it projects the action (pcas_specialist.py:156) and graph (pcas_specialist.py:181, preferring an IFC provenance graph on `request.metadata['ifc_provenance']`, else an empty view), calls `PcasMonitor.authorize`, and maps the verdict to `risk_score` (FORBID=1.0 / ABSTAIN=0.5 / PERMIT=0.0, pcas_specialist.py:208-227).

### Live call path (from the running app)

**Status: LIVE.** Traced concrete path:

1. `src/tex/main.py:876` — `pdp = PolicyDecisionPoint(...)` inside `build_runtime()` (def at main.py:519). `build_runtime` is invoked by `create_app()` (main.py:1358 eager / main.py:1388 deferred-background).
2. `src/tex/engine/pdp.py:205` — `PolicyDecisionPoint.__init__` sets `self._specialist_suite = specialist_suite or build_default_specialist_suite()`.
3. `src/tex/specialists/judges.py:410` — `build_default_specialist_suite()` → `SpecialistSuite(judges=default_specialist_judges())`.
4. `src/tex/specialists/judges.py:395` — `default_specialist_judges()` instantiates `PcasSpecialist()` in the default judge tuple.
5. `src/tex/engine/pdp.py:~289` — `PolicyDecisionPoint.evaluate(request)` calls `self._specialist_suite.evaluate(request=..., retrieval_context=...)` (pdp.py line within `evaluate`, confirmed: `specialist_bundle = self._specialist_suite.evaluate(...)`).
6. `src/tex/specialists/judges.py:335` — `SpecialistSuite.evaluate` iterates `judge.evaluate(request=..., retrieval_context=...)` over every judge, including `PcasSpecialist`.
7. `src/tex/specialists/pcas_specialist.py:151` — `PcasSpecialist.evaluate` → `PcasMonitor.authorize` (monitor.py:128) → `Evaluator.evaluate` (evaluator.py:131).

**Runtime-confirmed:** a live execution under `PYTHONPATH=.../src` produced `FORBID` on a toxic-flow action (`reasons=('deny:toxic_flow',)`, 0.522 ms) and `PERMIT` on a benign action (`reasons=('authorize:ok',)`), with all 9 strata firing in correct order. The `tests/frontier_thread_12/test_pcas.py` suite (32 tests, incl. PERMIT/ABSTAIN/FORBID end-to-end and a sub-1ms latency test) **passes 32/32 in 0.13s**.

**`tex.proofs` status: ORPHAN.** No Python file imports `tex.proofs` (verified: `grep -rn "tex\.proofs"` finds only its own `__init__.py`). The `.lean` file is referenced by nothing (`grep -rn non_interference` hits only the proofs docstring). CI does not build Lean (claim in proofs/__init__.py:29-30, and consistent with no build wiring).

### Wiring Out (PCAS dependencies)

- **Internal tex:** `tex.observability.telemetry.emit_event` (monitor.py:42, evaluator.py:54, adapter.py:51 — real function, telemetry.py:255). Nothing else from tex is imported by `pcas` core. The IFC provenance graph (`tex.governance.private_data_exec.ifc.provenance.ProvenanceGraph`) is referenced **only by docstring and duck-typed `getattr`** in `from_ifc_provenance` (adapter.py:229) — there is **no hard import**, so PCAS does not depend on IFC at module-load time.
- **External libs:** `pydantic` v2 (`BaseModel`, `ConfigDict`, `Field`, validators) throughout; Python stdlib only otherwise (`time`, `enum`, `dataclasses`, `json` inside `_json_extract`, `os`/`pathlib` in the specialist). **No third-party Datalog/parser/crypto binding.** 100% stdlib runtime as the docstring claims (verified — no native extension import anywhere in scope).

---

## Implementation Reality

**REAL (no stubs in the `pcas` engine).** Every stage does real work and is exercised by tests + a live run:
- Lexer/parser fully implemented with structured errors (no `pass`/`TODO`/`NotImplementedError` anywhere in `pcas/` — verified by grep: zero hits for `NotImplementedError`, `TODO`, `FIXME`, `raise NotImplemented`).
- Stratifier implements real Apt-Blair-Walker safety + iterative Tarjan SCC + negative-cycle rejection (stratify.py:192-265).
- Evaluator implements real semi-naive fixpoint with indexed joins, helpers, and stratified negation; recursion (transitive closure) demonstrated live (strata 2 `derived_from`).
- Monitor is fail-closed by construction; verified that load errors, eval errors, and the no-rule case each produce the correct conservative verdict.

**Minor reality caveats (not stubs, but worth flagging):**
- `_apply_helpers` exception handling is broad (`except Exception` → False/skip, evaluator.py:284, 301) — intentional sandboxing of helper code, but it silently swallows bugs in custom helpers.
- `from_ifc_provenance` is best-effort duck-typing (adapter.py:246-289); if a real `ProvenanceGraph`'s attribute names don't match (`kind`/`id`/`source`/`label`/etc.), nodes are silently skipped. In the live specialist path the projection is additionally wrapped in `try/except` → empty view (pcas_specialist.py:195-204), so a shape mismatch degrades to "empty graph → default policy authorizes everything non-toxic." This is safe-by-design but means IFC→PCAS coupling is loose and unverified end-to-end in this scope.

**`proofs` reality:**
- `proofs/__init__.py` is a **pure placeholder** — `__layer__ = None`, `__layer_kind__ = 'empty_placeholder'` (proofs/__init__.py:36-37). No code.
- `non_interference.lean` (238 lines) is a **real, substantive Lean 4 proof** of `CapLevel` total order, `join` commutativity/associativity/idempotence/identity/monotonicity (`join_le_join_of_le`, lean:174), and an abstract non-interference theorem `derive_chain_monotone` (lean:219) with `untrusted_propagates` (lean:230). It is mathematically self-contained and **`sorry`-free** in what it states (the docstring notes the Python-refinement bridge is intentionally *not stated* rather than `sorry`'d, lean:30-35). **BUT it is never compiled in CI and never connected to any Python code** — its load-bearing status for the running system is **zero**. It is documentation/publication material.

---

## Technology / SOTA

- **Datalog with stratified negation** — semi-positive Datalog, range-restricted (safe) rules, stratification rejecting recursion-through-negation. Classic results: Apt-Blair-Walker 1988 (stratifiability), Bancilhon-Maier-Ramakrishnan-Sagiv 1986 (semi-naive evaluation), Abiteboul-Hull-Vianu ch.13/15. These are correctly implemented (not just cited).
- **Iterative Tarjan strongly-connected-components** with an explicit work-stack (stratify.py:192) to avoid Python recursion limits — used to compute strata and detect negative cycles.
- **Semi-naive bottom-up fixpoint** with frozenset-based delta detection and a lazy per-column-set **hash-join index** (relation.py:154-183).
- **Reference-monitor pattern** with three-state `{PERMIT, ABSTAIN, FORBID}` deny-wins / fail-closed semantics aligned to Tex's PDP.
- **Pydantic v2 strict immutable models** (`frozen=True, extra='forbid'`) for the entire AST + adapter surface; canonical-JSON value discipline (no floats).
- **Lean 4 / Mathlib4 mechanized proof** of capability-lattice monotonicity → information-flow non-interference (Volpano-Smith 1996; FIDES arxiv 2505.23643 framing).
- **arxiv claims (claim, unverified against external source):** docstrings attribute the architecture to PCAS arxiv 2602.16708 (Palumbo et al., Wisconsin + Google) and claim "first production-grade implementation" + a Table-1 four-of-four superiority over the Microsoft Agent Governance Toolkit (pcas/__init__.py:11-19). The *Datalog engine itself is real and present*; the comparative-superiority and "paper-only / no released code" assertions are **marketing claims I cannot verify from this repo** and should be treated as such.

---

## Persistence

**Entirely in-memory and ephemeral.** No database, file, or durable store is written by `pcas`:
- The compiled policy lives in a single `PcasMonitor._evaluator` (monitor.py:101), built once per specialist instance.
- The EDB and closure are constructed fresh per `authorize` call and discarded (monitor.py:146-175); `Relation`s are immutable `frozenset`s.
- The only externalized state is **telemetry events** (`pcas.monitor.*`, `pcas.evaluator.*`, `pcas.graph.*`) via `emit_event`, and the `PolicyDecision` object returned to the caller (which the PDP may later persist/seal downstream — outside this unit).
- Policy **source** can be read from disk at construction via `policy_path` or the `TEX_PCAS_POLICY_PATH` env var (pcas_specialist.py:124-131); otherwise the in-code `_DEFAULT_POLICY` is used.

---

## Notable Findings

1. **PCAS does NOT seal / is not itself the Proof-Carrying Action Gate.** Despite the package living under the `feat/proof-carrying-gate` branch and the `__init__` framing, `pcas/` has **zero references** to `enforcement_seal`, `SealedFact`, or any sealing machinery (verified by grep). PCAS produces a deterministic Datalog *verdict* that flows into the PDP as a specialist signal; the proof-carrying *receipt* is sealed downstream (provenance/enforcement layer), not here. The relationship to the gate is **INDIRECT**.

2. **Docstring vs code: policy path mismatch.** `pcas_specialist.py:25` (docstring) claims the policy is "loaded from `var/pcas/policy.pcas` if present." The **actual code never looks at `var/pcas/policy.pcas`** — it only checks the `TEX_PCAS_POLICY_PATH` env var (pcas_specialist.py:128), and `var/pcas/` does not exist in the repo. In practice the hard-coded `_DEFAULT_POLICY` toxic-flow program runs unless an operator sets the env var. (Overstatement / stale docstring.)

3. **`proofs` package is inert.** `__init__.py` is an empty placeholder (`__layer_kind__='empty_placeholder'`); the lone Lean proof is never built (CI skips Lean, per its own docstring) and never imported. It is an ORPHAN publication artifact, not running code. The spine-pass listing of `proofs` is absent (it isn't in the classification list at all), consistent with ORPHAN/non-code.

4. **IFC→PCAS coupling is loose and unverified end-to-end.** `from_ifc_provenance` (adapter.py:229) is duck-typed and wrapped in try/except at the call-site (pcas_specialist.py:195); a real `ProvenanceGraph` whose attribute names differ would silently yield an empty graph, under which the default policy authorizes everything that isn't a literal toxic flow. The "PCAS over the IFC provenance graph" story (judges.py:391, pcas_specialist.py:8) is **architecturally wired but not demonstrably exercised with a real provenance graph** in this scope.

5. **ABSTAIN maps to advisory weight, not a block.** A no-rule-matched ABSTAIN becomes `risk_score=0.5` (pcas_specialist.py:216), i.e. PCAS only *hard*-forbids via explicit `@deny`. The fail-closed guarantee is real for *load/eval errors* (those become FORBID), but a policy that simply doesn't mention an action yields advisory 0.5, not a deterministic block — correct per the documented three-state design, but worth stating plainly.

6. **No dead code / no NotImplemented in the engine.** Grep across `pcas/` for `NotImplementedError`, `TODO`, `FIXME`, `raise NotImplemented`, `pass  #` returns nothing substantive. The engine is genuinely complete. The only "fallback" behaviors are intentional fail-closed conversions (parse/eval errors → FORBID) and sandboxed helper exception handling.

7. **`Fact` (Pydantic) is largely unused internally.** The evaluator and relations operate on raw value tuples for speed; `Fact` (relation.py:32) is exported and exists for API-boundary conversion but the hot path never constructs it — minor, not a defect.

8. **Performance claim substantiated (small graphs).** The docstring target "<1 ms p99 on ≤100 nodes/500 edges" (monitor.py:31) is backed by a real latency test (`test_monitor_latency_under_1ms_small_graph`, test_pcas.py:401) and a live measurement of 0.2–0.5 ms. Not independently load-tested at the 1k-node/10k-edge target named in `__init__.py:69`, so that larger-scale number is **(claim, unverified)**.

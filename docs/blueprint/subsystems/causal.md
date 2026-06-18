# Subsystem Dossier — `causal` (Causal Inference / Counterfactual Attribution)

Path: `/Users/matthewnardizzi/dev/tex/src/tex/causal/`
Branch: `feat/proof-carrying-gate`
Scope: 13 `.py` files, 5,228 lines.
Verification: every claim below is traced to source. `.md`/docstring claims that were NOT confirmed in code are marked `(claim, unverified)`.

---

## Overview

The `causal` package is Tex's **agent-failure attribution engine**. It answers two questions over an agent/decision trace:

1. **Post-incident**: "which prior step is the *root cause* of an observed failure, and how confident are we?" — implemented as a structural re-creation of the CHIEF paper's Hierarchical Causal Graph (HCG) plus a 4-stage counterfactual screener.
2. **Pre-emission (request path)**: "which declared upstream events most plausibly causally-enabled this proposed event?" — answered by cooperative-game-theoretic **Shapley values** in sub-millisecond time (`HierarchicalCausalGraph.fast_attribute`).

On top of that core there is a second, separately-cited mechanism — **ARM (Agentic Reference Monitor)** — that treats *denied* actions as first-class graph nodes and propagates trust through a 5-level integrity lattice, used to flag "causality laundering" (an agent re-attempting a denied action through a laundered path).

The package's *live deliverable* is `compute_attribution(decision)` (in `attribution_engine.py`): it converts a stored `Decision` into an OTAR trace, runs CHIEF + the screener, re-ranks candidates with optional prefill-SLM signals, computes an LSH-Shapley **blame distribution** across agents, runs an ARM-style causality-laundering check, and optionally attaches a **conformal prediction set** (an uncertainty region of trajectory indices). The result is signed (SCITT/COSE) by the API route and written to the evidence chain.

**Architectural self-label** (`__init__.py:1-2`, `:29-30`): Layer 4 "Execution Governance"; "wired via api/incident_routes and ecosystem/engine." The api/incident_routes half is **confirmed live**; the ecosystem/engine half is **wired but dormant at runtime** (see Wiring).

Most of the academic citations in the docstrings (arxiv IDs, dates, author names) reference papers from 2026 that cannot be checked from inside the repo; the *algorithms* they describe (Shapley, MinHash/LSH, split-conformal quantile, lattice meet, BFS reachability) are all genuinely implemented in code. Treat the specific arxiv numbers/dates as `(claim, unverified)` but the implemented math as real.

---

## File Inventory

| File | Lines | Role |
|------|------:|------|
| `__init__.py` | 66 | Package facade. Exports the CHIEF (`HierarchicalCausalGraph`, `HCGResult`), ARM (`AgenticReferenceMonitor`, label constants), counterfactual (`CounterfactualScreener`, `ScreeningOutcome`), and integrity-lattice (`IntegrityLevel`, `DEFAULT_TRUST_THRESHOLD`, `lattice_meet`, `DenialRecord`) public surface. Declares `__layer__ = 4`. |
| `chief.py` | 1028 | CHIEF HCG builder + backtracking attribution. `HierarchicalCausalGraph` (graph construction, `attribute_root_cause`, `fast_attribute`), `FastAttribution`/`HCGResult` models, exact + Monte-Carlo Shapley helpers. Largest/most central file. |
| `arm.py` | 554 | Agentic Reference Monitor. `AgenticReferenceMonitor` — records denials, computes integrity labels, deterministic `check_proposed`, ledger append of `DENIAL_EVENT`. Public label string constants. |
| `attribution_engine.py` | 853 | **Live orchestrator.** `compute_attribution(decision)` → `CausalAttributionResult`. Trace synthesis from a `Decision`, candidate enumeration, prefill re-ranking, ARM integrity classification, LSH-Shapley blame, optional conformal set. |
| `counterfactual.py` | 396 | `CounterfactualScreener` — 4-stage progressive causal screen (local / planning-control / data-flow / deviation-aware). Graph-mask reachability + cycle detection. |
| `conformal_attribution.py` | 628 | Conformal prediction over a trajectory. `compute_conformal_prediction_set` + 4 algorithms (vanilla, left/right/two-way filtration), transductive vs calibrated thresholds. |
| `lsh_shapley.py` | 352 | LSH-Shapley blame distribution. MinHash + banded LSH bucketing, exact in-bucket Shapley, normalization. `AgentContribution`, `blame_distribution`. |
| `prefill_signals.py` | 586 | Optional SLM prefill-signal extractor (per-step NLL + attention entropy). Lazy `transformers` backend, env-flagged, fail-closed empty fallback. |
| `_provenance_graph.py` | 328 | ARM provenance graph (`networkx.DiGraph`): node payloads (Call/Data/DataField/DeniedAction), labeled edges, `min_trust` (Definition 4), `has_counterfactual_chain_to` (BFS), `evaluate`. |
| `_hcg.py` | 148 | HCG node/edge types (`SubtaskNode`, `AgentNode`, `CausalEdge`, `NodeKind`, `EdgeKind`), deterministic node-id helpers, payload coercion. |
| `_otar.py` | 177 | OTAR (Observation/Thought/Action/Result) deterministic parser. Handles Tex-native, Who&When, and marker-delimited free text. |
| `_integrity.py` | 63 | The 5-level `IntegrityLevel` `IntEnum` lattice + `lattice_meet` (min) + `DEFAULT_TRUST_THRESHOLD`. |
| `_denial_record.py` | 49 | `DenialRecord` frozen pydantic model — the value ARM returns from `record_denial`. |

---

## Internal Architecture

The package has **two cores wired together by `attribution_engine.py`**: the CHIEF graph/screener path (the load-bearing one) and the ARM provenance-graph path (used for the integrity/laundering classification).

### A. OTAR substrate (`_otar.py`, `_hcg.py`)

- `OTARTuple` (`_otar.py:39-55`): frozen `(observation, thought, action, result)`, all default-empty strings.
- `parse_otar(step)` (`_otar.py:67-115`): deterministic, three detection paths — (1) Tex-native explicit keys; (2) Who&When `{role, content}` (assistant → thought+action, user/tool → observation+result, `_otar.py:104-107`); (3) marker-delimited free text via `_parse_markers` (`_otar.py:118-161`). The CHIEF paper's LLM parser is *not* used; `_otar.py:26-29` flags the LLM path as a future P1 TODO.
- `_hcg.py` defines the graph vocabulary: `NodeKind {SUBTASK, AGENT}`, `EdgeKind {SUB, AGT, STEP}`, payload models `SubtaskNode`/`AgentNode`/`CausalEdge`, and deterministic id functions `subtask_node_id` (`_hcg.py:118`), `agent_node_id` = `f"agent:{step_id}@{agent_id}"` (`_hcg.py:122-123`). `coerce_node_payload` (`_hcg.py:138-148`) defends against networkx returning untyped node `data`.

### B. CHIEF — `chief.py`

`HierarchicalCausalGraph` (`chief.py:210`) holds a `CounterfactualScreener` (default-constructed, `chief.py:222`).

1. **`build_from_trace(trace_events)`** (`chief.py:228-378`): parses steps (`_parse_trace`, `chief.py:673-724`), then materializes a `networkx.DiGraph`:
   - Subtask grouping: explicit `subtask_id` honoured; otherwise a heuristic increments a counter whenever `agent_id` changes (`chief.py:701-704`).
   - Adds `AgentNode` nodes (`chief.py:281-285`) and `SubtaskNode` nodes (`chief.py:295-299`).
   - Edges: `E_sub` (temporal subtask adjacency, `chief.py:302-309`), `E_step` (explicit `upstream_step_ids` data deps, `chief.py:319-332`), `E_agt` (prior step of same agent, `chief.py:340-350`), plus subtask→agent membership edges (`chief.py:356-364`).
   - Emits `causal.chief.graph_built` telemetry and returns `HCGResult(graph, subtask_ids, agent_step_ids)` (`chief.py:366-378`).

2. **`attribute_root_cause(causal_graph, observed_failure)` → `(root_cause_id, confidence)`** (`chief.py:384-473`): resolves the failure node (`_resolve_failure_id`, `chief.py:726-763`), collects candidate subtasks reverse-topologically (`_candidate_subtasks`, `chief.py:765-799`), drills to anomaly-flagged agent steps (`_candidate_agent_steps`, `chief.py:801-833`), then for each candidate calls `screener.screen_detailed` and keeps the **earliest** confirmed root cause (paper's `arg min_t`, `chief.py:435-465`). Degrades to earliest anomaly @ confidence 0.5 if the screener confirms none (`chief.py:460-464`). The LLM-based `F_eval` is replaced by a substring anomaly detector `_has_anomaly` over a fixed marker list `_ANOMALY_MARKERS` (`chief.py:57-71`, `:869-887`).

3. **`fast_attribute(...)` → `FastAttribution`** (`chief.py:479-667`): the request-path Shapley attributor. Defines a coalition payoff `v(S)` (`chief.py:609-622`):
   `v(S) = liveness_factor * (0.4*(1-e^{-|S|/3}) + 0.3*[first_upstream∈S] + 0.3*|S|/n)`, `liveness_factor = 1.0` if any active agents else `0.5`. Computes per-candidate Shapley via `_compute_shapley_values` (`chief.py:895-923`): **exact** for `n ≤ 6` (`_shapley_exact`, bitmask coalitions, `chief.py:926-970`), **Monte-Carlo** otherwise (`_shapley_monte_carlo`, Castro-Gómez-Tejada permutation estimator with integer-bitmask payoff cache and a **fixed seed `0xC0FFEE`** for replayability, `chief.py:973-1028`). Aggregate `confidence = sum(shapley)` clamped to `[0,1]` by the efficiency axiom. Empty upstream chain → zeroed result (`chief.py:597-604`). Verified live: a 3-upstream call returns confidence ≈ 0.853 with shares `[0.484, 0.184, 0.184]`.

### C. Counterfactual screener — `counterfactual.py`

`CounterfactualScreener.screen_detailed(...)` (`counterfactual.py:101-238`) runs 4 stages in order, returning a frozen `ScreeningOutcome(is_true_root_cause, confidence, stage, rationale)`:

1. **Local** (`:126-162`): if the candidate has no upstream AGENT predecessors → error originates here → root cause @0.95, *unless* `_is_reversible` (a later in-between AGENT step recovered) → not-root @0.4.
2. **Planning-control** (`:164-190`): `_planning_control_attribution` (`:326-396`) builds the `EdgeKind.AGT`-only subgraph, finds a `nx.simple_cycles` cycle containing the candidate, and decides planner-vs-executor fault from OTAR thought/action distinctness (identical thoughts under repeated errors → planner fault @0.8).
3. **Data-flow** (`:192-218`): masks the candidate (`graph.copy(); remove_node`) and tests whether the failure is still reachable from any in-degree-0 AGENT source (`nx.has_path`). Still reachable → downstream propagator, not-root @0.7.
4. **Deviation-aware** (`:220-231`): `_is_reversible` (`:283-323`) walks descendants strictly between suspect and failure timesteps; a `_RECOVERY_MARKERS` token in `otar.result` ⇒ reversible ⇒ not-root @0.5. Otherwise → irreversible root cause @0.85.

`screen(...)` (`:68-99`) is the legacy `(bool, float)` wrapper.

### D. ARM — `arm.py` + `_provenance_graph.py` + `_integrity.py`

- `_integrity.py`: `IntegrityLevel` IntEnum `TOOL_DESC(0) < TOOL_UNTRUSTED(1) < TOOL_TRUSTED(2) < USER_INPUT(3) < SYS_INSTR(4)` (`:25-42`); `lattice_meet = min`, raising on empty (`:50-63`); `DEFAULT_TRUST_THRESHOLD = TOOL_TRUSTED` (`:47`).
- `_provenance_graph.py` `ProvenanceGraph` (`:139`): backed by `networkx.DiGraph` (`:156`). Node payloads `CallNode`/`DataNode`/`DataFieldNode`/`DeniedActionNode`. Key behaviour: `add_call` **auto-attaches** a `COUNTERFACTUAL` edge from the most-recent denial to the next call, then clears `_last_denial_id` (the paper's "next tool call" heuristic, `:164-181`). Enforcement queries: `min_trust` (lattice-meet over data ancestors; empty → `SYS_INSTR`, `:237-256`), `has_counterfactual_chain_to` (reverse BFS tracking whether a counterfactual edge has been crossed — avoids exponential path enumeration, `:258-301`), `evaluate` (combined transitive-taint then laundering decision, `:303-323`).
- `arm.py` `AgenticReferenceMonitor` (`:105`): three deployment modes (in-memory only / with hash-chained ledger / shared external graph). `record_denial` (`:167-267`) adds a `DeniedActionNode`, wires explicit counterfactual targets, and — when a ledger+`CryptoProvenance` are wired — appends a real `DENIAL_EVENT` `ProposedEvent` via `InMemoryLedger.append_proposed` (`_append_denial_event`, `:511-546`). `integrity_label_for` (`:269-334`) maps a node to one of the 4 public label strings, prioritizing laundering taint. `check_proposed` (`:336-373`) is a deterministic graph decision that fail-closes ("unknown_event" → deny) and *never* asks an LLM (`:339`). Note the deliberate import ordering / cycle-avoidance comment block (`:55-71`) — `arm.py` primes `tex.ecosystem.proposed_event` before cold `tex.events.*` imports.

### E. Attribution orchestrator — `attribution_engine.py` (the live entry point)

`compute_attribution(decision, include_conformal, conformal_alpha, conformal_algorithm)` (`:680-846`):

1. `_trace_from_decision` (`:317-406`): each `Finding` → step with `agent_id = finding.source`; each `ASIFinding` → step with `result = "violated: …"` so CHIEF's anomaly markers fire (`:369`); uncertainty flags → one summary step; empty decision → a `decision.summary` synthetic step.
2. Builds the HCG and screener; `_enumerate_candidates` (`:423-534`) screens every anomaly-bearing step (up to `_MAX_CANDIDATES=8`, `:249`), assigning a perspective tag and graph confidence, then sorts confirmed-first/earliest/highest.
3. `extract_signals(trace)` (prefill SLM) → `_rerank_with_signals` (`:542-586`): `final_conf = graph_conf * (1 + 0.5 * clipped_normalised_nll)` with `_SIGNAL_WEIGHT_ALPHA=0.5` (`:245`). When no SLM, candidates keep graph confidence.
4. `_causality_laundering_check` (`:594-624`): **heuristic** — flags True if any ASI finding is in `{ASI03, ASI04, ASI06}` with severity > 0.7. Docstring explicitly calls this a v1 heuristic to be replaced by a live ARM provenance query (`:611-614`).
5. Per-candidate **effective integrity**: `_classify_agent_integrity` (`:172-186`) maps `agent_id` dot-prefix to a lattice level via `_AGENT_TRUST_MAP` (`:156-169`); `_effective_integrity_for_candidate` (`:189-238`) walks HCG ancestors (bounded at 64 nodes) and takes `lattice_meet`.
6. `_agent_contributions` (`:632-672`) → `blame_distribution` (LSH-Shapley) populates `blame_distribution`.
7. Optional conformal set via `compute_conformal_prediction_set`, wrapped in try/except (fail-closed, `:803-819`).
8. Returns `CausalAttributionResult` (`:276-309`) — never None, never raises on a structurally valid Decision (`:82-93` fail-closed contract).

### F. Conformal attribution — `conformal_attribution.py`

`compute_conformal_prediction_set(...)` (`:505-621`): builds per-step non-conformity scores (`_build_scored_steps`, `:184-240`) from prefill NLL if present else screener confidence; computes a split-CP threshold transductively (`_compute_threshold_transductive`, upper `⌈(n+1)(1-α)⌉/n` quantile, `:248-280`) or **calibrated** if `TEX_CONFORMAL_CALIBRATION_PATH` points at a scores file (`_load_calibration_scores`, `:308-331`); dispatches one of 4 algorithms (`:584-590`). Two-way filtration (`_two_way_filtration_set`, `:417-497`) is the default: anchor at the peak-score step, greedily expand toward the higher-scoring neighbor while either neighbor ≥ threshold. Empty/unknown-algorithm cases return an honest empty set (`start=end=-1`).

### G. LSH-Shapley blame — `lsh_shapley.py`

`blame_distribution(contributions)` (`:289-346`): single-agent → `{id: 1.0}`. Otherwise computes MinHash signatures over discretized 4-d feature shingles (`_minhash_signatures`, 32 SHA-256-seeded hashes, `:109-145`), buckets agents by banded LSH collisions with union-find (`_bucket_by_lsh`, bands of 4, `:148-193`), runs **exact** Shapley within each bucket (`_exact_shapley`, classical marginal formula, capped at k≤6 with deterministic subdivision, `:203-247`) over a heuristic super-additive value function (`_default_value_function`, `:250-286`), and globally normalizes to sum 1.0 (degenerate → uniform, `:338-341`). Verified live: 2-agent input `{a(denial):0.727, b:0.273}`.

### H. Prefill signals — `prefill_signals.py`

`extract_signals(trace)` (`:524-577`): returns `_EMPTY_SIGNALS` unless `TEX_ATTRIBUTION_SLM_ENABLED=1` **and** a backend loads (`_try_load_slm`, `:226-289`). Default backend is `transformers`-based (`_load_transformers_backend`, `:292-356`, imported lazily so the module loads cleanly without torch/transformers). `_TransformersBackend.prefill_signals` (`:374-470`) runs one no-grad forward pass, computes shifted-cross-entropy per-token NLL and per-query attention entropy (mean over layers/heads), and aggregates to per-step `StepSignal`. Custom backends installable via `set_slm_backend`. `render_trace_for_signals` (`:478-517`) is public so the evidence ZK module can hash an identical input.

---

## Public API

From `tex.causal` (`__init__.py:48-66`, verified importable):
`HierarchicalCausalGraph`, `AgenticReferenceMonitor`, `CounterfactualScreener`, `HCGResult`, `ScreeningOutcome`, `DenialRecord`, `IntegrityLevel`, `DEFAULT_TRUST_THRESHOLD`, `lattice_meet`, and label strings `LABEL_TRUSTED`/`LABEL_UNTRUSTED_INPUT`/`LABEL_DERIVED_FROM_TAINTED`/`LABEL_TAINTED_BY_DENIAL`.

The **actually-consumed** public surface (by code outside the package):
- `tex.causal.attribution_engine.compute_attribution`, `CausalAttributionResult`, `_trace_from_decision`.
- `tex.causal.prefill_signals.render_trace_for_signals`.
- `tex.causal.chief.HierarchicalCausalGraph.fast_attribute` (referenced by ecosystem engine; dormant — see below).

`attribution_engine.__all__` = `[CausalCandidate, CausalAttributionResult, compute_attribution]` (`:849-853`).
`conformal_attribution.__all__`, `lsh_shapley.__all__`, `prefill_signals.__all__` similarly export their entry points.

---

## Wiring

### Wiring In (importers outside the package)

```
src/tex/api/incident_routes.py:98   from tex.causal.attribution_engine import CausalAttributionResult, compute_attribution
src/tex/api/incident_routes.py:102  from tex.causal.prefill_signals import render_trace_for_signals
src/tex/api/incident_routes.py:350  from tex.causal.attribution_engine import _trace_from_decision
src/tex/vigil/causal.py:369,386     from tex.causal.attribution_engine import compute_attribution   (lazy, inside methods)
src/tex/ecosystem/engine.py:739     self._causal.fast_attribute(...)   (guarded by `if self._causal is not None`)
```
`src/tex/evidence/attribution_zk.py`, `src/tex/evidence/recorder.py`, `src/tex/graph/query.py` mention `tex.causal` only in **docstrings** — confirmed no runtime imports (`grep` for `from tex.causal`/`import tex.causal` in those files returns nothing).
The `__init__` public classes (`AgenticReferenceMonitor`, `HierarchicalCausalGraph`, `CounterfactualScreener`, `IntegrityLevel`, …) have **no importers outside the package** except the dormant `fast_attribute` reference. ARM is exercised only by `tests/causal/test_arm.py`.

### Live call path (confirmed)

**Path 1 — HTTP attribution endpoint (LIVE, unconditional):**
```
tex.main.create_app
  → app.include_router(build_incident_router())          src/tex/main.py:1442  (no flag guard)
  → POST /v1/incidents/{decision_id}/attribute            src/tex/api/incident_routes.py:626-632
      attribute_incident()
        → store.get(decision_id)                          incident_routes.py:652
        → compute_attribution(decision, include_conformal=…, conformal_alpha=…, conformal_algorithm=…)
                                                           incident_routes.py:660-665
          → tex.causal.attribution_engine.compute_attribution
            → HierarchicalCausalGraph.build_from_trace / attribute path,
              CounterfactualScreener, blame_distribution (LSH-Shapley),
              extract_signals, compute_conformal_prediction_set
```
This makes `attribution_engine`, `chief`, `counterfactual`, `_hcg`, `_otar`, `lsh_shapley`, `prefill_signals`, `conformal_attribution`, `_integrity` all **LIVE**. End-to-end coverage exists in `tests/test_integration_layer.py:1507-1700` (real `POST …/attribute`).

**Path 2 — Vigil v5 causal port (LIVE):**
```
tex.main.create_app
  → from tex.vigil.causal import CausalAttributionPort     src/tex/main.py:1770
  → app.state.vigil_engine = VigilEngine(..., causal_port=CausalAttributionPort(decision_store=…))
                                                            src/tex/main.py:1790-1796
  → CausalAttributionPort._attribution_root_cause / _maybe_seal_decision_attribution
      → from tex.causal.attribution_engine import compute_attribution
                                                            src/tex/vigil/causal.py:369,386
```
A second live consumer of `compute_attribution`, gated behind whether a decision is resolvable for the vigil reading.

**Path 3 — Ecosystem engine fast_attribute (WIRED, DORMANT at runtime):**
`tex/ecosystem/engine.py:739` calls `self._causal.fast_attribute(...)` inside step-5, but only `if self._causal is not None` (`:737`). At runtime, `EcosystemEngine` is constructed in `main.py:946-959` **without** a `causal=` argument, so `self._causal` is `None` (`engine.py:299`). The `TEX_ECOSYSTEM_CAUSAL` flag in `ecosystem_config.py:73` produces only a **boolean field on `EcosystemFlags`**, not a `HierarchicalCausalGraph`; `EcosystemFlags.from_env()` is not used to build the engine in `main.py`. So `fast_attribute` is real, tested (`tests/causal/test_chief_fast_attribute.py`, `test_chief_shapley.py`), and import-reachable, but **does not execute on the live request path** as currently wired.

**ARM** (`AgenticReferenceMonitor`, provenance graph, denial recording, `check_proposed`): **DEMO/TEST-ONLY** — no live caller; only `tests/causal/test_arm.py`. It is real, working code, but not on any runtime call path.

### Wiring status

**LIVE** overall (Path 1 + Path 2 carry the bulk of the package). With a finer split: the `attribution_engine`/CHIEF/screener/conformal/LSH/prefill stack is **LIVE**; `fast_attribute` is wired-but-dormant; ARM is **DEMO_TEST_ONLY**. Net: `MIXED`, dominated by LIVE.

### Wiring Out (dependencies)

Internal tex subsystems:
- `tex.observability.telemetry.emit_event` (used by chief, arm, counterfactual, attribution_engine, prefill_signals, provenance graph).
- `tex.domain.decision.Decision` (attribution_engine input type).
- `tex.events.ledger.InMemoryLedger`, `tex.events._canonical.canonical_sha256`, `tex.ontology.event_types.EventKind`, `tex.ecosystem.proposed_event.ProposedEvent` (ARM ledger append + import-cycle priming, `arm.py:71-76`).
- `tex.events.crypto_provenance.CryptoProvenance` (TYPE_CHECKING only, `arm.py:84-85`).

External libraries:
- `networkx` (DiGraph for HCG and ARM provenance graph; reachability, cycles, topo sort, ancestors).
- `pydantic` v2 (all frozen `extra="forbid"` models).
- stdlib: `math`, `random`, `hashlib`, `struct`, `threading`, `os`, `itertools`, `dataclasses`, `datetime`, `uuid`, `enum`.
- **Optional / lazy**: `transformers` + `torch` — imported only inside `prefill_signals._load_transformers_backend` (`:303-313`), behind `TEX_ATTRIBUTION_SLM_ENABLED`. The package imports and runs fully without them.

---

## Implementation Reality

**REAL, executing logic** (not stubs):
- CHIEF graph construction, backtracking, exact + Monte-Carlo Shapley — all run; verified live (`fast_attribute` produced real shares, 87 causal tests pass).
- Counterfactual 4-stage screen — genuine networkx graph-mask reachability + cycle analysis.
- ARM provenance graph queries — real lattice-meet `min_trust`, real BFS `has_counterfactual_chain_to`, real `DENIAL_EVENT` ledger append.
- LSH-Shapley — real MinHash/banded-LSH/union-find/exact-Shapley/normalization; verified live.
- Conformal prediction — real split-CP quantile threshold + 4 set-construction algorithms.
- Prefill `_TransformersBackend` — a real shifted-cross-entropy NLL + attention-entropy implementation (it just requires `transformers`/`torch` + the SLM env flag, neither installed/on by default).

**The single `NotImplementedError`** (`prefill_signals.py:205`) is the `_SLMBackend` **protocol base method** — an interface guard, not a hollow stub. The concrete `_TransformersBackend` overrides it (`:374`).

**Honest heuristics labelled as such in code** (real but acknowledged-approximate):
- `_has_anomaly` substring markers replace the paper's LLM `F_eval` (`chief.py:869-887`).
- `_causality_laundering_check` is an ASI-category/severity heuristic, *not* a live ARM provenance query — the docstring says so and points at the real follow-on (`attribution_engine.py:594-624`). This is the one place where the result's `causality_laundering_suspected` does **not** actually consult the ARM graph.
- `_agent_contributions.has_denial/has_taint` are proxies derived from candidate membership, not from a live ARM graph (`attribution_engine.py:657-662`).
- `model_weight_sha256` is the SHA-256 of the string `"transformers:{model_id}"`, an explicit surrogate for hashing real safetensors (`prefill_signals.py:344-349`).

**No crypto/zk/tee primitives live inside this package.** The "PTV/ZK envelope" and "TEE attestation" steps described in `attribution_engine.py:55-65` are built in `tex.api.incident_routes` (the `proof_pending` mode lives there), not here. The only crypto touched directly is `canonical_sha256` for argument digests and the ledger's own signing in the (test-only) ARM path.

**Fail-closed posture is genuinely implemented**: `compute_attribution` synthesizes a `decision_summary`/`fallback_empty_graph` candidate rather than returning None (`attribution_engine.py:720-731`, `_trace_from_decision:389-404`); the conformal call is try/except'd; `extract_signals` returns the empty singleton on any failure.

---

## Technology / SOTA

- **Cooperative game theory**: Shapley value, both exact (closed-form weighted marginal sum over `2^n` bitmask coalitions) and unbiased Monte-Carlo permutation estimator (Castro-Gómez-Tejada style) with prefix-sharing integer-bitmask payoff cache (`chief.py`). LSH-Shapley variant with MinHash bucketing reducing complexity at scale (`lsh_shapley.py`).
- **Causal attribution**: structural re-creation of CHIEF's HCG + progressive counterfactual screening, operationalizing "counterfactual re-execution" as graph-mask reachability rather than LLM replay (`chief.py:22-25`, `counterfactual.py`).
- **Information-flow security**: a 5-level integrity lattice with monotonic-taint propagation (lattice meet over data ancestors) and denial-induced counterfactual edges to detect "causality laundering" (`_integrity.py`, `_provenance_graph.py`, `arm.py`) — modeled on the ARM paper.
- **Conformal prediction**: split-CP quantile thresholds with filtration-based contiguous prediction sets (vanilla / left / right / two-way), transductive vs calibrated coverage modes (`conformal_attribution.py`).
- **LLM interpretability signals**: prefill-stage per-token NLL + attention entropy as out-of-distribution scores (`prefill_signals.py`).
- **Design patterns**: dependency injection (ARM's 3 modes, screener injection), frozen pydantic value objects everywhere, deterministic seeding for replayability (`_SHAPLEY_MC_SEED`, `_LSH_SEED_VERSION`), env-flag feature gating, fail-closed degradation.

The cited 2026 arxiv numbers/authors/dates are `(claim, unverified)` from inside the repo; the implemented algorithms are real.

---

## Persistence

The package is **almost entirely in-memory and stateless per call**:
- HCG and ARM provenance graphs are transient `networkx.DiGraph` instances built per `compute_attribution` / per ARM monitor; no durable store.
- `prefill_signals` keeps a **process-local** loaded-SLM singleton (`_LOADED_SLM`, guarded by `_SLM_LOCK`, `:180-182`) — a cache, not persistence.
- ARM, when wired with a ledger, writes a `DENIAL_EVENT` into `tex.events.ledger.InMemoryLedger` — durability is delegated entirely to that ledger; ARM holds no own store. This path is test-only at present.
- Conformal **calibration scores** are the only on-disk read: a plain text file at `TEX_CONFORMAL_CALIBRATION_PATH`, one float per line (`conformal_attribution.py:308-331`). Absent → transductive mode.
- The attribution *result* is persisted **outside** this package: `tex.api.incident_routes` signs it (SCITT/COSE) and writes an evidence row via `tex.evidence.recorder` (`recorder.py:473-485`).

State that lives across calls: only the SLM cache and the `TEX_CONFORMAL_CALIBRATION_PATH` file.

---

## Notable Findings

1. **`fast_attribute` is dormant on the live path.** It is real, tested, and import-reachable, but `EcosystemEngine` is built without `causal=` in `main.py:946`, so `self._causal is None` and the step-5 call at `engine.py:739` never fires in production. The `__init__.py:2` claim "wired via … ecosystem/engine" is therefore an **overstatement** for the runtime — the ecosystem half is wired-but-off. (api/incident_routes half is accurate.)

2. **ARM is fully built but unused at runtime.** `AgenticReferenceMonitor`, the provenance graph, denial recording, deterministic `check_proposed`, integrity labeling, and the real `DENIAL_EVENT` ledger append are all implemented and pass `tests/causal/test_arm.py`, but no live code constructs or calls an `AgenticReferenceMonitor`. It is `DEMO_TEST_ONLY`. The spine pass's "causal=LIVE" is correct for the *package* (the attribution_engine path is live) but masks that the ARM subcomponent is not on any call path.

3. **Causality-laundering in the live result is a heuristic, not an ARM query.** `causality_laundering_suspected` in every `CausalAttributionResult` is set by `_causality_laundering_check` (`attribution_engine.py:594-624`), which inspects ASI category/severity — it does **not** consult the ARM provenance graph or its `has_counterfactual_chain_to`. The docstring honestly flags this as v1-heuristic-to-be-replaced. Anyone reading "causality laundering per arxiv 2604.04035" in the result should know the real ARM mechanism (which exists in `arm.py`) is *not* what produced the flag.

4. **The "hybrid no one else has implemented" prefill re-ranking is inert by default.** `TEX_ATTRIBUTION_SLM_ENABLED` defaults to `"0"` (`prefill_signals.py:42-43` comment, `_try_load_slm:236`), and `transformers`/`torch` are optional. So in a default deployment `signals_available=False`, `attribution_method="graph"`, and step-6 re-ranking is a no-op pass-through. The hybrid path is real code but ships off.

5. **Docstring arxiv citations are unverifiable from the repo** and include very specific 2026 dates/authors (e.g. CHIEF 2602.23701, ARM 2604.04035, conformal 2605.06788, LSH-Shapley 2605.03581, MASPrism 2605.07509). Mark all as `(claim, unverified)`. The *algorithms* are genuinely implemented; the provenance labels are decoration.

6. **`model_weight_sha256` is a surrogate**, not a real weights hash (`prefill_signals.py:344-349`). It hashes the string `"transformers:{model_id}"`. The field is destined for ZK proof binding, where a fake weight hash would undermine the proof — flagged here because the docstring says "Required for ZK proof generation."

7. **Deterministic-by-fixed-seed Shapley/LSH** (`_SHAPLEY_MC_SEED = 0xC0FFEE` at `chief.py:108`; `_LSH_SEED_VERSION` at `lsh_shapley.py:76`). This trades per-call statistical independence for replayability — correct for an evidence chain (the same Decision must hash to the same attribution), but worth knowing the Monte-Carlo "samples" are not independent across calls.

8. **Friend-access into ProvenanceGraph internals**: `arm.py:498` reaches `self._graph._g` (the raw networkx graph) with a `# noqa: SLF001` to walk predecessors for the originator/derived distinction. Minor encapsulation break, intentional and commented.

9. **No dead files.** All 13 files are reachable: 9 via the live `compute_attribution` path, 4 (`arm.py`, `_provenance_graph.py`, `_integrity.py`, `_denial_record.py`) via the ARM cluster — of which `_integrity.py` is *also* used live by `attribution_engine` (`lattice_meet`, `IntegrityLevel`), while the ARM trio is test-only.

10. **Verification run**: `PYTHONPATH=…/src python -m pytest tests/causal -q` → **87 passed**. Live import + execution of `blame_distribution` and `fast_attribute` confirmed real numeric output (not placeholders).

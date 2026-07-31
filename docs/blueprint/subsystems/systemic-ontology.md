# Subsystem Dossier: Systemic Risk & Ontology

**Scope:** `src/tex/systemic/` (9 files, 3 453 LOC) and `src/tex/ontology/` (8 files, 1 217 LOC)
**Branch:** `feat/proof-carrying-gate`
**Method:** Every `.py` file read in full. Wiring traced by grepping actual imports/call-sites and following them from `tex.main` / `tex.api` routes. Claims from docstrings/`.md` are labelled `(claim, unverified)` unless confirmed in code. All references are `file:line` under `/Users/matthewnardizzi/dev/tex`.

---

## Overview

Two adjacent-but-distinct units share this dossier:

1. **`systemic/`** — forward-looking systemic-risk modeling for the agent ecosystem. Three composable scorers: a **ProbGuard/Pro2Guard PCTL DTMC** (probguard.py), a **Koopman-lifted, conformal-covered digital twin** (digital_twin.py + `_koopman`/`_conformal`/`_sccal`), and a **bounded-BFS cascade predictor** (cascade_predictor.py). They fuse into one `[0,1]` systemic axis via `SystemicRiskEvaluator.score_fused` (risk_evaluator.py).

2. **`ontology/`** — the type system for the temporal knowledge graph. `EntityTypeRegistry` and `EventTypeRegistry` are the roots: 12 entity kinds and 23 event kinds with frozen Pydantic v2 schemas, plus an `OntologyValidator` that type-checks proposed events. Four side modules (`airo`, `role_ontology`, `interaction_ontology`, `governance_ontology`) map types to compliance vocabularies.

**Wiring reality (headline):**
- **probguard `apply_predictive_holds`** is **LIVE** on the synchronous PDP request path (unconditional call; per-request opt-in via metadata).
- **EcosystemDigitalTwin** is **LIVE** but via its own dedicated route `POST /v1/ecosystem/twin/simulate` — it is NOT on the guardrail hot path.
- **`OntologyValidator` + `EntityTypeRegistry` + `EventTypeRegistry`** are **INDIRECT**: constructed and injected into the live `EcosystemEngine` at startup, but `validate_event` only fires when `TEX_ECOSYSTEM=1` (default OFF).
- **`SystemicRiskEvaluator`** (the fusion scorer) is **ORPHAN in production** — never instantiated outside tests; the engine's Step-7 call site references the *type* in comments but is wired with `systemic=None`.
- **`airo`, `role_ontology`, `interaction_ontology`, `governance_ontology`** are **DEMO_TEST_ONLY** — imported only by `tests/ecosystem/`.

---

## File Inventory

### `systemic/`

| File | LOC | Role |
|------|-----|------|
| `__init__.py` | 69 | Package facade; re-exports `SystemicRiskEvaluator`, `EcosystemDigitalTwin`, `CascadePredictor`, trajectory models, Koopman/SCCAL helpers. Sets `__layer__=4`. |
| `risk_evaluator.py` | 186 | `SystemicRiskEvaluator`: PCTL `score()` + Thread-9 convex-fusion `score_fused()` (PCTL+SCCAL+cascade). **Not instantiated in prod.** |
| `probguard.py` | 611 | ProbGuard/Pro2Guard DTMC over a 27-state abstraction; `reachability_probability` (PCTL bounded-until); `apply_predictive_holds` PDP hook. **LIVE.** |
| `digital_twin.py` | 665 | `EcosystemDigitalTwin`: replay-and-perturb simulator (Koopman roll-out + SCCAL + PCTL + conformal band). **LIVE via twin route.** |
| `_koopman.py` | 692 | EDMD Koopman operator (polynomial+RBF dictionary default; optional torch NN-lift); `fit_koopman`, `advance`, `predict_trajectory`; `TenantSignalProfile`. |
| `_sccal.py` | 737 | Ollivier-Ricci curvature + curvature-gated attention recurrence; exact-OT (scipy LP) / log-domain Sinkhorn dispatcher; `compute_sccal`. |
| `_conformal.py` | 152 | Anytime-valid conformal risk control; `CalibrationBuffer`, `band_for_prediction` (Hoeffding-corrected quantile). |
| `cascade_predictor.py` | 244 | `CascadePredictor`: bounded BFS over a dependency graph; `DependencyEdge`; `estimate_edge_probability`. **LIVE via twin route (optional).** |
| `trajectory.py` | 97 | Frozen Pydantic models: `TrajectoryStep`, `CascadePath`, `SimulationTrajectory`, `SystemicWeights`. |

### `ontology/`

| File | LOC | Role |
|------|-----|------|
| `__init__.py` | 47 | Facade; re-exports `EntityKind`, `EntityTypeRegistry`, `EventKind`, `EventTypeRegistry`, `OntologyValidator`. Sets `__layer__=4`. |
| `entity_types.py` | 177 | 12 `EntityKind`s, `TrustLabel`, per-kind frozen Pydantic schemas, `EntityTypeRegistry`. **INDIRECT (engine, flag-gated).** |
| `event_types.py` | 323 | 23 `EventKind`s, typed/permissive payload schemas, dynamic event-class factory, `EventTypeRegistry`. **INDIRECT.** |
| `validator.py` | 144 | `OntologyValidator.validate_event` (4 checks) + `EventLookup` protocol. **INDIRECT (engine Step 1, flag-gated).** |
| `airo.py` | 137 | Static dict mapping entity/event kinds → AIRO/DPV URIs; `map_entity_to_airo`, `map_event_to_airo`. **DEMO_TEST_ONLY.** |
| `governance_ontology.py` | 129 | Static dict of 10 `(entity,event)`→regulatory-anchor bindings; `regulatory_bindings_for`. **DEMO_TEST_ONLY.** |
| `interaction_ontology.py` | 139 | Static adjacency table of legal `(from_kind,to_kind)`→EventKinds; `allowed_interactions`. **DEMO_TEST_ONLY.** |
| `role_ontology.py` | 121 | Static dict of 6 domain roles → reasoning patterns; `reasoning_pattern_for_role`. **DEMO_TEST_ONLY.** |

---

## Internal Architecture

### A. ProbGuard PCTL DTMC — `probguard.py` (the live core)

**State abstraction (probguard.py:80-127).** `EcosystemState` is projected to a finite 27-state space = 3 (agent-count band) × 3 (capability-pressure band) × 3 (compromise band). Band cut-points are module constants (`_AGENT_COUNT_BANDS`, `_CAPABILITY_PRESSURE_BANDS`, `_COMPROMISE_BANDS`, lines 80-94). `abstract_state` (line 107) reads `state.active_agent_ids`, `aggregate_drift_signals["capability_grant_rate"]`, and `sliding_window_compromise_ratio`. `_ALL_STATES` (line 130) and `_STATE_INDEX` (line 138) are computed once at import. **Unsafe states** = the 9 states ending in `compromise_high` (`_UNSAFE_STATES`, line 144). The docstring is explicit and honest that the band cut-points are "ours" and not lifted from any paper (lines 44-49).

**DTMC model (probguard.py:149-240).** `DTMCModel` is a `@dataclass(slots=True)` holding a raw count matrix `_counts`. `observe_transition` (line 205) increments counts (silently drops unknown abstraction ids). `transition_matrix` (line 214) builds a row-stochastic matrix with Laplace add-α smoothing plus a **self-loop diagonal prior** (`smoothing_alpha=0.05`, `self_loop_prior=50.0`, lines 184-194). The docstring (lines 158-181) is candid that these defaults are `research-early`, repo-chosen, NOT from any cited paper, and names the test that guards the cold-start `< 0.10` bound. Matrix is cached and invalidated on `_dirty`.

**Reachability (probguard.py:243-309).** `reachability_probability` computes `P[F^{≤k} unsafe | initial_state]` via the standard absorbing-set trick: unsafe rows become self-loops (line 286-290), one-hot the initial state (line 292), propagate the distribution `k` steps via pure-stdlib matrix-vector products (lines 297-306), sum mass on the unsafe set (line 309). This is real PCTL bounded-until semantics, pure stdlib, no numpy. Unknown initial state → `0.0` (line 277).

**Module singleton (probguard.py:312-326).** `_DEFAULT_MODEL` accumulates transitions across calls; `_reset_default_model` is test-only; `default_model()` returns it.

**Pro2Guard predictive ABSTAIN — the live PDP hook (probguard.py:361-611).** This is the genuinely wired part:
- `evaluate_systemic_lookahead(request)` (line 457) is **pure and deterministic**: it reads `request.metadata["systemic_lookahead"]`, builds a *fresh* `DTMCModel` from optional caller-supplied `transition_counts` (`_model_from_counts`, line 435 — never touches `_DEFAULT_MODEL`, count loop capped at 100 000, line 452), computes reachability, and returns a frozen `SystemicLookaheadOutcome`. Absent metadata → `NEUTRAL_LOOKAHEAD` (zero-cost no-op, line 466/469).
- `apply_predictive_holds(base, request)` (line 517) is the function the PDP calls. **Monotone-lowering invariant** is enforced at a single guard (line 544): `if base.verdict is not Verdict.PERMIT: return base`. Only a PERMIT can be demoted to ABSTAIN; it can never raise to FORBID or relax a verdict. It composes two opt-in signals: the DTMC lookahead and `rv4_path.classify(request).recoverable` (line 548, imported lazily from `tex.contracts.rv4_path`). On a fire it rebuilds an immutable `RoutingResult` with verdict `ABSTAIN`, appended `Finding`s, flags, and scores (lines 562-611). Lazy imports of `tex.domain`/`tex.engine.router` (lines 538-555) deliberately avoid an import cycle with the PDP.

### B. Digital twin — `digital_twin.py`

`EcosystemDigitalTwin` (line 227) orchestrates the four math modules.

- **`__init__` (line 249)** holds a per-tenant Koopman op (`_koopman`, None until trained), an observation buffer `_transitions`, a shared/`default_model()` DTMC, a `CalibrationBuffer`, `SystemicWeights`, an optional `TenantSignalProfile`, and the `learned_dictionary` flag.
- **`fork_at` (line 286)** validates the ISO timestamp, deep-copies the DTMC, copies the calibration snapshot, shares the frozen Koopman model, snapshots KG versions into a `TwinSnapshot`, bumps `_generation`, emits `ecosystem.twin.fork_at`. Fork isolation is real (deep copies; `graph=None` on the fork).
- **`simulate_forward` (line 336)** is the substantive method:
  1. `_state_to_abstract_vector` (line 110) → 4-D vector `[compromise, log-entity-count, drift_mean, drift_max]`.
  2. `_perturb_vector` (line 178) applies counterfactual deltas (`compromise_delta`, `drift_delta`, `add_agents/tools`).
  3. `predict_trajectory` (Koopman roll-out; identity advance when untrained).
  4. `_build_interaction_graph` (line 148) or caller `adjacency_override` → adjacency for SCCAL; `compute_sccal` with curvature-gated recurrence (line 393).
  5. Per step: PCTL via `reachability_probability` on a `_abstract_state_label` (line 207) of the continuous vector; a **cascade proxy** = `0.5·compromise + 0.5·max(drift)` (line 418); convex fusion into `fused_systemic_score` (lines 422-427); conformal band via `band_for_prediction` (line 429).
  6. Builds `SimulationTrajectory`; `most_likely`/`worst_case` cascade paths are left **None** here (set by the caller's cascade predictor) (lines 459-461); emits `ecosystem.twin.simulate_forward`.
  Determinism is a stated design goal (lines 355-357) and is real given fixed inputs.
- **Training API:** `observe_transition` (line 477) buffers `(x_t, x_{t+1})`, records a conformal residual once trained, refits Koopman at the threshold and every 8 transitions after, and also feeds the DTMC. `_refit_koopman` (line 519) calls `fit_koopman` with the tenant profile. `update_tenant_profile` (line 549) swaps the profile and eager-refits on a version bump (Thread 9.1 self-tuning loop).
- `_make_run_id` (line 652) = SHA-256 over `(state_hash, perturbation, generation)` → 32-hex `twin_run_id` (evidence-chain anchor).

### C. Koopman — `_koopman.py`

Real **EDMD** implementation. `_lift_polynomial_rbf` (line 250) builds the default dictionary: linear + squares + pairwise cross-terms + RBFs, optionally scaled by calibrator signal weights. `_lifted_dim` (line 314) = `2d + C(d,2) + n_rbfs` (18 for d=4, n_rbf=4). `_build_rbf_centers` (line 191) places centers by deterministic quantile selection along PC1 (via `np.linalg.svd`), reserving a fraction for `high_leverage_regions`. `fit_koopman` (line 500) solves the ridge-regularized least squares `K = (ΦₓᵀΦₓ + λI)⁻¹ΦₓᵀΦ_Y)ᵀ` via `np.linalg.solve` (line 604); returns `None` below `MIN_TRAINING_N=8` (line 526). `advance` (line 624) lifts, multiplies by `K`, decodes the first `state_dim` coords, clamps to `[0,1]`. **None Koopman → identity advance** (line 641-642), the honest cold-start.

**NN-lift path (lines 324-497):** a genuine torch two-layer learned dictionary (`_NNLift`, line 328) trained end-to-end via one-step prediction loss (`_train_nn_lift`, line 452), with deterministic seeding from the SHA-256 of the data (line 467-472). This is **graceful-fallback, not default**: torch is imported behind a guarded `try` (`_HAS_TORCH`, lines 69-76; verified **False** in this environment), and `fit_koopman` silently degrades `learned_dictionary=True → polynomial+RBF` when torch is missing (lines 536-542). A pure-numpy inference forward (`_nn_lift_from_state`, line 408) exists so torch is not needed on the inference path.

### D. SCCAL — `_sccal.py`

Real discrete **Ollivier-Ricci curvature** computation. `compute_curvature` (line 319) computes per-edge `κ(u,v) = 1 − W₁(μ_u, μ_v)/d(u,v)` (`_ollivier_ricci_for_edge`, line 275) with the standard α-lazy mass distribution; shortest paths via Floyd-Warshall (`_shortest_paths`, line 258). **Optimal transport dispatcher** (`_wasserstein1_general`, line 239): exact LP via `scipy.optimize.linprog` HiGHS when combined support ≤ 64 (`_wasserstein1_exact_lp`, line 136) else log-domain Sinkhorn (`_wasserstein1_sinkhorn`, line 198). scipy is present here (`_HAS_SCIPY=True` verified), so the exact-OT path runs by default; a Sinkhorn fallback exists if scipy is absent. `curvature_gated_attention_step` (line 447) implements the paper's bidirectional ψ/ϕ predictors with sigmoid curvature gates and a KL-divergence co-evolutionary signal; `curvature_gated_recurrence` (line 544) runs it for `steps` and returns mean divergence. `compute_sccal` (line 584) assembles the composite `[0,1]` score with two weight regimes (recurrence-on: 0.40 divergence / 0.25 coupled / 0.20 neg-curvature / 0.15 tension, line 700-708; geometry-only: 0.55/0.25/0.20, line 710-715) and top-K most-negative-curvature edges for root-cause attribution.

### E. Conformal — `_conformal.py`

`CalibrationBuffer` (line 54) is an append-only, capacity-bounded score buffer dropping NaN/inf. `anytime_valid_quantile` (line 87) implements the Romano finite-sample quantile adjustment `(1−α)(n+1)/n` plus a **Hoeffding correction** `ε = √(log(2/δ)/(2n))` that decays as `1/√n` (line 116). Cold start (n=0) returns a conservative wide band `1.0` (line 108). `band_for_prediction` (line 124) wraps a point estimate in a symmetric interval clipped to `[0,1]`.

### F. Fusion + trajectory models — `risk_evaluator.py`, `trajectory.py`

`SystemicRiskEvaluator.score` (risk_evaluator.py:74) computes the pure-PCTL axis and incrementally feeds the DTMC. `score_fused` (line 112) is the Thread-9 convex combination of PCTL + SCCAL + cascade reachability per `SystemicWeights`; when given a `twin_trajectory` it defaults SCCAL/cascade to the **worst** step (line 159-170 — the right governance behavior of forbidding on the upper bound). `trajectory.py` holds the frozen output models; `SystemicWeights.__init__` (line 91) enforces weights sum ≤ 1.0 (defaults 0.35/0.45/0.20).

### G. Cascade predictor — `cascade_predictor.py`

`CascadePredictor.predict_cascade_paths` (line 97) is a real bounded BFS over a caller-supplied `DependencyEdge` set: indexes edges by source (line 126), expands with cycle detection (line 170), prunes when aggregate `prod(p_edge)` drops below `min_probability` (line 173), caps at `MAX_PATHS_RETURNED=64`, sorts by aggregate probability descending, emits `ecosystem.cascade.predict`. The predictor is deliberately stateless about the graph (lines 92-95). `estimate_edge_probability` (line 227) combines empirical co-failure rate, an analytical `1/(1+spectral_gap)` lower bound, and a `0.1` cold-start prior.

### H. Ontology registries — `entity_types.py`, `event_types.py`, `validator.py`

**`EntityTypeRegistry` (entity_types.py:152)** maps 12 `EntityKind`s (line 26) to frozen Pydantic schemas sharing `EntityBase` (line 50: id/kind/trust_label/capability_set/history_pointer/registered_at/metadata). `schema_for` returns `model_json_schema()`; `model_for` returns the class. `TrustLabel` (line 41) is a 4-level enum.

**`EventTypeRegistry` (event_types.py:292)** maps 23 `EventKind`s (line 38). The interesting machinery is the **mechanical payload-tightness rule** (lines 76-209): event kinds whose name implies a second entity get a tightened typed payload via `_make_typed_event` (line 188 — a runtime-generated frozen `EventBase` subclass pinning `kind` and `payload` type); permissive kinds get `_make_permissive_event` (line 200) with an open `dict` payload. `OUTBOUND_CONTENT_EMITTED` additionally requires `content_hash` (line 148) for the downstream EU Art 50 / CA SB 942 chain. `payload_model_for` (line 315) returns the typed payload or `None`.

**`OntologyValidator.validate_event` (validator.py:62)** runs four ordered checks: (1) `EventKind` resolves; (2) payload validates against the typed schema (only when a typed payload exists); (3) `actor_entity_id` non-empty; (4) `upstream_event_ids` resolve via an injected `EventLookup` protocol (line 27) — skipped with a soft telemetry warning when no lookup is wired. It emits `ontology.validation.{ok,failed,upstream_skipped}` telemetry. The package stays pure-types; live entity-store resolution is explicitly delegated to the engine (lines 73-77).

### I. Compliance side-ontologies — `airo.py`, `governance_ontology.py`, `interaction_ontology.py`, `role_ontology.py`

All four are **pure static lookup tables with thin accessor functions** — real data, no stubs, but no production caller:
- `airo.py`: `_ENTITY_TO_AIRO` (line 43) / `_EVENT_TO_AIRO` (line 62) dicts → AIRO/DPV URIs; accessors raise `KeyError` on unknown kind. Carries `TODO(verify-airo-spec)` on several mappings.
- `governance_ontology.py`: 10 anchor `(entity,event)` pairs → regulatory anchor strings (`eu_ai_act:art_50`, `nist:ai_rmf:*`, etc., line 45); default fallback for unlisted pairs.
- `interaction_ontology.py`: `_ALLOWED` adjacency (line 23) of legal type-level interactions; `is_interaction_allowed` convenience.
- `role_ontology.py`: 6 seed roles → reasoning patterns (inputs/outputs/constraints/airo_role/buyer_narrative).

---

## Public API

### `systemic/` (from `__init__.py:54-69`)
`SystemicRiskEvaluator`, `EcosystemDigitalTwin`, `CascadePredictor`, `DependencyEdge`, `estimate_edge_probability`, `CascadePath`, `SimulationTrajectory`, `SystemicWeights`, `TrajectoryStep`, `TenantSignalProfile`, `curvature_gated_attention_step`, `curvature_gated_recurrence`, `DEFAULT_HORIZON`, `MAX_HORIZON`.
Additional module-level public-by-use symbols actually imported elsewhere: `probguard.apply_predictive_holds`, `digital_twin.{EcosystemDigitalTwin, DEFAULT_HORIZON, MAX_HORIZON}`, `cascade_predictor.{CascadePredictor, DependencyEdge}`, `trajectory.{SimulationTrajectory, SystemicWeights}`.

### `ontology/` (from `__init__.py:41-47`)
`EntityKind`, `EntityTypeRegistry`, `EventKind`, `EventTypeRegistry`, `OntologyValidator`. The sub-ontology accessors (`map_entity_to_airo`, `regulatory_bindings_for`, `allowed_interactions`, `reasoning_pattern_for_role`, etc.) are public on their modules but NOT re-exported from the package facade and have no production caller.

---

## Wiring

### IN — who imports these symbols (verified by grep across `src/tex`)

```
systemic:
  api/ecosystem_twin_routes.py:67-69  → CascadePredictor, DependencyEdge,
                                         EcosystemDigitalTwin, DEFAULT/MAX_HORIZON,
                                         SimulationTrajectory, SystemicWeights
  engine/pdp.py:79                    → apply_predictive_holds
  main.py:90                          → EcosystemDigitalTwin
  contracts/runtime_enforcement.py:365 → (TODO comment only, not an import)

ontology:
  main.py:89                          → EntityTypeRegistry, EventTypeRegistry, OntologyValidator
  ecosystem/engine.py:89              → OntologyValidator
  causal/arm.py:76                    → EventKind
  compliance/_common.py:48            → EventKind
  ecosystem/bridge.py:46              → EventKind
  (sub-ontologies airo/role/interaction/governance: ONLY tests/ecosystem/*)
```

### LIVE call paths

**1. probguard `apply_predictive_holds` — LIVE, unconditional on the PDP path.**
```
POST /v1/.../evaluate (api/routes.py:128 command.execute)
  → commands/evaluate_action.py:214  self._pdp.evaluate(request)
  → engine/pdp.py:409                 apply_predictive_holds(base=routing_result, request=request)
  → systemic/probguard.py:517         apply_predictive_holds(...)
```
The call is **not env-gated** (no flag around pdp.py:409). Its *effect* is opt-in per request: a no-op unless `request.metadata["systemic_lookahead"]` (or an RV4 recoverable path policy) is present. The monotone-lowering guard (probguard.py:544) means at worst it demotes PERMIT→ABSTAIN. This is the one genuinely live, hot-path piece of `systemic/`.

**2. EcosystemDigitalTwin — LIVE via dedicated route (not the guardrail path).**
```
main.py:1066                ecosystem_twin = EcosystemDigitalTwin()   (graph=None)
main.py:1684 / app.state    app.state.ecosystem_twin + ecosystem_state_factory set
main.py:1528-1529           app.include_router(build_twin_router())
api/ecosystem_twin_routes.py:113 async def simulate(...)
  :119  twin = app.state.ecosystem_twin   (503 if None)
  :150  forked = twin.fork_at(...)
  :164  trajectory = forked.simulate_forward(...)
  :178  predictor.predict_cascade_paths(...)   (only if cascade_seed_event_id supplied)
```
Endpoint `POST /v1/ecosystem/twin/simulate`, gated by `RequireScope("evidence:read")` (routes.py:78). Constructed with `graph=None` (main.py:1066), so the live twin uses the caller-passed `EcosystemState` from `app.state.ecosystem_state_factory` (main.py:1083+), not a KG snapshot.

**3. OntologyValidator / EntityTypeRegistry / EventTypeRegistry — INDIRECT (engine, flag-gated).**
```
main.py:940-944   OntologyValidator(entity_registry=EntityTypeRegistry(),
                                    event_registry=EventTypeRegistry(),
                                    event_lookup=_ecosystem_ledger)
main.py:946-947   EcosystemEngine(ontology=_ecosystem_ontology, ...)   (NO systemic= arg)
main.py:960       EcosystemBridge(engine=ecosystem_engine)
commands/evaluate_action.py:999  bridge.emit_verdict(...)
  → ecosystem/bridge.py:182       self._engine.evaluate(proposed)
  → ecosystem/engine.py:513       self._ontology.validate_event(proposed)
```
The validator is genuinely constructed and injected, but `evaluate_action.py:961` short-circuits and returns the response unchanged unless `os.environ["TEX_ECOSYSTEM"]=="1"` (default OFF). So entity/event registries are reachable from a route but only execute under the ecosystem flag → **INDIRECT**.

**4. `EventKind` enum — LIVE (used outside the flag gate).** Imported by `causal/arm.py:76`, `compliance/_common.py:48`, `ecosystem/bridge.py:46`. The enum *values* are referenced in bridge/causal logic that runs on broader paths; the *registries/validator* are the flag-gated part.

### Wired status summary

| Component | Status | Why |
|-----------|--------|-----|
| `probguard.apply_predictive_holds` / `evaluate_systemic_lookahead` | **LIVE** | Unconditional call at pdp.py:409 on `/v1/.../evaluate`. |
| `EcosystemDigitalTwin` + `_koopman`/`_sccal`/`_conformal` | **LIVE** | `POST /v1/ecosystem/twin/simulate` (main.py:1529, routes.py:113). |
| `CascadePredictor` | **LIVE (conditional)** | Same route, only when `cascade_seed_event_id` supplied (routes.py:178). |
| `EntityTypeRegistry` / `EventTypeRegistry` / `OntologyValidator` | **INDIRECT** | Injected into live engine but fires only under `TEX_ECOSYSTEM=1` (evaluate_action.py:961). |
| `EventKind` enum | **LIVE** | Imported by causal/compliance/bridge on broader paths. |
| `SystemicRiskEvaluator` (incl. `score_fused`) | **ORPHAN in prod** | Never instantiated outside tests; engine `systemic=None` (main.py:946). |
| `airo`, `role_ontology`, `interaction_ontology`, `governance_ontology` | **DEMO_TEST_ONLY** | Imported only by `tests/ecosystem/`. |

### OUT — dependencies

**`systemic/` depends on:**
- `tex.ecosystem.state.EcosystemState` (risk_evaluator, probguard, digital_twin)
- `tex.graph.temporal_kg.InMemoryTemporalKG` (digital_twin, optional `graph`)
- `tex.observability.telemetry.emit_event` (everywhere)
- `tex.domain.{verdict,finding,severity}`, `tex.engine.router.RoutingResult`, `tex.contracts.rv4_path` (probguard, **lazy** imports at apply_predictive_holds, lines 538-555)
- External: **numpy** (digital_twin, `_koopman`, `_sccal`, `_conformal`); **pydantic v2** (all models); **torch** (optional, `_koopman` NN-lift — absent here); **scipy** (optional, `_sccal` exact-OT — present here); stdlib `hashlib`, `collections.deque`, `copy`, `uuid`, `math`.

**`ontology/` depends on:**
- `tex.ecosystem.proposed_event.ProposedEvent` (validator)
- `tex.observability.telemetry.emit_event` (validator)
- External: **pydantic v2** only (entity_types, event_types, validator). The four side-ontologies have **zero imports** beyond `__future__`/`typing` — pure static data.

---

## Implementation Reality

**REAL, substantive logic:**
- ProbGuard DTMC + PCTL bounded-reachability — genuine pure-stdlib matrix propagation with absorbing-set semantics (probguard.py:243-309). Verified: 27 states, 9 unsafe.
- EDMD Koopman with ridge least-squares, deterministic RBF placement, identity cold-start fallback (`_koopman.py`).
- Ollivier-Ricci curvature with exact-OT (scipy LP) and Sinkhorn fallback, plus curvature-gated attention recurrence (`_sccal.py`). scipy present → exact path runs.
- Anytime-valid conformal with Hoeffding correction (`_conformal.py`).
- Bounded-BFS cascade predictor with cycle detection and probability pruning (`cascade_predictor.py`).
- Ontology registries: real Pydantic schemas + runtime-generated typed event classes + a 4-check validator (`entity_types`, `event_types`, `validator`).
- The monotone-lowering Pro2Guard PDP hook — real, with the invariant enforced at a single guard (probguard.py:544).

**Graceful fallbacks (real impl + degradation, NOT hollow stubs):**
- Koopman NN-lift: real torch path behind `_HAS_TORCH` guard; degrades to polynomial+RBF when torch absent (`_koopman.py:69-76, 536-542`). Torch is absent in this environment → default path is the hand-crafted dictionary.
- SCCAL OT: exact LP when scipy + small support, else Sinkhorn (`_sccal.py:239-255`).
- Koopman cold start: identity advance when `< MIN_TRAINING_N=8` transitions (`_koopman.py:526, 641`).
- Conformal cold start: wide band `1.0` at n=0 (`_conformal.py:108`).

**Stubs / TODO / dead code:**
- **No `NotImplementedError`, no `raise NotImplementedError`, no bare `pass`-only bodies** anywhere in either unit (verified by reading every file). The `risk_evaluator.py` docstring (lines 4-5) notes it "replaces the prior `NotImplementedError` stub" — that replacement is real.
- **TODO markers** are pervasive but cosmetic/forward-looking, not blocking:
  - `entity_types.py:159-161`, `event_types.py:299-301`, `validator.py:68-74` — `TODO(P0)` lines inside docstrings restating already-implemented behavior (the methods below them are fully implemented).
  - `airo.py` — multiple `TODO(verify-airo-spec)` and `TODO(P1)` on mappings; `event_types.py:159` permissive-payload `TODO(p1-tighten-schema)`; `governance_ontology.py:43,114` `TODO(revisit-after-pilot-data)`; `role_ontology.py:106` `TODO(p1-expand-role-table)`.
  - `contracts/runtime_enforcement.py:365` — `TODO(P2): wire S from tex.systemic.risk_evaluator` — the fusion scorer is explicitly NOT yet wired into enforcement.
- **`SystemicRiskEvaluator.score_fused`** is fully implemented but **dead in production** — only tests reach it. The engine's Step-7 comment block (engine.py:835-844) cites it as a design direction; the live engine passes `systemic=None`.

---

## Technology / SOTA

- **PCTL probabilistic model checking** (Hansson-Jonsson 1994 bounded-until semantics) over a learned DTMC — ProbGuard / Pro2Guard `(claim, unverified: arXiv:2508.00500)`. Implementation is real and matches the described absorbing-set method.
- **Koopman operator theory / EDMD** — least-squares operator estimation with a polynomial+RBF observable dictionary; optional learned NN dictionary. `(claim: arXiv:2601.01076)`.
- **Discrete Ollivier-Ricci curvature** with α-lazy random walks and Wasserstein-1 optimal transport (exact network-simplex/HiGHS LP or entropic Sinkhorn). `(claim: SCCAL arXiv:2603.13325, GeomHerd arXiv:2605.11645)`. The OT and curvature math are genuine.
- **Anytime-valid conformal risk control** — cumulative calibration with a Hoeffding `1/√n` correction. `(claim: arXiv:2602.04364)`.
- **Curvature-gated attention recurrence** — sigmoid curvature gates × softmax attention, bidirectional ψ/ϕ predictors, KL co-evolutionary divergence. Real math, novel composition.
- **Bounded BFS cascade genealogy** with independence-product path probability and STPA/Spark-to-Fire taxonomy tags. `(claim: arXiv:2603.04474, 2604.06024, 2512.17600)`.
- **AIRO (AI Risk Ontology)** + DPV vocabulary mapping; EU AI Act / NAIC / FTC / CA SB 942 / NIST AI RMF regulatory anchors. `(claim: Golpayegani et al. 2022)`.
- **Design patterns:** registry pattern (entity/event), protocol injection (`EventLookup`), runtime class factory (`_make_typed_event`), frozen Pydantic v2 `extra="forbid"` throughout, deterministic seeding (SHA-256 → torch generator), monotone-lowering safety invariant.

---

## Persistence

**Everything is in-memory / per-process. No durable store in either unit.**
- `DTMCModel._counts` is an in-memory count matrix; `_DEFAULT_MODEL` is a module-level singleton living for the process lifetime (probguard.py:316). No serialization to disk.
- `EcosystemDigitalTwin` holds its Koopman op, transition buffer, and calibration buffer in instance state. The live twin (main.py:1066) is a single long-lived in-memory instance; `fork_at` produces isolated in-memory copies.
- `CalibrationBuffer` is a capacity-bounded in-memory list (`_conformal.py:54`, max 10 000).
- `KoopmanState` is a *frozen Pydantic model* designed to be replay-stable/serializable (nested tuples for NN weights), but nothing in scope writes it to durable storage.
- Ontology registries are stateless lookups over module-level dicts (`_ENTITY_MODELS`, `_EVENT_MODELS`); the side-ontologies are immutable module-level tables.
- Durability appears only *adjacent* to the unit: `twin_run_id` / `state_hash` are SHA-256 anchors intended for the evidence chain, and `OntologyValidator` reads upstream existence via an injected `EventLookup` (the ledger) — but the persistence lives in those other subsystems, not here.

---

## Notable Findings

1. **`SystemicRiskEvaluator` is orphaned in production despite being the package's headline export.** `__init__.py:35,55` exports it first; the whole `score_fused` fusion (PCTL+SCCAL+cascade) is implemented; yet it is never instantiated outside tests. The engine's Step-7 block (engine.py:855-913) is wired to call `self._systemic.score(state=...)` but main.py:946 constructs `EcosystemEngine` with no `systemic=` argument, so `self._systemic is None` and Step-7 always takes the `flag_off_and_no_collaborator` skip branch (engine.py:901). The engine comment at line 143 already admits the evaluator "exists today as an unverified" component. **The most sophisticated scorer in the unit does not run in production.**

2. **The genuinely live `systemic/` surface is narrow: the Pro2Guard PDP lookahead.** `apply_predictive_holds` runs on every PDP evaluation but is a zero-cost no-op unless the caller sets `request.metadata["systemic_lookahead"]`. So even the live path is dormant by default — it is a per-request opt-in feature, not an always-on rail. The monotone-lowering invariant (probguard.py:544) is correctly and minimally enforced.

3. **Digital twin runs on a side route, not the decision path.** `POST /v1/ecosystem/twin/simulate` is a "what-if" simulator gated by `evidence:read`. It is fully implemented and live, but a twin trajectory never feeds back into a live verdict (the cascade-path fields in the trajectory are set to `None` and only populated by the route's own optional cascade call). This matches the docstring's "honest scope" note (digital_twin.py:34-44).

4. **Four side-ontologies are test-only data tables.** `airo.py`, `role_ontology.py`, `interaction_ontology.py`, `governance_ontology.py` (526 LOC combined) have **no production importer** — confirmed by grep: only `tests/ecosystem/test_ontology_validator.py` and `test_ecosystem_imports.py` touch them. They are real, well-formed lookup tables (regulatory anchors, AIRO URIs, legal interaction adjacency, role patterns) but currently dead weight for the running app. The `OntologyValidator` itself does NOT consult `interaction_ontology` or `governance_ontology` — its four checks (validator.py:62-134) never call `allowed_interactions` or `regulatory_bindings_for`.

5. **`TODO(P0)` docstring lines contradict the implemented reality.** `entity_types.py:159-161`, `event_types.py:299-301`, and `validator.py:68-72` carry `TODO(P0)` comments describing behavior that is already fully implemented in the method body directly beneath them. These are stale scaffolding artifacts, not real gaps — a reader trusting the docstrings would wrongly conclude the registries are unfinished.

6. **Cold-start DTMC defaults are explicitly flagged as non-published guesses — a point of intellectual honesty.** probguard.py:158-194 repeatedly states `smoothing_alpha=0.05` and `self_loop_prior=50.0` are repo-chosen `research-early` values, NOT from any cited paper, and names the guarding test. This is the opposite of overstatement; the only published anchor claimed is the PCTL semantics itself.

7. **torch absent → NN-lift never runs by default.** `_HAS_TORCH=False` verified in this environment. `learned_dictionary=True` would silently degrade to the polynomial+RBF dictionary (`_koopman.py:536-542`). The live twin (main.py:1066) constructs with default `learned_dictionary=False` anyway, so the torch path is doubly dormant. This is a real graceful fallback, not a stub.

8. **The cascade predictor's `MAX_PATHS_RETURNED` break is a documented approximation.** cascade_predictor.py:158-164 breaks BFS expansion at 64 paths but acknowledges in-comment that without a priority queue this can miss some high-probability paths when the graph is dense. Honest, but a correctness caveat for large dependency graphs.

9. **`risk_evaluator.score_fused` uses a `drift_max` proxy for cascade reachability when no explicit cascade probability is passed** (risk_evaluator.py:166-170). Since the scorer is unwired this is moot today, but the fusion would substitute a drift signal for true cascade BFS output — worth noting if it is ever wired.

10. **No contradictions found between the `.md`-style module docstrings and the code's actual algorithms** for the live pieces — the probguard, koopman, sccal, and conformal docstrings accurately describe what the code does (including the honest-scope and research-early disclaimers). The contradictions are confined to (a) the stale `TODO(P0)` lines and (b) the gap between the package's exported ambition (`SystemicRiskEvaluator` fusion) and its actual wiring.

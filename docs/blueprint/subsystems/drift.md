# Subsystem Dossier — `drift` (Drift Detection)

> Scope: `/Users/matthewnardizzi/dev/tex/src/tex/drift/`
> Branch: `feat/proof-carrying-gate`
> Method: code-read, import-traced, call-path-verified. Docstring/`.md` claims are labelled `(claim, unverified)` unless confirmed in code.

---

## Overview

The `drift` unit is a **streaming distributional change-point + emergent-norm detection** library. It bundles four substantive capabilities behind one package:

1. **BOCPD** — Bayesian Online Change-Point Detection (Adams & MacKay 2007), a real, numpy-free, log-domain conjugate-Bayesian detector (`_bocpd.py`).
2. **Adaptive CUSUM** — a secondary Page-1954 cumulative-sum detector (`_cusum.py`), selectable as an alternative `detector_kind`.
3. **Anytime-valid e-process** — a Robbins/Howard-style mixture test-martingale producing a Ville-bounded anytime-valid p-value (`_anytime_valid.py`).
4. **Emergent-norm tracer** — a side-channel multi-agent collusion detector via pairwise mutual information + shared-target convergence (`emergent_norm.py`).

A **signal registry** (`signal_registry.py`) names seven ecosystem drift signals and also hosts a **pre-emission drift orchestrator** (`evaluate_drift`) intended as the ecosystem engine's Step-6 call site. An **evidence adapter** (`evidence_adapter.py`) lifts an anytime-valid certificate into a sealed `TexEvidence` for the engine's e-value spine.

**Reality summary.** The math is genuine and implemented (no hollow stubs, no `NotImplementedError`, no bare `pass`). But wiring is **MIXED and surprising**:

- The component that is **truly LIVE in the running app** is `_anytime_valid.AnytimeValidEProcess`, reached through the **learning layer's calibration trigger** on the `POST /report_outcome` route — *not* through the ecosystem engine.
- The headline `evaluate_drift` orchestrator + `ChangePointDetector` (BOCPD/CUSUM) + `DriftSignalRegistry` path is **wired but dormant**: the only production caller (`EcosystemEngine` Step 6) is constructed in `main.py` **without** a `drift=` collaborator, so `self._drift is None` and the entire BOCPD/registry path is skipped at runtime.
- `EmergentNormTracer` has **no production caller at all** — it is exported and tested but orphaned.
- `evidence_adapter.certificate_to_tex_evidence` is consumed only by `engine/risk_spine.py`, which is itself not constructed in `main.py` (inert by default) and only instantiated live inside the `capstone` flow (INDIRECT).

`__layer__ = 4` / `__layer_kind__ = 'execution_governance'` (`__init__.py:39-40`).

---

## File Inventory

| File | Lines | Role |
|---|---:|---|
| `__init__.py` | 85 | Package facade. Re-exports `ChangePointDetector`, `ChangePointEvent`, `EmergentNormTracer`, `EmergentPattern`, `DriftSignalRegistry`, `DriftSignal`, pattern/signal constants. Declares `__layer__`/`__layer_kind__`. Does **not** re-export `evaluate_drift`, `_anytime_valid`, `_cusum`, `_bocpd`, or `evidence_adapter` (those are imported by full path). |
| `_bocpd.py` | 376 | Private numerical core of BOCPD. Normal-Gamma conjugate sufficient stats, Student-t predictive, constant-hazard prior, log-domain forward recursion with logsumexp, top-K pruning, restart-on-underflow. Pure stdlib (`math`, `dataclasses`). |
| `_cusum.py` | 176 | Private adaptive two-sided CUSUM detector. EWMA mean/variance baseline, Welford warmup, reset-on-alarm. Pure stdlib. |
| `_anytime_valid.py` | 306 | Mixture e-process (Robbins method of mixtures over a discrete λ-grid). Emits `AnytimeValidCertificate` with Ville-bounded `p_anytime_valid`. Per-observation + cumulative clipping for overflow safety. Pure stdlib. |
| `change_point.py` | 406 | Public `ChangePointDetector` (per-signal state dict over BOCPD or CUSUM) + frozen `ChangePointEvent`. Optional ledger emission of `CHANGE_POINT_DETECTED` via injected `ledger`+`provenance`. Warmup suppression + anti-flutter + BOCPD restart on detection. |
| `signal_registry.py` | 882 | `DriftSignal`/`DriftSignalRegistry` (7 seeded signals) **and** the Step-6 `evaluate_drift` orchestrator (`_DriftOrchestrator`, `DriftEvaluation`, `ProbeMapPolicy`, signal→Rath-dimension map, soft-score reader). The largest and most overloaded file. |
| `emergent_norm.py` | 513 | `EmergentNormTracer` + `EmergentPattern`. Pairwise mutual-information action-lockstep clustering (union-find) and shared-target Z-score convergence. Pure-helper MI/union-find. |
| `evidence_adapter.py` | 188 | Bridge: `certificate_to_tex_evidence` + `RiskStreamEProcess` (e-process bound to a named risk stream → sealed `TexEvidence`). Factories `false_permit_monitor`, `abstain_rate_monitor`. |

Total: **2,932** lines across 8 `.py` files (excludes `__pycache__`).

---

## Internal Architecture

### 1. BOCPD core — `_bocpd.py`

- **`_NormalGammaSufficient`** (`_bocpd.py:98`) — `(mu, kappa, alpha, beta)` sufficient stats for a Normal-Gamma posterior over `(μ, τ=1/σ²)`.
  - `updated_with(x)` (`:120`) — exact one-observation conjugate update (Murphy 2007 eq. 86–89), `O(1)`.
  - `log_predictive(x)` (`:130`) — closed-form log Student-t predictive (ν=2α, scale²=β(κ+1)/(ακ)). Guards `scale_sq <= 0 / non-finite` by returning `-1e18` so the hypothesis loses normalisation (`:141-145`) — defensive, not a stub.
- **`BOCPDState`** (`_bocpd.py:156`) — mutable parallel arrays `run_lengths[]`, `log_joint[]`, `sufficient_stats[]`. `hazard_log_change = -log(λ)` (`:184`), `hazard_log_grow = log1p(-1/λ)` (`:189`). `initialise_if_empty()` seeds `r=0` with log-mass 0 (`:195`).
- **`_logsumexp`** (`:204`) — shifted log-sum-exp; returns `-inf` for empty / all-`-inf`.
- **`bocpd_step(state, x)`** (`:222`) — the algorithm:
  1. predictive likelihoods for each active hypothesis (`:245`);
  2. growth + change-point joint masses (`:248-256`);
  3. new hypothesis set = `[0] + [r+1...]` (`:259-261`);
  4. normalise by `log_evidence`; **on catastrophic underflow (`-inf`) restart from prior** (`:265-271`) per Alami 2020;
  5. sufficient-stat update — `r=0` carries prior, grown carry `x` (`:277-279`);
  6. top-K pruning by `log_joint` then re-normalise (`:282-298`).
  - **Change-point score** (`:314-332`): mass at `r_t < previous_MAP + 1` — the smoothed Adams-MacKay "MAP dropped" drop indicator, clamped to `[0,1]`. `0.0` on the very first step (`previous_map == _NEVER`).
- **`make_default_state`** (`:350`) — validates `hazard_lambda > 1`, `top_k >= 2`, positive prior hypers. Defaults: λ=250, K=50, weakly-informative `μ0=0, κ0=0.01, α0=1, β0=1` (`:65-68`).

### 2. CUSUM core — `_cusum.py`

- **`CUSUMState`** (`:57`) — `k`, `h`, `ewma_alpha`, `warmup_steps`, EWMA `mean`/`var`, `s_pos`/`s_neg`.
- **`cusum_step(state, x)`** (`:89`):
  - warmup (`step <= warmup_steps`): Welford running mean/var, no alarms (`:98-116`);
  - post-warmup: `z=(x-μ̂)/σ̂`, two-sided `S⁺/S⁻` recursion (`:122-123`), alarm when `max(S⁺,S⁻) >= h` (`:124`);
  - on alarm: reset sums, re-anchor `mean=x`, floor variance (`:127-137`) — Tang & Han 2023 observation-adjusted reset;
  - else: slow EWMA baseline update (`:139-144`).
- **`make_default_cusum_state`** (`:158`) — validates and defaults `k=0.5, h=5.0, ewma_alpha=0.05, warmup=30` (`:51-54`).

### 3. Anytime-valid e-process — `_anytime_valid.py`

- **`AnytimeValidCertificate`** (`:112`) — frozen `(p_anytime_valid, log_e_value, dominant_lambda, cumulative_deviation, sample_size)`. `is_significant_at(alpha)` (`:153`) → `p < α`, validates `0<α<1`.
- **`AnytimeValidEProcess`** (`:167`) — discrete λ-grid mixture `(0.25, 0.5, 1.0, 1.5, 2.5)` (`:100`).
  - `observe(standardised_x)` (`:196`): per-observation clip ±50σ + cumulative clip ±50σ (overflow defence, `:214-223`); per-λ `log e_t(λ)=λ|S_t| - ½λ²V_t` with `V_t=sample_size` (`:236-237`); mixture via `_log_mean_exp` (`:240`); `p=min(1, exp(-logE_t))`, `p=1` when `logE_t<=0` (`:251-261`). Uses two-sided `|S_t|` form (`:227-232`).
  - `reset()` (`:271`) — restart to zero state.
- **`_log_mean_exp`** (`:287`) — stable `log((1/N)Σexp)`, `-1e18` sentinel on all-`-inf`.

> Note: the verbatim `|S_t|` (two-sided) construction inflates Type-I to ≈2α; the rigorous `2^K/α` correction is **not** applied here — it is applied by the downstream consumer `engine/risk_spine.action_log_e_threshold` (`risk_spine.py:166-180`). The e-process itself only emits the raw `1/E_t`.

### 4. Public change-point detector — `change_point.py`

- **`ChangePointEvent`** (`:79`) — frozen externalised report (`event_id`, `signal_name`, `step_index`, `detected_at`, `detector_kind`, `change_point_score`, `run_length_map`, `posterior_mean`, `detection_threshold`, optional `ledger_event_id`).
- **`ChangePointDetector`** (`:102`):
  - `__init__` (`:121`) validates bounds and the **XOR invariant**: `ledger` and `provenance` must be supplied together (`:150-154`).
  - `update(signal_name, signal_value, at) -> bool` (`:183`) — per-signal step counter, dispatch to `_update_bocpd` or `_update_cusum`.
  - `_update_bocpd` (`:244`) — lazy per-signal `BOCPDState`; warmup suppression (`step <= warmup_steps`, `:256`); fire when `score >= threshold`; **anti-flutter** (no second fire within `warmup_steps`, `:268-272`); on fire, **restart the BOCPD trellis** (`:276-278`).
  - `_update_cusum` (`:292`) — lazy per-signal `CUSUMState`; fire on `result.fired`.
  - `_record_detection` (`:316`) — build `ChangePointEvent`, append to ledger if wired (`:352-355`), append to in-memory `_detections`, emit `drift.change_point.detected` telemetry (`:358`).
  - `_append_to_ledger` (`:369`) — builds a `ProposedEvent(event_kind="change_point_detected")`, milli-unit float coercion for JCS/RFC-8785 canonicalisation (`:383-394`), calls `self._ledger.append_proposed(proposed=..., provenance=...)`. Real ledger emission **only when constructed with `ledger`+`provenance`** — neither caller in the tree does so (see Wiring).

### 5. Signal registry + Step-6 orchestrator — `signal_registry.py`

- **`DriftSignal`** (`:66`) — frozen `(signal_id, description, aggregation_window_seconds, baseline_mean, baseline_stddev)`.
- **`DriftSignalRegistry`** (`:132`) — dict of signals, seeds **7 defaults** (`_DEFAULT_SIGNAL_DEFS:78`, `_seed_defaults:272`). `register`/`get`/`update_baseline`/`signal_ids`/`to_dict` + container dunders. Validates non-empty id, positive window, positive stddev.
- **`DriftEvaluation`** (`:311`) — frozen pydantic output: `drift_delta` + Rath three axes (`semantic/coordination/behavioral_drift`) + `signals_evaluated`, `change_point_detected`, `anytime_valid_p_value`, `dominant_signal_id`, `dominant_lambda`, `dominant_dimension`.
- **`_DriftOrchestrator`** (`:409`) — composes one `ChangePointDetector(detector_kind="bocpd")` + a per-signal-id dict of `AnytimeValidEProcess`.
  - `evaluate(proposed, state_before)` (`:433`): `_probe_signals_for` → standardise → BOCPD `update` (Bayesian leg) → `_bocpd_soft_score` → `AnytimeValidEProcess.observe` (frequentist leg) → **blend** `max(bocpd_score, 1-p)` per signal (`:567-573`) → **max-pool** into Rath dimensions via `_SIGNAL_TO_DIMENSION` (`:579-591`) → emit `drift.evaluate.complete` telemetry. Never raises (fail-open here; fail-closed at engine).
- **`evaluate_drift`** (`:638`) — module entry; lazy per-registry `_DriftOrchestrator` singleton keyed by `id(registry)` (`:670-676`); default registry via `_module_default_registry` lazy singleton (`:680`).
- **`ProbeMapPolicy`** (`:713`) — declarative `exact_rules` + `substring_rules` event_kind→signal_id classifier. `DEFAULT_PROBE_MAP_POLICY` (`:763`) maps ~18 exact + 12 substring event kinds.
- **`_probe_signals_for`** (`:810`) — classify proposed event → `{signal_id: baseline+1.0}` (baseline from `state_before.aggregate_drift_signals`, confirmed present at `ecosystem/state.py:31`).
- **`_bocpd_soft_score`** (`:849`) — reads the most recent `ChangePointEvent.change_point_score` for the signal from `detector.detections`; `0.0` on any error (defensive, `:872`).

### 6. Emergent-norm tracer — `emergent_norm.py`

- **`EmergentPattern`** (`:76`) — frozen `(pattern_id, kind, agent_ids, target_entity_id, severity, detected_at, evidence)`.
- **`EmergentNormTracer`** (`:96`) — stateless across calls; thresholds `mi_threshold_nats=0.1`, `target_convergence_threshold=2.0`, `min_cluster_size=3`, `window_size=200`.
  - `trace_norms(recent_event_window)` (`:166`) — truncate to window → `_detect_action_lockstep` + `_detect_shared_target_convergence` → sort by severity → emit `drift.emergent_norm.flagged` telemetry per pattern.
  - `_detect_action_lockstep` (`:237`) — per-agent action histograms bucketed by `bucket_field` (default `step_id`, falls back to event index); pairwise MI on shared buckets (`_mutual_information_nats`); high-MI edges → union-find clusters (`_connected_components`); severity = `mean_MI × cluster_size/n_total`.
  - `_detect_shared_target_convergence` (`:370`) — per-target volume, population mean/stddev, Z-score; flag when `distinct_actors >= min_cluster_size`, `sigma>0`, `z >= threshold`; severity = `z × distinct_actors/n_targets`.
- **`_mutual_information_nats`** (`:447`) — empirical plug-in MI in nats; Miller-Madow correction left as a `TODO(P2)` (`:461`). **Real implementation**, returns `max(mi,0)`.
- **`_connected_components`** (`:484`) — union-find with path compression. Real.

### 7. Evidence adapter — `evidence_adapter.py`

- **`certificate_to_tex_evidence(cert, ...)`** (`:77`) — builds `TexEvidence(kind=E_PROCESS, is_true_e_value=True, sequentially_predictable=True, maturity=RESEARCH_EARLY, log_e_value=cert.log_e_value, sample_size=cert.sample_size)`. Confirmed `EvidenceKind.E_PROCESS`/`EvidenceMaturity.RESEARCH_EARLY` exist (`domain/evidence.py:215,241`).
- **`RiskStreamEProcess`** (`:110`) — e-process bound to a named stream; `observe` seals each obs into `TexEvidence`; `is_breached(alpha)` reflects Ville-significance; `reset()`. Factories `false_permit_monitor` (`:171`) / `abstain_rate_monitor` (`:181`) with stream ids/nulls/filtrations (`:60-71`).

**Internal data flow (the `evaluate_drift` orchestrator):**
`ProposedEvent` → `_probe_signals_for` → `{signal_id: probed}` → for each signal: `ChangePointDetector.update` (BOCPD) → `_bocpd_soft_score`; `AnytimeValidEProcess.observe` → `AnytimeValidCertificate`. Blend → Rath max-pool → `DriftEvaluation`. The two cores (`_bocpd`, `_anytime_valid`) are otherwise independent and individually reusable.

---

## Public API

Exported via `tex.drift` (`__init__.py:65-85`):
- Classes: `ChangePointDetector`, `ChangePointEvent`, `EmergentNormTracer`, `EmergentPattern`, `DriftSignalRegistry`, `DriftSignal`.
- Constants: `PATTERN_ACTION_LOCKSTEP`, `PATTERN_SHARED_TARGET_CONVERGENCE`, `DEFAULT_SIGNAL_IDS`, and the seven `SIGNAL_*` ids.

Imported by full path (not in `__all__`) by other subsystems:
- `tex.drift.signal_registry.evaluate_drift` + `DriftSignalRegistry` (engine Step 6).
- `tex.drift._anytime_valid.AnytimeValidEProcess` (learning + engine/risk_spine).
- `tex.drift.evidence_adapter.certificate_to_tex_evidence` (engine/risk_spine).

`evidence_adapter` also has its own `__all__` (`:47-58`): `RiskStreamEProcess`, `certificate_to_tex_evidence`, the stream/null/filtration constants, `false_permit_monitor`, `abstain_rate_monitor`.

---

## Wiring

### Wiring In — who imports the unit

`grep "from tex\.drift"` across `src/tex` (excluding the package itself) returns exactly **five** real import statements:

| Importer | Symbol | Status |
|---|---|---|
| `ecosystem/engine.py:785` | `DriftSignalRegistry`, `evaluate_drift` | wired but **dormant** (collaborator never passed — see below) |
| `learning/trigger.py:56` | `AnytimeValidEProcess` | **LIVE** |
| `learning/drift.py:45` | `AnytimeValidEProcess` | used only by `RiskStreamEDetector` (orphan — no caller) |
| `engine/risk_spine.py:107` | `AnytimeValidEProcess` (reused VERBATIM) | INDIRECT (risk_spine not built in `main.py`) |
| `engine/risk_spine.py:108` | `certificate_to_tex_evidence` | INDIRECT (same) |

`ChangePointDetector`, `ChangePointEvent`, `EmergentNormTracer`, `EmergentPattern`, `DriftSignalRegistry` (as a class) have **no production import outside the package** other than `engine.py`'s `evaluate_drift` path. `contracts/runtime_enforcement.py:20` references `ChangePointDetector` in a **docstring only** (verified: no import statement; `grep "import.*ChangePointDetector" runtime_enforcement.py` is empty).

### Wiring In — the LIVE call path (verified, file:line)

The only path that reaches drift code in the default running app:

```
POST /report_outcome                              api/routes.py:396  (route, scope outcome:write)
  → ReportOutcomeCommand.execute                  api/routes.py:404 → _get_report_outcome_command:591
  → self._orchestrator.ingest_outcome(outcome)    commands/report_outcome.py:92
  → FeedbackLoopOrchestrator ... self._trigger.on_outcome(result.outcome)
                                                  learning/feedback_loop.py:272
  → AnytimeValidCalibrationTrigger.on_outcome     learning/trigger.py:151
  → state.eprocess.observe(standardised_x=x)      learning/trigger.py:197
       where state.eprocess = AnytimeValidEProcess()   learning/trigger.py:190
```

Construction wiring in the app factory:
- `learning_trigger = AnytimeValidCalibrationTrigger(orchestrator=..., proposals=...)` — `main.py:1030`.
- `learning_orchestrator.set_trigger(learning_trigger)` — `main.py:1034` (back-reference bound after construction; `set_trigger` at `feedback_loop.py:200`).
- `report_outcome_command = ReportOutcomeCommand(..., orchestrator=learning_orchestrator)` — `main.py:1036`.
- Router included via `app.include_router(build_api_router())` — `main.py:1441`.

So `_anytime_valid.AnytimeValidEProcess` is **LIVE**. The rest of the unit is reached only conditionally/indirectly.

### Why the BOCPD / `evaluate_drift` / registry path is dormant

`evaluate_drift` is called at `ecosystem/engine.py:800`, but **only inside `if self._drift is not None:`** (`engine.py:783`). `self._drift = drift` (`engine.py:300`) comes from the `drift: object | None = None` constructor arg (`engine.py:210`). The single production construction of `EcosystemEngine` is `main.py:946`, and it passes only `ontology, graph, projection, events, provenance, contracts` — **no `drift=`** (verified: `grep -A30 "EcosystemEngine(" main.py | grep drift` is empty). Therefore at runtime `self._drift is None`, Step 6 takes the `drift_skipped_no_collaborator` branch (`engine.py:823`), and BOCPD / CUSUM / `DriftSignalRegistry` / `ChangePointDetector` / the Rath three-dimension classifier are **never executed by the app**.

The `TEX_ECOSYSTEM_DRIFT` flag (`ecosystem_config.py:75`) parses into an `EcosystemFlags.drift` bool, but `EcosystemFlags` is a pure dataclass and **does not construct or inject the engine's `drift=` collaborator** — no code path in `main.py` reads that flag to build a `DriftSignalRegistry`. The flag is effectively inert for this unit.

### Wiring In — `EmergentNormTracer`

No production caller. Exported and presumably tested, but `grep "EmergentNormTracer"` across `src/tex` (excluding `drift/`) returns **nothing**. **ORPHAN.**

### Wiring In — `evidence_adapter` / `change_point` ledger emission

- `certificate_to_tex_evidence` is consumed only by `engine/risk_spine.py:290`. `RiskSpine` is **not constructed in `main.py`** (`grep "RiskSpine(" main.py` empty), so `PDP._risk_spine is None` and `apply_risk_spine` (`engine/pdp.py:423`) is an inert no-op in the default build. `RiskSpine` is constructed live only in `capstone/flow.py:256` (capstone = INDIRECT per the spine pass). So `evidence_adapter` is **INDIRECT**.
- `ChangePointDetector._append_to_ledger` is real, but no caller ever constructs the detector with `ledger`+`provenance`, so ledger emission of `CHANGE_POINT_DETECTED` never fires in production. (Telemetry-only at best, and the detector itself is unreached.)

### Wiring Out — dependencies

Internal `tex.*`:
- `tex.ecosystem.proposed_event.ProposedEvent` (signal_registry, change_point) — confirmed fields `event_kind/actor_entity_id/target_entity_id/proposed_at` (`proposed_event.py:22-26`).
- `tex.ecosystem.state.EcosystemState` (signal_registry) — `aggregate_drift_signals` confirmed (`state.py:31`).
- `tex.observability.telemetry.emit_event` (signal_registry, change_point, emergent_norm) — confirmed (`telemetry.py:255`).
- `tex.domain.evidence.{EvidenceKind, EvidenceMaturity, TexEvidence}` (evidence_adapter) — confirmed (`evidence.py:201,227,245`).

External libraries:
- `pydantic` (`BaseModel/ConfigDict/Field`) — `change_point.py`, `signal_registry.py`, `emergent_norm.py`.
- **stdlib only** for the numerical cores: `_bocpd.py`, `_cusum.py`, `_anytime_valid.py` use only `math`/`dataclasses`/`typing` (no numpy/scipy). `evidence_adapter.py` uses only `dataclasses`/`uuid`. This dependency-minimalism is a real, verified property — the docstring claim "stdlib-only" holds.

---

## Implementation Reality

**REAL — no stubs.** Every algorithm in scope is fully implemented:

- BOCPD: genuine log-domain Normal-Gamma/Student-t forward recursion with top-K pruning and underflow restart (`_bocpd.py:222-347`). Not a placeholder.
- CUSUM: genuine two-sided adaptive statistic with EWMA baseline + observation-adjusted reset (`_cusum.py:89-155`).
- Anytime-valid e-process: genuine Robbins mixture martingale with Ville bound `p=1/E_t` and overflow clipping (`_anytime_valid.py:196-269`).
- Mutual-information collusion detector + union-find: genuine plug-in MI and clustering (`emergent_norm.py:447-513`).

**No `NotImplementedError`, no `raise NotImplementedError`, no bare `pass`-only bodies, no `...` placeholders** in scope (verified by read).

**TODOs present, all non-blocking and honestly annotated:**
- `signal_registry.py:154-172` — TODOs marked **`— DONE`** for the seed table; remaining live TODOs are calibration (`:163`) and joint/multivariate BOCPD (`:167`).
- `change_point.py:192-209` — a block of TODOs each marked `— DONE` except the β-divergence robust upgrade (`:204`, real open item) and hyperparameter exposure (`:208`).
- `_bocpd.py:64` — expose prior hypers via constructor (open).
- `emergent_norm.py:174-199` — TODOs marked `— DONE`/`Done` except white-box probe upgrade (`:193`) and Audit-the-Whisper FP wrapper (`:198`) and Miller-Madow MI correction (`:461`, `TODO(P2)`).

**Defensive fail-open vs fail-closed (real, not hollow):**
- `_bocpd.log_predictive` returns `-1e18` on degenerate scale (`:141-145`).
- `bocpd_step` restarts from prior on `-inf` evidence (`:265-271`).
- `_anytime_valid.observe` clips ±50σ per-obs and cumulative (`:214-223`).
- `_bocpd_soft_score` swallows all exceptions → `0.0` (`signal_registry.py:872`).
- `evaluate_drift`/`_DriftOrchestrator.evaluate` never raises; engine Step 6 wraps in try/except → `drift_delta=0.0` (`engine.py:815`). Fail-closed is documented as living at the engine layer, and it does.

**Crypto note:** the unit contains no crypto of its own. Its only crypto touch is `ChangePointDetector._append_to_ledger`, which delegates signing to an injected `provenance` (a `CryptoProvenance` whose algorithm agility lives in `tex.pqcrypto`). Since the detector is never constructed with a ledger/provenance in production, this path is unexercised. No native-vs-fallback crypto decision lives in `drift`.

---

## Technology / SOTA

- **BOCPD** — Adams & MacKay 2007 (arXiv:0710.3742) with Normal-Gamma conjugacy → closed-form Student-t predictive (Murphy 2007 §7.6.3); constant-hazard geometric segment prior; **top-K run-length pruning + restart** per Alami, Maillard, Féraud 2020 (PMLR v119) for O(K) per step; log-domain logsumexp throughout. (All algorithm choices verified against the code; literature citations are docstring claims, but the *implemented math matches* the named algorithm.)
- **Adaptive CUSUM** — Page 1954 two-sided cumulative sum; EWMA in-control baseline; Tang & Han 2023 observation-adjusted reset. Defaults `k=0.5, h=5.0` (≈10³ ARL claim, unverified empirically).
- **Anytime-valid inference** — Robbins 1970 method of mixtures; Howard et al. 2021 sub-Gaussian time-uniform confidence sequences; Ville's inequality for the `p=1/E_t` bound; discrete λ-grid mixture (stdlib reason given in docstring). The two-sided `|S_t|` ≤2-factor inflation is real and corrected downstream in `risk_spine`.
- **Emergent-norm / collusion** — Bonjour et al. 2022 information-theoretic action-MI collusion signal (side-channel track of Schroederdewitt et al. 2026, since Tex has no white-box activations); shared-target Z-score convergence. Union-find with path compression.
- **Design patterns** — strategy (BOCPD vs CUSUM behind one `update` surface), frozen pydantic value objects for safe ledger hand-off, lazy per-key singletons (`_DEFAULT_ORCHESTRATORS`, `_e_processes`, per-signal state dicts), declarative rule policy (`ProbeMapPolicy`) with exact→substring fallthrough, milli-unit float canonicalisation for deterministic JCS/RFC-8785 hashing.
- **Rath 2026 three-dimension drift taxonomy** (`signal_registry.py:575-608`) — semantic/coordination/behavioral axes via max-pooling over a signal→dimension map. Implemented but, like the rest of `evaluate_drift`, unreached in production.

> The arXiv ids (2512.18561 AAF, 2603.08578 Drift-to-Action, 2601.04170 Rath, 2604.01151 collusion, etc.) and the "71-step median detection delay" benchmark are **docstring claims, unverified** — there is no benchmark harness in scope and no test in this directory was read. The *algorithms named* are correctly implemented; the *empirical performance claims* are not substantiated by code here.

---

## Persistence

- **Entirely in-memory.** All detector state lives in Python objects: `ChangePointDetector._bocpd_states/_cusum_states/_step_counts/_detections` dicts (`change_point.py:167-177`); `_DriftOrchestrator._e_processes` dict (`signal_registry.py:431`); module-level singletons `_DEFAULT_ORCHESTRATORS`/`_MODULE_DEFAULT_REGISTRY` (`signal_registry.py:406,688`); `AnytimeValidEProcess._cumulative_deviation/_sample_size/_log_e_per_lambda` (`_anytime_valid.py:180-184`).
- `EmergentNormTracer` is **stateless across calls** — each `trace_norms` operates only on the supplied window.
- **No database.** The only durable path is the *optional* `CHANGE_POINT_DETECTED` ledger append in `change_point.py:369-406`, which (a) writes to an injected `ledger` (an `InMemoryLedger` in the app factory anyway) and (b) is never wired with a ledger in production. The Postgres table `tex_drift_events` (`stores/drift_events.py`) is a **separate unit** — it does not import `tex.drift` and belongs to the discovery/reconciliation drift-event store (served by `build_drift_router`, `api/governance_history_routes.py`). Do not conflate it with this subsystem.

---

## Notable Findings

1. **Headline path is dormant (biggest finding).** The BOCPD/CUSUM/`DriftSignalRegistry`/`evaluate_drift`/Rath-taxonomy machinery — the bulk of `signal_registry.py` and all of `change_point.py`/`_bocpd.py`/`_cusum.py` — is wired into `EcosystemEngine` Step 6 but **never executed in the default app**, because `main.py:946` constructs the engine without a `drift=` collaborator (`self._drift is None`, `engine.py:783`). The engine docstring even says "Step 6 — drift detection [done, Thread 7]" (`engine.py:464`) — accurate as *code present*, misleading as *runtime-active*.

2. **The only LIVE drift code is `_anytime_valid`, reached via the learning layer — not the ecosystem engine.** The genuine production consumer is `AnytimeValidCalibrationTrigger` on `POST /report_outcome` (`trigger.py:190,197`; `main.py:1030`). An auditor expecting "drift detection" to fire through the ecosystem pipeline would be wrong; it fires through calibration learning.

3. **`EmergentNormTracer` is an ORPHAN.** Fully implemented (513 lines), exported, but zero production importers. Dead in the running system.

4. **`TEX_ECOSYSTEM_DRIFT` flag is inert for this unit.** It is parsed (`ecosystem_config.py:75`) but no code uses it to construct/inject a `DriftSignalRegistry` into the engine. Setting it to `1` does **not** turn on BOCPD drift scoring.

5. **`evidence_adapter` is INDIRECT only.** `certificate_to_tex_evidence` reaches the app exclusively through `engine/risk_spine.py`, and `RiskSpine` is not built in `main.py` (`PDP._risk_spine is None`, `apply_risk_spine` inert) — it is constructed live only inside `capstone/flow.py:256`.

6. **`RiskStreamEDetector` (learning/drift.py:302) is dead** — it imports/uses `AnytimeValidEProcess` but has no caller (`grep "RiskStreamEDetector(" src/tex` empty). The live learning consumer is the *trigger*, not this detector.

7. **`seal_drift_step` (risk_spine) has no caller** — exported, unused.

8. **`change_point.py` ledger emission is real but unexercised.** `_append_to_ledger` correctly builds a canonicalised `CHANGE_POINT_DETECTED` event, but no construction site passes `ledger`+`provenance`, so it never runs.

9. **Two-sided e-process inflation handled downstream, not here.** `_anytime_valid.observe` uses `|S_t|`, which yields ≈2α false-positive rate; the rigorous `2^K/α` correction lives in `risk_spine.action_log_e_threshold` (`risk_spine.py:166`). A reader of `_anytime_valid.py` alone could over-trust the raw `p_anytime_valid`. The `evidence_adapter` honestly tags maturity `RESEARCH_EARLY` and notes the sub-Gaussian null is "not yet validated on real production data" (`evidence_adapter.py:27-33`) — that humility is real and matches the code.

10. **Stale-but-harmless docstring TODO in `signal_registry.py:154-162`** still prints the "TODO(P1): seed with default signals … — DONE" block; the work is done, the TODO text just lingers. Cosmetic.

11. **`__init__.py` does not export the actually-live symbol.** `evaluate_drift`, `_anytime_valid`, and `evidence_adapter` are absent from `__all__`; consumers reach them by private full path. The package facade advertises the dormant API (`ChangePointDetector`, `EmergentNormTracer`) and hides the live one. No correctness issue, but a discoverability/contradiction smell.

12. **Empirical claims unverified.** The "71-step median detection delay (IQR 39–177)" and "0.97 attribution accuracy" numbers in `__init__.py:14-15` and elsewhere are docstring claims with no benchmark code in scope — **(claim, unverified)**.

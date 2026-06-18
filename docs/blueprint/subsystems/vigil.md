# Subsystem Dossier: `vigil`

> **Scope-label correction (read first).** The task brief labels Vigil as a
> "continuous monitoring / alerting / watchdog" unit. **That is wrong, verified
> in code.** There is no polling loop, no watchdog thread, no alert dispatcher,
> no schedule anywhere in `src/tex/vigil/`. `vigil` is the **selection /
> cognition layer that decides *what Tex chooses to say*** each time the
> `/v1/vigil` route is hit. It reads six cross-cutting "dimensions" off
> `app.state`, computes **Bayesian surprise** (KL divergence between a posterior
> belief and a "model of normal" prior), and ranks/gates a small set of
> *authored, sealed-filled* sentences. The "watch" framing is only true in the
> loose sense that the frontend can poll it (or hold an SSE stream) — the
> server itself fires nothing on its own. Path of truth: `vigil/engine.py:53`
> (`VigilEngine.run`) is invoked synchronously per request from
> `api/vigil_routes.py:281`.

---

## Overview

`vigil` is a self-contained cognitive layer with no DB and (almost) no external
dependencies in its hot path. Its job each cycle:

1. **Read** the six dimensions from the live `app.state` stores
   (`dimensions.py:read_dimensions`) → a list of `DimensionReading`.
2. **Model normal** for each dimension by warming a conjugate prior from sealed
   ledger history (`normal.py:ModelOfNormal`).
3. **Compute Bayesian surprise** = `D_KL(posterior || prior)` in closed form
   for Beta–Bernoulli and Gamma–Poisson families (`conjugate.py`).
4. **Select** the calm few lines above threshold, always speak the
   human-decision gate, collapse redundant symptom lines, and emit a
   "standing word" (`Absolute` / `Open`) — `selector.py:select`.
5. **Fill** each chosen line from an **authored deterministic template**, using
   only sealed slot values (`utterances.py:fill`). This is the "iron rule":
   *surprise chooses which sealed truths to speak; it never writes the words.*

A second, **pull** path (`explainer.py`) turns a clicked line into a grounded
narration — deterministic by default, optionally fluent via an OpenAI provider,
but always restating only sealed facts.

The package is staged as a "build ladder" v1 → v5. **All five rungs are
*implemented*, and — contrary to the package docstring — all five are *wired
live* in production** (`main.py:1769-1786` injects the v2 learner, v3 preference
model, v4 EFE selector, and v5 causal port). The engine self-reports capability
`"v5"` when fully injected (`engine.py:113`, verified by smoke test).

**Wired status: LIVE.** `tex.main.create_app` mounts `build_vigil_router()`
(`main.py:1458`) and constructs `app.state.vigil_engine` with the full ladder
(`main.py:1776-1786`). A second live consumer is `tex.voice` (mounted at
`main.py:1459`), which imports `vigil.utterances.fill` and `vigil.Explainer`.

---

## File Inventory

All paths under `/Users/matthewnardizzi/dev/tex/src/tex/vigil/`.

| File | Lines | Role |
|------|------:|------|
| `__init__.py` | 51 | Package facade. Re-exports `VigilEngine`, `select`, `Explainer`, etc. Build-ladder docstring (partly stale — see Notable Findings). |
| `engine.py` | 123 | `VigilEngine` — one object that runs a cycle: read dimensions → optional v3 recalibration → optional v5 attribution → build model (v2) → select (v1 or v4) → fold observations (v2). `capability()` reports the active rung. |
| `dimensions.py` | 343 | `read_dimensions` + 6 per-dimension reader fns. Turns `app.state` stores into `DimensionReading` objects. Defines `DimensionReading`, `ProofRef`. **This is the only file that reads external stores.** |
| `normal.py` | 124 | `ModelOfNormal` — warms a per-dimension conjugate prior from reading history. Holds the base-prior tables `_GAMMA_BASE` / `_BETA_BASE` and the safe-state floors. |
| `conjugate.py` | 181 | Closed-form Bayesian-surprise math. `BetaBelief`, `GammaBelief`, `beta_surprise`, `gamma_surprise`, and a stdlib-only `digamma`. No SciPy. |
| `selector.py` | 195 | `select()` — the v1/v1.5 selector. Surprise ranking + redundancy collapse + human-gate pass-through + standing word. Defines `VigilSelection`, `ChosenUtterance`, `SelectorConfig`. |
| `utterances.py` | 165 | Authored sentence forms (`FORMS`), `select_form`, `fill`. The "iron rule" enforcement point: `template.format(**sealed_slots)` only, refuses to improvise. |
| `explainer.py` | 526 | The **pull** path. `Explainer.explain` assembles a sealed `EvidenceFacts` sheet per dimension and either narrates via a provider or via the deterministic floor `_render_deterministic`. `build_default_explainer` gates the OpenAI provider on settings. |
| `_openai_explainer.py` | 60 | `OpenAITextProvider` — transport-only adapter over OpenAI's **Responses API** (`client.responses.create`). Lazy import; optional dependency. |
| `learning.py` | 235 | **v2** `DirichletNormalLearner` — accumulating Gamma–Poisson sufficient statistics as a live model of normal. Thread-safe, per-tenant/per-dimension. Sealable snapshot. |
| `preference.py` | 288 | **v3** `PreferenceModel` — preference / Value-of-Information fitted from resolved decision outcomes. Calibrates the speak threshold from revealed cost asymmetry. |
| `efe.py` | 223 | **v4** `ExpectedFreeEnergySelector` — policy selection by Expected Free Energy (epistemic + pragmatic value) with submodular cause→symptom collapse. Falls back to v1 `select()` when no preference model. |
| `causal.py` | 474 | **v5** `CausalAttributionPort` + `CausalSeal` — seals cause→symptom edges into an own hash-chained ledger before they may inform speech (provability gate). Optional "regulator-grade" COSE-signed path. |
| `calibration_provider.py` | 188 | `CalibrationProposalVigilProvider` + `CompositeHeldProvider`. Adapts a pending calibration proposal into the held-card seam (decision-first composition). |
| `held_provider.py` | 110 | `HeldDecisionVigilProvider` — adapts the runtime's `HeldDecisionSink` into the `/v1/vigil` `human_decision` channel. |

Total: **15 files, ~3,046 lines.**

---

## Internal Architecture

### Data model (`dimensions.py`)

* `ProofRef` (`dimensions.py:36`) — a pointer to sealed evidence: `kind`, `id`,
  `sha256`, `seq`. `is_empty()` at `:45`.
* `DimensionReading` (`dimensions.py:49`) — one dimension's observation this
  cycle. `kind ∈ {"beta","gamma"}` (`:33`). For gamma, `observation =
  (count, exposure)`; for beta, `(successes, failures)`. Carries `history`
  (to warm the prior), `slots` (sealed values to fill the form), `proof`,
  `explained_by` (declared symptom→cause edges for v1.5/v4 collapse, `:63`),
  `is_human_gate` (`:66`), and the v5 `causal` / `counterfactual` attachments
  (`:71`,`:74`).

### The six dimensions (`dimensions.py:87-327`)

`read_dimensions` (`:330`) runs five single readers in build order then extends
with the `_execution` pair (`:338-342`). The order carries no precedence — the
selector ranks by surprise.

| Reader | `app.state` store read | What it observes | Kind | Prior posture |
|--------|------------------------|------------------|------|---------------|
| `_discovery` (`:87`) | `scan_run_store` | new agents registered this scan | gamma | volume, mean≈2 |
| `_identity` (`:123`) | (builds governance via `tex.api.agent_routes`) | high-risk agents ungoverned | gamma | **safety**, mean≈0.25; `explained_by=("discovery",)` |
| `_monitoring` (`:164`) | `connector_health_store` | connectors failing to report | gamma | **safety**, mean≈0.25 |
| `_evidence` (`:270`) | `discovery_ledger` | chain intact? + length | beta | **safety**, Beta(50,1) — break = maximal surprise |
| `_learning` (`:297`) | `proposal_store` | pending calibration proposals | gamma | volume, mean≈1 |
| `_execution` (`:205`) | `decision_store` | FORBID volume **and** the ABSTAIN human-gate | gamma | volume; ABSTAIN line is `is_human_gate=True` |

Every reader is **defensive**: a missing/half-initialized store returns `None`
(or `[]`) rather than raising — e.g. `dimensions.py:88-97`, `:172-177`. The
`_identity` reader is notable because it *reaches into the API layer*
(`from tex.api.agent_routes import _build_governance, ...` at `:126`) to compute
governance coverage on the fly — a real cross-layer call, not a stub.

### Model of normal (`normal.py`)

`ModelOfNormal.prior_for` (`:84`) dispatches on `kind`.

* **Gamma** (`_gamma_prior`, `:91`): start from `_GAMMA_BASE` (`:43`), then
  *accumulate* every numeric history entry: `shape = base_shape + sum(counts)`,
  `rate = base_rate + len(counts)` (`:98-99`). Accumulation — never a sliding
  window — is the load-bearing design choice (`normal.py:5-9`): a slow drift
  still reads as a departure.
* **Beta** (`_beta_prior`, `:107`): start from `_BETA_BASE` (`:60`, evidence =
  `Beta(50,1)`), accumulate `(successes, failures)` tuples from history.

`warm=True` iff history existed; otherwise the deliberately skeptical base
fires. Safety dimensions seed near-zero so any departure registers; volume
dimensions seed a modest baseline with pseudo-strength `rate=4` so a new shop
isn't a "night-one flood" (`normal.py:46-47`).

### Surprise math (`conjugate.py`)

* `digamma(x)` (`:54`) — stdlib-only ψ(x): recurrence to push x above 6, then
  the standard asymptotic expansion (`:78-82`). Verified numerically:
  `digamma(1.0) = -0.577216` (the Euler–Mascheroni constant −γ, exactly
  correct).
* `BetaBelief` / `GammaBelief` (`:94`,`:116`) — frozen conjugate beliefs with
  `update()` (conjugate posterior) and `mean`. Constructors enforce strictly
  positive parameters (`:101`,`:123`).
* `beta_surprise` (`:141`) and `gamma_surprise` (`:163`) — **closed-form KL
  divergence** `D_KL(posterior || prior)` in nats, clamped ≥ 0 for round-off.
  No sampling, no inference engine. Verified: `gamma_surprise(Gamma(8,4),
  observe 20)` ≈ 6.44 nats — a large, sane belief shift.

The docstring frames this as the *realized* epistemic-value term of expected
free energy; v4 computes the same functional *in expectation* (`conjugate.py:11-14`).

### Selector v1 / v1.5 (`selector.py:select`, `:110`)

Flow:
1. `_standing_word` (`:92`) → `"Open"` if a human-gate exists, or any safety
   dimension is non-zero / chain broken; else `"Absolute"`.
2. Pull the human-decision gate out (`:121-135`) — it is **never ranked**,
   always spoken when a form exists, `surprise=0.0`, `requires_human=True`.
3. Build candidates: for each ranked reading, `select_form` + `_surprise_for`
   (`:139-147`). A reading with nothing sealed to say yields no candidate.
4. Sort by raw surprise descending (`:150`).
5. **v1.5 redundancy collapse** (`:161-169`): a declared symptom is suppressed
   iff a *louder-or-equal* cause was already spoken — "if the symptom is bigger
   than its cause, the explanation is contradicted by magnitude, so it still
   speaks."
6. Threshold (`min_surprise=0.05` nats) and cap (`max_spoken=4`) — "the calm
   few" (`:171-173`, `SelectorConfig` at `:40`).

`_surprise_for` (`:77`) is the bridge: `model.prior_for(reading)` → conjugate
`update()` → `beta_surprise`/`gamma_surprise`.

### Utterance forms (`utterances.py`)

`FORMS` (`:47`) is the authored registry: one `UtteranceForm` per dimension
(plus `monitoring_single`, `evidence_intact`/`evidence_broken`, and two v5
`*_counterfactual` forms). `select_form` (`:125`) picks the right variant;
`fill` (`:150`) is the **iron-rule enforcement point** — it raises
`ValueError("refusing to speak ... The vigil does not improvise")` if any
required sealed slot is missing (`:159-163`) and otherwise does only
`template.format(**sealed)`. **The `learning` form's `speaks_when` is hard-wired
to `False`** (`:105`) — pending calibrations were retired as a spoken vigil line
and now surface only as a held-card calibration hold.

### The v2–v5 ladder

These are **optional collaborators** injected into `VigilEngine.__init__`
(`engine.py:37-51`), each defaulting to `None` so v1 runs the concrete path.

* **v2 — `DirichletNormalLearner` (`learning.py:127`).** Accumulating
  Gamma–Poisson sufficient stats per `(tenant, dimension)`, guarded by an
  `RLock`. `observe()` (`:151`) folds a cycle's count, warm-starting from sealed
  history on first sight. `as_model()` (`:186`) returns a `_LearnedModelOfNormal`
  (`:83`) that sources learnable dims from accumulated state and **pins every
  safety dimension to its fixed base** (`:101-108`) — the "safety floor":
  `LEARNABLE_GAMMA = {discovery, execution, learning}` only (`:62`). Evidence
  (beta) deliberately inherits the v1 strong-integrity prior. `snapshot()` /
  `snapshot_sha256()` (`:203`,`:230`) give a deterministic, sealable view of
  "normal" — the model's evolution is itself auditable. The engine does
  **predict-then-learn**: select on the pre-cycle model, then `observe`
  (`engine.py:97-105`).

* **v3 — `PreferenceModel` (`preference.py:83`).** A `_CostModel` (`:67`)
  accumulates `interrupt_cost` vs `miss_cost` from resolved
  decision+outcome pairs (`learn_from_outcome`, `:107`; mapping driven by
  `tex.domain.outcome.OutcomeLabel`). `speak_threshold()` (`:184`) =
  `base * (interrupt+prior)/(miss+prior)`, clamped to `[0.005, 0.40]` — a
  **normative floor**: it can never rise high enough to silence a safety line
  (`NORMATIVE_FLOOR = {identity, monitoring, evidence, human_decision}`, `:53`).
  `value_of_information()` (`:198`) returns surprise-comparable VoI, floored at
  `_FLOOR_VOI=0.25` for floor dimensions. `learn_from_stores()` (`:148`) is the
  idempotent per-cycle recalibration tick (dedup by `outcome_id`), called from
  `engine.py:62-71`. **"Silence is never consent":** a dismissal only counts as
  interrupt-cost when `was_safe is True` (`:138`).

* **v4 — `ExpectedFreeEnergySelector` (`efe.py:92`).** Replaces ranking with
  **policy selection**: `value = epistemic + pragmatic`, EFE = −value
  (`_EFECandidate.value`, `:86`). The cause→symptom collapse zeroes a symptom's
  epistemic term *inside the objective* (submodular non-linearity, `:88`),
  generalizing v1.5's post-hoc filter. Greedy selection with collapse is argued
  to be **EFE-optimal, not heuristic**, because the only cross-line coupling is
  the cause→symptom edge (`efe.py:34-37`). Contract-preserving fallback: with no
  preference model it delegates verbatim to v1 `select()` (`efe.py:111-112`).
  Uses v3's calibrated threshold via `_resolve_threshold` (`:213`).

* **v5 — `CausalAttributionPort` (`causal.py:159`).** `attribute()` (`:192`)
  re-tags readings: a *declared* `explained_by` edge is only kept when the cause
  actually fired this cycle (`_edge_confidence`, `:419`) **and** the attribution
  seals successfully and the chain verifies — otherwise the edge is dropped so
  the symptom is never silently collapsed on an unproven claim (`:235-238`).
  `CausalSeal` (`:94`) is an append-only, hash-chained ledger
  (`record_hash = sha256(payload_sha256 + previous_hash)`, `:117`) with
  `verify_chain()` (`:132`) — verified working by smoke test (append×2 →
  `verify_chain()==True`). `is_sealed` (`:292`) is the provability gate. An
  optional "regulator-grade" path (`_maybe_seal_decision_attribution`, `:376`)
  binds `tex.causal.attribution_engine.compute_attribution` and mints a
  COSE-signed evidence row — **but this path is dead (see Notable Findings).**

### The held-card seam (`held_provider.py`, `calibration_provider.py`)

These adapt runtime sources into the `/v1/vigil` `human_decision` channel,
mirroring the v2–v5 "real interface the runtime injects" pattern.

* `HeldDecisionVigilProvider.current` (`held_provider.py:39`) reads the freshest
  unresolved item from a `HeldDecisionSink.peek()` (the queue the standing PDP /
  discovery path append ABSTAINs to), with tenant scoping (`:61-70`), and maps
  it to the held-card payload, preferring the Layer-4 `Hold`'s own sentence
  (`:83-89`).
* `CalibrationProposalVigilProvider.current` (`calibration_provider.py:68`)
  adapts the freshest pending `CalibrationProposal` into the same held-card
  shape, speaking *meaning not numbers* (`_direction`, `:151`;
  `_safety_sentence` from the anytime-valid OPE bound, `:172`).
* `CompositeHeldProvider` (`calibration_provider.py:33`) tries providers in
  precedence order — **decision-first**, so a held decision always wins the
  single held-card slot over a calibration proposal.

### The explanation (pull) path (`explainer.py`)

`Explainer.explain` (`:148`): `_facts_for` (`:243`) assembles a per-dimension
`EvidenceFacts` sheet from the same stores (defensive). If empty or no provider
→ deterministic floor (`_render_deterministic`, `:439`). If a provider exists,
it builds a JSON `user_prompt` of *sealed facts only* (`_build_user_prompt`,
`:215`) under a hard system prompt (`_SYSTEM_PROMPT`, `:107`: "use ONLY the
facts ... NEVER give advice"), and on any provider exception falls back to the
floor (`:198-209`). `build_default_explainer` (`:496`) gates the OpenAI provider
on `settings.semantic_provider == "openai"` and a key (`:515`); otherwise the
deterministic floor.

---

## Public API

Exported from `vigil/__init__.py:41-51`:

| Symbol | Defined | Used by |
|--------|---------|---------|
| `VigilEngine` | `engine.py:34` | `api/vigil_routes.py:33,281`; `main.py:1776` |
| `VigilSelection`, `ChosenUtterance`, `SelectorConfig`, `select` | `selector.py` | engine, efe; route maps `VigilSelection` to DTOs |
| `Explainer`, `Explanation`, `ExplanationMode`, `build_default_explainer` | `explainer.py` | `api/vigil_routes.py:33,435`; `main.py:1791`; `voice/voice_ask.py:41` |

Not in `__all__` but imported across the tree:
* `vigil.utterances.{UtteranceForm, fill}` → `voice/answer_forms.py:29`.
* `vigil.dimensions.ProofRef` → used inside `explainer.py`.
* `vigil.{causal, efe, learning, preference}` classes → injected in `main.py:1770-1773`.

---

## Wiring

### Wiring IN (who calls this unit)

```
tex.main.create_app
  ├─ main.py:1458  app.include_router(build_vigil_router())          # mounts /v1/vigil
  └─ main.py:1769-1786  builds the engine + ladder on app.state:
        PreferenceModel()                       (v3)  main.py:1775
        DirichletNormalLearner()                (v2)  main.py:1783
        ExpectedFreeEnergySelector()            (v4)  main.py:1786
        CausalAttributionPort(decision_store=…) (v5)  main.py:1786
        VigilEngine(learner=…, preference=…, efe_selector=…, causal_port=…)
        build_default_explainer()               (pull) main.py:1791
        CompositeHeldProvider([HeldDecisionVigilProvider, CalibrationProposalVigilProvider])
                                                       main.py:1710-1725
```

### LIVE call path (request → surprise → sentence)

```
HTTP GET /v1/vigil
  → api/vigil_routes.py:325  vigil()                      (RequireScope("decision:read"))
  → api/vigil_routes.py:332  _build_vigil_response(request, tenant)
  → api/vigil_routes.py:281  engine = app.state.vigil_engine; selection = engine.run(request, tenant)
  → vigil/engine.py:53       VigilEngine.run
        ├─ vigil/dimensions.py:330  read_dimensions(request, tenant)   → reads app.state stores
        ├─ vigil/preference.py:148  preference.learn_from_stores(...)   (v3 recalibration)
        ├─ vigil/causal.py:192      causal_port.attribute(readings)     (v5 sealed attribution)
        ├─ vigil/learning.py:186    learner.as_model(tenant)            (v2 live normal)
        ├─ vigil/efe.py:98          efe_selector.select(...)            (v4 policy selection)
        │      └─ vigil/conjugate.py:163  gamma_surprise / beta_surprise
        │      └─ vigil/utterances.py:150 fill(form, sealed_slots)
        └─ vigil/learning.py:151    learner.observe(reading)            (v2 predict-then-learn)
  → api/vigil_routes.py:289  held_decision_provider.current(tenant)     (human-decision channel)
  → api/vigil_routes.py:301  VigilResponse(...)                          (wire DTO)
```

Two further live entrypoints on the same router: `GET /v1/vigil/stream` (SSE,
`vigil_routes.py:338`, runs `_build_vigil_response` in the threadpool) and
`POST /v1/vigil/explain` (`vigil_routes.py:419` → `Explainer.explain`).

A **second live consumer** is `tex.voice` (router mounted `main.py:1459`):
`voice/answer_forms.py:29` imports `vigil.utterances.fill` (iron-rule sentence
filling) and `voice/voice_ask.py:41` imports `vigil.Explainer`.

### Wiring OUT (dependencies)

**Internal tex subsystems:**
* `tex.domain.verdict.Verdict` (`dimensions.py:218`, `explainer.py:257`) — verdict mix.
* `tex.domain.outcome.OutcomeLabel` (`preference.py:45`) — cost-model labels.
* `tex.api.agent_routes._build_governance` & resolvers (`dimensions.py:126`, `explainer.py:339`) — governance coverage. **A vigil → api back-reference.**
* `tex.config.get_settings` (`explainer.py:505`) — explainer provider gating.
* `tex.causal.attribution_engine.compute_attribution` (`causal.py:369,386`) — v5 root-cause (real module, confirmed at `causal/attribution_engine.py:680`).
* `tex.evidence.recorder.record_attribution`, `tex.evidence.scitt_cose_alg.cose_alg_for` (`causal.py:387-388`) — v5 strong-seal (real).
* `tex.evidence.signed_statement.mint_signed_statement` (`causal.py:399`) — **BROKEN import; module is actually `tex.evidence.scitt_statement`.** See Notable Findings.

**External libraries:**
* Stdlib only in the hot path: `math`, `hashlib`, `json`, `dataclasses`, `threading`, `enum`, `uuid`. **No NumPy/SciPy** — digamma is hand-rolled (`conjugate.py:54`).
* `openai` — optional, lazy-imported only inside `_openai_explainer.py:42`.
* `fastapi` / `pydantic` / `starlette` — in `api/vigil_routes.py`, not in the vigil package itself.

---

## Implementation Reality

**REAL (not stubs):**
* The full surprise pipeline runs end-to-end. Smoke test (PYTHONPATH=src):
  `gamma_surprise(Gamma(8,4), observe 20) ≈ 6.44 nats`; `digamma(1) = -0.577216`
  (= −γ, exact). Engine reports `capability()=="v5"` when fully injected.
* `conjugate.py` KLs are genuine closed-form expressions (not approximations) —
  `beta_surprise` (`:141`) and `gamma_surprise` (`:163`) use `lgamma`/`digamma`
  terms, clamped ≥ 0 for round-off only.
* v2 learner accumulation, safety-floor pinning, and sealable snapshot are real
  and thread-safe (`learning.py`, `RLock`).
* v3 cost-asymmetry threshold, normative floor, idempotent store folding — real
  (`preference.py`).
* v4 EFE policy selection with submodular collapse — real, with a genuine
  contract-preserving fallback to v1 (`efe.py:111`).
* v5 `CausalSeal` hash chain is real and verifies (smoke-tested). The provability
  gate genuinely refuses unsealed attributions (`causal.py:235-238`,
  `:277-278`).
* The explainer's deterministic floor is a real, fully-functional offline path
  (`explainer.py:439`); the OpenAI provider is a real graceful-fallback adapter,
  not a stub (`_openai_explainer.py`).

**STUBS / DEAD / INERT (flagged):**
1. **`learning` utterance is permanently silent** — `utterances.py:105`
   `speaks_when=lambda s: False`. By design (retired), but means the `_learning`
   dimension reading (`dimensions.py:297`) feeds the model of normal yet can
   *never* become a spoken line.
2. **v5 counterfactual machinery is unwired dead code.** `engine.py:78` only
   calls `causal_port.attribute()`. `CausalAttributionPort.counterfactual()`
   (`causal.py:244`), `CounterfactualClaim` (`:71`), and the two
   `*_counterfactual` authored forms (`utterances.py:110-121`) have **no caller
   anywhere** (grep across `src/tex` finds no `.counterfactual(` call and no use
   of `execution_counterfactual`/`identity_counterfactual`). Built, never wired.
3. **v5 "regulator-grade" COSE-signed seal path is dead** for two independent
   reasons: (a) a **broken import** — `causal.py:399` does
   `from tex.evidence.signed_statement import mint_signed_statement`, but no such
   module exists (it is `tex.evidence.scitt_statement`; `ModuleNotFoundError`
   confirmed). The error is swallowed by the broad `except` at `causal.py:412`,
   so the method silently returns `None` and falls back to the hash-chained
   ledger. (b) Even with the import fixed, `main.py:1786` constructs
   `CausalAttributionPort(decision_store=…)` **without** `evidence_recorder` or
   `signing_key_resolver`, so `_maybe_seal_decision_attribution` early-returns
   `None` at `causal.py:380` regardless. The COSE path is currently
   unreachable. (Every *other* symbol on that path — `record_attribution`,
   `mint_signed_statement`, `cose_alg_for`, `SignedStatement.envelope_cbor` —
   does exist with matching signatures, so the typo is the sole blocker.)
4. **No native crypto in this unit.** All hashing is `hashlib.sha256` (stdlib).
   The only "regulator-grade" signing is delegated out to `tex.evidence`, which
   is itself dead here per (3). The vigil's own seal needs no key.

No `NotImplementedError`, no `TODO`, no `pass`-only bodies in scope.

---

## Technology / SOTA

* **Bayesian surprise** = `D_KL(posterior || prior)` as the selection axis
  (information-theoretic "what changed my beliefs most"), a better ranking than
  severity. Two conjugate families cover everything: **Beta–Bernoulli** (rates /
  binary) and **Gamma–Poisson** (counts). Both KLs **closed form** — no
  sampling, no inference engine.
* **Stdlib-only digamma** via recurrence + asymptotic expansion
  (`conjugate.py:54`) — deliberate avoidance of a SciPy dependency.
* **Accumulating (non-windowed) conjugate priors** as a "model of normal"
  resistant to slow-drift gaming (`normal.py:5-9`).
* **Active inference / Expected Free Energy**: the v4 selector frames line
  selection as EFE minimization = epistemic (surprise) + pragmatic (VoI), and
  argues greedy + submodular collapse is exactly EFE-optimal given the causal
  structure (`efe.py:23-37`).
* **Decision-theoretic notification (VoI):** v3 calibrates the speak/stay-quiet
  threshold from revealed cost asymmetry rather than a hand-set constant
  (`preference.py`).
* **Append-only hash-chained ledger** (`record_hash = sha256(payload_sha256 +
  prev_hash)`) as a provability gate for causal claims (`causal.py:94`).
* **SCITT/COSE signed statements** referenced for the regulator-grade path
  (currently dead, see above).
* **SSE (Server-Sent Events)** for one-way server→client push of the chosen
  voice, with threadpool offload to avoid wedging the event loop
  (`vigil_routes.py:338-412` — the comment documents a fixed multi-minute wedge
  regression).
* **Ports-and-adapters / optional-collaborator** design pattern throughout: the
  engine consults injected rungs; absent ones leave v1 running.

---

## Persistence

**The vigil package owns no durable storage.** All durable state is read from
`app.state` stores (`scan_run_store`, `connector_health_store`,
`discovery_ledger`, `proposal_store`, `decision_store`, `outcome_store`) that
live in other subsystems.

In-process, transient state held *inside* vigil objects (lifetime = the app
process, lost on restart):
* `DirichletNormalLearner._gamma` — accumulated per-tenant/per-dimension counts
  (`learning.py:147`), guarded by `RLock`. Sealable via `snapshot_sha256()` but
  **not persisted** anywhere.
* `PreferenceModel._cost` + `_seen` — accumulated cost model and dedup set
  (`preference.py:99,103`).
* `CausalSeal._entries` / `_payloads` — the in-memory hash-chained attribution
  ledger (`causal.py:107-108`). **Not durable**; rebuilt empty each boot.

The v1 path is "stateless-per-cycle" (`engine.py:35`): `ModelOfNormal` is
recomputed from each reading's history every cycle. v2 makes "normal" live but
still only in memory.

---

## Notable Findings

1. **Scope label is wrong.** Vigil is *not* monitoring/alerting/watchdog. It is
   a Bayesian-surprise **selection/cognition** layer for "what Tex says." No
   loop, no scheduler, no alert sink in scope. (Documented up top.)

2. **Package docstring is stale / contradicted by `main.py`.**
   `__init__.py:14-15` and `engine.py:18-20` say *"v1 + v1.5 are live; v2-v5 are
   inert scaffolds."* In reality `main.py:1776-1786` injects **all five rungs**,
   and the live engine reports `capability()=="v5"`. The scaffolds were built
   *and wired* since those docstrings were written. Treat the "inert" claim as
   stale (claim, contradicted in code).

3. **Broken import quietly disables the v5 COSE-signed "regulator-grade" seal.**
   `causal.py:399` imports `tex.evidence.signed_statement` (nonexistent;
   correct module is `tex.evidence.scitt_statement`). The `ModuleNotFoundError`
   is caught by the broad `except` at `causal.py:412`, so the failure is
   invisible at runtime and the system silently degrades to the hash-chained
   ledger. **A one-line typo fix would re-enable it** (all other symbols on the
   path exist). This is a genuine latent bug.

4. **The entire counterfactual feature is dead code.** `CausalAttributionPort.
   counterfactual()`, `CounterfactualClaim`, and the `execution_counterfactual`
   / `identity_counterfactual` authored forms have no caller — `engine.py` only
   ever calls `.attribute()`. The "what would have happened" line that the
   docstrings (`utterances.py:107-121`, `causal.py:8`) describe is never
   produced by the running app.

5. **vigil → api back-reference.** Both `dimensions.py:126` and
   `explainer.py:339` import private helpers from `tex.api.agent_routes`
   (`_build_governance`, `_resolve_*`). A cognition layer reaching *up* into the
   API layer to compute governance coverage is an architectural smell (and a
   potential import-cycle risk), though it is wrapped in try/except and works.

6. **`learning` dimension can never speak.** `utterances.py:105`
   (`speaks_when=False`). Intentional (retired in favor of held-card calibration
   holds) but easy to misread — the dimension is read and fed into the model of
   normal, yet is structurally barred from becoming an utterance.

7. **Iron rule is genuinely enforced in code, not just documented.**
   `utterances.fill` (`:158-163`) raises rather than improvising a missing slot;
   the explainer feeds the LLM *only* sealed-fact JSON (`explainer.py:215`)
   under a hard "use ONLY these facts / never advise" system prompt. The
   prompt-injection fence ("a watched agent cannot reach Tex's mouth") is real
   in the sense that no unsealed text path reaches either the form filler or the
   provider prompt.

8. **Math is correct, not hand-wavy.** `digamma(1) = −γ` and a sane KL value
   were both verified by direct execution. The closed-form KLs and the conjugate
   updates are standard and correctly parameterized (shape/rate for Gamma).

9. **All persistence is volatile.** The "auditable evolution of normal"
   (`learning.py` snapshot) and the causal seal ledger (`causal.py`) are
   sealable/verifiable but never written to disk — they reset every boot. The
   durable evidence lives in the *other* subsystems' ledgers, not here.

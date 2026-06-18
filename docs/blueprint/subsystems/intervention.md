# Subsystem Dossier — Intervention / Commands / Operator

> Scope: `src/tex/intervention/`, `src/tex/commands/`, `src/tex/operator/`
> Branch: `feat/proof-carrying-gate`
> Method: code read + import/call-site tracing. Every load-bearing claim is cited `file:line`. `.md`/docstring claims are labelled **(claim, unverified)** unless confirmed in code.

---

## Overview

This dossier covers three directories that the orchestration script grouped together because they sit at the "execution-governance / use-case" altitude. In reality they are **three independent units with very different wiring statuses**:

1. **`commands/`** — CQRS-style application-service command handlers (`EvaluateActionCommand`, `ReportOutcomeCommand`, `ActivatePolicyCommand`, `CalibratePolicyCommand`, `ExportBundleCommand`). **This is the most live code in the entire Tex application.** `EvaluateActionCommand.execute()` is the single hot-path function behind `POST /evaluate`. Constructed in `tex.main.build_runtime` and bound to `app.state`, invoked from `tex.api.routes`. Status: **LIVE**.

2. **`intervention/`** — the AAF "bounded-compromise" cost-bounded steering layer (Step 8 of the ecosystem pipeline): a real implementation of Theorem 5 from arxiv 2512.18561, plus AIR-style eradication-rule synthesis, Neyman-Pearson multi-monitor selection, and a restorative-path executor. The math is **real and unit-tested**, but the production runtime **never wires it in**: `tex.main` builds the `EcosystemEngine` *without* an `intervention_calc`, so the engine's `self._intervention_engine is None` and Step 8 is a no-op at runtime. Status: **MIXED** — `kinds` is imported on a live path; the engine/calculator are reachable-but-dormant; eradication / neyman_pearson / restorative are **test-only**.

3. **`operator/`** — a Kubernetes control-plane component: an `EnrollmentController` (namespace watch → governed-set reconciliation) + a `SidecarInjector` MutatingAdmissionWebhook that injects the `tex.pep` enforcement proxy into pods of governed namespaces. It is a **separate process** (`python -m tex.operator`, deployed by `deploy/helm/tex/templates/operator.yaml:16`), **not** reachable from `tex.main`/`build_runtime`/API routes. Status from the Python-app spine: **ORPHAN**; status as a deployable artifact: real and Helm-wired.

The combined verdict is therefore `MIXED`: one unit is the live hot path, one is real-but-dormant math, one is a real-but-out-of-process control plane.

---

## File Inventory

| File | LOC | Role |
|---|---|---|
| **commands/** | | |
| `commands/__init__.py` | 11 | Layer marker only (`__layer__=4`, `execution_governance`); no re-exports. |
| `commands/evaluate_action.py` | 1199 | `EvaluateActionCommand` — THE evaluation hot path. Resolves policy → runs PDP → validates alignment → persists decision/evidence/precedent/action-ledger → optional ecosystem pass → tenant-baseline. |
| `commands/report_outcome.py` | 172 | `ReportOutcomeCommand` — records observed outcomes vs prior decisions, classifies, optional learning-orchestrator routing + evidence. |
| `commands/activate_policy.py` | 59 | `ActivatePolicyCommand` — activates a policy version; returns before/after. |
| `commands/calibrate_policy.py` | 153 | `CalibratePolicyCommand` — summarizes classified outcomes → calibrator recommendation → optional new policy snapshot save/activate. |
| `commands/export_bundle.py` | 212 | `ExportBundleCommand` — thin wrapper over `EvidenceExporter`: full/JSONL/filtered evidence-bundle export. |
| **intervention/** | | |
| `intervention/__init__.py` | 105 | Package re-exports (28 symbols); `__layer__=4`. Imports all submodules. |
| `intervention/kinds.py` | 41 | `InterventionKind` enum (8 kinds) + frozen `Intervention` dataclass. |
| `intervention/engine.py` | 623 | `InterventionEngine` — Step-8 selector/applicator; `select()` (lowest-cost satisfying the bound), `apply()` (cert + signed governance-log append), eradication branch, `air_phase_for()`. |
| `intervention/bounded_compromise.py` | 479 | `BoundedCompromiseCalculator` + `CompromiseCertificate` — AAF Theorem 5 math (eta*, lambda_min, welfare bound), g_max estimator. |
| `intervention/eradication.py` | 526 | `EradicationRuleSynthesizer` (LLM + deterministic modes), `IncidentContext`, `SynthesizedRule`, `InMemoryRuleRegistry`, `RuleRegistry`/`LLMClient` protocols. |
| `intervention/neyman_pearson.py` | 387 | `NeymanPearsonSelector` (greedy Lagrangian monitor-portfolio knapsack), `MonitorPortfolio`, `PortfolioSelection`, `compose_intervention_pool()`. |
| `intervention/restorative.py` | 298 | `RestorativePathExecutor` — walks a manifest restorative path, emits ordered signed records, transitions institutional state. |
| **operator/** | | |
| `operator/__init__.py` | 45 | Label constants (`GOVERN_LABEL`, `GOVERN_ENABLED`, `TENANT_LABEL`, `EXCLUDE_LABEL`); package docstring. |
| `operator/__main__.py` | 81 | `python -m tex.operator` entrypoint: `build_app()` (webhook + `/scope`), `main()` (controller thread + uvicorn). |
| `operator/controller.py` | 101 | `EnrollmentController` — framework-agnostic `reconcile_event`/`resync` core + import-guarded K8s list-watch `run()` driver. |
| `operator/scope.py` | 95 | `EnrollmentScope` (thread-safe governed-namespace set), `GovernedNamespace`, `is_namespace_governed()`. |
| `operator/webhook.py` | 225 | `SidecarInjector`: `should_inject`, `injection_patch` (init+sidecar JSONPatch), `build_admission_response`, `build_webhook_app` (Starlette `/mutate`,`/healthz`). |

---

## Internal Architecture

### commands/evaluate_action.py — the hot path

`EvaluateActionCommand` (`commands/evaluate_action.py:88`) is a `__slots__`-based application service constructed with up to 11 collaborators (`commands/evaluate_action.py:132-185`): a `PolicyDecisionPoint`, four `InMemory*` stores, an evidence recorder, action ledger, agent registry, tenant baseline, and three **optional** wiring hooks — `memory_system`, `provenance_feed`, `ecosystem_bridge`.

`execute(request)` (`commands/evaluate_action.py:187`) is the single function behind `POST /evaluate`. Control flow:

1. **Resolve policy** (`_resolve_policy`, `:556`) — explicit `policy_id` else active policy. Stamps the registry audit context with `policy.version` (`:200-210`) and always clears it in `finally` (`:354-363`).
2. **Auto-register the agent** (`_ensure_controlled_agent_registered`, `:365`) — derives a stable UUID5 from the agent fingerprint (namespace `AGENT_IDENTITY_NAMESPACE`, `:36`), registers/upgrades the agent as `visibility_status="controlled"`. This is the "every adjudication is a discovery signal" mechanic.
3. **Run the PDP** (`self._pdp.evaluate`, `:214`) → `PDPResult`.
4. **Validate alignment** (`_validate_pdp_alignment`, `:581`) — hard `ValueError`s if request_id/policy_version/decision_id/verdict/confidence/final_score don't agree across request, policy, decision and response (`:594-617`). This is the integrity spine.
5. **Persist** — two branches (`:241-289`):
   - **MemorySystem path** (production wiring): `memory_system.record_decision_with_policy(...)` writes decision+input+policy in one transaction, then evidence chain, then mirror; back-propagates `evidence_hash` onto the frozen response via `model_copy` (`:255`).
   - **Legacy path** (tests): `decision_store.save()` + `evidence_recorder.record_decision(...)`.
   Both branches call `_record_contract_violation_evidence` (`:796`) to emit per-violation addressable evidence rows linked by `parent_evidence_hash`.
6. **Optional ecosystem pass** (`_maybe_apply_ecosystem`, `:904`) — see below.
7. **Action-ledger append** (`_record_action_ledger_entry`, `:1069`) — only when `request.agent_id` is set; folds capability violations + ASI short codes into an `ActionLedgerEntry`.
8. **Continuous provenance** (`:337-341`) — `provenance_feed.note_action(agent_id)`, wrapped so it can never break the verdict.
9. **Tenant baseline** (`_update_tenant_baseline`, `:1148`) — appends a content-signature record only on PERMIT + agent-attached decisions (`:1176`), resolving tenant from the registry to prevent spoofing.

Two notable embedded sub-mechanics:

- **SCITT refusal receipts** (`_build_refusal_context`, `:748`): on `Verdict.FORBID` only, builds a `ScittRefusalEvent` (`event_type=REFUSAL_EVENT_PRE_GENERATION`) carrying the decision's own reasons as rationale, mapping a finding token to a SCITT risk category when one matches `ALL_RISK_CATEGORIES` (`:771-776`), else `RISK_OTHER`. Passed as `c2pa_context` to the recorder.
- **TEE composite attestation** (`_build_evidence_metadata`, `:677`): gated on `os.environ["TEX_TEE_MODE"]=="1"`; lazily imports `tex.tee.compose_attestation` and attaches a hardware-rooted JWT to the evidence metadata; failures are recorded as a metadata flag, never blocking (`:688-695`).

**Ecosystem pass** (`_maybe_apply_ecosystem`, `:904`): the bridge to the intervention layer's home, the `EcosystemEngine`. Three-way gate (`:957-965`): `bridge is None` → return unchanged; `TEX_ECOSYSTEM != "1"` → return unchanged (no engine call); otherwise auto-register the actor in the ecosystem graph (`:981-997`) and call `bridge.emit_verdict(...)` (`:999`). The returned `EcosystemVerdict.axis_scores` (six axes incl. `bounded_compromise_score`) are projected into `response.scores` under the `ecosystem.*` namespace (`:1028-1049`), clamped to `[0,1]`, and the GAAT level is published as an `ecosystem_graduated_level:<value>` uncertainty flag (`:1057-1060`). All failures fall back to the legacy response (`:1005-1010`).

### commands — the other four

All four are thin, frozen-result application services:

- `ReportOutcomeCommand.execute` (`report_outcome.py:80`): resolves the referenced decision (`:118`), validates `outcome.request_id == decision.request_id` (`:126-138`), then either routes through a learning `orchestrator.ingest_outcome` (`:92`) or saves directly, classifies via `classify_outcome` (`:98`), optional evidence.
- `ActivatePolicyCommand.execute` (`activate_policy.py:37`): captures previous active, calls `policy_store.activate(version)`, translates `KeyError`→`LookupError`.
- `CalibratePolicyCommand.execute` (`calibrate_policy.py:57`): `summarize_outcomes` → `calibrator.recommend` → optional `apply_recommendation` + `policy_store.save`/`activate`. Enforces `activate ⇒ save` (`:88`).
- `ExportBundleCommand` (`export_bundle.py:79`): validates the exporter implements `BundleCapableExporter` (`:95`), delegates `export_json`/`export_jsonl`/`export_filtered_json`; for filtered exports it re-verifies the chain via `tex.evidence.chain.verify_evidence_chain` (`:189-199`).

### intervention/ — the AAF bounded-compromise layer

**`kinds.py`** — `InterventionKind` (`kinds.py:18`) is an 8-member str-enum: `CAPABILITY_REVOKE`, `TRUST_SCORE_REDUCE`, `REWARD_SHAPE`, `POLICY_PATCH`, `HUMAN_APPROVAL_GATE`, `QUARANTINE`, `RESTORATIVE_PATH`, `ERADICATION_RULE_SYNTHESIS`. `Intervention` (`:33`) is a frozen/slots dataclass carrying `expected_cost_to_system` and `expected_cost_to_adversary` (the two cost fields the bound consumes).

**`bounded_compromise.py`** — the mathematical kernel. `BoundedCompromiseCalculator` (`:106`):
- `estimate_adversary_payoff(drift_signals)` (`:190`) maps drift → g_max, preferring `abc_drift_d_star` (Bhardwaj ABC D*) then `bocpd_run_length_posterior`, falling back to raw `drift_delta`, taking the **max** of recognized signals as a deterrent over-estimate (`:255-257`); returns `fallback_g_max` (0.5) when no signal present.
- `satisfies_bound(...)` (`:261`) — the strict-dominance check `lambda*H - g_max >= epsilon` (`:307-311`). Both inputs are **window-aggregated**, not per-step.
- `long_run_compromise_ratio_from_window(...)` (`:313`) — `eta* = alpha*H / (lambda*H - g_max)`, returns the `_VACUOUS_BOUND_RATIO=1.0` sentinel (`:77`,`:329`) when slack ≤ 0.
- `compute_minimum_penalty(...)` (`:397`) — implements `lambda_min = g_max/H + alpha/eta*`, **deliberately diverging from the paper's printed formula** `(g_max + alpha*H)/(H*eta*)`, with an in-code rationale that the printed form doesn't algebraically rearrange Theorem 5 (`:401-412`). This is a genuine, documented correction, not a stub.
- `certify(...)` (`:431`) — assembles a `CompromiseCertificate` (`:80`) with eta*, lambda_min, slack, and a clamped welfare-shortfall upper bound (`:456-467`).

**`engine.py`** — `InterventionEngine` (`:117`):
- `select(...)` (`:161`) — FAIL-CLOSED selector: estimates g_max, sorts candidates ascending by `(cost_to_system, intervention_id)` (`:247-250`), returns the first candidate that both `satisfies_bound` and yields `eta <= target_max_compromise_ratio` (`:252-293`); returns `None` on empty set, calc error, or no satisfier. Every branch emits telemetry.
- `apply(intervention)` (`:306`) — builds a fresh certificate at apply time using the prior g_max, runs the eradication branch when `kind == ERADICATION_RULE_SYNTHESIS` (`:380-393`), composes a structured payload (`_build_log_payload`, `:555`) carrying the full certificate + AIR phase tag, and appends via `self._ledger.record_observation(...)` (`:425`). Raises `InterventionApplyError` (FAIL-CLOSED) on certify/eradication/ledger failure. Returns `None` when no ledger is wired.
- `_eradicate_apply` (`:452`) — pulls `incident_context` from intervention params, constructs an `IncidentContext`, calls `synthesizer.synthesise(...)` + `registry.register(...)`, returns a serializable rule dict or `None` (FAIL-CLOSED). Lazily imports `IncidentContext` (`:484`).
- `air_phase_for(kind)` (`:94`) — maps each kind to an AIR lifecycle phase via `_KIND_TO_PHASE` (`:78-87`): HUMAN_APPROVAL_GATE→`hold`, RESTORATIVE_PATH→`recover`, ERADICATION→`eradicate`, everything else→`contain`. **This is the "hold/intervention" semantics referenced in the task context** — there is no separate "hold queue"; "hold" is the AIR phase tag for the human-approval-gate kind. Verified: `air_phase_for(HUMAN_APPROVAL_GATE) == "hold"`.

**`eradication.py`** — `EradicationRuleSynthesizer` (`:159`) is genuinely two-mode:
- LLM mode (`_synthesise_via_llm`, `:278`) — calls an injected `LLMClient.generate_rule_json`, parses JSON, builds a `SynthesizedRule`. Best-effort: a failing/rejected LLM rule falls through to deterministic mode (`:226-237`).
- Deterministic mode (`_synthesise_deterministic`, `:316`) — **always available**, no external dependency; builds a forbid-rule from `(actor, event_kind, payload_fingerprint[:12])`, severity climbing with `contract_violation_severity >= 0.7` (`:325`).
- `_run_checks` (`:396`) — schema/safety/cost gate: non-empty rule_id, non-empty forbidden kinds, valid severity, predicate-count ≤ 10 and ltlf-depth ≤ 6 (`:419-429`). Returns `None` (FAIL-CLOSED) on any failure.
- `InMemoryRuleRegistry` (`:449`) — append-only dict registry with idempotent `register` (`:462`) and a `matches(actor,event_kind,payload)` predicate evaluator (`:485`). A `RuleRegistry` Protocol (`:514`) keeps the Postgres swap mechanical **(claim, unverified — no Postgres registry exists in this tree)**.

**`neyman_pearson.py`** — `NeymanPearsonSelector.select_portfolio` (`:181`): greedy Lagrangian knapsack over monitors. For each monitor computes utility `log(LR) - lambda*cost` (`:230-231`), sorts descending, accepts while utility>0, cost fits the budget, and the union-bound composite false-alarm stays ≤ alpha (`:244-273`). Composite detection = `1 - prod(1 - P_d_i)` under an independence assumption (`:275`). `compose_intervention_pool` (`:332`) dedupes candidate interventions by `intervention_id` across selected monitors.

**`restorative.py`** — `RestorativePathExecutor.execute(path_id, target_entity_id)` (`:93`): (a) looks up the path via `governance_graph.lookup_restorative_path` (`:146`), (b) appends a header record + one ordered signed record per `restorative_event_kind` (`:179-215`), (c) transitions the in-memory `institutional_states[target] = target_legal_state_id` and verifies it (`:223-248`). Returns `True` only if all three clauses hold; FAIL-CLOSED to `False` otherwise.

### operator/ — the K8s control plane

- `EnrollmentScope` (`scope.py:40`) is a thread-safe (`RLock`) governed-namespace map. A namespace is governed iff `tex.systems/govern=enabled` (`is_namespace_governed`, `scope.py:34`); tenant defaults to the namespace name unless `tex.systems/tenant` is set (`_tenant_for`, `scope.py:29`). `to_jsonable()` (`scope.py:90`) is what `/scope` serves to node agents.
- `EnrollmentController` (`controller.py:24`): `reconcile_event(type, ns, labels)` (`:30`) applies one watch verb to the scope; `resync(snapshot)` (`:47`) replaces the whole set; `run()` (`:54`) is the import-guarded K8s list-then-watch loop (raises a clear error if the `kubernetes` lib is absent, `:60-66`).
- `webhook.py`: `should_inject` (`:55`) gates on namespace-governed ∧ not opted-out (`tex.systems/govern-exclude`) ∧ not already injected. `injection_patch` (`:125`) builds a JSONPatch adding an iptables-redirect init container (`_init_container`, `:108`, needs `NET_ADMIN`/`NET_RAW`) and the `tex-proxy` sidecar running `python -m tex.pep` (`_proxy_container`, `:77`), with pod identity from the downward API (`TEX_AGENT ← metadata.name`, `:90-92`). `build_admission_response` (`:159`) always allows, patches when injection applies. `build_webhook_app` (`:195`) is a Starlette app exposing `POST /mutate` + `GET /healthz`.

---

## Public API

**commands/** (consumed by `tex.main` + `tex.api`):
- `EvaluateActionCommand`, `EvaluateActionResult` (+ `DecisionEvidenceRecorder`, `DecisionPrecedentStore` protocols)
- `ReportOutcomeCommand`, `ReportOutcomeResult`, `OutcomeEvidenceRecorder`
- `ActivatePolicyCommand`, `ActivatePolicyResult`
- `CalibratePolicyCommand`, `CalibratePolicyResult`
- `ExportBundleCommand`, `ExportBundleResult`, `BundleCapableExporter`

**intervention/** (`__init__.py:76-105`, 28 symbols): `InterventionEngine`, `InterventionApplyError`, `InterventionSelectionError`, `air_phase_for`, `BoundedCompromiseCalculator`, `CompromiseCertificate`, `EradicationRuleSynthesizer`, `IncidentContext`, `SynthesizedRule`, `InMemoryRuleRegistry`, `RuleRegistry`, `LLMClient`, `RuleSynthesisError`, `NeymanPearsonSelector`, `MonitorPortfolio`, `PortfolioSelection`, `MonitorCandidateSource`, `compose_intervention_pool`, `RestorativePathExecutor`, `Intervention`, `InterventionKind`, plus DEFAULT_* tuning constants. **Note:** live consumers import submodules directly, not this package `__init__`.

**operator/**: label constants (`__init__.py`); `EnrollmentScope`/`GovernedNamespace`/`is_namespace_governed` (`scope.py`); `EnrollmentController` (`controller.py`); `should_inject`/`injection_patch`/`build_admission_response`/`build_webhook_app`/`InjectorConfig` (`webhook.py`); `build_app`/`main` (`__main__.py`).

---

## Wiring

### Wiring In — commands (LIVE)

Live call path for the evaluation hot path:

```
uvicorn tex.main:app                          (deploy/helm/tex/templates/pdp.yaml:37)
  → tex.main.create_app → build_runtime
      → EvaluateActionCommand(...)            tex/main.py:962
      → app.state.evaluate_action_command     tex/main.py (runtime bound, see :1690-1698 for ecosystem siblings)
  → POST /evaluate handler                    tex/api/routes.py:117 evaluate_action(...)
      → _get_evaluate_action_command(request) tex/api/routes.py:124,581
      → command.execute(domain_request)       tex/api/routes.py:128
```

The other four commands are bound and routed identically: constructed at `tex/main.py:1036` (report_outcome), `:1043` (activate), `:1047` (calibrate), `:1053` (export); imported and dispatched at `tex/api/routes.py:24-28` and used at `routes.py:404/408` (outcome), `442/445` (activate), `482/485` (calibrate), `526` (export). `EvaluateActionResult`/etc. are also imported by `tex/api/schemas.py:10-14`.

A **second live entry** into `EvaluateActionCommand` exists via the PEP transport: `tex/enforcement/transport.py:29` imports it, and `DirectCommandTransport.evaluate` calls `self._command.execute(request)` (`transport.py:88`) — the in-process PEP path.

### Wiring In — intervention (MIXED: imported live, executed never)

- `tex/ecosystem/engine.py:87` imports `InterventionKind` at module top-level (so `intervention.kinds` *is* on a live import path whenever the ecosystem engine module loads, which `tex.main` does at `main.py:83`).
- `tex/ecosystem/engine.py:393-402` constructs an `InterventionEngine` **only if `intervention_calc is not None`**.
- **The live runtime never passes `intervention_calc`.** `tex/main.py:946` constructs `EcosystemEngine(ontology=..., graph=..., projection=..., events=..., provenance=..., contracts=...)` with **no `intervention_calc` and no `candidate_interventions`** arguments. Therefore `self._intervention_engine is None` (`engine.py:402`) and the entire Step-8 block (`engine.py:955-1124`) is skipped at runtime.
- Even the `EcosystemEngine.evaluate()` itself only runs when `TEX_ECOSYSTEM=1` (`engine.py:490-506` short-circuits to an inert PERMIT otherwise), and the bridge only fires from `EvaluateActionCommand` under the same flag (`evaluate_action.py:961`).

Net: the intervention **engine/calculator/restorative are reachable code that is never exercised by the running app**; `eradication`, `neyman_pearson`, `compose_intervention_pool`, `InMemoryRuleRegistry`, `NeymanPearsonSelector`, `RestorativePathExecutor`, `EradicationRuleSynthesizer` are constructed **only in `tests/`** (verified repo-wide: `tests/intervention/*`, `tests/test_integration_layer.py:2727,2874,2880`). No production code constructs any of them.

Other references to `tex.intervention` are **docstrings/TODOs only** (not imports): `contracts/violation.py:10`, `contracts/runtime_enforcement.py:54,227`, `institutional/sanctions.py:54,80`, `institutional/controller.py:19` — all "P2; deferred to tex.intervention" prose, no call.

### Wiring In — operator (ORPHAN from the Python app; LIVE as a K8s artifact)

- **No Python module in `src/tex` imports `tex.operator`** except a single docstring mention in `enforcement/__init__.py:35` ("auto-injected by `tex.operator`") — not an import.
- The operator runs as its **own process**: `deploy/helm/tex/templates/operator.yaml:16` sets `command: ["python", "-m", "tex.operator"]`, fronted by a Service (`operator.yaml:32`), a `MutatingWebhookConfiguration` pointing at `/mutate` (`deploy/helm/tex/templates/webhook.yaml:27-29`), RBAC for namespace watch (`deploy/helm/tex/templates/rbac.yaml`), and a cert-manager TLS secret (`webhook.yaml:42-48`).
- There is **no `[project.scripts]`/console_scripts** entry and **no `[operator]` extra** declared in `pyproject.toml` (grep returned nothing), despite the controller's error message advising "install tex with the `[operator]` extra" (`controller.py:64-65`) — see Notable Findings.

So from the spine BFS (which traces the `tex.main` Python app) the operator is correctly **ORPHAN**; from a deployment standpoint it is a real, wired admission webhook + namespace controller. This dossier records `wired_status=MIXED` to capture both facts (commands LIVE, intervention reachable-but-dormant, operator app-orphan).

### Wiring Out — dependencies

**commands** → `tex.domain.*` (agent, decision, evaluation, evidence, policy, tenant_baseline, verdict, outcome), `tex.engine.pdp` (`PolicyDecisionPoint`/`PDPResult`), `tex.stores.*` (action_ledger, agent_registry, decision_store, policy_store, precedent_store, tenant_content_baseline, outcome_store), `tex.evidence.*` (c2pa_emitter, exporter, chain), `tex.learning.*` (calibrator, outcomes), and lazily `tex.tee.compose_attestation` (TEE-mode-gated). External libs: stdlib only (`logging`, `os`, `uuid`, `datetime`, `dataclasses`, `pathlib`); pydantic via the domain models (`model_copy`/`model_dump`).

**intervention** → `tex.observability.telemetry.emit_event` (every module), `tex.institutional.governance_log.GovernanceLog` (duck-typed `record_observation`, never hard-imported), `tex.institutional.governance_graph.GovernanceGraph` (duck-typed `lookup_restorative_path`). External libs: stdlib only (`math`, `hashlib`, `json`, `datetime`, `dataclasses`, `enum`, `typing.Protocol`). No numpy/scipy — the Neyman-Pearson and AAF math is pure-Python.

**operator** → `starlette` (webhook app), `uvicorn` (`__main__`), `kubernetes` (import-guarded, controller driver only), and `tex.pep` (referenced as the injected sidecar command string, not imported). No `tex.observability` — the operator does not emit Tex telemetry (verified: no `emit_event` in `operator/`).

---

## Implementation Reality

| Component | Reality | Evidence |
|---|---|---|
| `EvaluateActionCommand.execute` | **REAL** — full PDP→persist→evidence→ledger→ecosystem→baseline pipeline; the live hot path. | `evaluate_action.py:187-353` |
| `_validate_pdp_alignment` | **REAL** — six hard cross-field equality checks. | `evaluate_action.py:594-617` |
| SCITT refusal receipts | **REAL**, FORBID-gated. | `evaluate_action.py:748-794` |
| TEE attestation | **REAL but env-gated** (`TEX_TEE_MODE=1`), lazy-imported, failure-isolated. | `evaluate_action.py:677-695` |
| Ecosystem fold-in | **REAL but env-gated** (`TEX_ECOSYSTEM=1`); inert otherwise. | `evaluate_action.py:957-1067` |
| Report/Activate/Calibrate/Export commands | **REAL**, thin delegators. | respective files |
| `BoundedCompromiseCalculator` | **REAL math**, Theorem-5 faithful, with a *documented correction* to the paper's `lambda_min`. Unit-tested. | `bounded_compromise.py:397-429` |
| `InterventionEngine.select/apply` | **REAL** but dormant in prod (never constructed with a calc). FAIL-CLOSED throughout. | `engine.py:161-448`; dormancy: `main.py:946`, `engine.py:402` |
| `EradicationRuleSynthesizer` | **REAL** two-mode; deterministic mode has no external dep. **Test-only** wiring. | `eradication.py:159-430` |
| `NeymanPearsonSelector` | **REAL** greedy Lagrangian. **Test-only** wiring. | `neyman_pearson.py:181-312` |
| `RestorativePathExecutor` | **REAL** mechanical executor (in-memory state). **Test-only** wiring. | `restorative.py:93-258` |
| `InMemoryRuleRegistry` | **REAL** in-memory; Postgres variant is a **(claim, unverified)** future. | `eradication.py:449-511` |
| operator webhook + controller | **REAL** — produces valid K8s JSONPatch + admission response; K8s driver import-guarded. | `webhook.py:125-187`, `controller.py:54-101` |

**No `NotImplementedError`, no `raise NotImplemented`, no bare `pass`-only bodies, no `TODO`-blocked logic** were found inside the three scope directories. The only `TODO(P2)` strings live *outside* the scope (in `contracts/`). The "stub" character of the intervention layer is **wiring dormancy**, not hollow code — the logic is complete and tested; the production app simply never calls it.

The crypto/signing in this unit is **delegated, not implemented here**: `InterventionEngine.apply` and `RestorativePathExecutor` emit records via a duck-typed `ledger.record_observation`, and the docstrings say signing routes through `tex.pqcrypto.algorithm_agility` via `GovernanceLog` (`engine.py:34-39`) — **(claim, unverified in this unit; the signing lives in `tex.institutional`/`tex.pqcrypto`, out of scope here)**. Within scope there is no native-vs-pure-python crypto fork to assess.

---

## Technology / SOTA

- **AAF bounded-compromise (arxiv 2512.18561 v3, Theorem 5 / Proposition 1)** — `eta* = alpha*H / (lambda*H - g_max)` with strict-dominance slack epsilon; the certificate is designed to let an external auditor *reconstruct the math offline* from a signed log record (`bounded_compromise.py:80-103`, `engine.py:597-615`). The code knowingly diverges from the paper's printed `lambda_min` formula with an algebraic justification (`bounded_compromise.py:401-412`).
- **AIR incident-response lifecycle (arxiv 2602.11749)** — detect/contain/recover/eradicate; the `air_phase_for` mapping tags each intervention so AIR-compatible tooling can join (`engine.py:65-96`). Eradication-rule synthesis (LLM + deterministic) is the "eradicate" phase.
- **Neyman-Pearson multi-monitor selection (arxiv 2507.15886, Hua et al., NeurIPS 2025)** — Lagrangian relaxation of the cost-constrained monitor knapsack: include monitor m iff `log(LR_m) - lambda*cost_m > 0`, with a union-bound composite-false-alarm cap (`neyman_pearson.py:190-273`).
- **Restorative justice / sanction ladder (arxiv 2601.11369)** and **embodied-agent recovery benchmarks (arxiv 2604.07833 v2)** — cited for the restorative executor (`restorative.py:1-35`).
- **CQRS / application-service pattern** — each command is a single-responsibility service over injected stores; results are frozen dataclasses; `__slots__` throughout `commands/`.
- **Ambient/ztunnel-style auto-enrollment** — label-driven governance (`tex.systems/govern=enabled`) + MutatingAdmissionWebhook sidecar injection, the istio-init iptables-REDIRECT pattern (`webhook.py:108-122`). This is a faithful K8s service-mesh control-plane design.

---

## Persistence

- **commands**: no state of its own; everything is delegated. Durability comes from the injected `memory_system` (Postgres transaction path, `evaluate_action.py:246`) or the in-memory legacy stores. Action ledger, precedent, tenant baseline, evidence chain, and outcome store are all external collaborators.
- **intervention**: the engine and restorative executor are **stateless**; durability is the injected `ledger` (`GovernanceLog`), to which they append signed observation records. `InMemoryRuleRegistry` (`eradication.py:449`) and `RestorativePathExecutor`'s `institutional_states` dict (`restorative.py:91`) are **in-memory only**; both are documented as awaiting Postgres backing **(claim, unverified)**.
- **operator**: `EnrollmentScope` is an **in-memory, process-local, thread-safe** dict (`scope.py:45`). There is no persistence — the scope is the live projection of cluster namespace labels, reconciled by the controller on every restart via list-then-watch (`controller.py:83-98`). This is correct for a K8s controller (the cluster is the source of truth).

---

## Notable Findings

1. **Intervention Step 8 is real code that the running app never executes.** `tex/main.py:946` builds `EcosystemEngine` without `intervention_calc`/`candidate_interventions`, so `self._intervention_engine is None` (`engine.py:402`) and the entire Step-8 selection/apply block (`engine.py:955-1124`) is dead at runtime. The unit's docstrings repeatedly claim "Priority: P2 (live)" (`engine.py:49`, `bounded_compromise.py:57`, `restorative.py:35`) — **this "live" is an overstatement relative to the production wiring**; the honest status is "implemented + unit-tested, not wired into the running pipeline." The ecosystem engine's own pipeline comment is more accurate: "Step 8 — intervention selection ... [pending]" (`engine.py:466`) and "(P2 stub)" (`engine.py:17`).

2. **Eradication / Neyman-Pearson / Restorative are test-only.** Repo-wide construction grep shows these classes are instantiated **exclusively** under `tests/` (e.g. `tests/intervention/test_engine.py`, `test_neyman_pearson.py`, `test_bounded_compromise.py`, `tests/test_integration_layer.py:2727,2874`). No `src/tex` production module ever constructs `EradicationRuleSynthesizer`, `NeymanPearsonSelector`, `compose_intervention_pool`, or `RestorativePathExecutor`. The spine classification `intervention=LIVE` is true only in the weak sense that `intervention.kinds.InterventionKind` is imported at `ecosystem/engine.py:87`; the substantive logic is not on any live call path.

3. **`lambda_min` deviates from the cited paper — on purpose, and documented.** `compute_minimum_penalty` implements `g_max/H + alpha/eta*` rather than the paper's printed `(g_max + alpha*H)/(H*eta*)`, with an in-code algebraic justification and a pointer to `FRONTIER_DELTA_thread_8.md §10` **(cross-ref claim, unverified)**. This is a genuine correctness call, not a bug, and is the kind of thing an auditor should know.

4. **Operator advertises a `[operator]` pip extra that does not exist.** `controller.py:64-65` raises `"install tex with the [operator] extra"` when the `kubernetes` lib is missing, but `pyproject.toml` declares no such extra and no `[project.scripts]` entry (grep empty). The operator is invoked purely as `python -m tex.operator` from the Helm Deployment (`operator.yaml:16`). The error message is misleading.

5. **Operator is a control-plane process, not an application import.** Grouping it with `commands`/`intervention` under one "operator surface" header is slightly misleading: it shares no runtime with the PDP application. Its only link to the rest of Tex is the *string* `python -m tex.pep` it injects as a sidecar (`webhook.py:81`) and the `/scope` JSON the eBPF DaemonSet polls. The init container requires `NET_ADMIN`/`NET_RAW` and rewrites pod egress via iptables (`webhook.py:113-121`) — a real privilege the blueprint should flag for security review.

6. **"operator surface" in the task context ≠ this `operator/` package.** The task framing ("operator surface, intervention/hold mechanics") suggests a human-operator approval/hold queue. There is **no such queue** in scope. "hold" is purely the AIR phase string returned by `air_phase_for(HUMAN_APPROVAL_GATE)` (`engine.py:71,83`), and `operator/` is the *Kubernetes operator*, not a human-operator console. The two senses of "operator" collide in the directory grouping; the code contains neither a hold queue nor a human-operator UI here.

7. **`commands/__init__.py` exports nothing.** It is a pure layer marker (`__init__.py:9-10`); all command classes are imported by fully-qualified submodule path. Harmless, but means `from tex.commands import EvaluateActionCommand` would fail — callers use `from tex.commands.evaluate_action import ...` (confirmed at `main.py:33-37`, `api/routes.py:24-28`).

8. **No dead `NotImplementedError`/`pass`-stubs anywhere in scope.** The crypto-reality concern from the spine pass does not apply to this unit: there is no crypto implemented here at all (signing is delegated to the governance log / pqcrypto, out of scope). The FAIL-CLOSED discipline (return `None`/`False`, raise `*ApplyError`) is consistently real, not placeholder.

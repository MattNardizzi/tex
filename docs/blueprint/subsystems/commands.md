# Subsystem Dossier: `commands` (Use-Case Command Handlers)

> Code-cited audit. Every claim below was verified by reading the source and tracing
> live call paths with grep, not by trusting docstrings. All paths are absolute.
> Verified on the working tree at `/Users/matthewnardizzi/dev/tex` (checked-out branch
> at audit time: `fix/entity-grounding-kwarg`; the task referenced `feat/proof-carrying-gate`
> — the `src/tex/commands/` files are identical content either way, last touched `Jun 9`).
> Import sanity confirmed: `PYTHONPATH=.../src python -c "from tex.commands... import *"` → OK,
> `__layer__ = 4`, `__layer_kind__ = 'execution_governance'`.

---

## Overview

The `commands` unit is Tex's **application service layer** — the CQRS-style use-case
command handlers that are the app's actual entry verbs. There are exactly five command
classes, one per durable mutation the system can perform:

| Verb | Command class | What it does |
|------|---------------|--------------|
| **Evaluate an action** | `EvaluateActionCommand` | Run the PDP, persist the decision + evidence, feed precedent/ledger/provenance/baseline |
| **Report an outcome** | `ReportOutcomeCommand` | Attach an observed outcome to a prior decision, classify it, record evidence |
| **Activate a policy** | `ActivatePolicyCommand` | Flip the active policy version in the policy store |
| **Calibrate a policy** | `CalibratePolicyCommand` | Derive a recommendation from classified outcomes, optionally save/activate a new snapshot |
| **Export evidence** | `ExportBundleCommand` | Package the evidence chain as JSON / JSONL / filtered JSON |

Each command is a thin, constructor-injected orchestrator: it owns no I/O of its own,
holds narrow store/engine references via `__slots__`, validates invariants, and delegates
the heavy mechanics to the engine (`PolicyDecisionPoint`), the stores, the evidence
recorder/exporter, the learning layer, and (for the central command) the memory system.

`EvaluateActionCommand` is the spine. Every other command is small (59–212 lines);
`evaluate_action.py` is **1,199 lines** and carries the bulk of the unit's real logic —
it is the verb that ties the *brain* (PDP verdict) to the *evidence/provenance* spine.

Layer marker (`/Users/matthewnardizzi/dev/tex/src/tex/commands/__init__.py:9-10`):
`__layer__ = 4`, `__layer_kind__ = 'execution_governance'`.

---

## File Inventory

| File | Lines | Role |
|------|-------|------|
| `/Users/matthewnardizzi/dev/tex/src/tex/commands/__init__.py` | 11 | Package marker only. Exposes `__layer__ = 4`, `__layer_kind__ = 'execution_governance'`. No re-exports. |
| `/Users/matthewnardizzi/dev/tex/src/tex/commands/evaluate_action.py` | 1199 | **Central command.** `EvaluateActionCommand` — resolve policy → run PDP → validate alignment → persist decision + evidence (legacy or MemorySystem path) → precedent + action-ledger + provenance feed + tenant baseline + optional ecosystem pass. Defines `EvaluateActionResult`, `DecisionEvidenceRecorder`/`DecisionPrecedentStore` protocols. |
| `/Users/matthewnardizzi/dev/tex/src/tex/commands/report_outcome.py` | 172 | `ReportOutcomeCommand` — resolve decision → validate request linkage → persist outcome (direct or via learning orchestrator) → classify → optional evidence. Defines `OutcomeEvidenceRecorder` protocol and `ReportOutcomeResult`. |
| `/Users/matthewnardizzi/dev/tex/src/tex/commands/activate_policy.py` | 59 | `ActivatePolicyCommand` — capture previous active, activate the requested version through the policy store. Defines `ActivatePolicyResult`. The narrowest command (one store dep). |
| `/Users/matthewnardizzi/dev/tex/src/tex/commands/calibrate_policy.py` | 153 | `CalibratePolicyCommand` — resolve source policy → summarize classifications → ask calibrator for a recommendation → optionally apply/save/activate a new snapshot. Defines `CalibratePolicyResult` and `execute_for_policy_outcomes()` convenience wrapper. |
| `/Users/matthewnardizzi/dev/tex/src/tex/commands/export_bundle.py` | 212 | `ExportBundleCommand` — thin facade over `EvidenceExporter` for full JSON, raw JSONL, and filtered JSON bundle exports. Defines `BundleCapableExporter` protocol and `ExportBundleResult`. |

Total: **1,806 lines** across 6 files (5 commands + `__init__`).

---

## Internal Architecture (per command)

### 1. `EvaluateActionCommand` — the spine

**File:** `/Users/matthewnardizzi/dev/tex/src/tex/commands/evaluate_action.py`

**Constructor** (`__init__`, lines 132–185). Keyword-only. Slots at lines 107–130.

| Dependency | Type | Required? | Source in `build_runtime` |
|------------|------|-----------|---------------------------|
| `pdp` | `PolicyDecisionPoint` | **yes** | `main.py:881` |
| `policy_store` | `InMemoryPolicyStore` | **yes** | policy store |
| `decision_store` | `InMemoryDecisionStore` | **yes** | decision store |
| `precedent_store` | `DecisionPrecedentStore \| None` | no | precedent store |
| `evidence_recorder` | `DecisionEvidenceRecorder \| None` | no | `recorder` (`main.py:633`) |
| `action_ledger` | `InMemoryActionLedger \| None` | no | action ledger |
| `agent_registry` | `InMemoryAgentRegistry \| None` | no | agent registry |
| `tenant_baseline` | `InMemoryTenantContentBaseline \| None` | no | tenant baseline (V11) |
| `memory_system` | `Any \| None` | no | `memory` (`main.py:555`) — **canonical production path** |
| `provenance_feed` | `Any \| None` | no | `provenance_feed` (`main.py:696`) |
| `ecosystem_bridge` | `Any \| None` | no | `ecosystem_bridge` (`main.py:965`), Thread 7 |

**`execute(request: EvaluationRequest) -> EvaluateActionResult`** (lines 187–363).
Orchestration order (this is the real, code-traced sequence):

1. **Resolve policy** — `_resolve_policy(request)` (lines 556–579): uses
   `request.policy_id` if set (`policy_store.require`), else `policy_store.require_active()`.
   Resolved **first** so every subsequent registry write is stamped with `policy_version`
   provenance (lines 193–211 set `registry.set_audit_context(policy_version=..., write_source="evaluate_action")`, best-effort).
2. **Auto-register controlled agent** — `_ensure_controlled_agent_registered(request)`
   (lines 365–447): if the request carries `agent_identity`/`agent_id`, derive a stable
   UUID (`uuid5(AGENT_IDENTITY_NAMESPACE, identity.stable_key)`, line 389), register or
   upgrade the agent to `visibility_status="controlled"` **before** PDP runs so identity/
   capability/behavior streams fire on the first action. This is a real side effect: it
   writes to `agent_registry` (`registry.save(...)`, lines 401/413/446).
3. **Run PDP** — `self._pdp.evaluate(request=request, policy=policy)` (line 214) → `PDPResult`.
4. **Validate alignment** — `_validate_pdp_alignment(...)` (lines 581–617): asserts
   `decision.request_id == request.request_id`, `decision.policy_version == policy.version`,
   and that the response's `decision_id`/`policy_version`/`verdict`/`confidence`/`final_score`
   all match the decision. Raises `ValueError` on mismatch (→ HTTP 400).
5. **Durable persistence — two branches** (lines 238–289):
   - **MemorySystem path** (production, `memory_system is not None`, lines 241–265):
     builds full input payload (`request.model_dump(mode="json")`, lines 699–709), builds
     evidence metadata (`_build_evidence_metadata`, lines 635–697), then calls
     `memory_system.record_decision_with_policy(decision=, full_input=, policy=, evidence_metadata=)`
     — decision + input + policy snapshot written in **one Postgres transaction**, then
     JSONL evidence chain, then Postgres mirror (target method exists at
     `/Users/matthewnardizzi/dev/tex/src/tex/memory/system.py:181`). Then `_save_precedent`,
     back-propagate `evidence_hash` onto the response, then contract-violation evidence rows.
   - **Legacy path** (`memory_system is None`, used by most unit tests, lines 266–289):
     `decision_store.save(decision)` → `_save_precedent` → if recorder present,
     `_record_decision_evidence` → back-propagate hash → contract-violation rows.
6. **Optional ecosystem pass** — `_maybe_apply_ecosystem(...)` (lines 318–322, impl
   904–1067): only runs when `ecosystem_bridge` is wired **and** `TEX_ECOSYSTEM=1`. Forwards
   `pdp_result.routing_result` through `bridge.emit_verdict(...)`, folds six axis scores into
   `response.scores` under the `ecosystem.*` namespace, publishes GAAT level as an
   uncertainty flag. **Advisory only** in Thread 7 — failures are caught and the legacy
   verdict survives (lines 1005–1010). With the flag off it returns `response` unchanged.
7. **Action-ledger write** — `_record_action_ledger_entry(...)` (lines 324–331, impl
   1069–1146): only when `action_ledger` wired **and** `request.agent_id is not None`.
   Builds an `ActionLedgerEntry` with verdict/scores/capability violations/ASI short-codes/
   identity hashes and `ledger.append(entry)`.
8. **Provenance feed** — (lines 337–341): if `provenance_feed` wired and `agent_id` set,
   `provenance_feed.note_action(request.agent_id)`. Wrapped in bare `try/except` so
   provenance can **never** break the verdict.
9. **Tenant baseline** — `_update_tenant_baseline(...)` (lines 342–345, impl 1148–1199):
   only on **PERMIT**, agent-attached decisions, with a registry to resolve `tenant_id`.
   Appends a `ContentSignatureRecord` (V11 anomaly baseline). Guarded so ABSTAIN/FORBID
   never poison the baseline (lines 1176–1177).
10. **Return** `EvaluateActionResult(response, decision, policy, pdp_result, evidence_record)` (347–353).
11. **`finally`** (lines 354–363): always `registry.clear_audit_context()` so a concurrent
    save doesn't inherit this evaluation's `policy_version`.

**Inputs:** `EvaluationRequest` (domain). **Outputs:** `EvaluateActionResult` wrapping the
public `EvaluationResponse`, the internal `Decision`, resolved `PolicySnapshot`, raw
`PDPResult`, and the `EvidenceRecord | None`.

**Side effects (real, traced):** agent-registry writes, decision-store write,
precedent-store write, hash-chained evidence-chain append (decision + SCITT refusal receipt
on FORBID + per-violation contract-violation rows), action-ledger append, provenance-feed
notification, tenant-baseline append, optional TEE attestation in evidence metadata
(`TEX_TEE_MODE=1`, lines 677–695), optional ecosystem axis-score projection.

**FORBID-specific evidence** — `_build_refusal_context` (lines 748–794): on `Verdict.FORBID`
it builds a `ScittRefusalEvent` (PRE_GENERATION, draft-kamimura-scitt-refusal-events-02)
carrying the rationale (`decision.reasons`, truncated to 480 chars) and risk category, passed
to `recorder.record_decision(..., c2pa_context=...)`. The recorder's `record_decision`
accepts `c2pa_context` and gates the SCITT block on FORBID
(`/Users/matthewnardizzi/dev/tex/src/tex/evidence/recorder.py:104-206`). Real wire.

**Contract-violation evidence** — `_record_contract_violation_evidence` (lines 796–902):
for each `decision.findings` with `source == "contracts.behavioral"`, calls
`recorder.record_contract_violation(...)` to emit a separately-addressable evidence row with
its own `record_hash` and a `parent_evidence_hash` back-reference. Best-effort
(`try/except` + `_logger.warning`); the recorder method is discovered via `getattr` and
silently skipped if absent. Method exists at `recorder.py:359`.

---

### 2. `ReportOutcomeCommand`

**File:** `/Users/matthewnardizzi/dev/tex/src/tex/commands/report_outcome.py`

**Constructor** (lines 67–78). Keyword-only. Slots 60–65.

| Dependency | Type | Required? |
|------------|------|-----------|
| `decision_store` | `InMemoryDecisionStore` | **yes** |
| `outcome_store` | `InMemoryOutcomeStore` | **yes** |
| `evidence_recorder` | `OutcomeEvidenceRecorder \| None` | no |
| `orchestrator` | `object \| None` | no (wired to `FeedbackLoopOrchestrator` in prod) |

**`execute(outcome: OutcomeRecord) -> ReportOutcomeResult`** (lines 80–116). Order:

1. `_resolve_decision(outcome)` (118–124): `decision_store.require(outcome.decision_id)`,
   raises `LookupError` (→ 404) if missing.
2. `_validate_decision_alignment(...)` (126–138): asserts `outcome.request_id ==
   decision.request_id`, else `ValueError` (→ 400).
3. **Persist — two branches** (lines 91–96):
   - **Orchestrator path** (prod): `orchestrator.ingest_outcome(outcome)` →
     `ingest_result.validation.outcome` is the stored outcome. This routes through the
     learning layer's trust-tier validation + reputation update (target method exists at
     `/Users/matthewnardizzi/dev/tex/src/tex/learning/feedback_loop.py:211`).
   - **Legacy direct-write** (no orchestrator): `outcome_store.save(outcome)`.
4. `classify_outcome(decision=, outcome=)` (98–101) → `OutcomeClassification`.
5. Optional evidence — `_record_outcome_evidence(...)` (140–172) when `evidence_recorder`
   present: `recorder.record_outcome(outcome, policy_version=decision.policy_version,
   metadata={...})`, metadata carrying the decision verdict/score/confidence and the full
   classification booleans (is_correct, is_error, is_false_permit, is_false_forbid,
   is_abstain_review, is_unknown).

**Output:** `ReportOutcomeResult(outcome, decision, classification, evidence_record)`.
**Side effects:** outcome-store write (or orchestrator ingest incl. reputation update),
hash-chained outcome evidence append.

---

### 3. `ActivatePolicyCommand`

**File:** `/Users/matthewnardizzi/dev/tex/src/tex/commands/activate_policy.py`

**Constructor** (lines 34–35): `policy_store: InMemoryPolicyStore` (only dep). Slot 32.

**`execute(version: str) -> ActivatePolicyResult`** (lines 37–60):
1. Type/blank validation (`TypeError` / `ValueError`).
2. Capture `previous_active = policy_store.get_active()` (line 48).
3. `policy_store.activate(normalized_version)` (line 51); `KeyError` → re-raised as
   `LookupError` (→ 404).
4. Returns `ActivatePolicyResult(activated_policy, previous_active_policy)`.

Deliberately narrow — no calibration, no evidence recording (per its own docstring, verified
in code). **Side effect:** flips the active-version pointer in the policy store.

---

### 4. `CalibratePolicyCommand`

**File:** `/Users/matthewnardizzi/dev/tex/src/tex/commands/calibrate_policy.py`

**Constructor** (lines 46–55). Keyword-only. Slots 40–44.

| Dependency | Type |
|------------|------|
| `policy_store` | `InMemoryPolicyStore` |
| `outcome_store` | `InMemoryOutcomeStore` |
| `calibrator` | `ThresholdCalibrator` |

**`execute(*, source_policy_version=None, classifications, new_version=None, save=False,
activate=False, metadata_updates=None) -> CalibratePolicyResult`** (lines 57–113). Order:
1. `_resolve_source_policy(...)` (139–153): named version via `policy_store.require`, else
   `policy_store.require_active()`; `LookupError` if unavailable.
2. `summarize_outcomes(tuple(classifications))` (line 79) → `OutcomeSummary`.
3. `calibrator.recommend(policy=, summary=)` (81–84) → `CalibrationRecommendation`.
4. Rule: `activate=True` requires `save=True` (88–89, else `ValueError`).
5. If `save`: `new_version` required (92–93), then
   `calibrator.apply_recommendation(policy=, recommendation=, new_version=,
   metadata_updates=, activate=)` → new `PolicySnapshot`, then `policy_store.save(...)`
   (102), and if `activate` then `policy_store.activate(new_version)` (105).
6. Returns `CalibratePolicyResult(source_policy, recommendation, summary, classifications,
   calibrated_policy)`.

`execute_for_policy_outcomes(...)` (115–137) is a thin convenience wrapper that forwards to
`execute`. **Side effects:** optionally writes a new policy snapshot and/or activates it.
Note: `outcome_store` is injected but is **not** read inside `execute` — calibration consumes
already-classified outcomes passed in by the caller (consistent with its docstring; the store
is held for symmetry/future use).

---

### 5. `ExportBundleCommand`

**File:** `/Users/matthewnardizzi/dev/tex/src/tex/commands/export_bundle.py`

**Constructor** (lines 94–99): `exporter: EvidenceExporter`. **Validates** the exporter
implements the `BundleCapableExporter` protocol (lines 11–65) at construction, raising
`TypeError` otherwise. Slot 92.

Three public methods (all keyword-only, all return `ExportBundleResult`):
- `export_json(*, path, export_name, verify_chain=True, indent=2)` (101–128): builds the
  in-memory bundle (`exporter.build_bundle`) and writes the file (`exporter.export_json`);
  returns both with `export_format="json"`.
- `export_jsonl(*, path)` (130–147): `exporter.export_jsonl(path)`; returns `bundle=None`,
  `export_format="jsonl"` (raw records aren't wrapped in a bundle).
- `export_filtered_json(*, path, record_type, decision_id, outcome_id, request_id,
  policy_version, export_name, verify_chain=False, indent=2)` (149–210): writes the filtered
  file via `exporter.export_filtered_json`, re-fetches the filtered records
  (`exporter.filter_records`), and **reconstructs** an `EvidenceExportBundle` in code —
  either by running `verify_evidence_chain(...)` (lazy import, line 189) when `verify_chain`
  is set, or by stamping a trivially-valid `ChainVerificationResult` (lines 193–199) when not.
  `verify_chain` defaults to `False` here because filtered subsets aren't guaranteed to be a
  contiguous chain.

Thinnest of the multi-method commands — pure delegation; the packaging mechanics live in the
`evidence` subsystem. **Side effect:** writes evidence files to disk.

---

## Public API

The unit's public surface (importable symbols):

- `EvaluateActionCommand`, `EvaluateActionResult` — `evaluate_action.py`
- `ReportOutcomeCommand`, `ReportOutcomeResult`, `OutcomeEvidenceRecorder` — `report_outcome.py`
- `ActivatePolicyCommand`, `ActivatePolicyResult` — `activate_policy.py`
- `CalibratePolicyCommand`, `CalibratePolicyResult` — `calibrate_policy.py`
- `ExportBundleCommand`, `ExportBundleResult`, `BundleCapableExporter` — `export_bundle.py`
- Protocols defined in `evaluate_action.py`: `DecisionEvidenceRecorder`, `DecisionPrecedentStore`

All command classes use `__slots__`; all `*Result` types are `@dataclass(frozen=True, slots=True)`.
The package `__init__.py` re-exports **nothing** — callers import from the concrete modules.

---

## Wiring (LIVE call paths)

### A. Construction — `build_runtime` in `main.py`

`create_app` (`/Users/matthewnardizzi/dev/tex/src/tex/main.py:1314`) calls `build_runtime`
(`main.py:524`, invoked at `main.py:1363` and lazily at `1393`). `build_runtime` constructs all
five commands and `_build_app_state` publishes them on `app.state`
(`main.py:1661–1665`). Confirmed **LIVE**.

| Command | Constructed at | Notable wiring |
|---------|----------------|----------------|
| `EvaluateActionCommand` | `main.py:967` | full fan-out: `pdp`, `policy_store`, `decision_store`, `precedent_store`, `evidence_recorder=recorder`, `action_ledger`, `agent_registry`, `tenant_baseline`, `memory_system=memory`, `provenance_feed`, `ecosystem_bridge` |
| `ReportOutcomeCommand` | `main.py:1041` | `decision_store`, `outcome_store`, `evidence_recorder=recorder`, `orchestrator=learning_orchestrator` (the `FeedbackLoopOrchestrator` built at `main.py:1011`) |
| `ActivatePolicyCommand` | `main.py:1048` | `policy_store` only |
| `CalibratePolicyCommand` | `main.py:1052` | `policy_store`, `outcome_store`, `calibrator` |
| `ExportBundleCommand` | `main.py:1058` | `exporter` (the `EvidenceExporter` built at `main.py:648`) |

Published on app.state: `main.py:1661` (`evaluate_action_command`), `1662`
(`report_outcome_command`), `1663` (`activate_policy_command`), `1664`
(`calibrate_policy_command`), `1665` (`export_bundle_command`).

> Note: the prompt's cited lines (962, 1036, 1043, 1047, 1053) are within a few lines of the
> current positions (967, 1041, 1048, 1052, 1058) — minor drift since the memo was written;
> the construction blocks are unchanged in substance.

### B. Invocation — HTTP routes in `tex.api`

The canonical router (`/Users/matthewnardizzi/dev/tex/src/tex/api/routes.py:98`,
`APIRouter(tags=["tex"])`, **no prefix**) is included at `main.py:1446` via
`build_api_router()`. Each route fetches its command from `app.state` via a small accessor
and calls `.execute(...)`:

| Command | HTTP route (method + path) | Route handler | Resolver | `.execute` call | Scope |
|---------|----------------------------|---------------|----------|-----------------|-------|
| `EvaluateActionCommand` | **POST `/evaluate`** | `routes.py:117` | `_get_evaluate_action_command` (`routes.py:581`) | `routes.py:128` | `decision:write` |
| `ReportOutcomeCommand` | **POST `/outcomes`** | `routes.py:396` | `_get_report_outcome_command` (`routes.py:591`) | `routes.py:408` | `outcome:write` |
| `ActivatePolicyCommand` | **POST `/policies/activate`** | `routes.py:435` | `_get_activate_policy_command` (`routes.py:601`) | `routes.py:445` | `policy:write` |
| `CalibratePolicyCommand` | **POST `/policies/calibrate`** | `routes.py:472` | `_get_calibrate_policy_command` (`routes.py:613`) | `routes.py:485` | `policy:write` |
| `ExportBundleCommand` | **POST `/evidence/export`** | `routes.py:519` | `_get_export_bundle_command` (`routes.py:625`) | `routes.py:530/536/546` | `evidence:read` |

All routes wrap `.execute` in a uniform exception ladder: `LookupError`→404, `ValueError`→400,
`TypeError`→500 (plus `OSError`→500 for export). DTOs map in/out
(`payload.to_domain()` → command → `*ResponseDTO.from_command_result(...)`).

### C. `EvaluateActionCommand` has FIVE additional live entry points

`EvaluateActionCommand` is reached not only via POST `/evaluate` but through every
gateway/streaming/MCP surface, all reusing the same `app.state.evaluate_action_command`:

- **Canonical guardrail webhook** — `POST /v1/guardrail` (`guardrail.py:784`), resolver
  `_get_evaluate_action_command` (`guardrail.py:872`, type-checked `isinstance` at 879),
  `.execute(domain_request)` at `guardrail.py:828`.
- **Gateway adapters** — `POST /v1/guardrail/{portkey,litellm,cloudflare,solo,truefoundry,
  bedrock,...}` (`guardrail_adapters.py:163+`), `.execute` at `guardrail_adapters.py:79`
  (imports `_get_evaluate_action_command` from `guardrail.py`, line 45).
- **Streaming** — SSE/async/chunk routes (`guardrail_streaming.py`, prefix `/v1/guardrail`),
  `.execute` at lines 121 (and command fetched at 179/325/415).
- **MCP server** — `POST /mcp` (`mcp_server.py:309`, prefix `/mcp`), `.execute` at
  `mcp_server.py:258`.
- **Other consumers** — `governance_standing_routes.py` and `tenant_routes.py` reference the
  command's verdict path; the microsecond-floor → deep-eval bridge is wired at
  `main.py:1746` (`evaluate_command=runtime.evaluate_action_command`).

All five command-construction lines and all route call-sites are present in the running app:
**every command is LIVE.**

---

## EvaluateActionCommand as the central verb (brain → evidence/provenance)

This is the unit's load-bearing claim and it holds up in code. `EvaluateActionCommand` is the
single place where Tex's **brain** (the Policy Decision Point verdict) is joined to the
**evidence/provenance spine**:

1. **Brain in** — `self._pdp.evaluate(request=request, policy=policy)` (line 214) produces a
   `PDPResult` carrying `decision`, `response`, `routing_result`, `agent_bundle`
   (`/Users/matthewnardizzi/dev/tex/src/tex/engine/pdp.py:115-140`). The command does not
   compute the verdict — it consumes it and *enforces* its internal consistency
   (`_validate_pdp_alignment`, lines 581–617).

2. **Verdict → evidence** — the same `decision` is sealed into the hash-chained evidence chain
   via either `memory_system.record_decision_with_policy(...)` (line 246, transactional prod
   path) or `recorder.record_decision(..., c2pa_context=...)` (line 742, legacy path), and the
   resulting `record_hash` is back-propagated onto the public response's `evidence_hash`
   (lines 255–257 / 280–282). On FORBID, a SCITT refusal receipt is folded into that same row
   (lines 740, 748–794). Per-violation contract-evidence rows cross-reference it
   (lines 261–265 / 285–289).

3. **Verdict → provenance / identity** — the action is appended to the agent action ledger
   (`_record_action_ledger_entry`, lines 324, 1069–1146) and the continuous provenance feed is
   pinged so behavioural identity re-seals off the hot path
   (`provenance_feed.note_action(...)`, lines 337–339). The agent is also auto-registered as
   "controlled" before the PDP even runs (step 2 above), so identity flows from the very first
   adjudication.

4. **Verdict → learning/anomaly substrate** — the decision is saved as precedent context
   (`_save_precedent`, lines 254/268, 619–633) feeding retrieval, and on PERMIT a tenant
   content-signature baseline record is appended (`_update_tenant_baseline`, lines 342,
   1148–1199) feeding V11 anomaly detection.

No other command in the unit runs the PDP. `EvaluateActionCommand` *is* the
"evaluate an action → verdict + evidence" verb; everything downstream (outcomes, calibration)
references decisions it produced.

---

## Implementation Reality

**Real, not stubbed.** Every command's `execute` performs genuine orchestration against real
collaborators that are constructed concretely in `build_runtime` (PDP at `main.py:881`, real
`EvidenceRecorder` at `633`, real `EvidenceExporter` at `648`, real `MemorySystem` at `555`,
real `FeedbackLoopOrchestrator` at `1011`, real `ContinuousProvenanceFeed` at `696`). There
are no `NotImplementedError`, `pass`-body, or `TODO`-gated paths in the five command files.

**Optional features are flag-gated, not faked.** Three capabilities are behind explicit
defaults/env flags and degrade cleanly to a documented baseline when off — these are real
fallbacks, not stubs:
- **MemorySystem path** vs **legacy decision_store path** (`memory_system is None`): both are
  fully implemented; production wires MemorySystem, most unit tests drive the legacy branch.
- **Ecosystem pass** (`_maybe_apply_ecosystem`): inert unless `ecosystem_bridge` wired **and**
  `TEX_ECOSYSTEM=1`. Advisory in Thread 7 — it folds axis scores but does **not** override the
  verdict, and any exception is swallowed (the legacy verdict survives, lines 1005–1010). The
  composition gate to FORBID/SANCTION is explicitly deferred to "Thread 8" per the docstring.
- **TEE attestation** (`_build_evidence_metadata`, lines 677–695): only when `TEX_TEE_MODE=1`;
  collection failure is recorded as a metadata flag and never blocks the decision.

**Best-effort sections are correctly isolated.** Audit-context set/clear (lines 200–210,
359–362), provenance-feed notification (337–341), and contract-violation evidence
(852–902) are all wrapped so they can never break the user-facing verdict. This is defensive
by design, not incompleteness.

**Validation is real and fail-loud where it matters.** `_validate_pdp_alignment` and
`_validate_decision_alignment` raise `ValueError` on any integrity drift between
request/policy/decision/response — these are not no-ops.

**One inert-but-injected dependency:** `CalibratePolicyCommand.outcome_store` is constructed
and injected (`main.py:1054`) but not read inside `execute` (calibration consumes
caller-supplied classifications). Held for symmetry; not a bug, but worth noting.

---

## Technology

- **Language:** Python 3.11+ (`from __future__ import annotations`; `UTC` from `datetime`;
  `X | None` unions; `match`-free but modern typing).
- **Patterns:** CQRS-style command handlers; constructor dependency injection (keyword-only);
  `__slots__` on every command for memory discipline; frozen `@dataclass(slots=True)` results;
  `typing.Protocol` + `@runtime_checkable` for narrow recorder/exporter/precedent interfaces
  (duck-typed, so in-memory and Postgres-backed collaborators interchange).
- **Domain models:** Pydantic-style frozen models (`EvaluationRequest`, `Decision`,
  `EvaluationResponse`, etc.) — mutated only via `.model_copy(update={...})`, never in place
  (the command comments call this out as "the only mutation we allow at the application layer").
- **Engine boundary:** `PolicyDecisionPoint` (the brain) is the only compute dependency;
  commands never re-implement scoring.
- **Standards referenced in code:** SCITT refusal events (draft-kamimura-scitt-refusal-
  events-02), C2PA emission context, composite TEE attestation (CrossGuard pattern), GAAT
  graduated enforcement levels (ecosystem axis).
- **HTTP:** FastAPI routers; commands themselves are transport-agnostic (no FastAPI imports in
  the command files — confirmed).
- **Env flags:** `TEX_ECOSYSTEM`, `TEX_TEE_MODE`.

---

## Persistence

Commands own no storage; they orchestrate the persistence subsystems:

- **Decisions:** `InMemoryDecisionStore.save(decision)` (legacy) or, in production, the
  unified transactional write through `MemorySystem.record_decision_with_policy(...)`
  (decision + replay input + policy snapshot in **one Postgres transaction**, then JSONL
  evidence chain, then Postgres mirror — `memory/system.py:181`).
- **Evidence:** hash-chained JSONL chain via `EvidenceRecorder` — decision rows, SCITT refusal
  receipts (FORBID), per-violation contract rows; exported as bundles by `ExportBundleCommand`
  through `EvidenceExporter` (full JSON / raw JSONL / filtered JSON on disk).
- **Outcomes:** `InMemoryOutcomeStore.save(...)` (legacy) or via
  `FeedbackLoopOrchestrator.ingest_outcome(...)` which adds trust-tier validation + reputation
  update (`learning/feedback_loop.py:211`).
- **Policies:** `InMemoryPolicyStore` (`require`/`require_active`/`get_active`/`save`/`activate`).
- **Precedent / ledger / baseline:** `precedent_store.save(decision)`,
  `InMemoryActionLedger.append(...)`, `InMemoryTenantContentBaseline.append(...)`.
- **Provenance:** `ContinuousProvenanceFeed.note_action(agent_id)` (off-hot-path re-sealing).

Default in-memory stores are durable-protocol-shaped (`Protocol` interfaces), so a
Postgres/durable backend swaps in without touching command code — and the production runtime
does exactly that via `MemorySystem`.

---

## Notable Findings

1. **The unit is fully LIVE.** All five commands are constructed in `build_runtime`
   (`main.py:967/1041/1048/1052/1058`), published on `app.state` (`1661-1665`), and invoked by
   real HTTP routes (`/evaluate`, `/outcomes`, `/policies/activate`, `/policies/calibrate`,
   `/evidence/export`). Traced end to end — no dead handlers.

2. **`EvaluateActionCommand` is the spine, by line count and by role.** 1,199 of the unit's
   1,806 lines (66%). It is the only command that runs the PDP and the only one with five+
   distinct entry surfaces (REST `/evaluate`, guardrail webhook, gateway adapters, SSE
   streaming, MCP). It is also the join point where verdict → evidence → provenance → learning
   all hang off one method.

3. **The other four commands are deliberately thin and narrow.** `ActivatePolicyCommand`
   (59 lines, one dep) and `ExportBundleCommand` (pure exporter facade) carry almost no logic;
   `ReportOutcomeCommand` and `CalibratePolicyCommand` add a validation + a delegation. This is
   intentional CQRS hygiene, confirmed in code (their docstrings' "intentionally excluded"
   lists match the actual bodies).

4. **Real evidence/provenance spine, not theatre.** SCITT refusal receipts on FORBID,
   per-violation contract-evidence rows with `parent_evidence_hash` cross-references, action
   ledger, and continuous provenance feed are all wired with live recorder methods that exist
   (`recorder.py:104/300/359`). This is the substantive, defensible core.

5. **Branch note.** The working tree is on `fix/entity-grounding-kwarg`, not the
   `feat/proof-carrying-gate` named in the task. The `src/tex/commands/` files are unchanged
   (last modified `Jun 9`); no proof-carrying-gate-specific code appears inside the command
   files themselves (that work lands in `provenance/` per the memo). No discrepancy in this
   unit, but worth flagging for the reader's mental model.

6. **`CalibratePolicyCommand.outcome_store` is injected but unused** inside `execute` —
   calibration consumes caller-supplied classifications. Harmless, slightly misleading; a
   candidate for removal or a comment.

7. **Line drift in the memo's cited construction lines** (962→967, 1036→1041, 1043→1048,
   1047→1052, 1053→1058). Substance unchanged; just a few lines of insertion since the note.

8. **Ecosystem pass is advisory in this layer.** Despite the elaborate `_maybe_apply_ecosystem`
   plumbing, with `TEX_ECOSYSTEM=0` (the default) it is a no-op, and even when on it only
   *annotates* the response — it cannot flip the verdict (composition gate deferred to a future
   thread). Read it as enrichment, not enforcement, at the command layer today.

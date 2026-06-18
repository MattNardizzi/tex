# Subsystem Dossier: `agent` — Agent Registry & Abstractions

> Scope: `/Users/matthewnardizzi/dev/tex/src/tex/agent/` (the three evaluation streams + their orchestrating suite). Because the suite and evaluators are meaningless without the registry and domain models they read, this dossier also documents the directly-coupled out-of-scope pieces that constitute the "agent abstractions / identity" layer: `tex.stores.agent_registry` (the `InMemoryAgentRegistry` named in the task brief), `tex.stores.action_ledger`, `tex.domain.agent`, and `tex.domain.agent_signal`. Those are clearly labelled as out-of-scope-but-coupled.
>
> Branch: `feat/proof-carrying-gate`. All claims are code-verified with `file:line`. Docstring/markdown claims are labelled `(claim, unverified)` unless confirmed in code.

---

## Overview

The `agent` unit is **Architectural Layer 2 ("identity")** (`src/tex/agent/__init__.py:9-10`: `__layer__ = 2`, `__layer_kind__ = 'identity'`). It is the agent-governance evidence producer of Tex's Policy Decision Point (PDP). For every evaluation request that carries an `agent_id`, it answers three orthogonal questions and emits three peer signals that the router fuses with the content-side streams (deterministic / specialists / semantic / retrieval):

1. **Identity** — given *who* this agent is (trust tier, lifecycle status, environment match, attestations, age), how much risk does identity alone contribute? (`identity_evaluator.py`)
2. **Capability** — is this *specific action* inside the agent's declared capability surface? (`capability_evaluator.py`)
3. **Behavioral** — is what the agent is doing *now* consistent with how it has behaved over time, and (V11) with how every agent in its tenant has behaved? (`behavioral_evaluator.py`)

`suite.py` composes the three into one `AgentEvaluationSuite.evaluate()` that the PDP calls once per request, and short-circuits to a **neutral bundle** when no agent is supplied so content-only requests have zero agent influence.

The unit is **stateless**: all durable state lives outside it, in `InMemoryAgentRegistry` (who the agent is) and `InMemoryActionLedger` (what it has done). The evaluators read from those; they never write.

**Wiring verdict: LIVE.** The suite is built in `tex.main.build_runtime` and handed to the `PolicyDecisionPoint`; the registry is mounted on a FastAPI router and threaded through the evaluate-action command. Both the evaluation path and the CRUD path trace from a running route.

---

## File Inventory

### In scope — `src/tex/agent/`

| File | Lines | Role |
|---|---|---|
| `__init__.py` | 11 | Package marker only. Declares `__layer__ = 2`, `__layer_kind__ = 'identity'`. No exports, no logic. |
| `suite.py` | 121 | `AgentEvaluationSuite` — composes the three streams, resolves the agent through the registry (`require_evaluable`), returns `AgentEvaluationBundle`; neutral bundle when `agent_id is None`. Re-exports `AgentNotFoundError`, `AgentRevoked`. |
| `identity_evaluator.py` | 288 | `AgentIdentityEvaluator` — pure evaluator over trust tier / lifecycle / environment / attestations / age → `AgentIdentitySignal`. Plus `neutral_identity_signal()` and helpers. |
| `capability_evaluator.py` | 182 | `AgentCapabilityEvaluator` — pure evaluator that hard-flags out-of-surface actions (action_type/channel/environment/recipient) → `CapabilitySignal`. Plus `neutral_capability_signal()`. |
| `behavioral_evaluator.py` | 513 | `AgentBehavioralEvaluator` — derives a `BehavioralBaseline` from the action ledger and a `TenantContentBaselineLookup` from the tenant baseline → `BehavioralSignal` with cold-start handling. Plus `neutral_behavioral_signal()` and helpers. |

Total in-scope: **1,115 lines** across 5 files.

### Out of scope but directly coupled (documented because the brief names "InMemoryAgentRegistry / agent abstractions / identity")

| File | Lines | Role |
|---|---|---|
| `stores/agent_registry.py` | 186 | `InMemoryAgentRegistry` — the source-of-truth store for `AgentIdentity` records, monotonic revisioning, lifecycle transitions, history. Defines `AgentNotFoundError`, `AgentRevoked`. |
| `stores/action_ledger.py` | 222 | `InMemoryActionLedger` — per-agent bounded deque of `ActionLedgerEntry`; `compute_baseline()` derives the `BehavioralBaseline`. |
| `domain/agent.py` | 604 | The agent abstractions: `AgentLifecycleStatus`, `AgentTrustTier`, `AgentEnvironment`, `CapabilitySurface`, `AgentAttestation`, `AgentIdentity`, `ActionLedgerEntry`, `BehavioralBaseline`. |
| `domain/agent_signal.py` | 342 | The signal output schemas: `AgentIdentitySignal`, `CapabilitySignal`, `BehavioralSignal`, `AgentEvaluationBundle`. |
| `stores/agent_registry_postgres.py` (`PostgresAgentRegistry`) | — | Durable registry used when `database_configured` (`main.py:564,569`). Not read in full for this dossier; named here because it is the live registry in Postgres mode. |

---

## Internal Architecture

### Data flow within the unit

```
EvaluationRequest (carries agent_id, action_type, channel, environment, recipient, content, ...)
        │
        ▼
AgentEvaluationSuite.evaluate(request)                                 suite.py:85
        │  if request.agent_id is None ──► _neutral_bundle()           suite.py:86-87,106
        │
        ├─► registry.require_evaluable(agent_id) ──► AgentIdentity      suite.py:91
        │       (raises AgentRevoked if REVOKED — terminal)            agent_registry.py:144-156
        │
        ├─► AgentIdentityEvaluator.evaluate(agent, request)            suite.py:93 → identity_evaluator.py:47
        ├─► AgentCapabilityEvaluator.evaluate(agent, request)          suite.py:94 → capability_evaluator.py:37
        └─► AgentBehavioralEvaluator.evaluate(agent, request)          suite.py:95 → behavioral_evaluator.py:91
                  │  reads InMemoryActionLedger.compute_baseline()      action_ledger.py:119
                  │  reads InMemoryTenantContentBaseline.lookup() (opt) behavioral_evaluator.py:296
        │
        ▼
AgentEvaluationBundle(agent_present=True, identity, capability, behavioral)   suite.py:97-103
```

### `AgentEvaluationSuite` (`suite.py:44-113`)

- Holds references only (`__slots__` at `suite.py:56-63`): registry, ledger, optional tenant baseline, and the three evaluators. Evaluators default-construct if not injected (`suite.py:78-83`). "Stateless aside from holding references… safe to share across threads" (`suite.py:48-49`) — confirmed: no mutable instance state, all writes happen in the stores it references.
- `evaluate()` is the single entrypoint. Key behaviors:
  - No `agent_id` → neutral bundle (`suite.py:86-87`). This is the "no regression on content-only requests" contract (`suite.py:5-12`, docstring) — verified by `_neutral_bundle()` setting `agent_present=False` and using the three `neutral_*` signals (`suite.py:106-113`).
  - `require_evaluable` is called *before* the three evaluators (`suite.py:91`), so a `REVOKED` agent raises `AgentRevoked` and never reaches the streams. The docstring "REVOKED is terminal: surface the error to the application layer" (`suite.py:89-90`) is accurate.
  - QUARANTINED/PENDING/SLEEPING are *not* short-circuited here; they flow into the evaluators which handle them (`suite.py` comment at 88-90; QUARANTINE handling at `identity_evaluator.py:69-79,147-149`).

### `AgentIdentityEvaluator` (`identity_evaluator.py:38-183`)

Pure, stateless. Computes 5 sub-scores, then composes:

1. **Trust-tier baseline** (`identity_evaluator.py:59`) — from `AgentTrustTier.baseline_risk_contribution` (UNVERIFIED 0.55 → PRIVILEGED 0.03, `domain/agent.py:108-117`).
2. **Lifecycle** (`identity_evaluator.py:67`, `_lifecycle_risk` at `214-220`) — ACTIVE 0.05, PENDING 0.45, QUARANTINED 1.0, REVOKED 1.0. **Note:** `_lifecycle_risk` has no `SLEEPING` key, but SLEEPING agents never reach here in the live path because `require_evaluable` allows SLEEPING through *but* — see Notable Findings #5; SLEEPING would raise `KeyError` in `_lifecycle_risk` (`identity_evaluator.py:214-220`).
3. **Environment match** (`identity_evaluator.py:85-104`) — 0.0 if match else 0.65, via `_environment_matches` (`240-255`) which normalizes both sides through `_ENVIRONMENT_ALIASES` (`228-232`: dev/development→sandbox, prod→production) so "prod" ≡ PRODUCTION.
4. **Attestations** (`identity_evaluator.py:106-133`) — 0 attestations → 0.45; all expired → 0.55 + WARNING finding; active → `max(0.10, 0.30 - 0.05*active)`.
5. **Age** (`identity_evaluator.py:135-144`) — fresh (`< _FRESH_AGENT_SECONDS` = 3600s, line 35) → 0.40 + `fresh_agent` flag; else 0.05.

**Composition** (`identity_evaluator.py:146-163`): QUARANTINED forces `risk_score=1.0, confidence=0.95` outright. Otherwise a **weighted max-mean**: `risk = min(1.0, 0.6*mean + 0.4*max)` over the five sub-scores — "prevents one bad signal from dominating but still surfaces single-axis problems" (`identity_evaluator.py:151-154`). Confidence comes from `_confidence_for_tier_and_attestations` (`258-269`): tier baseline confidence, +0.05 if ≥2 active attestations, −0.10 (floor 0.30) if fresh.

The signal also carries **discovery provenance** (`identity_evaluator.py:178-182`) pulled from `agent.metadata` via `_metadata_str` (`272-288`, defensively clamps to 512 chars, returns None on any miss) — `discovery_source`, `discovery_external_id`, `discovery_risk_band`. This is the seam between the discovery layer and runtime fusion.

### `AgentCapabilityEvaluator` (`capability_evaluator.py:27-165`)

Pure, stateless, the hard-block stream. Checks four dimensions against `agent.capability_surface` (a `CapabilitySurface`):

- action_type → `surface.permits_action_type` (`capability_evaluator.py:50`)
- channel → `surface.permits_channel` (`69`)
- environment → `surface.permits_environment` (`90`)
- recipient → `surface.permits_recipient` (`110`)

Each `permits_*` returns `True` when its allow-list is empty (= unrestricted for that dimension, `domain/agent.py:202-245`). Recipient matching supports email (`@`), URL (`://`), and bare-domain forms and matches exact or `endswith('.'+allowed)` subdomain (`domain/agent.py:230-245`).

**Scoring** (`capability_evaluator.py:127-151`): any violation → CRITICAL finding per dimension + `risk = min(1.0, 0.55 + 0.15*len(violated))`, `confidence=0.95`. No violation but **unrestricted surface** → `risk=0.30, confidence=0.55` + `agent_unrestricted_surface` uncertainty flag (posture concern, `131-143`). Fully in-surface → `risk=0.05, confidence=0.92`. The "router will route it to FORBID through normal fusion" claim (`capability_evaluator.py:31-35`) is consistent with the high risk + the findings reaching the router (`engine/router.py:302-303`).

### `AgentBehavioralEvaluator` (`behavioral_evaluator.py:65-405`)

Pure-with-respect-to-inputs (`__slots__` = ledger/window/tenant_baseline, `behavioral_evaluator.py:78`). Per-evaluation it:

1. Calls `self._ledger.compute_baseline(agent_id, window=200)` (`behavioral_evaluator.py:97`) and `list_for_agent(..., limit=20)` for the recent abstain window (`98`, `_RECENT_WINDOW=20` at line 56).
2. Computes the **tenant lookup** once via `_lookup_tenant` (`281-301`): if no tenant baseline wired → neutral cold-start (`_neutral_tenant_lookup`, `432-449`); else `compute_content_signature(request.content)` (MinHash) then `tenant_baseline.lookup(...)`.
3. **Cold-start** (`baseline.is_empty`, i.e. zero ledger entries): returns `_cold_start_signal` (`452-502`) with `risk=0.20, confidence=0.40`, `cold_start=True`, all `novel_*` flags True, no findings. Comment (`460-465`) explains it deliberately does *not* escalate risk on cold-start to avoid double-counting uncertainty the router already weighs.
4. Otherwise computes deviation components (`behavioral_evaluator.py:117-227`):
   - novel action_type (`124-130`), novel channel (`132-137`), novel recipient domain per-agent (`139-152`) — each contributes more when frequency is 0.
   - **forbid streak** (`156-178`): ≥3 → WARNING (or CRITICAL ≥5) finding + score; ==2 → 0.30 soft.
   - **capability violation rate** (`182-203`): `min(1.0, 1.5*rate)`, WARNING finding if ≥0.30.
   - **recent abstain rate** (`206-215`): >0.50 → soft score + uncertainty flag.
   - **V11 tenant signals** (`_fold_tenant_signals`, `303-405`): tenant-novel content (Jaccard-based novelty ≥0.85 → WARNING finding; ≥0.65 → soft uncertainty) and tenant-novel recipient domain (unseen tenant-wide → 0.50 + WARNING). Cold-start tenant emits an uncertainty flag but **never a finding** ("we do not punish day-one users", `326-335`).
5. **Composition** (`behavioral_evaluator.py:229-241`): a max-mean over positive components — `risk = min(1.0, 0.55*mean + 0.45*max)`. Confidence ramps with sample size: 0.85 at ≥25 samples (`_MIN_SAMPLE_FOR_FULL_CONFIDENCE`, line 53), else `0.50 + 0.014*sample_size` + `limited_behavioral_history` flag (`237-241`).

`_domain_of` (`505-513`) parses email/URL/bare recipient to a lowercase domain, mirroring the ledger's `_extract_recipient_domain` (`action_ledger.py:209-222`).

### Registry (`stores/agent_registry.py:35-187`) — out-of-scope-but-coupled

- `InMemoryAgentRegistry` keyed by `UUID`, `RLock`-guarded (`agent_registry.py:44-50`). `_by_id` is current revision; `_history` is the full revision list per agent.
- `save()` (`58-98`): first registration forces `revision=1`; updates create `revision N+1`, preserve `registered_at`, refresh `updated_at` — immutable-by-revision (uses `model_copy`).
- `set_lifecycle()` (`100-130`): produces a new revision; no-op if status unchanged.
- `require_evaluable()` (`144-156`): the gate the suite uses — raises `AgentRevoked` for REVOKED, otherwise returns the record (PENDING/ACTIVE/QUARANTINED/SLEEPING pass through).
- **Self-governance hook:** both `save` and `set_lifecycle` are gated by `gate_controller_mutation(...)` (`agent_registry.py:70,111`) from `tex.selfgov.governor`. By default the gate is **inert** — `gate_controller_mutation` returns `_UNGATED (allowed=True, gated=False)` when `_BINDING is None` (`selfgov/governor.py:484-486`), so writes proceed ungoverned unless a governor is bound. See Notable Findings #3.

---

## Public API

Symbols other code imports from this unit (verified by grep across `src/tex`):

| Symbol | Defined | Imported by |
|---|---|---|
| `AgentEvaluationSuite` | `suite.py:44` | `tex.main` (`main.py:15,651`) |
| `neutral_identity_signal` | `identity_evaluator.py:186` | `tex.engine.pdp` (`pdp.py:18`); `suite.py:31` |
| `neutral_capability_signal` | `capability_evaluator.py:168` | `tex.engine.pdp` (`pdp.py:17`); `suite.py:27` |
| `neutral_behavioral_signal` | `behavioral_evaluator.py:408` | `tex.engine.pdp` (`pdp.py:16`); `suite.py:24` |
| `AgentIdentityEvaluator` / `AgentCapabilityEvaluator` / `AgentBehavioralEvaluator` | the three evaluator files | `suite.py:21-32` (intra-unit only) |
| `AgentNotFoundError`, `AgentRevoked` (re-exported) | `agent_registry.py:27,31`; re-exported at `suite.py:117-121` | suite `__all__` |
| `__layer__`, `__layer_kind__` | `__init__.py:9-10` | spine/architecture introspection (`__init__.py:8` comment) |

The evaluator classes themselves are not imported outside the unit — only the suite (composition) and the three `neutral_*` factories (which the PDP uses to synthesize a neutral bundle when no agent evaluator is wired, `pdp.py:16-18`, used in `_neutral_agent_bundle`).

---

## Wiring

### Wiring IN (who calls this unit)

**Composition root** — `tex.main.build_runtime`:
- `from tex.agent.suite import AgentEvaluationSuite` (`main.py:15`).
- `agent_suite = AgentEvaluationSuite(registry=agent_registry, ledger=action_ledger, tenant_baseline=tenant_baseline)` (`main.py:651-655`).
- The registry is selected at `main.py:562-576`: `PostgresAgentRegistry()` when `database_configured`, else `InMemoryAgentRegistry()`. The ledger is selected the same way (`action_ledger`).
- `pdp = PolicyDecisionPoint(..., agent_evaluator=agent_suite, ...)` (`main.py:876-883`).
- The suite is also placed on app state: `app.state.agent_suite = runtime.agent_suite` (`main.py:1606`), and the registry: `app.state.agent_registry = runtime.agent_registry` (`main.py:1603`).

### LIVE call path #1 — evaluation (the verdict path)

```
HTTP route (e.g. POST /v1/guardrail/evaluate)
  api/guardrail.py:828  command.execute(domain_request)          # EvaluateActionCommand
    commands/evaluate_action.py:214  self._pdp.evaluate(request, policy)
      engine/pdp.py:282-283  agent_bundle = self._agent_evaluator.evaluate(request)   # ← AgentEvaluationSuite.evaluate
        agent/suite.py:91  self._registry.require_evaluable(request.agent_id)
        agent/suite.py:93-95  identity/capability/behavioral .evaluate(...)
      engine/pdp.py:377/385  self._router.route(..., agent_bundle=agent_bundle)
        engine/router.py:226-228  fuses identity/capability/behavioral risk_scores
        engine/router.py:302-303  all_findings.extend(agent_bundle.all_findings)
        engine/router.py:503-504  confidences["agent"] = agent_bundle.aggregate_confidence
```

The agent bundle's three risk scores and aggregate confidence are **fused into the final verdict** at the router (`engine/router.py:226-228, 503-504`) and the agent findings feed the final finding set (`router.py:302-303`). This is a true verdict influence, not dead metadata. The PDP protocol contract is `AgentEvaluator` (`engine/pdp.py:102-112`), which `AgentEvaluationSuite` satisfies structurally (it exposes `evaluate(request) -> AgentEvaluationBundle`).

`EvaluateActionCommand` is constructed with `agent_registry=agent_registry` (`main.py:969`, `commands/evaluate_action.py:141,181`) and itself resolves/auto-registers controlled agents (`_ensure_controlled_agent_registered`, called at `commands/evaluate_action.py:213`).

### LIVE call path #2 — registry CRUD / lifecycle (the management path)

```
build_agent_router()  api/agent_routes.py:987     (mounted at main.py:1443: app.include_router(build_agent_router()))
  POST  (register)   api/agent_routes.py:1006-1034  registry.save(agent)
  PATCH (update)     api/agent_routes.py:1251-1297  registry.save(candidate)
  POST  (lifecycle)  api/agent_routes.py:1300-1320  registry.set_lifecycle(agent_id, payload.status)
  GET   (read/list/history)  api/agent_routes.py:1037-1401  registry.get/list_all/list_by_status/history
    _resolve_registry(request) reads request.app.state.agent_registry  (agent_routes.py:456-457)
```

The registry is also consumed by `api/discovery_surface_routes.py`, and threaded into the contract enforcement / twin-state / institutional subsystems (`main.py:705,747,764,788,969,1083,1187,1740`).

**`wired_status = LIVE`.** Both paths trace from mounted FastAPI routes through `build_runtime` composition. No lazy/feature-flag guard hides the agent suite from the PDP — it is unconditionally constructed and injected (`main.py:651-655, 878`). The only conditional is in-memory vs Postgres *backend* selection (`main.py:562`, driven by `database_configured`), not on/off.

### Wiring OUT (what this unit depends on)

**Internal tex subsystems:**
- `tex.domain.agent` — `AgentIdentity`, `AgentEnvironment`, `AgentLifecycleStatus`, `AgentTrustTier`, `BehavioralBaseline` (the abstractions).
- `tex.domain.agent_signal` — `AgentIdentitySignal`, `CapabilitySignal`, `BehavioralSignal`, `AgentEvaluationBundle` (the outputs).
- `tex.domain.evaluation` — `EvaluationRequest` (input).
- `tex.domain.finding` / `tex.domain.severity` — `Finding`, `Severity` (structured findings).
- `tex.domain.tenant_baseline` — `TenantContentBaselineLookup`, `compute_content_signature` (V11 MinHash novelty).
- `tex.stores.agent_registry` — `InMemoryAgentRegistry`, `AgentNotFoundError`, `AgentRevoked`.
- `tex.stores.action_ledger` — `InMemoryActionLedger` (behavioral substrate).
- `tex.stores.tenant_content_baseline` — `InMemoryTenantContentBaseline` (optional).
- (transitively, via the registry) `tex.selfgov.governor` — `gate_controller_mutation`, `describe_agent_save`, `describe_lifecycle`.

**External libraries:** none used directly inside `src/tex/agent/`. Only stdlib (`uuid.UUID`). Pydantic is used by the domain models it imports, not by the evaluators themselves.

---

## Implementation Reality

**REAL.** The four in-scope files are dense, branchy, deterministic scoring logic with no stubs, no `NotImplementedError`, no `TODO`, and no `pass`-only placeholders. Verified by reading all 1,115 lines.

- **No stubs / placeholders:** grep for `NotImplementedError|TODO|FIXME|raise NotImplementedError` across the four files returns nothing. The only "future revision" notes are honest tuning deferrals, not missing logic:
  - `identity_evaluator.py:34` "Tunable via policy in a future revision" — the value (`_FRESH_AGENT_SECONDS=3600`) is real and used (`136`).
  - `behavioral_evaluator.py:59-60` thresholds "policy layer can override … without changing this file" — the thresholds (`0.85`, `0.65`) are real and used (`341,366`).
  - `domain/agent.py:259-261` "cryptographic verification belongs to a pluggable verifier in a future revision" — **this is a real gap:** `AgentAttestation` stores a `signature` field (`domain/agent.py:269`) but the identity evaluator only **counts** attestations and checks expiry (`identity_evaluator.py:107-133`); it never verifies the signature. The signature is unverified provenance. (Honest in the docstring; flagged below.)

- **Scoring is genuine, not cosmetic:** every sub-score feeds the max-mean composition that becomes `risk_score`, which the router fuses into the verdict (call path #1 above). The QUARANTINED override (`identity_evaluator.py:147-149` → 1.0) and the capability hard-block (`capability_evaluator.py:127-132` → up to 1.0 + CRITICAL findings) are real enforcement levers.

- **Behavioral baseline math is real and deterministic:** `compute_baseline` (`action_ledger.py:119-200`) computes verdict rates, action/channel/domain distributions, mean score, capability-violation rate, and the contiguous forbid streak from the actual ledger window — pure function, no randomness.

- **V11 tenant novelty is real:** `compute_content_signature` and the Jaccard-based novelty flow are wired (`behavioral_evaluator.py:295-301`), gated behind the optional `tenant_baseline` (None-safe via `_neutral_tenant_lookup`, `432-449`). When the tenant baseline is not wired, the evaluator reproduces V10 behavior exactly (`behavioral_evaluator.py:73-76`, verified: tenant fields default neutral and emit only an uncertainty flag). In the live runtime the tenant baseline **is** wired (`main.py:654`).

- **No crypto/zk/tee in this unit.** (The signature-verification gap above is the only cryptographic touchpoint, and it is unimplemented.)

- **Graceful-degradation paths are real, not hollow:** neutral signals (`identity_evaluator.py:186-206`, `capability_evaluator.py:168-182`, `behavioral_evaluator.py:408-429`) are fully-formed valid signals, not empty stubs; the PDP uses them to keep unit tests / minimal compositions working without the agent stack (`pdp.py:282-285`).

---

## Technology / SOTA

- **Multi-stream evidence fusion**: three independent risk signals (identity/capability/behavioral) each emitting `(risk_score, confidence, findings, uncertainty_flags)` — a peer-to-peer evidence model fused downstream by the router rather than a monolithic score. The "seven-stream fusion" framing (`behavioral_evaluator.py:14`, `suite.py` neighborhood) is borne out: agent contributes 3 of the streams the router weighs (`engine/router.py:226-228`).
- **Weighted max-mean aggregation** (`identity_evaluator.py:158` `0.6*mean + 0.4*max`; `behavioral_evaluator.py:234` `0.55*mean + 0.45*max`): a deliberate compromise between averaging (catches steady drift) and max (catches single-axis spikes). Documented intent matches code.
- **MinHash / Jaccard content novelty at tenant scope** (V11): `compute_content_signature` + `TenantContentBaselineLookup.novelty_score = 1 - max Jaccard similarity` (`domain/agent_signal.py:230-238`, `behavioral_evaluator.py:295-301`). This is the cross-agent "no agent in your tenant has ever sent content like this" signal (`behavioral_evaluator.py:12-27`).
- **Immutable-by-revision identity** (event-sourcing-lite): every registry mutation produces a new `AgentIdentity` revision while preserving history (`agent_registry.py:88-98,121-130`); the identity record is "hashed into the evidence chain on every decision" (`domain/agent.py:316`, claim — the hashing happens in the evidence subsystem, not here).
- **Environment-alias normalization** to avoid spurious mismatches (`identity_evaluator.py:228-255`), mirrored in `EvaluateActionCommand._coerce_environment` (referenced `identity_evaluator.py:227`).
- **Strict domain modeling**: frozen Pydantic v2 models with `extra='forbid'`, tz-aware datetime enforcement, dedup/casefold normalizers, hex-digest validators (`domain/agent.py` throughout; `domain/agent_signal.py`).
- **Posture-as-evidence**: an unrestricted capability surface is itself surfaced as low-grade risk + uncertainty (`capability_evaluator.py:134-143`) — the docstring's "first-class evidence stream, not a separate dashboard" (`domain/agent.py:158-161`) is realized in code.

---

## Persistence

- **The `agent` unit itself holds no state** — evaluators are stateless; the suite holds only references. Confirmed via `__slots__` (`suite.py:56-63`, `behavioral_evaluator.py:78`) and the absence of any mutation of `self` in `evaluate()`.
- **Durable-ish state lives in the stores:**
  - `InMemoryAgentRegistry` — **in-memory**, `RLock`-guarded dicts (`agent_registry.py:44-50`). Lost on process restart. The **durable** path is `PostgresAgentRegistry` (`main.py:564,569`), selected when `database_configured`.
  - `InMemoryActionLedger` — **in-memory**, bounded `deque(maxlen=5000)` per agent (`action_ledger.py:44,66`); oldest entries roll off (`action_ledger.py:30-37`). Durable path: `PostgresActionLedger` (`main.py:563,571`).
- **`BehavioralBaseline` is never stored** — recomputed at evaluation time from the latest ledger window (`domain/agent.py:535-539`; `action_ledger.py:119-200`; consumed `behavioral_evaluator.py:97`). Verified: no field on any store persists a baseline.
- **Tenant content baseline** state lives in `InMemoryTenantContentBaseline` (out of scope; wired at `main.py:654`).

---

## Notable Findings

1. **Attestation signatures are stored but never verified.** `AgentAttestation.signature` exists (`domain/agent.py:269`) and the docstring says crypto verification "belongs to a pluggable verifier in a future revision" (`domain/agent.py:259-261`). The identity evaluator only counts active/expired attestations (`identity_evaluator.py:107-133`); a forged-but-unexpired attestation would *lower* identity risk just as a real one would. This is an honest, documented gap — not an overstatement — but it means "attestations reduce risk" is trust-on-assertion, not trust-on-proof.

2. **`_lifecycle_risk` is missing the `SLEEPING` case → latent `KeyError`.** `AgentLifecycleStatus` defines five states incl. `SLEEPING` (`domain/agent.py:53-57`), and `require_evaluable` lets SLEEPING pass through (it only rejects REVOKED, `agent_registry.py:154-156`; `AgentLifecycleStatus.can_evaluate` includes SLEEPING, `domain/agent.py:60-70`). But `_lifecycle_risk` (`identity_evaluator.py:214-220`) has keys for only ACTIVE/PENDING/QUARANTINED/REVOKED. A SLEEPING agent reaching the identity evaluator would raise `KeyError`. The richly-documented "dormant doctrine / SLEEPING forces ABSTAIN" behavior (`domain/agent.py:43-77`) is **not** implemented in the identity stream (no SLEEPING branch anywhere in `identity_evaluator.py`). **(claim in docstring, unverified in this evaluator — and actively buggy if hit.)** Whether it can be hit depends on whether anything ever sets status to SLEEPING; grep is warranted before relying on it.

3. **Registry self-governance gate is inert by default.** `save`/`set_lifecycle` route through `gate_controller_mutation` (`agent_registry.py:70,111`), but with no governor bound the gate returns `_UNGATED (allowed=True)` (`selfgov/governor.py:484-486`). So in the default runtime, registry mutations are *not* actually governed — the chokepoint is wired but dormant. This matches the project memory note that governance is "inert" unless explicitly bound. Real, but quiescent.

4. **The "InMemoryAgentRegistry" named in the brief is out-of-scope-of-the-directory but is the spine the unit reads.** It lives in `tex.stores.agent_registry`, not `tex.agent`. The `agent` directory contains only evaluators + the suite; the registry/ledger/domain models live under `stores/` and `domain/`. Anyone auditing "the agent unit" must follow those imports (done here).

5. **`__init__.py` is a pure marker.** No re-exports — every consumer imports concrete symbols from the submodules directly (`suite.py`, `identity_evaluator.py`, etc.). The `__all__` that matters is in `suite.py:117-121`, not the package `__init__`.

6. **Spine classification "agent = LIVE" is confirmed.** Two independent live call paths (evaluation via PDP, CRUD via `build_agent_router`) trace from mounted routes through `build_runtime`. The agent bundle measurably moves the verdict (router fusion at `engine/router.py:226-228`). No orphan, no demo-only gating.

7. **Docstrings are accurate where checked.** The "no regression on content-only requests" contract (`suite.py:5-12`), "REVOKED is terminal" (`suite.py:89-90`), "stateless / thread-safe" claims, the V10-bit-for-bit-when-no-tenant-baseline claim (`behavioral_evaluator.py:73-76`), and "QUARANTINED forces risk 1.0" (`identity_evaluator.py:147-149`) all match the code. The one material divergence between docstring and code is the SLEEPING dormant doctrine (#2).

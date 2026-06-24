# Subsystem Dossier — `selfgov` (Reflexive Self-Governance)

> Code-cited audit. Every important claim is traced to `file:line` by reading the
> code, not docstrings. Branch: `feat/proof-carrying-gate` (working tree was on
> `fix/entity-grounding-kwarg` at audit time; selfgov files identical). All paths
> absolute. Import checks run with `PYTHONPATH=/Users/matthewnardizzi/dev/tex/src`.

---

## Overview

- **Unit:** `tex.selfgov` — "Tex governs its OWN controller."
- **Layer:** **5** (declared in code: `__layer__ = 5`, `__layer_kind__ = "self_governance"` at `/Users/matthewnardizzi/dev/tex/src/tex/selfgov/__init__.py:10-11`). Called "Wave 2 / L5" / the *meta-circular stratum*.
- **One line:** A single chokepoint API, `gate_controller_mutation(descriptor)`, that routes Tex's *own controller mutations* (the writes that change what Tex decides NEXT — policy activate/save/delete/clear, proposal apply/rollback, agent lifecycle/capability surface, in-process key material) through the **same** `PolicyDecisionPoint`, the **same** ABSTAIN surface, the **same** monotone+floor rules, and seals each ruling as a `SealedFact(ENFORCEMENT)` into the **same** hash-chained ledger the DECISION seam uses.
- **Maturity (self-declared, accurate):** `research-early`. The module is **inert until bound** via `bind_reflexive_governor`, and **production never binds it.**
- **`wired_status`:** **WIRED-BUT-INERT (opt-in, never opted-in in production).** The gate *call-sites* are live at 6 real chokepoint modules, but with the governor unbound (the production default) every call returns `_UNGATED` (`allowed=True, gated=False`) — i.e. today's behaviour byte-for-byte. The only place anything binds the governor is `capstone/flow.py` (a demo/test runner) and the test suite. **`tex.main` does not import, reference, or bind it anywhere** (`grep -in "reflexiv|selfgov|bind_reflex|gate_controller|capstone" src/tex/main.py` → no matches; `main.py` is 2027 lines).

**Empirical smoke test (run at audit time):**
```
layer: 5 self_governance
bound at import (production default): False
unbound gate -> allowed=True gated=False verdict=UNGATED mechanism=ungated
census entries: 36   (WIRED=18, COVERED_VIA=10, EXCLUDED=8)
deploy_frozen entries: 10
tests/test_reflexive_gov.py -> 26 passed
```

---

## File Inventory

| File (absolute) | Lines | Role |
|---|---|---|
| `/Users/matthewnardizzi/dev/tex/src/tex/selfgov/__init__.py` | 28 | Package marker. Sets `__layer__ = 5`, `__layer_kind__ = "self_governance"`; re-exports the public API from `governor.py` (12 symbols). |
| `/Users/matthewnardizzi/dev/tex/src/tex/selfgov/governor.py` | 1018 | The entire unit: the deploy-frozen stratum constants, the controller-mutation census (the self-census table), the gate types, the binding lifecycle, the gate itself, the monotone verdict composer, the EvaluationRequest builder, the ENFORCEMENT sealer, and 9 typed descriptor builders. |

There are exactly **2 `.py` files** (1046 lines total). The rule-engine half the gate composes with (`metaguard`) lives **outside** this package at `/Users/matthewnardizzi/dev/tex/src/tex/specialists/metaguard.py` (371 lines) — see *Technology*.

---

## Internal Architecture

`governor.py` is structured in seven bands. Citations are `governor.py:<line>` unless noted.

### 1. Module honesty boundary (docstring, `:1-103`)
A long module docstring that is, unusually, an *honesty contract*. It explicitly enumerates what is **NOT** claimed (`:20-44`): NOT "provably cannot ungovern itself"; NOT a proven-complete mutation surface (the census is *enumerated + tripwired*, not proven); NOT protection against arbitrary in-process code (an attacker running Python can monkeypatch the gate out — named at `:28-31`); and the gate is **inert until bound** with the warning at `:36-37`: *"Production today does not bind it — say 'the capability is wired and opt-in,' never 'Tex is reflexively governed by default.'"* This audit confirms that warning is accurate.

### 2. Level-0 deploy-frozen stratum (`:143-215`)
- `GOVERNOR_POLICY_ID = _mg.GOVERNOR_POLICY_ID` = `"reflexive-governor"` (`:147`).
- `GOVERNOR_POLICY_VERSION = "reflexive-governor-frozen-v1"` (`:148`).
- `GOVERNOR_FROZEN_POLICY` (`:157-164`) — a **code-constant `PolicySnapshot`**, deliberately never stored in any policy store (so no in-process mutation path reaches it). `permit_threshold=0.35`, `forbid_threshold=0.65`, **`minimum_confidence=0.0`**. The `0.0` is documented honestly (`:150-156`): the PDP's confidence on descriptor-JSON is uncalibrated (measured ~0.58 on neutral descriptors), so a confidence gate would ABSTAIN-deny every routine mutation; the real deny power lives in metaguard.
- `DEPLOY_FROZEN_STRATUM` (`:169-215`) — a 10-entry tuple of `(target, reason)` naming what the gate **cannot** reach in-process (env vars `TEX_SEAL_DECISIONS`, `TEX_API_KEYS`, `DATABASE_URL`, `TEX_EVIDENCE_KEY_DIR`, etc.; the evidence-seal key *file*; the frozen policy + metaguard signatures themselves; the binding capability token; arbitrary in-process code; live ledger/PDP reference swaps at the composition root). This is the "gate the gate terminates here" boundary.

### 3. The census types + the census itself (`:218-278`)
- `MutationSite` (`:222-229`) — frozen dataclass: `path, qualname, status, note`.
- `CONTROLLER_MUTATION_CENSUS` (`:232-273`) — **the self-census table** (reproduced in full below).
- An "enumerated-deferred" residual comment (`:275-278`) naming agent attestation/trust-tier changes as not-yet-classified.

### 4. Gate types (`:281-327`)
- `MutationDescriptor` (`:285-293`) — frozen dataclass, the typed mutation attempt as the gate sees it: `surface, mutation_class, subject_id, payload, environment="production"`.
- `GateOutcome` (`:296-310`) — the ruling. **`allowed: bool` is the only field a chokepoint consults** (`:298-299`); the rest is audit surface (`gated, verdict, mechanism, reasons, floor_codes, caution_codes, hold, enforcement_record, decision_sealed`).
- `_MECHANISMS` (`:313-322`) — the 8 named ways a ruling is produced: `ungated, no_change, stage_pass, registration_pass, protective_pass, pdp+metaguard, no_regress_backstop, error_fail_closed`.
- `_UNGATED` (`:324-327`) — the cached `allowed=True, gated=False, verdict="UNGATED"` outcome returned when unbound.

### 5. Binding lifecycle (`:330-457`)
- `_Binding` (`:334-339`) — holds the duck-typed `pdp`, `policy`, optional `ledger`, and the capability `token` (an opaque `object()`).
- Module-global state: `_BINDING_LOCK` (RLock), `_BINDING` (the single live binding or `None`), `_EVAL_DEPTH` (a `ContextVar` for the no-regress backstop), `_observed_max_eval_depth` (test-visible high-water mark) (`:342-349`).
- `bind_reflexive_governor(*, pdp, ledger=None, policy=None) -> token` (`:352-403`) — binds and seals a PERMIT `protective_pass`. **Re-binding while bound is denied, sealed, AND raises** (`:368-380`) — the one deliberate exception to deny-by-not-raising, because a silently-ignored bind would leave the caller believing it is governed (fail-open).
- `unbind_reflexive_governor(token) -> bool` (`:406-438`) — a **foreign token** is denied by *returning `False`* and sealing the attempt (`:413-421`); the correct token unbinds and seals.
- `reflexive_governor_bound() -> bool` (`:441-442`).
- `bound_reflexive_governor(...)` (`:445-457`) — a `@contextmanager` test/composition helper that binds for the block. **This is the only entry point any non-test caller uses** (capstone).

### 6. The gate (`:460-654`)
- `gate_controller_mutation(descriptor | callable)` (`:464-513`) — **THE single reflexive chokepoint API.** Fast path: `if _BINDING is None: return _UNGATED` (`:483-485`) — one `None` check, never builds the descriptor (the chokepoints pass a zero-arg lambda so the inert path is zero-cost). Bound path delegates to `_gate_bound`. **Any internal error → fail-closed deny** (FORBID, sealed, never raises) (`:486-513`).
- `_gate_bound(binding, descriptor)` (`:516-640`) — the real ruling, in order:
  1. `evaluate_metaguard(descriptor)` (`:519`).
  2. **no-change fast pass** (byte-identical / missing target): PERMIT, no seal (`:524-528`).
  3. **no-regress backstop** (`:534-549`): if `_EVAL_DEPTH > 0` (a gated mutation attempted *during* a gate evaluation), deterministic FORBID, sealed, no recursion.
  4. **deterministic fast passes when metaguard didn't fire** (`:554-584`): `stage_pass` (new inactive snapshot, unsealed), `registration_pass` (new agent identity birth, unsealed), `protective_pass` (mutation toward caution — PERMIT, sealed).
  5. **full ruling** (`:586-640`): increments `_EVAL_DEPTH`, calls `binding.pdp.evaluate(request=_build_request(descriptor), policy=binding.policy)`, composes the verdict, builds a metaguard hold if metaguard demoted a PERMIT to ABSTAIN with no PDP hold (`:612-621`), seals the ENFORCEMENT fact, and returns.
- `compose_gate_verdict(pdp_verdict, mg)` (`:643-654`) — **monotone composition**: `mg.floor → FORBID`; `mg.caution and pdp PERMIT → ABSTAIN`; otherwise the PDP verdict unchanged. Metaguard can only LOWER, never raise.

### 7. Request building, sealing, descriptor builders (`:657-1018`)
- `_IRREVERSIBLE_CLASSES = {POLICY_DELETE, POLICY_CLEAR, KEY_MUTATION}` (`:662`).
- `_build_request(descriptor)` (`:665-689`) — builds an `EvaluationRequest` (`action_type="controller_mutation"`, `channel="selfgov"`), hashing the payload (sha256) and, for irreversible classes, attaching the existing wired `metadata["action_class"]` (IRREVERSIBLE × **TENANT** blast — honestly *not* PUBLIC, so the L4 structural floor does **not** fire on it; `:678-681`).
- `_seal_enforcement(...)` (`:692-744`) — builds and appends a `SealedFact(kind=SealedFactKind.ENFORCEMENT, maturity=RESEARCH_EARLY)`. The sealed `claim` text is itself honesty-bounded (`:714-721`): *"…gate outcome sealed (authorship+integrity); verdict correctness NOT proven; mutation-surface completeness NOT proven (enumerated census…)."* **Fail-closed:** `ledger is None → return None`; an append failure is logged and degrades to "not sealed," never crashes the ruling (`:736-744`).
- **9 descriptor builders** (`:773-990`): `describe_policy_save`, `describe_policy_activate`, `describe_policy_delete`, `describe_policy_clear`, `describe_proposal_apply`, `describe_proposal_rollback`, `describe_standing_activate`, `describe_lifecycle`, `describe_agent_save`, plus `describe_key_mutation`. These read the *current* store state (`store.get(...)`, `store.get_active()`) to diff old→new and compute `weakening_axes` / `widened_dimensions`, which is what gives metaguard its deterministic deny power. They are duck-typed and exception-safe (a builder error fails the gate closed).
- `__all__` (`:993-1018`) — 23 exported symbols.

### The self-governance model (what it gates and what "reflexive" means in code)
"Reflexive / L5" means: the **same** `PolicyDecisionPoint` instance that rules customer actions is bound (via `bind_reflexive_governor(pdp=...)`) and re-used to rule *mutations to Tex's own controller*. A controller mutation is operationally defined (`governor.py:10-18`) as a write that changes what Tex decides next. The "gate the gate" regress is terminated by the **two-level stratum** (`:71-80`): level-1 surfaces are gated+sealed; level-0 (the governor's own frozen policy, the metaguard signature set, the binding token) is **deploy-frozen** — mutating it is a redeploy, not a gateable in-process operation — and any *stored-policy impersonation* of the governor policy family floors deterministically via `metaguard.governor_self_target`. The recursion surface is additionally killed at runtime by the `_EVAL_DEPTH` no-regress backstop (a gated mutation attempted mid-evaluation is denied without recursion; pinned by test, max depth proven = 1).

---

## The Self-Census Table (reproduced in full)

This is `CONTROLLER_MUTATION_CENSUS` at `/Users/matthewnardizzi/dev/tex/src/tex/selfgov/governor.py:232-273`. **36 entries**, status counts (verified by running the module): **WIRED = 18, COVERED_VIA = 10, EXCLUDED = 8** (the 4 "SHOULD" entries at `:264-267` carry status `EXCLUDED`, so they fold into the 8). Reproduced verbatim by `path | qualname | status | note`:

**MUST — chokepoints (WIRED: a `gate_controller_mutation` call sits at the method definition):**

| path | qualname | status | note |
|---|---|---|---|
| `src/tex/stores/policy_store.py` | `InMemoryPolicyStore.save` | WIRED | base store under the wrapper; dev/test compositions use it directly |
| `src/tex/stores/policy_store.py` | `InMemoryPolicyStore.activate` | WIRED | verdict-changing flip |
| `src/tex/stores/policy_store.py` | `InMemoryPolicyStore.delete` | WIRED | evidence destruction |
| `src/tex/stores/policy_store.py` | `InMemoryPolicyStore.clear` | WIRED | evidence destruction |
| `src/tex/memory/policy_snapshot_store.py` | `DurablePolicyStore.save` | WIRED | the ONE live instance (main.py:557 `policy_store = memory.policies`); save can replace active-version bytes |
| `src/tex/memory/policy_snapshot_store.py` | `DurablePolicyStore.save_in_tx` | WIRED | eval-path idempotent re-persist is a no_change fast pass; byte-replacement is gated |
| `src/tex/memory/policy_snapshot_store.py` | `DurablePolicyStore.activate` | WIRED | THE chokepoint: ActivatePolicyCommand/CalibratePolicyCommand/FeedbackLoopOrchestrator all converge here |
| `src/tex/memory/policy_snapshot_store.py` | `DurablePolicyStore.delete` | WIRED | gated before the postgres delete |
| `src/tex/memory/policy_snapshot_store.py` | `DurablePolicyStore.clear` | WIRED | cache wipe |
| `src/tex/learning/feedback_loop.py` | `FeedbackLoopOrchestrator.apply_proposal` | WIRED | METHOD is the gate unit (save+activate+safety-commit are all-or-nothing on deny; gate sits before approve) |
| `src/tex/learning/feedback_loop.py` | `FeedbackLoopOrchestrator.rollback_proposal` | WIRED | rollback activates an older version; weakening rules apply to the target |
| `src/tex/governance/standing.py` | `StandingGovernance.activate` | WIRED | caller swallows exceptions (api/discovery_surface_routes.py:212-213) → gate denies by NOT mutating, never by raising |
| `src/tex/stores/agent_registry.py` | `InMemoryAgentRegistry.save` | WIRED | capability_surface replacement moves the structural floor; save can also flip lifecycle wholesale (lifecycle rules applied to saves) |
| `src/tex/stores/agent_registry.py` | `InMemoryAgentRegistry.set_lifecycle` | WIRED | QUARANTINED→ACTIVE is a verdict-RAISING mutation reachable entirely outside commands/ (agent_routes.py:1300-1323, dormancy.wake) |
| `src/tex/c2pa/signer.py` | `register_signing_key` | WIRED | in-process key material |
| `src/tex/c2pa/signer.py` | `clear_signing_keys` | WIRED | in-process key material |
| `src/tex/c2pa/signer.py` | `set_keystore` | WIRED | in-process key material (keystore lookup swap) |
| `src/tex/evidence/seal.py` | `_persist_key` | WIRED | the only in-process write of the evidence seal key file; file replacement from outside the process is DEPLOY_FROZEN |

**MUST — covered via a WIRED chokepoint (delegation pinned by tripwire):**

| path | qualname | status | note (the pinned delegation line) |
|---|---|---|---|
| `src/tex/commands/activate_policy.py` | `ActivatePolicyCommand.execute` | COVERED_VIA | `self._policy_store.activate(` |
| `src/tex/commands/calibrate_policy.py` | `CalibratePolicyCommand.execute` | COVERED_VIA | `self._policy_store.activate(` |
| `src/tex/memory/system.py` | `MemorySystem.activate_policy` | COVERED_VIA | `self.policies.activate(` |
| `src/tex/memory/system.py` | `MemorySystem.record_policy_snapshot` | COVERED_VIA | `self.policies.save(` |
| `src/tex/stores/agent_registry_postgres.py` | `PostgresAgentRegistry.set_lifecycle` | COVERED_VIA | `self._cache.set_lifecycle(` |
| `src/tex/stores/agent_registry_postgres.py` | `PostgresAgentRegistry.save` | COVERED_VIA | `self._cache.save(` |
| `src/tex/discovery/dormancy.py` | `DormancyManager.wake` | COVERED_VIA | `self._registry.set_lifecycle(` |
| `src/tex/discovery/service.py` | `apply (capability surface / quarantine)` | COVERED_VIA | `self._registry.set_lifecycle(` |
| `src/tex/api/agent_routes.py` | `transition_lifecycle` | COVERED_VIA | `registry.set_lifecycle(` |
| `src/tex/api/learning_routes.py` | `apply/rollback proposal routes` | COVERED_VIA | `orch.apply_proposal(` |

**SHOULD — enumerated and decided (all statused EXCLUDED):**

| path | qualname | status | note |
|---|---|---|---|
| `src/tex/stores/calibration_proposal_store.py` | proposal status transitions | EXCLUDED | proposals parameterize nothing until apply_proposal — which is WIRED; staging metadata, not a controller mutation |
| `src/tex/learning/outcome_validator.py` | `_quarantine` | EXCLUDED | produces a ValidationResult marking an OUTCOME quarantined (evidence hygiene); does not transition agent lifecycle or policy |
| `tenant_content_baseline` | baseline writes | EXCLUDED | observational baselines feed drift detection (signals may only LOWER a verdict — monotone rule caps blast radius); enumerated-deferred for a future census revision |
| `src/tex/provenance/ledger.py` | keygen-on-construct (:71-73) | EXCLUDED | constructing a NEW ledger does not mutate the live one; the live reference swap is DEPLOY_FROZEN (composition root) |

**EXCLUDED — one-line reasons:**

| path | qualname | status | note |
|---|---|---|---|
| decision/precedent/outcome/entity stores | `*` | EXCLUDED | evidence records — they record what happened, they do not parameterize verdicts |
| `src/tex/api/auth.py` | `:279 activate example` | EXCLUDED | docstring usage example inside RequireScope, not a route |
| ledger appends | `SealedFactLedger.append / recorder` | EXCLUDED | governance OUTPUT (append-only evidence), not a controller mutation; gating them would recurse the seal |
| **`nanozk / compliance / _pending`** | `*` | **EXCLUDED** | **dead code per CLAUDE.md — tested but not wired** |

### What the table *means* — and why it is un-mined ground truth

This census is Tex's own machine-checked declaration of **which write surfaces actually change what it decides next**, and which do not. Three load-bearing meanings:

1. **It is a self-audit of the controller surface, tripwired by `tests/test_reflexive_gov.py`.** WIRED entries assert a `gate_controller_mutation` call literally sits at the method body (verified — see *Wiring*); COVERED_VIA entries pin the exact delegation line (e.g. `ActivatePolicyCommand.execute` is covered because it calls `self._policy_store.activate(`). The "completeness" of the surface is `addressed by enumeration, not proven` (`governor.py:24-27`).

2. **The last EXCLUDED row is a cross-subsystem death certificate.** `MutationSite("nanozk / compliance / _pending", "*", "EXCLUDED", "dead code per CLAUDE.md — tested but not wired")` (`governor.py:272`) is the un-mined ground truth: selfgov *formally excludes compliance, nanozk, and `_pending` from the controller-mutation surface on the grounds that they are dead*. This is corroborated independently of this module:
   - `CLAUDE.md:33` — *"`compliance/**` and `_pending/**` are tested but **dead** — a passing test there ≠ wired."*
   - `CLAUDE.md:32` — nanozk is a *"DEACTIVATED placeholder … computes HMAC/hash stand-ins, not real proofs … hard-gated fail-closed."*
   - `docs/blueprint/_spine/reachability.md:27,101,191` — `_pending` = **ORPHAN** (33 files, zero importers); `compliance` = tests-only.
   So if another doc cites this census line to declare compliance dead/alive, the citation is **accurate**: compliance is dead (tests-only, no live importer; `main.py` imports neither compliance nor nanozk — grep confirmed).

3. **It honestly names the residual.** The `:275-278` comment and the SHOULD/EXCLUDED lists are the "what we did NOT gate and why" ledger — agent attestation/trust-tier changes via `registry.save` are *enumerated-deferred* (census v1 gates capability widening + lifecycle flips only). This is the opposite of an overclaim: the gap is named in code.

---

## Public API

Re-exported from `tex.selfgov` (`__init__.py:13-28`) and declared in `governor.py:__all__` (`:993-1018`):

**Constants / types:** `CONTROLLER_MUTATION_CENSUS`, `DEPLOY_FROZEN_STRATUM`, `GOVERNOR_FROZEN_POLICY`, `GOVERNOR_POLICY_ID` (`"reflexive-governor"`), `GOVERNOR_POLICY_VERSION` (`"reflexive-governor-frozen-v1"`), `GateOutcome`, `MutationDescriptor`, `MutationSite`.

**The gate + composition:** `gate_controller_mutation` (the single chokepoint API), `compose_gate_verdict`.

**Binding lifecycle:** `bind_reflexive_governor`, `unbind_reflexive_governor`, `reflexive_governor_bound`, `bound_reflexive_governor` (context manager).

**Descriptor builders (in `__all__` but NOT re-exported by the package `__init__`):** `describe_policy_save`, `describe_policy_activate`, `describe_policy_delete`, `describe_policy_clear`, `describe_proposal_apply`, `describe_proposal_rollback`, `describe_standing_activate`, `describe_lifecycle`, `describe_agent_save`, `describe_key_mutation`. (Chokepoints import these directly from `tex.selfgov.governor`, not from the package root.)

---

## Wiring (importers + live path)

**9 src importers** (matches the "~9 importers" expectation), **3 test files**, **0 scripts** import `tex.selfgov` directly. Classification:

| Importer (absolute) | What it imports | Call-site | Class |
|---|---|---|---|
| `/Users/matthewnardizzi/dev/tex/src/tex/stores/policy_store.py` | `gate_controller_mutation` + 4 `describe_policy_*` (`:7-12`) | real gate calls at `:54, :155, :182, :197` | **LIVE chokepoint** |
| `/Users/matthewnardizzi/dev/tex/src/tex/memory/policy_snapshot_store.py` | `gate_controller_mutation` + describers (`:30-35`) | gate calls at `:98, :112, :153, :179, :206` | **LIVE chokepoint** (this is the ONE production policy store: `main.py:565 policy_store = memory.policies`) |
| `/Users/matthewnardizzi/dev/tex/src/tex/learning/feedback_loop.py` | `gate_controller_mutation` + proposal describers (`:71-74`) | gate calls at `:662, :732` | **LIVE chokepoint** |
| `/Users/matthewnardizzi/dev/tex/src/tex/governance/standing.py` | `describe_standing_activate, gate_controller_mutation` (`:86`) | gate call at `:233` | **LIVE chokepoint** |
| `/Users/matthewnardizzi/dev/tex/src/tex/stores/agent_registry.py` | `gate_controller_mutation` + agent describers (`:20-23`) | gate calls at `:70, :111` | **LIVE chokepoint** |
| `/Users/matthewnardizzi/dev/tex/src/tex/c2pa/signer.py` | `describe_key_mutation, gate_controller_mutation` (`:78`) | gate calls at `:108, :116, :126` | **LIVE chokepoint** |
| `/Users/matthewnardizzi/dev/tex/src/tex/evidence/seal.py` | lazy import inside `_persist_key` (`:207`) | gate call at `:209` | **LIVE chokepoint** (lazy, to avoid an import cycle — noted at `seal.py:66`) |
| `/Users/matthewnardizzi/dev/tex/src/tex/specialists/metaguard.py` | only a docstring mention + the shared `GOVERNOR_POLICY_ID` constant (`:80`) | — (selfgov imports metaguard, not vice-versa) | **dependency provider, not an importer of selfgov** |
| `/Users/matthewnardizzi/dev/tex/src/tex/capstone/flow.py` | `bound_reflexive_governor` (`:79`) | **binds** at `:312` `with bound_reflexive_governor(pdp=pdp, ledger=ledger):` | **DEMO/TEST runner** (see below) |

(`src/tex/provenance/enforcement_seal.py:16` only references selfgov in a docstring; it shares the `SealedFactKind.ENFORCEMENT` seam but does not import selfgov code.)

**Test importers:** `tests/test_reflexive_gov.py` (881 lines, 26 tests — the dedicated tripwire suite), `tests/test_attempt_seal.py`, `tests/test_wave2_twelveleap_composition.py`. All three bind via `bound_reflexive_governor`.

### Is there a LIVE bind path from the running app? **No.**

- `tex.main` (the production composition root, 2027 lines) contains **zero** references to `reflexive`, `selfgov`, `bind_reflexive`, `gate_controller`, or `capstone` (grep returned nothing). It builds the runtime (`build_runtime`, `:524`) and the FastAPI app (`create_app`, `:1314`) without ever calling `bind_reflexive_governor`.
- The **only** non-test code that binds the governor is `capstone/flow.py:312`, and `capstone/flow.py` self-describes as a *"demo runner core"* (`:5`) — it is invoked by `scripts/capstone_demo.py:58` and the `tests/capstone/` suite, never by `main.py` or any `tex.api` route.
- The 6 live chokepoints all call `gate_controller_mutation(lambda: …)`. With `_BINDING is None` (the production default — confirmed: `reflexive_governor_bound() == False` at import) every call hits the fast path `return _UNGATED` (`governor.py:483-485`), i.e. `allowed=True` → the mutation proceeds ungoverned.

**True `wired_status`: the call-sites are wired-live; the governor is never bound in production, so the gate is inert (zero behavioural effect) on every production path.** The capability is, exactly as the module says, *"wired and opt-in."* The only opt-in callers are the capstone demo and the test suite.

---

## Implementation Reality

**This is real, working code — not a stub.** Distinctions:

- **Real logic:** the gate (`gate_controller_mutation` / `_gate_bound`), the monotone composer, the no-regress backstop (ContextVar-based, proven max-depth-1 by test), the fail-closed error path, the ENFORCEMENT sealer, and all 9 descriptor builders are fully implemented and exercised by 26 passing tests (`tests/test_reflexive_gov.py` → `26 passed in 1.31s`). When bound (as in capstone/tests), it genuinely evaluates mutations through the real `PolicyDecisionPoint` and seals real `SealedFact(ENFORCEMENT)` records.
- **The honest gap (named in code, not a hidden stub):** the PDP is **uncalibrated for mutation descriptors** (`governor.py:38-44, 150-156`). So the discriminating deny power in bound mode is carried *almost entirely by the deterministic metaguard signatures + frozen thresholds*, not by the probabilistic PDP layers. `minimum_confidence=0.0` is set deliberately so a routine mutation isn't ABSTAIN-denied on uncalibrated confidence. This is research-early, and the code says so.
- **Not a stub, but inert:** the production default is unbound, so in production the entire subsystem is a no-op pass-through. There is no fake/placeholder logic; it simply isn't switched on.
- **No fabrication:** the sealed claim text bakes in its own caveats (`:714-721`); the census refuses to claim completeness (`:24-27`); the module docstring forbids over-reading the name (`:36-37`). This is the most *self-honest* subsystem in the codebase rather than the most over-stated.

**Bottom line:** REAL implementation, GREEN tests, but **WIRED-INERT** — the safety property it describes ("Tex's self-mutations are governed by its own PDP and sealed") is **not in force in production today** because nothing binds it.

---

## Technology

- **Python 3.10+** dataclasses (`frozen=True, slots=True`), `contextvars.ContextVar` (no-regress depth), `threading.RLock` (binding mutual exclusion), `contextlib.contextmanager`.
- **Hard internal dependency on `tex.specialists.metaguard`** (`/Users/matthewnardizzi/dev/tex/src/tex/specialists/metaguard.py`, 371 lines). Metaguard is the deterministic rule engine the gate composes with: it provides the 11 mutation-class constants (`POLICY_ACTIVATE`, `POLICY_WRITE`, `POLICY_DELETE`, `POLICY_CLEAR`, `PROPOSAL_APPLY`, `PROPOSAL_ROLLBACK`, `GOVERNANCE_ACTIVATE`, `AGENT_SAVE`, `LIFECYCLE_TRANSITION`, `KEY_MUTATION`, `GOVERNOR_BINDING`), `evaluate_metaguard()`, `weakening_axes()`, `widened_dimensions()`, and the `MetaguardResult` (`floor`, `caution`, `protective_pass`, `no_change`). The shared `GOVERNOR_POLICY_ID = "reflexive-governor"` is defined in metaguard (`metaguard.py:81`) and re-exported by selfgov. (Note: the docstring positions metaguard as "embedded as `specialists/metaguard.py`" — design choice (A)+(B) at `:46-69`.)
- **Domain dependencies:** `tex.domain.evaluation.EvaluationRequest`, `tex.domain.evidence.EvidenceMaturity`, `tex.domain.policy.PolicySnapshot`, `tex.domain.verdict.Verdict`.
- **Provenance dependency:** `tex.provenance.models.{SealedFact, SealedFactKind, SealedFactRecord}` — the seal is a `SealedFactKind.ENFORCEMENT` fact (the same kind the M0 enforcement seam uses, shared with `provenance/enforcement_seal.py`).
- **The PDP is duck-typed** (`_Binding.pdp: Any` with `.evaluate(request=, policy=)`) — selfgov does **not** import `PolicyDecisionPoint` directly, keeping it decoupled.
- Crypto: none here directly; the chain it seals into is ECDSA-P256-signed (asserted at `:99-102`), but that lives in `provenance`, not selfgov.

---

## Persistence

- **The subsystem itself holds no durable state.** Its only state is the process-global `_BINDING` (in-memory, `None` in production) and a `ContextVar` eval-depth counter. There is no DB table, file, or store owned by selfgov.
- **What it writes:** when bound *with a ledger*, each governed ruling appends one `SealedFact(ENFORCEMENT)` to the bound `SealedFactLedger` (`_seal_enforcement`, `:692-744`). That ledger is the hash-chained, ECDSA-P256-signed provenance chain owned by `tex.provenance` — persistence is delegated, append-only, and **fail-closed** (a seal failure degrades to "not sealed," never crashes the gate).
- **`ledger=None` is valid** (`bind_reflexive_governor(..., ledger=None)`): the gate still rules, it just seals nothing. So "governed but unsealed" is a legal mode.
- `GOVERNOR_FROZEN_POLICY` is a **code constant**, deliberately never persisted to any policy store — that is the architectural guarantee that no in-process mutation path can reach the governor's own policy (`:150-156`).

---

## Notable Findings

1. **WIRED-INERT is the headline.** The 6 chokepoints carry real `gate_controller_mutation` calls (live), but `tex.main` never binds the governor, so in production every call returns `_UNGATED (allowed=True)` and the subsystem has **zero behavioural effect**. The module's own docstring (`:36-37`) instructs exactly this framing: *"the capability is wired and opt-in," never "Tex is reflexively governed by default."* — and that is correct.

2. **Only one non-test binder, and it is a demo.** `capstone/flow.py:312` is the sole non-test `bound_reflexive_governor` call; capstone is a demo/test runner (`scripts/capstone_demo.py` + `tests/capstone/`), not a request-serving path. So the "self-governance is on" story exists *only* inside the capstone artifact and the test suite.

3. **The self-census is an un-mined cross-subsystem death certificate.** `CONTROLLER_MUTATION_CENSUS[...]` at `governor.py:272` formally excludes `nanozk / compliance / _pending` as *"dead code per CLAUDE.md — tested but not wired."* This is independently corroborated (`CLAUDE.md:32-33`, `docs/blueprint/_spine/reachability.md`). Any audit quoting this line to call compliance dead is citing accurate ground truth. The census is the single best machine-checked map of *which write surfaces actually steer Tex's decisions*.

4. **Self-honest to an unusual degree.** The module enumerates what it does NOT claim (`:20-44`), the sealed `claim` text bakes in "verdict correctness NOT proven; completeness NOT proven" (`:714-721`), and the residual gap (attestation/trust-tier via `registry.save`) is named in code (`:275-278`). This is the inverse of the overstated-subsystem pattern the audits were burned by.

5. **The discriminating power is metaguard, not the PDP (today).** In bound mode the PDP is uncalibrated for mutation descriptors (measured ~0.58 confidence on neutral descriptors); `minimum_confidence=0.0` is set so the gate doesn't ABSTAIN-deny everything. So the *real* deny logic is the deterministic `weakening_axes` / `widened_dimensions` / lifecycle signatures in metaguard. The PDP reuse buys the shared ABSTAIN surface + DECISION seal + future signals — not, yet, mutation-specific risk discrimination (`:38-44`).

6. **The recursion ("gate the gate") is genuinely terminated**, three ways: the two-level deploy-frozen stratum (level-0 is a redeploy, not gateable), the `_EVAL_DEPTH` ContextVar no-regress backstop (mid-evaluation mutation → deterministic FORBID, no recursion), and `governor_self_target` flooring on stored-policy impersonation. Proven by `tests/test_reflexive_gov.py` (26/26 green).

7. **One deliberate fail-open guard.** Re-binding while already bound *raises* (`:368-380`) rather than silently denying — because a swallowed re-bind would leave the caller falsely believing it is governed. This is the single exception to the "deny by not raising" contract and is documented as intentional.

8. **Threat-model boundary stated plainly:** an attacker who can run arbitrary Python in-process can monkeypatch the gate out (`:28-31`, `DEPLOY_FROZEN_STRATUM` entry at `:206-209`). The gate governs mutation *requests* flowing through governed surfaces, not the code segment itself. No overclaim.

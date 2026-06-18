# Trace: learning-flywheel-e2e

**Claim under test:** The Discover→Decide→Prove→Learn loop closes: outcomes/abstains
flow back into calibration through a vetting gate.

**Verdict: CONFIRMED** (one honest nuance recorded under "Gaps" — the reflexive
governance gate on *apply* is inert-by-default, but the human-approver
requirement that actually guards application is real and unconditional).

Branch: `feat/proof-carrying-gate`. All paths absolute under
`/Users/matthewnardizzi/dev/tex`. Verified by reading code + a build smoke test
(`build_api_router()` / `build_learning_router()` import clean and expose the
routes; the orchestrator + trigger import and wire).

---

## The two ingress paths into the loop (both LIVE on the running app)

### Path A — generic outcome reporting: `POST /outcomes` → ReportOutcomeCommand

1. `src/tex/main.py:1041-1046` — `ReportOutcomeCommand` is constructed **with**
   `orchestrator=learning_orchestrator`. This is the wire that makes the command
   route through the loop instead of doing a legacy direct write.
2. `src/tex/commands/report_outcome.py:80-96` — `execute()`: resolves the
   decision, validates request linkage, then **`self._orchestrator.ingest_outcome(outcome)`**
   (line 92) because `_orchestrator is not None`. The `else` branch (line 95,
   direct `outcome_store.save`) is dead when wired through `main`.

### Path B — the human-resolved-ABSTAIN flywheel: `POST /decisions/{id}/seal`

This is the flywheel's *fuel* path and the most load-bearing for the claim.

1. `src/tex/api/routes.py:246-252` — `seal_human_resolution` route, scope
   `decision:write`. Registered on the app via `build_api_router()` (returns the
   module `router`, `routes.py:576-578`), included at `src/tex/main.py:1446`.
2. `routes.py:295-301` — records the human act (`approve`/`hold`/`refuse`) as a
   hash-chained, PQ-signed evidence row via `recorder.record_human_resolution(...)`.
3. `routes.py:343-350` — **`response["outcome_capture"] = capture_resolution_outcome(...)`**
   passing `parent_record_hash=record.record_hash`. This is the line that stops
   the resolution being "dropped on the floor".
4. `src/tex/api/outcome_autoseal.py:263-341` `capture_resolution_outcome`:
   - flag `TEX_AUTOSEAL_OUTCOME` **defaults ON** (`autoseal_enabled()`, line 84-87:
     only `{0,false,no,off}` disable it). So capture is live by default.
   - pulls `orchestrator` + `recorder` off `request.app.state` (lines 290-291);
     both are set in `main` (`app.state.learning_orchestrator`, `main.py:1668`).
   - runs `_do_capture` under a bounded `ThreadPoolExecutor` (5s default) so it
     never blocks the worker; on timeout/error it degrades but the seal stands.
5. `outcome_autoseal.py:191-253` `_do_capture`:
   - `_build_outcome` (`156-188`) mints a labeled `OutcomeRecord` at the
     **REPORTED** default tier, `source=HUMAN_REVIEWER`,
     `verification=AUDIT_SIGN_OFF`. Trust is **not** pre-stamped — the validator
     earns it. ABSTAIN maps via `map_resolution_to_outcome` (`101-153`):
     approved→RELEASED/was_safe=True, refused→BLOCKED/was_safe=False,
     held→ESCALATED/was_safe=None; classify() → `ABSTAIN_REVIEW` for held holds,
     `FALSE_PERMIT`/`FALSE_FORBID` for reversed terminal verdicts.
   - **`ingest_result = orchestrator.ingest_outcome(outcome)`** (line 217) — same
     sanctioned ingest as Path A.
   - **seals the outcome as its own evidence row** parent-linked by
     `parent_evidence_hash=parent_record_hash` (`recorder.record_outcome(...)`,
     lines 225-238). This is the "→ seal" terminus of the chain.

---

## The vetting gate (`ingest_outcome`) — LIVE, real logic

`src/tex/learning/feedback_loop.py:211-282` `FeedbackLoopOrchestrator.ingest_outcome`:

1. **Validate** — `self._validator.validate(outcome)` (line 219).
   `src/tex/learning/outcome_validator.py:193-309` is substantive: 10 named
   failure checks (decision_missing, request_id_mismatch, tenant_mismatch,
   label_inconsistent, override_inconsistent, too_late [90d], reporter_blank,
   reporter_rate_limited [sliding window, `InProcessRateLimiter` line 137-160],
   duplicate_outcome, conflicting_with_prior). On any failure →
   `_quarantine` sets `trust_level=QUARANTINED` (line 356-373). On success →
   `_promote` to VALIDATED (or VERIFIED for audit/replay sources) (line 328-353).
   No stubs / NotImplementedError / TODO.
2. **Persist** — `self._outcomes.save(result.outcome)` (line 220). Quarantined
   rows ARE persisted (for audit) but the eligibility query excludes them — see
   below, this is the gate's teeth.
3. **Reputation** — when ground truth present, `self._reputation.record_observation(...)`
   (line 260). `src/tex/learning/reporter_reputation.py:170` is real:
   exponential time-decay (half-life 14d), bounded weight [0.05, 1.5], Postgres-
   capable (`import psycopg`, `SCHEMA_SQL`).
4. **Trigger hook** — `self._trigger.on_outcome(result.outcome)` (line 272),
   wrapped in try/except so a trigger fault never breaks ingest.

### The eligibility filter = the vetting gate's teeth

`src/tex/stores/outcome_store.py:334-368` `list_calibration_eligible` returns
**only** outcomes where `outcome.trust_level.is_calibration_eligible` (line 354).
`src/tex/domain/outcome_trust.py:63` `is_calibration_eligible` ⇒ VALIDATED +
VERIFIED only. Quarantined / REPORTED outcomes can never reach the calibrator.
This is what makes "through a vetting gate" true rather than decorative.

---

## The autonomous trigger — what makes the loop *close on its own*

`src/tex/learning/trigger.py` `AnytimeValidCalibrationTrigger`:

- Wired in `main.py:1035-1039`: constructed with the orchestrator + proposal
  store, then `learning_orchestrator.set_trigger(learning_trigger)` (line 1039)
  breaks the construction cycle.
- `on_outcome` (`151-279`): only calibration-eligible PERMIT outcomes with a
  ground-truth safety label carry the false-permit signal (`_carries_signal`,
  `326-336`). Standardises the false-permit indicator (`339-350`) and folds it
  into a **real** anytime-valid e-process
  (`src/tex/drift/_anytime_valid.py:196-269` `observe` — λ-grid mixture
  e-value, per-obs + cumulative clip, Ville's-inequality p-value; not a stub).
- On boundary crossing (`p_anytime_valid < alpha`, sample ≥ 5) it calls
  **`self._orchestrator.propose(...)`** (line 236) with a sealable crossing
  certificate in `trigger_metadata`. If `propose()` declines, it does NOT reset
  and does NOT supersede (lines 244-258) — the crossing stands.
- Lapse-on-supersession via `_supersede_existing` (`283-320`) marks older pending
  proposals EXPIRED only after the replacement exists.

---

## `propose()` — the full safety/vetting pipeline before a proposal exists

`src/tex/learning/feedback_loop.py:305-644`. Every gate is real and each refusal
returns `proposal=None` with advisories:

1. cold-start guard (`368-385`, default min 30 eligible).
2. **EvidenceSufficiency** gate (`392-414`) — `src/tex/learning/sufficiency.py:125`
   geometric mean of completeness/freshness/reliability/representativeness, with
   representativeness as a HARD sub-gate (≥0.15) — refuses to move a threshold
   having seen only one error mode. Wired in `main.py:1025` (`sufficiency_gate=EvidenceSufficiency()`).
3. **PoisoningDetector** (`355-358`, `418-430`) — `src/tex/learning/poisoning_detector.py:171`
   detects reporter clustering / sudden label shift / repeat disagreement (real
   `Counter`/`defaultdict` aggregation). Wired `main.py:1023`.
4. **Drift FREEZE** (`434-459`) — `DriftClassifier` FREEZE posture refuses to draft.
5. trust-weighted summary feeds **`calibrator.recommend`** (`474-477`) —
   `src/tex/learning/calibrator.py:134` real conservative threshold logic.
6. **CalibrationSafetyGuard.evaluate** (`479-510`) — `src/tex/learning/calibration_safety.py:141-341`
   hard floors/ceilings, per-cycle delta clips, cumulative 24h budget, per-policy
   min-interval rate limit, abstain-band preservation. Real; wired `main.py:1019`.
7. no-movement short-circuit (`512-528`).
8. **ReplayValidator** against recent decisions (`531-540`); risky-change event.
9. **OffPolicyEvaluator** (`561-592`) — anytime-valid upper bound on
   counterfactual unsafe-release rate; refuses if bound > budget. Wired `main.py:1026`.
10. only then `CalibrationProposal.build(...)` + `self._proposals.save(proposal)`
    (`612-624`) in **PENDING** state. The orchestrator **never auto-applies**.

---

## Apply / recalibrate / seal terminus

`apply_proposal` (`feedback_loop.py:648-697`) — reached from
`POST /v1/learning/proposals/{id}/approve` (`src/tex/api/learning_routes.py:492-534`,
scope `learning:approve`, `build_learning_router()` included at `main.py:1518-1519`):
- requires an explicit `approver` string resolved from the authenticated actor
  (`learning_routes.py:515-517`) — **human-in-the-loop is unconditional**.
- `approve` → `calibrator.apply_recommendation` (real, `calibrator.py:338`) →
  `policies.save` + `policies.activate(new_version)` (the **threshold
  recalibration** lands) → `safety.commit(...)` records the movement →
  `proposals.mark_applied`. The ENFORCEMENT seal fires inside the gate (below).

---

## Build smoke test (evidence the wiring is not import-broken)

`PYTHONPATH=…/src python -c "import …"` → `imports OK`;
`build_api_router()` exposes `/seal`; `build_learning_router()` exposes
`/proposals` POST and `/approve`. (See session log.)

---

## Gaps / honest nuances

1. **Reflexive governance gate on apply is inert-by-default.**
   `apply_proposal` (`feedback_loop.py:662`) calls
   `gate_controller_mutation(lambda: describe_proposal_apply(...))`. In
   `src/tex/selfgov/governor.py:464-487`, when no binding is installed it returns
   `_UNGATED` (`allowed=True, gated=False`) — a zero-cost passthrough. So the
   *reflexive/PDP* gate on application does not actively rule unless a binding is
   bound. The logic is real and **fail-closed when bound** (any error → FORBID +
   ENFORCEMENT seal), but the default deployment runs it ungated. This does NOT
   break the claim: application is still guarded by the **unconditional human
   `approver`** requirement at the route + method level. It only means the
   *additional* autonomous self-governance layer is opt-in, consistent with the
   project's "inert governance" caveat.
2. **`degraded` capture is silent-to-the-loop on timeout.** If the bounded
   autoseal capture (`outcome_autoseal.py:316-330`) times out, the seal succeeds
   but the labeled outcome may not be confirmed in-band (continues on a pool
   thread). The flywheel still receives the outcome on success; the degraded path
   is a latency-bound honesty signal, not a drop.

Neither gap interrupts the traced call path from
outcome/ABSTAIN → ingest (validate→persist→reputation) → eligibility-gated
calibration (sufficiency/poisoning/drift/safety/replay/OPE) → PENDING proposal →
human-approved recalibration → seal. The flywheel is **wired, not inert.**

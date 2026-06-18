# Subsystem Dossier: `learning` — the "Learn" layer (Layer 6)

> Scope: `/Users/matthewnardizzi/dev/tex/src/tex/learning/` (16 `.py` files, 6085 LOC).
> Branch: `feat/proof-carrying-gate`. All paths absolute. Code-verified; `.md`/docstring
> claims are labelled `(claim, unverified)` unless confirmed in code.

## Overview

The `learning` package is the **Learn** arm of Tex's Discover→Decide→Prove→Learn loop. It
turns observed real-world *outcomes* of past decisions into **conservative, human-gated,
versioned policy-threshold proposals** — and never auto-applies them. The package marker
declares this explicitly: `__layer__ = 6`, `__layer_kind__ = 'learning'`
(`src/tex/learning/__init__.py:9-10`).

The spine of the unit is a single orchestrator class,
`FeedbackLoopOrchestrator` (`src/tex/learning/feedback_loop.py:131`), which the docstring
calls "the single legitimate path from outcome to proposal." It chains, in order:
outcome **validation** → **persistence** → **reporter-reputation** update → (on an
evidence-driven trigger) a guarded **proposal pipeline** (sufficiency gate → poisoning
scan → drift classification → trust-weighted calibration → safety clipping → replay →
off-policy evaluation → health) → **PENDING** proposal → explicit human **apply / reject
/ rollback**.

Two design properties dominate the code and check out against the source:

1. **Never auto-applies.** `apply_proposal` requires an `approver` string supplied by a
   caller *outside* this module; there is no auto-approve anywhere in the package
   (`feedback_loop.py:648-697`; trigger only ever calls `propose`, never `apply` —
   `trigger.py:236`).
2. **Loosening is always human-gated.** Autonomous probabilistic signals can only ever
   move the policy *toward caution* (tighten); the e-detector has no `loosen` action
   (`drift.py:241-251`, `DriftAction` enum has only `NONE/TIGHTEN/REVIEW`).

The statistical machinery is real and stdlib-only: a **Waudby-Smith & Ramdas betting
confidence sequence** for off-policy evaluation (`ope.py`), an **anytime-valid e-process**
trigger and drift detector (`trigger.py`, `drift.py`), a **geometric-mean evidence-
sufficiency gate** (`sufficiency.py`), exponential-decay reporter reputation
(`reporter_reputation.py`), and a min-aggregate health score (`health.py`).

The unit is **LIVE**: built in `tex.main.build_runtime` and reachable from authenticated
`/v1/learning/*` API routes (call path proven below).

---

## File Inventory

| File | LOC | Role (one line) |
|---|---:|---|
| `__init__.py` | 11 | Layer marker only (`__layer__=6`, `__layer_kind__='learning'`). No re-exports. |
| `feedback_loop.py` | 821 | **Orchestrator.** `FeedbackLoopOrchestrator` — ingest → reputation → propose → apply/reject/rollback. The unit's spine. |
| `calibrator.py` | 498 | `ThresholdCalibrator` + `CalibrationRecommendation` — conservative, sample-weighted permit/forbid/min-confidence threshold deltas; `apply_recommendation` mints the new `PolicySnapshot`. |
| `calibration_safety.py` | 397 | `CalibrationSafetyGuard` — hard bounds, per-cycle delta clips, 24h cumulative-movement budget, rate-limit, abstain-band preservation; thread-safe. |
| `outcome_validator.py` | 471 | `OutcomeValidator` — REPORTED→VALIDATED/VERIFIED/QUARANTINED; 10 structural checks + in-process reporter rate limiter. |
| `outcomes.py` | 412 | Pure classification: `classify_outcome`/`classify_batch`, `OutcomeSummary`, and trust+reputation-weighted `summarize_outcomes_weighted`. |
| `replay.py` | 303 | `ReplayValidator` — re-derives historical verdicts under proposed thresholds; counts flips, safe-blocks, unsafe-releases. Stateless. |
| `ope.py` | 369 | `OffPolicyEvaluator` + `wsr_upper_bound` — anytime-valid WSR betting CS upper bound on counterfactual unsafe-release rate; Howard cross-check. |
| `sufficiency.py` | 317 | `EvidenceSufficiency` — 4-dimension (completeness/freshness/reliability/representativeness) geometric-mean readiness gate for delayed ground truth. |
| `drift.py` | 423 | `PolicyDriftMonitor` (verdict-distribution windows) + `RiskStreamEDetector` (anytime-valid e-detector → tighten-only). |
| `drift_classifier.py` | 201 | `DriftClassifier` — fuses drift + poisoning + calibration history into DATA/BEHAVIOR/POLICY/ADVERSARIAL/UNKNOWN + posture (NORMAL/ELEVATED/FREEZE). |
| `poisoning_detector.py` | 389 | `PoisoningDetector` — reporter clustering, sudden label shifts, repeated disagreement vs VERIFIED. Read-only. |
| `reporter_reputation.py` | 472 | `ReporterReputationStore` — exponential-decay per-reporter weight in `[floor,ceiling]`; in-memory default, optional Postgres write-through. |
| `health.py` | 294 | `compute_health` → `CalibrationHealth` (GREEN/YELLOW/RED); 7 subscores aggregated by **minimum**. |
| `observability.py` | 349 | Observer impls (`Logging`/`Metrics`/`Composite`) + `LearningAlertEngine` + `DEFAULT_ALERT_RULES`. |
| `trigger.py` | 358 | `AnytimeValidCalibrationTrigger` — per (tenant, policy) false-permit e-process; on crossing calls `propose` + lapse-on-supersession. |

---

## Internal Architecture

### Orchestrator (`feedback_loop.py`)

`FeedbackLoopOrchestrator.__init__` (`feedback_loop.py:156-198`) wires nine required
collaborators (decision/outcome/policy/proposal stores, validator, reputation,
calibrator, safety, replay, drift monitor) plus optional ones that default to `None`/inert
so "an orchestrator built the legacy way behaves identically" (`:193-198`):
`drift_classifier`, `poisoning_detector`, `observer` (→ `_NullObserver`),
`sufficiency_gate`, `ope_evaluator`, and a post-construction `_trigger`
(`set_trigger`, `:200-207` — bound after construction to break the trigger↔orchestrator
cycle).

**`ingest_outcome`** (`:211-282`): `validator.validate(outcome)` → `outcomes.save(...)` →
emit `outcome_persisted` (and `outcome_quarantined` / `reporter_rate_limited` events) →
conditionally `reputation.record_observation(...)` when the outcome is valid, has a
reporter, and `was_safe is not None` → finally, **defensively**, `trigger.on_outcome(...)`
wrapped in a bare `try/except` that swallows any exception so "a trigger fault never breaks
ingest" (`:270-274`). `_derive_agreement` (`:284-301`) computes consensus agreement against
prior VERIFIED outcomes, defaulting to "agreed" with no VERIFIED prior so first reporters
aren't penalized.

**`propose`** (`:305-644`) — the guarded pipeline, in code order:

1. Validate `tenant_id`/`created_by` non-blank (`:325-328`); resolve source policy
   (active or named, `:751-754`).
2. Pull `list_calibration_eligible(tenant, since)` + `quarantine_count` (`:334-341`).
3. Always compute `drift_monitor.report(...)` (even on cold start) (`:344`).
4. Poisoning scan over recent vs a ≥30-day baseline window (`:350-358`).
5. `drift_classifier.classify(...)` (`:360-365`).
6. **Cold-start guard**: if `eligible_count < cold_start_minimum` (default 30,
   `:82`) return `proposal=None` with a "cold start" advisory (`:368-385`).
7. **Sufficiency gate** (optional): `sufficiency.assess(eligible)`; if `not ready`,
   emit `calibration_insufficient_evidence` and return `None` (`:392-414`).
8. Emit `poisoning_detected` if findings (`:418-430`).
9. **Adversarial freeze**: if `drift_classification.posture is FREEZE`, refuse + emit
   `proposal_freeze` (`:434-459`).
10. Build trust-weighted summary: `classify_batch` → `summarize_outcomes_weighted(...,
    reporter_weight=reputation.weight_for)` (`:462-472`).
11. `calibrator.recommend(policy, weighted.as_outcome_summary())` (`:474-477`).
12. `safety.evaluate(policy, recommendation)`; if `not allowed` → refuse + emit
    `calibration_safety_blocked` (`:479-510`); if the clipped recommendation is unchanged
    → "no movement" advisory, return `None` (`:512-528`).
13. **Replay** over recent same-version decisions; emit `proposal_replay_risky` if
    `replay_report.risky_change` (`:530-553`).
14. **OPE gate** (optional): `ope.evaluate(...)`; gate on the **bound, not the point
    estimate** — `if not ope_report.within_budget(self._ope_budget)` (default 0.05,
    `:176`) refuse + emit `calibration_ope_blocked` (`:560-592`).
15. Compute `health` (`:594-598`), assemble metadata (drift, classification, poisoning,
    weighted/raw totals, OPE, trigger cert) (`:600-610`), build `CalibrationProposal`,
    `proposals.save(...)`, emit `proposal_created` (`:612-635`).

**`apply_proposal`** (`:648-697`): all-or-nothing by construction. First a **reflexive
governance gate** —
`gate_controller_mutation(lambda: describe_proposal_apply(...))` — and if `not allowed`,
return the proposal *unchanged* before any approve/save/activate runs (`:662-663`). On
allow: `proposals.approve` → `calibrator.apply_recommendation(activate=True)` →
`policies.save` + `policies.activate` → `safety.commit(...)` (records cumulative movement)
→ `proposals.mark_applied` → emit `proposal_applied`.

**`reject_proposal`** (`:699-719`) and **`rollback_proposal`** (`:721-747`): rollback
requires an APPLIED proposal carrying a `rollback_target_version` (else `RuntimeError`,
`:728-731`), passes the same governance gate, then `policies.activate(rollback_target)` +
`mark_rolled_back`.

Three module-level dict serializers (`_drift_report_dict`, `_drift_classification_dict`,
`_poisoning_summary_dict`, `:787-814`) flatten reports into proposal metadata.

### Calibrator (`calibrator.py`)

`ThresholdCalibrator` (`:49`) is a **rule-based, conservative** recommender, not an ML
model. `recommend` (`:134-336`) computes false-permit / false-forbid / abstain-review /
unknown rates, then:

- **False permits first** (the primary risk): tightens permit & forbid thresholds and
  raises min-confidence (`:196-222`).
- **False forbids second**, *only* when they dominate false permits by >0.03
  (`false_forbids_dominate`, `:229`): eases thresholds (`:225-252`).
- High abstain-review and high unknown volume nudge **min-confidence up** rather than
  forcing stronger permits (`:256-294`).
- Movement is bounded by a **sqrt severity curve × sample weight × ceiling**
  (`_bounded_delta`, `:422-439`); `sample_weight` ramps 0→1 between `minimum_sample_size`
  (12) and `full_trust_sample_size` (50) (`_sample_weight`, `:407-420`).
- `_normalize_thresholds` clamps into sane ranges and **preserves a minimum abstain band**
  (`:454-484`).

Below `minimum_sample_size`, it returns an all-`current` no-change recommendation with a
"sample too small" reason and `sample_weight=0` (`:157-182`). `changed` is a structural
property comparing current vs recommended (`:40-46`).

`apply_recommendation` (`:338-405`) is the only mutator: `policy.model_copy(update=...)`
mints a new immutable `PolicySnapshot` with the recommended thresholds and a rich
`calibration` metadata block (sample stats, deltas, reasons, lineage
`calibration_parent_version`). `build_default_calibrator()` (`:497`) returns the default.

### Calibration safety (`calibration_safety.py`)

`CalibrationSafetyGuard` (`:87`) is a **second, stricter** safety layer independent of the
calibrator's own clamps. Module constants set **hard floors/ceilings**
(`HARD_PERMIT_FLOOR=0.10 … HARD_MIN_ABSTAIN_BAND=0.10`, `:44-50`), per-cycle deltas
(`:53-55`), a **0.10 / 24h cumulative budget** (`:60-61`), and a **1h min interval**
(`:64`). `evaluate` (`:141-341`), under an `RLock`:

1. Prunes the per-policy event window; **rate-limits** if within `min_interval` (`:172-181`).
2. **Clips** each delta to its cap, flagging `bounds_violated` (`:183-227`).
3. **Cumulative budget**: sum of abs deltas over the window + this delta; if any axis
   exceeds budget → `budget_exhausted` (`:229-249`).
4. **Hard-clamps** the resulting thresholds into the absolute safe zone and re-asserts the
   abstain band (`:251-307`).
5. `allowed = not (rate_limited or budget_exhausted)` — note bounds-violation alone does
   **not** block; it clips (`:309`). Returns a `SafetyDecision` carrying the rebuilt
   `clipped_recommendation` whose movement "can only reduce … never enlarge" (`:148-152`).

`commit` (`:343-366`) appends the applied movement to the policy's history and sets
`last_calibrated_at`, so future evaluations see real cumulative drift. Called by the
orchestrator only after a successful apply (`feedback_loop.py:681`).

### Outcome validator (`outcome_validator.py`)

`OutcomeValidator.validate` (`:193-309`) is **deterministic and pure**; it returns a
`ValidationResult` rather than raising, so the caller persists the quarantined record.
Checks (each a `ValidationFailure`, `:76-86`): decision-missing (hard return), request-id
mismatch, tenant mismatch, structural label coherence (re-derived via
`OutcomeRecord.classify`, `:425-443`), override consistency, report lag (>90d default),
reporter-blank, **reporter rate-limit** (`InProcessRateLimiter`, sliding window, `:137-160`),
duplicate (same reporter+label+safety), and **conflict-with-prior** (a less-trusted source
disagreeing with a higher-trust prior, by `_trust_rank`, `:279-298`,`:379-388`). On any
failure → `_quarantine` (trust=QUARANTINED). On success → `_promote`: source-type baseline
decides VALIDATED vs straight-to-VERIFIED (`:328-353`). Backfills tenant/policy_version from
the linked decision (`:311-326`).

### Outcomes classification (`outcomes.py`)

Pure functions. `classify_outcome` (`:91-184`) is an explicit literal verdict×label map
(no hidden rules, by design `:108`). `summarize_outcomes` (`:187-225`) aggregates counts;
`OutcomeSummary` exposes `error_rate`/`reviewed_error_rate` (`:72-88`).
`summarize_outcomes_weighted` (`:334-401`) is the **trust-weighted** path the calibrator
consumes: each non-quarantined outcome contributes
`trust_tier_weight × reporter_reputation × (0.5 + 0.5·confidence)` (`:368-374`);
`WeightedOutcomeSummary.as_outcome_summary` (`:314-331`) rounds to integer counts
(banker's rounding) so the existing integer-API calibrator can consume the weighted view,
intentionally collapsing sub-vote labels to zero.

### Replay (`replay.py`)

`ReplayValidator.replay` (`:113-275`) is stateless. For each historical decision it
re-derives the verdict under the proposed thresholds via `_rederive_verdict` (`:278-300`,
mirrors the PDP: `score>=forbid→FORBID`; `score<=permit AND conf>=min_conf→PERMIT`; else
ABSTAIN), counts flips (new permits/abstains/forbids/resolved-abstains), and scores
label-based safety impact: `would_have_blocked_safe` (PERMIT→FORBID on a safe outcome) and
`would_have_released_unsafe` (FORBID→PERMIT on an unsafe outcome) (`:210-235`). Only
VALIDATED/VERIFIED outcomes count for labels (`:123-129`). **Hard-block detection**:
decisions with `final_score>=0.999 AND confidence>=0.999` are counted as
`hard_blocked_unchanged` (deterministic-gate saturation is threshold-immune, `:177`).
`risky_change` = flips/total > `risky_flip_threshold` (default 0.10, `:248-250`).

### Off-policy evaluation (`ope.py`)

`OffPolicyEvaluator.evaluate` (`:177-250`) builds the **decision-ordered Bernoulli stream**
"this counterfactual permit was unsafe" over the labelled decisions the *proposed* policy
would PERMIT, then computes:

- `wsr_upper_bound(stream, alpha)` (`:253-343`) — the **headline** anytime-valid one-sided
  WSR **betting confidence sequence** with predictable, variance-adaptive plug-in bets
  (`:307-324`), inverted for the crossing `U = inf{m : K_t^-(m) >= 1/alpha}` by 60-step
  binary search on the monotone log-capital (`:326-343`). Empty stream → vacuous 0.0.
- `_anytime_valid_upper_bound(successes, n, alpha)` (`:346-369`) — the older **Howard**
  time-uniform Hoeffding boundary, order-free, kept as an auditable cross-check.

`OPEReport.within_budget` (`:150-152`) is the gate predicate: `upper_bound <= budget`. No
importance weighting is needed because the proposed re-threshold is deterministic given a
logged decision's `(score, confidence)` (`:9-14`).

### Sufficiency (`sufficiency.py`)

`EvidenceSufficiency.assess` (`:125-175`) scores four dimensions in `[0,1]` —
completeness (`n/target`), freshness (fraction within horizon, `:179-194`), reliability
(label-trust × reporter diversity, `:196-230`), representativeness (`4·p·(1−p)` on the
unsafe fraction, `0.1` for one-sided windows, `:232-263`) — and combines via
`_geometric_mean` (`:303-317`) whose zero-collapse means any dead dimension fails
readiness. `ready` requires `n >= hard_floor(8)` **and** `representativeness >= 0.15`
**and** `overall >= readiness_threshold(0.55)` (`:153-157`). `reason` names the weakest
dimension in plain language ("I've only seen one side of this…", `:265-300`).

### Drift (`drift.py`)

Two mechanisms. `PolicyDriftMonitor.report` (`:113-174`) windows the last `2·window`
decisions for a policy version into previous/current slices and computes per-rate deltas +
human flags (`abstain_rate_climbing`, etc., `:197-228`). Read-only; never mutates the
store. `RiskStreamEDetector` (`:302-423`) wraps one `AnytimeValidEProcess`
(`tex.drift._anytime_valid`) per stream (`FALSE_PERMIT`, `ABSTAIN_RATE`), standardizes each
Bernoulli event against a baseline rate (`_standardise_indicator`, `:288-299`), and on a
crossing recommends **TIGHTEN** for false-permits (autonomous-safe) or **REVIEW** for
abstain (human-gated) — `_action_for` (`:358-368`); there is no autonomous loosen.

### Drift classifier (`drift_classifier.py`)

`DriftClassifier.classify` (`:72-193`) fuses the drift report, poisoning report, and
calibration recency into a `ClassifiedDrift`: insufficient data → UNKNOWN/NORMAL; medium/
high poisoning → **ADVERSARIAL** with **FREEZE** (high) or ELEVATED_REVIEW (medium); recent
calibration → expected **POLICY**; abstain-dominant movement → **BEHAVIOR**; permit+forbid
move while abstain holds → **DATA**; else UNKNOWN. The FREEZE posture is what the
orchestrator refuses on (`feedback_loop.py:434`).

### Poisoning detector (`poisoning_detector.py`)

`PoisoningDetector.detect` (`:171-201`) runs three independent, conservative detectors:
reporter **clustering** (≥N distinct reporters submitting the same label in a 6h window,
`:205-253`), **sudden label shift** (per-tenant false-permit/forbid rate jump ≥0.20 vs a
baseline window, ≥20 samples each, `:257-309`), and **repeated disagreement** vs VERIFIED
outcomes (`:313-373`). Read-only; produces `PoisoningReport` with `has_findings`/
`max_severity` (`:97-111`). Action is the orchestrator's responsibility (`:20-23`).

### Reporter reputation (`reporter_reputation.py`)

`ReporterReputationStore` (`:100`) tracks per-reporter agreement/disagreement with
**exponential time decay** (`half_life=14d`, applied lazily at read/write,
`_apply_decay`, `:249-263`) and maps the Laplace-smoothed decayed-agreement ratio onto a
bounded weight in `[floor=0.05, ceiling=1.5]` via a sqrt-smoothed ramp around the neutral
1.0 (`_compute_weight`, `:306-341`). New reporters (< 5 obs) stay neutral. `weight_for`
(`:228-235`) is the callable the weighted summarizer uses; unknown → neutral 1.0.
**Persistence**: pure in-memory unless `DATABASE_URL` is set, in which case it ensures a
schema and write-through-persists to Postgres (`SCHEMA_SQL` `:50-61`; `_ensure_schema`,
`_hydrate_from_postgres`, `_persist_state` `:345-449`); bootstrap failure degrades to
in-memory (`:159-168`).

### Health (`health.py`)

`compute_health` (`:106-261`) produces seven subscores (false_permit, false_forbid,
abstain, sample_size, reporter_diversity via normalized entropy `:264-286`, quarantine_rate,
drift_volatility) using ramp/band helpers (`:76-103`), then aggregates by **minimum** (any
RED subscore drags overall RED, `:249-251`) — deliberately not averaging so "your sample
size is too small" surfaces even when all else is fine (`:18-23`). Bands: RED<0.55,
GREEN≥0.80 (`:64-73`).

### Observability (`observability.py`)

`LoggingLearningObserver` (`:57`) logs every event, WARN-level for a frozenset of
operator-critical ones (`:62-71`). `MetricsLearningObserver` (`:80`) keeps thread-safe
lifetime + per-tenant counters and a recent-events ring, exposing `snapshot()`,
`count_in_window()`, and `prometheus_text()`. `CompositeLearningObserver` (`:166`) fans out
and swallows per-observer faults. `LearningAlertEngine` (`:280`) is **stateless**, re-deriving
alerts each `evaluate()` from `DEFAULT_ALERT_RULES` (6 threshold rules over the metrics
window, `:210-277`).

### Trigger (`trigger.py`)

`AnytimeValidCalibrationTrigger` (`:100`) is what lets the learning voice speak unprompted.
`on_outcome` (`:151-279`, wrapped in a fault-swallowing outer method `:151-169`) feeds only
calibration-eligible PERMIT outcomes carrying a safety label (`_carries_signal`, `:326-336`)
into a **per (tenant, source-policy) anytime-valid e-process** on the standardized
false-permit indicator (`_standardise_false_permit`, `:339-350`). On a crossing
(`p_anytime_valid < alpha` past a 5-obs floor) it **drafts first** by calling
`orchestrator.propose(..., trigger_metadata={crossing certificate})` (`:236-242`); only if a
proposal actually results does it then **supersede** prior pending proposals for the same
target (`_supersede_existing` → `mark_expired`, `:283-320`) and `reset` the e-process for a
fresh baseline (`:268-270`). If `propose` declines (sufficiency/safety/freeze/no-movement)
the crossing stands and nothing is superseded (`:244-258`). The supersession is feature-
detected via `getattr` so it degrades gracefully if the store lacks `list_pending`/
`mark_expired` (`:295-298`).

---

## Public API

Imported by code outside the package (verified by grep, see Wiring In):

- `feedback_loop`: `FeedbackLoopOrchestrator`, `IngestResult`, `ProposalDraftResult`.
- `calibrator`: `ThresholdCalibrator`, `build_default_calibrator`, `CalibrationRecommendation`.
- `calibration_safety`: `CalibrationSafetyGuard` (+ HARD_* / DEFAULT_* constants, `SafetyDecision`).
- `outcome_validator`: `OutcomeValidator`, `ValidationResult`, `ValidationFailure`, `InProcessRateLimiter`.
- `outcomes`: `classify_outcome`, `classify_batch`, `summarize_outcomes`, `summarize_outcomes_weighted`, `OutcomeClassification`, `OutcomeSummary`, `WeightedOutcomeSummary`.
- `replay`: `ReplayValidator`, `ReplayReport`, `ReplayCount`.
- `ope`: `OffPolicyEvaluator`, `OPEReport`, `wsr_upper_bound`, DEFAULT_OPE_ALPHA, etc.
- `sufficiency`: `EvidenceSufficiency`, `SufficiencyReport`.
- `drift`: `PolicyDriftMonitor`, `PolicyDriftReport`, `RiskStreamEDetector`, `RiskStream`, `DriftAction`, `EDriftSignal`.
- `drift_classifier`: `DriftClassifier`, `ClassifiedDrift`, `DriftPosture`, `DriftType`.
- `poisoning_detector`: `PoisoningDetector`, `PoisoningReport` (+ finding dataclasses).
- `reporter_reputation`: `ReporterReputationStore`, `ReporterReputation`.
- `health`: `compute_health`, `CalibrationHealth`, `HealthBand`, `HealthSubscore`.
- `observability`: `MetricsLearningObserver`, `LearningAlertEngine`, `LoggingLearningObserver`, `CompositeLearningObserver`, `Alert`, `AlertRule`, `DEFAULT_ALERT_RULES`.
- `trigger`: `AnytimeValidCalibrationTrigger`, `TriggerOutcome`.

> Note: `__init__.py` exports **nothing** but the layer marker — consumers import from
> submodules directly (`src/tex/learning/__init__.py:1-11`).

---

## Wiring

### Wiring In (who imports the unit) — code-verified

`grep -rn "from tex.learning" src/tex` (excluding the package itself):

- `src/tex/main.py:91-108` — imports the whole stack into `build_runtime`.
- `src/tex/api/learning_routes.py:51-52,630-631` — orchestrator + outcomes + health/drift.
- `src/tex/api/routes.py:29` — `PolicyDriftMonitor`, `PolicyDriftReport`.
- `src/tex/api/schemas.py:28-29` — `CalibrationRecommendation`, `OutcomeClassification`, `OutcomeSummary`.
- `src/tex/commands/calibrate_policy.py:6-7` and `src/tex/commands/report_outcome.py:9` — command-layer use.
- `src/tex/domain/calibration_proposal.py:39-41` — `CalibrationProposal.build` consumes `CalibrationRecommendation`, `CalibrationHealth`, `ReplayReport`.
- `src/tex/adversarial/completeness.py:132` — imports `wsr_upper_bound` (the OPE bound is reused by the adversarial/completeness subsystem).

### Live call path (proven, file:line)

**Construction.** `src/tex/main.py:2016` `app = create_app()` → `create_app`
(`:1309`) → `build_runtime` (`:519`). Inside `build_runtime` the entire learning stack is
constructed (`:987-1041`): stores, `OutcomeValidator(:989)`, `CalibrationSafetyGuard(:993)`,
`ReplayValidator(:994)`, `DriftClassifier(:995)`, `PoisoningDetector(:996)`,
`PolicyDriftMonitor(:997)`, `MetricsLearningObserver(:1000)` + `CompositeLearningObserver`
+ `LearningAlertEngine(:1004)`, then `FeedbackLoopOrchestrator(:1006)` with
`sufficiency_gate=EvidenceSufficiency()` and `ope_evaluator=OffPolicyEvaluator()`
(`:1020-1021`), then `AnytimeValidCalibrationTrigger(:1030)` bound back via
`learning_orchestrator.set_trigger(:1034)`. The orchestrator is also handed to
`ReportOutcomeCommand(orchestrator=…)` (`:1040`).

**Publication.** `build_runtime` returns a `TexRuntime` carrying
`learning_orchestrator/reporter_reputation/learning_metrics/learning_alert_engine`
(`:1208-1217`); `_attach_runtime_to_app` publishes them onto `app.state`
(`:1663-1672`: `app.state.learning_orchestrator = runtime.learning_orchestrator`, etc.).
The learning router is mounted: `from tex.api.learning_routes import build_learning_router;
app.include_router(build_learning_router())` (`:1513-1514`).

**Request paths.**
- **Ingest:** `POST /v1/.../outcomes` → `routes.py:396 report_outcome` →
  `_get_report_outcome_command` (`:591`) → `ReportOutcomeCommand.execute`, which calls
  `self._orchestrator.ingest_outcome(outcome)` (`commands/report_outcome.py:91-92`) →
  validator + reputation + (defensive) trigger.on_outcome → propose.
- **Proposals:** `learning_routes.py` resolves the orchestrator from
  `request.app.state.learning_orchestrator` (`:173-178`) and exposes
  `POST /proposals` → `orch.propose` (`:388-389`),
  `POST /proposals/{id}/approve` → `orch.apply_proposal` (`:518-520`),
  `/reject` → `orch.reject_proposal` (`:560-562`),
  `/rollback` → `orch.rollback_proposal` (`:603-605`),
  guarded by `RequireScope("learning:write"|"learning:approve")` (`:375,495,539,582`).
- **Read surfaces:** `/metrics`, `/metrics/prometheus` read
  `app.state.learning_metrics` (`:724,737`); `/alerts` reads
  `app.state.learning_alert_engine` (`:757`); `/reputation*` reads the reputation store.

**Conclusion: `wired_status = LIVE`.** The orchestrator and its read surfaces are
reachable from authenticated API routes via `app.state`, populated unconditionally in
`build_runtime`. The **autonomous** proposal path is also live (trigger bound at `:1034`
and invoked on every ingest), independent of the manual `POST /proposals`.

### Wiring Out (dependencies)

**Internal tex subsystems:**
- `tex.domain.*` — `CalibrationProposal`, `Decision`, `OutcomeRecord`, `OutcomeTrustLevel`/
  `OutcomeSourceType`/`VerificationMethod`, `PolicySnapshot`, `Verdict`, `OutcomeLabel`/`OutcomeKind`.
- `tex.stores.*` — `CalibrationProposalStore`, `InMemoryDecisionStore`, `InMemoryOutcomeStore`,
  `InMemoryPolicyStore` (orchestrator); the proposal/reputation stores carry their own
  Postgres write-through.
- `tex.drift._anytime_valid.AnytimeValidEProcess` — the e-process used by both `trigger.py`
  and `drift.py`'s `RiskStreamEDetector` (verified present, real impl:
  `src/tex/drift/_anytime_valid.py:168` with `observe`/`is_significant_at`/`reset`).
- `tex.selfgov.governor` — `gate_controller_mutation`, `describe_proposal_apply`,
  `describe_proposal_rollback` (the reflexive gate in apply/rollback). **Inert at runtime**
  — see Notable Findings.

**External libraries:** `psycopg` (Postgres, optional at runtime but a **hard top-level
import** in `reporter_reputation.py:36`), Pydantic (`drift.py` models, domain), and Python
stdlib only for the maths (`math`, `dataclasses`, `datetime`, `threading`,
`collections`). The OPE/sufficiency/trigger/drift maths add **no new third-party deps**
(`ope.py:69`, `sufficiency.py:33`, `trigger.py:42`).

---

## Implementation Reality

**REAL logic (no stubs).** Every file in scope is substantive, working logic. There is no
`NotImplementedError`, no TODO/FIXME, and no pass-only placeholder in the package:

```
$ grep -rn "NotImplementedError\|TODO\|FIXME\|raise NotImplemented" src/tex/learning  →  (no matches)
```

Spot-verified by execution (`PYTHONPATH=…/src`):
- Package imports cleanly; `ReporterReputationStore()` reports `is_durable=False` with no
  `DATABASE_URL` and `weight_for('nobody')==1.0`.
- `wsr_upper_bound([])==0.0` (vacuous empty-stream case).
- `OffPolicyEvaluator` / Howard cross-check compute real bounds.

**The statistics are genuine, not decorative:**
- **WSR betting confidence sequence** (`ope.py:253-343`) — full predictable-plug-in bet
  schedule (`:307-324`) and monotone-capital inversion (`:326-343`), matching the cited
  Waudby-Smith & Ramdas construction. The `wsr <= howard` ordering claim is **asserted in
  tests** for representative streams (`tests/test_ope_wsr.py:93-101`). See Notable Finding 1
  for the precise scope of that claim.
- **Anytime-valid e-process** trigger and drift detector — real mixture e-process backing
  (`tex.drift._anytime_valid`), Ville-bounded p-values.
- **Geometric-mean sufficiency gate**, **exponential-decay reputation**, **min-aggregate
  health**, **sliding-window rate limiters** — all implemented as described.

**Graceful fallbacks (real impl + degraded path), not hollow stubs:**
- `ReporterReputationStore` and `CalibrationProposalStore` run **pure in-memory** when
  `DATABASE_URL` is unset, and write-through to Postgres when set; Postgres bootstrap
  failure degrades to in-memory with an error log (`reporter_reputation.py:159-168`). At
  runtime in this repo (no `DATABASE_URL`), **state is in-memory and non-durable**.
- The trigger and the metrics/composite observers swallow their own faults so they can
  never break the ingest hot path (`trigger.py:158-169`, `feedback_loop.py:270-274`,
  `observability.py:176-179`).

**Optional-collaborator inertness (by design):** `sufficiency_gate`, `ope_evaluator`,
`drift_classifier`, `poisoning_detector`, and `_trigger` all default to `None`/inert in the
orchestrator constructor (`feedback_loop.py:169-198`), but **all of them are wired live** in
`build_runtime` (`main.py:1017-1034`), so the production loop runs the full frontier
pipeline, not the legacy subset.

---

## Technology / SOTA

- **Off-policy evaluation via betting confidence sequences (WSR).** One-sided,
  variance-adaptive, anytime-valid upper bound on the counterfactual unsafe-release rate;
  no importance weighting (deterministic re-threshold). Gates on the *bound*, not the point
  estimate (`ope.py:9-67,150-152`). Howard time-uniform Hoeffding kept as a conservative
  cross-check. Cited sources: Waudby-Smith & Ramdas (arXiv 2010.09686), Karampatziakis et
  al. 2021, Howard et al. 2021.
- **Anytime-valid e-process / e-detector** (Ville's inequality) for the **calibration
  trigger** and **drift detection** — the loop fires on *evidence* (boundary crossing with
  horizon-wide bounded false-alarm), not on a clock or count (`trigger.py:14-26`,
  `drift.py:231-251`). The crossing certificate is sealed into proposal metadata.
- **Evidence-sufficiency under delayed ground truth** — a 4-dimension geometric-mean
  readiness gate with a representativeness hard sub-gate (`sufficiency.py`), citing an
  "Evidence Sufficiency Under Delayed Ground Truth" reference (claim, unverified — the cite
  is in the docstring; the *math* is verified in code).
- **Conservative rule-based calibration** (false-permit-first priority, sqrt-bounded
  deltas, abstain-band preservation) plus a **defense-in-depth safety guard** (hard bounds +
  per-cycle clip + cumulative budget + rate limit).
- **Trust-weighted aggregation** combining outcome trust tier × **time-decayed reporter
  reputation** (Laplace-smoothed, sqrt-ramped) × confidence.
- **Adversarial / poisoning surface**: reporter clustering, sudden label-shift, repeated-
  disagreement, feeding a drift classifier that can FREEZE the loop.
- **Lapse-on-supersession** lifecycle for proposals (newer crossing expires an older
  un-acted proposal — never an attention timer) (`trigger.py:28-37,283-320`).
- Patterns: dependency injection with optional inert collaborators; protocol-typed narrow
  store interfaces (`outcome_validator.py:109-135`); observer/composite + stateless alert
  engine; frozen slotted dataclasses + immutable `PolicySnapshot.model_copy` mutation.

---

## Persistence

- **In-memory by default.** The orchestrator's decision/outcome/policy stores are the
  in-memory variants in `build_runtime`. The **reputation** and **proposal** stores are
  in-memory unless `DATABASE_URL` is set (`reporter_reputation.py:147-157`,
  `calibration_proposal_store.py:143-152`). In this repo at runtime (no `DATABASE_URL`),
  **all learning state is process-local and lost on restart** — `is_durable=False`
  (verified by execution).
- **Postgres write-through (optional).** Reputation persists to `tex_reporter_reputation`
  (`SCHEMA_SQL`, `reporter_reputation.py:50-61`) with upsert-on-observation; proposals
  write-through on every mutation. Hydration on construction.
- **Safety-guard movement history** is in-memory per-policy under an `RLock`
  (`calibration_safety.py:131-132`); **not** persisted — cumulative-budget enforcement
  resets on restart.
- **Metrics / alerts** are in-memory ring buffers + counters (`observability.py:92-101`);
  alerts are derived, never stored. E-process state (trigger, drift) is in-memory per
  target and reset on a confirmed regime change.

---

## Notable Findings

1. **OPE docstring overstates the `wsr <= howard` ordering as "always."** `ope.py:50-52`
   and `:128-131` say the Howard bound is "by construction never tighter than WSR … so
   `wsr <= howard` always holds and is asserted in the tests." Verified nuance: WSR is
   **order-dependent** (it consumes the actual decision-ordered stream), so the inequality
   holds for representative/interleaved streams (which the live gate feeds) — the tests
   scope it exactly that way (`tests/test_ope_wsr.py:76-82,93-101` use randomized streams).
   An adversarially front-loaded tiny stream can give `wsr > howard` (I reproduced
   `wsr=0.9332 > howard=0.658` on a hand-crafted 10-event stream). Not a bug — the gate
   never sees such streams — but the word "always" is an overstatement relative to the
   `wsr_upper_bound` function's behavior on arbitrary input.

2. **The "reflexive governance gate" on apply/rollback is inert at runtime.**
   `apply_proposal`/`rollback_proposal` call
   `gate_controller_mutation(lambda: describe_proposal_apply(...))` (`feedback_loop.py:662,732`),
   but `gate_controller_mutation` returns `_UNGATED (allowed=True)` whenever `_BINDING is
   None` (`selfgov/governor.py:484-486`), and **nothing in `build_runtime`/`create_app`
   binds the governor** (`grep` finds the binder used only in
   `specialists/metaguard.py`, not in `main.py`/`runtime`). So in production the gate is a
   structural pass-through; it only denies once a governance binding is installed (tests).
   This matches the auditor's "inert governance" note. The *human-approval* requirement
   (an `approver` string) is the real gate and is genuinely enforced; the reflexive seal is
   a hook awaiting a binding.

3. **`reporter_reputation.py` imports `psycopg` at module top (`:36`), unconditionally.**
   Unlike the runtime-optional DSN logic, the import itself is hard, so the *entire*
   learning import chain (and thus `build_runtime`) requires `psycopg` to be installed even
   in pure in-memory mode. (Confirmed installed here — import succeeds.) Same for
   `calibration_proposal_store.py:44`. This is a latent deploy dependency, not a stub.

4. **`__init__.py` re-exports nothing.** Despite the docstring describing the layer
   (`:1-5`), the package surfaces only `__layer__`/`__layer_kind__`. All public symbols are
   imported from submodules. Not a bug; worth noting for anyone expecting `from
   tex.learning import FeedbackLoopOrchestrator`.

5. **Dead-ish helper:** `outcome_validator._verdict_outcome_compat` (`:446-460`) is
   documented "used by tests; not enforced by validator directly" and indeed is not called
   anywhere in the validator's own logic — a test-only soft check living in production code.

6. **`drift.py` `RiskStreamEDetector` is real but appears unused by the live orchestrator.**
   The orchestrator's *autonomous* firing uses `trigger.AnytimeValidCalibrationTrigger`
   (also an e-process), not `RiskStreamEDetector`. `RiskStreamEDetector`/`RiskStream`/
   `DriftAction` are defined and exported but I found no `build_runtime` call site wiring
   the detector into the loop — it is library surface available to callers, not part of the
   wired proposal path. (The wired drift surface is `PolicyDriftMonitor`, used at
   `feedback_loop.py:344` and `routes.py:29`.) Flag: potential partially-orphaned capability
   within an otherwise-live unit.

7. **Strong, code-true safety properties** (no overstatement found): never auto-applies
   (no apply path without an external `approver`); loosening is never autonomous (e-detector
   has no `loosen`, `drift.py:241-251`); the OPE gate refuses on the *bound* even when
   replay looks benign (`feedback_loop.py:556-592`); the safety guard's clipped
   recommendation can only reduce movement (`calibration_safety.py:148-152`). These claims
   from the docstrings are confirmed in the code.

8. **Surprise (positive):** the trigger's "draft-first-then-supersede" ordering
   (`trigger.py:215-270`) genuinely avoids the race where expiring an old proposal before
   the replacement drafts would lapse a good proposal for nothing — and it declines to
   supersede/reset when `propose` refuses downstream. Careful lifecycle engineering, matches
   its docstring.

# Tex backend — autonomous learning build (tex_10)

What changed, why, what's proven here, and what you should verify on your own
machine. Read the last section before you trust the green checks.

## The problem this build fixes

The Layer-6 learning machinery was complete and ran, but it was **dormant**:
`FeedbackLoopOrchestrator.propose()` had exactly one caller — the manual
`POST /v1/learning/proposals`. Nothing fired it autonomously, so in production
the proposal store stayed empty and the learning voice never spoke unprompted.
Proven before the build by streaming 40 real outcomes through ingest alone →
0 proposals; the vigil learning dimension emitted nothing until `propose()`
was called by hand.

## What was built (frontier, grounded in 2025–2026 work)

Three statistical cores, each replacing a heuristic with a principled,
anytime-valid method, plus the trigger that makes the voice speak.

**1. Autonomous trigger — `src/tex/learning/trigger.py`**
`AnytimeValidCalibrationTrigger` maintains an anytime-valid e-process (reusing
the repo's existing `drift/_anytime_valid.py`, Howard/Ramdas/Robbins mixture)
per `(tenant, policy_version)` on the false-permit signal, standardised against
the policy's tolerated rate. When the e-process crosses its boundary
(anytime-valid p < α, false-alarm bounded over the infinite horizon by Ville),
it calls the existing `propose()` and **seals the crossing certificate into the
proposal metadata** — Tex can prove *why* it spoke. Not a cron, not a count:
it fires on evidence. Hangs off the ingest path, fully defensive (never breaks
ingest), opt-in (an orchestrator with no trigger behaves exactly as before).

**2. Off-policy safety bound — `src/tex/learning/ope.py`**
`OffPolicyEvaluator` reuses `_rederive_verdict` to compute the proposed
policy's counterfactual action on each logged decision and places an
**anytime-valid upper confidence bound** on the counterfactual unsafe-release
rate (time-uniform Hoeffding, Howard et al. 2021). This is the "gated
deployment" guarantee (Karampatziakis/Mineiro/Ramdas): the bound holds at the
moment the operator looks. `propose()` gates on the *bound*, not the point
estimate — a bound above budget refuses the proposal even when replay looks
benign. Sealed into proposal metadata as the provable held-card sentence.

**3. Evidence-sufficiency gate — `src/tex/learning/sufficiency.py`**
`EvidenceSufficiency` replaces the crude cold-start count with a four-dimension
readiness score (completeness, freshness, reliability, representativeness;
"Evidence Sufficiency Under Delayed Ground Truth", 2025). Geometric mean so any
collapsed dimension fails readiness; representativeness is a hard sub-gate — a
window that has seen only one error mode can never justify moving a threshold.
When not ready, Tex stays silent **honestly** and names the weakest dimension.

**4. Lapse-on-supersession (the doctrine, wired)**
A proposal never nags and never expires on a timer. A fresh boundary crossing
over the same target supersedes the older pending proposal — `mark_expired()`
(previously an orphan with zero callers) now has its first real caller. Draft
first, supersede only on a successful draft, so a good proposal is never lapsed
for a draft that declines.

**5. Surface: calibration as a second kind of hold**
- `src/tex/vigil/calibration_provider.py`: `CalibrationProposalVigilProvider`
  maps the freshest pending proposal to the held-card payload with
  `hold.kind="calibration"`, the proposed change + safety bound as pull-only
  handles, and a Tex-voice sentence speaking meaning (loosen/tighten), not
  numbers. `CompositeHeldProvider` composes it **decision-first** — a held
  decision always wins the single slot; a proposal never preempts it.
- `src/tex/api/vigil_routes.py`: `HoldDTO` extended additively (`kind`,
  `proposal_id`, `proposed_change`, `safety_bound`; defaults keep decision
  holds byte-identical on the wire).
- `src/tex/vigil/utterances.py`: the `{count} proposals waiting` utterance is
  retired (`speaks_when=False`). Learning no longer surfaces as a notification
  line — only as the held-card hold.

**Backward compatibility:** the orchestrator's new collaborators
(`sufficiency_gate`, `ope_evaluator`, `trigger`) are all optional and default
to inert. An orchestrator constructed the legacy way is byte-for-byte
identical in behaviour. `propose()` gained one optional `trigger_metadata`
param.

## Verified here (ran, passed)

- **18/18** new tests — `tests/test_learning_autonomous.py`: trigger fires on a
  miscalibrated stream, silent on a well-calibrated one, seals certificate +
  OPE into metadata, supersession leaves exactly one PENDING with priors
  EXPIRED, never raises on no-signal; sufficiency ready/blocks thin/one-sided/
  stale; OPE bound zero-exposure / conservative / tightens with n / blocks over
  budget; provider maps to calibration hold; composite decision-first.
- **249** passing across every suite touching the changed modules —
  `test_feedback_loop`, `test_calibration_proposal_store`,
  `test_calibration_safety`, `test_latency_and_drift`,
  `test_learning_observability`, `tests/vigil`, `tests/drift`.
- **432** passing across all top-level app-building / endpoint tests (every
  test that calls `create_app()` / `TestClient`), confirming the `main.py`
  wiring and the `HoldDTO` change compose and serve.
- **558** passing across untouched core subsuites sampled for ripple —
  `tests/governance`, `tests/runtime`, `tests/contracts`.
- Full app composes: `create_app()` builds; `held_decision_provider` is a
  `CompositeHeldProvider`.
- **Runtime trace:** 40 outcomes streamed through ingest **only** → first
  proposal drafted autonomously ~20 outcomes in (nobody called `propose()`);
  one PENDING after supersession; proposal carried a sealed e-process
  certificate (p_anytime_valid ≈ 1.6e-03 < α=0.01) and a sealed OPE bound; the
  vigil reads it.

## Pre-existing failures (NOT caused by this build)

Six endpoint tests fail. **All six fail identically on a pristine, unmodified
unzip of the same archive** — confirmed by running them against a clean copy.
They are in the discovery/scan + scheduler family (a demo-connector seeding
issue on this checkout), untouched by this build:

- `test_governance_endpoint.py::TestUngovernedHeld::test_held_candidate_appears_as_ghost_ungoverned_row`
- `test_discovery_routes.py::TestScan::test_scan_returns_summary_and_entries`
- `test_discovery_routes.py::TestScan::test_scan_idempotent_via_api`
- `test_discovery_routes.py::TestLedger::test_ledger_paginates`
- `test_discovery_routes.py::TestLedger::test_ledger_verify_chain`
- `test_governance_history_routes.py::TestSchedulerRoutes::test_status_with_no_tenants`

## Verify locally (not run here)

- The **full** ~3,900-test suite end to end. The harness here can't hold the
  whole run in one session, and several suites need backends not installed in
  this sandbox: `tests/pqcrypto`, `tests/frontier_thread_12_tee`,
  `tests/nanozk`, `tests/zkprov` (ML-DSA / TEE attestation / ZK provers). Run:
  `pip install httpx pytest-xdist` then
  `PYTHONPATH=src pytest tests/ -n auto --dist=loadscope`.
- Endpoint behaviour against your real Postgres (`DATABASE_URL` set) — the runs
  here were pure in-memory.

## Wire-level note for the frontend pass (next zip)

The `/v1/vigil` `human_decision.hold` now carries, when
`hold.kind == "calibration"`: `proposal_id`, `proposed_change`
(permit/forbid/min_confidence before→after), `safety_bound` (the OPE dict),
and `resolving_question`. The three verbs map to existing routes:
approve → `POST /v1/learning/proposals/{id}/approve`,
refuse → `.../reject`, keep-holding → no write (the proposal lapses on
supersession). That's the contract `texApi.js` + the held card render against.

# Subsystem Dossier — `engine` (the Decision engine / PDP / "brain")

> Scope: `/Users/matthewnardizzi/dev/tex/src/tex/engine/`
> Branch: `feat/proof-carrying-gate`
> Architectural layer (self-declared, `engine/__init__.py:9`): **Layer 4 — Execution Governance** (the Policy Decision Point).
> Reachability: **LIVE** — verified end-to-end below.

All claims below were verified by reading the code. Statements drawn from docstrings or `.md` files that were *not* confirmed in code are explicitly labelled `(claim, unverified)`.

---

## Overview

The `engine` unit is Tex's **Policy Decision Point (PDP)** — the orchestration "brain" that takes one `EvaluationRequest` + one immutable `PolicySnapshot` and produces a single verdict in `{PERMIT, ABSTAIN, FORBID}`, together with a fused risk score, confidence, findings, reasons, uncertainty flags, latency breakdown, a determinism fingerprint, and a stack of audit certificates.

The pipeline is **deterministic** (no LLM sits in the verdict path; the semantic "judge" is a pluggable analyzer that defaults to a deterministic analyzer — `pdp.py:206`). The verdict is computed by a strict precedence ladder (`router.py` `_determine_verdict`, "R0–R4 selective-risk rule") fed by a weighted fusion of up to **seven evidence streams** (`router.py:392` `_fuse_scores`). On top of the router sit a series of **monotone-lowering** rails — each can only ever demote `PERMIT → ABSTAIN`, never relax a verdict — and a **structural FORBID floor** that short-circuits to FORBID on a deterministic proof of violation, bypassing the router entirely.

Key engine-owned concepts:
- **R0–R4 selective-risk ladder** + 7-stream weighted fusion (`router.py`).
- **Conformal Risk Control (CRC) gate** — a finite-sample, distribution-free risk-controlling cutoff with a two-sided certified hold band (`crc_gate.py`). **Inert by default** (no calibration data shipped).
- **The Hold** — abstention made first-class: epistemic-vs-aleatoric typing + the single pivotal fact that would resolve it (`hold.py`), optionally re-ranked by a closed-form EPIG/credal resolver (`credal_hold.py`).
- **Abstention certificate** — descriptive sealed receipt for an ABSTAIN with a non-weaponization witness (`abstention_certificate.py`).
- **Behavioral-contract bridge** (LTLf, `contract_bridge.py`) and **path-policy bridge** (LTLf over execution paths, `path_policy_bridge.py`) — both opt-in, both can hard-FORBID or soft-ABSTAIN.
- **Live multiplicative e-value risk spine** (`risk_spine.py`) — anytime-valid drift monitor; **None by default** (no-op).
- **Verdict transcript + monotonicity witness** (`verdict_transcript.py`) — canonical hashable execution trace, always built; the substrate for a future zk-Verdict.
- **Verdict certificate** (`verdict_certificate.py`) — offline robustness + QIF evidence ABOUT the verdict; **inert default**, never read by the verdict path.

---

## File Inventory

| File | Lines | Role (one line) |
|---|---:|---|
| `__init__.py` | 11 | Layer marker only (`__layer__ = 4`, `execution_governance`). No exports. |
| `pdp.py` | 1356 | **`PolicyDecisionPoint`** — the orchestrator. Runs the full pipeline `evaluate()`, builds `Decision`/`EvaluationResponse`, seals attempt/decision/transcript, applies the structural FORBID floor + soft merges + CRC + holds. |
| `router.py` | 864 | **`DecisionRouter`** + `RoutingResult` + `SelectiveRiskRule`. 7-stream weighted fusion, confidence computation, the R0–R4 verdict ladder, reasons/uncertainty-flag/ASI builders. |
| `crc_gate.py` | 950 | **`ConformalRiskGate`** + `CRCCertificate`. RCPS/SCRC two-sided risk-controlling permit/forbid cutoffs; Hoeffding-Bentkus UCBs; LTT joint budget + epsilon-collar. Inert default. |
| `hold.py` | 357 | **`Hold`** + `build_hold`. Typed (epistemic/aleatoric/mixed) abstention; flag→pivotal-fact map; resolution mode; spoken sentence. |
| `credal_hold.py` | 505 | L8 credal interval (closed-form LP extrema over a weight-ambiguity polytope) + EPIG acquisition ranking; `rank_pivotal_flags` is the one wire into `hold.py`. |
| `abstention_certificate.py` | 266 | `build_abstention_certificate` — descriptive ABSTAIN receipt: trigger + justification + non-weaponization witness, read from the CRC certificate. |
| `contract_bridge.py` | 689 | Behavioral-contract (LTLf) adapter: `evaluate_contracts_for_request`, `SessionEnforcerRegistry`, ledger replay. Translates `ContractViolation`→`Finding`; hard→FORBID, soft→ABSTAIN. |
| `path_policy_bridge.py` | 317 | Path-policy (LTLf-over-path) adapter: `evaluate_path_policies_for_request`. block→FORBID, warn→ABSTAIN, audit→findings only. Opt-in via `request.metadata["path_policy"]`. |
| `risk_spine.py` | 528 | L9 live multiplicative e-value spine: `RiskSpine`, `apply_risk_spine`. Anytime-valid drift hold (PERMIT→ABSTAIN). Inert (None) by default. |
| `verdict_transcript.py` | 952 | Canonical `VerdictTranscript` + `MonotonicityWitness` + derive/verify; `build_verdict_transcript`. Hashable execution trace, offline-checkable witness. |
| `verdict_certificate.py` | 619 | L12 `VerdictCertificate`: robustness (lower confidence bound over a seeded paraphrase family) + QIF leakage point-estimate. Inert default; evidence only, never read by verdict path. |

**Total: 12 `.py` files, ~7,453 lines.**

---

## Internal Architecture

### 1. `PolicyDecisionPoint.evaluate` — the pipeline (`pdp.py:243-604`)

A single `evaluate(*, request, policy) -> PDPResult` call executes, in this fixed order (timed per stage into `LatencyBreakdown`):

1. **ATTEMPT seal** (`pdp.py:261`) — `seal_attempt(self._decision_ledger, ...)`. Fail-closed, observation-only; no-op when no ledger.
2. **Deterministic recognizers** (`pdp.py:264`) — `self._deterministic_gate.evaluate(...)` → `DeterministicGateResult`.
3. **Retrieval grounding** (`pdp.py:271`) — `self._retrieval_orchestrator.retrieve(...)` → `RetrievalContext`. Default is a no-op orchestrator (`build_noop_retrieval_orchestrator`, `pdp.py:202`).
4. **Agent governance** (`pdp.py:282-285`) — `self._agent_evaluator.evaluate(request)` (identity/capability/behavioral) or a neutral bundle (`_neutral_agent_bundle`, `pdp.py:1337`) when no evaluator is wired.
5. **Specialist judges** (`pdp.py:289`) — `self._specialist_suite.evaluate(...)` → `SpecialistBundle`.
6. **Semantic judge** (`pdp.py:296`) — `self._semantic_analyzer.analyze(...)` → `SemanticAnalysis`.
7. **Behavioral contracts** (`pdp.py:311`) — `evaluate_contracts_for_request(...)` → `ContractEvaluationOutcome`. `NEUTRAL_OUTCOME` when no enforcer/registry.
8. **Path policies** (`pdp.py:325`) — `evaluate_path_policies_for_request(request=request)` → `PathPolicyOutcome`. `NEUTRAL_PATH_OUTCOME` when no `path_policy` metadata.
9. **Structural FORBID floor** (`pdp.py:339`) — `detect_structural_floor(specialist_bundle, request=request)` → `StructuralFloorResult`.

**Hard-violation short-circuit** (`pdp.py:343-374`): `hard_violation = contract_outcome.has_hard_violation or path_outcome.has_block or structural_floor.fired`. If true, the router is **skipped**; `_build_hard_forbid_routing_result` synthesises a FORBID (`final_score=1.0`, `confidence=1.0`) folding deterministic + contract + path + structural findings (`pdp.py:673-747`), and `build_asi_findings` is still called to preserve the OWASP ASI evidence trail (`pdp.py:361`).

**Routed branch** (`pdp.py:375-437`), in order, each rebuilding the immutable `RoutingResult`:
- `self._router.route(...)` — the base verdict (`pdp.py:377`).
- `_merge_soft_contract_signals` if a soft contract violation fired — promotes PERMIT→ABSTAIN (`pdp.py:391`, body `820-885`).
- `_merge_path_signals` for path warn/audit — warn promotes PERMIT→ABSTAIN (`pdp.py:398`, body `749-789`).
- `apply_predictive_holds(base, request)` — Pro2Guard DTMC lookahead + RV4 recoverable-path holds, PERMIT→ABSTAIN only (`pdp.py:409`; impl `systemic/probguard.py:517`).
- `apply_cadence_hold(base, request)` — autonomous-attack action-cadence circuit-breaker, soft only (`pdp.py:418`; impl `deterministic/cadence.py:574`).
- `apply_risk_spine(self._risk_spine, base, request)` — e-value drift hold (`pdp.py:423`; impl `risk_spine.py:466`). No-op when spine is None.
- `apply_pq_durability_hold(base, request, decision_ledger)` — PQ-non-repudiation hold (`pdp.py:432`; impl `pqcrypto/pq_durability.py:257`).

**CRC gate — "the last touch"** (`pdp.py:445-457`): `self._crc_gate.apply(verdict, final_score)`. On `crc_result.demoted`, `_apply_crc_demotion` rebuilds the result as ABSTAIN (`pdp.py:791-818`). The CRC certificate is always attached.

**The Hold** (`pdp.py:467-476`): `build_hold(...)` — only non-None when the verdict is ABSTAIN.
**Abstention certificate** (`pdp.py:485-493`): `build_abstention_certificate(...)` — only non-None for ABSTAIN.

**Materialization** (`pdp.py:495-604`): `LatencyBreakdown`, `content_sha256 = sha256(request.content)`, `compute_determinism_fingerprint(...)` (over content hash + policy version + every stream's result, but **not** CRC/holds/spine — those are explicitly out of the fingerprint, see `crc_gate.py:69-72`, `risk_spine.py:236-238`), then `_build_decision`, `seal_decision`, `build_verdict_transcript` + `derive_monotonicity_witness` + `seal_verdict_transcript`, then `_build_response`. Returns a frozen `PDPResult` (`pdp.py:115-147`) carrying every intermediate artifact.

### 2. `DecisionRouter` — fusion + verdict ladder (`router.py:172-865`)

**Stream scores** (`router.py:203-244`):
- `deterministic_score` — `1.0` if blocked, else max finding-severity score (`CRITICAL=1.0, WARNING=0.55, INFO=0.20`) (`router.py:373-390`).
- `specialist_score` — **cross-specialist fusion** via `tex.specialists.fusion.fuse` (`router.py:214-216`); `fused_risk >= max_risk_score` (corroboration-aware, only increases sensitivity).
- `semantic_score = semantic_analysis.max_dimension_score`.
- `criticality_score = policy.criticality_for(action_type, channel, environment)`.
- three agent stream scores (identity/capability/behavioral) when `agent_present`, else `0.0`.

**Fusion** (`_fuse_scores`, `router.py:392-427`): a bounded weighted sum over `_effective_weights`. When no agent is present, `_effective_weights` (`router.py:429-470`) **renormalizes the three agent weights back into the four content weights** so the no-agent path reproduces pre-fusion behavior exactly (the documented backwards-compat contract). Default weight vector (`domain/policy.py:33`): deterministic 0.234, specialists 0.195, semantic 0.273, criticality 0.078, agent_identity 0.060, agent_capability 0.090, agent_behavioral 0.070 (sums to 1.0).

**Confidence** (`_compute_confidence`, `router.py:507-547`): content base = `det*0.25 + spec*0.20 + sem*0.55`, minus penalties for low-confidence dimension / weak evidence; when agent present, blended 80/20 and boosted +0.10 on a capability violation. Per-stream confidences are also surfaced verbatim under reserved `conf_stream:*` score keys (`router.py:322-329`, helper `_per_stream_confidences` `router.py:472-505`) so the credal hold can read them without recomputation.

**Verdict ladder** (`_determine_verdict`, `router.py:549-633`), strict precedence, constants in `SelectiveRiskRule` (`router.py:50-96`):
- **R0** structural/deterministic floor: deterministic `blocked` → FORBID; agent `QUARANTINED` → ABSTAIN; agent capability violation → FORBID (`router.py:578-584`).
- **R1** semantic-dominance override → FORBID when semantic recommends FORBID with confidence ≥ 0.85, `max_dimension_score` ≥ 0.90, `evidence_sufficiency` ≥ 0.40 (`router.py:593-599`).
- **R2** soft-semantic / score FORBID escalation: semantic FORBID + `final_score ≥ permit_threshold` → FORBID; or `final_score ≥ forbid_threshold` → FORBID (`router.py:606-612`).
- **R3** ABSTAIN — every uncertainty trigger (`_should_abstain`, `router.py:635-720`): semantic recommends ABSTAIN; confidence below policy minimum; low-confidence dimension; weak evidence + score≥permit; any specialist ≥ 0.60 (score<forbid); a **structural specialist** (clawguard/mcpshield/planguard/mage/agentarmor/argus/attriguard/vigil) ≥ 0.30 with a matched policy clause; `no_retrieval_context` flag + score≥permit; the mid-band `permit < score < forbid`; agent forbid-streak ≥ 3; cold-start agent on borderline; PENDING lifecycle.
- **R4** PERMIT — *only* when positively clean: `final_score ≤ permit_threshold` AND `confidence ≥ minimum_confidence` AND semantic recommends PERMIT; otherwise falls through to **ABSTAIN, never default PERMIT** (`router.py:626-633`).

The "probabilistic signals only ever lower a verdict" invariant is the through-line; R0 stays deterministic (`router.py:73-76`).

### 3. `ConformalRiskGate` — calibration / thresholds with a guarantee (`crc_gate.py:430-938`)

This is the engine's only *statistically calibrated* threshold mechanism. Given a labelled calibration set of `(final_score, unsafe)` records (`CalibrationRecord`, `crc_gate.py:103-118`), at construction it sweeps a 1001-point grid (`_DEFAULT_GRID_SIZE`, `crc_gate.py:406`) to find:
- a **permit cutoff** `lambda_hat` — the most permissive score whose Hoeffding-Bentkus UCB on the (marginal or SCRC-selective) false-permit rate is ≤ `alpha` (`_calibrate`, `crc_gate.py:617-693`);
- a symmetric **forbid cutoff** `lambda_forbid` bounding the false-forbid (over-blocking) rate (`_calibrate_forbid`, `crc_gate.py:695-781`).

The UCB is `hoeffding_bentkus_ucb = min(hoeffding_ucb, bentkus_ucb)` (`crc_gate.py:351-400`) — Bentkus inverted via exact binomial CDF + 60-iteration binary search. The joint two-sided budget `delta` is split Bonferroni across the two families (`delta_permit`, `delta_forbid`, `crc_gate.py:514-522`), and an `epsilon`-collar (default one grid step) shrinks both certified regions to transfer the guarantee from grid node to continuous score (`_collar_permit`/`_collar_forbid`, `crc_gate.py:593-615`).

`apply(verdict, final_score)` (`crc_gate.py:870-928`) is a pure comparison: inert or non-PERMIT → pass-through; PERMIT with `score ≤ lambda_hat` → PERMIT certified; PERMIT outside the certified region (or no certifiable region) → **demote to ABSTAIN** with flag `crc_permit_region_exceeded`. Every call attaches a full `CRCCertificate` (`crc_gate.py:124-331`, built by `certificate_template` `crc_gate.py:818-866`).

### 4. The Hold + credal/EPIG resolver (`hold.py`, `credal_hold.py`)

`build_hold` (`hold.py:198-357`) returns `None` for any non-ABSTAIN verdict. For an ABSTAIN it: accrues epistemic vs aleatoric mass from the uncertainty flags via `_FLAG_PIVOTS` (`hold.py:96-136`); margin-labels the `HoldType` (EPISTEMIC/ALEATORIC/MIXED, margin 0.20); picks the pivotal flag (fixed order, unless `stream_confidences` are threaded and >1 epistemic candidate, in which case `rank_pivotal_flags` re-ranks them); chooses a `ResolutionMode` (SELF_HEAL / HUMAN_FACT / HUMAN_JUDGMENT); reads the certified band straight off the CRC certificate (never recomputes it, `hold.py:312-320`); and produces a spoken `sentence`/`detail`. Pure and deterministic (preserves the fingerprint).

`credal_hold.py` builds a **credal interval** of fused risk as the exact `[risk_low, risk_high]` over an L1-ball of fusion-weight ambiguity intersected with the simplex, plus per-stream confidence boxes, by closed-form greedy mass-transport LP extrema (`_linear_extremum`, `credal_hold.py:209-248`) — no solver. The **EPIG resolver** (`score_acquisition`/`rank_acquisitions`/`rank_pivotal_flags`, `credal_hold.py:337-505`) ranks candidate evidence acquisitions by expected resolution probability then expected width drop, over a *synthetic* posterior (centered at `final_score`, default fusion weights). The module is explicit that this is `research-early` and "EPIG over a synthetic posterior", not "decision-optimal over the live posterior" (`credal_hold.py:57-85`).

### 5. The two bridges (`contract_bridge.py`, `path_policy_bridge.py`)

Both convert an external runtime checker into PDP-shaped outcomes. `contract_bridge` adapts `tex.contracts.ContractEnforcer` (LTLf behavioral contracts, ABC 6-tuple), supports stateless OR session-scoped (`SessionEnforcerRegistry` LRU, ledger replay to seed `_soft_pending`), maps soft clauses (`soft_invariant`/`soft_governance`) → WARNING/soft, others → CRITICAL/hard (`contract_bridge.py:563-571`). It touches one enforcer internal (`enforcer._violations[:]`, `contract_bridge.py:446`) during priming, documented loudly. `path_policy_bridge` wires `tex.governance.path_policy.PathPolicyChecker`; severity `block→FORBID`, `warn→ABSTAIN`, `audit→INFO finding` (`path_policy_bridge.py:247-274`). Both return a neutral zero-cost outcome when their opt-in input is absent.

### 6. Transcript + witness (`verdict_transcript.py`)

`build_verdict_transcript` (`verdict_transcript.py:610-891`) reconstructs a canonical, byte-stable, hashable stage list (evidence stages → structural floor → routing → monotone holds), capturing verdict-carrying endpoints from the live `RoutingResult` objects and honestly labelling the per-hold attribution inside the aggregate `monotone_holds` stage as reconstructed-from-flags. `derive_monotonicity_witness` (`verdict_transcript.py:361-514`) is a **pure relation** asserting: no transforming stage moved toward PERMIT, risk never decreased, continuity threads, the structural floor (if fired) forced FORBID@1.0, and endpoints match. `verify_transcript_witness` (`verdict_transcript.py:536-553`) re-derives and compares canonical bytes — the offline self-certifying checker. The transcript hash is a plain SHA-256 — explicitly **not** a zk proof; the zk-Verdict story is `speculative` (`verdict_transcript.py:36-41`).

---

## Public API

Imported by code outside `engine/` (call-sites traced in *Wiring In*):

- `pdp.py`: **`PolicyDecisionPoint`**, `PDPResult`, `build_default_pdp`, and the `Router`/`AgentEvaluator` Protocols.
- `router.py`: `DecisionRouter`, `RoutingResult`, `build_default_router`, `SelectiveRiskRule`, `DEFAULT_SELECTIVE_RISK_RULE`.
- `crc_gate.py`: `ConformalRiskGate`, `CRCCertificate`, `CRCGateResult`, `CalibrationRecord`, `build_default_crc_gate`, `hoeffding_ucb`, `bentkus_ucb`, `hoeffding_bentkus_ucb`.
- `hold.py`: `Hold`, `HoldType`, `ResolutionMode`, `build_hold`.
- `contract_bridge.py`: `evaluate_contracts_for_request`, `ContractEvaluationOutcome`, `NEUTRAL_OUTCOME`, `SessionEnforcerRegistry`.
- `path_policy_bridge.py`: `evaluate_path_policies_for_request`, `PathPolicyOutcome`, `NEUTRAL_PATH_OUTCOME`.
- `risk_spine.py`: `RiskSpine`, `apply_risk_spine`, `RISK_SPINE_FLAG`, `seal_drift_step`, etc.
- `abstention_certificate.py`: `build_abstention_certificate`.
- `credal_hold.py`: `rank_pivotal_flags` + the rich credal API.
- `verdict_certificate.py`: `VerdictCertificate`, `certify_verdict`, `stability_p_low`, `generate_neighborhood`, `estimate_verdict_channel_leakage`, `QIFSample`, `RobustnessObservation`, `verdict_certificate_metadata`.
- `verdict_transcript.py`: `VerdictTranscript`, `MonotonicityWitness`, `build_verdict_transcript`, `derive_monotonicity_witness`, `verify_transcript_witness`, `recompute_witness`.

`engine/__init__.py` itself exports **nothing** except the layer markers (`engine/__init__.py:9-10`); all imports are deep (`from tex.engine.pdp import ...`).

---

## Wiring

### Wiring In (who imports the engine)

Verified by grep over `src/tex` (excluding `engine/` and pycache):

- **`tex.main`** (the composition root): `from tex.engine.pdp import PolicyDecisionPoint` (`main.py:69`); `from tex.engine.contract_bridge import SessionEnforcerRegistry` (`main.py:40`). Constructs the live PDP at `main.py:876`.
- **`tex.commands.evaluate_action`**: `from tex.engine.pdp import PDPResult, PolicyDecisionPoint` (`evaluate_action.py:28`); calls `self._pdp.evaluate(...)` at `evaluate_action.py:214`.
- **`tex.selfgov.governor`**: routes self-governance mutations through "the real `PolicyDecisionPoint.evaluate`" (`governor.py:13,48`).
- **`tex.capstone`** (`flow.py:70-71`, `compose.py:50-52`, `verify.py:55`): imports `PolicyDecisionPoint`, `RiskSpine`, `PDPResult`, `RISK_SPINE_FLAG`, `stability_p_low`. (Reachability INDIRECT per spine pass.)
- **`tex.bench`** (`honest_decline.py:43`, `replay_trial.py`, `wave2_corpus/*`): `build_hold`, verdict-certificate helpers, `hoeffding_bentkus_ucb`.
- **`tex.provenance.transcript_seal`**: `MonotonicityWitness`, `VerdictTranscript` (`transcript_seal.py:53`).
- **`tex.ecosystem.bridge`** / **`tex.zkpdp.arbiter`** / **`tex.contracts.action_class`**: import `RoutingResult` / `DecisionRouter` / `hoeffding_bentkus_ucb`.
- `deterministic/cadence.py`, `pqcrypto/pq_durability.py`, `systemic/probguard.py` import `RoutingResult` under `TYPE_CHECKING` only (annotation, no runtime edge).

### Live call path (from the running app)

**`wired_status = LIVE`.** Confirmed end-to-end:

1. `POST /v1/guardrail` → `guardrail_evaluate(...)` (`api/guardrail.py:788`).
2. → `command = _get_evaluate_action_command(request)`; `result = command.execute(domain_request)` (`api/guardrail.py:825,827`).
3. → `EvaluateActionCommand.execute` (`commands/evaluate_action.py:187`) → `pdp_result = self._pdp.evaluate(request=..., policy=...)` (`commands/evaluate_action.py:214`).
4. The `EvaluateActionCommand` (with its `pdp`) is built in `build_runtime` at `main.py:962-963` and attached to `app.state` (`main.py:1656`); the PDP itself is constructed at `main.py:876-883`.

There is no flag gating the PDP itself — it is always live. (Adapter routes under `/v1/guardrail/<gateway>` in `api/guardrail_adapters.py:51,79` also resolve to `command.execute`.)

**Live construction (`main.py:876-883`)** passes only:
```
PolicyDecisionPoint(
    retrieval_orchestrator=retrieval_orchestrator,
    agent_evaluator=agent_suite,
    contract_enforcer=contract_enforcer,            # or None
    contract_session_registry=contract_session_registry,  # or None
    contract_action_ledger=contract_action_ledger,
    decision_ledger=decision_ledger,                # None unless TEX_SEAL_DECISIONS=1
)
```
It does **not** pass `crc_gate`, `risk_spine`, or `router`. Therefore in production:
- the **CRC gate is the inert default** (`build_default_crc_gate()`, `pdp.py:231`) — pass-through, `certified=False`, `lambda_hat=1.0` (verified at runtime: `enabled=False, certified=False, lambda_hat=1.0`). It never demotes a PERMIT until an operator supplies calibration.
- the **risk spine is `None`** → `apply_risk_spine` is a byte-for-byte no-op (`risk_spine.py:479-480`).
- the **router is the default** `build_default_router()` with `DEFAULT_SELECTIVE_RISK_RULE`.

Contracts are live: `main.py` builds a seeded contract suite and either a stateless `ContractEnforcer` or a `SessionEnforcerRegistry` unless disabled (`main.py` block around the PDP construction). `decision_ledger` is `None` unless `TEX_SEAL_DECISIONS` is set, so attempt/decision/transcript seals are no-ops by default.

### Wiring Out (engine dependencies)

**Other tex subsystems (runtime imports in `pdp.py`):** `contracts.runtime_enforcement`, `deterministic.cadence`/`deterministic.gate`, `agent.{behavioral,capability,identity}_evaluator`, `domain.*` (abstention_certificate, agent_signal, asi_builder, decision, determinism, evaluation, finding, latency, policy, retrieval, verdict), `provenance.{attempt_seal,decision_seal,ledger,transcript_seal}`, `retrieval.orchestrator`, `semantic.{analyzer,schema}`, `specialists.{base,ifc_specialist,judges,structural_floor,fusion}`, `pqcrypto.pq_durability`, `systemic.probguard`. Other engine files also pull `governance.path_policy`, `ecosystem.{proposed_event,state}`, `drift._anytime_valid`/`drift.evidence_adapter`, `domain.evidence`, `observability.telemetry`.

**External libraries:** `pydantic` (every model), and Python stdlib only otherwise — `hashlib`, `math`, `time`, `json`, `random`, `dataclasses`, `enum`, `collections`, `threading`, `datetime`, `uuid`, `logging`. **No numpy/scipy/crypto libs** in this unit; all the statistics (binomial CDF, Hoeffding/Bentkus, LP extrema, MI/min-entropy) are hand-rolled in pure Python.

---

## Implementation Reality

**`implementation_reality = REAL`.** No `NotImplementedError`, no `TODO`/`FIXME`, no pass-only bodies anywhere in `engine/`. The only "placeholder" token is a benign constant comment (`contract_bridge.py:117`, a neutral state-hash string).

Real, substantive logic (not stubs):
- **CRC gate math is real**: exact binomial CDF (`_binom_cdf`, `crc_gate.py:361-371`), Bentkus UCB via inequality inversion + binary search (`crc_gate.py:374-395`), the grid sweep, epsilon-collar, Bonferroni split, and the two-sided certificate are all implemented and self-consistent. Runtime-verified that the default gate is inert.
- **Router fusion + R0–R4 ladder is real** and fully branched; the no-agent weight renormalization is implemented (`router.py:429-470`).
- **Credal LP extrema** are a real closed-form greedy transport solver (`credal_hold.py:209-248`), documented as verified against a brute-force grid in tests `(claim, unverified — tests not read here)`.
- **e-value spine** reuses `AnytimeValidEProcess` verbatim and composes via `compose_spine`; the `2^K/α` action threshold is implemented (`risk_spine.py:167-179`).
- **Transcript witness** derivation/verification is a real pure relation over the stage list.
- **Verdict certificate** robustness bound (`stability_p_low`) reuses `hoeffding_bentkus_ucb` on the instability complement; QIF estimates (min-entropy leakage + Shannon MI) are real plug-in estimators (`verdict_certificate.py:298-350`).

**Honest "inert by default" seams (real code, but switched off in the live runtime):**
- CRC gate: inert (no calibration) — `crc_gate.py:537-553`, `build_default_crc_gate` `crc_gate.py:931-938`. Not wired with calibration in `main.py`.
- Risk spine: `None` by default; `apply_risk_spine(None, ...)` returns base unchanged.
- Verdict certificate: shipped default `VERDICT_CERT = certify_verdict()` is inert (`verdict_certificate.py:589`); `verdict_certificate_metadata()` returns `{"enabled": False, "certified": False}` while inert (`verdict_certificate.py:599-601`). It is **never read by the verdict path** — evidence only.
- Decision/attempt/transcript seals: no-ops unless `decision_ledger` is wired (`TEX_SEAL_DECISIONS=1`).

**Self-declared honesty about maturity (claims, confirmed in code as scope-limiting docstrings, not as behavior):**
- `credal_hold.py:57-85` — "EPIG over a synthetic posterior", `research-early`, NOT the live-posterior North-Star. The wired effect is genuinely observation-only (only reorders which question an ABSTAIN asks first).
- `risk_spine.py:78-88` — the sub-Gaussian null is "research-early until benchmarked on production data".
- `verdict_transcript.py:36-41` — the zk-Verdict is `speculative`; the module emits a plain SHA-256, not a succinct argument.
- `verdict_certificate.py` — `qif_certified` is `Literal[False]`, `qif_estimate_only` is `Literal[True]`: a certified QIF guarantee is structurally unconstructible this wave (genuinely enforced by the pydantic `Literal` types, `verdict_certificate.py:482-495`).

**Crypto/zk reality (per ground rules):** there is **no native crypto in `engine/`**. The "proofs" here are (a) a plain SHA-256 commitment over the canonical transcript (`verdict_transcript.py:231-234`) and (b) finite-sample statistical bounds (CRC/robustness). Signing/hash-chaining lives outside the unit in `provenance/transcript_seal.py` (ECDSA-P256, per its docstring — `(claim, unverified)` from here). So: no hollow crypto stub, but also no zk — the unit is honest that the transcript hash "does not claim" a zk proof.

---

## Technology / SOTA

- **Selective risk / abstention as a first-class verdict** — the R0–R4 ladder that never defaults to PERMIT (`router.py:50-96`).
- **Conformal Risk Control (RCPS)** — Bates–Angelopoulos–Lei–Malik–Jordan distribution-free risk-controlling prediction sets, one-sided monotone, Hoeffding-Bentkus UCB; extended two-sided with **Learn-then-Test** Bonferroni FWER split + epsilon-collar, and **Selective CRC** acted-set conditioning (`crc_gate.py` module docstring; all cited as arXiv lines). Implementation matches the described math.
- **Anytime-valid sequential testing** — multiplicative e-value spine, Ville's inequality, the `2^K/α` two-sided `|S_t|` correction (Safe Testing / Grünwald-de Heide-Koolen cited) (`risk_spine.py`).
- **Credal sets + EPIG** — convex-set-of-measures interval via LP extrema; decision-targeted expected predictive information gain (EPIG, Bickford Smith 2023) standing in credal width for predictive entropy; epistemic/aleatoric split (Hüllermeier-Waegeman 2021) (`credal_hold.py`).
- **LTLf runtime verification** — behavioral contracts (ABC 6-tuple, LTL3 three-valued) and path policies (policies-on-paths) (`contract_bridge.py`, `path_policy_bridge.py`).
- **Quantitative Information Flow** — min-entropy leakage (Smith FoSSaCS 2009) + Shannon MI, capped at `log2(3)` channel capacity (Köpf-Smith) (`verdict_certificate.py`).
- **Randomized-smoothing-style robustness** — one-sided lower confidence bound on verdict-stability over a seeded paraphrase family (Cohen-Rosenfeld-Kolter precedent) (`verdict_certificate.py`).
- Design patterns: dependency injection of every collaborator into the PDP (`__slots__` constructor, `pdp.py:182-241`), immutable frozen pydantic/dataclass results rebuilt rather than mutated, named-constant rule objects (`SelectiveRiskRule`, `CredalParams`) to eliminate inline magic numbers, Protocols (`Router`, `AgentEvaluator`) for substitutability.

---

## Persistence

The engine unit is **almost entirely in-memory / stateless per request**:
- `PolicyDecisionPoint` holds only injected collaborators in `__slots__`; `evaluate` is a pure function of `(request, policy)` aside from the seal seams (`pdp.py:167-180`).
- `ConformalRiskGate` is stateless after construction (calibration frozen into instance fields); re-instantiate to recalibrate (`crc_gate.py:436-439`).
- `RiskSpine` is the **one stateful object** — it accumulates `AnytimeValidEProcess` state across requests on the injected instance (`risk_spine.py:228-256`); but it is `None` in the live runtime, so no live state.
- `SessionEnforcerRegistry` keeps an LRU dict of per-session `ContractEnforcer` instances in memory (`contract_bridge.py:186-288`); session/recovery state lives there, bounded by capacity (default 256).
- **Durable state is delegated out of the unit.** Decisions persist via `EvaluateActionCommand` → decision store / memory system (outside `engine/`). The optional `SealedFactLedger` (attempt/decision/transcript/drift seals) is an in-memory ledger unless backed durably; default-off (`main.py` `TEX_SEAL_DECISIONS`). The `ifc_labels` cache is consume-once (`pdp.py:1080-1084`).

No file/DB writes originate inside `engine/`.

---

## Notable Findings

1. **CRC gate, risk spine, and verdict certificate are all inert in production.** The headline "calibration / thresholds with a statistical guarantee" story is fully implemented but switched off: `main.py:876` never passes `crc_gate=` (calibrated) or `risk_spine=`. Live behavior is the **uncalibrated policy thresholds** (`permit_threshold`/`forbid_threshold` on the `PolicySnapshot`) via the R0–R4 ladder, with the CRC gate a pass-through. This is by design and documented, but means the "provably bounded false-permit rate" is *available, not active*. **Verified at runtime:** default gate `enabled=False, certified=False, lambda_hat=1.0`.

2. **No hand-tuned permit/forbid thresholds live in `engine/`** — they come from the `PolicySnapshot` (`domain/policy.py:81-91`); there is no module-level default for them (a policy must supply them). The *fusion weights* do have a module default (`domain/policy.py:33-41`). So "the eight-axis / scoring" is really a **seven-stream weighted fusion** (4 content + 3 agent) → one scalar, then a categorical ladder; the CRC gate is the optional eighth, calibrated layer.

3. **The "monotone-lowering" invariant is enforced structurally, not just asserted.** Every rail (soft contract, path warn, predictive holds, cadence, risk spine, PQ durability, CRC) rebuilds the `RoutingResult` and only ever demotes PERMIT→ABSTAIN; the hard-FORBID floor short-circuits the router. `verdict_transcript.derive_monotonicity_witness` then *re-derives* a witness that no stage moved toward PERMIT — a genuine cross-check, not a comment.

4. **Honesty discipline is real and code-enforced in places.** `verdict_certificate.qif_certified: Literal[False]` / `qif_estimate_only: Literal[True]` make "certified QIF" structurally unconstructible (pydantic will reject any other value). `credal_hold.py` and `risk_spine.py` carry explicit `research-early` scope caveats matching their wired behavior (observation-only / inert).

5. **Determinism fingerprint deliberately excludes the CRC/holds/spine.** `compute_determinism_fingerprint` is built from the stream results only (`pdp.py:506-513`); the docstrings state the monotone layers are intentionally outside the fingerprint (`crc_gate.py:69-72`, `risk_spine.py:236-238`). Consequence: two runs that differ only in CRC demotion share a fingerprint — defensible (the CRC gate is itself deterministic given calibration), but worth noting for any audit that treats the fingerprint as a verdict identity.

6. **One documented private-internal touch.** `contract_bridge._prime_enforcer_with_history` writes `enforcer._violations[:] = pre_violations` (`contract_bridge.py:446`) to suppress double-counted priming violations — flagged loudly in its own docstring as "the one place the bridge touches enforcer internals". Not a bug, but a coupling to `tex.contracts` internals.

7. **`engine/__init__.py` exports nothing** but the layer marker; all wiring is via deep imports. Minor: there is no curated public surface for the unit, so "public API" is defined by `__all__` lists in individual modules (present in most files; absent in `pdp.py` and `router.py`, which rely on direct symbol import).

8. **No dead code found** in the unit. The rich credal API (`credal_interval`, `rank_acquisitions`) beyond `rank_pivotal_flags` is exercised by tests/benches `(claim, unverified)`; within the live path only `rank_pivotal_flags` is reached, and only when `stream_confidences` are threaded *and* there is >1 epistemic candidate flag.

9. **Spine-pass classification confirmed.** `engine = LIVE` is correct: the PDP is reached unconditionally from `POST /v1/guardrail`. Sibling INDIRECT subsystems (capstone, bench) consume engine symbols but are not on the request path.

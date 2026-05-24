# FRONTIER_DELTA — Thread 7: Ecosystem Engine Steps 3, 5, 6, 7 fully wired

**Generated:** May 18, 2026 (research window: May 1 — May 18, 2026, with full sweep back to Jan 2026).
**Status:** Pre-build research brief. Subject to Phase 3 sweep at completion.
**Thread scope:** Wire steps 3 (contracts), 5 (causal attribution), 6 (drift), and 7 (systemic risk, flag-gated) of `EcosystemEngine.evaluate()` such that no axis returns hardcoded zero. Step 7 calls a `NotImplementedError`-raising scorer behind `TEX_ECOSYSTEM_SYSTEMIC=0` default; Thread 9 implements the scorer.

## TL;DR for the build

- **No design change is forced by post-May-14 frontier work.** The Section 1.4 anchors plus the Tex `engine.py` references (AAF arxiv 2512.18561, Bhardwaj ABC arxiv 2602.22302, Kaptein arxiv 2603.16586) are still the right floor and ceiling. Building to them as planned.
- **Three frontier add-ons** are wired in opportunistically because the cost of doing them is near-zero and they widen the moat against Microsoft Agent 365 / AGT, Zenity, Noma:
  1. **Drift-to-Action anytime-valid risk certificate** (arxiv 2603.08578, Mar 9 2026) on the Step 6 output, in addition to BOCPD run-length posterior.
  2. **Prefill-signal-style fast attribution** for Step 5 — borrows the *technique* (zero-decode signals) from MASPrism (arxiv 2605.07509, May 8 2026) but applied to the *symbolic action graph already in memory*, not to LLM internals, so we hit the 5ms p99 budget that MASPrism's 2.66s/trace cannot.
  3. **Resource-budget composition hook** documented for Step 3 (arxiv 2601.08815 v3, Ye/Tan, Mar 25 2026) — not wired in this thread, but the `contract_violation_severity` field is split into a `behavioral_severity / resource_severity` 2-tuple in CHANGELOG so a future thread can add Ye/Tan-style resource contracts without touching the engine. *Note: implementation deferred to a future thread; only the field shape changes here, no scoring logic for the resource leg.*
- **Survival-level finding (Section 5).** Microsoft Agent 365 went GA May 1, 2026. Microsoft AGT shipped an Intent Manager with drift policies on May 14, 2026 (4 days ago). Zenity ships "AI Intent Detection." **All three do declared-intent semantic drift comparison. None ships statistical change-point (BOCPD) on agent action streams. Step 6's wedge survives.** None ships causal-influence-graph attribution on the request path. Step 5's wedge survives. None ships eight-axis composite verdicts with cryptographic-evidence emission. Tex's whole-engine wedge survives.

---

## 1. What's newer than Section 1.4

Filtered to arXiv 2604+ and 2605+ and vendor news after May 1, 2026.

### Causal attribution (Step 5)

- **arxiv 2605.07509 — MASPrism: Lightweight Failure Attribution for Multi-Agent Systems Using Prefill-Stage Signals** (Liu, Feng, Pu, Chen — May 8, 2026, 10 days ago). Two prefill passes from a small LM (Qwen3-0.6B), no decoding. Extracts token-level NLL and attention weights. **2.66s per trace average**, 6.69× speedup over single-pass LLM prompting baseline. Beats Gemini-2.5-Pro by up to 89.50% relative improvement on TRAIL. **Top-1 accuracy on Who&When-HC: +33.41% over best baseline.** Beats the AAAI 2026 paper (arxiv 2509.08682) 36.2% step-level number on that benchmark. *This is now the failure-attribution SOTA.*
- **arxiv 2603.10749 — AttriGuard: action-level causal attribution via parallel counterfactual tests + teacher-forced shadow replay** (Mar 11, 2026). Already in Tex's frontier-references list via Thread 4 (AttriGuard is in CLAIMS §4.7) but reinforces that "pre-emission causal attribution" is the right framing for Step 5.
- **arxiv 2602.07918 — CausalArmor: causal ablation for over-defense** (Feb 8, 2026). Cited as alternative.
- **arxiv 2605.00248 — Causal Foundations of Collective Agency** (May 2026). Causal games + causal abstraction for *when a group becomes a collective agent*. Background framing for Step 5's "attribution at the ecosystem level," not directly wired.

### Drift detection (Step 6)

- **arxiv 2603.08578 — Drift-to-Action Controllers: Budgeted Interventions with Online Risk Certificates** (Mar 9, 2026). Three contributions: (i) **anytime-valid risk certificate** for drift under delayed supervision (no peeking penalty — you can stop the test at any time), (ii) belief-driven controller that maps drift evidence to cost-aware interventions, (iii) streaming evaluation protocol jointly measuring safety + recovery + operational cost. **This paper is the wedge.** Tex's existing `_bocpd.py` produces a run-length posterior; we layer Drift-to-Action's anytime-valid risk certificate on top so callers get *both* "is there a change point" and "is acting on it justified given budget."
- **arxiv 2512.05013 — TDKPS: Detecting Perspective Shifts in Multi-agent Systems**. Claims to be the *first principled framework* for monitoring behavioral dynamics in black-box MAS. Theory ahead of practice.
- **arxiv 2603.03456 — Asymmetric Goal Drift in Coding Agents Under Value Conflict** (Mar 3, 2026). GPT-5 mini, Haiku 4.5, Grok Code Fast 1 all exhibit asymmetric goal drift. Empirical evidence that drift detection on the request path matters; doesn't change Tex's design.
- **arxiv 2302.04759 — Robust and Scalable Bayesian Online Changepoint Detection** (Altamirano 2023). 10× faster than closest competitor with closed-form recursions. **Tex's `_bocpd.py` already cites Alami 2020 R-BOCPD with top-K pruning, which is a different acceleration line.** Both reach sub-millisecond per-observation. No action — Tex's current implementation is already in the same speed band.
- **arxiv 2508.03858 — MI9** (already in Tex's bibliography). Uses **Jensen-Shannon divergence + Mann-Whitney U test** for drift, NOT BOCPD. Goal-conditioned baselines. *Most relevant published competitor design for Step 6 — and our BOCPD-based approach is more principled (sequential, Bayesian, exact run-length posterior) than JS-divergence batch tests.*

### Contract / Step 3

- **arxiv 2601.08815 v3 — Agent Contracts: A Formal Framework for Resource-Bounded Autonomous AI Systems** (Ye/Tan, Mar 25, 2026, accepted COINE 2026 at AAMAS 2026). **Resource-bounded** contracts: 7-tuple specifying token budgets, time bounds, cost limits, delegation hierarchies with **conservation laws** (delegated budget ≤ parent budget). 90% token reduction, 525× lower variance in iterative workflows, zero conservation violations in multi-agent delegation. **Orthogonal to Bhardwaj ABC** (which Tex Thread 1 already wired): ABC governs *how* an agent behaves; Ye/Tan governs *how much* an agent may consume. Ye/Tan and Bhardwaj explicitly cite each other as complementary. **Nobody composes both.**
- **Bhardwaj ABC §4 Compositionality Theorem** (arxiv 2602.22302). The Thread 1 build wired the per-session enforcer; Section 4 of the paper establishes that contract guarantees compose across multi-agent chains under (C1) interface compatibility, (C2) assumption discharge, (C3) governance consistency, (C4) recovery independence, with quantified probabilistic degradation bounds. Tex Step 3 is now the ecosystem-level call site where this composition lives — a single line in `EcosystemAxisScores` aggregates per-session severities.
- **arxiv 2604.05229 — Koch, "From Governance Norms to Enforceable Controls"** (Apr 2026). Layered translation method from ISO/IEC 42001 / 23894 / 42005 to four control layers (governance objectives, design-time constraints, **runtime mediation**, assurance feedback). Tex Step 3 sits in the runtime-mediation layer.

### Systemic risk (Step 7, flag-gated to Thread 9)

- **arxiv 2605.11645 — GeomHerd: Forward-looking Herding Quantification via Ricci Flow Geometry on Agent Interactive Simulations** (May 2026, 1 week ago). Discrete **Ollivier-Ricci curvature on agent-interaction graphs**. Fires median **272 steps before** order-parameter onset; contagion detector recalls 65% of critical trajectories **318 steps early**. On co-firing trajectories, beats price-correlation-graph baselines by 40 steps. **Strict superset of SR-DTMA's lagging detection.** Thread 9's design target.
- **arxiv 2508.00500 v3 — ProbGuard: Probabilistic Runtime Monitoring** (Mar 27, 2026). DTMC + PCTL, PAC-style bounds, 38.66s ahead warnings. Already in Tex's references; v3 doesn't change the design.
- **arxiv 2512.03180 — AGENTSAFE** (Dec 2025). Unified governance framework with cryptographic provenance + auditable assurance. Tex's whole-engine is the production realization.

### Whole pipeline — the AAF paper Tex is built on

- **arxiv 2512.18561 v3 — AAF: Adaptive Accountability Framework** (Alqithami, Mar 19, 2026). End-to-end runtime layer combining (i) cryptographically verifiable interaction provenance, (ii) **distributional change points in streaming traces** = Step 6, (iii) **causal influence graph for responsibility attribution** = Step 5, (iv) cost-bounded interventions (reward shaping + targeted policy patching) = Step 8 (future thread). Establishes **bounded-compromise guarantee:** if expected intervention cost > adversary expected payoff, long-run compromised-interaction fraction converges strictly below 1. **Tex is the first production AAF realization.** AAF itself is a 87,480-run factorial simulation up to 500 agents, not a production runtime.

---

## 2. What competitors shipped (May 1 — May 18, 2026)

### Microsoft Agent 365 — GA May 1, 2026 (17 days ago)

- USD $15/user/month, Microsoft 365 E7 included.
- Cross-cloud registry sync with AWS Bedrock + Google Cloud public preview.
- Windows 365 for Agents (managed runtime sandbox) public preview, US-only.
- Local agent discovery via Microsoft Defender + Intune.
- Ecosystem partners since March 2026: Genspark, Zensai, Egnyte, Zendesk, Kasisto, Kore, n8n.

**Verdict for Thread 7:** No overlap with Steps 3/5/6/7. Agent 365 is a discovery + identity + lifecycle control plane. It does not score behavioral contracts via LTLf, does not do causal attribution per request, does not do statistical change-point on action streams, does not compute eight-axis composite verdicts. Survival-level threat is *distribution*, not capability.

### Microsoft Agent Governance Toolkit — Intent Manager (May 14, 2026, 4 days ago)

Blog: "Governance at the Speed of Agents: Microsoft Agent Framework and Agent Governance Toolkit, Better Together." Adds:
- **Intent Manager** with `DriftPolicy.SOFT_BLOCK | HARD_BLOCK | LOG_ONLY` for orchestrated workflows.
- **Cost governance module** — gradual budget drift + sudden cost spike detection. (Resource-bounded, Ye/Tan-style.)
- **Decision BOM** — Merkle-chained tamper-evident audit chain for governance events.
- Intent inheritance for child agents (narrowed scope).

**Verdict for Thread 7:** Microsoft is now in the *same problem space* as Tex Step 6 (drift) but with a fundamentally different mechanism — **declared-intent comparison** vs. Tex's **statistical change-point on action distributions**. Declared-intent drift catches "agent did action X but X wasn't in the declared plan." BOCPD catches "agent's tool-call rate distribution shifted regimes regardless of what was declared." Both are useful; they don't subsume each other. Tex's wedge: Microsoft can't detect collusive emergent behavior, frustration regimes, or capability-escalation pressure that doesn't violate any declared intent — those are *distributional* shifts AGT doesn't model.

Microsoft cost governance overlaps with the deferred Ye/Tan resource-contract leg. We are deferring resource contracts to a future thread (CLAIMS notes this), but the `contract_violation_severity` field is shape-preserving so we can add the resource leg later.

Microsoft Decision BOM Merkle chain overlaps with Tex's Thread 5 cosign chain and the AAF cryptographic provenance — Tex's chain is post-quantum (ML-DSA-65), Merkle-context-tree, CPSA-formally-verified (Thread 6). Microsoft uses Ed25519 with no formal verification. Tex moat intact.

### Zenity (Apr 7, 2026 — AI Intent Detection)

Page: zenity.io/academy/ai-intent-detection. "Deploy a security platform that understands agent intent and identifies drift in real time. Visibility into memory, context, and reasoning allows teams to detect subtle manipulations or misalignments before they escalate."

**Verdict:** Same intent-comparison mechanism as Microsoft. Same gap on statistical change-point and causal attribution. Modulos's vendor guide (April 2026) confirms Zenity is "agent-security focused, not a compliance/GRC platform" — i.e., does not produce eight-axis composite verdicts that map onto governance objectives.

Zenity's March 2026 ServiceNow Build Partnership and Gartner "Company to Beat" recognition (April 23, 2026) means Zenity is the distribution incumbent. Tex's moat is depth of evidence, not breadth of integrations.

### Noma Security

No public May 2026 product update on drift or attribution. $132M Series B (Mar 2026, Section 1.4) was infrastructure/identity-focused. No overlap with Thread 7 scope.

### Pillar, HiddenLayer, Mindgard

Model-layer focus (jailbreak / extraction / red-teaming). Out of scope for Thread 7.

### F5/CalypsoAI, CrowdStrike/Pangea, Palo Alto/Protect AI

All operate at AI-gateway level. Microsoft AGT is closer to Tex's request-path runtime than any of these. Pangea was integrated into CrowdStrike Falcon by April 2026 but still operates at content-filtering layer.

### ElixirData Context OS (May 2026 buyer-guide mention)

Claims Policy Gates + Decision Traces + Authority Model + Context Graphs. Reviewing public materials — appears to be policy-as-code with decision-traceability, comparable to AGT's policy engine + Decision BOM. No statistical drift, no causal attribution, no multi-axis composite. Not a competitor for Step 5/6.

### Vijil

Pre-deployment evaluation + Trust Score. Not runtime. Out of scope.

---

## 3. Standards revised

No IETF SCITT, FIPS, C2PA, or EU AI Act revision since May 1, 2026 changes the design of Thread 7 (which is request-path scoring, not evidence emission). The Thread 5/6 work owns the standards surface; Thread 7 inherits.

- IETF SCITT architecture **draft-22** (April 2026) — still current. Tex `attest_state` already targets `application/scitt-statement+cose` (TODO P1 in `engine.py:611`).
- C2PA 2.4 — still current. Thread 6 emits manifests; Thread 7 doesn't change this path.
- EU AI Act Article 50 Draft Guidelines (May 8, 2026) — Thread 5/6 already incorporated; Thread 7 doesn't touch.
- NIST CSRC: no FIPS 204 / 203 / 205 revisions since Section 1.4.

---

## 4. What this changes about the build plan

**Plan from the spec stands.** The Section 1.4 anchors (Adams/MacKay, Kaptein, ProbGuard, SR-DTMA, ABC) are the right floor. The May 8–14 frontier work *reinforces* the plan without forcing a redesign.

### What changes in implementation

1. **Step 5 `CHIEF.fast_attribute()`** — I will NOT try to port MASPrism (it's 2.66s/trace, 530× over budget). I will design `fast_attribute()` to use the *symbolic action graph already constructed in `HierarchicalCausalGraph.build_from_trace`* and run **only the leaf-causality walk**, returning a top-K candidate-source list and a confidence score. The full `attribute_root_cause()` (which does multi-hop graph search + LLM-judge tie-breaking) remains the post-incident endpoint. The brief commentary in the code will name MASPrism as the *technique inspiration* (zero-decode signals from already-computed state) without copying it.

2. **Step 6 `signal_registry.evaluate_drift()`** — Wire BOCPD as the primary detector (already implemented in `_bocpd.py`), but **also emit an anytime-valid p-value alongside the run-length posterior** per Drift-to-Action (arxiv 2603.08578). The anytime-valid p-value is a small post-processing step on the BOCPD output — no new dependency. This means downstream interventions (Step 8, Thread 8) can apply Drift-to-Action's budgeted-intervention controller without rework.

3. **Step 3 `contract_violation_severity`** — The existing `EcosystemAxisScores.contract_violation_severity` field is preserved as the *behavioral* severity. CLAIMS will document that this field corresponds to ABC behavioral contracts (Bhardwaj 2602.22302) and that Ye/Tan resource contracts (2601.08815) are a future addition behind a separate axis.

4. **Step 7 `TEX_ECOSYSTEM_SYSTEMIC=0` flag** — Per spec. The call site cites both ProbGuard (PCTL/DTMC, current SOTA for probabilistic guarantees) AND GeomHerd (arxiv 2605.11645, the forward-looking geometric direction) in the docstring as the two-paper design target for Thread 9's eventual implementation.

### What I'm NOT doing

- Not implementing `SystemicRiskEvaluator.score()` (Thread 9's job per spec).
- Not implementing Ye/Tan resource contracts (deferred, only documenting the future split).
- Not adding new dependencies. `_bocpd.py` is stdlib-only; I'm keeping `fast_attribute()` and `evaluate_drift()` stdlib-only too.
- Not touching steps 1, 2, 4, 8 except to update the stale telemetry-event comment per acceptance criterion #5.

---

## 5. Numerical SOTA targets to beat or be honest about

| Surface | Tex Thread 7 target | Reference SOTA | Stance |
|---|---|---|---|
| `EcosystemEngine.evaluate()` end-to-end | **≤50 ms p99** | Microsoft AGT policy engine 0.1ms p99 (Apr 2026) | Honest: AGT is a *single policy check*, Tex is *eight composed axes including BOCPD + causal attribution + cryptographic emission*. Not comparable. We are honest about this in CLAIMS. |
| Step 3 contract eval (in-engine call) | ≤500 µs p99 (already wired to Thread 1 SessionEnforcerRegistry) | Bhardwaj §6 5.2–6.8 violations/session detected | Inherited from Thread 1; no new target. |
| Step 5 `fast_attribute()` | **≤5 ms p99** | MASPrism 2.66 s/trace (10 days ago) | Tex `fast_attribute()` does *graph-walk attribution*, not LLM-prefill — incomparable; we name MASPrism as inspiration not benchmark. Full `attribute_root_cause` (post-incident) targets the AAAI 2026 36.2% Top-1 step accuracy and the MASPrism +33.41% Top-1 on Who&When-HC. |
| Step 6 BOCPD drift detect | **≤2 ms p99 per signal**, 71-step median detection delay (matches Tex's AAF benchmark in `_bocpd.py` docstring) | AAF empirical 71-step median detection delay (arxiv 2512.18561) | Match the existing Tex `_bocpd.py` benchmark. No regression. |
| Step 6 anytime-valid risk certificate | ≤1 ms p99 post-processing on BOCPD output | Drift-to-Action (arxiv 2603.08578) — sublinear in window size | Native composition; latency is dominated by BOCPD itself. |
| Step 7 (flag-gated; Thread 9 implements) | ≤30 ms p99 budget remaining when flag is on | GeomHerd 272-step forward-looking median, ProbGuard 38.66s ahead | Out of scope for Thread 7. Reserved as Thread 9 target. |

**Hard rule:** Total `evaluate()` p99 ≤ 50 ms (per spec acceptance criterion #6). With the per-step targets above plus Step 1 (ontology, already < 0.5 ms) and Step 2 (graph projection, ≤5 ms) and Step 4 (governance LTS, ≤5 ms), budget is:

```
1 (0.5) + 2 (5) + 3 (0.5) + 4 (5) + 5 (5) + 6 (3) + 7 (0 when off) + emit/ledger (5) = ~24 ms p99 with all axes wired and Step 7 off
```

This leaves ~26 ms of headroom. When `TEX_ECOSYSTEM_SYSTEMIC=1` is flipped on (Thread 9), the 30 ms Thread 9 budget fits.

---

## 6. Design decisions justified against the frontier

### Step 3 — Why call `evaluate_contracts_for_request` from inside the engine

**Choice:** Step 3 calls the existing `tex.engine.contract_bridge.evaluate_contracts_for_request` (Thread 1's wiring) with a `ContractEnforcer` resolved via `SessionEnforcerRegistry` keyed on `(proposed.actor_entity_id, proposed.session_id)`.

**Rejected alternative:** Instantiating a fresh `ContractEnforcer` per call. This would lose ABC's session-scoped (p, δ, k)-satisfaction state — the recovery-window counter would reset every event, undoing Thread 1.5's contribution. Bhardwaj §3.3 explicitly requires per-session state.

**Frontier alignment:** Ye/Tan (arxiv 2601.08815 §4) and Bhardwaj §4 Compositionality Theorem both require that aggregation of per-agent contract states preserve session state. The `SessionEnforcerRegistry` is the registry pattern AAF §6 implicitly requires (without naming).

**Severity extraction:** `enforcer.compliance_scores()` returns a `ComplianceScores` dataclass; we map `1.0 - reliability_index` into `axis_scores.contract_violation_severity` so that 0.0 = perfect compliance, 1.0 = total violation. Same direction as Section 1.4 ABC §3.

### Step 5 — Why `fast_attribute()` walks the action graph, not the LLM prefill

**Choice:** `CHIEF.fast_attribute(proposed, state_before, k=3)` walks the in-memory action-graph DAG built incrementally as events are admitted. Returns a `FastAttribution` dataclass with `top_candidates: tuple[str, ...]` (event IDs) and `confidence: float`.

**Rejected alternative 1:** Port MASPrism prefill signals. MASPrism is 2.66 s/trace; the budget is 5 ms p99. 530× slowdown. Even with caching, MASPrism's two prefill passes through Qwen3-0.6B cannot fit.

**Rejected alternative 2:** Use the full `HierarchicalCausalGraph.attribute_root_cause` from Thread 3. That endpoint is the *post-incident* attribution — it does multi-hop search, LLM-judge tie-breaking, and counterfactual evaluation. Order-of-magnitude too slow for the request path.

**Rejected alternative 3:** Skip Step 5 attribution entirely on the request path (do post-incident only). This is what every competitor does. AAF §4.3 specifically requires runtime attribution to be part of the "trace + attribute + intervene" pipeline; doing it only post-incident loses the closed-loop guarantee.

**Frontier alignment:** MASPrism's technique insight — *zero-decode signals from already-computed state* — applies here. The action graph is already in memory (Step 2 builds it). `fast_attribute()` reads it; it does not rebuild it. This is the spirit of MASPrism (no extra inference) without the cost of MASPrism (no extra LLM calls).

**Honest scope:** `fast_attribute()` returns the top-K direct causal predecessors of `proposed` in the action graph plus an aggregate confidence based on graph density around the candidates. It does NOT do counterfactual evaluation, LLM-judge ranking, or multi-hop search. The full `attribute_root_cause` endpoint remains the post-incident analysis tool. This is explicitly the "faster, less complete attribution" the spec requires.

### Step 6 — Why BOCPD + anytime-valid certificate, not MI9-style JS divergence

**Choice:** `signal_registry.evaluate_drift(proposed, state_before)` updates per-signal BOCPD state from `_bocpd.py` (already implemented), reads the run-length posterior, and emits both (a) the change-point mass at `r_t = 0` per Adams/MacKay §3 and (b) an anytime-valid p-value per Drift-to-Action §3 (e-process formulation).

**Rejected alternative 1:** MI9's Jensen-Shannon divergence on categorical event sequences (arxiv 2508.03858). JS divergence is a batch statistic — you compute it on a window vs. a reference. It is not a sequential test; you cannot "peek" at intermediate values without inflating false-positive rate. BOCPD is exact-sequential by design.

**Rejected alternative 2:** Edit-distance drift (arxiv 2509.11367). Lightweight but loses the run-length posterior — you get a binary "drift / no drift" without the "how recently did regime change" signal that the run-length posterior provides. Drift-to-Action requires the posterior for its controller.

**Rejected alternative 3:** Mahalanobis-distance two-sample test. Same batch limitation as JS divergence.

**Frontier alignment:** AAF §4 specifies "distributional change points in streaming traces" — BOCPD is the canonical streaming Bayesian change-point algorithm. Drift-to-Action's anytime-valid certificate is the formalization of "you can act on the drift signal at any time without inflating false-positive rate," which is what a runtime governance system needs. The combination is novel as a *production wiring* even though both components are individually published.

**Honest scope:** We do not implement Drift-to-Action's full belief-driven controller (Thread 8 / intervention). We compute the anytime-valid certificate; Thread 8 decides whether to act on it.

### Step 7 — Why a flag-gated call site, not a stub return

**Choice:** Step 7 reads `os.environ.get("TEX_ECOSYSTEM_SYSTEMIC", "0")`. When `"0"` (default): emits a `step_7.systemic_skipped_flag_off` telemetry event and contributes 0.0 to `systemic_risk_under_event`. When `"1"`: calls `SystemicRiskEvaluator.score(state_before, proposed)`. The call is wrapped in try/except: on `NotImplementedError` the engine fails closed to ABSTAIN with rationale `"step 7 systemic risk requires Thread 9; flag was set but scorer not implemented"`. On any other exception, also ABSTAIN. Never PERMIT.

**Rejected alternative:** Have step 7 always return 0.0 and not call any code. This loses the call-site documentation and makes Thread 9's wiring harder. The current shape lets Thread 9 land by *only* implementing `SystemicRiskEvaluator.score()`, no engine.py change required.

**Frontier alignment:** ProbGuard (arxiv 2508.00500 v3, Mar 27 2026) is the cited model for Thread 9's eventual implementation — PCTL property `P_{<θ}[F unsafe_state]` over a DTMC abstraction of the ecosystem. GeomHerd (arxiv 2605.11645, May 2026) is the alternative direction (Ollivier-Ricci curvature on agent interaction graph). The docstring names both so Thread 9 can choose. This thread does not commit to either.

**Honest scope:** When the flag is off, the engine continues to admit events without considering systemic risk. CLAIMS will state this explicitly — Tex's eight-axis claim is "evaluates across all eight axes" not "computes a non-neutral score on all eight axes today." Systemic risk axis is wired and ready; the scorer lands in Thread 9.

---

## 7. Theory-ahead-of-practice wedges shipped in Thread 7

For each, the theory exists in a 2026 paper. The competitor shipping data shows no production deployment.

1. **Eight-axis composite verdict with cryptographic evidence emission per event** — AAF (arxiv 2512.18561) is the paper, with 87,480-run simulation suite. Tex is the first production runtime. Microsoft Agent 365 / AGT / Zenity / Noma do not compose ≥3 axes per event; they layer at the policy / identity / discovery levels separately.

2. **Pre-emission causal attribution on the request path** — AAF §4.3 mandates it; AttriGuard (arxiv 2603.10749), CausalArmor (arxiv 2602.07918), MASPrism (arxiv 2605.07509) implement the *concept* in research contexts. No competitor ships request-path attribution. Microsoft AGT's Decision BOM reconstructs decisions *post-hoc*; Tex's `fast_attribute()` is *before admission*.

3. **BOCPD with anytime-valid certificate on agent action streams** — `_bocpd.py` already implements Adams/MacKay + Alami top-K. Drift-to-Action (arxiv 2603.08578) adds the anytime-valid certificate. Combination is novel as a production wiring. Microsoft AGT and Zenity ship declared-intent semantic drift only.

4. **Ecosystem-scoped behavioral contract composition** — Bhardwaj ABC §4 Compositionality Theorem (arxiv 2602.22302) is the theory. Tex Thread 1 wired single-agent ABC; Thread 7 puts the composition at the ecosystem aggregate. No competitor ships LTLf-temporal contracts at all (AGT does propositional rules; AgentSpec acknowledges its DSL "lacks support for trajectory-based safety analysis").

---

## 8. Files I will modify

| File | Change |
|---|---|
| `src/tex/ecosystem/engine.py` | Wire steps 3, 5, 6, 7 in `evaluate()`. Remove the `steps_3_5_6_7.skipped` telemetry event. Update docstring TODOs (line 278–283) from `[pending]` to `[done]`. |
| `src/tex/causal/chief.py` | Add `class FastAttribution` (frozen Pydantic model) and `def fast_attribute(self, ...)` method on `HierarchicalCausalGraph`. |
| `src/tex/drift/signal_registry.py` | Add `def evaluate_drift(proposed: ProposedEvent, state_before: EcosystemState) -> DriftEvaluation` orchestrator. New `class DriftEvaluation` (frozen Pydantic). |
| `src/tex/drift/_anytime_valid.py` | **NEW** — Drift-to-Action anytime-valid p-value computation (e-process). Pure stdlib. |
| `docs/ecosystem.md` | Document `TEX_ECOSYSTEM_SYSTEMIC` env flag and its semantics. |
| `tests/test_integration_layer.py` | New `TestEcosystemEightAxisPipeline` class with one integration test exercising all 4 steps in a single `/v1/guardrail` request. |
| `tests/test_thread7_integration.py` | **NEW** — Thread 7 dedicated end-to-end tests (CLAIMS-anchored). |
| `tests/test_chief_fast_attribute.py` | **NEW** — unit tests for `fast_attribute()`. |
| `tests/test_drift_signal_registry_evaluate.py` | **NEW** — unit tests for `evaluate_drift()` orchestrator + anytime-valid p-value. |
| `tests/test_ecosystem_engine_step7_flag.py` | **NEW** — unit tests for the `TEX_ECOSYSTEM_SYSTEMIC` flag both states. |
| `CLAIMS.md` | New §3 "Eight-axis ecosystem composition" section. |
| `COMMIT_MSG_thread_7.txt` | Conventional commit with the May 2026 anchors and the wedge statement. |
| `scripts/demo_thread_7_eightaxis.sh` | Single curl producing a verdict whose evidence record demonstrates all four newly-wired axes. |

**No deletions, no breaking changes.** Existing 2,350 tests (Thread 6 final count from `COMMIT_MSG_thread_6.txt`) continue to pass. Target: +30 new tests, total 2,380 passing.

---

## 9. CLAIMS line to ship

Per acceptance criterion #8:

> Tex's ecosystem engine evaluates every proposed event across all eight governance axes — ontology, graph projection, behavioral contracts, governance LTS, causal attribution, drift detection, and systemic risk — before admitting the event into the ecosystem state.

The CLAIMS section will additionally specify which axis is *active scoring* vs *flag-gated*, per Section 7 honest-scope discipline.

---

## 10. Phase 3 sweep plan

At thread completion, re-run frontier searches dated within the last 14 days (May 4 – Jun 1 expected window) on these exact queries:

1. `arxiv runtime governance multi-axis agent pipeline 2026`
2. `arxiv prefill signal causal attribution agent millisecond 2606`
3. `arxiv anytime-valid drift detection LLM agent 2606`
4. `Microsoft Agent Governance Toolkit changelog May June 2026`
5. `Zenity Noma drift attribution causal 2606`
6. `arxiv 2606 ecosystem governance behavioral contract composition`

If anything published between brief-write (May 18) and thread-completion changes the design, the brief is updated *before* the commit and the commit message names the new development.

---

**End of FRONTIER_DELTA_thread_7.md.**

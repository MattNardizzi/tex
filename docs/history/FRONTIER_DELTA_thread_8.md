# FRONTIER_DELTA — Thread 8: Bounded-Compromise Calculator + Intervention Engine + Restorative Path Executor

**Generated:** May 19, 2026 (research window: May 1 — May 19, 2026, with sweep back to Feb 2026).
**Status:** Pre-build research brief. Subject to Phase 3 sweep at completion.
**Thread scope:** Implement `tex.intervention.bounded_compromise.BoundedCompromiseCalculator`, `tex.intervention.engine.InterventionEngine`, and `tex.intervention.restorative.RestorativePathExecutor`, all currently scaffolds raising `NotImplementedError`. Wire as step 8 of `EcosystemEngine.evaluate()` at the call site marked TODO in `src/tex/ecosystem/engine.py:796-798` and the `_forbid()` helper at `:1101`.

---

## TL;DR for the build

- **Build to the AAF v3 paper (arxiv 2512.18561 v3, Mar 19 2026) verbatim.** Section 1.4 understated the math; the actual Theorem 5 is a **ratio bound** η* = αH / (λH − g_max), not just the inequality "cost > payoff." Proposition 1 gives closed-form minimum viable penalty λ_min = (g_max + αH) / (Hη*). These two formulas are the load-bearing math for `BoundedCompromiseCalculator`.

- **One post-May-14 paper opportunistically incorporated:** arxiv 2604.07833v2 (Embodied Agents Runtime Governance, Apr 10 2026) — gives concrete recovery-success benchmarks (91.4% ± 3.0%) and a multi-tier intervention taxonomy (bounded retry / controller mode switch / recovery capability / Human Override) that maps cleanly onto Tex's seven `InterventionKind`s. Used as numerical SOTA target for `RestorativePathExecutor.execute()`.

- **Survival-level finding (Section 5): The Microsoft Agent Governance Toolkit has NOT shipped an intervention/remediation engine.** AGT is "policy enforcement, zero-trust identity, execution sandboxing, reliability engineering" — pre-execution screening, not post-FORBID intervention selection. Microsoft Agentic Center of Enablement (Power Platform) ships a human-in-the-loop "Action Plan agent" but it's tenant-admin scope, not request-path. **Tex Step 8 wedge is open.**

- **Closest academic neighbors are AIR (arxiv 2602.11749, Feb 12 2026) and SafeAgent (arxiv 2604.17562, Apr 19 2026).** Both implement intervention loops, neither implements a bounded-compromise theorem with mathematical convergence guarantees. AIR's eradication-via-LLM-synthesized-guardrail-rules is a novel mechanism Tex does not have; **explicitly deferred to a future thread**, not in Thread 8 scope.

- **Section 1.4 ambiguity flagged:** `arxiv 2508.00500v3` is cited as both "ProbGuard" and "Pro2Guard." These are the same paper; v1/v2 used "Pro2Guard," v3 (Mar 27 2026) renamed to "ProbGuard." Citation harmonized below.

---

## 1. What's newer than Section 1.4 (May 14 → May 19, 2026 + back-sweep)

Filtered to arxiv 2603+ and 2604+ and 2605+ and vendor news after May 1, 2026.

### Intervention math and cost-bounded selection (the Thread 8 core)

- **arxiv 2512.18561 v3 (AAF, Alqithami, Mar 19 2026) — VERIFIED.** PDF fetched and §5.4 read in full. The actual theorem is:

  > **Theorem 5 (Bounded-Compromise).** If `λH ≥ g_max + ε` for some `ε > 0`, then `limsup_T (C_T / T) ≤ η*` a.s., where `η* = αH / (λH − g_max)`. Welfare shortfall `ΔJ_soc ≤ αH·Δ_max / (λH − g_max)`.

  Where `α` is false-alarm budget, `H` is intervention window length (paper uses H=25), `λ` is per-step penalty amplitude per culpable agent, `g_max` is adversary's max expected per-step gain, `Δ_max` bounds private rewards. Proposition 1: `λ_min = (g_max + αH) / (Hη*)`. **Section 1.4 simplified this to "cost > payoff iff long-run ratio < 1." The actual math is a ratio bound, not an iff. Building to the paper.**

- **arxiv 2507.15886 — Combining Cost-Constrained Runtime Monitors for AI Safety** (Hua, Baskerville, Lemoine, Hopman; NeurIPS 2025; v2 Oct 2025). Neyman-Pearson lemma applied to monitor-combination protocols under budget. "More than double recall rate compared to naive baseline in a code review setting; two monitors can Pareto dominate either alone." **Adjacent to Tex Step 8 but different surface:** this paper allocates *detection* under budget; Tex Step 8 allocates *intervention* after FORBID. Cited in module docstring as the principled monitor-combination reference; the design of `InterventionEngine.select()` could be extended in a future thread to do Neyman-Pearson-style allocation when *multiple* candidate interventions have different cost/coverage profiles. **For Thread 8, sticking with AAF's cost-min-under-bound semantics.**

### Intervention apply / remediation lifecycle (the `.apply()` and restorative-path surface)

- **arxiv 2602.11749 — AIR: Agent Incident Response** (Xiao, Sun, Chen; Tianjin U + SMU; Feb 12 2026). The first incident response framework for LLM agents. Four-phase NIST-style lifecycle: detect, contain, recover, eradicate. Detection rate >90%, remediation success >95%, eradication >95% across code/embodied/computer-use agents. **Novel mechanism: LLM-synthesized guardrail rules during eradication that get added to plan-level check set to block recurrence.** Tex has no equivalent `InterventionKind`. **DEFER:** adding `LLM_SYNTHESIZED_GUARDRAIL` as a new kind is its own thread (requires plan-level check infrastructure Tex doesn't have); Thread 8 ships the existing 7 kinds. Cited in module docstring as the proximal academic competitor and the source for the "detect → contain → recover → eradicate" terminology that the `Intervention.rationale` field will follow.

- **arxiv 2604.07833 v2 — Harnessing Embodied Agents: Runtime Governance for Policy-Constrained Execution** (Apr 10 2026). Three governance dimensions: unauthorized action interception, runtime violation detection, recovery/rollback. **Numerical SOTA for `RestorativePathExecutor`:**
  - 96.2% ± 2.7% interception rate for unauthorized actions
  - Unsafe continuation 100% → 22.2% ± 3.1% under runtime drift
  - 91.4% ± 3.0% recovery success rate with full policy compliance
  - Recovery Manager removal collapses success to 28.1%
  
  Intervention taxonomy: bounded retry, controller mode switching, recovery capability invocation, escalation to Human Override Interface, "Compliant Enforcement Fraction (CEF) = 1.0" — analogous to Tex's seven `InterventionKind`s. **Tex's existing kinds already span this taxonomy** (CAPABILITY_REVOKE = revoke recovery capability, HUMAN_APPROVAL_GATE = Human Override Interface, QUARANTINE = sandbox/rollback, etc.). No new kinds needed.

- **arxiv 2604.17562 — SafeAgent: A Runtime Protection Architecture for Agentic Systems** (Liu, Ilyushin, Ni, Zhu; Apr 19 2026). Stateful decision problem over interaction trajectories. Separates execution governance (runtime controller around the agent loop) from semantic risk reasoning (context-aware decision core with operators for **risk encoding, utility-cost evaluation, consequence modeling**). **Closest design-pattern neighbor to Tex Step 8.** Different in two ways: (1) no bounded-compromise theorem — relies on heuristic utility-cost, not analytical convergence guarantee; (2) prompt-injection-focused, not general norm-violation. **Cited as comparable architecture; Tex's wedge over SafeAgent is the AAF cost-bound theorem.**

- **arxiv 2605.04785 v1 — AgentTrust: Runtime Safety Evaluation and Interception for AI Agent Tool Use** (Chenglin Yang, May 6 2026, 13 days ago). Pre-execution structured verdict (allow / warn / block / review) with shell deobfuscation normalizer, SafeFix suggestions, RiskChain detection for multi-step attacks. **Pre-execution screening, not post-FORBID intervention selection.** Different surface from Step 8 (closer to Step 4/5 of Tex's pipeline).

### Restorative paths (the `RestorativePathExecutor` surface)

- **arxiv 2601.11369 (Bracale/Syrnikov et al., Jan 2026) re-verified.** §4.2 restorative paths and §6.2.2 sanction ladder remain the floor. Tex `src/tex/institutional/sanctions.py:RestorativePath` already mirrors this paper's three restoration kinds (expiry / credit_relief / clean_restoration). No design change.

- **No 2603–2605 paper extends restorative-path math beyond 2601.11369.** Searched specifically for "restorative governance multi agent 2604 2605" and similar; nothing newer surfaced. Tex's existing model is current.

### EU AI Act (the "auto-execute restorative path" config knob)

- **No EU AI Act revision affects Thread 8.** Article 50 second draft of Code of Practice (Mar 2026) remains floor; final June 2026. Article 26 deployer obligations (post-market monitoring) take effect Aug 2, 2026 — Tex's "async-execute the restorative path if configured" feature directly supports Article 26 monitoring + remediation but does not require a new draft revision. The HRAIS Annex III extension to Dec 2, 2027 (per Section 1.4) is unrelated to runtime intervention.

### Adjacent / informative-only (not cited in code)

- **arxiv 2603.16586 — Runtime Governance for AI Agents: Policies on Paths** (Kaptein 2026). Already wired by prior threads. Re-verified: still current.
- **arxiv 2604.24686 — RiskGate / Agent Viability Framework** (Apr 2026). Already wired as Thread 7.1 (P3 monotonic restriction). Thread 8's `BoundedCompromiseCalculator` respects but doesn't modify the viability floor.
- **arxiv 2508.00500 v3 (ProbGuard, renamed from Pro2Guard, Mar 27 2026).** PCTL property `P_{<θ}[F unsafe_state]`. 38.66s lookahead is for the *detection* layer; Tex Step 6 owns this. Thread 8 receives FORBID and acts. **The 38.66s lookahead is not Thread 8's responsibility — clarification only.**

---

## 2. What competitors shipped (May 1 — May 19, 2026)

### Microsoft Agent Governance Toolkit — active development through May 14, 2026

GitHub `microsoft/agent-governance-toolkit` has releases 5 days ago and 3 weeks ago. May 14, 2026 blog post "Governance at the Speed of Agents" pairs AGT with Microsoft Agent Framework 1.0. AGT description: **"runtime governance: deterministic policy enforcement, zero-trust identity, execution sandboxing, and reliability engineering."** 339+ adversarial tests added. Bootstrap integrity self-verification. Covers 10/10 OWASP Agentic Top 10 (now ASI 2026 taxonomy).

April 30, 2026: AGT shipped `McpSecurityScanner` — scans MCP tool definitions for prompt-injection indicators, returns `RiskScore`. **Pre-execution detection, not intervention selection.**

**Verdict for Thread 8: AGT has NOT shipped an intervention/remediation engine.** AGT blocks unsafe actions (FORBID equivalent) but does not select cost-minimizing interventions under a bounded-compromise constraint, does not execute restorative paths, does not emit ML-DSA-signed governance ledger records for the intervention itself. **Tex Step 8 wedge survives.**

### Microsoft Agent 365 — May 2026 update

Per techcommunity.microsoft.com May 2026 blog: Microsoft Defender provides "agent security posture management... prioritized security recommendations, risk context, attack path analysis." Microsoft Purview AI Observability in DSPM provides "unified visibility into all agents." **Posture management + recommendations + auditable hunting in Advanced Hunting** — not request-path runtime intervention.

### Microsoft Agentic Center of Enablement (Power Platform admin)

Three guardian agents: **Highlights, Insights, Action Plan**. Action Plan agent "converts insights into comprehensive remediation plans that you review and approve before execution. All agent activity is recorded for a complete audit trail." **Human-in-the-loop, tenant-admin scope, not request-path.** Closest in surface to Tex's HUMAN_APPROVAL_GATE intervention kind but operates at a different layer.

### Zenity, Noma, Pillar, HiddenLayer, Mindgard

No public May 2026 product update on cost-bounded intervention selection or restorative-path execution. Zenity's April 7 "AI Intent Detection" is detection-side. Same observation as Thread 7 brief.

### F5/CalypsoAI, CrowdStrike/Pangea, Palo Alto/Protect AI

AI-gateway layer. No intervention-engine equivalent.

### Survival summary

**No commercial product as of May 19, 2026 ships:**
1. Mathematical bounded-compromise guarantee (the AAF Theorem 5 wedge)
2. Cost-minimum intervention selection under analytical convergence bound (the `InterventionEngine.select()` wedge)
3. ML-DSA-signed governance ledger emission per intervention applied (the post-quantum audit-trail wedge)
4. Restorative-path execution tied to a Cournot-paper-grounded institutional state machine (the `RestorativePathExecutor` + Thread 2 governance graph wedge)

These four properties are conjunctively unique to Tex. Each one alone is found in academic work (AIR, SafeAgent, AAF sim, Embodied Agents prototype, 2601.11369 theory) but no published or shipping system composes all four.

---

## 3. Standards revised since May 14, 2026

None affect Thread 8.

- **IETF SCITT architecture draft-22** (Apr 2026) — Thread 8 emits to governance ledger via `tex.institutional.governance_log` which is downstream of SCITT envelope assembly; no change.
- **FIPS 204 (ML-DSA)** — already wired via `tex.pqcrypto.algorithm_agility`; Thread 8 routes through `select_institutional_signing_provider`.
- **C2PA 2.2 / 2.3** — content credentials; orthogonal to intervention layer.
- **EU AI Act Article 50 Code of Practice second draft** (Mar 2026) — transparency obligations; Thread 8 supports but doesn't depend on.
- **OWASP Agentic Security Initiative (ASI) 2026 taxonomy** — replaced original "Agentic Top 10" labels in March 2026. Tex CLAIMS.md may want to harmonize but Thread 8 itself doesn't reference ASI codes in code paths.

---

## 4. What this changes about the build plan

**Three substantive deltas from the prompt's "State of the art to match" section:**

### Δ1. Math correction in `BoundedCompromiseCalculator`

The prompt says "long-run compromise ratio < 1 iff expected intervention cost > expected adversary payoff." The actual AAF Theorem 5 is a **ratio bound**, not an iff:

```
η* = αH / (λH − g_max)
```

`long_run_compromise_ratio` returns `η*` (a number in (0, 1)), not a boolean. `satisfies_bound` checks `λH ≥ g_max + ε` (the **window-aggregated** penalty, not the per-step). `estimate_adversary_payoff` returns `g_max` — the *maximum* expected per-step adversary gain, which is what the theorem actually quantifies over.

**Concrete implementation changes vs. the scaffold signatures:**

- `satisfies_bound(*, proposed_intervention_cost_to_adversary, adversary_expected_payoff)` — the parameter naming is fine but the semantics need a window: this becomes `cost_to_adversary` interpreted as `λ · H` (window-aggregated), `adversary_expected_payoff` interpreted as `g_max` (per-step max). Document this clearly.
- `long_run_compromise_ratio(*, intervention_history, adversary_payoff_history)` — empirically estimates `α`, `H`, `λ̄`, `ĝ_max` from history tuples, returns η̂* as the empirical ratio bound. Also returns 1.0 if `λH ≤ g_max` (bound vacuous — system is not in the regime the theorem applies to). Document the vacuous case explicitly.
- `estimate_adversary_payoff(*, drift_signals)` — reads ABC drift D* and the institutional state's tracked g_max-by-actor map (if Thread 2's `institutional_states` is populated) to estimate the current `g_max`. Falls back to a configurable prior when drift signals are absent.

Add a `compute_minimum_penalty` method for Proposition 1 — operators querying "what's the smallest viable penalty to bound my long-run ratio at 0.1?" get a closed-form answer.

### Δ2. Intervention rationale follows AIR's four-phase vocabulary

The `Intervention.rationale` field (existing on `kinds.py:Intervention`) will be populated using the **AIR detect/contain/recover/eradicate** vocabulary even though Tex doesn't implement eradication's LLM rule-synthesis. Format:

```
"phase=contain action=trust_score_reduce reason=drift_delta=0.42 above threshold=0.3 actor=agent_X cost_to_system=0.05 cost_to_adversary=0.30 satisfies_bound=True"
```

This makes Tex's verdicts AIR-vocabulary-compatible at the rationale layer without depending on AIR or its DSL. **Future thread can layer AIR-style rule synthesis on top by adding `LLM_SYNTHESIZED_GUARDRAIL` as a new `InterventionKind`.** That work is explicitly out of scope for Thread 8 (needs plan-level check infrastructure Tex doesn't have).

### Δ3. Restorative-path executor targets the Embodied Agents numbers

`RestorativePathExecutor.execute()` returns `bool` per scaffold. **Tighten the contract:** return `True` only if (a) the manifest restorative path exists, (b) every restorative event in `restorative_event_kinds` was emitted to `governance_log` in declared order via ML-DSA-signed records, and (c) final actor `institutional_state` matches `target_legal_state_id`. Operators tracking the **recovery success rate** can target the arxiv 2604.07833 91.4% ± 3.0% number. (For initial implementation: this is mechanical, not statistical — every well-formed path call succeeds. Statistical recovery rates are a downstream metric.)

---

## 5. Numerical SOTA targets

| Property | Target | Source |
|---|---|---|
| Long-run compromise ratio | η* ≤ 0.5 at default (α=0.05, H=25, λ chosen by Prop. 1) | AAF Thm 5 |
| Welfare shortfall | ΔJ_soc ≤ αH·Δ_max/(λH−g_max) | AAF Thm 5 |
| Recovery success | mechanical 100% in unit tests; 91%+ aspiration in production | arxiv 2604.07833 |
| Detection delay (informative — owned by Step 6, not Step 8) | median 71 steps | AAF §7.3 |
| Intervention apply overhead p99 | < 10 ms per current EcosystemEngine budget | Tex engine.py:29 |
| Governance ledger record size | ≤ 40 B + ML-DSA-65 sig | AAF §4.2 + FIPS 204 |
| Test coverage on new modules | ≥ 90% (matches existing bar) | tex_build_master_prompt §3 |

---

## 6. Design decisions justified against the frontier

| Decision | Alternative considered | Why chosen |
|---|---|---|
| Implement AAF Theorem 5 ratio bound η* | Use SafeAgent (2604.17562) utility-cost heuristic | AAF provides analytical convergence guarantee; SafeAgent doesn't. Investors / cyber insurers value provable bounds over heuristics. |
| Use Tex's existing 7 `InterventionKind`s | Add `LLM_SYNTHESIZED_GUARDRAIL` from AIR (2602.11749) | AIR's mechanism requires plan-level check infrastructure Tex lacks. Adding it would expand Thread 8 scope by ~3×. Deferred as standalone thread. |
| Route ML-DSA signing through `tex.pqcrypto.algorithm_agility` | Direct ML-DSA-65 call | Section 3 hard constraint: algorithm agility. Also: NIST CNSA 2.0 may move to ML-DSA-87 by 2030; the abstraction protects against rework. |
| Fail-closed on cost calculator error (ABSTAIN, not PERMIT) | Default-permit on calculator exception | Section 3 hard constraint: no default PERMIT on error. |
| Intervention selection happens before ledger append (step 8 first, ledger second) | Append first, then add intervention metadata | If selection raises, the FORBID verdict goes out cleanly without polluting the ledger with a half-applied intervention. |
| `RestorativePathExecutor` is sync; "auto-execute restorative path" config knob is async | All-sync | Async lets restorative path replay happen off the request critical path while keeping the verdict on the wire. EU AI Act Article 26 monitoring is non-blocking. |
| Use ABC Drift Bounds Theorem D* (Thread 1 wired) to feed `estimate_adversary_payoff` | Hardcoded g_max prior | Thread 1 already produces this signal; using it makes Step 8's payoff estimate empirical, not nominal. |

---

## 7. Citations to include in module docstrings (verbatim)

- `bounded_compromise.py`: arxiv 2512.18561 v3 (AAF, Alqithami, Mar 19 2026), §5.4 Thm 5 + Prop 1; arxiv 2507.15886 (Hua et al., NeurIPS 2025) for Neyman-Pearson framing of cost-constrained allocation (informative); arxiv 2602.22302 (Bhardwaj ABC) for D* drift bound input.
- `engine.py` (the intervention engine, not ecosystem): arxiv 2512.18561 §4.4 three-tier playbook (responsibility heap → reward shape / policy patch / link throttle); arxiv 2602.11749 (AIR) for detect/contain/recover/eradicate vocabulary; arxiv 2604.07833v2 for intervention taxonomy; arxiv 2604.17562 (SafeAgent) as design-pattern neighbor; arxiv 2601.11369 §6.2.2 sanction ladder.
- `restorative.py`: arxiv 2601.11369 §4.2 (Bracale/Syrnikov, Jan 2026) three restoration kinds; arxiv 2604.07833v2 for recovery success benchmarks.

---

## 8. Out of scope (explicitly deferred)

These were considered and excluded from Thread 8 to keep the thread bounded:

1. **AIR-style LLM-synthesized eradication rules.** Requires plan-level check infrastructure. Future thread: `tex.intervention.eradication`.
2. **Neyman-Pearson multi-monitor selection** (Hua et al. 2507.15886). Tex Step 8 today picks among interventions, not among monitors. When the system grows multiple specialist intervention selectors, this becomes relevant.
3. **Probabilistic model checking for proactive intervention** (ProbGuard 2508.00500v3). Step 6/7 territory, not Step 8.
4. **Digital-twin counterfactual replay** of intervention effects. `tex.systemic.digital_twin` is its own scaffold; future Thread 10+.
5. **Inequality monitoring on intervention application** (AAF §7.3 compromise-vs-Gini Pareto). Out of scope for the calculator math; observability-only.

---

## 9. Pre-build checklist

- [x] FRONTIER_DELTA written.
- [ ] `BoundedCompromiseCalculator` implementation.
- [ ] `InterventionEngine.select()` + `.apply()` implementation.
- [ ] `RestorativePathExecutor.execute()` implementation.
- [ ] Wire into `EcosystemEngine.evaluate()` at `:796-798` and `_forbid()` at `:1101`.
- [ ] Unit tests on the three modules at ≥ 90% coverage.
- [ ] Integration test in `tests/test_integration_layer.py` covering FORBID-with-intervention.
- [ ] CLAIMS.md update.
- [ ] Demo curl script.
- [ ] Existing 1,881 tests still pass.
- [ ] Phase 3 sweep (last-14-days re-search) before commit.

---

## 10. Honest caveats

- **Search dependency on training-data cutoff.** My training data ends Jan 2026; everything May 2026 came from web_search results. Two arxiv URLs I tried to web_fetch hit rate limits or returned empty PDFs (2512.18561 PDF empty body on first try, succeeded second try; 2507.15886 PDF rate-limited but abstract verified via search snippet). Where I couldn't fetch the full body, I relied on multiple corroborating search snippets and stated so.
- **Section 1.4 anchor verification.** I verified AAF (2512.18561), 2601.11369, 2602.22302 (Bhardwaj ABC), 2604.24686 (RiskGate), 2603.16586 (Kaptein), 2604.07833 (Embodied), 2508.00500 (Pro2Guard/ProbGuard rename). These all resolved. I did not verify every arxiv ID in section 1.4 (e.g., 2603.18894, 2602.23701, 2604.23374) since they're not load-bearing for Thread 8.
- **The Hua et al. arxiv ID is 2507.15886 (July 2025), not a 2026 ID** as the standing-orders document might lead one to expect. NeurIPS 2025 paper, v2 Oct 2025. Still post-cutoff for the original section 1.4 list framing but pre-Jan-2026 for me. I'm including it because it's the principled framework on cost-constrained selection and is the closest math-side neighbor to Tex Step 8 even though older than the rest.
- **AIR self-describes as "the first work on incident response for AI agents, no direct baselines."** This is a strong claim. I have not independently audited their literature review to confirm no priors exist; I take it as their claim. For Tex's positioning, this is mildly useful — being adjacent to "the first" framework is a stronger reference than being adjacent to "one of many."

---

## 11. Phase 3 pre-completion sweep (May 19, 2026, end of build)

Three queries run at the end of build (per Section 2 Phase 3 of the standing orders):

1. **`bounded compromise intervention agent governance arxiv May 2026`** — no new papers since the brief. One adjacent paper found, **arxiv 2604.07778 ("The Accountability Horizon: An Impossibility Theorem for Governing Human-Agent Collectives")**, which is an impossibility result about accountability assignment in human-agent collectives. Different problem space from Thread 8 (cost-bounded intervention selection); informative-only.

2. **`agent governance toolkit remediation intervention engine release May 2026`** — important finding. The **Microsoft Agent Governance Toolkit DOES have a remediation surface** that I under-acknowledged in §2 of this brief. Per a March 26, 2026 Microsoft Medium post (Imran Siddique, "Securing AI agents with agent governance"): AGT ships an SLO-style **error budget** that drives automated remediation. When an agent's "safety SLI" drops below 99% (>1% policy violations), AGT can automatically trigger:
   - a **kill switch**,
   - a **downgrade of the agent's execution ring**, or
   - a **circuit breaker** that rejects new requests until recovery.

   **Honest re-assessment of the wedge:** the §2 claim "AGT stops at 'block unsafe action' without selecting from candidate interventions" was too strong. AGT has three threshold-triggered response actions. However:
   - AGT's mechanism is **reactive threshold logic** ("SLI dropped → trigger kill switch"). Tex Step 8 is **prescriptive math** ("select lowest-cost candidate λ s.t. λH ≥ g_max + ε, with provable η* ceiling").
   - AGT has no **analytical convergence guarantee** (no bounded-compromise theorem, no minimum-viable-penalty formula).
   - AGT does not **select among multiple candidate interventions by cost** — it has a fixed three-step escalation ladder.
   - AGT emits **deterministic policy enforcement** records; it does not emit a **CompromiseCertificate** with the math an underwriter can reconstruct offline.

   **Wedge survives but is narrower.** The right way to describe Tex's differentiation as of May 19, 2026 is: "AGT remediates via SLO-driven threshold escalation; Tex remediates via cost-minimum selection under an analytical bound, with the math cryptographically attested per intervention." That's still a real wedge — Microsoft's framing maps neatly onto SRE-style error budgets; Tex's framing maps onto the AAF Theorem 5 ratio bound and is closer to what insurance underwriters and NAIC examiners actually verify. But "AGT has no remediation surface at all" was incorrect. CLAIMS.md should reflect this.

3. **`AAF Adaptive Accountability Framework v4 follow-up paper 2026`** — no v4 or follow-up. AAF v3 (March 19, 2026) is still the canonical reference. The arxiv 2512.18561 v3 PDF remains the load-bearing source.

**Phase 3 verdict:** no build changes required. One honest correction needed in CLAIMS.md §"Why this matters" (the AGT-has-no-remediation claim is too strong — AGT has threshold-driven remediation; Tex's wedge is the analytical bound + cryptographic certificate). I'll fold this correction into the commit message and the CLAIMS update so future outreach is honest.


- **Search dependency on training-data cutoff.** My training data ends Jan 2026; everything May 2026 came from web_search results. Two arxiv URLs I tried to web_fetch hit rate limits or returned empty PDFs (2512.18561 PDF empty body on first try, succeeded second try; 2507.15886 PDF rate-limited but abstract verified via search snippet). Where I couldn't fetch the full body, I relied on multiple corroborating search snippets and stated so.
- **Section 1.4 anchor verification.** I verified AAF (2512.18561), 2601.11369, 2602.22302 (Bhardwaj ABC), 2604.24686 (RiskGate), 2603.16586 (Kaptein), 2604.07833 (Embodied), 2508.00500 (Pro2Guard/ProbGuard rename). These all resolved. I did not verify every arxiv ID in section 1.4 (e.g., 2603.18894, 2602.23701, 2604.23374) since they're not load-bearing for Thread 8.
- **The Hua et al. arxiv ID is 2507.15886 (July 2025), not a 2026 ID** as the standing-orders document might lead one to expect. NeurIPS 2025 paper, v2 Oct 2025. Still post-cutoff for the original section 1.4 list framing but pre-Jan-2026 for me. I'm including it because it's the principled framework on cost-constrained selection and is the closest math-side neighbor to Tex Step 8 even though older than the rest.
- **AIR self-describes as "the first work on incident response for AI agents, no direct baselines."** This is a strong claim. I have not independently audited their literature review to confirm no priors exist; I take it as their claim. For Tex's positioning, this is mildly useful — being adjacent to "the first" framework is a stronger reference than being adjacent to "one of many."

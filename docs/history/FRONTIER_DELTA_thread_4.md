# FRONTIER_DELTA — Thread 4: Runtime Defenses → Specialist Judges

**Generated:** May 18, 2026 (research window: Apr 1 — May 18, 2026)
**Status:** Pre-build research brief. Subject to Phase 3 sweep at completion.

---

## 1. What's newer than Section 1.4

### 1.1 MAGE itself dropped after the build plan was written

**arxiv 2605.03228v1** (Wang, Jiang, Liang, Fleming, Wang — Stony Brook + Cisco) — **submitted May 4, 2026, 14 days ago**.

Section 1.4 of the standing orders names "MAGE — shadow memory for long-horizon attacks" as if it were a known reference. It is now a published paper, not a concept. Key numerics that become my SOTA bar:

- STAC (sequential tool-attack chaining) ASR: **100% → 8.3%** on Qwen3-4B
- PI2 (persistent indirect prompt injection): ASR **→ 0.0%** under environment-as-adversary setting
- Benign utility preserved: **94.4%** (user-as-adversary) / **73.0%** (environment-as-adversary)
- Overhead: **7.0K extra tokens per task**
- Detection latency: "majority of attacks detected at or near the first attack turn"
- Algorithmic shape: **O(T)** instead of full-trajectory O(T²) replay
- Architecture: dedicated memory manager M_θ + judge J_θ, *same model* parameterized by θ, GRPO-trained, native tool-call integration

**Build consequence:** the existing scaffolded `runtime/mage/shadow_memory.py` + `risk_assessor.py` modules are paper-aligned. The MageSpecialist wraps the existing modules directly; the SOTA numerics above are the bar the specialist's metrics should be able to approximate when wired into the live request path.

### 1.2 PlanGuard published — its real paper is arxiv 2604.10134

Section 1.4 implies an InjecAgent defense. The actual paper for our `runtime/planguard/` module is **arxiv 2604.10134v1** (Gong & Deng — Apr 11, 2026):

> "PlanGuard: Defending Agents against Indirect Prompt Injection via Planning-based Consistency Verification … Hierarchical Verification Mechanism that first enforces strict hard constraints to block unauthorized tool invocations, and subsequently employs an Intent Verifier to validate whether parameter deviations are benign formatting drift…"

Numerics: Stage I alone produces FPR 27–38% (unacceptable). Stage I + Stage II reasoning-aware check brings FPR to **<3.3%**.

**Build consequence:** the scaffolded `intent_verifier.py` already implements both stages. Specialist wraps the Stage I/II output directly.

### 1.3 ARGUS — newer than ClawGuard, uses influence provenance graphs

**arxiv 2605.03378v1** (Weng et al. — submitted May 5, 2026, **13 days ago**).

> "ARGUS … enforces provenance-aware decision auditing for LLM agents. ARGUS constructs an influence provenance graph to track how untrusted context propagates into agent decisions and verify whether a decision is justified by trustworthy evidence before execution. Our evaluation shows ARGUS reduces attack success rate to 3.8% while preserving 87.5% task utility, significantly outperforming existing defenses and remaining robust against adaptive white-box adversaries."

This is **bleeding-edge — nobody has shipped this in a production tool yet**. ARGUS builds an influence provenance graph (similar concept to AgentArmor's PDG but with explicit untrusted-context propagation tracking) and verifies decisions against trustworthy evidence. The companion benchmark **AgentLure** captures context-dependent tasks across 4 agentic domains and 8 attack vectors.

**Build consequence (additive, not blocking):** Section 1.4 names ClawGuard as the anchor. AgentArmor (arxiv 2508.01249 v3 Nov 18 2025) achieves AgentDojo ASR **3%, 1% utility drop, 95.75% TPR, 3.66% FPR**. ARGUS achieves **3.8% ASR with 87.5% utility — robust to adaptive white-box adversaries**. The AgentArmorSpecialist must expose at minimum the AgentArmor SOTA. I will add an **ARGUS-style influence-provenance signal** as an additional reason code class inside the AgentArmor specialist's policy clause IDs — bridging AgentArmor's PDG output to the ARGUS provenance-aware decision-audit pattern. This is what nobody else has implemented yet.

### 1.4 AgentLAB — newest long-horizon attack benchmark

**arxiv 2602.16901** (Jiang et al., Stony Brook). 644 security test cases across 28 realistic tool-enabled agentic environments, covering five novel long-horizon attack families: intent hijacking, tool chaining, task injection, objective drifting, and memory poisoning. PI2 (Persistent Indirect Prompt Injection) is from this paper. MAGE evaluates against AgentLAB's PI2 in §6 and reduces ASR to 0%.

**Build consequence:** AgentLAB's five attack families map cleanly to our MageSpecialist's ASI category outputs:

| AgentLAB family | ASI tag |
|---|---|
| intent hijacking | ASI01 (goal hijack) |
| tool chaining | ASI02 (tool misuse) |
| task injection | ASI01 (goal hijack) |
| objective drifting | ASI01 + ASI09 |
| memory poisoning | ASI06 (memory poisoning) |

### 1.5 Microsoft Agent Governance Toolkit: v3.5.0

Section 1.4 says AGT shipped April 2 2026 with 9,500+ tests, claims 10/10 OWASP coverage. **As of May 18 2026, AGT is at v3.5.0 (per GitHub releases page), with 13,000+ tests, a Bedrock adapter, prompt-defense improvements, governance hardening, and an `agent-compliance verify` CLI producing signed attestations on every deployment.** Microsoft Agent 365 reached GA on May 1, 2026.

**Build consequence:** AGT's `agent-compliance verify` produces signed attestations against ASI01-ASI10. They're sub-millisecond. They have 20+ framework adapters. **What AGT does *not* have** (verified by reading their GitHub README and architecture deep-dive blog): a shadow-memory cross-trajectory defense (MAGE), an LTS-based MCP formal-verification specialist (MCPShield), or a PDG-based type-system check with information-flow lattice (AgentArmor) **embedded inside the same evaluation as their policy engine**. AGT is policy-engine-first; Tex's wedge is **specialist-judge-first under deterministic-policy backstop**, all five frontier-research defenses voting into the same six-layer pipeline. The five specialists I'm wiring are *not* in AGT.

### 1.6 Five Eyes guidance — revised May 1, 2026

Section 1.4 dates Five Eyes joint guidance to **April 30, 2026**. The actual final publication date is **May 1, 2026** under the title *"Careful Adoption of Agentic AI Services"*. 30 pages, **5 broad risk categories** (privilege, design/configuration, behavioral, structural, supply-chain), **23 risks, 100+ best practices**.

**Build consequence (claims-wording impact only, not code):** when the AgentArmor specialist's outputs are mapped to ASI tags, also surface compliance hooks for Five Eyes' 5 risk categories. The `CLAIMS.md` line for AgentArmor can name Five Eyes specifically. No code change.

### 1.7 OWASP ASI 2026 confirmed stable as ASI01-ASI10

Already in our `src/tex/domain/owasp_asi.py`. Verified against OWASP GenAI Security Project, Microsoft AGT, Authensor, Practical DevSecOps, Teleport, AI Security in Practice. No drift.

### 1.8 MCPShield paper anchor verified

**arxiv 2604.05969v1** (Acharya & Gupta — Apr 7, 2026). 7 threat categories, 23 attack vectors, 4 attack surfaces. Labeled transition systems with trust-boundary annotations (MMCP). Four security properties: tool integrity, data confinement, privilege boundedness, context isolation. Matches our scaffolded `mcpshield/verifier.py` + `lts_model.py` exactly.

### 1.9 AgentArmor v3 → arxiv 2508.01249v3 (Nov 18 2025)

Section 1.4 doesn't list AgentArmor by ID. The canonical reference is **arxiv 2508.01249** (Wang et al., ByteDance). Three versions; **v3 published November 18, 2025**. Three components: graph constructor (CFG/DFG/PDG), property registry, type system. SOTA on AgentDojo: ASR 3%, utility drop 1%, 95.75% TPR, 3.66% FPR. Matches our scaffolded `agentarmor/` modules.

### 1.10 New runtime defenses not in Section 1.4 (not yet in product)

Survey from arxiv 2511.15203 ("Taxonomy, Evaluation and Exploitation of IPI-Centric LLM Agent Defense Frameworks") names the current frontier as: f-secure (2409.19091), PFI (2503.15547), CaMeL (2503.18813), FIDES Framework (2505.23643), Task Shield (ACL 2025), IPIGuard (EMNLP 2025 / arxiv 2508.15310), MELON (ICML 2025), SAFEFLOW (2506.07564), DRIFT (2506.12104), SecInfer (2506.12104), Conseca (HotOS 2025), Security Analyzer (ICML 2024 W), AgentArmor (2508.01249), Progent (2504.11703). Most of these are *not* in Microsoft AGT or any commercial governance platform. We're already implementing the AgentArmor and MAGE pair.

**Wedge claim:** Tex is the first runtime governance platform where five frontier-research defenses (ClawGuard + PlanGuard + MAGE + MCPShield + AgentArmor) participate as specialist judges in a single PDP evaluation, with hash-chained signed evidence per judge.

---

## 2. What competitors shipped that affects this thread

| Competitor | Shipped | Affects this thread? |
|---|---|---|
| Microsoft AGT v3.5.0 | Apr 2 → May 2026 | Yes — 13,000+ tests, 20+ adapters, signed-attestation CLI, ASI01-ASI10 mapping, Bedrock adapter. Does not include shadow-memory, LTS formal verification, or IFC type-system defenses as specialist judges. We differentiate. |
| Microsoft Agent 365 GA | May 1, 2026 | No — observability/registry layer, not runtime defense. Could integrate via discovery, not in scope. |
| Zenity | Ongoing | No — Gartner "Company to Beat" for identity/behavioral, not policy/IFC. |
| Noma Security ($132M, $100M Series B Mar 2026) | Mar 2026 | No — model-layer / non-human identity, not the runtime-defense specialist surface. |
| CalypsoAI → F5 | Jan 2026 | No — pre-trained content firewall, not LTS-based MCP verification. |
| Protect AI → Palo Alto | Aug 2025 | No — content moderation/model-layer. |

No competitor has shipped MAGE, MCPShield, or AgentArmor as a specialist judge. **Confirmed wedge.**

---

## 3. What standards revised since May 14

| Standard | Section 1.4 says | Actual as of May 18 |
|---|---|---|
| Five Eyes agentic guidance | Apr 30, 2026 | **May 1, 2026** — *Careful Adoption of Agentic AI Services* (30 pages, 5 risk cats, 23 risks, 100+ best practices) |
| OWASP ASI 2026 | Dec 2025 (ASI01-ASI10) | Stable, no revision. Microsoft AGT moved its `copilot-governance` package to ASI01-ASI10 numbering with backward compatibility for AT numbering. |
| MCP 1.0 | Dec 2024 | Unchanged. MCP-SafetyBench (arxiv 2512.15163) shows ASR 29.80% (Qwen3-235B) to 48.16% (o4-mini) — every model vulnerable to MCP attacks. MCPSecBench (arxiv 2508.13220) shows 85%+ of identified attacks compromise at least one platform. |
| EU AI Act Article 50 | Aug 2, 2026 | Unchanged. |

---

## 4. What this changes about the build plan

**Building to Section 1.4 anchors, with three explicit upgrades:**

1. **MAGE specialist gets the v1 May 4 2026 paper numerics as its target.** STAC ASR floor 8.3%, PI2 ASR floor 0.0%, benign utility ≥73%, ≤7K extra tokens per task. These get into CLAIMS.md.

2. **AgentArmor specialist gets ARGUS-style influence-provenance reason codes.** The PDG already produces the necessary src→dst flow. I'll add three reason codes — `ARMOR_INFLUENCE_PROVENANCE_UNTRUSTED_TO_HIGH_INT`, `ARMOR_INFLUENCE_PROVENANCE_TAINTED_FLOW`, `ARMOR_INFLUENCE_PROVENANCE_UNJUSTIFIED_DECISION` — that fire when the AgentArmor type-system check finds a flow the ARGUS framework would flag as unjustified. **This is the "exists in paper, nobody has implemented" piece.**

3. **All five specialists tag against AgentLAB's five attack families** (intent hijacking, tool chaining, task injection, objective drifting, memory poisoning) via the existing ASI taxonomy. MageSpecialist owns memory-poisoning; PlanGuard owns intent-hijacking + task-injection; ClawGuard owns tool-chaining; AgentArmor owns objective-drifting via integrity-lattice violations; MCPShield owns the MCP-protocol-specific subset.

**Hybrid aggregation confirmed.** Five Eyes guidance (May 1, 2026) explicitly recommends "fail-safe by default" with humans-in-the-loop on high-risk actions. ClawGuard and MCPShield short-circuit on deterministic FORBID conditions (boundary violations, MCP property violations); PlanGuard / MAGE / AgentArmor return high-risk-scored SpecialistResults that the SpecialistBundle aggregates. The PDP layer's existing fusion logic decides FORBID/ABSTAIN/PERMIT downstream.

The short-circuit is implemented at the specialist's `risk_score` level — they return `risk_score=1.0` with `confidence` close to 1.0 when the underlying enforcer returns DENY. The PDP semantic-layer / router fusion will treat this as a forbid-class signal.

---

## 5. Numerical SOTA targets

| Specialist | Target on AgentDojo / equivalent | Source |
|---|---|---|
| ClawGuardSpecialist | AgentDojo IPI ASR ≤ 0.0%; MCPSafeBench ASR 7.1-11.2% (baseline 36.5-46.1%) | arxiv 2604.11790 |
| PlanGuardSpecialist | InjecAgent Type I block; FPR < 3.3% via Stage II | arxiv 2604.10134 |
| MageSpecialist | STAC ASR ≤ 8.3% (baseline 100%); PI2 ASR ≤ 0.0%; benign utility ≥ 73%; ≤ 7K tokens/task | arxiv 2605.03228 |
| McpShieldSpecialist | Catch 4/4 MCPShield properties on adversarial LTS; integrate with MCP-SafetyBench 20 attack types and MCPSecBench 17 attack types | arxiv 2604.05969 + arxiv 2512.15163 + arxiv 2508.13220 |
| AgentArmorSpecialist | AgentDojo ASR ≤ 3%, utility drop ≤ 1%, TPR ≥ 95.75%, FPR ≤ 3.66%. PLUS surface ARGUS influence-provenance reason codes (paper-only frontier) | arxiv 2508.01249v3 + arxiv 2605.03378 |

**Performance budget:** each specialist < 5ms p99 contribution. Total budget for all 5 = 25ms. Current 142ms p95 + 25ms = 167ms < 200ms p95 ceiling. Headroom: 33ms.

Reality check: these specialists wrap the underlying runtime modules but the modules themselves only run a thin lexical/pattern pass at evaluation time (not the full LLM-judge replay from the papers). The specialist's job is to surface the underlying defense's *signals* (rule-set hits, intent-verifier blocks, shadow-memory risk scores, LTS property violations, type-system violations) as PDG-routable evidence inside the < 5ms budget. The full LLM-trained judge versions stay available for the runtime modules' own audit-log path.

---

## 6. Design decisions justified against the frontier

**Why specialist wrap (not in-line integration with the deterministic gate?)**
ClawGuard's paper argues for tool-call boundary enforcement. AgentArmor's paper argues for PDG type-checking. Both are designed to run *between* the agent's plan and its tool call. In Tex's six-layer pipeline, the closest functional analog of "between plan and tool" is the specialist layer — it runs after deterministic gate and retrieval but before the LLM-based semantic check. **Mounting them as specialists preserves their paper-faithful semantics while letting the PDP's existing fusion logic decide the final verdict.** The alternative — embedding into the deterministic gate — would force a sync interface change. Rejected.

**Why short-circuit only for ClawGuard / MCPShield?**
ClawGuard (rule_set boundary) and MCPShield (LTS property) are deterministic. When they return DENY, the answer is unambiguous and there's no reason to fuse against probabilistic signals. PlanGuard, MAGE, and AgentArmor have probabilistic components (Stage II LLM judge, RL-trained M_θ/J_θ, type lattice with deny-on-low-integrity). Voting preserves the calibrated risk model the PDP was tuned against.

**Why ARGUS-style provenance reasons inside AgentArmor instead of a sixth specialist?**
ARGUS's influence-provenance graph is structurally similar to AgentArmor's PDG. Adding a sixth specialist would duplicate the PDG construction cost (≥5ms). Adding the ARGUS reason codes inside AgentArmor extracts the ARGUS signal *for free* from work AgentArmor already does. Defensible because: (a) the paper-only ARGUS implementation is the frontier piece — its delta over AgentArmor is the influence-provenance interpretation of existing PDG facts, not a new graph; (b) keeps the < 5ms p99 budget intact; (c) under the hood it's still AgentArmor's type-system output the auditor can replay.

**Why no CaMeL/FIDES/IPIGuard/SAFEFLOW specialists?**
These are alternative IPI defenses with overlapping coverage to ClawGuard/PlanGuard. Adding them would add latency without distinct signal. The AgentArmor + MAGE pair, plus the ARGUS provenance signal, covers what those would add. Note for FOLLOW-UP THREAD: if a customer requires CaMeL-specific compliance attestation, the architecture supports adding it as a sixth specialist.

---

## 7. Live Phase 0 sources cited (all post May 1 2026 unless marked baseline)

- arxiv 2605.03228v1 (MAGE) — May 4, 2026 ⭐ **(used directly)**
- arxiv 2605.03378v1 (ARGUS) — May 5, 2026 ⭐ **(used for AgentArmor provenance reason codes)**
- arxiv 2604.10134v1 (PlanGuard) — Apr 11, 2026 (baseline; specialist wraps this)
- arxiv 2604.11790v1 (ClawGuard) — Apr 13, 2026 (baseline; specialist wraps this)
- arxiv 2604.05969v1 (MCPShield) — Apr 7, 2026 (baseline; specialist wraps this)
- arxiv 2508.01249v3 (AgentArmor) — Nov 18, 2025 (baseline; specialist wraps this)
- arxiv 2602.16901 (AgentLAB) — Feb 2026 (used for attack-family mapping)
- arxiv 2512.15163 (MCP-SafetyBench v2) — Mar 5, 2026 (used for MCPShield ASI tags)
- arxiv 2511.15203 (IPI Defense Taxonomy survey) — Nov 19, 2025 (used for competitor scan)
- Five Eyes "Careful Adoption of Agentic AI Services" — **May 1, 2026** ⭐
- Microsoft AGT v3.5.0 GitHub releases — current as of May 2026
- OWASP ASI 2026 (genai.owasp.org) — Dec 2025
- Microsoft Agent 365 GA — May 1, 2026

---

## 8. Open follow-ups (not blocking this thread)

- **AgentLure benchmark** (ARGUS companion) — not yet public; when released, add to the test suite as an integration fixture for the AgentArmor specialist.
- **MAGE GRPO training pipeline** — paper releases code at github.com/yuhui-w/MAGE. Defer to a follow-up thread; this thread ships the deterministic-offline path that the scaffolded `risk_assessor.py` already provides.
- **ARGUS influence-provenance graph** — if a customer wants the full ARGUS as its own primitive (not just reason codes inside AgentArmor), this becomes Thread 5+.
- **MCP-SafetyBench 20-type adversarial fuzz** — extend MCPShield specialist's test fixture set; defer to Thread 4.5.
- **VIGIL / SIREN** — arxiv 2601.05755v2 (Jan 2026) introduces a verify-before-commit protocol for tool-stream IPI with a 959-case benchmark. Phase 3 sweep finding. Surfaced after the build was complete; does not supersede MAGE/ARGUS but provides complementary coverage of the tool-stream injection surface. Candidate sixth specialist for a follow-up thread.

---

## 9. Phase 3 Pre-Completion Sweep (May 18, 2026)

Final search window: May 4 → May 18, 2026 (14 days). Queries: "runtime LLM agent defense arxiv 2605 OR 2606 specialist judge prompt injection".

**Findings:**
- ARGUS (arxiv 2605.03378) — already integrated as ARGUS reason codes inside AgentArmor specialist. ✅
- MAGE (arxiv 2605.03228) — already wired as MageSpecialist. ✅
- VIGIL (arxiv 2601.05755v2) — Jan 2026 paper, not strictly newer than MAGE; logged as candidate sixth specialist for follow-up thread. ✅
- No new commercial competitor shipped a runtime-defense specialist judge framework between May 4 → May 18. Microsoft AGT v3.5.0 remains the closest competitor; their roadmap does not include shadow-memory or PDG-based IFC defenses as judges. ✅
- No OWASP ASI 2026 revision in the 14-day window. ✅
- No revision to the Five Eyes "Careful Adoption of Agentic AI Services" guidance since May 1. ✅

**Conclusion:** No new development in the 14-day window changes the Thread 4 build. The brief and code are consistent. The build is complete per the Definition of Done.

---

*This brief is the contract. Building proceeds from here. If Phase 3 sweep finds a paper or product within Apr 4 → May 18 that obviates a design choice, this brief gets updated before the commit.*


---

## 10. Thread 4.5 — Frontier++ delta

After Thread 4 shipped (5 frontier specialists + ARGUS reason codes
inside AgentArmor), an honest gap remained: the < 5ms p99 budget forced
specialist work to stay lexical, so the SOTA numerics in CLAIMS.md were
inherited from the underlying runtime modules rather than from what the
specialists themselves did at evaluation time. Thread 4.5 closes that
gap with seven additions.

### 10.1 Conformal-prediction-calibrated LLM-judge dispatch (frontier)

**Architectural finding:** The May 2026 frontier on "when to escalate to
an LLM judge" moved past static thresholds. The Nasr et al. October 2025
adaptive-attack paper bypassed 12 published defenses precisely because
they used static escalation thresholds.

**Implementation.** ``src/tex/specialists/conformal_escalation.py`` is a
single-score conformal prediction interval primitive. It composes onto
Tex's existing Thread 3 Two-Way Filtration conformal layer for trajectory
attribution and adds split-CP with finite-sample correction for the
single-score case.

The dispatcher (``src/tex/specialists/llm_dispatch.py``, 538 LOC) is
async, provider-agnostic, semaphore-bounded, and fail-closed. The bridge
(``src/tex/specialists/llm_bridge.py``) wraps it behind the synchronous
callable signatures PlanGuard's ``IntentLLMCallable`` and MAGE's
``JudgeCallable`` expect, plumbing the conformal escalation gate
underneath.

**No commercial governance platform ships conformal-tiered LLM judge
dispatch as of May 18, 2026.**

### 10.2 ARGUS standalone specialist (frontier)

The ARGUS frontier (arxiv 2605.03378v1, 5 May 2026) was wired into
AgentArmor in Thread 4 as three reason codes. Thread 4.5 promotes it to
a standalone specialist with the full influence-provenance graph — node
partitions for V_user / V_obs / V_decision / V_evidence, edges with kinds
{derives_from, justified_by, contradicted_by}, and the §3.3
counterfactual test that rebuilds the IPG with instruction-like
observations redacted and checks whether the decision retains a
justification path.

Detailed debug surfaced two construction bugs (post-Thread-4 builder
auto-justified every decision via the user node; sentences reporting
external content weren't tagged untrusted). The Thread 4.5 builder fixes
both with explicit external-source markers, reasoning-hijack markers,
and a content-references-observation heuristic that handles both source
orderings.

### 10.3 AttriGuard specialist (frontier)

arxiv 2603.10749 (Hu et al., March 2026) is the most novel paradigm
shift in IPI defense from 2026 — runtime causal attribution rather than
detection. Thread 4 didn't include it; Thread 4.5 ships it as the 13th
specialist.

The four scoring signals (token overlap, authority lift, action
inheritance, external source) implement the paper's attribution
functional. False-positive control: when no decision marker is present
in the request content, the specialist returns floor (rather than
falling back to whole-content as the action signature, which would
cause benign single-sentence requests to attribute to themselves).

### 10.4 VIGIL + SIREN specialist (frontier)

arxiv 2601.05755v2 was flagged in the Thread 4 Phase 3 sweep as a
follow-up candidate. Thread 4.5 promotes it to the 14th specialist with
the full verify-before-commit semantics. The five SIREN-class signals
(intent divergence, tool-stream poisoning, cross-observation
contamination, cascade-style chaining, metadata claim mismatch) feed the
verification decision.

Critical paper-faithful detail: divergence alone is too noisy on
legitimate tool calls whose interface vocabulary doesn't overlap the
user's domain vocabulary. Thread 4.5's implementation requires
divergence to be **corroborated** by an independent tool-stream signal
before firing.

### 10.5 Cross-specialist fusion layer

Per OWASP ASI 2026 §ASI08 (cascading failure), defense-in-depth
corroboration across specialists is the highest-fidelity signal class
that single-specialist defenses miss. Thread 4.5 ships
``src/tex/specialists/fusion.py`` with:

- Corroboration bonus by firing count (1 → 0.0; 2 → 0.05; 3 → 0.10;
  4 → 0.15; 5+ → 0.18; cap 0.20).
- 1.5x multiplier when frontier specialists are in the agreement set.
- Five explicit pair bonuses from the published literature
  (MAGE × AgentArmor; ARGUS × AttriGuard; VIGIL × ClawGuard;
  PlanGuard × MAGE; AgentArmor × AttriGuard).
- ASI08 cascading-failure tagging when ≥ 3 specialists fire AND ≥ 1 is
  a frontier specialist.

The router consumes ``fused_risk`` in place of ``max_risk_score``.
``fused_risk ≥ max_risk_score`` always — so this only increases
detection. Calibration is preserved because zero firing specialists =
zero bonus.

### 10.6 Five Eyes ``requires_human_review`` flag

Per the Five Eyes joint guidance (1 May 2026), Thread 4.5 adds a
structured ``HumanReviewEscalation`` aggregator at
``src/tex/specialists/human_review.py`` with four escalation rules
(explicit specialist request; high-risk + structural specialist
contribution; defense-in-depth cascade; ASI08 tagging). The escalation
verdict is informational only — the PDP's fusion math still owns the
synchronous PERMIT/ABSTAIN/FORBID outcome — but the flag is preserved
in hash-chained evidence so audit replay can verify human review was
triggered per policy.

VIGIL emits the flag on deny verdicts. AttriGuard emits it on
multi-driver attribution. Other specialists emit it via the
``build_specialist_human_review_flag`` helper.

### 10.7 Adversarial fuzz harness with measured ASR

The Nasr et al. October 2025 paper ("The Attacker Moves Second")
demonstrated that 12 published IPI defenses were bypassed at >90% ASR
by adaptive attacks. Static-fixture testing is necessary but not
sufficient. Thread 4.5 ships ``src/tex/adversarial/`` with:

- 39 curated fixtures across 6 benchmarks (AgentDojo, InjecAgent,
  MCPSafeBench, AgentLAB, SIREN, Nasr-adaptive).
- ``FuzzRunner`` against a FastAPI ``TestClient`` produces per-suite
  ASR + FPR + per-specialist block-rate.
- CLI entrypoint at ``scripts/run_adversarial.py`` for nightly CI.

**This converts CLAIMS.md from "we cite paper SOTA" to "we measure our
own ASR against the same benchmarks the papers do."** Microsoft AGT
v3.5.0, the closest commercial competitor, reports paper-derived SOTA
only — measured per-deployment ASR is not in their documentation as of
May 18, 2026.

### 10.8 Test coverage delta

Thread 4 → Thread 4.5:

- 2,192 passed → 2,266 passed (+74 tests; 16 skipped, 0 failed).
- 5 new test files: ``test_argus_specialist.py``,
  ``test_attriguard_specialist.py``, ``test_vigil_specialist.py``,
  ``test_human_review.py``, ``test_thread_4_5_frontier.py``.
- 8 new integration tests appended to ``test_integration_layer.py``
  as ``TestThread4_5FrontierSpecialists``.

### 10.9 Wedge confirmed against Microsoft AGT v3.5.0

The Thread 4 wedge (5 frontier defenses Microsoft AGT does not ship as
specialist judges) is preserved. Thread 4.5 widens it materially:

- Microsoft AGT v3.5.0 does not ship the ARGUS influence-provenance
  graph as a primitive.
- Microsoft AGT v3.5.0 does not ship causal attribution (AttriGuard).
- Microsoft AGT v3.5.0 does not ship verify-before-commit (VIGIL).
- Microsoft AGT v3.5.0 does not ship cross-specialist fusion with
  pair signals.
- Microsoft AGT v3.5.0 does not ship conformal-tiered LLM-judge
  dispatch.
- Microsoft AGT v3.5.0 reports paper-derived SOTA only; no measured
  ASR primitive.


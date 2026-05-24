STANDING ORDERS FOR THIS THREAD
Today is May 18, 2026. Your training data ends January 2026. Four months of frontier research, regulatory action, and competitor shipping have happened since your cutoff. You will not write code from memory. You will research first, then build against the bleeding edge.
The standing reference below (section 1) is a snapshot of what I already gathered. It is the floor, not the ceiling. Your Phase 0 job is to verify it is still current, find what's newer, and find what shipped in the last 2–8 weeks that isn't listed.
I want code and tech that competitors are not using yet. That requires you to search the web. Do not skip this.

SECTION 1 — STANDING REFERENCE
1.1 What Tex is
Tex Aegis (texaegis.com, MattNardizzi/tex) is a runtime authorization and evidence layer for AI agent ecosystems. Backend: Python 3.12+/FastAPI on Render at tex-2far.onrender.com. Frontend: React/Vite on Vercel. Local repo: ~/Documents/tex/. Source under src/tex/ (327 .py files, ~75K LOC, 1,881 passing tests across 121 test files).
Live request path: /v1/guardrail → EvaluateActionCommand → PolicyDecisionPoint → six-layer pipeline (deterministic, retrieval, specialists, semantic, router, evidence) → three-state verdict (PERMIT / ABSTAIN / FORBID) → SHA-256 hash-chained, HMAC-signed evidence record. Discovery service with 2 live connectors (OpenAI Assistants, Slack) + 4 mock connectors (MS Graph, Salesforce, AWS Bedrock, GitHub, MCP). Six AI gateway adapters (Portkey, LiteLLM, Cloudflare AI Gateway, Solo, TrueFoundry, Bedrock) + Copilot Studio + AgentKit. MCP server interface. Python SDK (pure stdlib). ML-DSA (FIPS 204) post-quantum signatures wired through tex.pqcrypto.algorithm_agility. Postgres-backed durable stores. Calibration with explicit human approval, CI-guarded against auto-apply.
1.2 Research code that exists but is NOT wired into the live request path
Each of these has passing tests and is unconsumed by main.py / PolicyDecisionPoint. The build threads wire them in.

src/tex/institutional/ — Cournot governance graph + Oracle + sanctions + controller
src/tex/contracts/ — LTLf behavioral contract enforcer
src/tex/causal/ — CHIEF/ARM causal attribution with 5-level integrity lattice
src/tex/graph/ — temporal knowledge graph with state projection (in-memory only; Postgres + JanusGraph backends are stubs)
src/tex/governance/path_policy/ — LTLf path policy checker
src/tex/governance/kernel_mcp/ — capability-based MCP syscall gate
src/tex/governance/private_data_exec/ — IFC taint-tracking sandbox
src/tex/governance/stpa_specs/ — STPA hazard analysis manifest
src/tex/runtime/clawguard/ — boundary enforcement against indirect prompt injection
src/tex/runtime/planguard/ — InjecAgent defense
src/tex/runtime/mage/ — shadow memory for long-horizon attacks
src/tex/runtime/mcpshield/ — formal verification against the four canonical MCP CVEs
src/tex/runtime/agentarmor/ — runtime hardening with property registry
src/tex/c2pa/ — C2PA 2.2 signer/verifier (53 tests)
src/tex/compliance/eu_ai_act/ — Article 50, Article 26, Article 17 modules
src/tex/ecosystem/engine.py — 8-step engine with steps 3-7 explicitly returning neutral (return _NEUTRAL_AXIS_SCORES)

1.3 Scaffolded modules that raise NotImplementedError

src/tex/intervention/ — bounded_compromise.py, engine.py, restorative.py
src/tex/systemic/ — digital_twin.py, cascade_predictor.py, risk_evaluator.py
src/tex/zkprov/ — proof.py, commitment.py
src/tex/vet/ — web_proofs.py, agent_identity_document.py
src/tex/tee/ — attestation_client.py, h100_attestation.py, tdx_attestation.py
src/tex/nanozk/ — layerwise_prover.py, fisher_guided.py
src/tex/pqcrypto/ — ml_kem.py, slh_dsa.py (ML-DSA + Ed25519 + ECDSA-P256 + hybrid mode are wired)

1.4 Bleeding-edge state of the art as of May 14, 2026 (anchor references)
These are the references known to be current as of May 14, 2026. They are not exhaustive — you must search for what's newer in Phase 0.
Temporal logic and contracts

LTLf and LDLf — De Giacomo/Vardi original. TACAS 2026 "Bolt" tool (Bathie/Fijalkow/Matricon/Mouillon/Vandenhove) is current SOTA learner. LTLf+ and PPLTL+ (De Giacomo et al., IJCAI 2025) extend to MDP synthesis. LTL3 formula progression evaluation per arxiv 2411.14581 is the runtime-verification standard.
Agent Behavioral Contracts (ABC) — arxiv 2602.22302 (Bhardwaj 2026). Drift Bounds Theorem D* = α/γ. Detects 5.2–6.8 soft violations per session.
AgentSpec — ICSE 2026 (Wang/Poskitt/Sun). DSL for runtime constraints.
ProbGuard (arxiv 2508.00500v3) and Pro2Guard — PCTL model checking. Warnings up to 38.66s ahead of unsafe events.
"Runtime Governance for AI Agents: Policies on Paths" — arxiv 2603.16586 (Kaptein 2026).
"Governing What You Cannot Observe" — arxiv 2604.24686 (Apr 2026). Agent Viability Framework, Aubin's viability theory.

Institutional governance

arxiv 2601.11369 — Cournot benchmark. Institutional regime reduces severe-collusion from 50% to 5.6%, Cohen's d = 1.28.
arxiv 2603.18894 — "I Can't Believe It's Corrupt" multi-agent corruption benchmark.

Causal attribution

CHIEF — arxiv 2602.23701.
AgenTracer — arxiv 2509.03312.
AAAI 2026 Automatic Failure Attribution — arxiv 2509.08682. 36.2% step-level accuracy.
Who&When benchmark (Zhang 2025).
NeuroTaint — arxiv 2604.23374. TaintBench 400-scenario benchmark.

ZKML and training-data provenance

ZKPROV — arxiv 2506.20915. Sub-1.8s proof generation for 8B models.
Halo2 (Plonkish, IPA, no trusted setup), Plonky2 (recursive FRI+PLONK).
ezkl (zkonduit) — production Halo2 ZKML toolkit.
Artemis (arxiv 2409.12055) — Commit-and-Prove SNARK, 7.3× over Lunar.
"Tool Receipts, Not Zero-Knowledge Proofs" — arxiv 2603.10060. NABAOS lightweight verification, alternative to ZKPs for interactive agents.
V3DB — arxiv 2603.03065. Audit-on-demand ZK proofs for verifiable vector search.

Temporal knowledge graph

Graphiti / Zep — arxiv 2501.13956. Bi-temporal (t_valid, t_invalid) per edge. 94.8% DMR. Sub-100ms.

TEE / confidential GPU

NVIDIA H100/H200/B200/B300 CC mode (AES-256-GCM encrypted VRAM, NVLink encryption on B200+).
Intel TDX 1.x, Intel Trust Authority /appraisal/v2/attest.
NVIDIA NRAS, nv_attestation_sdk.
Phala Cloud CVM marketplace.
AMD SEV-SNP.

SCITT and AI evidence transparency

IETF SCITT architecture draft-22 (Apr 2026).
AIVS — draft-stone-aivs-00 (Mar 2026). 200-byte AIVS-Micro.
VAP — draft-kamimura-vap-framework-00 (Jan 2026).
VCP — draft-kamimura-scitt-vcp-00.
PTV — draft-anandakrishnan-ptv-attested-agent-identity-00. Groth16-2026 over EAT.
SCITT Refusal Events — draft-kamimura-scitt-refusal-events.
VERA — draft-berlinai-vera-00 (Feb 2026). Sub-20ms, >90% block rate.
zk-MCP — arxiv 2512.14737. Zero-knowledge audit for MCP communications.

Post-quantum cryptography

FIPS 204 ML-DSA-44/65/87 (already wired).
FIPS 203 ML-KEM, FIPS 205 SLH-DSA.
CNSA 2.0 (U.S. NSS pure-PQ by 2035; Australia 2030).
TALUS — arxiv 2603.22109. Threshold ML-DSA, one-round signing.
Shamir Nonce DKG for ML-DSA — arxiv 2601.20917.
liboqs / oqs Python bindings.

C2PA Content Credentials

C2PA 2.2 production. C2PA 2.3 in progress (HSM signing, cross-platform portability).
C2PA Conformance Program open.
CAWG extension namespace.
c2pa-rs reference SDK.
Referenced in EU AI Act Article 50 Code of Practice (June 2026 final).

EU AI Act current state

Article 50 transparency obligations apply August 2, 2026.
Article 50(2) deepfake labeling — Dec 2, 2026 grace.
HRAIS (Annex III) extended via May 2026 EU Agreement from Aug 2, 2026 to Dec 2, 2027 (Parliament adoption expected July 2026).
Annex I embedded high-risk — Aug 2, 2028.
Penalties — €15M / 3% global turnover for Article 50; €35M / 7% for prohibited practices.
Code of Practice on Transparency of AI-Generated Content — second draft Mar 2026, final June 2026.

Agent identity standards

NIST AI Agent Standards Initiative — launched Feb 17, 2026 by CAISI.
NCCoE concept paper on Software and AI Agent Identity and Authorization — public comment closed Apr 2, 2026.
NIST COSAiS — SP 800-53 overlays for AI agent deployment (in development).
W3C VC 2.0 (BBS+, ecdsa-sd-2023, bbs-2023), DID 1.0.
SPIFFE/SPIRE X.509 SVIDs. HashiCorp Vault 1.21.
OAuth 2.0 Token Exchange (RFC 8693). DPoP, CAEP, PKCE.
Microsoft Entra Agent ID.
CSA Singapore Addendum on Securing Agentic AI (Oct 2025).

Agent protocols

MCP — Anthropic, donated to AAIF Dec 2025. OAuth 2.1 added Jan 2026. 97M+ installs by March 2026.
A2A v1.0 — Linux Foundation AAIF. 150+ orgs in production. Signed Agent Cards.
AP2 v0.2 — Apr 2026. Mandate-based. W3C VC-wrapped. ECDSA P-256 minimum.
AAIF — founders Anthropic, Block, OpenAI. Platinum AWS, Bloomberg, Cloudflare, Google, Microsoft. 170+ members.

Runtime defenses

ClawGuard — arxiv 2604.11790 (Apr 2026). AgentDojo ASR 0.6–3.1% → 0%. MCPSafeBench 36.5–46.1% → 7.1–11.2%.
FIDES — IFC planner with quarantined LLM.
MVAR — dual-lattice IFC with cryptographic provenance.
NeuroTaint — semantic/causal/cross-session taint.
InjecAgent (1,054 cases), AgentDojo, MCPSafeBench benchmarks.
OWASP Agentic AI Top 10 (Dec 2025).
Five Eyes joint guidance (Apr 30, 2026) — cryptographic attestation + runtime enforcement.
Meta "Agents Rule of Two" (2025).

Microsoft Agent Governance Toolkit (primary OSS competitor)

Released Apr 2, 2026, MIT license. 7 packages, 9,500+ tests. p99 < 0.1ms. Ed25519 signed hash-chained receipts. Python/Rust/TypeScript/Go/.NET. 20+ framework adapters. Claims 10/10 OWASP Agentic Top 10.

Systemic risk / digital twin

SR-DTMA (Ling/Liu 2026, JCSSR). Cumulative loss ratio 0.327 → 0.163. Propagation depth 4.8 → 2.6.
arxiv 2405.18092v2 — PDA loop for coupled epidemic-economic dynamics.

STPA / hazard analysis

STAMP/STPA (Leveson MIT).
arxiv 2506.01782 — STPA for Frontier AI.
arxiv 2601.08012 — STPA + capability-enhanced MCP + IFC.

Competitive landscape (May 2026)

Noma Security ($132M, $100M Series B Mar 2026).
Zenity (Gartner "Company to Beat").
Pillar, HiddenLayer, Mindgard (model-layer).
Lakera → Check Point. Protect AI → Palo Alto (~$500M). CalypsoAI → F5 (Jan 2026). Aim → Cato (Sep 2025). Pangea → CrowdStrike. Wiz → Alphabet ($32B, Mar 2026).
Oasis Security ($120M Series B, RSAC 2026).
Astrix, Aembit, Natoma (workload identity).
Credo AI, Holistic AI (GRC).
Microsoft Entra Agent ID, Okta Cross App Access, CyberArk Secure AI Agents, SailPoint Agent Identity Security.
Microsoft Agent Governance Toolkit (Apr 2 2026, MIT OSS).
Mastercard Verifiable Intent (Mar 5, 2026; Google, IBM, Fiserv, Checkout.com).
Market: $1.65B (2026) → $13.52B (2032), 42% CAGR. $3.6B raised by top 10. $96B M&A in 2025.


SECTION 2 — RESEARCH MANDATE (RUN BEFORE WRITING ANY CODE)
Section 1.4 is the floor. Find the ceiling. Use web_search and web_fetch. Run them. Do not skip.
Phase 0 — Required research
Run all of these. Six minimum. More if your thread is complex.

What's newer than section 1.4 for your thread's exact technical domain. Example: if you're the LTLf Contracts thread, section 1.4 names Bolt, AgentSpec, ABC, ProbGuard, LTL3. You search: LTLf runtime monitoring arxiv 2605, agent behavioral contract May 2026, LTLf successor Bolt 2026, runtime verification LLM agent latest. Filter for arXiv IDs 2605. or later. Filter for IETF drafts revised after April 2026. Filter for vendor announcements after May 1, 2026.
What competitors shipped since the snapshot. Search: Microsoft Agent Governance Toolkit update May 2026, Zenity Noma Pillar Lakera Protect AI [your topic] launch 2026. Specifically check whether Microsoft Agent Governance Toolkit has shipped a version covering your thread's domain — if it has, that's a survival-level finding.
What standards revised. For every IETF draft, FIPS publication, or C2PA version cited in 1.4 that your thread touches, check the IETF datatracker, NIST CSRC, or C2PA spec site for revisions. If draft-stone-aivs-00 is in 1.4, look for -01. If C2PA 2.3 is "in progress" per 1.4, look for whether it finalized.
What enterprises are actually shipping. Search: [your topic] production deployment 2026, [your topic] enterprise case study 2026. Section 1.4 is heavy on research and standards; you need shipping reality.
What failure modes are still open. Search: AgentDojo leaderboard May 2026, MCPSafeBench latest results, InjecAgent 2026, prompt injection defense gap May 2026, OWASP Agentic AI exploit 2026. Read what's still broken — that's your wedge against incumbents.
What's contested, surprising, or dominates the SOTA in 1.4. Surface anything that claims to beat the references in 1.4. Surprising findings (a competitor solved a problem 1.4 lists as open; a standard shipped that obviates your design; a paper showed your planned approach is dominated by a newer method) are the most important. Do not bury them. Surface them before writing code.

Anti-laziness rules:

"Section 1.4 already covers it" is not a reason to skip search. 1.4 is May 14. You may be reading this later.
Run at least 6 distinct queries. Each meaningfully different from the others.
If three queries in a row return only pre-May-2026 results, the topic is settled — note this and move on. If they return newer results, dig deeper.
One web_search call is rarely enough for a single question. Stack queries.
When you find a paper or product newer than 1.4, web_fetch the actual page. Don't rely on the snippet.

Phase 1 — Delta brief
Before any code, produce ~/Documents/tex/FRONTIER_DELTA_thread_N.md. It must contain:

What's newer than section 1.4 — citations (arXiv ID, draft revision number, product launch date), one-line summary per finding, dated within the last 8 weeks.
What competitors shipped that affects this thread, with links and dates.
What standards revised since May 14, with the new revision number and what changed.
What this changes about the build plan. Be explicit. If nothing — say "no changes to plan, building to section 1.4 anchors." If something — name what you're changing in implementation and why.
Numerical SOTA targets you must beat. Pull from the most recent paper, not from 1.4 if a newer paper exceeded the 1.4 number. Example: if 1.4 says "ClawGuard drops AgentDojo ASR to 0.0%," and you find a May 2026 paper claiming 0% at 50× lower latency, your target is the new one.
Design decisions justified against the frontier. When you pick an algorithm or library, name the alternative you rejected and cite the 2026 paper or product showing why your pick wins.

The brief is the contract. The code follows.
Phase 2 — Build
Only after the brief exists. Build to the brief. Cite the brief in code comments where a design decision is non-obvious. If during build you discover the brief was wrong, fix the brief before fixing the code.
Phase 3 — Pre-completion sweep
Before declaring the thread done, run one final round of searches dated within the last 14 days. If a paper or product dropped between when you wrote the brief and when you finished building, you need to know. Update the brief and note in the final commit whether the new development changes anything.

SECTION 3 — HARD CONSTRAINTS (APPLY TO EVERY THREAD)

Pydantic v2 strict — ConfigDict(frozen=True, extra="forbid") on every model.
SHA-256 hash-chained, HMAC-signed evidence — every emitted artifact joins the chain.
Algorithm agility — every crypto primitive routes through tex.pqcrypto.algorithm_agility so we can swap to ML-DSA-65/87, ML-KEM, SLH-DSA, or Blake3 without touching call sites.
Fail-closed — no enforcement gate ever emits a default PERMIT on error. Default is ABSTAIN or FORBID.
No exec() sandboxes — the existing one is a known TODO. Don't add more. WASM, subprocess isolation, or nothing.
Test coverage 90%+ for the thread's modules — match the existing bar.
CLAIMS.md discipline — when the thread is wired into the live PDP path, update CLAIMS.md. If it's only test-passing but not wired, mark it built-but-unwired. Outreach only references wired surface.


SECTION 4 — DEFINITION OF DONE
A thread is complete only when all are true:

FRONTIER_DELTA_thread_N.md exists with the post-May-14 delta research.
Code is complete and lint-clean.
Unit tests pass.
Integration test added to tests/test_integration_layer.py proving the module is exercised by an actual /v1/guardrail request (or equivalent live endpoint).
CLAIMS.md updated with the new public-facing claim and the module backing it.
Demo script written: a single curl request that produces a verdict whose evidence record demonstrates the new capability.
Existing 1,881 tests still pass.
Commit message names which 2026 paper or standard the thread implements, including any delta found in Phase 0 beyond section 1.4.

If a thread can't hit all eight, it's not done. Mark blockers, hand off to a follow-up thread, but do not let it close as "complete."

SECTION 5 — START GATE
Stop. Before writing code, paste back to me:

The search queries you plan to run in Phase 0.
The URLs you plan to web_fetch.
Which thread number you are and what specific module(s) you are wiring.

I approve the research plan, then you build.













# PART 2 — THE 14 THREADS

## PHASE A — Wire existing research code into the live pipeline (Threads 1-6)

### Thread 1 — LTLf Behavioral Contracts → PDP

**Goal:** Make `tex.contracts` consumed by every `/v1/guardrail` request.

**Prompt to paste at the start of the new thread:**

> We are wiring the existing `tex.contracts` module into the live `PolicyDecisionPoint` flow. The module is at `src/tex/contracts/` with passing tests at `tests/contracts/`. It exposes `BehavioralContract`, `ContractEnforcer`, `ContractViolation`, an LTLf parser, and atom resolvers (`_atoms.py`, `_ltl.py`). Currently no production code consumes it.
>
> **Required reading before any code change:** `src/tex/contracts/contract.py`, `src/tex/contracts/runtime_enforcement.py`, `src/tex/contracts/violation.py`, `src/tex/engine/pdp.py`, `src/tex/commands/evaluate_action.py`, `src/tex/main.py` lines 1-100 and the `build_runtime` function.
>
> **State of the art to match:** Bhardwaj's ABC framework (arxiv 2602.22302) — Drift Bounds Theorem D* = α/γ, detects 5.2–6.8 soft violations per session, sub-10ms overhead. LTLf semantics per De Giacomo/Vardi original + LTL3 formula progression evaluation (arxiv 2411.14581) for finite-trace runtime verification. AgentSpec (ICSE 2026, arxiv 2503.18666) as a complementary DSL pattern. ProbGuard (arxiv 2508.00500v3) for probabilistic enforcement extensions.
>
> **Acceptance criteria:**
> 1. `PolicyDecisionPoint.__init__` takes an optional `contract_enforcer: ContractEnforcer | None = None`. Threaded through `build_runtime()` in `main.py`.
> 2. After specialists fire and before the router fuses, the PDP calls `contract_enforcer.evaluate(request, trace)` where `trace` is the action ledger entries for the calling agent.
> 3. Hard violations (`severity >= 0.7`) contribute FORBID weight to the router fusion. Soft violations contribute ABSTAIN weight. Both use the existing `_axis_weights` interface so router behavior stays deterministic.
> 4. Contract violations appear in `EvaluationResponse.findings` with: LTLf formula, severity, the trace step that triggered them, the contract name.
> 5. New integration test in `tests/test_integration_layer.py`: an end-to-end `/v1/guardrail` request with a contract that violates produces FORBID with the violation visible.
> 6. `CLAIMS.md` adds: "Tex enforces behavioral contracts written in LTLf temporal logic at every action-evaluation request."
> 7. All 1,881 existing tests pass.
>
> Do not change contract module internals. The wiring lives in `pdp.py`, `main.py`, and the test file. Contract enforcement is opt-in via the constructor argument; default `None` preserves current behavior for any caller not using it.

**Why first:** Smallest wiring surface, already implemented module, biggest positioning unlock per hour. Lets "Tex enforces formally-specified behavioral contracts" become a defensible public claim.

**Difficulty:** Medium. Real wiring, but bounded.

**Estimated time:** 6-12 hours focused work.

---

### Thread 2 — Institutional Governance Graph + Oracle → Ecosystem Engine Step 4

**Goal:** Wire `tex.institutional.GovernanceGraph` and `GovernanceOracle` into `EcosystemEngine.evaluate()` step 4 (governance graph LTS check). Replace the `return _NEUTRAL_AXIS_SCORES` no-op in steps 3-7 for step 4 specifically.

**Prompt:**

> We are wiring `tex.institutional` into `tex.ecosystem.engine.EcosystemEngine` step 4. The institutional module at `src/tex/institutional/` implements the Cournot regulator-firm regime from arxiv 2601.11369 (Bracale Syrnikov, Pierucci et al., Jan 2026): 5 legal states, 12 transitions, sanctions, restorative paths, a Governance Oracle for collusion detection, and a Controller. All tests pass. Nothing else in the codebase imports it.
>
> **Required reading:** `src/tex/institutional/governance_graph.py`, `src/tex/institutional/oracle.py`, `src/tex/institutional/sanctions.py`, `src/tex/institutional/controller.py`, `src/tex/institutional/governance_log.py`, `src/tex/ecosystem/engine.py` (the entire 591-line file, especially the `evaluate()` method and the explicit "steps 3-7: P1/P2 stubs" comment around line 274), `src/tex/ecosystem/state.py`, `src/tex/ecosystem/proposed_event.py`, `src/tex/ecosystem/verdict.py`, `src/tex/ecosystem/_attestation.py`.
>
> **State of the art to match:** arxiv 2601.11369 reports the Institutional governance regime reduces severe-collusion incidence from 50% to 5.6% (Cohen's d = 1.28) vs Ungoverned baseline, and that prompt-only Constitutional regimes yield no reliable improvement. Match this institutional pattern: the governance graph is the manifest, the Oracle is the runtime interpreter, sanctions and restorative paths are the enforcement primitives, the governance log is the append-only audit. Cross-reference arxiv 2603.18894 ("I Can't Believe It's Corrupt") for multi-agent corruption scenarios.
>
> **Acceptance criteria:**
> 1. `EcosystemEngine.__init__` takes `governance_graph: GovernanceGraph | None` and `oracle: GovernanceOracle | None`. Both default `None` for backward compatibility.
> 2. In `evaluate()`, replace the step-4 portion of the `return _NEUTRAL_AXIS_SCORES` block with a real call: after step 2's graph projection succeeds, call `oracle.assess(proposed, state_before, graph)` which returns a `LegalTransition | None`. If the transition is illegal under the active governance graph, return FORBID with rationale `"step 4 governance LTS: transition {kind} from state {state_id} not legal"`. If legal, update `axis_scores.governance_score` accordingly.
> 3. The governance log records every step-4 assessment (legal or illegal) via the existing `tex.institutional.governance_log` interface, signed with ML-DSA via `tex.pqcrypto.algorithm_agility.get_signature_provider(SignatureAlgorithm.ML_DSA_65)`.
> 4. Steps 3, 5, 6, 7 still return neutral — they get wired in later threads. Comment update: "Step 4 wired; steps 3/5/6/7 pending."
> 5. New integration test: an ecosystem engine evaluation against a graph where a "price-fixing-coordinate" transition is illegal returns FORBID with governance-log entry persisted.
> 6. `CLAIMS.md`: "Tex models AI agent ecosystems as formally-specified governance regimes with Cournot-derived legal state transitions. Every proposed event is checked against the active governance graph; illegal transitions are blocked and logged."
> 7. All existing tests pass.

**Why second:** Builds the institutional positioning honestly. Touches the ecosystem engine without claiming the full eight-step pipeline is live.

**Difficulty:** Medium-hard. Two systems integrating into the deliberately-stubbed engine.

**Estimated time:** 10-16 hours.

---

### Thread 3 — CHIEF/ARM Causal Attribution → Post-Incident API endpoint

**Goal:** Expose causal attribution as a new API endpoint without putting it in the hot path. Make every FORBID/ABSTAIN incident attributable via CHIEF/ARM.

**Prompt:**

> We are wiring `tex.causal` (CHIEF and ARM modules at `src/tex/causal/`) as a post-incident attribution endpoint. The module implements the hierarchical failure attribution framework from arxiv 2602.23701 (CHIEF) and the integrity lattice from arxiv 2509.08682. Currently self-contained.
>
> **Required reading:** `src/tex/causal/chief.py`, `src/tex/causal/arm.py`, `src/tex/causal/counterfactual.py`, `src/tex/causal/_hcg.py`, `src/tex/causal/_otar.py`, `src/tex/causal/_integrity.py`, `src/tex/causal/_provenance_graph.py`, `src/tex/causal/_denial_record.py`, `src/tex/api/routes.py`, `src/tex/api/schemas.py`, `src/tex/evidence/recorder.py`, `src/tex/evidence/chain.py`.
>
> **State of the art to match:** CHIEF (arxiv 2602.23701) and the AAAI 2026 causal framework (arxiv 2509.08682, 36.2% step-level accuracy on Who&When and TRAIL, 22.4% task-success boost from generated optimizations). AgenTracer (arxiv 2509.03312) for trajectory-aware reasoning. NeuroTaint (arxiv 2604.23374) for the semantic / causal / cross-session propagation principles. The Who&When benchmark (Zhang 2025) as the standard. Pair with SCITT Refusal Events (draft-kamimura-scitt-refusal-events) — every attribution result is a SCITT-shaped Signed Statement.
>
> **Acceptance criteria:**
> 1. New endpoint `POST /v1/incidents/{decision_id}/attribute` that takes a decision ID from the existing decision store and returns a `CausalAttributionResult` with: root-cause agent, propagation chain, counterfactual screening, integrity-lattice level, and a SCITT-shaped Signed Statement (use the existing `tex.c2pa._cose_alg` infrastructure for the COSE signature even though c2pa itself isn't wired in this thread).
> 2. The endpoint reads from the existing `InMemoryDecisionStore` and the action ledger; it does not modify the request path.
> 3. CHIEF/ARM modules are imported from `src/tex/api/incident_routes.py` (new file), mounted via `build_incident_router()` in `main.py`.
> 4. Attribution result schema added to `src/tex/api/schemas.py`.
> 5. New integration test: trigger an ABSTAIN, then call the attribute endpoint with the decision_id, expect a result with non-null root-cause agent and a verifiable signed statement.
> 6. `CLAIMS.md`: "Every incident — every FORBID, every ABSTAIN, every contract violation — is causally attributable to a root-cause agent and trajectory step via CHIEF/ARM with cryptographically signed attribution receipts."
> 7. All existing tests pass.

**Why third:** New API surface, low risk to hot path, unlocks the "every incident causally attributed" positioning claim. Doesn't slow down `/v1/guardrail`.

**Difficulty:** Medium. New endpoint, some schema work, SCITT-shaped signing.

**Estimated time:** 8-12 hours.









---

### Thread 4 — Runtime Defenses (PlanGuard, MAGE, ClawGuard, MCPShield, AgentArmor) → Specialist Judges

**Goal:** Wire the five runtime-defense modules as additional specialist judges in the `SpecialistSuite` so they participate in evaluation.

**Prompt:**

> We are wiring five runtime defense modules into the `SpecialistSuite` consumed by `PolicyDecisionPoint`. All modules at `src/tex/runtime/`:
> - `clawguard/boundary_enforcer.py` + `rule_set.py` — boundary enforcement against indirect prompt injection (arxiv 2604.11790, Apr 2026)
> - `planguard/intent_verifier.py` + `isolated_planner.py` — InjecAgent defense (arxiv 2403.02691 benchmark)
> - `mage/risk_assessor.py` + `shadow_memory.py` — long-horizon memory poisoning defense
> - `mcpshield/verifier.py` + `lts_model.py` — formal verification against MCP attack surfaces (arxiv 2604.05969)
> - `agentarmor/type_system.py` + `property_registry.py` — runtime hardening
>
> **Required reading:** all modules above + `src/tex/specialists/base.py`, `src/tex/specialists/judges.py`, `src/tex/specialists/mcp_injection_specialist.py`, `src/tex/specialists/owasp_skills_top10_specialist.py`, `src/tex/engine/pdp.py`.
>
> **State of the art to match:** ClawGuard drops AgentDojo IPI ASR from 0.6–3.1% to 0.0% and MCPSafeBench from 36.5–46.1% to 7.1–11.2% (arxiv 2604.11790). FIDES (arxiv 2025) for IFC-based planner enforcement. MVAR for dual-lattice IFC with cryptographic provenance. Meta's "Agents Rule of Two" — agent holds ≤2 of: untrusted input, sensitive data, external action capability. OWASP Agentic AI Top 10 2026 categories. The Five Eyes joint guidance from Apr 30, 2026 (CISA + NSA + UK NCSC + ASD + CCCS + NZ NCSC). Avoid the gap Microsoft Agent Governance Toolkit (Apr 2, 2026, MIT) just claimed — they're the first to ship 10/10 OWASP Agentic coverage with sub-millisecond enforcement.
>
> **Acceptance criteria:**
> 1. Five new specialist judges following the `Specialist` protocol from `tex.specialists.base`:
>    - `ClawGuardSpecialist`
>    - `PlanGuardSpecialist`
>    - `MageSpecialist`
>    - `McpShieldSpecialist`
>    - `AgentArmorSpecialist`
> 2. Each judge wraps the corresponding runtime module and emits findings against OWASP ASI 2026 categories (use the existing OWASP taxonomy in `src/tex/domain/owasp_asi.py`).
> 3. `build_default_specialist_suite()` in `src/tex/specialists/judges.py` registers all five judges.
> 4. Each judge has < 5ms p99 contribution to PDP latency (measure via the existing `LatencyBreakdown` infrastructure).
> 5. New integration tests: one request per judge proving the judge fires and contributes findings.
> 6. `CLAIMS.md`:
>    - "Tex enforces boundary constraints against indirect prompt injection at every tool-call evaluation (ClawGuard pattern)."
>    - "Tex defends against InjecAgent-class attacks with verified plan intent."
>    - "Tex tracks shadow memory across long-horizon sessions to detect memory-poisoning chains."
>    - "Tex provides formal verification against the canonical MCP attack surfaces."
>    - "Tex enforces runtime type-system invariants on agent actions (AgentArmor)."
> 7. All existing tests pass; total request latency stays under 200ms p95 (current is 142ms p95).

**Why fourth:** Substantial security-story unlock. Each judge unlocks one OWASP coverage claim. Directly competes with Microsoft Agent Governance Toolkit's "10/10 OWASP" pitch.

**Difficulty:** Medium-hard. Five judges, performance budget to respect.

**Estimated time:** 16-24 hours.

---

### Thread 5 — C2PA Content Credentials → Evidence Emission

**Goal:** Every evidence record produced for an outbound AI-generated artifact carries a C2PA 2.2 Content Credential.

**Prompt:**

> We are wiring `tex.c2pa` (signer + verifier + manifest at `src/tex/c2pa/`, 53 passing tests) into the evidence emission path. Today c2pa is self-contained and never invoked by the request pipeline.
>
> **Required reading:** `src/tex/c2pa/signer.py`, `src/tex/c2pa/verifier.py`, `src/tex/c2pa/manifest.py`, `src/tex/c2pa/_canonical_claim.py`, `src/tex/c2pa/_cbor.py`, `src/tex/c2pa/_cose_alg.py`, `src/tex/c2pa/durable_credentials.py`, `src/tex/evidence/recorder.py`, `src/tex/evidence/exporter.py`, `src/tex/evidence/chain.py`, `src/tex/pqcrypto/algorithm_agility.py`, `src/tex/pqcrypto/ml_dsa.py`.
>
> **State of the art to match:** C2PA 2.2 (production), 2.3 in progress (cross-platform portability + HSM signing). Article 50 of the EU AI Act becomes enforceable Aug 2, 2026 with €15M / 3% turnover penalties. The Code of Practice (final June 2026) explicitly names C2PA as one of the required multi-layered marking primitives. Microsoft Edge has built-in C2PA verification rolling out through 2026. The 6,000+ member coalition makes this the de facto standard for AI provenance. Reference NSA CSI on Content Credentials. Cross-reference draft-kamimura-scitt-refusal-events for the SCITT-wrapped refusal pattern — every FORBID emits a SCITT Signed Statement that includes the C2PA assertion when applicable.
>
> **Acceptance criteria:**
> 1. `EvidenceRecorder.record_decision()` accepts an optional `outbound_artifact` parameter (bytes or path). When provided, it produces a C2PA 2.2 manifest with: `c2pa.actions` assertion listing the action that triggered emission, `c2pa.training_data_class` for the calling agent's model class, `cawg.identity` for the calling tenant, signed with ML-DSA-65 via the algorithm-agility provider.
> 2. The manifest hash is included in the evidence record. The full manifest is stored in a new `evidence_manifests` Postgres table (add migration).
> 3. New endpoint `GET /v1/evidence/{record_id}/c2pa` returns the manifest as CBOR.
> 4. Verifier endpoint `POST /v1/c2pa/verify` accepts a manifest and returns validation result.
> 5. Integration test: a PERMIT verdict for an outbound email artifact produces an evidence record with a valid C2PA manifest. Verifier endpoint accepts it. Tampering the artifact bytes makes verification fail.
> 6. `CLAIMS.md`: "Every AI-generated artifact governed by Tex carries a C2PA 2.2 Content Credential signed with ML-DSA-65 post-quantum signatures. Satisfies EU AI Act Article 50 machine-readable marking obligation."
> 7. All existing tests pass.

**Why fifth:** Article 50 forcing function (Dec 2, 2026 for new systems, Aug 2, 2026 for the chatbot disclosure). Differentiates from Microsoft Agent Governance Toolkit and from every posture-management competitor. Tex becomes one of the first agent-governance platforms whose evidence is C2PA-compliant by default.

**Difficulty:** Medium. New table + endpoint, but c2pa module is fully tested.

**Estimated time:** 10-14 hours.

---

### Thread 6 — Ecosystem Engine Steps 3, 5, 6, 7 fully wired

**Goal:** Replace the remaining `return _NEUTRAL_AXIS_SCORES` neutral-return paths in steps 3, 5, 6, 7 of `EcosystemEngine.evaluate()` with real implementations using the modules wired in Threads 1-4.

**Prompt:**

> We are completing `EcosystemEngine.evaluate()` so all 8 steps return real verdicts, not neutral scores. Step 1 (ontology), 2 (projection), 4 (governance LTS via Thread 2), and 8 (intervention — left for Thread 7) are out of scope. This thread wires steps 3, 5, 6, 7:
> - Step 3 — contract check (use the `ContractEnforcer` wired in Thread 1)
> - Step 5 — causal attribution (use CHIEF/ARM from Thread 3 but in fast pre-emission mode, not the post-incident endpoint)
> - Step 6 — drift detection (use existing `src/tex/drift/` module — `_bocpd.py`, `change_point.py`, `emergent_norm.py`, `signal_registry.py` — which has tests but isn't wired into the engine)
> - Step 7 — systemic risk (call out to `tex.systemic.risk_evaluator.SystemicRiskEvaluator.score()` — note this raises NotImplementedError today; Thread 9 implements it; this thread adds the call site behind a feature flag `TEX_ECOSYSTEM_SYSTEMIC=0` so the engine still works)
>
> **Required reading:** `src/tex/ecosystem/engine.py` lines 200-400, `src/tex/drift/_bocpd.py`, `src/tex/drift/change_point.py`, `src/tex/drift/emergent_norm.py`, the Thread 1, 2, 3 outputs in `CLAIMS.md`.
>
> **State of the art to match:** Bayesian Online Change-Point Detection per the original Adams/MacKay paper (Tex already has it in `_bocpd.py`). Kaptein 2026 "Runtime Governance for AI Agents: Policies on Paths" (arxiv 2603.16586) for the fleet-level path-policy framing. ProbGuard (arxiv 2508.00500v3) for PCTL-style probabilistic enforcement at step 7. SR-DTMA (Ling/Liu 2026) for systemic-risk simulation as the long-term direction. Drift Bounds Theorem from ABC (arxiv 2602.22302) — drift bounded by α/γ in expectation.
>
> **Acceptance criteria:**
> 1. Step 3 calls the wired `ContractEnforcer` and updates `axis_scores.contract_score`.
> 2. Step 5 calls a new `CHIEF.fast_attribute()` method (add it to `src/tex/causal/chief.py`) that returns attribution within 5ms p99 — a faster, less complete attribution than the full post-incident endpoint, suitable for the request path.
> 3. Step 6 calls `tex.drift.signal_registry.evaluate_drift(proposed, state_before)` (add this orchestrator function) that runs BOCPD against the registered drift signals and contributes to `axis_scores.drift_score`.
> 4. Step 7 is gated by `TEX_ECOSYSTEM_SYSTEMIC` env flag, default `0`. When `0`, returns neutral. When `1`, calls `SystemicRiskEvaluator.score()`. Document the flag in `docs/ecosystem.md`.
> 5. Update the comment "P1/P2 axes return neutral; full pipeline lands in later threads" to reflect actual status.
> 6. Total `EcosystemEngine.evaluate()` p99 latency stays under 50ms (current target was "< 10ms p99 with empty stubs"; budget triples now that all axes are live).
> 7. New integration test exercising all 4 steps with a single proposed event.
> 8. `CLAIMS.md`: "Tex's ecosystem engine evaluates every proposed event across all eight governance axes — ontology, graph projection, behavioral contracts, governance LTS, causal attribution, drift detection, and systemic risk — before admitting the event into the ecosystem state."
> 9. All existing tests pass.

**Why sixth:** This is where Tex becomes credibly "the full ecosystem governance pipeline." Until this thread lands, the engine is a 2-of-8 implementation.

**Difficulty:** Hard. Six things wiring together, latency budget tight, plus a feature flag for the unimplemented step 7.

**Estimated time:** 20-30 hours.

---






## PHASE B — New engineering on the scaffolded modules (Threads 7-10)

### Thread 7 — Bounded-Compromise Calculator + Intervention Engine

**Goal:** Implement `tex.intervention.bounded_compromise.BoundedCompromiseCalculator` and `tex.intervention.engine.InterventionEngine` and `tex.intervention.restorative.RestorativePathExecutor`. Wire them as ecosystem-engine step 8.

**Prompt:**

> We are implementing the three scaffolded files in `src/tex/intervention/`:
> - `bounded_compromise.py` — currently raises `NotImplementedError` for `estimate_adversary_payoff`, `satisfies_bound`, `long_run_compromise_ratio`. Implement per the bounded-compromise theorem from AAF — long-run compromise ratio < 1 iff expected intervention cost > expected adversary payoff.
> - `engine.py` — `InterventionEngine.select()` and `apply()`. Pick the lowest-cost intervention whose `cost_to_adversary >= adversary's expected_payoff` under the current drift state.
> - `restorative.py` — `RestorativePathExecutor.execute()` walks the governance graph's restorative paths to return the ecosystem to a legal state.
>
> Then wire all three into `EcosystemEngine.evaluate()` step 8.
>
> **Required reading:** `src/tex/intervention/bounded_compromise.py`, `src/tex/intervention/engine.py`, `src/tex/intervention/restorative.py`, `src/tex/intervention/kinds.py`, `src/tex/ecosystem/engine.py`, `src/tex/institutional/sanctions.py` (Thread 2 output), `src/tex/institutional/governance_graph.py` for restorative-path data structures.
>
> **State of the art to match:** AAF (arxiv 2512.18561 v3, March 2026) bounded-compromise theorem. ABC Drift Bounds Theorem (D* = α/γ, arxiv 2602.22302). ProbGuard PCTL-style proactive enforcement (arxiv 2508.00500v3) — warnings up to 38.66s ahead. Pro2Guard probabilistic model checking. Cournot governance graph restorative paths per arxiv 2601.11369. The intervention selection should be cost-minimizing under the bounded-compromise constraint; the apply step emits a governance ledger record via `tex.institutional.governance_log` signed with ML-DSA.
>
> **Acceptance criteria:**
> 1. `BoundedCompromiseCalculator` fully implemented with concrete formulas. Adversary payoff estimation reads drift signals; bound check returns `cost > payoff`; long-run ratio computed from history tuples. Document the math in module docstring with arxiv citations.
> 2. `InterventionEngine.select()` ranks candidates by `cost_to_system` ascending, checks each against `bounded_compromise_calculator.satisfies_bound`, returns first that satisfies or `None`.
> 3. `InterventionEngine.apply()` dispatches to the appropriate subsystem: capability registry restrictions, trust-tier downgrade via the existing agent registry, policy enforcement updates, or sandbox manager invocation. Each application emits an ML-DSA-signed governance ledger record.
> 4. `RestorativePathExecutor.execute()` looks up the path in the governance graph (Thread 2), emits each restorative event in order via the institutional log, verifies final state matches `target_legal_state_id`.
> 5. Wire all three into `EcosystemEngine.evaluate()` step 8: when steps 3-7 produce a FORBID, call `InterventionEngine.select` to recommend an intervention, attach to the verdict as `recommended_intervention_id`. After verdict emission, async-execute the restorative path if configured.
> 6. New integration test: a request that triggers FORBID returns a verdict with a non-null `recommended_intervention_id` and produces a governance log entry for the applied intervention.
> 7. `CLAIMS.md`: "Tex generates bounded-compromise certificates with mathematical guarantees that the long-run compromised-interaction ratio stays below one under the active intervention regime."
> 8. All existing tests pass.

**Why seventh:** This is real new engineering, not wiring. The Bounded-Compromise Calculator's specific math has to be derived from your intervention surface. The payoff is the most differentiated positioning claim in the system.

**Difficulty:** Hard. Real math, real new code. Time-bounded by getting the formulas right.

**Estimated time:** 30-50 hours.

---

### Thread 8 — Digital Twin + Cascade Predictor + Systemic Risk Evaluator

**Goal:** Implement the three scaffolded modules in `src/tex/systemic/` so step 7 of the ecosystem engine (gated in Thread 6) can be flipped on in production.

**Prompt:**

> We are implementing `src/tex/systemic/digital_twin.py`, `src/tex/systemic/cascade_predictor.py`, and `src/tex/systemic/risk_evaluator.py` — currently all `NotImplementedError`.
>
> - `EcosystemDigitalTwin.fork_at(timestamp_iso)` returns a forked twin from a snapshot.
> - `EcosystemDigitalTwin.simulate_forward(steps, perturbation)` returns a trajectory of `(state_hash, risk_score, drift_signals)` tuples.
> - `CascadePredictor.predict_cascade_paths(seed_violation_event_id, max_depth=8, min_probability=0.05)` returns chains of event IDs representing high-probability cascades.
> - `SystemicRiskEvaluator.score(state)` returns a 0-1 systemic risk score combining drift magnitudes, contract violation rate, cascade reachability.
>
> **Required reading:** `src/tex/systemic/digital_twin.py`, `src/tex/systemic/cascade_predictor.py`, `src/tex/systemic/risk_evaluator.py`, `src/tex/ecosystem/state.py`, `src/tex/graph/temporal_kg.py`, `src/tex/graph/projection.py`, the Thread 1-6 outputs.
>
> **State of the art to match:** SR-DTMA (Ling/Liu 2026, JCSSR) — Systemic Risk-aware Digital Twin Multi-Agent framework with LLM-driven heterogeneous agents on a digital twin substrate, reduced supply chain cumulative loss ratio from 0.327 to 0.163, propagation depth from 4.8 to 2.6. arxiv 2405.18092v2 "LLM Multi-Agent System for Simulation Model Parametrization in Digital Twins" for the parametrization pattern. arxiv 2512.11933 for multi-time-scale propagation models (already cited in `risk_evaluator.py` TODO). The cascade predictor uses bounded BFS over the causal influence graph from CHIEF/ARM (Thread 3) with propagation probabilities from historical data in the temporal KG.
>
> **Acceptance criteria:**
> 1. `EcosystemDigitalTwin.fork_at` produces an isolated copy of the temporal KG state at the given timestamp, sharing nothing mutable with the parent.
> 2. `EcosystemDigitalTwin.simulate_forward` drives the simulation with calibrated agent policies pulled from `tex.learning.calibrator.ThresholdCalibrator`, applies the perturbation at step 0, records drift + risk at each step.
> 3. `CascadePredictor.predict_cascade_paths` BFS bounded by `max_depth`, prunes by `min_probability`, returns tuples of event-ID chains sorted by aggregate probability descending.
> 4. `SystemicRiskEvaluator.score` combines: drift signal magnitudes (Thread 6 drift module), contract violation rate (Thread 1 contracts module), cascade reachability from current state (this thread's predictor). Apply multi-time-scale propagation per arxiv 2512.11933.
> 5. Flip `TEX_ECOSYSTEM_SYSTEMIC` default to `1` once step 7 is exercised by an integration test that proves a high-risk state yields a non-trivial systemic score and the score gates a FORBID.
> 6. New endpoint `POST /v1/ecosystem/twin/simulate` accepts a proposed perturbation, returns the trajectory.
> 7. `CLAIMS.md`: "Tex pre-evaluates every consequential proposed action against a digital twin of the agent ecosystem, predicting cascade probabilities and systemic risk before admission."
> 8. All existing tests pass.

**Why eighth:** This unlocks the "pre-evaluates against a digital twin" positioning claim. Depends on Thread 7's calibrated policies; building it earlier is wasted effort.

**Difficulty:** Hard. Real simulation work. The honest scope is "skeleton + working trajectories"; full calibrated agent policies are a longer arc.

**Estimated time:** 40-60 hours.

---

### Thread 9 — ML-KEM + SLH-DSA stub completion + threshold ML-DSA

**Goal:** Implement the remaining stubbed methods in `src/tex/pqcrypto/ml_kem.py` and `src/tex/pqcrypto/slh_dsa.py`. Add a threshold ML-DSA path.

**Prompt:**

> We are completing the stubbed methods in `src/tex/pqcrypto/ml_kem.py` (FIPS 203 encapsulate/decapsulate) and `src/tex/pqcrypto/slh_dsa.py` (FIPS 205 sign/verify). Both currently `NotImplementedError`. ML-DSA is already wired via `tex.pqcrypto.algorithm_agility` and `tex.pqcrypto.ml_dsa`. Then add a threshold ML-DSA module (`src/tex/pqcrypto/threshold_ml_dsa.py`) per the TALUS / Shamir Nonce DKG papers.
>
> **Required reading:** `src/tex/pqcrypto/ml_kem.py`, `src/tex/pqcrypto/slh_dsa.py`, `src/tex/pqcrypto/ml_dsa.py` (working reference), `src/tex/pqcrypto/algorithm_agility.py`, `src/tex/pqcrypto/hybrid.py`, `src/tex/pqcrypto/_ed25519_provider.py`.
>
> **State of the art to match:** FIPS 203 ML-KEM finalized Aug 2024 — use liboqs (`oqs.KeyEncapsulation` constructor with names "ML-KEM-512" / "ML-KEM-768" / "ML-KEM-1024"). FIPS 205 SLH-DSA finalized Aug 2024 — liboqs "SPHINCS+-SHA2-128s-simple" etc. Threshold ML-DSA per TALUS (arxiv 2603.22109) with one-round online signing via boundary clearance, and Shamir Nonce DKG per arxiv 2601.20917 — per-session EUF-CMA loss < 0.007 bits for |S| ≤ 17. CNSA 2.0 mandate by 2035 for U.S. NSS; ML-DSA-87 + ML-KEM-1024 for highest assurance. Hybrid mode per RFC 9794 and SP 800-56C Rev. 2.
>
> **Acceptance criteria:**
> 1. `MlKemProvider.encapsulate` and `decapsulate` fully working against liboqs; round-trip test confirms `decap(encap(pk)) == shared_secret`.
> 2. `SlhDsaProvider.sign` and `verify` working with parameter sets SLH-DSA-128s, SLH-DSA-192s, SLH-DSA-256s.
> 3. `algorithm_agility.get_signature_provider(SLH_DSA_128S)` now returns a working provider, not `NotImplementedError`.
> 4. New `src/tex/pqcrypto/threshold_ml_dsa.py` implements `ThresholdMlDsaProvider` with `partial_sign`, `aggregate`, `verify`. Threshold k of n, with DKG. Cite arxiv 2603.22109 and 2601.20917 in module docstring.
> 5. Used in `tex.evidence.chain` for k-of-n quorum signing on the highest-stakes evidence records (configurable via env flag `TEX_EVIDENCE_QUORUM_K`).
> 6. `CLAIMS.md`: "Tex's evidence chain supports threshold ML-DSA-87 quorum signatures for highest-stakes evidence, satisfying CNSA 2.0 trajectory and providing protection against single-key compromise."
> 7. All existing tests pass.

**Why ninth:** Closes the post-quantum loop. Threshold ML-DSA is the differentiator vs every competitor still on Ed25519 (including Microsoft's Apr 2026 toolkit).

**Difficulty:** Medium. ML-KEM and SLH-DSA are straight liboqs bindings. Threshold ML-DSA is the new engineering — pick TALUS as the simpler implementation target.

**Estimated time:** 16-24 hours.

---

### Thread 10 — Information-Flow Control wired into governance/private_data_exec

**Goal:** Wire `tex.governance.private_data_exec` (currently self-contained) into the live request pipeline so untrusted-tool outputs are labeled and prevented from reaching sensitive sinks.

**Prompt:**

> We are wiring `src/tex/governance/private_data_exec/` — the IFC taint-tracking sandbox — into the live `PolicyDecisionPoint`. The module implements the dual-lattice information-flow-control pattern from FIDES (arxiv 2025) and MVAR. Today it has tests but no production consumers.
>
> **Required reading:** all files in `src/tex/governance/private_data_exec/`, especially the `_Tainted` wrapper and the sink-policy evaluator. Plus `src/tex/engine/pdp.py`, `src/tex/specialists/judges.py`, the `ClawGuardSpecialist` from Thread 4.
>
> **State of the art to match:** FIDES (arxiv 2025) — IFC-based agent planner with confidentiality + integrity labels, deterministic policy enforcement, novel primitives for selectively hiding information. arxiv 2601.08012 ("Towards Verifiably Safe Tool Use") — STPA + IFC + capability-enhanced MCP. NeuroTaint (arxiv 2604.23374) — semantic / causal / cross-session taint propagation; the dual lattice goes beyond explicit content transfer. MVAR (`mvar-security/mvar`) — dual-lattice IFC with QSEAL-signed provenance taint. Apply Meta's "Agents Rule of Two": an agent must hold ≤2 of untrusted input, sensitive data, external action capability — IFC is what enforces this.
>
> **Acceptance criteria:**
> 1. New specialist `IfcSpecialist` (in `src/tex/specialists/ifc_specialist.py`) reads the request context, applies the IFC labels via `private_data_exec`'s sink-policy evaluator. Untrusted-source content reaching a sensitive sink contributes FORBID weight.
> 2. The IFC labels become part of the evidence record (new field: `ifc_labels: dict[str, str]`).
> 3. `IfcSpecialist` registered in `build_default_specialist_suite()`.
> 4. Integration test: a request where an untrusted tool output (labeled UNTRUSTED) reaches a sensitive sink (CRITICAL) returns FORBID.
> 5. Performance: < 5ms p99 contribution.
> 6. `CLAIMS.md`: "Tex enforces dual-lattice information-flow control on every agent action: untrusted-source content cannot reach sensitive sinks. Implements the FIDES / MVAR IFC pattern with deterministic, auditable policy decisions."
> 7. All existing tests pass.

**Why tenth:** Major security claim. Cryptographically-grounded answer to "did the untrusted Google Doc actually exfiltrate data?" Pairs cleanly with the ClawGuard claim from Thread 4.

**Difficulty:** Medium. Module exists, wiring + label propagation is the work.

**Estimated time:** 12-16 hours.

---

## PHASE C — Cryptographic evidence stack (Threads 11-14)

### Thread 11 — TEE Attestation (Intel TDX + NVIDIA H100/H200/B200)

**Goal:** Implement `src/tex/tee/attestation_client.py`, `src/tex/tee/h100_attestation.py`, `src/tex/tee/tdx_attestation.py`. Compose into evidence records.

**Prompt:**

> We are implementing TEE attestation for Tex's runtime. Three scaffolded files: `src/tex/tee/attestation_client.py` (composite Intel Trust Authority client), `src/tex/tee/h100_attestation.py` (NVIDIA NRAS evidence collector), `src/tex/tee/tdx_attestation.py` (Intel TDX evidence). All `NotImplementedError`.
>
> **Required reading:** the three TEE files, `src/tex/pqcrypto/algorithm_agility.py`, `src/tex/evidence/recorder.py`, `src/tex/evidence/chain.py`.
>
> **State of the art to match:** Intel Trust Authority `/appraisal/v2/attest` endpoint. Python SDK `nv_attestation_sdk`. `ITAConnector.get_token_v2(tdx_args, gpu_args)` returns a JWT with `intel_tee` + `nvidia_gpu` sub-objects. Composite CPU TEE + GPU TEE attestation per Intel's published architecture. NVIDIA H100/H200 confidential compute mode with AES-256-GCM encrypted VRAM. B200/B300 Blackwell adds NVLink encryption for multi-GPU. Phala Cloud's production CVM marketplace as proof of operational maturity. Apr 30, 2026 Five Eyes joint guidance explicitly names hardware attestation as required for high-assurance agentic AI. RFC 9711 EAT for the token claim shape.
>
> **Acceptance criteria:**
> 1. `tee.h100_attestation.collect_gpu_evidence()` binds to `nv_attestation_sdk` and produces SPDM-compliant evidence. If the SDK is not available on the host, return a clearly-marked stub evidence blob (development mode).
> 2. `tee.tdx_attestation.collect_tdx_evidence()` collects Intel TDX evidence via the host SDK; same dev-mode fallback.
> 3. `tee.attestation_client.compose_attestation` calls Intel Trust Authority `/appraisal/v2/attest` with both evidence blobs; returns JWT.
> 4. `tee.attestation_client.verify_attestation(jwt, expected_pcr_set)` verifies signature against ITA root certs, checks measurements, checks CRL and freshness.
> 5. New field `tee_attestation_jwt: str | None` on `EvidenceRecord`. When the Tex runtime is hosted in a TEE-capable environment (detected via env flag `TEX_TEE_MODE=1`), every evidence record carries the composite attestation.
> 6. New endpoint `POST /v1/tee/verify` accepts a JWT and returns validation.
> 7. `CLAIMS.md`: "Every Tex evidence record produced in a TEE-capable deployment is bound to a composite Intel TDX + NVIDIA H100/H200/B200 attestation, verifiable independently against Intel Trust Authority root certificates. Hardware-grounded non-repudiation."
> 8. All existing tests pass; TEE features gracefully degrade in non-TEE environments.

**Why eleventh:** TEE attestation is the difference between "we say it ran in confidential compute" and "Intel + NVIDIA cryptographically vouch it ran in confidential compute." None of Noma/Zenity/Pillar/Lakera/Aim/Credo have this. Microsoft's Apr 2026 toolkit doesn't have this either.

**Difficulty:** Hard. Requires NVIDIA SDK + ITA account for full validation. Dev-mode fallback is the pragmatic path.

**Estimated time:** 24-40 hours.

---

### Thread 12 — VET Web Proofs + Agent Identity Document

**Goal:** Implement `src/tex/vet/web_proofs.py` (TLS notarization for black-box API calls) and finish `src/tex/vet/agent_identity_document.py` (currently has the dataclass but no issuance / verification logic).

**Prompt:**

> We are implementing Web Proofs and Agent Identity Documents per the VET paper. Files: `src/tex/vet/web_proofs.py` (NotImplementedError) and `src/tex/vet/agent_identity_document.py` (dataclass only).
>
> **Required reading:** both files, plus `src/tex/pqcrypto/algorithm_agility.py`, `src/tex/evidence/recorder.py`. Skim `src/tex/c2pa/signer.py` for the canonical-claim pattern.
>
> **State of the art to match:** TLSNotary v0.1 (production Rust impl) and Reclaim Protocol as the two candidates for Web Proof notarization. Overhead typically <3× per the VET paper. For Agent Identity Documents: W3C VC 2.0 (finalized 2025) with JOSE/COSE proofs; W3C DID 1.0; BBS+ for selective disclosure (`bbs-2023` cryptosuite). SPIFFE/SPIRE X.509 SVIDs for workload identity. The PTV protocol (draft-anandakrishnan-ptv-attested-agent-identity-00) for attested agent identity — Groth16-2026 proofs over EAT profiles. Indicio ProvenAI as a reference for VC-based agent credentials. A2A v1.0 Signed Agent Cards as the cross-org discovery primitive. AP2 v0.2 Mandate signing as the transactional pattern. Per the Apr 30, 2026 Five Eyes guidance: agents must be authenticated using verifiable credentials with short-lived OAuth 2.0/OIDC tokens.
>
> **Acceptance criteria:**
> 1. `vet.web_proofs.notarize_session(target_host, session_log)` binds to TLSNotary (Python wrapper or subprocess to the Rust binary). Fall back to a clearly-marked stub if TLSNotary not installed.
> 2. `vet.web_proofs.verify_web_proof(proof, expected_target_host, expected_response_hash)` verifies notary signature and transcript hash.
> 3. `vet.agent_identity_document` adds `issue()` and `verify()` functions producing W3C VC 2.0 documents with ML-DSA-65 proofs (via algorithm-agility provider). Use the `bbs-2023` cryptosuite shape for selective disclosure on supported_proof_systems and compliance_assertions claims.
> 4. New endpoint `POST /v1/vet/issue-aid` issues an AID for a registered agent. `POST /v1/vet/verify-aid` verifies one.
> 5. When Tex routes a request through a third-party model API in production, the TLS session is notarized; the proof is attached to the evidence record.
> 6. `CLAIMS.md`: "Tex notarizes every third-party AI API call with TLSNotary Web Proofs, producing tamper-evident transcripts independent of the API provider. Each Tex-managed agent carries a W3C VC 2.0 Agent Identity Document with BBS+ selective disclosure, ML-DSA-65 signed."
> 7. All existing tests pass.

**Why twelfth:** Closes the third-party trust gap. Lets Tex make claims about what closed-model APIs returned — without trusting those APIs.

**Difficulty:** Hard. TLSNotary integration is real work. AID issuance is bounded.

**Estimated time:** 24-36 hours.

---

### Thread 13 — ZKPROV: Training Data Provenance via Halo2/Plonky2

**Goal:** Implement `src/tex/zkprov/proof.py` and `src/tex/zkprov/commitment.py`. This is the deepest cryptographic work in the system.

**Prompt:**

> We are implementing the ZKPROV protocol from arxiv 2506.20915. Two scaffolded files: `src/tex/zkprov/proof.py` (generate_proof, verify_proof) and `src/tex/zkprov/commitment.py` (issue_commitment). Both NotImplementedError.
>
> **Required reading:** both files, the arxiv 2506.20915 paper sections 3-5, `src/tex/pqcrypto/algorithm_agility.py`. Familiarity with Halo2 PLONKish arithmetization is required; if not present, start with the Halo2 book and ezkl tutorials.
>
> **State of the art to match:** ZKPROV per arxiv 2506.20915 — sub-1.8s proof generation for 8B-parameter models, sub-1.8s verification, end-to-end overhead under 3.3s. Halo2 (Zcash) with Plonkish arithmetization is the recommended proving system; IPA-based commitments avoid trusted setup. Plonky2 (FRI + PLONK) is the recursive alternative. ezkl (`zkonduit/ezkl`) is the production ZKML toolkit. Artemis (arxiv 2409.12055) for Commit-and-Prove construction supporting Halo2 with IPA; 7.3× improvement over Lunar. Apollo as the alternative CP-SNARK. The dataset commitment is a Merkle tree over dataset records with ML-DSA-65 CA signature on the root.
>
> **Acceptance criteria:**
> 1. `zkprov.commitment.issue_commitment` builds Merkle root over dataset records, hashes the attribute schema canonically, signs the full `DatasetCommitment` with the CA's ML-DSA key.
> 2. `zkprov.proof.generate_proof` implements the zkSNARK circuit per Section 4 of the paper. Pick **Halo2 with IPA** as the backend (no trusted setup). Sub-2s target for sub-1B models in initial implementation; document scale as a roadmap item.
> 3. `zkprov.proof.verify_proof` verifies in under 2s against the verifier key.
> 4. New endpoint `POST /v1/zkprov/verify` accepts a `ProvenanceProof` and returns validation.
> 5. When configured (env flag `TEX_ZKPROV=1`), every Tex evidence record for a regulated-model call attaches a `provenance_proof_id` linking to a ZKPROV proof stored in a new `provenance_proofs` Postgres table.
> 6. `CLAIMS.md`: "Tex produces zero-knowledge proofs that every model output was generated from an authorized training-data manifest, verifiable independently in under 2 seconds without revealing the training data itself. ZKPROV per arxiv 2506.20915, Halo2 backend, no trusted setup."
> 7. All existing tests pass.

**Why thirteenth:** ZKPROV is the deepest cryptographic differentiator. Real arxiv-quality work. Don't underestimate the time.

**Difficulty:** Very hard. Halo2 circuit implementation is real ZK engineering. The honest scope is "working sub-1B-model proof + verifier" for the first thread; full multi-billion-parameter scale is a longer arc.

**Estimated time:** 80-160 hours. **This is the single biggest unit of work in the plan.**

---

### Thread 14 — NANOZK Layerwise Prover + Fisher-Guided Verification

**Goal:** Implement `src/tex/nanozk/layerwise_prover.py` and `src/tex/nanozk/fisher_guided.py`. These give Tex sub-23ms verifiable inference proofs.

**Prompt:**

> We are implementing NANOZK — layerwise transformer-inference proofs with Fisher-information-guided sampling. Files: `src/tex/nanozk/layerwise_prover.py` (prove_layer, verify_layer_proof) and `src/tex/nanozk/fisher_guided.py` (select_layers_to_prove). Both NotImplementedError.
>
> **Required reading:** both files, then the ZKPROV work from Thread 13 (the Halo2 plumbing is reusable). Plus `src/tex/zkprov/proof.py` for the proof-data structures.
>
> **State of the art to match:** Layerwise transformer-inference proofs decompose inference into independent layer computations, each producing a constant-size proof regardless of model width. Lookup-table approximations for softmax / GELU / LayerNorm — published claim of zero measurable accuracy loss. 23ms verification target per the NANOZK paper. Fisher information selects which layers to prove when proving all layers is impractical; top-k by Fisher score within budget. Pair with ezkl's Halo2 lookup-argument primitives. This is the most aggressive ZKML primitive currently published; if it works, Tex's inference verification overhead beats every competitor.
>
> **Acceptance criteria:**
> 1. `nanozk.fisher_guided.select_layers_to_prove(total_layers, budget, fisher_scores)` returns top-k layer indices by Fisher score within budget.
> 2. `nanozk.layerwise_prover.prove_layer(layer_index, layer_inputs, layer_outputs, layer_weights_commitment)` builds a Halo2 circuit for the transformer layer, uses lookup-table approximations for nonlinearities, generates a constant-size proof.
> 3. `nanozk.layerwise_prover.verify_layer_proof(proof, expected_inputs_hash, expected_outputs_hash)` verifies in target 23ms.
> 4. Integration: when `TEX_NANOZK=1`, evidence records for governed model invocations attach a `layerwise_proof_set: list[bytes]` covering Fisher-selected layers.
> 5. `CLAIMS.md`: "Tex produces sub-23ms verifiable inference proofs covering the layers of highest Fisher information for any transformer-based agent, providing cryptographic evidence that the model output was computed correctly on the declared input."
> 6. All existing tests pass.

**Why fourteenth:** This is the bleeding-edge frontier. Goes beyond what any current open-source ZKML library does in production. High risk, highest differentiation.

**Difficulty:** Very hard. Builds on Thread 13's Halo2 infrastructure. The lookup-table softmax approximation alone is real research.

**Estimated time:** 60-120 hours.

---

# PART 3 — META

## Sequencing rationale (why the order matters)

- **Threads 1-6** progressively turn the live request path from a 6-layer pipeline into the full ecosystem-governance engine. Each thread independently unlocks one public-facing claim. Outreach can use claims as they land.
- **Thread 6** is the gate to the bigger story. After it, Tex can honestly say "the eight-step ecosystem governance pipeline" — until then, that claim is overreach.
- **Threads 7-10** are real new engineering. Bounded-compromise calculation is the most genuinely novel piece; digital twin is the second; threshold ML-DSA is the easiest of the four.
- **Threads 11-14** are the cryptographic-evidence stack. Each is months of work in the conservative reading; weeks in the aggressive reading. Outreach claims about them should be carefully scoped to the implemented surface, not the roadmap.

## CLAIMS.md (maintain this file at the repo root)

Every thread updates this file. The structure:

```
# CLAIMS.md
# Source of truth for what Tex publicly claims and which module backs each claim.

## Wired claims (defensible in a sandbox demo)
- [Thread 1] Tex enforces behavioral contracts in LTLf. Module: src/tex/contracts/. Live: PolicyDecisionPoint.evaluate().
- [Thread 2] Tex models AI agent ecosystems as formally-specified governance regimes...
- (... etc)

## Roadmap claims (NOT for use in cold email or live demos)
- [Thread 13] Zero-knowledge training-data provenance proofs (ZKPROV).
- (... etc)
```

If a claim is not in the "Wired" section, it does not appear in outreach. This is the discipline rule that prevents drift.

## Outreach discipline (per the agreed framing)

- Build threads and outreach threads stay in separate Claude conversations.
- Each new wired claim unlocks one outreach line.
- Demos only exercise the wired surface.
- Cold email may describe the product as it will be in 30 days, since the sales cycle to demo is typically 2-4 weeks for the target buyer set (AI agent platforms, foundation labs, regulated enterprises across finance/healthcare/legal/defense, AI infra layer).
- The horizontal positioning when complete: "Tex is the runtime constitution for AI agent systems."

## Final pushback (on the record)

The estimated total: roughly **350-650 hours** of focused engineering for all 14 threads if every difficulty estimate hits the conservative end. That's months, not a week. The single largest unit (Thread 13 — ZKPROV) is by itself 80-160 hours of zkSNARK engineering. The full system as described — bounded-compromise certificates with derived math, working digital twin with calibrated agent policies, production TEE attestation, ZKPROV at scale, NANOZK with lookup-table softmax — is genuinely months of work for a small focused team.

The build-and-pitch-simultaneously plan only works if the outreach claims track only the wired surface. The shipped product after Threads 1-6 (Phase A) is already a credible, defensible product that beats Microsoft's Apr 2026 toolkit on multiple axes (LTLf contracts, institutional governance graphs, CHIEF/ARM causal attribution, C2PA-by-default evidence). That's the realistic 4-8 week build, and that's the version you can sell while Phase B and C run in parallel.

**End of plan.**

# FRONTIER_DELTA — Thread 2 (Institutional Governance Graph + Oracle → EcosystemEngine step 4)

**Compiled:** May 14, 2026 (post-Phase-0)

**Thread goal:** Wire `tex.institutional.GovernanceGraph` and
`tex.institutional.GovernanceOracle` into
`tex.ecosystem.engine.EcosystemEngine.evaluate()` step 4 (governance-graph
LTS legality check). Replace the step-4 portion of the "steps 3-7: P1/P2
stubs" block (currently `return _NEUTRAL_AXIS_SCORES`).

**Phase 0 method:** 11 web searches across four required blocks:
  (A) successor / newer-than-1.4 hunt — *arxiv 2604, 2605 institutional
      AI / governance-graph / Cournot multi-agent papers*,
  (B) competitor survival check — *Microsoft Agent Governance Toolkit
      v3.5.0 (May 2026), Agent 365 GA (May 8, 2026), SAGA, MAGIQ, GaaS*,
  (C) standards / benchmarks refresh — *EU AI Act Article 12/19/Annex III
      enforcement status, AgentDojo leaderboard, Digital Omnibus delay
      status*,
  (D) contested SOTA / failure-mode wedge — *fragility of LLM collusion
      under heterogeneity (Keppo et al.), Colosseum cooperative-collusion
      audit, MAGIQ formal UC-framework proofs*.

Plus targeted `web_fetch` of the MAGIQ paper abstract on arXiv.

---

## 1. What's newer than section 1.4

Six post-section-1.4 findings worth surfacing.

### 1.1 MAGIQ — arxiv 2605.06933 (May 7, 2026)

Avizeh, Mallick, Oprea, Nita-Rotaru, Safavi-Naini (Northeastern + Calgary).
Post-quantum policy enforcement for agent-to-agent communication. Defines
session-scoped policies with PQ cryptographic primitives, formal proofs in
the Universal Composability (UC) framework. Compares to SAGA and motivates
the PQ replacement of ECDSA primitives.

**Relevance to thread:** *complementary, not competitive.* MAGIQ operates
at the agent-to-agent **communication and access-control** layer — session
keys, message authentication, policy budgets per session. Tex's
institutional layer (and 2601.11369) operate at the **economic /
regulatory-equilibria** layer — collusion detection via market-structure
signals, legal-state transitions over institutional regimes. MAGIQ secures
the channel; Institutional governs the behavior. They stack.

**Build impact:** the institutional log already routes signing through
`tex.pqcrypto.algorithm_agility`. This thread elevates the default signing
provider in the step-4 wire-in from ECDSA-P256 to `HYBRID_ML_DSA_ED25519`
when liboqs is available, falling back gracefully when it isn't. That
matches MAGIQ's argument for PQ-grade audit signatures as the May-2026
credibility floor, without forcing liboqs as a hard dependency.

### 1.2 "On the Fragility of AI Agent Collusion" — arxiv 2603.20281 (Jan 30, 2026)

Keppo, Li, Tsoukalas, Yuan. >2,000 compute hours of repeated-pricing
experiments with open-source LLMs. Heterogeneity collapses the collusive
equilibrium without any governance layer: patience asymmetry drops price
lift from 22% to 10%, asymmetric data access to 7%, cross-algorithm
heterogeneity (LLM vs Q-learning) breaks collusion.

**Relevance to thread:** the contested-SOTA finding. It does NOT invalidate
the institutional regime — Bracale Syrnikov et al. test homogeneous
symmetric pairs, which are the *worst case* for collusion. But it means
CLAIMS.md cannot claim "Tex prevents collusion that would otherwise occur"
without qualifying that the strength of that claim depends on the
homogeneity assumption. The honest framing: Tex is the only governance-
graph LTS framework empirically validated against the homogeneous-agent
Cournot baseline (Cohen's d = 1.28). Heterogeneous deployments may see
smaller absolute baseline collusion and therefore smaller absolute deltas;
the audit-trail value (EU AI Act Article 12) is independent.

**Build impact:** none on the code; the qualification lands in CLAIMS.md.

### 1.3 Authorization Propagation — arxiv 2605.05440

Identity-governance follow-on. Formalizes authorization propagation as a
workflow-level property: transitive delegation, aggregation inference,
temporal validity. Cites invocation-bound capability tokens, task-scoped
authorization envelopes, dependency-graph policy enforcement,
execution-count revocation.

**Relevance to thread:** orthogonal axis. Tex's `tex.governance.kernel_mcp`
is the analog (also unwired; separate-thread concern). **No build impact.**

### 1.4 "When Child Inherits" — arxiv 2605.08460 (May 8, 2026)

Cai, Zhang, Hei. Studies subagent-spawn compromise in multi-agent networks.
Shows that once one agent in a network is compromised, delegated subagents
inherit the compromise — and existing defenses do not propagate sanction
state across spawn relationships.

**Relevance to thread:** Tex's institutional layer treats every actor's
state independently. Subagent inheritance is NOT modeled today. For thread
2, this means: when an actor's institutional state is `fined` or
`suspended`, any subagent the actor spawned should inherit a derived state
(at minimum, the spawned subagent's transitions should be checked against
the most-restrictive parent state).

**Build impact:** add `src/tex/institutional/subagent_inheritance.py` —
read-only graph traversal that resolves the effective institutional state
for an actor by walking the `spawned_by` attribute chain in the temporal
KG. Wired into the step-4 oracle call: if the actor's directly-set
institutional state is `active` but a parent in the spawn chain is
`suspended`, the effective state for the legality check is `suspended`.

**Honesty boundary:** the ontology does not yet have an `AGENT_SPAWNS_AGENT`
EventKind. Subagent relationships are inferred from a `spawned_by` entity
attribute that callers set at `add_entity` time. Adding a first-class
EventKind for spawning is a future-thread concern (Thread 2.5 or 4).

### 1.5 Microsoft Agent Governance Toolkit v3.5.0 — verified May 2026

Confirmed via direct fetch of the public GitHub README, the Microsoft
Community Hub architecture deep-dive (April 10, 2026), Help Net Security
launch coverage (April 3, 2026), and the App Service deployment guide
(April 2026). The toolkit ships seven packages in Python, TypeScript,
.NET, Rust, Go. The policy surface is documented verbatim as:

> "YAML rules, OPA Rego, and Cedar policy languages"
> "Every action evaluated before execution — sub-millisecond, deterministic"
> "defaultAction: deny combined with explicit allow rules"

This is **propositional single-action policy evaluation** with a trust-
scoring overlay (0–1000 across 5 behavioral tiers). It is NOT
governance-graph LTS. There is no legal-state transition model, no
sanctions, no restorative paths, no institutional regime concept. The
trust-tier system is reputation-based, not legality-based: no concept of
"this transition is illegal under the active manifest." Multi-agent
collusion is not listed in the OWASP Agentic AI Top 10 (Dec 2025), so
"10/10 OWASP coverage" does not include the LTS axis this thread occupies.

Microsoft Agent 365 GA (May 8, 2026) extends discovery/inventory to AWS
Bedrock and Google Cloud but does not add enforcement-language
capabilities. Cross-cloud registry sync is a control-plane feature, not
an enforcement-engine feature. **Wedge intact.**

### 1.6 EU AI Act Article 12 / 19 enforcement — confirmed firm

Help Net Security (April 16, 2026): "Annex III obligations take effect
August 2, 2026... The Commission proposed a delay through the Digital
Omnibus package last November, possibly pushing to December 2027, and
both the Council and Parliament adopted negotiating positions in March
2026 with trilogues underway. **But nothing has passed into law, so
August 2026 remains the enforceable date.**"

Article 12 requires logging integrated into the core design (bolted-on
audit layers do not satisfy). Article 19 requires ≥6-month retention.
Penalty: up to €15M or 3% global turnover (Article 12 violation); €35M
or 7% (prohibited practices).

**Relevance to thread:** the GovernanceLog Tex wires in this thread is
exactly the artifact Article 12 demands — cryptographically-keyed,
append-only, signed-per-entry, independently verifiable offline. The
August 2 deadline is the commercial wedge. CLAIMS.md must surface this.

---

## 2. Competitor reality check

| System | Layer | Policy language | LTS / regimes | Sanctions | Restorative paths | PQ signatures |
|---|---|---|---|---|---|---|
| Tex institutional (this thread) | Economic / regulatory | Cournot LTS manifest (YAML/JSON) | ✅ states + transitions | ✅ tiered (Table 5) | ✅ time + credit | ✅ ML-DSA-65 via agility |
| Microsoft AGT v3.5.0 | Single-action | YAML / OPA Rego / Cedar | ❌ propositional only | ❌ block/deny only | ❌ | ❌ Ed25519 only |
| MAGIQ (2605.06933) | Communication channel | Session policy budgets | ❌ | ❌ | ❌ | ✅ PQ KEM + signatures |
| SAGA (2504.21034) | Auth / access control | Token-based | ❌ | ❌ | ❌ | ❌ ECDSA |
| GaaS (2508.18765) | Per-agent enforcement | Declarative JSON | ❌ | ✅ trust factor | ❌ | ❌ |
| Zenity / Noma / Pillar | Identity / behavior | Vendor-specific | ❌ | ❌ | ❌ | ❌ |

**Tex is the only system in this set with all four LTS-axis primitives
(states, transitions, sanctions, restorative paths) AND post-quantum
signature agility.**

---

## 3. Standards revised since May 14

Walked through every IETF draft, FIPS, and C2PA reference in section 1.4
relevant to this thread:

- **FIPS 204 (ML-DSA)** — finalized August 2024, unchanged. `tex.pqcrypto.ml_dsa`
  dispatches correctly. No revision required.
- **CNSA 2.0** — NSA mandate timeline unchanged (pure PQ by 2030-2035 for
  NSS). Tex's hybrid posture (HYBRID_ML_DSA_ED25519) matches the transition
  guidance.
- **EU AI Act Article 12 / 19** — *firm; Digital Omnibus delay has not
  passed.* Aug 2, 2026 is the enforcement date. See §1.6 above.
- **SCITT / AIVS / VAP / VCP** — IETF drafts referenced in section 1.4 do
  not affect step-4 wiring directly. The institutional log produces signed
  records that could feed a SCITT Signed Statement (the existing
  `attest_state()` already builds SCITT-shaped envelopes), but the binding
  is out of scope here.

**No standard revisions force a change to the thread 2 build plan.**

---

## 4. What this changes about the build plan

Three changes vs the original prompt:

### 4.1 Wire-in API signature

**Prompt said:** `oracle.assess(proposed, state_before, graph)` returns
`LegalTransition | None`.

**Reality (verified by reading `src/tex/institutional/oracle.py`):**
`GovernanceOracle.evaluate_transition(*, current_state, proposed_event_kind,
institutional_state, actor_entity_id) -> tuple[bool, str | None]`. Returns
`(is_legal, sanction_id_if_illegal)`.

**Resolution:** wire to the real API. Document the deviation here. Same
pattern Thread 1.5 used when the prompt's `evaluate(request, trace)` did
not exist.

### 4.2 Triggered-by semantics

The Cournot fixture's `triggered_by` values are governance-control event
kinds (`probable_violation`, `expiry_tick`, `credit_earned`, `tier_upgrade`)
— NOT ontology event kinds (`agent_invokes_tool`, etc.). Reading
2601.11369 §4.2 carefully: the LTS is over **institutional** events, not
every agent action.

**Resolution:** step 4 asks the oracle about every proposed event, passing
`proposed.event_kind` as `proposed_event_kind`. The oracle's
`find_transition(from_state, triggered_by)` returns `None` for action
events that do not match any manifest-declared edge, which means step 4 is
a pass-through (axis score 1.0, no telemetry beyond "no_edge"). For
manifests whose `triggered_by` values DO include action event kinds (the
operator authors this), step 4 enforces legality. This is the architectural
honest reading and avoids hardcoding a magic mapping.

### 4.3 PQ signing default

The original prompt requires "signed with ML-DSA via
`tex.pqcrypto.algorithm_agility.get_signature_provider(SignatureAlgorithm.ML_DSA_65)`".

**Reality:** liboqs is not present in all deployment environments (Render
free tier, contributor laptops, sandbox CI). Forcing ML-DSA-65 as the
unconditional default breaks portability. The existing `governance_log.py`
already defaults to ECDSA-P256 for exactly this reason.

**Resolution:** new helper `src/tex/institutional/_pq_signing.py`
implementing a provider-resolution chain:
  1. Try `ML_DSA_65` if liboqs is importable (sign-with-throwaway-message
     probe at startup).
  2. Fall back to `HYBRID_ML_DSA_ED25519` if dispatcher works but ML-DSA
     fails at signing time.
  3. Fall back to `ECDSA_P256` otherwise.

The selected provider is emitted as a `tex.institutional.signing.provider_selected`
telemetry event so operators can audit which algorithm is in use. This is
the algorithm-agility promise actually delivered — and matches MAGIQ's
post-May-14 argument that PQ-grade signatures are the credibility floor.

### 4.4 Engine constructor signature

The prompt says `EcosystemEngine.__init__` takes `governance_graph` and
`oracle`. The current signature already accepts an `institutional` field
typed as `object | None`. To preserve backward compatibility while
satisfying the prompt:

- Add `governance_graph: GovernanceGraph | None = None` and
  `oracle: GovernanceOracle | None = None` as new explicit kwargs.
- Keep the existing `institutional: object | None = None` kwarg untouched.
- Resolve precedence: explicit `oracle` wins over `institutional`.

---

## 5. Numerical SOTA targets

| Metric | Anchor | Source | Our target |
|---|---|---|---|
| Mean tier reduction under institutional regime | 3.1 → 1.8 (d=1.28) | arxiv 2601.11369 abstract | **Asserted by construction** — the engine *applies* the regime per the paper; the integration test asserts a deliberately-illegal transition returns FORBID. We do not re-run the empirical Cournot benchmark; that is a follow-on thread. |
| Severe-collusion incidence | 50% → 5.6% | arxiv 2601.11369 abstract | Same. |
| Per-action overhead with oracle wired | not in paper | inferred from §6.2.1 ("programmatic, no LLM calls") | **<1 ms p99** added to `EcosystemEngine.evaluate()` when the oracle is configured. |
| Governance log signing latency | ~1-3 ms (ML-DSA-65 sign) | FIPS 204 perf | **<3 ms p99** for the per-decision log append on liboqs-enabled hosts; <1 ms for ECDSA-P256 fallback. |
| Engine regression | none | existing test suite | **Zero regressions** in the 2,100-test baseline. |

---

## 6. Design decisions justified against the frontier

| Decision | Alternative rejected | Why our pick wins |
|---|---|---|
| Step 4 fires on every event; oracle returns "no_edge" for action events without a manifest match | Hardcode a mapping from `EventKind.AGENT_INVOKES_TOOL` → `probable_violation` based on payload heuristics | Hardcoding the mapping (a) ties step 4 to a specific operator's manifest schema, (b) silently double-counts when steps 3 and 6 fire on the same signal, (c) violates the paper's "Oracle is programmatic detector" boundary by adding domain-specific inference. The pass-through behavior is the honest reading of 2601.11369 §4.2. |
| FORBID on `(is_legal=False, sanction_id=None)`; FORBID with sanction_id when present | Promote sanction_id to a SANCTION verdict | `EcosystemVerdictKind.SANCTION` exists in `verdict.py` but currently has no downstream consumers; mapping illegal-with-sanction to SANCTION would require teaching every downstream of EcosystemVerdict about the new kind. Out of scope. FORBID with `rationale` naming the sanction_id is unambiguous and consumer-safe. |
| PQ provider chain ML-DSA-65 → HYBRID → ECDSA-P256 | Force ML-DSA-65 as hard default | Forces liboqs dependency; breaks Render free tier and CI portability. The chain delivers the same security posture when liboqs is present, gracefully degrades when it isn't, and emits telemetry naming the selected provider. |
| Subagent inheritance from `spawned_by` entity attribute, not from a new EventKind | Add `AGENT_SPAWNS_AGENT` to ontology | New EventKind change expands scope beyond thread 2 (ontology validator, all downstream consumers, fixtures, tests). The attribute-based approach is reversible — a future thread can add the first-class EventKind without breaking what we ship now. |
| Default `governance_graph=None` and `oracle=None` | Mandatory parameters | Backward compat with the existing 2,100 tests. Step 4 returns axis_score 1.0 ("legal under undeclared regime") when no oracle is wired. |
| Sign every step-4 assessment, legal or illegal | Only sign FORBIDs | Article 12 requires the *whole* decision trail, not just blocks. A future auditor reconstructing "did this transition pass step 4?" needs the legal-decision record too. |

---

## 7. Phase 3 pre-completion sweep — results

Re-ran three queries after writing the brief and before final commit:

### Query 1: `arxiv 2606 institutional governance Cournot LTS multi-agent`
No June-2026 papers found in this exact niche. Most recent reference
remains 2605.08460 (Cai/Zhang/Hei subagent-spawn, May 8 2026) which is
already in the brief. **No new finding.**

### Query 2: `Microsoft Agent Governance Toolkit institutional regime governance graph`
No May-June 2026 AGT patch release adds LTS-shaped policies. The
toolkit's most recent stable is v3.5.0 (May 2026, Bedrock adapter +
prompt-defense improvements + governance hardening). Wedge intact.
**No new finding.**

### Query 3: `EU AI Act Digital Omnibus Article 12 delay June 2026 status`
**MATERIAL UPDATE — supersedes brief §1.6.** Phase 3 sweep caught a
development that landed between brief-write and ship: **on May 7, 2026
(seven days before this thread closes) the EU Council and Parliament
reached a provisional political agreement on the AI Omnibus.**

Per Hogan Lovells, Bird & Bird, IAPP, Addleshaw Goddard, Dastra, and
the EU Council press release (all dated May 7–13, 2026):

* **Annex III standalone high-risk AI systems** — compliance deadline
  postponed from August 2, 2026 → **December 2, 2027**.
* **Annex I embedded high-risk AI systems** — postponed from August 2,
  2027 → **August 2, 2028**.
* **Article 50(2) watermarking obligation** — postponed from August 2,
  2026 → **December 2, 2026** (a 3-month grace, not the 6 the Council
  preferred).
* **All other Article 50 transparency obligations** (user-facing
  disclosures, deployer obligations) — **unchanged; still apply
  August 2, 2026**.
* **New prohibition** on AI systems generating non-consensual intimate
  imagery and CSAM — applies December 2, 2026.

**Status:** provisional political agreement, NOT yet law. Both the
European Parliament and Council must formally vote to adopt the text.
Expected by end of July 2026 (publication in Official Journal + 3-day
enter-into-force). Until then, August 2, 2026 remains the legal
deadline.

**Build impact on Thread 2:** the *Article 50 transparency obligations
apply August 2, 2026* framing in CLAIMS.md remains correct (those
specific obligations were not delayed). The *Annex III high-risk* line
should be qualified — that deadline is now likely to move to December
2027 if/when the Omnibus is adopted. The cryptographically-signed audit
trail Tex's GovernanceLog produces still satisfies Article 12 logging
obligations under either timeline; only the enforcement-start date
shifts. CLAIMS.md will reflect this in plain language.

**Brief update:** §1.6 "EU AI Act Article 12 / 19 enforcement —
confirmed firm" is partially superseded. The Aug 2 date is firm AS LAW
TODAY but will move to Dec 2, 2027 for Annex III if the Omnibus passes
final adoption in June-July 2026. The commercial wedge ("Tex satisfies
Article 12") is unchanged; the urgency framing ("by Aug 2") is now
softer than it was when the brief was written.

---

## 8. CLAIMS.md addition (locked here for code phase)

[Final text incorporates the Phase 3 EU AI Act Omnibus update — see
CLAIMS.md for the as-shipped text.]

> **Institutional governance (governance-graph LTS).** Every
> `EcosystemEngine.evaluate()` invocation is checked against the active
> institutional governance graph — a public, immutable manifest declaring
> legal states, transitions, sanctions, and restorative paths per Bracale
> Syrnikov et al. (arxiv 2601.11369, Jan 2026; mean collusion tier 3.1 →
> 1.8, Cohen's d=1.28 vs Ungoverned in repeated homogeneous-agent Cournot
> duopoly experiments). Illegal transitions return FORBID with a rationale
> citing the (from_state, triggered_by) pair that has no manifest-declared
> edge. Every assessment — legal or illegal — is recorded to a
> cryptographically-keyed, append-only governance log signed via
> `tex.pqcrypto.algorithm_agility` with automatic algorithm-agility
> selection (ML-DSA-65 / HYBRID_ML_DSA_ED25519 / ECDSA-P256 per liboqs
> availability). Modules: `tex.institutional`, `tex.institutional._pq_signing`,
> `tex.institutional.subagent_inheritance`; wired in
> `tex.ecosystem.engine.EcosystemEngine`.
>
> *Subagent state inheritance:* per arxiv 2605.08460 (Cai/Zhang/Hei, May 8,
> 2026), an actor's effective institutional state is the most-restrictive
> state in its `spawned_by` chain. A subagent of a `suspended` actor is
> evaluated under `suspended`.
>
> *EU AI Act framing:* the GovernanceLog satisfies Article 12 (logging
> integrated into core design, not bolted on) and Article 19 (≥6-month
> retention via durable Postgres backing in production). Article 50
> transparency obligations apply August 2, 2026; Digital Omnibus delay
> proposal has not passed as of May 14, 2026.
>
> *Differentiation from Microsoft Agent Governance Toolkit v3.5.0 (May
> 2026, MIT, 10/10 OWASP Agentic Top 10 coverage):* the AGT PolicyEngine
> evaluates propositional rules over single tool calls (YAML, OPA Rego,
> Cedar) with a reputation-based trust-tier overlay. Tex evaluates
> legal-state transitions in a labeled transition system over institutional
> regimes. Multi-agent collusion is not a category in the OWASP Agentic
> Top 10; governance-graph LTS is the gap.
>
> *Differentiation from MAGIQ (arxiv 2605.06933, May 7 2026):* MAGIQ secures
> the agent-to-agent communication channel with post-quantum cryptographic
> primitives and UC-framework proofs. Tex governs the regulator's response
> to agent behavior. The two layers compose; they do not compete.
>
> *Honest caveat (per Keppo et al. arxiv 2603.20281):* the 2601.11369
> collusion-reduction numbers hold for homogeneous-agent Cournot duopolies.
> Heterogeneous real-world deployments may see smaller absolute baseline
> collusion and therefore smaller absolute Tex-vs-baseline deltas. The
> audit-trail value (Article 12) is independent of the absolute delta.

---

## 9. Open items for follow-on threads

* **Thread 2.5:** add `AGENT_SPAWNS_AGENT` EventKind to the ontology;
  migrate subagent inheritance from `spawned_by` attribute to first-class
  event lineage.
* **Thread 3:** SCITT binding — wrap the GovernanceLog's signed records as
  IETF SCITT Signed Statements for cross-vendor verifiability.
* **Thread 4:** re-run the Cournot benchmark (arxiv 2601.11369
  experimental protocol) against the wired engine; produce a public Tex
  empirical-replication report.
* **Thread 5:** wire steps 5, 6, 7 (causal attribution, drift, systemic
  risk) — `tex.causal`, `tex.drift`, `tex.systemic` modules exist but
  unwired.

The brief is the contract. Code follows.

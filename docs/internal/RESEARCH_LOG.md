# RESEARCH_LOG — SIEVE (Sparse-Incidence Entity & Vantage Estimator)

> Every architectural choice below is recorded as **"chose X because the literature/field shows Y
> [source, date]"** or, where no prior art exists, as a **labeled novel-synthesis claim**. No choice
> rests on a technique merely because someone named it; each is earned from a cited source AND
> pushed past a stated frontier limit, OR explicitly marked NOVEL.

The organizing commitment that forces every downstream choice:

> **Discovery is a MEASUREMENT problem, not a detection problem.**

Every plane is a calibrated instrument that carries a *self-measured catchability*. Every resolved
agent is a probabilistic entity carrying fusion uncertainty. The headline deliverable is never a
count — it is a **lower-bound-with-CI plus a named-vantage blind-spot ledger**. This frame is what
structurally forces the honesty layer: because each plane feeds *measured* per-plane recall into the
completeness estimator, the engine cannot quietly assume totality.

This document is the generative source for `ARCHITECTURE.md` and `BLIND_SPOT_REGISTER.md`.

---

## 0. Method — how this log was derived

The frontier was surveyed across ten research veins in the evidence bundle (nhi-shadow-ai,
encrypted-traffic, behavioral-fingerprint, kernel-ebpf, entity-resolution, population-estimation,
static-supplychain, mcp-toolgraph, ai-gateways-casb, adjacent-deanon, registries-standards,
frontier-novelty). The recurring structural truth across **all** veins:

> The field splits into two non-overlapping camps. **Credential/declaration-keyed detectors**
> (NHI vendors, registries, OAuth/audit planes, AIP/SPIFFE, OTel) report an observed COUNT and
> imply totality. **Credential-LESS classifiers** (JA4, AgentPrint, FP-Agent, AgentSight) are each
> single-vantage, closed-world, and forgeable. *No one ships the connective tissue: probabilistic
> no-common-key fusion + shared-credential splitting + a calibrated unseen estimate + an honest
> named-blind-spot ledger.* That connective tissue is SIEVE.

Three of the cross-vein `novel_opportunities` recur with `confidence: high` in EVERY vein that has
a completeness section: (a) cross-plane capture-recapture for a calibrated unseen fraction;
(b) a named-blind-spot ledger driven by per-plane detection threshold τ; (c) honeytoken/decoy
fusion that injects the missing common identifier. These three become SIEVE's load-bearing novelty.

---

## 1. THE SIGNAL-PLANE MAP (derived from the research, not from any prompt)

Each plane below is recorded as a **calibrated instrument**: what it physically observes, its
active/passive nature, its latency class (time-to-first-detection), and its self-measured
catchability input to the estimator. The roster is the 14-plane breadth target — SIEVE's 9 core
planes (measurement spine) grafted with SIGNATURE's finer decomposition (more independent capture
occasions → stronger capture-recapture).

| # | Plane | What it physically sees | Active/Passive | Latency class (time-to-first-detection) |
|---|-------|--------------------------|----------------|------------------------------------------|
| P1 | TLS Client-Hello fingerprint (JA4/JA4+/JA4H) | Client SDK/runtime stack (httpx/OpenAI-SDK, Go net/http, aiohttp, curl, Playwright). An anonymity SET, not an identity. | passive | **instant** (pre-HTTP, first packet) |
| P2 | TLS Server-Hello + cert SPKI (JA4S/JA4X) | LLM provider endpoint identity even under ECH; destination-attribution fallback when SNI is encrypted. | passive | **instant** |
| P3 | HTTP/2 framing (Akamai SETTINGS/WINDOW_UPDATE/PRIORITY/pseudo-header order) | Independent client-stack signature used as a **coherence oracle** vs JA4 (JA4=Chrome but h2=Go ⇒ forgery alarm). | passive | **fast** (connection preface) |
| P4 | Token-stream length/timing waveform (TLS record sizes + inter-arrival) | THAT a flow is an LLM agent loop; provider+model+SDK; tool-call bursts; packetization mode 1:1 (chatbot UI) vs bundled (API). | passive | **fast** (first streamed response) |
| P5 | OAuth-grant & consent plane (SaaS/IdP admin APIs) | First- vs third-party consent grants (third-party = shadow-AI ingress), client IDs, scopes, age, last-used. | passive | **slow** (poll-bound) |
| P6 | Cloud control-plane audit (CloudTrail/Azure Activity/K8s audit, streamed) | Which principal called which API when; catches ephemeral seconds-lived identities **if streamed**. | passive | **fast** (streamed) / slow (batch) |
| P7 | Secrets-vault & CI/CD OIDC plane | Dynamic-credential minting, CI OIDC token issuance, pipeline service principals — where ephemeral workload identities are born. | passive | **fast** |
| P8 | Static supply-chain / provenance (import-AST, lockfiles, IaC IAM, SLSA/in-toto, container digests) | **Leading indicator** (agent exists before it egresses); IaC-granted IAM = pre-runtime blast-radius; **provenance-ABSENCE fraction = assumption-free lower bound** on un-attributable agents. | active | **fast** (parse-time) |
| P9 | Host kernel/boundary (eBPF: SSL_read/SSL_write uprobes + syscall tracepoints + exec_id/IMA hash) | Ground-truth: decrypted prompts bound to PID, actual files/sockets/exec, code-hash anchor, lineage. High-trust, low-coverage. **The labeling oracle.** | passive | **instant** |
| P10 | MCP/A2A tool-protocol plane (tools/list, AgentCard, JSON-RPC DAG) | Capability surface = tool set; invocation graph; tool-name MinHash deployment fingerprint; agent-vs-human tell (session negotiates MCP). | both | **fast** |
| P11 | OTel GenAI spans + provider usage/billing API | execute_tool/invoke_agent spans, mcp.session.id, trace_id chains, **per-minute per-key token time-series** for shared-credential decomposition. | passive | **fast** (~5 min billing) / instant (spans) |
| P12 | Client-side interaction biometrics (FP-Agent injected JS) | Keystroke latency, paste-vs-type, scroll-jump, mouse-teleport — agent-vs-human and agent-vs-agent on browser. Web-only, active. | active | **fast** (~1–3 min observation) |
| P13 | Signed-agent identity (Web Bot Auth RFC 9421 / SPIFFE SVID / AIP DID) | Cryptographically-verified operator identity + delegation chain for the opt-in minority. **The marked-recapture calibration anchor, never the discovery mechanism.** | passive | **instant** |
| P14 | Active honeytoken / decoy-MCP / prompt-injection canary lattice | Flushes zero-passive-signal agents; planted unique marker fuses read-footprint to act-footprint; LLM-only injection compliance + sub-1.5s timing confirms agenthood; **bite-rate calibrates per-plane catchability**. | active | **fast** (on bite) |
| **P0** | **Coverage / observability-health plane** (derived) — eBPF ring-buffer drops, un-hookable kernels, kTLS/QUIC/ECH-blinded flows, gateway-vs-edge bypass delta, **token-conservation residual** (billing − OTel spans − network-implied tokens) | What we are PROVABLY failing to see; the raw input to the τ-floor and the unseen estimate. | both | **slow** (aggregated) |

**Per-plane LATENCY profile (time-to-first-detection), summarized:**
- *instant* (≤ first packet / handshake): P1, P2, P9, P13. — These give the earliest possible sighting.
- *fast* (sub-minute to ~5 min): P3, P4, P6(streamed), P7, P8, P10, P11, P12, P14(on-bite).
- *slow* (poll / batch / aggregation-bound): P5, P6(batch audit), P0.

Design consequence of the latency profile: the *instant* planes (TLS handshake + eBPF + signed-id)
are the leading edge of detection and the first capture occasions; the *slow* planes (OAuth poll,
coverage-health aggregation) are completeness/correctness backstops, not first-responders. The
streaming engine must therefore **emit a provisional entity on the first instant-plane sighting**
and *tighten* (never loosen) its confidence as fast/slow planes corroborate.

---

## 2. PER-PLANE TECHNIQUE + CITATION (decision record)

### P1 TLS Client-Hello (JA4/JA4+)
- **Chose** JA4 as a credential-less, instant, anonymity-SET attribute (NOT an identity) **because**
  the field shows GREASE-robust sorted-cipher JA4 separates scripted clients from browsers at
  AUC≈0.998 / F1≈0.973 with top features ja4_b/cipher_count/ext_count [JA4+ spec, FoxIO 2024–2025;
  "When Handshakes Tell the Truth," arXiv 2602.09606, Feb 2026].
- **Pushed past** its named kill (full-stack emulation / utls / curl-impersonate forge a human JA4)
  by demoting JA4 to a *weak blocking key + anonymity-set-weighted edge*, never an identity claim,
  and routing fully-coherent forgeries to a NAMED blind spot. The coherence/forgery oracle below is
  what recovers the lie a single plane cannot.

### P2 TLS Server-Hello + cert SPKI (JA4S/JA4X)
- **Chose** JA4S/SPKI as the ECH-blinded **destination-attribution fallback** **because** ECH
  encrypts inner SNI and "any architecture that depends on SNI is on borrowed time" [Encrypted
  Client Hello deployment, Cloudflare/IETF 2025]. Grafted from SIGNATURE's finer plane split.

### P3 HTTP/2 framing (Akamai fingerprint)
- **Chose** h2 SETTINGS/WINDOW_UPDATE/pseudo-header order as an **independent coherence oracle**
  **because** browser-impersonation libs that forge JA4 usually do NOT also forge the exact h2
  preface [Akamai HTTP/2 fingerprint, Black Hat EU 2017; Scrapfly 2025]. Grafted from SIGNATURE.

### P4 Token-stream waveform
- **Chose** record-size+timing waveform as the "is-this-an-LLM-loop / which provider+model+SDK"
  signal and the **packetization-mode (1:1 vs bundled) agent-vs-human discriminator** **because**
  streaming SSE per-token packetization leaks a provider-distinctive length/timing waveform
  [Whisper Leak, arXiv 2511.03675, Nov 2025; AgentPrint, arXiv 2510.07176, Oct 2025; NetEcho,
  arXiv 2510.25472, Oct 2025; Cloudflare token-length side-channel, 2024-03].
- **Pushed past** its closed-world/topic-classifier framing by inverting it into a **provider+model
  fingerprint as an entity-resolution feature** + an open-set "unseen-model" abstain head.

### P5–P7 Control-plane (OAuth grant / cloud audit / vault-CI-OIDC)
- **Chose** the static∪dynamic∪behavioral tri-source spine and the **first- vs third-party OAuth
  split** as shadow-AI ingress **because** vendor disclosures converge on it [Token Security NHI
  ebook, 2026; Astrix UNC6395, 2025–2026; Oasis Security, 2026-03]. Streamed (not batched) audit
  to catch seconds-lived identities.
- **Pushed past** the credential-keyed totality overclaim: these are treated as ONE incidence
  channel each, feeding the cross-plane estimator; SaaS with no introspection API becomes a NAMED
  blind spot, never a silent zero.

### P8 Static supply-chain / provenance-absence
- **Chose** lockfile/IaC/SLSA parsing as a **leading indicator** and **provenance-ABSENCE fraction
  as an assumption-free lower bound** **because** an agent exists before it egresses (SDK in a
  lockfile predicts a future agent) [Qualys TotalAI MCP-as-shadow-IT, 2026-03; AgentDiscover
  Scanner; Agentproof, arXiv 2603.20356, 2026; CycloneDX AIBOM v1.7 + SLSA/in-toto, 2026]. This is
  a vantage the other proposals underweight — cheap, leading, assumption-free.

### P9 Host kernel/eBPF
- **Chose** SSL_read/SSL_write uprobes + sched_process_exec + bpf_ima_inode_hash as the **highest-
  admissibility ground-truth labeling oracle** **because** boundary tracing recovers decrypted
  prompts bound to a PID with measured code-hash at <3% overhead, no instrumentation [AgentSight,
  arXiv 2508.02736, Aug 2025; Tetragon exec_id, issue #2420; bpf_ima_inode_hash, kernel 5.11+/6.1;
  eBPF-PATROL, arXiv 2511.18155, Nov 2025; SPIFFE/SPIRE selectors].
- **Pushed past** the two-axis identity failures: code-hash alone is too COARSE (10k agents share
  one `python3` hash) and exec_id alone too FINE (every re-exec = new id) — resolved by the
  two-axis entity model (code-hash MERGES, behavior SPLITS). kTLS/QUIC/fileless become NAMED gaps.

### P10 MCP/A2A tool-protocol
- **Chose** the OBSERVED tool-call DAG as the capability/blast-radius map and the tool-set
  MinHash as a cross-plane fusion key **because** the set+sequence of tools an entity exercises IS
  its capability profile, and a SHA256/MinHash over tool names clusters deployments [AegisMCP, arXiv
  2510.19462, 2025-10; Censys MCP census, 2026-04; A2A AgentCard spec, LF 2025–2026; MCP server
  cards SEP-1649/1960]. MinHash (not flat SHA256) so renamed/near-duplicate tool-sets still cluster.

### P11 OTel GenAI spans + billing API
- **Chose** spans + the **per-minute per-key token time-series** as the shared-credential
  decomposition input **because** two agents on one api_key produce a *superposition* of distinct
  spend/cadence/model-mix patterns decomposable by mixture/changepoint methods [OTel GenAI semantic
  conventions v1.41, 2026-05; Anthropic Usage & Cost Admin API, 2025–2026]. Un-attributed spend
  (null api_key/workspace) = shadow surface.

### P12 Client-side interaction biometrics
- **Chose** keystroke/mouse/scroll/paste kinematics as the agent-vs-human and agent-vs-agent
  discriminator **because** behavioral-only fingerprints reach F1≈0.999 and separate agent
  *frameworks* (paste-vs-type, mouse-teleport, 0ms scroll) [FP-Agent, arXiv 2605.01247, May 2026].
  Grafted as its OWN active vantage (SIGNATURE decomposition) rather than collapsed.
- **Pushed past** its closed-world classifier by running OPEN-set: a dense cluster matching no known
  agent is a NEW discovered entity feeding the estimator, not a misclassification.

### P13 Signed-agent identity (calibration anchor)
- **Chose** Web Bot Auth / SPIFFE-SVID / AIP-DID as the **marked-recapture ground-truth cohort**,
  explicitly NOT as a discovery mechanism, **because** signed agents are exactly the honest minority
  you least needed to find — but they ALSO leave JA4/timing footprints, so per-plane recall measured
  against them calibrates the estimator [Web Bot Auth RFC 9421, Cloudflare 2025–2026; AIP, arXiv
  2603.24775, 2026; SPIFFE/SPIRE].
- **Pushed past** AIP's own named gap (cannot catch a compromised-but-still-signing agent) via the
  behavioral-vs-declared divergence detector (see NOVELTY §4 + the incoherence detector).

### P14 Active honeytoken / decoy lattice
- **Chose** a honeytoken FABRIC (decoy MCP tools, canary URLs, honey-credentials, agent-only DOM,
  prompt-injection canaries + sub-1.5s timing gate) **because** it converts a zero-passive-signal
  agent into a detection event, the planted unique marker fuses read- to act-footprint, and the
  injection+timing dual-gate is a near-zero-FP agent-vs-human confirmer [LLM Agent Honeypot, arXiv
  2410.13919, 2024-10; Parallel-Poisoned Web, arXiv 2509.00124, 2025-09; Decoy-MCP honeypot,
  Zeltser 2026]. Bite-rate over a known-size lattice = independent capture occasions.

### P0 Coverage/observability-health (derived)
- **Chose** to make coverage a FIRST-CLASS plane (ring-buffer drops, kernel/TLS-lib inventory,
  ECH-state, gateway-vs-edge bypass delta, **token-conservation residual**) **because** every tool
  drops events silently and reports zero uncertainty; turning the absence of telemetry into a
  *quantified positive shadow-volume signal* is the concrete absence-as-signal mechanism [Falco
  libsinsp ring-buffer drops; Valiant-Valiant impossibility, STOC 2011; SIEVE token-conservation
  residual — see NOVELTY §4]. This plane is the raw input to the τ-floor and the blind-spot ledger.

---

## 3. WHITE SPACES (named)

These are the literature-confirmed gaps that no shipping product or paper occupies, and that SIEVE
is architected to own. Each is the JOIN of two mature-but-siloed fields.

- **WS-1 — Cross-plane capture-recapture for a calibrated unseen-AGENT fraction.** Capture-recapture
  is mature in ecology/epidemiology and **ships** for an analogous problem (IBM Jazz software-defect
  content estimation, ieeexplore 852741) but has **never** been pointed at agents. Every NHI/CASB
  vendor asserts "complete visibility" or a "2–4×" vibe with no CI [CSA shadow-AI, 2026-04; Token/
  Astrix/Oasis]; every detection paper classifies but never estimates the unseen remainder.
- **WS-2 — Probabilistic no-common-key footprint FUSION with calibrated fuse/split confidence.**
  Vendor graphs (Clutch/Oasis/Astrix) correlate only on shared identifiers; cross-domain
  probabilistic ER (FuzzyLink/Splink) exists for voter/text records but is unapplied to fusing
  heterogeneous machine-identity sensor footprints with transitive, uncertainty-carrying resolution.
- **WS-3 — Shared-credential agent counter (clusters-behind-one-secret).** Every credential-keyed
  inventory collapses one credential to one identity by construction; account-sharing cluster-count
  estimation exists for human keystrokes [ResearchGate 247887278] but is unapplied to machine
  activity behind a shared service principal. This is named the single hardest constraint.
- **WS-4 — Honest named-blind-spot ledger driven by a per-plane τ floor.** Every vendor implies
  totality; every paper states limits in prose but ships no machine-readable coverage ledger that
  refuses to estimate into the physically-irreducible zero-signal class.
- **WS-5 — Active flush + injected-identifier fusion as a population-calibration instrument.**
  Honeytokens exist for breach detection; using a designed active-probe layer to (a) flush
  zero-passive-signal agents, (b) inject a cross-plane JOIN KEY, and (c) measure per-plane
  catchability to feed an unseen estimator is a combination no shipping product or paper covers.

---

## 4. NOVEL — not found in prior art today (labeled novel-synthesis)

Each item below is a **labeled novel-synthesis claim**: each component cites a source, but the
*combination* is stated absent from the bundle's prior art and is given a concrete verification with
a negative control. SIEVE adopts **five** non-prompt novelty techniques (quota ≥3 satisfied with
margin). N1–N3 are SIEVE's core; N4–N5 are grafted from CORROBORANT/SIGNATURE.

### N1 — Plane-typed transitivity as a shared-credential SPLITTER  *(NOVEL synthesis)*
- **Claim:** type every fusion edge by its producing plane; require transitive closure ONLY over
  *strong identity-grade* edges (code-hash, honeytoken co-trip, behavioral fingerprint), while
  *weak bridging* edges (shared IP/ASN/service-credential/popular-JA4) MAY violate transitivity.
  A transitivity violation across a weak bridge becomes a **positive detector** that two genuinely-
  distinct agents hide behind one credential.
- **Why beyond frontier:** TransClean [arXiv 2506.04006] and all collective-ER treat every edge
  identically and aim to *remove* inconsistency; no source models edge PROVENANCE to *exploit* the
  shared-key bridge as the splitting signal. The agent-vs-agent-behind-one-credential case is named
  hard-and-unsolved in the NHI/OWASP discourse [WS-3].
- **Verification (tex-enterprise):** plant two distinct recipe agents sharing one self-asserted
  `agent_external_id` (tex_gate trusts the name string blindly). Assert SIEVE resolves them to TWO
  entities via a transitivity violation on the bridging credential edge while their identity-grade
  behavioral/code-hash edges stay within-cluster. **Negative control:** two footprints of ONE agent
  must NOT split.

### N2 — Signed-cohort + honeytoken-lattice catchability CALIBRATION  *(NOVEL synthesis)*
- **Claim:** use the cryptographically-signed agent population [P13] as a known MARKED set to
  *empirically measure* each passive plane's recall, plus a known-size honeytoken lattice [P14] as
  independent recapture occasions — converting capture-recapture's *assumed* catchability into
  *measured* catchability, yielding a defensible unseen-fraction CI calibrated against ground truth.
- **Why beyond frontier:** capture-recapture ships (IBM Jazz) but has never been pointed at agents;
  Web Bot Auth is framed only as access control and the honeypot only as a tripwire. No source uses
  the signed cohort to CALIBRATE per-plane recall or honeytoken bite-rate as recapture.
- **Verification:** hold out a labeled signed/instrumented set; measure each passive plane's
  empirical hit-rate on it; feed those recalls as known capture probabilities; cross-validate by
  plane-ablation (drop a plane, predict its catch, score the error — grafted from CORROBORANT).

### N3 — Honeytoken-fabric injected join key + token-conservation residual  *(NOVEL synthesis)*
- **Claim:** (a) seeding per-vantage UNIQUE markers injects a common identifier into footprints that
  otherwise share none — a marker tripped on plane A and reappearing on plane B provably fuses one
  agent's read- and act-footprints (solving the no-common-identifier case by *injecting* one); and
  (b) continuously reconciling **billing-token totals − OTel-span totals − network-implied tokens**
  turns the ABSENCE of telemetry into a quantified positive shadow-agent-volume signal.
- **Why beyond frontier:** the parallel-poisoned-web paper uses agent-only DOM as a single-page
  tripwire; observability tools assume the agent is instrumented. No source uses planted markers as
  the cross-plane ER JOIN KEY, nor runs the token-conservation check whose residual IS the
  un-instrumented population. This is the single most concrete "absence-as-positive-signal"
  mechanism in any proposal and is directly buildable.
- **Verification:** plant an EVASIVE tex-enterprise agent that bypasses both `onboard_with_tex` and
  `tex_gate` (real file/subprocess/socket side-effect, zero `actions.jsonl` row). Assert (a) the
  bypassing agent's real side-effect is caught by the independent fs/eBPF plane, (b) the decoy
  co-trip fuses its footprints to one entity, (c) the token-conservation residual is non-zero and
  localizes it. **Negative control:** a fully-governed agent yields zero residual and trips no decoy.

### N4 — Cross-plane INCOHERENCE as a first-class positive detector  *(grafted from CORROBORANT; elevated to NOVEL headline)*
- **Claim:** an incoherent footprint — JA4 says Chrome but h2 SETTINGS say Go; browser TLS but
  bundled-API packetization; **signed identity says research-agent but tool-grammar matches a
  deploy-agent** — is itself the highest-confidence positive detector of a deliberately-hiding or
  compromised agent. Forging one plane is cheap (utls/curl-impersonate/httpcloak); forging ALL
  planes mutually-coherently is exponentially hard. The engine surfaces the specific *contradicting
  plane-PAIR* as evidence.
- **Why beyond frontier:** the literature treats JA4/h2/timing as independent detectors to AND/OR;
  no source makes inconsistency-across-planes a first-class detector or surfaces the contradicting
  pair. Critically, this catches the **compromised-but-still-signing agent that AIP explicitly
  cannot** [AIP, arXiv 2603.24775] — divergence between signed-identity and observed behavior raises
  an alarm AIP cannot raise on its own.
- **Why elevated:** in the source proposals this was an *implicit consequence* of typed-transitivity;
  the judge's graft makes it a HEADLINE mechanism with its own evidence surface (the plane-pair).
- **Verification:** plant agents that forge exactly one plane (utls Chrome-JA4 over a Go h2 stack;
  browser-JA4 with bundled-API packetization; valid Web-Bot-Auth signature over deploy-tool grammar).
  Assert each is flagged deliberately-hiding with the correct contradicting plane-pair. **Adversarial
  control:** a fully-coherent agent must NOT trip the detector (false-positive bound).

### N5 — Anonymity-set-weighted edges + Orlitsky-horizon active effort  *(grafted from SIGNATURE)*
- **Claim:** weight every fusion edge by **1/anonymity-set-size** (a JA4 shared by millions
  contributes ≈0 evidence; a honeytoken co-trip ≈certain) with a copula/anonymity-set correction
  for Fellegi-Sunter conditional-independence violation; and frame continuous discovery with the
  **Orlitsky extrapolation horizon** [PNAS 1607774113] where the honeytoken lattice *manufactures
  observation effort on demand* to push the horizon out when a coverage region goes quiet.
- **Why beyond frontier:** industry identity-graph stitching and the bot-fp papers treat fingerprints
  as identities or opaque hashes and hard-merge; none quantify and propagate the anonymity-set as the
  link's epistemic weight, nor use active effort to extend the unseen-species horizon.
- **Verification:** confirm a popular-JA4 bridge alone never merges distinct entities (its edge
  weight ≈0), and that injecting honeytoken effort into a quiet region tightens the estimate's CI.

---

## 5. The ≥3 non-prompt novelty techniques the design adopts (explicit)

Per the novelty quota, SIEVE adopts these five, each labeled NOVEL above and each absent from the
bundle's prior art (the prompt's named techniques — Fellegi-Sunter, capture-recapture/Chao, JA4 —
are *frontier-to-surpass*, never the novelty):

1. **N1** Plane-typed transitivity as a shared-credential splitter.
2. **N2** Signed-cohort + honeytoken-lattice catchability calibration.
3. **N3** Honeytoken-fabric injected join key + token-conservation residual.
4. **N4** Cross-plane incoherence as a first-class positive detector (catches compromised-but-signing).
5. **N5** Anonymity-set-weighted edges + Orlitsky-horizon active-effort continuous discovery.

**Prompt-anchoring self-audit.** Each *named* technique is justified independently from a cited
source AND pushed past a stated frontier limit, never adopted because it was named:
- *Fellegi-Sunter* — chosen as the only label-free (EM), TF-adjusted, missing-field-native,
  receipt-interpretable scoring core [Splink], then pushed past its two limits (conditional
  independence → anonymity-set/copula weighting N5; connected-components over-merge → TransClean
  plane-typed clustering N1, which repurposes the over-merge bug into the splitter).
- *Capture-recapture/Chao* — chosen because every vendor asserts totality and the estimator ships
  (IBM Jazz), then explicitly NOT shipped raw: replaced by SENECA when singletons vanish (the hiding
  regime) and DR-ML/log-linear under heterogeneity (the bundle proves raw Chao "lies optimistically"),
  and calibrated against the signed cohort N2 (which no source does).
- *JA4* — explicitly demoted from identity to a weak anonymity-SET edge with full-stack emulation
  declared a NAMED blind spot — the opposite of a naive fingerprint=agent echo.
- The five novelty mechanisms are combinations no competent engineer could produce from a buzzword
  list — each is conditioned on a specific cited failure mode.

---

## 6. Completeness estimator — decision record (the measurement spine's headline output)

- **Chose** a heterogeneity-robust, evasion-aware, open-population multiple-systems (capture-
  recapture) estimator over RESOLVED entities, with the zero-signal mass carved OUT as a named-
  vantage ledger **because** this is the WS-1 join and the calibrated-uncertainty requirement.
- **Estimator stack (reported as a RANGE, never a point):**
  - Good-Turing sample-coverage Ĉ = 1 − Q1·c/N → headline unseen FRACTION + CI [Blind-Spot-Mass,
    arXiv 2604.05057].
  - iChao2/Chao2 (S_obs + Q1²/(2Q2), bias-corrected at Q2=0, log-normal CI) → absolute unseen-COUNT
    LOWER bound [Chao 1984 / Chiu 2014].
  - conditional-log-linear-among-the-unobserved [arXiv 2407.03539] wrapped in doubly-robust-ML
    [arXiv 2602.09911] → valid CI if EITHER the capture model OR the population model is right;
    interaction terms for known plane correlations (P1 and P3 both proxy "uses requests").
  - **SENECA self-consistent missing-mass [arXiv 2605.00668]** as the default when Q1/Q2 collapse to
    zero — the EXACT regime hiding agents create, where classical Chao breaks ("lies optimistically").
  - Pitman-Yor Gaussian-CLT credible interval [arXiv 2501.16008] for closed-form uncertainty under
    power-law tails (realistic: a few prolific agents + a long rare tail).
  - online behavioral-response (Mb / trap-shy) hazard [arXiv 2106.03811] that INFLATES the band when
    per-entity recapture-rate decays after a probe (real-time evasion → conservative widening).
- **Calibration:** signed cohort recall (N2) + honeytoken bite-rate (N2) supply *measured*
  catchability; **plane-ablation cross-validation** (drop a plane, predict its catch, score the
  error — grafted from CORROBORANT) *empirically validates* the CI rather than assuming it.
- **τ floor / honesty carve-out:** the Valiant-Valiant impossibility bound [STOC 2011] makes τ (the
  per-plane detection threshold) an explicit measured parameter; mass below every plane's τ
  simultaneously is the irreducible blind spot — declared with its missing vantage, NEVER folded
  into N̂, NEVER fake-found.
- **Assumptions + failure modes + interval-widening** are recorded in full in `ARCHITECTURE.md §6`.

---

## 7. Grounding decisions (why reuse only the governance output boundary)

- **Chose** a greenfield engine in `src/tex/discovery/engine/` with its own data model, NOT an
  extension of `reconciliation.py`, **because** the current engine is pure key-equality
  (`reconciliation_key` = source:tenant:external_id.casefold, domain/discovery.py L370–379), which is
  exactly the brittleness SIEVE targets [grounding: reconciliation.py decide() L113-144].
- **Chose** to reuse exactly the governance OUTPUT boundary **because** `StandingGovernance.decide`
  reads the live registry on every action (standing.py L823/L842) and `AgentEvaluationSuite` reads it
  on every evaluation (suite.py L91) — not-in-registry == ungoverned. The one-way adapter must call
  `registry.save(AgentIdentity)` then `discovery_ledger.append(candidate, outcome)`, mirroring
  `service._apply` registry-first/ledger-last (service.py L691-721).
- **Chose** the inner candidate iterator (service.py L358) as the streaming hook and `_handle_candidate`
  (L594-630) as the unchanged unit of streaming work **because** `connector.scan` already returns an
  Iterable and the batch envelope (L336-459) is the only thing to replace.
- **Chose** to WIRE PresenceTracker (presence.py, observe_seen/observe_missing, N-consecutive-miss)
  as the delta primitive **because** it already does false-positive-suppressed disappearance but is
  correctly flagged UNWIRED into `service.scan` — a wiring opportunity, not a rebuild.
- **Chose** to wire the CoverageBoundary admissibility grade (provenance/models.py L238:
  proven|observed|platform_attested|claimed) into per-capability-edge trust **because** the PDP/UI
  must know how much to trust each capability edge — the most rigorous capability-trust primitive
  already present in the repo.
- **Chose** to treat `kernel_ebpf.py` and `network_egress.py` as REPLACE-the-source stubs (their
  grouping/risk/candidate logic is complete; only the in-process `events=`/`flows=` input is a stub)
  **because** the thin slice can run against real tex-enterprise side-effects via the eBPF/fs-diff
  plane today [grounding: connectors/base.py DiscoveryConnector Protocol L88-112; kernel_ebpf.py
  stub events=/replace_events].

---

## 8. Per-plane catchability + latency, as fed to the estimator (the measurement contract)

Every plane emits `Incidence(footprint, plane_id, catchability, observed_at)`. The `catchability`
field is self-measured (N2). `observed_at` + the plane's latency class drive both the open-population
estimator's time axis and the streaming engine's *tighten-only* confidence updates (§1).

| Plane | catchability source (measured, not assumed) | first-detection latency |
|-------|----------------------------------------------|--------------------------|
| P1/P3 | signed-cohort recall on TLS/h2 | instant/fast |
| P4/P11 | signed-cohort recall on waveform/billing + token-conservation cross-check | fast |
| P9 | near-1.0 where a sensor exists (ground truth); ring-buffer drop fraction subtracts | instant |
| P5–P7 | provider-API completeness (declared coverage) | slow/fast |
| P8 | provenance-presence fraction (absence is the lower bound) | fast |
| P10/P12 | honeytoken bite-rate + signed-cohort recall | fast |
| P13 | 1.0 for the signed subset by construction (the marked set) | instant |
| P14 | bite-rate over known-size lattice (the recapture term) | fast (on bite) |
| P0 | drop-counters + bypass-delta + token-residual (negative-space catchability) | slow |

---

*End RESEARCH_LOG.md — SIEVE. Research-derived; every choice cited or labeled NOVEL.*

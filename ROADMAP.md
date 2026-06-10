# Tex Roadmap — Proof-Carrying Control Plane

> Consolidated build checklist derived from a full-thread audit + research synthesis (June 2026).
> Direction: **Tex can only ever say or do what it can prove from a sealed, replayable fact.** Beat the
> detect-and-dashboard incumbents (Zenity / Noma / Pillar / Palo Alto / Lasso) by being *structural +
> cryptographic*, not a better classifier. See `MEMORY` notes `tex-sota-blueprint`, `tex-abstain-boundary`.

**Tags:** `[today]` buildable now on verified code · `[research]` net-new / research-grade (scope as a real project) ·
`[cut]` do not build / delete. **Effort:** S = days · M = 1–2 wk · L = 3 wk+.

---

## Already real & verified (NOT remaining — do not rebuild)
Fail-closed PDP (`engine/pdp.py`) · hash-chained ECDSA evidence ledger (`provenance/ledger.py`) · in-kernel eBPF PEP
(`pep/kernel/`) · RCPS/CRC math (`engine/crc_gate.py`) · anytime-valid OPE (`learning/ope.py`) · two-sided certified
band · CaMeL/IFC structural floor (`camel/`, `specialists/structural_floor.py`) · DTMC lookahead (`systemic/probguard.py`,
unwired) · e-process organ (`drift/_anytime_valid.py`, unwired to risk streams) · grounded text-voice + Bayesian-surprise
selector (`vigil/`) · Vigil hold/seal surface (`tex-systems`).

---

## Top 5 (start here)
- [ ] Phase 0 credibility floor — CI + close the no-auth routes (§A)
- [x] **Deactivate** `nanozk` (decision: keep, don't delete) — the one reputation-risky thing in the repo (§B)
- [ ] WSR bound + LTT joint certificate — the publishable guarantee, ~1–2 days (§E)
- [ ] Durability — wire Postgres so a restart doesn't erase the evidence chain (§C)
- [ ] The spoken-voice loop — keystone demo, client already written (§F)

---

## A. Credibility floor — do first  `[today]`
- [ ] Add CI (GitHub Actions) running the ~242 existing tests — none exists today · S
- [ ] Close the 4 no-auth route groups: `ecosystem_twin / tee / vet / zkprov` (incl. unauthenticated identity-doc revocation, `vet_routes.py:288`) · S
- [x] Flip auth fail-closed — no `_ANONYMOUS`-gets-all-scopes default in prod · S — done: the anonymous everything-allowed fallback is reachable ONLY in a non-production `TEX_APP_ENV`; production-like env (or `TEX_REQUIRE_AUTH=1`) with no keys fails closed (401). `api/auth.py:_is_production_like`. Tests: `tests/test_unblock_auth_failclosed.py`.
- [ ] Lock down CORS — `allow_origins=["*"]` + `allow_credentials=True` (`main.py:1291`) · S
- [~] delete stale `_pending` test — **done** (`tests/_pending/` removed: imported nonexistent `tex.pitch`, wired nowhere; −23 failures). Fix brittle/leaky tests — **partly deferred**: root cause is the discovery scheduler auto-starting + seeding stores during the test app lifespan (fresh stores are independent — verified), not simple cross-instance leakage; `governance_history`(5)/`discovery`(4) + order-dependent `causal/`(1) need the scheduler quiesced / store-lifecycle reset, which is discovery/durable-track architecture. · S

## B. Cut the theater / honesty  `[cut]`
- [x] **Deactivate (not delete)** `nanozk` — decision June 2026: keep in-tree for a future real backend, but make it inert + honest. Done: hard-gated fail-closed verifier (`verify_layer_proof_set` returns `is_valid=False` unless `TEX_NANOZK_ALLOW_SHIM=1`); `DEACTIVATED PLACEHOLDER (research-early)` banner on all 13 files; removed false claims ("first to wire LatticeFold+", "faithful implementation"); `src/tex/nanozk/DEACTIVATED.md` documents how to wire a real backend (DeepProve/EZKL). Regression guard: `tests/nanozk/test_deactivated.py`. NOTE: still trips the repo's fabrication tripwire (HMAC named next to intended-ZK vocab) — accepted false-positive on marked-dead code; resolve later via a narrow tripwire carve-out for `DEACTIVATED`-marked files. · done
- [ ] Quarantine `synthesize_test_eat_jwt` to tests only · S
- [ ] Stop presenting ML-DSA as live (ECDSA-P256 actually runs) and attestation as producing real tokens (verifier-only) · doc
- [ ] Fix factual errors: `c2pa/ledger.py` does not exist → it's `provenance/ledger.py`; say "the **chain** proves integrity," not the standalone signature · doc
- [ ] Stop marketing keyword specialists (`agentarmor/attriguard/clawguard`) as "semantic reasoning" · doc
- [ ] Prune dead weight: `_pending/` tree (34 modules) + unwired compliance layer (14 modules / ~1,900 LOC, 0 wired) · M
- [ ] Publish a `SELF_AUDIT` documenting all the above (owning limits = differentiation) · S

## C. Durability / production-readiness  `[today–research]`
- [ ] Wire the existing Postgres write-through stores as default (behind `DATABASE_URL`) so state/evidence survives restart — or explicitly position as single-process pilot · M
- [ ] Fix Helm contradiction — `replicas: 2` is impossible with in-memory state (inconsistent verdicts, broken chains) · S
- [ ] Provide a real Dockerfile for the web image (`ghcr.io/...tex:latest` has none); `render.yaml` only defines the worker; `.env.example` is empty · M
- [ ] Real observability export (OTel/Prometheus) — today it's homegrown in-process counters · M

## D. Core "truth model" upgrade — Proof-Carrying Control Plane  `[mixed]`
- [ ] Sealed truth object — generalize `provenance/ledger.py` into typed `SealedFact`s (DECISION/ENFORCEMENT/DRIFT/BLAME/IDENTITY/ANSWER), serialized as one canonical PCVR per action · L
- [ ] Multiplicative e-value spine — compose CRC + OPE + drift + per-agent deviation + voice-error into one Ville-bounded sealed scalar · M
- [ ] Durable Governance State Vector Σ — path-dependent governance, reconstructible-by-replay (also fixes in-memory gap) · M
- [ ] Wire the EXISTING `systemic/probguard.py` DTMC+PCTL lookahead into the PDP as a predictive ABSTAIN dimension · M
- [ ] Four-valued RV4 LTLf (permanent-violation=FORBID vs recoverable=ABSTAIN) feeding `engine/hold.py` · M
- [ ] FIDES dual-axis lattice (confidentiality × integrity) upgrade to `camel/capability.py` · M
- [ ] Rule-of-Two structural contract (untrusted-input ∧ sensitive-access ∧ state-change → FORBID) · S
- [ ] Route CaMeL interpreter denial → PDP structural FORBID (instead of deciding locally) · S
- [ ] Offline evidence bundle + standalone verifier (court-exhibit core; mostly packaging what's verified) · M
- [ ] `[research]` SCITT transparency log + witness cosigning (external non-equivocation; Go sidecar + actual witnesses) · L
- [ ] `[research]` Real TEE attestation producer (needs a confidential VM) · L
- [ ] Banzhaf alongside Shapley (`causal/lsh_shapley.py`); Koopman spectrum + ResDMD residual alarm (`systemic/_koopman.py`) · S–M

## E. The abstain boundary — the trust-critical layer  `[mixed]`
**Buildable today (on verified code):**
- [ ] WSR betting confidence sequence into `learning/ope.py:190` (current Howard bound is loose) · S — do first
- [ ] LTT joint two-sided certificate replacing the two independent sweeps in `engine/crc_gate.py`, + ε-collar · S (~1–2 days)
- [ ] SCRC acted-set conditioning of the risk estimand (measure "unsafe among emitted PERMITs") · S
- [ ] Rewrite `_determine_verdict` / `_should_abstain` (`engine/router.py:428/507`) to the unified R0–R4 rule (magic constants → one selective-risk object) · M
- [ ] Wire the EXISTING `drift/_anytime_valid.py` e-process to false-permit + abstain-rate streams → auto-tighten on breach · S–M
- [ ] Seal-as-label return path — add the `CalibrationRecord` constructor from a human seal (zero exist today); gate loosening through PENDING→APPROVED lifecycle; tightening is free · M

**Research-grade (scope honestly — not grafts):**
- [ ] `[research]` Action-class structural ABSTAIN floor (irreversible/high-blast) — the #1 adversarial defense; net-new ontology project (nothing exists in any verdict path) · L
- [ ] `[research]` Credal-conformal typed hold (epistemic/aleatoric via per-decision p-values) · M
- [ ] `[research]` EPIG decision-targeted resolving-question (needs a Layer-6 posterior; keep deterministic map as fallback) · M
- [ ] `[research]` Worst-case-valid CRC (ε-collar calibrated on an adversarial red-team corpus) · M

**Cut:** `[cut]` pseudo-random hold-widening (fights determinism) · runtime L2D learned head (guarantee comes from the gate) · autonomous loosening (must stay human-gated).

### Invariant to enforce (the trust contract)
- [ ] Hard rule in the PDP→voice boundary: **only an ABSTAIN may ever produce a user-facing hold** — no PERMIT/FORBID ever surfaces to the operator · S
- [ ] Hard rule: uncertainty may only ever resolve to ABSTAIN; probabilistic signals may only LOWER a verdict, never raise it (already enforced by CRC gate — make it an explicit, tested invariant) · S

## F. The voice layer (keystone)  `[research]`
- [ ] Build the server-side spoken loop: `/v1/voice/token`, `/v1/ask`, `/v1/speak` + self-hosted STT/TTS gateway (React client already written in `tex-systems`) · L + GPU infra
- [ ] NLI faithfulness/entailment gate on the grounded answerer (drop any claim not entailed by a sealed fact → abstain) · M
- [ ] Deterministic verbalization of load-bearing facts (verdict/hash/bound — zero LLM in that path) · S
- [ ] Seal each spoken answer as a voice-attestation record; add `learning:write` scope to the production proxy key · S

## G. Proof-of-superiority / validation  `[mixed]`
- [ ] Adaptive red-team harness (AgentDojo + "The Attacker Moves Second") in CI, results sealed into the ledger · M
- [ ] The "Replay Trial" flagship demo (structural FORBID survives 10 paraphrases → in-kernel block → offline tamper-verify) · M
- [ ] The honest-decline demo (Tex refuses a question with no sealed evidence, names the missing fact) · S

---

## Suggested sequence
1. **A** + **B** — clear the deck and cut the lie (the credibility floor blocks every provability claim).
2. **E (buildable-today)** + **D (core)** — the joint guarantee + the sealed truth model.
3. **C** — durability (so the evidence survives a restart).
4. **F** — the spoken-voice loop.
5. **G** — the proof harness + flagship demos.
6. **Research organs last** (D/E/F `[research]` items) — each must fail closed to today's behavior.

## Key references
Policies on Paths (arXiv:2603.16586) · Pro2Guard (2508.00500) · CaMeL (2503.18813) · FIDES (2505.23643) ·
"The Attacker Moves Second" (Nasr 2025) · Safe Testing (Grünwald, JRSS-B 2024) · Game-Theoretic Statistics (Ramdas 2023) ·
RCPS (Bates/Angelopoulos, JACM 2021) · Learn-then-Test (2110.01052) · WSR betting CS (2023) · conformal factuality
(Mohri–Hashimoto, ICML 2024) · AI-control (2501.17315) · adaptive monitor attacks (2510.09462, 2511.02997) · SCITT
(draft-ietf-scitt-architecture).

---
---

# WAVE 2 — the Mythos tier (the only forward priority)

> Scoped 2026-06-10 from a research + design + adversarial-feasibility pass (8-domain live-literature frontier sweep →
> 12 competing-design leaps → an adversarial judge that re-verified every code claim against the repo, audited every
> citation for fabrication, and hunted prior art). Method + raw verdicts: workflow `tex-wave2-mythos`.
>
> **Founder directive (2026-06-10): the Mythos tier is the only point.** Build the most powerful, sophisticated governance
> artifact that does not exist anywhere on Earth today — out of tech, theory, and research not yet implemented — and
> implement it *now*. This **supersedes the remaining Wave-1 "buildable-today" items as the priority.** The frontier leads;
> the on-ramps below exist only to put the first green number on a moonshot, never as the destination.
>
> **The honesty doctrine is not the brake on this — it is the weapon.** Anyone can *claim* a frontier system; Tex's mythos
> is that **every frontier claim survives an adversary running our own code.** That is the entire moat. So the four
> non-negotiables ride through Wave 2 untouched — ABSTAIN-only operator surface · monotone-lowering (a signal may only ever
> *lower* a verdict) · fail-closed · zero fabrication (label the maturity, never fake the property; the `nanozk` lesson
> governs absolutely). Every maturity tag below is a **receipt, not a hedge**: it is how we prove we are building the myth
> rather than marketing it. A `speculative` leap that ships its own falsification benchmark *is* the mythos; a polished
> claim with no benchmark is the thing we exist to never be.

## THE CAPSTONE — the artifact that exists nowhere (June 2026)

**The whole point of Wave 2 is one object: a single Tex governance verdict — PERMIT / ABSTAIN / FORBID — sealed and
replayable, that is *simultaneously* all eight of these. No system on Earth emits it today.**

1. **Hardware-attested to the exact guardrail that produced it.** Computed inside a confidential VM; the verdict + the
   policy-bundle measurement + the decision-input hash are folded into the attestation's own signed `report_data`, so a
   host-level adversary who flips the verdict cannot produce a verifier-accepted quote (**L2**). *Prior art attests the
   guardrail **code**; nobody binds the **decision**.*
2. **Proof-carrying in zero knowledge.** A succinct proof that the verdict is the correct output of the sealed arbitration
   relation — fuse → threshold → structural-FORBID floor → monotone gate — over committed scores and a committed policy,
   **without revealing the private facts** (**L1**). *Nobody emits a ZK proof of a governance verdict.*
3. **Post-quantum signed**, composite ML-DSA + classical, so the record still verifies after Q-Day — and the signer's PQ
   maturity is itself a verdict-*lowering* signal (**L10**).
4. **Wrapped in an always-valid risk certificate** that an adaptive *attacker-moves-second* campaign provably cannot push
   past the structural floor — a sealed test-martingale that auto-tightens on any breach (**L7 + L9**).
5. **Floored by a reversibility × blast-radius lattice** no probabilistic score can override, with an RCPS-bounded
   under-classification rate (**L4**).
6. **Carrying a negative-knowledge certificate** — a non-membership proof that Tex holds *no* sealed fact it is concealing,
   so an honest decline is *verifiable*, not asserted (**L3**). *The frontier sweep found no retrievable construction for
   "proof you don't know" — this primitive is genuinely open.*
7. **Witness-cosigned into an inter-org transparency log**, so a regulator in a *different* organization verifies the
   verdict and its evidence **without trusting Tex's log operator** (**L6**).
8. **Produced by a governor that governs itself** — its own controller mutations routed through the same PDP, the same
   ABSTAIN-only surface, the same ledger (**L5**) — and bounded by **certified properties of the output itself**: a
   counterfactual-robustness proof over a sealed paraphrase neighborhood and a quantitative information-flow ceiling on
   what the verdict leaks (**L12**).

**Each of the eight sits at a different maturity (frontier survey below); the capstone is their *composition*, and Wave 2 is
the program to make each property real and green — one falsifiable benchmark at a time — until the composite verdict ships.**
The twelve leaps are those eight properties' load-bearing pieces. We drive each toward its **North-Star ceiling** (the
never-built target) and bank a **first-green on-ramp** to prove the path is real, not painted.

**Verdict taxonomy** — `mythos-now` (never-built, buildable + testable this wave) · `theory-ahead` (theory unproven, but we
can build the artifact **+ the benchmark that earns it** — *the target zone*) · `research-grade` (needs research before a
testable artifact; scope as a project) · `vapor-to-cut` (cannot be built/tested without faking a property — **none of the 12
landed here**, though several were de-scoped off a vapor framing onto a testable one). Pass tally: **1 `mythos-now`, 9
`theory-ahead`, 2 `research-grade`; all `research-early` at honest read** — the prize is being *first*; the cost is that
nothing is `production` until its benchmark is green.

## Frontier synthesis — what is proven vs. theory-but-unbuilt (June 2026)

Real, retrieved-this-session anchors per domain (a handful of designer-supplied ePrint IDs were flagged by the judge as
misattributed — see *Citation hygiene* — so build tracks **re-verify before relying**):

- **zkML / proof-carrying compute.** *Proven:* DeepProve (Lagrange) proves **full small-LLM inference** end-to-end (GPT-2,
  Gemma-3; ~174 tok/min prove, 1–3.7 s verify; >12M proofs) — [DeepProve-1](https://lagrange.dev/blog/deepprove-1); real-time
  zkVMs in production (ZKsync Airbender 21.8 MHz/H100, SP1 Hypercube). *Theory-but-unbuilt:* zk-proof of **backpropagation**
  for a full LLM in native FP at frontier scale ([2606.05433](https://arxiv.org/abs/2606.05433), self-described 36-mo
  roadmap, OP-3 "highest-risk milestone"); **native floating-point** zkVMs ([SoK 2026/525](https://eprint.iacr.org/2026/525)
  — today's zkML proves a *quantized surrogate*, not the fp16 model); binding a proof-of-inference to a **policy/verdict**
  predicate in one artifact (asserted desirable, never demonstrated). NB: a *real published paper* is now titled
  ["NANOZK" (2603.18046)](https://arxiv.org/abs/2603.18046) — **unrelated** to Tex's deactivated `nanozk` placeholder; do not
  conflate.
- **Anytime-valid statistics.** *Proven:* e-processes, betting CS, combining-across-filtrations (Choe–Ramdas
  [2402.09698](https://arxiv.org/abs/2402.09698), JRSS-B 2026), Conformal Selective Acting
  ([2605.20270](https://arxiv.org/abs/2605.20270)). *Unbuilt:* **adversarially-robust / contamination-tolerant** e-processes
  with a degraded-but-honest Ville bound; a **cryptographically-sealed, replayable** e-value certificate (no retrieved work
  binds the betting math to a signed ledger); e-values are **absent from production guardrail tooling**.
- **AI control & adaptive robustness.** *Proven:* adaptive attacks bypass 12 defenses >90%
  ([Attacker-Moves-Second 2510.09023](https://arxiv.org/abs/2510.09023)); GRPO adaptive red-teaming
  ([2606.09701](https://arxiv.org/abs/2606.09701)); Defer-to-Resample **backfires** under adaptive injection
  ([2510.09462](https://arxiv.org/abs/2510.09462)). *Unbuilt / open:* **no control protocol carries an unconditional
  guarantee** against an adaptive untrusted model; reliable prompt-injection refusal does not exist (Meta Rule-of-Two is an
  explicit stopgap); untrusted-monitoring safety **cases** are paper sketches with no re-runnable artifact.
- **Confidential compute & attestation.** *Proven:* Blackwell+TDX **composite GPU attestation** ships
  ([Intel Trust Authority](https://docs.trustauthority.intel.com/main/articles/articles/ita/concept-gpu-attestation.html),
  Phala GPU-TEEs). *Unbuilt / open:* binding a **decision/verdict** (not code execution) into the attestation is the stated
  open problem in [Proof-of-Guardrail (2603.05786)](https://arxiv.org/abs/2603.05786) ("proof-of-execution ≠ proof-of-guardrail
  decision"); compound multi-hop attestation preserving semantic intent ([2605.03213](https://arxiv.org/abs/2605.03213) §VIII-A);
  continuous/liveness attestation that a guardrail kept running.
- **Conformal / credal / decision-targeted info.** *Proven:* conformalized credal sets (NeurIPS 2024
  [2402.10723](https://arxiv.org/abs/2402.10723)), EPIG (AISTATS 2023 [2304.08151](https://arxiv.org/abs/2304.08151)). *Open:*
  a **single joint anytime-valid** certificate bounding false-PERMIT **and** over-abstention on one stream; EPIG retargeted
  to **provably resolve a governance hold**; the certified limit that NLI/embedding hallucination-detection
  cannot distinguish faithful from hallucinated text ([2512.15068](https://arxiv.org/abs/2512.15068)).
- **Crypto transparency & negative knowledge.** *Proven:* C2SP **witness cosigning** ([tlog-witness](https://github.com/C2SP/C2SP/blob/main/tlog-witness.md),
  CoSi [1503.08768](https://arxiv.org/abs/1503.08768)); Key Transparency in production (WhatsApp AKD/SEEMless/Parakeet).
  *Open — the deep one:* **proof of ignorance / negative knowledge for an AI decision-maker** — the sweep found *no
  retrievable construction* for "proof you don't know" as a usable primitive; the closest (VeritasChain CAP-SRP,
  draft-kamimura-scitt-refusal-events) are conceptual / hash-chain logs without the non-membership guarantee.
- **Reflective / corrigible agency & reversibility.** *Proven-on-paper:* provably-corrigible lexicographic agents
  ([Nayebi 2507.20964](https://arxiv.org/abs/2507.20964)) — which **also proves post-hack corrigibility is undecidable**;
  Corrigibility Transformation ([2510.15395](https://arxiv.org/abs/2510.15395)). *Open:* scaling any irreversibility measure
  (relative reachability / AUP) **beyond tabular gridworlds** to real LLM action spaces; **pre-execution** certification of
  irreversibility for a concrete action class (STRATUS/GoEX are heuristic classifiers).
- **PQ signing & agent identity.** *Proven:* AWS KMS ML-DSA GA (Jun 2025); OpenSSL 3.5 ML-DSA; composite ML-DSA+classical
  ([draft-ietf-lamps-pq-composite-sigs](https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/)). *Open:*
  **post-quantum agent/workload identity** (SPIFFE/SPIRE has no PQ integration); a shipped evidence chain with a
  **formally-earned Q-Non-Equivocation** property ([2512.00110](https://arxiv.org/abs/2512.00110) defines the game, nobody
  ships the log); threshold ML-DSA round/trust model is unsettled.

## W2.0 — the enabling seam (land FIRST; unblocks half the wave)

The judges surfaced one blocker that recurs across **L1, L3, L6, L7, L9, L12**: **`SealedFactLedger` (`provenance/ledger.py`)
is tested-but-dead and `engine/pdp.py` never appends a `DECISION` SealedFact today.** Every "seal the verdict, then prove a
property of it" leap is built on a leaf that is not yet produced on the live path. So Wave 2 starts with a tiny, honest seam,
not a Mythos leap:

- [ ] **M0 — DECISION-sealing seam.** Instantiate `SealedFactLedger` on the live runtime and append one canonical
  `SealedFact(DECISION)` per verdict from `engine/pdp.py` — the constitution's 1–2 additive lines calling a self-contained
  module. This makes "show me where Tex seals a decision" answerable, and turns six downstream leaps from *false-seam* to
  *real-seam*. · S–M · **prereq for L1/L3/L6/L7/L9/L12**
- [ ] **M0b — calibration-corpus harness** (`bench/`): a reproducible builder for the labelled corpora three leaps need
  (action-class reversibility×blast labels; FIDES-confidentiality-tagged CRC red-team corpus; closed-world NLI
  answer-vs-sealed-fact pairs). Without real labels the RCPS/QIF/coverage certificates **must read `certified=False`
  (inert)**, exactly like the CRC gate without calibration. · M · **prereq for L4/L11/L12**
- [ ] **M0c — RUNTIME-DEPENDENT backend probes**, all fail-closed: ezkl/Halo2 (L1), real ML-DSA backend (L10), torch+NLI+GPU
  (L11), confidential VM (L2). Each leap ships a deterministic-shim / verifier-only path that runs in CI and an opt-in real
  backend that is **never silently trusted** (inherit the `zkprov`/`nanozk` hard-gate discipline). · S

## North-Star ceilings — what each leap is *actually* driving toward

These are the never-built targets. They are the point. Each is `speculative` today and several sit on stated open problems in
the literature — that is exactly why they are worth being first at. The table that follows is **not** a smaller ambition; it
is the **first green checkpoint** that proves each North-Star path is real and not painted.

- **L1 → ZK proof of the *full specialist-inference pipeline* bound to the verdict** — not just the arbitration relation; the [2606.05433](https://arxiv.org/abs/2606.05433)-class frontier (zk over real model execution), with the policy predicate fused in. *Open problem: nobody binds proof-of-inference to proof-of-policy in one artifact.*
- **L2 → continuous / liveness attestation** that the guardrail ran for the *whole session*, plus *multi-hop compound* attestation across a delegated agent chain ([2605.03213](https://arxiv.org/abs/2605.03213) §VIII-A — explicitly unsolved).
- **L3 → a post-quantum lattice (Module-SIS) non-membership accumulator** for the negative-knowledge proof — "proof you don't know," a primitive the sweep found *no retrievable construction* for, made post-quantum.
- **L4 → pre-execution *certified* reversibility classification across real LLM action spaces** — beyond tabular AUP/relative-reachability (explicitly never scaled), with the irreversibility budget over a trajectory.
- **L5 → fully reflexive governance over the *complete* mutation surface** with a deploy-frozen top stratum and a corrigibility head ([2507.20964](https://arxiv.org/abs/2507.20964)) — a governor that *provably cannot ungovern itself* (against the undecidability wall, by construction not by search).
- **L6 → live external C2SP OmniWitness federation across real independent orgs** + composable cross-org e-values — a governance *interchange standard*, not a dashboard.
- **L7 → an *unconditional* adaptive-adversary completeness bound** — the open problem the whole AI-control field states it does not have — approached via the sealed martingale + non-gameable corpus-coverage.
- **L8 → EPIG over a real Layer-6 posterior** so the resolving question is decision-*optimal*, not a heuristic flag order.
- **L9 → the full multiplicative spine** (drift × per-agent × voice-error) as one Ville-bounded sealed scalar — once every stream carries a genuine e-process null.
- **L10 → threshold / quorum ML-DSA governance verdicts** (TALUS/Mithril-class) with a *formally-earned* Q-Non-Equivocation property ([2512.00110](https://arxiv.org/abs/2512.00110)).
- **L11 → a certified-coverage spoken-proof loop** that beats the NLI certified-limit ([2512.15068](https://arxiv.org/abs/2512.15068)) on a closed-world corpus, end-to-end neural STT → verdict → TTS.
- **L12 → a genuine finite-sample QIF *leakage bound*** (not a point estimate) sealed per verdict, alongside the counterfactual-robustness proof.

## The 12 leaps — first-green on-ramp (the checkpoint that proves the path)

> Each row is the **earnable-this-wave** core of its North-Star above: the narrow claim that is *actually* true once the
> benchmark is green, and the experiment that earns it. Build the on-ramp, bank the number, then push toward the ceiling.

| # | Leap | Verdict | Eff | New module (self-contained) | The narrow claim that is *actually* true | Earns it by |
|---|------|---------|-----|------------------------------|------------------------------------------|-------------|
| **L4** | Action-class reversibility×blast-radius ABSTAIN floor | `mythos-now` | M | `contracts/action_class.py` | A *per-action sealed cert* binding a reversibility×blast **join-semilattice** floor to an **RCPS-bounded under-classification rate** (the lattice-floor itself is **not** novel — OWASP AISVS 9.2.x, [2603.14332](https://arxiv.org/pdf/2603.14332) — the *bounded* version is) | 300-cal/200-test labelled corpus; structural test where score=0.9 on irreversible×public FORBIDs via lattice and score=0.1 cannot silence it |
| **L9** | Live multiplicative e-value spine | `theory-ahead` | L | `engine/risk_spine.py` | The already-honest **drift e-process(es)** wired live as a **monotone-lowering ABSTAIN** trigger, each step sealed — *de-scoped from* multiplying in the per-agent stream (its inputs are heuristic [0,1], not an e-process null) | Ville false-hold ≤0.05 under continuous peeking on N=2000 null streams; calibrated-drift arm detects within bound |
| **L10** | PQ-maturity-gated live signer (ML-DSA) | `theory-ahead` | L | `pqcrypto/pq_durability.py` | Make the **runtime PQ-maturity of the signer a first-class signal that can only LOWER a verdict**: no real ML-DSA backend ⇒ `PQ-durable=false` SealedFact ⇒ any PQ-non-repudiation claim resolves to ABSTAIN (novel vs. [2512.00110](https://arxiv.org/abs/2512.00110), which is purely cryptographic) | Chain-head composite ML-DSA-87+ECDSA sign/verify round-trip (OpenSSL 3.5 confirmed live); maturity-probe fail-closed test (unknown id ⇒ NONE ⇒ ABSTAIN) |
| **L2** | Proof-of-Guardrail: verdict-bound attestation | `theory-ahead` | M | `tee/verdict_binding.py` | Fold the **categorical verdict** + policy-bundle digest + decision-input hash + prior ledger hash into the **composite-attestation `report_data` nonce** (narrowly novel vs. [2603.05786](https://arxiv.org/abs/2603.05786), which attests guardrail *code*) | Test-mode verdict-swap adversary ⇒ `ok=False` (`verdict_nonce_mismatch`), forgery=0 over the suite; **must fix verifier to check TDX `user_data`, not `eat_nonce`** |
| **L1** | zkPDP: proof-carrying verdict in ZK | `theory-ahead` | L | `zkpdp/arbiter.py` | One succinct proof that the **arbitration relation** (fuse→threshold→FORBID-floor→monotone gate) maps committed scores+policy to the claimed verdict — encode monotone-lowering + deny-floor as **UNSAT-when-violated** in-circuit | N=10k: verify accepts iff verdict==live-PDP, **0% accept on flipped verdict**; real ezkl/Halo2 prover/verify/size on the tiny circuit (the deterministic-shim path computes a keyed-hash stand-in — **not** a proof — and must never be cited as one; it inherits the deactivated-placeholder hard-gate discipline) |
| **L7** | Adversary-completeness certificate | `theory-ahead` | L | `adversarial/completeness.py` | An anytime-valid **survival-martingale** over an attacker-moves-second campaign whose null (deterministic floor, E[b]=0) makes "anytime-valid" honest — **with sealed corpus-coverage as a non-gameable first-class field** (else the cert is vacuous-by-construction) | Completeness-holds run (1800 queries, 0 breaches, p=1) **and** an injected-breach run that fires; correct **binary betting martingale** (not the sub-Gaussian form) |
| **L8** | Credal-conformal hold + EPIG resolver | `theory-ahead` | L | `engine/credal_hold.py` | Represent fused risk as a **credal interval** over the fusion weight-polytope (epistemic vs aleatoric), then rank evidence acquisitions by **EPIG** — closed-form LP extrema, deterministic | N=2000 synthetic holds, one true pivot: fraction-resolved-per-question beats dict-order/random; **needs `_compute_confidence` refactored to emit per-stream confidences first** |
| **L12** | QIF + counterfactual-robustness cert | `theory-ahead` | XL | `engine/verdict_certificate.py` | **Split & honest:** robustness half = a genuine Hoeffding `p_low` over a *seeded deterministic paraphrase neighborhood* (upgrades `bench/replay_trial.py`); QIF half = a **point estimate + capacity ceiling log₂3=1.585 bits**, explicitly **not** a finite-sample bound | Robustness p_low on a seeded neighborhood; QIF L_bits reported as data-dependent point estimate ≤ ceiling — *the word "bound" is not used for QIF this wave* |
| **L5** | Reflexive self-governance (meta-circular) | `theory-ahead` | L | `selfgov/governor.py` (+`specialists/metaguard.py`) | Route Tex's **own** controller mutations through the **same PDP / same ABSTAIN surface / same monotone+floor rules**, sealed into the **same ledger** — two-level *deploy-frozen* stratum to kill the regress (delta over Nidus [2604.05080](https://arxiv.org/abs/2604.05080) / Aegis [2603.16938](https://arxiv.org/abs/2603.16938) is the cryptographic replay-of-self-verdicts) | Reflexive-completeness (4/4 seams sealed, 0 chain breaks) + walk-down attack; **blocker: the 4 named seams are NOT the complete mutation surface** (`feedback_loop.py:669/:721`, `memory/system.py:337`, `policy_snapshot_store.py:157`) |
| **L6** | Governance-as-an-inter-org protocol (SCITT) | `theory-ahead` | XL | `interchange/gix.py` (+`gix_witness.py`,`gix_merge.py`) | Org B verifies org A's verdict+evidence **without trusting A's log operator**, via C2SP witness-cosigned checkpoints over a transparency log whose **leaves are governance verdicts**, plus authenticated **mean-merge** federated e-values | Non-equivocation: ≥3 witnesses refuse to cosign a forked/rewritten checkpoint; merge disjointness guard. **Hard-gated on M0 (DECISION-sealing) — the "one line in pdp.py" is false until then** |
| **L3** | Negative-knowledge certificate (provable ignorance) | `research-grade` | L | `evidence/negative_knowledge.py` | A non-membership cert over a **sorted-key accumulator** + **count-conservation** (attempts = permits+abstains+forbids+errors) so an honest decline is *verifiable*, not asserted — genuinely open primitive ([D6](#frontier-synthesis--what-is-proven-vs-theory-but-unbuilt-june-2026): "no retrievable construction") | Omission attack: rebuilding the epoch to hide a PERMIT must break the conservation predicate. **Make-or-break blocker: an upstream *attempt-sealing* hook that does not exist (`grep` empty) — without it `n_attempts` is trust-me.** Build the crypto half now, gate the completeness claim on the hook |
| **L11** | Sealed spoken-proof loop (NLI entailment cert) | `research-grade` | XL | `voice/entailment_cert.py` | **Split:** ship the **seal half now** (commit `model_id`+`λ̂`+calibration-manifest hash into the ECDSA voice chain, model-swap-fails-replay test); keep the **closed-world conformal-entailment** half research-grade until deps land | In-distribution coverage/FPR on a built closed-world corpus. **Blockers: `import transformers` raises in-env, no live prose verbalizer, and the certified NLI limit ([2512.15068](https://arxiv.org/abs/2512.15068))** — "entailment certificate" must not over-promise coverage |

## Build order — the path to the capstone
Not a retreat to incrementalism: every step is a load-bearing piece of the one never-built object, ordered so each unblocks
the next and banks a green number on a moonshot.
1. **W2.0 — the seam that unblocks six frontier leaps.** M0 DECISION-sealing + M0b corpus harness + M0c fail-closed backend probes. The capstone seals a verdict; today `pdp.py` seals none — so this tiny seam is the foundation the myth stands on. *Nothing downstream is honest (or even wired) without M0.*
2. **W2.1 — first-green on-ramps (bank the first real numbers):** **L9** (spine live, drift-first) · **L4** (action-class floor, `mythos-now`) · **L10** (PQ-maturity-gated signer, OpenSSL-3.5 path live) · **L2** (verdict-binding, test-mode). Each is one of the capstone's eight properties, green at its first checkpoint.
3. **W2.2 — frontier certificates:** **L1** (zkPDP: shim → real ezkl/Halo2 backend) · **L7** (adversary-completeness, correct binary martingale) · **L8** (credal-EPIG, after the `_compute_confidence` refactor) · **L12-robustness** (the earnable half).
4. **W2.3 — reflexive + interchange (the boldest):** **L5** (meta-circular governor, after closing the full chokepoint set) · **L6** (inter-org SCITT, XL). These two are where Tex stops being a product and becomes a *protocol that governs itself and others*.
5. **W2.R — research-grade, scoped as real projects (fail closed to today's behavior, never faked):** **L3** (needs the attempt-sealing hook) · **L11-entailment** (needs torch/GPU + closed-world corpus) · **L12-QIF** (ships only as a labeled point-estimate + capacity ceiling, never as a "bound" until the finite-sample estimator exists).
6. **The capstone composition** — once ≥6 of the eight properties are green, compose them onto a single sealed verdict object and ship the demo no competitor can replay: one PERMIT/ABSTAIN/FORBID that is at once ZK-proof-carrying, hardware-attested-to-policy, post-quantum-signed, anytime-valid, reversibility-floored, negative-knowledge-bearing, inter-org-witnessed, and self-governed.

> **Every Wave-2 leap must fail closed to today's verdict** when its backend/corpus/seam is absent: inert certificate, no
> surfaced hold, ABSTAIN-only on the operator surface, monotone-lowering preserved. A green benchmark promotes a leap from
> `research-early`; until then the name yields to the property.

## Citation hygiene (Wave 2)
Citations above were retrieved by the `tex-wave2-mythos` workflow on 2026-06-10 (WebSearch). The adversarial judge flagged a
handful of **designer-supplied ePrint IDs as misattributed** (e.g. an ePrint number reused for the wrong scheme; a couple of
draft-IETF references carried `UNVERIFIED-FROM-MEMORY` from `tee/` docstrings rather than re-fetched). **Build tracks must
re-verify each citation against the primary source before it lands in code or a customer-facing claim.** Foundational works
cited from memory (Howard–Ramdas–McAuliffe–Sekhon CS; Smith min-entropy QIF) are `UNVERIFIED-FROM-MEMORY` and must be pinned
on use. No citation here is load-bearing for a *capability* claim — capability claims rest only on the green benchmarks above.

## Key Wave-2 references (retrieved 2026-06-10)
DeepProve-1 (Lagrange, [lagrange.dev](https://lagrange.dev/blog/deepprove-1)) · zk-frontier-training ([2606.05433](https://arxiv.org/abs/2606.05433)) ·
SoK zkVMs ([2026/525](https://eprint.iacr.org/2026/525)) · "NANOZK" paper, *distinct from Tex's nanozk* ([2603.18046](https://arxiv.org/abs/2603.18046)) ·
Conformal Selective Acting ([2605.20270](https://arxiv.org/abs/2605.20270)) · combining-across-filtrations ([2402.09698](https://arxiv.org/abs/2402.09698)) ·
Attacker-Moves-Second ([2510.09023](https://arxiv.org/abs/2510.09023)) · GRPO red-team ([2606.09701](https://arxiv.org/abs/2606.09701)) ·
Proof-of-Guardrail ([2603.05786](https://arxiv.org/abs/2603.05786)) · compound-attestation gap ([2605.03213](https://arxiv.org/abs/2605.03213)) ·
conformalized credal sets ([2402.10723](https://arxiv.org/abs/2402.10723)) · EPIG ([2304.08151](https://arxiv.org/abs/2304.08151)) ·
NLI certified-limit ([2512.15068](https://arxiv.org/abs/2512.15068)) · C2SP witness cosigning ([tlog-witness](https://github.com/C2SP/C2SP/blob/main/tlog-witness.md)) ·
CoSi ([1503.08768](https://arxiv.org/abs/1503.08768)) · provably-corrigible agents ([2507.20964](https://arxiv.org/abs/2507.20964)) ·
Corrigibility Transformation ([2510.15395](https://arxiv.org/abs/2510.15395)) · Nidus ([2604.05080](https://arxiv.org/abs/2604.05080)) ·
Aegis ([2603.16938](https://arxiv.org/abs/2603.16938)) · action-class authority OWASP AISVS 9.2.x + dynamic-capability binding ([2603.14332](https://arxiv.org/pdf/2603.14332)) ·
PQ audit-evidence Q-Non-Equivocation ([2512.00110](https://arxiv.org/abs/2512.00110)) · composite PQ sigs ([draft-ietf-lamps-pq-composite-sigs](https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/)).

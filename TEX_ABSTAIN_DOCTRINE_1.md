# Tex — The Abstain Doctrine

> The state-of-the-art architecture for the one verdict the operator actually sees.
> Synthesised from the selective-prediction, conformal-risk, learning-to-defer,
> value-of-information, and three-way-decision literatures, foundations through
> the May 2026 frontier. Written in the honest-scorecard register of
> `LAYER_4_STATUS.md`: the vision is uncompromising, the disclosure is total.

---

## 0. The one idea

FORBID stands on a **proof**. PERMIT stands on a **bound**. ABSTAIN, today, stands on
**nothing** — it is the residual middle band of a score, governed by hand-tuned
thresholds, and it is the *only verdict the operator ever experiences* (PERMIT keeps
the glass clean, FORBID blocks in silence). The most rigorous engineering in Layer 4
sits behind the two verdicts no one feels, and the least rigorous behind the one that
costs a human their attention.

The fix is not "a better threshold." It is a category move, the same shape as
*supervised dashboards → autonomous witnessing*, applied to the verdict itself:

> **ABSTAIN stops being a leftover and becomes a typed, certified, self-resolving,
> anytime-valid, cryptographically-sealed object that knows *why* it cannot decide
> and *what single fact* would let it.**

No one in agent governance has built this. The pieces exist in five separate
literatures. The novelty is the fusion, operated over an adversarial agent action
stream, sealed as evidence, and spoken by a voice that hands a human the pivotal
question — never the case file.

We call the operator-facing object **the hold**: Tex *holds* the action (fail-closed,
like FORBID), but unlike FORBID the hold carries forward a named resolution path.

---

## 1. The reframe: a hold is two verdicts wearing one mask

Every literature that has studied "I cannot decide" splits the reason in two, and the
split is the whole game (Hüllermeier & Waegeman 2021; Der Kiureghian & Ditlevsen 2009):

- **Epistemic** uncertainty — *reducible*. "I cannot decide because I lack information
  that exists." Representational gap, missing context, an unseen signal. Resolvable by
  acquiring the fact.
- **Aleatoric** uncertainty — *irreducible*. "I cannot decide because the situation is
  genuinely ambiguous." No fact Tex could fetch resolves it; the call is a judgement.

Today's ABSTAIN treats both identically and dumps both on a human. That is wrong twice:
the epistemic holds never needed a human — they needed *the fact*; the aleatoric holds
are the only ones that genuinely belong to a person, and they arrive unframed, buried in
the same pile.

The advanced hold **diagnoses which kind it is and acts on the difference.** That single
distinction reorganises everything below it. (The dichotomy is contested at the margins —
the same fixed input can be argued either way depending on whether future information
gathering is admitted; ICLR 2025 blogpost, Gruber et al. So we treat the type as a
*calibrated score*, not a hard label, and let the resolution path degrade gracefully.)

---

## 2. The five properties, each with its lineage

### Property 1 — CERTIFIED (a guarantee, not a band)

Today the CRC gate (RCPS; Bates, Angelopoulos, Lei, Malik & Jordan, JACM 2021;
Conformal Risk Control, Angelopoulos, Bates, Fisch, Lei & Schuster, ICLR 2024) bounds
**false-permit only** — one-sided, monotone, demotes PERMIT→ABSTAIN. ABSTAIN inherits
the certificate but the certificate is *about the permit region*. It says nothing about
the hold itself.

Make it **two-sided**. Calibrate two thresholds so the error rate *among the verdicts Tex
actually acts on* is bounded on both sides — a PERMIT leaks unsafe at ≤ α_permit, a FORBID
blocks safe at ≤ α_forbid — and the hold becomes the **certified region where neither side
clears its budget**, with its own coverage guarantee.

Frontier instantiations (all 2025–26, all already half-cited in `crc_gate.py`):
- **SCRC** — Selective Conformal Risk Control (Xu, Guo, Wei, NJIT, arXiv 2512.12844):
  two-stage — select the confident set, then control risk on it. SCRC-T (exchangeable,
  exact finite-sample) / SCRC-I (PAC-style, cheaper).
- **SCOPE** (Badshah, Emami, Sajjad, arXiv 2602.13110): calibrate the acceptance
  threshold so the error rate *among non-abstained decisions* is ≤ α — precisely the
  missing object.
- **SCoRE** (arXiv 2603.24704): the e-value variant; separates marginal deployment risk
  from per-instance selective deployment risk.

Result: the hold carries a certificate of the same caliber as PERMIT's — risk budget,
both thresholds, calibration size, bound method, reproducible by an EU-AI-Act auditor —
now attached to the verdict the operator sees.

### Property 2 — TYPED (epistemic vs aleatoric)

Decompose the uncertainty at the hold point. Proper scoring rules give a clean split
(arXiv 2404.12215): expected conditional entropy → aleatoric; expected pairwise
KL-divergence across the posterior → epistemic. Decision-theoretic framing in
arXiv 2412.20892. This is the discriminator no competitor has, and it is what makes the
hold *smart* rather than merely *honest*.

- High epistemic / low aleatoric → **resolvable**. Do not call a human yet.
- High aleatoric → **judgement**. This one is the human's, and only this one.

### Property 3 — RESOLVING (the single pivotal fact)

For an epistemic hold, compute *which one fact would collapse the indecision*. This is
value of information, the oldest idea in the room (Lindley 1956, expected information
gain; the foundation of Bayesian experimental design).

Critical design choice — **target the decision, not the model**:
- **BALD** (Houlsby et al. 2011; Gal et al. 2017) maximises info gain about model
  *parameters* — and famously chases the most obscure, least relevant inputs.
- **EPIG** — Expected Predictive Information Gain (Bickford Smith et al. 2023) — maximises
  info gain about the *prediction we actually care about*.

Tex wants EPIG, not BALD: the fact that flips *this* permit/forbid call, not the fact that
teaches the model most in general. Implementation lineage: active feature acquisition via
conditional-mutual-information maximisation (arXiv 2508.01957), Fisher-information
unification (arXiv 2208.00549).

Two resolution modes:
- **Self-heal** — if the pivotal fact is something Tex can acquire deterministically
  (re-query a signal, pull the identity record, check a path precondition), Tex acquires
  it and re-evaluates, often collapsing the hold to PERMIT/FORBID **with no human at all**.
  The hold becomes a *self-resolving state*, not a dead end. (Three-way-decision theory
  named this exact open problem 15 years ago — "decreasing the size of the boundary region
  through further information"; Yao, decision-theoretic rough sets, below.)
- **Framed question** — if only a human holds the fact, defer with *the exact question*,
  monospace, one line — not the case file.

### Property 4 — DEFERRED WELL (the human is interrupted only when it pays)

When a hold does reach a human, it must *earn* the interruption. This is learning-to-defer,
done with guarantees:
- Foundations: Madras et al. 2018 (learning to defer); Mozannar & Sontag 2020 (consistent
  surrogate estimators); Montreuil 2026 (AAAI — Bayes-optimal routing, surrogate-consistency
  guarantees, top-k deferral, adversarial robustness for L2D).
- Complement vs defer: DeCoDe (arXiv 2505.19220) — a gate that chooses among autonomous,
  human-only, and genuine human-AI complementarity.
- The tradeoff is real and bounded both ways (HULA, arXiv 2303.06710; PAINT, arXiv 2210.10765;
  "When to ASK", arXiv 2604.02226): too few requests → mistakes; too many → the operator is
  overloaded and the system loses its point. Optimise the **joint** human+Tex outcome with a
  bound on *wrongful deferral* — don't interrupt for something the human will rubber-stamp;
  don't pass something the human would have caught.
- Honesty anchor: selective prediction only improves the joint outcome **if the human
  actually does better on the deferred cases** ("On the Limits of Selective AI Prediction",
  arXiv 2508.07617). So the deferral policy must be calibrated against *real reviewer
  outcomes* — the same Layer-6 dependency the CRC gate already has. We do not get to assume
  the human is an oracle.

The classical guarantee underneath all of this: **KWIK — Knows What It Knows** (Li, Littman,
Walsh): a system that asks the expert *iff* it has insufficient basis to predict, and is
*guaranteed never to act dangerously under a false belief that it knows*. That is the
fail-closed soul of a governance hold, stated as a learning-theory property.

### Property 5 — ANYTIME-VALID (valid right now, not on average)

`LAYER_4_STATUS.md` discloses open item #3: plain conformal assumes exchangeability; under
an adaptive, online-updated **agent action stream** that breaks. The exact fix exists:
- **Conformal Selective Acting** (Khosravi & Huo, Georgia Tech, arXiv 2605.20270, May 2026):
  an **e-process per threshold** delivering *selective risk* control with *anytime-pathwise*
  validity — a certificate that holds at every wall-clock round simultaneously, no matter
  when you look or stop. They name the empty cell prior work left open and fill it.
- Foundation: e-values / e-processes / safe anytime-valid inference (Ramdas, Vovk, Shafer,
  Wang; Ville's inequality; *Game-Theoretic Statistics and Safe Anytime-Valid Inference*,
  Statistical Science 2023). An e-value's expectation under the null is ≤ 1; that single
  constraint yields a Type-I guarantee at *any* stopping time.

This is the difference between "valid on average over a long run" and "valid on this
deployment, this round, right now" — which is exactly what a CISO at 3 a.m. and an
EU-AI-Act auditor both require. It is also the only honest way to certify a stream that
*learns while you watch it*.

### (Property 5½ — SEALED)

Each hold is written to the hash-chained evidence ledger as a first-class object of the
same caliber as a FORBID proof attribution and a PERMIT certificate: the two thresholds,
the uncertainty decomposition, the pivotal fact and its EPIG score, the resolution path
taken (self-heal / defer), the e-process certificate at that round. The witness seals
*why it held* the moment it held — provenance for the hold, not just the block and the pass.

---

## 3. The lineage map (foundations → frontier)

```
Reject option / selective classification
  Chow 1957, 1970 ............ optimal cost-based abstention (Bayes reject rule)
  Bartlett & Wegkamp 2008 .... reject with hinge loss
  El-Yaniv & Wiener 2010 ..... selective classification; the risk–coverage curve
  Cortes/DeSalvo/Mohri 2016 .. learning with rejection
  Geifman & El-Yaniv 2017/19 . SelectiveNet — reject optimised end-to-end

Three-way decisions  (the accept / DEFER / reject trichotomy, with a theory)
  Yao 2009–2011 .............. decision-theoretic rough sets; boundary region = deferment;
                               thresholds from loss functions via Bayesian decision;
                               *names the "shrink the boundary via more info" problem*
  Game-theoretic rough sets .. thresholds as equilibria of competing criteria

Conformal risk control  (distribution-free guarantees)
  RCPS — Bates et al. 2021 ... what PERMIT already uses (one-sided)
  Conformal Risk Control 2024  monotone risk, ICLR
  SCRC 2512.12844 ............ select-then-control, two-sided
  SCOPE 2602.13110 ........... bound error among non-abstained at α
  SCoRE 2603.24704 ........... e-value selective risk (MDR / SDR)
  Conformal Selective Acting    e-process per threshold, anytime selective risk
    2605.20270                  (fixes the exchangeability gap)

Anytime-valid inference (SAVI)
  Ville 1939 ................. the inequality
  Ramdas/Vovk/Shafer/Wang .... e-values, e-processes, testing-by-betting

Uncertainty decomposition
  Hüllermeier & Waegeman 2021  epistemic vs aleatoric, the canonical treatment
  Proper-scoring decomp 2404.12215; decision-theoretic view 2412.20892
  (contested: ICLR 2025 blogpost — treat type as a score, not a label)

Value of information / active acquisition
  Lindley 1956 .............. expected information gain
  BALD — Houlsby 2011, Gal 2017 . info gain on parameters
  EPIG — Bickford Smith 2023 .... info gain on the PREDICTION  ← Tex uses this
  Active feature acquisition 2508.01957 (CMI); Fisher unification 2208.00549

Learning to defer / human–AI complementarity
  Madras 2018; Mozannar & Sontag 2020 (consistency)
  Montreuil 2026 (AAAI) ...... Bayes-optimal routing, top-k, adversarial robustness
  DeCoDe 2505.19220 .......... autonomous / human-only / complementarity gate
  Limits 2508.07617 .......... defer only helps if the human does better
  KWIK (Li/Littman/Walsh) .... never act dangerously under a false belief of knowing

LLM abstention (applied)
  Wen et al. 2025 (TACL) ..... "Know Your Limits" survey (query/model/human-values)
  Yadkori et al. 2024 ........ conformal abstention bounds hallucination rate
  OpenAI 2025 ................ hallucination as an incentive problem (bluffing is rewarded)
  over-refusal caveat ........ R-tuning pushed too far refuses everything — calibrate
```

---

## 4. Why nobody has built this (the category claim)

Each literature owns one property and is blind to the others:

- **Selective-conformal** papers *certify* the abstention band — but never **type** it
  (epistemic vs aleatoric) and never **resolve** it (VOI). Their abstention is still a
  dead end, just a guaranteed one.
- **VOI / active-learning** *resolves* uncertainty — but carries **no distribution-free
  guarantee** on the abstention region and is never wired to a governance verdict.
- **Learning-to-defer** *defers well* — but does not first try to **self-resolve**, and
  the deferral carries **no certificate**.
- **Three-way-decision theory** has the exact accept/defer/reject **trichotomy** and even
  names the shrink-the-boundary problem — but its thresholds are loss-function plug-ins
  with **no finite-sample distribution-free guarantee, no typing, no anytime validity,
  no evidence**.
- **LLM-abstention** work *encourages* "I don't know" — but it's calibration heuristics,
  **no per-decision guarantee, no resolution path, no proof**.

Tex would be the first to fuse all five —
**certified (two-sided, anytime-valid) × typed (epistemic/aleatoric) × self-resolving
(decision-targeted VOI) × deferred-well (joint-outcome L2D, KWIK floor) × sealed
(hash-chained evidence)** — and the first to run it over an **adversarial agent action
stream** and surface it through a **voice** that speaks the pivotal question.

That is a defensible "nobody has this" — not because any one piece is exotic, but because
the integration target (a governance verdict that is simultaneously guaranteed, diagnostic,
self-healing, and auditable) has never been the thing anyone was building toward.

---

## 5. How it lands in the voice doctrine

This is not a bolt-on; it is the voice doctrine *realised*. The operator hears the hold.
The advanced hold gives the voice something worth saying:

- not — "I'm unsure about `bedrock-invoke-03`."  (weak; today)
- but — *epistemic, self-healed:* "I held `bedrock-invoke-03` for a beat — I needed to see
  the caller's identity check. It passed. Released." (no human touched it)
- or — *epistemic, human-held:* "I'm holding `bedrock-invoke-03`. I'd clear it if I knew
  whether this caller is inside the finance boundary. That's the one thing I can't see."
  (the pivotal question, not the file)
- or — *aleatoric:* "I'm holding `bedrock-invoke-03`. This one isn't mine to call — the
  policy and the context genuinely conflict, and that's your judgement, not my computation."
  (honest deferral, framed as judgement)

The object that rises monospace on reach is still the hash and the exact name. The voice
carries the meaning, and the meaning is now the **type + the pivotal question**. The hold
earns the interruption by handing the human exactly the question — never the case file.
Patience is the product; the hold is patience with a reason and a way out.

---

## 6. Honest scorecard

**Shippable now (same calibration dependency as the existing gate):**
- Two-sided conformal band (SCRC-T / SCOPE construction) → the hold gets its own
  certificate. Touches `crc_gate.py`, `router.py`, the decision certificate.
- Deterministic self-heal for the subset of pivotal facts Tex can already fetch
  (identity record, path precondition, a re-queryable signal). Highest near-term leverage:
  it removes human interrupts *today* for the holds that never needed one.

**Frontier (buildable, needs care, partly research):**
- Anytime-valid e-process per threshold (Conformal Selective Acting) — the right object
  for the live stream; more involved than the offline split-conformal gate.
- Decision-targeted VOI (EPIG) over the candidate-fact set — needs a posterior good enough
  to estimate predictive information gain.
- Calibrated joint-outcome deferral — needs real reviewer-outcome labels (Layer 6).

**The limit (disclosed, not hidden):**
- The epistemic/aleatoric split is contested and hard to estimate cleanly; we ship it as a
  calibrated *score* with graceful degradation, never a hard claim.
- Every guarantee is only as honest as the calibration data behind it. Until Layer 6 supplies
  real outcome labels, the certified band and the deferral policy run *inert / pass-through*
  exactly as the CRC gate does today — the *capability* is wired, the *live guarantee* needs
  the operator's data.
- VOI assumes the pivotal fact, once acquired, is trustworthy; under an adversary that can
  *supply* the fact, acquisition itself is an attack surface — self-heal must only ever
  consume signals from inside the sealed boundary, never from the action's own payload.

The honest sentence for a sophisticated room:
> "Our hold is the only governance verdict that tells you *why* it can't decide and *what
> would resolve it* — certified on both sides, valid at every round, and sealed as evidence.
> Here's the part that runs the moment you give us labels, and here's the frontier we're
> hardening." — **not** "it's solved."

---

## 7. Build sequence (and the one entry point)

1. **Two-sided certified band** — turn ABSTAIN into a region with its own certificate.
   *(Foundation; everything else hangs off the certificate object.)*
2. **Deterministic self-heal + EPIG fact-ranking** — the hold names and, where it can,
   fetches the pivotal fact. *(The piece the operator feels first; removes interrupts.)*
3. **Typed hold** — epistemic/aleatoric score routes self-heal vs defer.
4. **Anytime-valid e-process** — upgrade the band for the live adversarial stream.
5. **Calibrated joint-outcome deferral** — once Layer-6 reviewer labels exist.
6. **Seal** — write the hold as a first-class evidence object throughout.

**Entry point: build #1 first.** The certified band is the spine — the typing, the VOI,
and the deferral are all *modifications of, and attachments to, the certificate object*.
Build the resolution path before the certificate and you have a clever feature with nothing
underneath it; build the certificate first and every later property has somewhere to attach.

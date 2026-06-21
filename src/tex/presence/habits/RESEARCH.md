# L3 habits — frontier survey (June 2026)

The question L3 answers: how do you let an agent *notice a pattern in a user's history
and offer it as a rule* without (a) the agent silently rewriting itself, (b) asserting a
pattern that is really noise, or (c) the phrasing model becoming the source of the
"fact." Every citation below was retrieved and read **this session** (2026-06-21);
where the literature is silent, that is stated rather than papered over with an invented
source.

## 1. Auditable agent memory — the design thesis, confirmed by the frontier
The 2026 agent-memory stacks (Letta/MemGPT, Mem0, et al.) make memory an explicit,
editable, inspectable component instead of weights — exactly the substrate S5/L2 already
build on. The decisive finding for L3 is the **auditability trade-off** these surveys
name directly: *"the agent decides what to remember" is harder to audit than "the system
decides on rules you wrote."* L3 is engineered onto the auditable side of that line — it
does NOT let the agent self-edit a profile; it mines a candidate rule deterministically
and a **human seals it**, so what changes is always a rule a person confirmed, carrying
its receipts. ("Top 10 AI Memory Products 2026", Medium; "Agent Memory & Knowledge
Systems Compared (2026)", fountaincity.tech; Letta, "Memory Blocks".)

## 2. Suggest-then-confirm (human-in-the-loop) — the interaction model
The HITL literature supports the "offer, don't assert" loop: *rule- and
constraint-driven HITL ensures domain-specific verifiability and transparency*, and the
strongest systems *combine automated suggestions, human intervention, and explicit
rules* rather than any one alone — humans *confirm or modify* the AI's proposal. There is
also a cautionary result worth heeding: soliciting feedback can *reduce* user trust if it
reads as the system offloading its job (AAAI HCOMP 2022). L3's answer: surface a
hypothesis only when a conservative statistic says it is real (so the operator is asked
rarely and only about strong patterns), and present it with its receipts, not as a chore.
(Springer, "Human-in-the-loop ML: state of the art", 2022; ScienceDirect HITL survey;
AAAI HCOMP 2022 trust study.)

## 3. Avoiding false patterns — support/confidence + the multiplicity guard
Classic association-rule mining gives the vocabulary (support / confidence / lift) and
the standing warning that **confidence alone yields spurious associations** in imbalanced
data — lift > 1 and **domain-expert review of every surfaced rule** are the standard
guards. Notably, the practical literature *"focuses on practical guidance rather than
formal statistical significance / multiple-comparisons corrections"* — i.e. the rigor L3
needs is under-served there, so L3 imports it from testing theory:

- **Wilson score interval** for the dominant-outcome rate. Brown, Cai & DasGupta
  (*Interval Estimation for a Binomial Proportion*, Statist. Sci. 16(2):101–133, 2001)
  recommend Wilson/Jeffreys for small *n* over the Wald interval. Honest caveat they
  prove and L3 carries: Wilson coverage can dip **below** nominal near p≈0/1 even at
  n=100 — so L3 treats the bound as a *screen*, never a guarantee, and never lets k=n
  read as certainty (the bound stays < 1).
- **Multiplicity correction.** Testing many subjects and surfacing any that crosses a bar
  is textbook multiple-comparisons inflation. L3 applies **Bonferroni** over the family of
  subjects tested (`alpha/m`). This is FWER control, chosen deliberately over the more
  powerful **Benjamini–Hochberg FDR** (Benjamini & Hochberg 1995; FDR has more power than
  FWER but *tolerates a fraction of false discoveries*). For a trust-critical "I've
  noticed…", even one false pattern erodes the core promise, so controlling the
  probability of *any* false suggestion (FWER) is the aligned choice; the cost is recall,
  disclosed in `NOTES.md`. (BH *is* applied to pattern mining elsewhere, e.g.
  arXiv:2407.00317 taxonomy-aware co-location detection — the powerful-but-permissive
  path L3 rejects on purpose.)

## 4. Selection bias in a self-generated history — the honest ceiling on confidence
A tenant's sealed records are not an i.i.d. sample; they are the population the tenant's
own prior decisions *selected*. Under data-dependent selection, marginal coverage can
provably fail — Jin & Ren, *Confidence on the Focal: Conformal Prediction with
Selection-Conditional Coverage* (arXiv:2403.03868; JRSS-B 87(4):1239, 2025) — the same
caveat S5's calibration feed already carries. L3 therefore labels its confidence as a
**heuristic consistency screen, selection-biased and fixed-sample**, never a calibrated
coverage guarantee, and notes the e-value/anytime-valid upgrade path for the sequential
(re-mining-across-sessions) case.

## What the frontier does NOT give us (stated, not invented)
No retrieved source provides a turn-key "mine a habit from a sealed governance ledger and
seal it as a revocable, monotone, per-tenant rule" primitive. That composition — a
deterministic miner whose only confirmable action is a *tightening* correction through an
existing sealed-memory write-gate — is L3's own, assembled from the pieces above and
benchmarked by its tests (`tests/presence/habits/`), not borrowed.

## Sources (retrieved 2026-06-21)
- Letta/MemGPT & agent-memory 2026: https://medium.com/@bumurzaqov2/top-10-ai-memory-products-2026-09d7900b5ab1 · https://fountaincity.tech/resources/blog/agent-memory-knowledge-systems-compared/ · https://www.letta.com/blog/memory-blocks
- HITL: https://link.springer.com/article/10.1007/s10462-022-10246-w · https://www.sciencedirect.com/science/article/abs/pii/S0167739X22001790 · https://ojs.aaai.org/index.php/HCOMP/article/view/7464
- Association rule mining: https://en.wikipedia.org/wiki/Association_rule_learning · https://www.appliedaicourse.com/blog/association-rule-mining/
- Wilson interval: Brown, Cai & DasGupta 2001 — https://en.wikipedia.org/wiki/Binomial_proportion_confidence_interval · https://pmc.ncbi.nlm.nih.gov/articles/PMC2706447/
- Multiple comparisons / FDR: https://en.wikipedia.org/wiki/False_discovery_rate · https://arxiv.org/pdf/2407.00317
- Selection-conditional coverage: https://arxiv.org/abs/2403.03868 (JRSS-B 2025)

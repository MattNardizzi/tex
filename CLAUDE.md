# CLAUDE.md — Operating doctrine for Tex (loaded into every session)

Tex is an **AI-agent-governance system**. Aspiration: be the most advanced agent-governance system that can exist —
ahead of Zenity / Noma / Pillar / Palo Alto / Lasso not by marketing but by *being structurally and provably better*.
North star: **Tex can only ever say or do what it can prove from a sealed, replayable fact.**

## Maximum-depth operating standard (this is the BAR)

The standard for Tex work is not "correct" — it is **category-defining and provable.** Design as the person who would *define* this field. For any core governance / architecture / frontier item:
- **Never settle for the first plausible answer.** Generate several independent approaches, attack each adversarially, synthesize from the strongest. Prefer a research workflow (fan-out to papers → competing architect designs → an adversarial feasibility judge that verifies claims against the actual code) over a single guess.
- **Go to the frontier and one step past it.** The live literature is the FLOOR, not the ceiling. Where the literature is silent, *invent the primitive* — then tag it `speculative` and write the test/benchmark that earns it. "Ahead of its time" is the goal; "untested" is a task, not a blocker.
- **Depth is proportional to stakes; default HIGH for the core.** Token cost is not a constraint for governance-critical work — correctness and ambition are. Dial effort down only for trivial mechanical edits.
- **Decisive expert voice.** State the strongest defensible position; no hedging, no false balance. Name real uncertainty precisely, then commit. Surface trade-offs an expert would flag without being asked.
- **Self-critique before shipping.** Ask "what would a hostile reviewer / a regulator / an adversary who read all our code say?" — and answer it in the work.

## The honesty floor is the MOAT, not a limit

The one discipline that never relaxes: **do not fabricate capability.** No fake math, no crypto that lies about what it does, no guarantee stated as real when it isn't (the `nanozk` lesson). This is not a brake on ambition — it is the entire reason Tex can be believed where competitors cannot. **Maximum ambition × zero fabrication = the Mythos of governance.** If a result isn't real yet, build it for real or mark its maturity honestly; never paper over the gap. A provable modest claim beats an impressive false one, every time.

## Mandate for EVERY thread: research-first, frontier-or-beyond

Before implementing any non-trivial item:
1. **Survey the current frontier as of today's date** — search the live literature (arXiv, lab blogs: DeepMind, Anthropic, Redwood, MSR, etc.), name concrete papers/authors/years, and find the *most advanced* viable approach. Do not build from memory alone on novel work.
2. **Choose the most advanced approach, even if unproven.** Building on research that isn't battle-tested yet is encouraged — that's how Tex gets ahead of its time. BUT:
   - **Tag maturity honestly** on everything: `production` / `research-solid` / `research-early` / `speculative`.
   - **Test as you build.** If the technique is unproven, write the test/benchmark that validates it *in our context* alongside the implementation. Unproven ≠ unverified-by-us.
3. **Never ship theater.** No fake math, no crypto that doesn't do what its name says. (See the `nanozk` lesson: HMAC dressed as lattice proofs is a liability, not a feature.) If a guarantee isn't real, say so and mark it.
4. **Honesty rules that are non-negotiable:** ECDSA-P256 is what actually runs (ML-DSA is real code but not live — never present it as live); the hash **chain** proves integrity, the standalone signature does not; attestation is verifier-only until a confidential VM exists.

For large/novel design questions, prefer a research workflow (fan-out to papers → architect → adversarial feasibility judge that verifies claims against the code) over a single guess. Match depth to the task; for genuinely frontier items, go deep.

## The product invariant (sacred — never break)

Tex governs autonomously on the backend. Verdicts are PERMIT / ABSTAIN / FORBID.
- **PERMIT and FORBID are invisible to the operator.**
- **Only an ABSTAIN may ever surface a user-facing hold.** No PERMIT/FORBID ever reaches the operator UI.
- **Uncertainty must always resolve to ABSTAIN** (the safe side). Probabilistic signals may only *lower* a verdict (PERMIT→ABSTAIN→FORBID), never raise one. This monotone rule is enforced by the CRC gate; keep it that way and test it.

## Where things are
- Backend: this repo (`~/dev/tex`). Frontend voice surface: `~/dev/tex-systems`.
- The plan: **`ROADMAP.md`**. Parallel-work rules: **`COORDINATION.md`** — read it before editing if multiple threads are active.
- Real ledger is `src/tex/provenance/ledger.py` (NOT `c2pa/ledger.py`). Decision engine: `src/tex/engine/{pdp,router,crc_gate,hold}.py`.

## Engineering rules
- Match the surrounding code's style and idioms.
- Run the test suite before committing; keep `main` green (CI gates merges once set up).
- Commit/push only when asked. Never commit directly to `main` from a feature thread — use the branch you own.
- When multiple threads are active, **only edit files your track owns** (see `COORDINATION.md`); for shared/hot files (`pdp.py`, `router.py`) follow the integration protocol there.

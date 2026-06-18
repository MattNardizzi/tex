# Handoff prompt — paste into a fresh thread to build the join

Copy everything in the fenced block into a new Claude Code thread opened in `~/dev/tex`.

```
We are building the "Proof-Carrying Action Gate" — joining Tex's decision brain to its
enforcement body so a forbidden agent action is actually blocked, and every allow/deny emits
an offline-verifiable, externally-anchored receipt bound to an attested agent identity.

FIRST: read docs/enforcement/BRAIN-BODY-JOIN.md end to end. It is the full plan, the verified
competitive landscape (this fusion is unowned as of mid-June 2026), the architecture, the
phased build plan, and the honest risks. Don't re-derive what's there.
ALSO read docs/enforcement/RESEARCH-FINDINGS.md — the verified deep-research the plan is built
on (the 3 camps, who has/lacks what, the next-paradigm target, source caveats). When you reach
the SOTA phases (1-4: external anchor, attested identity, in-path proxy, zkML), RE-GROUND in
current research before building — the broad frontier sweep was not completed, so treat the
plan's phase targets as direction, not a verified spec.

Repo: ~/dev/tex  (PYTHONPATH=src ; .venv python3.12 ; on branch feat/proof-carrying-gate)
GitHub MattNardizzi/tex → Render auto-deploys `main` only (this branch does NOT deploy).

The three pieces you are wiring together ALREADY EXIST and work — confirm by reading them:
- BODY:  src/tex/enforcement/gate.py  (TexGate: FORBID raises, wrapped callable never runs;
         every gated execution emits exactly one GateEvent to a configurable observer)
- BRAIN: src/tex/governance/standing.py  (StandingGovernance.decide_for_request(request) — the
         documented in-process PEP bridge; returns DecisionOutcome(verdict, released, ...))
- PROOF: src/tex/discovery/conduit/seal.py  (ConduitReceipt + ConduitProvenanceChain; offline-
         verifiable; optional RFC-3161 external anchor). Verifier pattern:
         scripts/verify_conduit_receipt.py --selftest

YOUR FIRST TASK = Phase 0 ONLY (the smallest slice that proves the join), then STOP and show it:
1. Build a TexEvaluationTransport adapter whose .evaluate(request) calls
   standing.decide_for_request(request) and maps DecisionOutcome -> PERMIT passes / non-release
   blocks. This adapter IS the brain<->body join.
2. Build a GateEventObserver that seals one offline-verifiable receipt per decision (allow AND
   deny) onto a new EnforcementProvenanceChain, reusing the conduit seal machinery; add an
   ENFORCEMENT_DECISION event kind.
3. Write an offline verifier selftest (mirror scripts/verify_conduit_receipt.py --selftest) that
   PROVES: a FORBID blocks the callable AND emits a receipt that verifies; flip one byte in the
   sealed payload -> the verifier rejects it.
Keep it ALL LOCAL — no network, no new infra, no external anchor yet (that's Phase 1).

HARD RULES:
- Show each step RAN (tests/selftest output) before moving on. One small step at a time.
- Do NOT build Phase 1+ yet. Do NOT touch main. Do NOT deploy or push without explicit say-so.
- Never fake it — no rigged demos or planted results. Fail-closed everywhere.
- Pre-existing unrelated test reds to ignore: tests/zkprov (needs sympy; use --ignore=tests/zkprov)
  and one governance_history scheduler test. Run conduit/enforcement tests with PYTHONPATH=src.
- The founder works in plain language and is stretched — be a steady anchor, lead with the vision
  (Tex is the first voice of AI; proof is the receipt), don't pile on complexity.

Start by confirming you've read the plan (3 bullets of the Phase 0 task in your own words), then
propose the smallest first commit and stop for go-ahead.
```

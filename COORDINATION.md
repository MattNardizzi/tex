# COORDINATION.md — running 5–6 threads in parallel without breaking the wiring

Goal: parallelize the `ROADMAP.md` build across many Claude threads with **zero file collisions** and a **green `main`** at all times.

## The mechanism: one worktree + one branch per thread

A **git worktree** is a second working folder backed by the same repo, checked out to its own branch. Threads in
different worktrees CANNOT overwrite each other — they edit different folders, merge through git.

Set up (run once, from `~/dev/tex`):
```bash
cd ~/dev/tex
git worktree add ../tex-unblock   -b track/unblock     # Wave 0: CI + auth + cut nanozk
git worktree add ../tex-abstain   -b track/abstain     # abstain boundary
git worktree add ../tex-truth     -b track/truth       # e-value spine + sealed truth object
git worktree add ../tex-struct    -b track/struct      # structural floor upgrades
git worktree add ../tex-durable   -b track/durable     # durability / Postgres / deploy
git worktree add ../tex-voice     -b track/voice       # spoken-voice loop (+ tex-systems)
git worktree add ../tex-proof     -b track/proof       # validation harness + demos
```
Then **each thread connects to its OWN folder** (`~/dev/tex-abstain`, etc.) — in the Claude app, point the new chat at
that folder. Remove a finished worktree with `git worktree remove ../tex-<name>`.

## Wave order (respect dependencies)

**Wave 0 — Unblockers (land FIRST, fast). `track/unblock`** — can itself be 2 threads (CI/auth vs nanozk) since files are disjoint:
- CI (`.github/`), close 4 no-auth routes, fail-closed auth, CORS — then **cut `nanozk`**.
- Everything else waits until CI is green and nanozk is gone.

**Early interface PR — `track/truth` ships the `TexEvidence`/e-value type FIRST** (tiny PR), because other tracks code against it. Do this before Wave 1 fans out.

**Wave 1 — Parallel build tracks (after Wave 0 + the e-value interface merge):** run all of these at once.

## File-ownership map (DO NOT edit outside your track's paths)

| Track | Folder | Owns these paths |
|---|---|---|
| **unblock** | `tex-unblock` | `.github/`, `api/auth.py`, `api/rate_limit.py`, `api/{ecosystem_twin,tee,vet,zkprov}_routes.py`, `nanozk/` (delete), CORS line in `main.py` |
| **abstain** | `tex-abstain` | `engine/crc_gate.py`, `engine/hold.py`, `learning/ope.py`, `learning/drift.py`, `learning/calibrator.py`, verdict rule in `engine/router.py` |
| **truth** | `tex-truth` | `provenance/ledger.py`, new `domain/evidence.py` (TexEvidence/e-value), `drift/_anytime_valid.py`, evidence-bundle export |
| **struct** | `tex-struct` | `systemic/probguard.py`, `specialists/structural_floor.py`, `camel/capability.py`, `governance/path_policy/ltlf.py`, contracts |
| **durable** | `tex-durable` | `stores/`, `db/`, `memory/`, `deploy/`, `render.yaml`, `Dockerfile` |
| **voice** | `tex-voice` | `api/voice_routes.py` (new: `/v1/ask`, `/v1/speak`, `/v1/voice/token`), the STT/TTS gateway, **`~/dev/tex-systems`** |
| **proof** | `tex-proof` | `bench/`, `adversarial/`, test harnesses, demo scripts |

## Hot/shared files — serialized, never edited in parallel
`engine/pdp.py` and `main.py` (`build_app` wiring) are the integration points multiple tracks need.
**Rule:** a track that needs a `pdp.py`/`main.py` change (a) keeps it MINIMAL (just wire in its new function/signal),
(b) posts a line in the Status table below, (c) merges that small change FAST, (d) everyone else rebases. Never let two
branches sit on divergent `pdp.py` edits. New capabilities should be a self-contained module that `pdp.py` calls via a
stable function — so the `pdp.py` delta is one or two lines.

## Merge protocol (keeps main green)
1. Start each work session: `git pull origin main` into your worktree (rebase or merge main in).
2. Build + **run tests** before any commit. Keep your branch green.
3. Push your branch → open a PR → CI must pass → merge to `main`.
4. **Small, frequent merges** beat big-bang. Rebase onto `main` at least daily.
5. End-of-day integration pass: merge everything green; resolve any `pdp.py`/`main.py` wiring in one short serialized step.

## Status table (each thread updates its row)
| Track | Branch | Owner/thread | Status | Touches pdp.py/main.py? |
|---|---|---|---|---|
| unblock | track/unblock | unblock thread | Wave 0 done: CI workflow + auth on 4 routers + CORS lockdown; PR open. nanozk cut still pending. | CORS line only (1 call → tex.api.cors) |
| abstain | track/abstain | abstain thread | **MERGED (#14)**: act-vs-ask boundary — WSR betting CS (ope.py) + LTT joint two-sided cert/ε-collar/SCRC (crc_gate.py) + R0–R4 unified rule (router.py) + e-detector (learning/drift.py). All behind behavior-preserving defaults; guard suite + monotone-lowering FAIL-test green. | **no** — CRC gate + router already wired in pdp.py; new params default to current behavior, so 0 hot-file edits |
| truth | track/truth | truth thread | **All 5 PRs merged** (#5 TexEvidence type, #6 e-value spine, #9 SealedFacts/PCVR ledger, #11 drift e-process wiring, #13 offline bundle+standalone verifier). Additive only; 65 truth-track + 5 guard tests green. NOT YET WIRED into the live PDP verdict — that 1–2 line `pdp.py` call belongs to the engine/abstain track. | no |
| struct | track/struct | struct thread | **MERGED (#17)**: Pro2Guard predictive ABSTAIN dim + RV4 four-valued LTLf (perm→FORBID / recoverable→ABSTAIN) + FIDES dual-axis camel lattice + Rule-of-Two contract + CaMeL-denial→FORBID. All in owned files (probguard.py, structural_floor.py, capability.py, ltlf.py, contracts/{rule_of_two,rv4_path}.py). | yes — 2 additive lines: `detect_structural_floor(.., request=request)` + `apply_predictive_holds(..)` on the routed branch; +1 import |
| durable | track/durable | durable thread | **MERGED (#7)**: Postgres write-through default-on (+ DB-gated restart-survival test); Helm replicas 2→1 + Recreate + evidence/keys PVC + DATABASE_URL/prod-secret env + TEX_ENV→TEX_APP_ENV fix + probes + scrape; real Dockerfile + .dockerignore; render.yaml web svc + Postgres + disk; .env.example; live OpenMetrics /metrics (+ optional OTLP). | **1 line**: `install_metrics(app)` in create_app (self-contained `observability/metrics.py`) |
| voice | track/voice | voice thread | **MERGED (#10)**: spoken-voice loop — `api/voice_routes.py` (/v1/voice/token, /v1/ask, /v1/speak) + `voice/` (deterministic verbalizer + exact-match faithfulness gate + ECDSA voice-attestation chain) + `gateway/` (self-hosted STT/TTS, offline backend; neural seams labeled). 40 voice/gateway tests green; verdict-path suites still green. tex-systems frontend on-contract. | 1 line (include_router) |
| proof | track/proof | proof thread | **MERGED (#8)**: Wave G — adaptive red-team (attacker-moves-second) → real ASR (static 0% / adaptive 80% / lexical 100% / **structural 0%**), sealed into ECDSA-signed offline-verifiable bundles; Replay Trial + honest-decline demos; CLI no-op gate bug fixed. Gate runs in existing pytest CI. | no |

## Cross-track notes (struct → others)

**New opt-in `request.metadata` keys (all zero-cost no-ops when absent):**
- `systemic_lookahead` → Pro2Guard DTMC predictive ABSTAIN (`systemic/probguard.py`).
- `rv4_path_policies` → four-valued RV4 path policies; permanent→FORBID, recoverable→ABSTAIN (`contracts/rv4_path.py`).
- `rule_of_two` → untrusted ∧ sensitive ∧ state-change → FORBID (`contracts/rule_of_two.py`).

**For the `abstain` track (owns `engine/hold.py`):** the predictive holds raise two
uncertainty flags that `hold._FLAG_PIVOTS` has no tailored pivot for yet —
`systemic_lookahead_risk` (aleatoric: a forward-looking probability → HUMAN_JUDGMENT)
and `rv4_recoverable_violation` (epistemic: a pending future step would resolve it →
SELF_HEAL/HUMAN_FACT). `build_hold` degrades gracefully today (verdict is still ABSTAIN
and a hold is still built); adding those two pivots would give each a precise resolving
question. Non-blocking.

---

# WAVE 2 — Mythos tier track breakdown (the only forward priority)

Wave 2 builds the one never-built **capstone** verdict object (see `ROADMAP.md` → THE CAPSTONE): a single PERMIT/ABSTAIN/FORBID
that is simultaneously ZK-proof-carrying, hardware-attested-to-policy, post-quantum-signed, anytime-valid, reversibility-floored,
negative-knowledge-bearing, inter-org-witnessed, and self-governed. The twelve leaps are its load-bearing pieces. Same
mechanism as Waves 0–1: **one worktree + one branch per track, zero file collisions, green `main` always.** Every leap is a
**self-contained new module** that `pdp.py`/`main.py` calls in **1–2 additive lines** — no two tracks edit a hot file on
divergent lines. Every leap **fails closed to today's verdict** when its backend/corpus/seam is absent (inert certificate,
ABSTAIN-only surface, monotone-lowering preserved). The four non-negotiables (ABSTAIN-only surface · monotone-lowering ·
fail-closed · zero fabrication) are invariants no track may weaken.

## The one hard dependency — land FIRST
**`wave2-seam` (M0)** is a hard prerequisite for **L1, L3, L6, L7, L9, L12.** Today `SealedFactLedger`
(`provenance/ledger.py`) is *tested-but-dead* and `engine/pdp.py` appends **no** `DECISION` SealedFact — so every "seal the
verdict, then prove a property of it" leap is built on a leaf that is never produced on the live path. M0 instantiates the
ledger on the live runtime and appends one canonical `SealedFact(DECISION)` per verdict (the constitution's 1–2 additive
`pdp.py` lines into a self-contained module). **No Wave-2 leap that consumes a sealed decision may claim its `pdp.py` wiring is
"one line" until M0 merges** — several designs asserted a seam that does not exist yet.

## Worktree / branch setup (run once, from `~/dev/tex`)
```bash
git worktree add ../tex-w2-seam        -b track/wave2-seam        # M0: DECISION-sealing + corpus harness + fail-closed backend probes
git worktree add ../tex-w2-actionclass -b track/wave2-actionclass # L4  (mythos-now)
git worktree add ../tex-w2-spine       -b track/wave2-spine       # L9
git worktree add ../tex-w2-pqlive      -b track/wave2-pqlive      # L10
git worktree add ../tex-w2-poguard     -b track/wave2-poguard     # L2
git worktree add ../tex-w2-zkpdp       -b track/wave2-zkpdp       # L1
git worktree add ../tex-w2-advcomplete -b track/wave2-advcomplete # L7
git worktree add ../tex-w2-credal      -b track/wave2-credal      # L8
git worktree add ../tex-w2-vcert       -b track/wave2-vcert       # L12
git worktree add ../tex-w2-reflexive   -b track/wave2-reflexive   # L5
git worktree add ../tex-w2-interchange -b track/wave2-interchange # L6
git worktree add ../tex-w2-negknow     -b track/wave2-negknow     # L3  (research-grade)
git worktree add ../tex-w2-spokenproof -b track/wave2-spokenproof # L11 (research-grade)
```

## File-ownership map (DO NOT edit outside your track's paths)

| Track | Leap | Owns these paths (new unless noted) | `pdp.py`/`main.py` delta |
|---|---|---|---|
| **wave2-seam** | M0 | `engine/pdp.py` DECISION-seal call (owns the shared seam), `provenance/ledger.py` live-instantiation wiring, `bench/wave2_corpus/` (labelled-corpus harness), `pqcrypto/_backend_probe.py` + `tee/_mode_probe.py` (fail-closed RUNTIME-DEPENDENT probes) | **owns** the 1–2 line DECISION-seal in `pdp.py` — everyone else rebases onto it |
| **wave2-actionclass** | L4 | `contracts/action_class.py` (mirrors `rule_of_two.py`/`rv4_path.py`), `tests/test_action_class.py` | 1 line in `detect_structural_floor` (opt-in via `request.metadata['action_class']`) |
| **wave2-spine** | L9 | `engine/risk_spine.py`, `tests/test_risk_spine.py` (reuses `drift/_anytime_valid.py` verbatim) | 1 line: `risk_spine.apply(...)` monotone-lowering hook on the routed branch |
| **wave2-pqlive** | L10 | `pqcrypto/pq_durability.py`, `tests/test_pq_durability.py` (reads `ml_dsa.active_backend_id()`, composite via `algorithm_agility`) | 1 line: emit `PQ-durable` SealedFact + maturity→ABSTAIN signal |
| **wave2-poguard** | L2 | `tee/verdict_binding.py`, `tests/tee/test_verdict_binding.py` (mirrors `decision_bound_nonce`; **fix verifier to check TDX `user_data`, not `eat_nonce`**) | 1 line at the `commands/evaluate_action` seam (test-mode) |
| **wave2-zkpdp** | L1 | `zkpdp/arbiter.py` (reuses `zkprov/backends.py` dispatcher + hard-gate), `tests/zkpdp/` | 0 lines (consumes M0's sealed decision; opt-in proof emission) |
| **wave2-advcomplete** | L7 | `adversarial/completeness.py`, `tests/adversarial/test_completeness.py` (drives `adversarial/adaptive.py`; binary martingale sibling of `drift/_anytime_valid.py`) | 0 lines (Layer-4/5 eval tooling, off the per-request path) |
| **wave2-credal** | L8 | `engine/credal_hold.py`, `tests/test_credal_hold.py`; **+ refactor `engine/router.py:_compute_confidence`** to emit per-stream confidences (coordinate w/ `abstain`-track owner of `router.py` verdict rule) | 1–2 lines threading per-stream confidences into `build_hold` |
| **wave2-vcert** | L12 | `engine/verdict_certificate.py`, `tests/test_verdict_certificate.py`; upgrades `bench/replay_trial.py` (robustness half) | 0–1 line (opt-in cert emission; QIF half ships as labeled point-estimate only) |
| **wave2-reflexive** | L5 | `selfgov/governor.py`, `specialists/metaguard.py`, `tests/test_reflexive_gov.py`; **must enumerate the FULL mutation surface** (`commands/{activate,calibrate}_policy.py`, `governance/standing.py`, `feedback_loop.py:669/:721`, `memory/system.py:337`, `policy_snapshot_store.py:157`, key rotation) | 1 line: route controller mutations through `gate_controller_mutation` |
| **wave2-interchange** | L6 | `interchange/gix.py`, `interchange/gix_witness.py`, `interchange/gix_merge.py`, `tests/interchange/` (RFC-9162 Merkle over `record_hash`; C2SP witness semantics in-tree, live OmniWitness behind a flag) | 1 line (publish-checkpoint hook); **hard-gated on M0** |
| **wave2-negknow** | L3 | `evidence/negative_knowledge.py`, `tests/test_negative_knowledge.py` (sorted accumulator reuses `zkprov/commitment.py`); **blocked on an upstream attempt-sealing hook (M0 extension) — build the crypto half, gate the completeness claim** | 0 lines until the attempt-sealing hook is scoped |
| **wave2-spokenproof** | L11 | `voice/entailment_cert.py`, `tests/voice/test_entailment_cert.py`; ship the **seal half now** (commit `model_id`+`λ̂`+manifest into the ECDSA voice chain), entailment half research-grade until `transformers`/`torch`/GPU land | 0 lines (wires at the existing `voice/voice_gate.py` NLI seam) |

## Hot/shared files — serialized, never edited in parallel
As in Waves 0–1: `engine/pdp.py` and `main.py` are integration points. **`wave2-seam` owns the DECISION-seal `pdp.py` line;**
all other tracks keep their `pdp.py`/`main.py` touch to a single additive call into their self-contained module and rebase
onto `wave2-seam` once it lands. **`engine/router.py`** is shared between `wave2-credal` (the `_compute_confidence` refactor)
and the existing `abstain` track's verdict rule — serialize that one refactor through a small fast PR before `wave2-credal`
fans out. Never let two branches sit on divergent `pdp.py`/`router.py` edits.

## Suggested order (mirrors `ROADMAP.md` → Build order)
1. **wave2-seam (M0)** — unblocks six leaps; nothing sealed-decision-dependent is honest until it merges.
2. **First-green on-ramps:** wave2-spine (L9) · wave2-actionclass (L4) · wave2-pqlive (L10) · wave2-poguard (L2).
3. **Frontier certificates:** wave2-zkpdp (L1) · wave2-advcomplete (L7) · wave2-credal (L8, after the `router.py` refactor) · wave2-vcert (L12 robustness half).
4. **Reflexive + interchange:** wave2-reflexive (L5, after the full chokepoint enumeration) · wave2-interchange (L6).
5. **Research-grade (scope as projects, fail closed):** wave2-negknow (L3) · wave2-spokenproof (L11, entailment half) · wave2-vcert QIF half (labeled point-estimate only).
6. **Capstone composition** — once ≥6 of the eight capstone properties are green, compose them onto one sealed verdict object + ship the replay-proof demo.

## Status table (each Wave-2 thread updates its row)
| Track | Branch | Leap | Status | Touches pdp.py/main.py? |
|---|---|---|---|---|
| wave2-seam | track/wave2-seam | M0 | not started — **prereq for L1/L3/L6/L7/L9/L12** | yes (owns DECISION-seal line) |
| wave2-actionclass | track/wave2-actionclass | L4 | **PR open**: `contracts/action_class.py` — reversibility×blast IntEnum join-semilattice (UNKNOWN fail-closed tops, worst-step join), fixed FORBID/ABSTAIN/NEUTRAL cell map, opt-in `metadata['action_class']` (no-op absent; reads no envelope), single-hypothesis Hoeffding-Bentkus UCB on the **under-classification** rate (reuses `crc_gate`; `certified=False` until a *field* corpus — synthetic computes-but-abstains), anti-circular 300-cal/200-test corpus w/ tripwire. ONE additive call in `detect_structural_floor` (FORBID cell only; ABSTAIN recorded-only, rv4-recoverable precedent). Earnable tests green: 0.9 score forbids *via the lattice* / 0.1 can't silence / spoofed bundle can't fire. 111 passed (named verdict-path set + new). | **no** — 1 additive call in `detect_structural_floor`; zero pdp.py/main.py |
| wave2-spine | track/wave2-spine | L9 | not started | 1 line |
| wave2-pqlive | track/wave2-pqlive | L10 | not started | 1 line |
| wave2-poguard | track/wave2-poguard | L2 | not started | 1 line (test-mode) |
| wave2-zkpdp | track/wave2-zkpdp | L1 | not started — needs M0 + real ezkl/Halo2 backend for the regulator-grade path | 0 lines |
| wave2-advcomplete | track/wave2-advcomplete | L7 | not started — needs correct binary martingale | 0 lines |
| wave2-credal | track/wave2-credal | L8 | not started — needs `_compute_confidence` refactor first | 1–2 lines |
| wave2-vcert | track/wave2-vcert | L12 | not started — robustness half earnable; QIF half = labeled point-estimate | 0–1 line |
| wave2-reflexive | track/wave2-reflexive | L5 | not started — needs FULL mutation-surface enumeration | 1 line |
| wave2-interchange | track/wave2-interchange | L6 | not started — hard-gated on M0 | 1 line |
| wave2-negknow | track/wave2-negknow | L3 | not started — blocked on attempt-sealing hook | 0 lines |
| wave2-spokenproof | track/wave2-spokenproof | L11 | not started — seal half now; entailment needs torch/GPU + corpus | 0 lines |

## Citation discipline (Wave 2)
Citations in `ROADMAP.md` were retrieved by the `tex-wave2-mythos` workflow on 2026-06-10. The adversarial judge flagged a
handful of designer-supplied ePrint IDs as misattributed and a few IETF drafts as `UNVERIFIED-FROM-MEMORY` (carried from
`tee/` docstrings). **Before any citation lands in code, a docstring, or a customer-facing claim, the owning track
re-verifies it against the primary source.** No Wave-2 *capability* claim rests on a citation — only on a green benchmark.

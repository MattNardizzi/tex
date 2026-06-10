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
| abstain | track/abstain | — | not started | yes — verdict wiring |
| truth | track/truth | — | not started | maybe — evidence emit |
| struct | track/struct | struct thread | Structural-floor hardening DONE (5): Pro2Guard predictive ABSTAIN dim + RV4 four-valued LTLf (perm→FORBID / recoverable→ABSTAIN) + FIDES dual-axis camel lattice + Rule-of-Two contract + CaMeL-denial→FORBID. All in owned files (probguard.py, structural_floor.py, capability.py, ltlf.py, contracts/{rule_of_two,rv4_path}.py). 763 tests green (excl. pre-existing rustworkx lib failure I don't own). PR pending. | yes — 2 additive lines: `detect_structural_floor(.., request=request)` + `apply_predictive_holds(..)` on the routed branch; +1 import |
| durable | track/durable | — | not started | no |
| voice | track/voice | — | not started | no (new routes) |
| proof | track/proof | — | not started | no |

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

# CURATION.md — public-repo front-door curation (track/onramp, 2026-06-12)

The public repo (`github.com/MattNardizzi/tex`) greets a visitor with internal
operator docs and build artifacts. This file lists every curation action this
track **executed** (staged on this branch for review) and every action it
**proposes** (exact commands, left for the founder to run at land time —
several candidates are load-bearing for tooling or referenced by files this
track does not own). Nothing here is irreversible; git history retains all.

---

## 0. URGENT — flagged for the founder, before any launch traffic

1. **A retired PRIVATE seal key is in public git history.**
   `var/tex/keys/evidence_seal_key.json` was tracked (added in `eef9c24`,
   untracked in `6af43d0` "chore(hygiene): untrack runtime state"); both
   commits are reachable from `origin/main`, which is public. Verified this
   session: the historical key blob's SHA-256 differs from the live key's —
   so this is the **rotated-away v1 key** (Wave-1 rotation held), not the
   active one. But the deferred history scrub is now load-bearing: this
   on-ramp exists to drive strangers into this repo. Recommend
   `git filter-repo` (or BFG) on `var/` before promoting the front door, or
   a conscious, written acceptance of the exposure. Historical
   `var/tex/evidence/evidence.jsonl` snapshots are also in history (lower
   sensitivity; same scrub covers them).
2. **No root LICENSE file** (only `vendor/mithril/upstream/LICENSE`). A
   public repo with no license is "all rights reserved" by default — fine if
   intended, but the README now invites people to clone and run; the legal
   posture should be a decision, not an accident.

## 1. Zip inspection result (deliverable D gate)

All four `tex-frontend*.zip` files were extracted and scanned this session:

```
unzip -l  → each contains only: index.html, vercel.json, README.md, favicon.svg
grep -rinE "(api[_-]?key|secret|token|password|bearer|sk-[a-zA-Z0-9]|pk_live|AKIA[A-Z0-9]|BEGIN (RSA|EC|OPENSSH) PRIVATE)"
          → zero matches in all four archives
```

**No secrets found.** Contents are four near-identical iterations of the
static marketing site (only external references: Calendly, Google Fonts,
vortexblack.ai). They are redundant exports of the tracked `tex-frontend/`
directory.

## 2. Executed on this branch (staged, reviewable in the diff)

| File | Action | Rationale |
|---|---|---|
| `tex-frontend.zip`, `tex-frontend 2.zip`, `tex-frontend 3.zip`, `tex-frontend 4.zip` | `git rm --cached` + `.gitignore` (`tex-frontend*.zip`); local copies kept | Near-duplicate build artifacts (~48 KB of zips duplicating the tracked `tex-frontend/` dir); no secrets (see §1); pure front-door clutter |
| `README.md` (root) | **added** | The public front door — was absent entirely |
| `scripts/quickstart.py`, `scripts/verify_it_yourself.py` | **added** | The zero-config first-run path the README documents |
| `scripts/smoke_guardrail.py` | path fix `parents[0]` → `parents[1]` | Its self-bootstrap pointed at nonexistent `scripts/src`; scripts are in-scope for this track |
| `sdks/python/README.md` | honesty pass | `pip install tex-guardrail` 404s and `api.tex.systems` does not resolve (both re-verified 2026-06-12) — added a status banner; cut the "suitable for SOC 2, FINRA, HIPAA…" claim (zero field validation; zero production deployments) |

## 3. Proposed, not executed (founder runs at land time)

Internal operator docs at root. Recommended mechanism: `git mv` into
`docs/internal/` (keeps them tracked so worktrees/threads still get them;
cleans the front-door listing). NOT executed here because each has inbound
references from tooling or from files this track does not own — moving them
without updating those references would leave stale pointers.

| File | Proposal | Blocker for executing here |
|---|---|---|
| `CLAUDE.md` | keep at root | Loaded from repo root by the agent harness every session; moving breaks the doctrine load. Content is internal-flavored but contains no secrets; founder may prefer a public-facing rewrite later |
| `COORDINATION.md` | `git mv` → `docs/internal/` at land | The multi-thread ownership protocol file; active tracks (incl. this one) append rows at its current path |
| `ROADMAP.md` | `git mv` → `docs/internal/` at land | Referenced by `CLAUDE.md` (not this track's file to edit) |
| `THREAD_PRIMER.md` | `git mv` → `docs/internal/` at land | Referenced by `audit_tools/assemble.py` (tooling; not this track's to edit) |
| `SELF_AUDIT.txt` | `git mv` → `docs/internal/` at land | Referenced by `CLAUDE.md`, `ROADMAP.md`, `TEX_SYSTEM.md` |
| `BLUEPRINT_APPLIED.txt` | `git mv` → `docs/internal/` at land | No tooling references (only the git-excluded PROMPT.md); kept with its siblings for one coherent founder-reviewed move |
| `SANDBOX_LIVE.md` | `git mv` → `docs/internal/` at land | Same — moved together with the set |
| `SANDBOX_SIMULATOR.md` | `git mv` → `docs/internal/` at land | Referenced from `src/tex/main.py` (a comment/docstring; main.py is 0-lines for this track) |
| `TEX_SYSTEM.md` | keep at root | Generated ground truth (`audit_tools/`); now linked from the README as the deep map |
| `index.json` | keep tracked (note: 1.4 MB) | Ground-truth artifact regenerable via `audit_tools/`; untracking would leave fresh clones without it. Founder may later move generation artifacts to releases |
| `tex-frontend/` (dir) | keep tracked | The actual site source (4 small files); the clutter was the zips, now untracked |
| `OPERATOR.md` | n/a | Does not exist at root (stale mention in internal notes); nothing to curate |

Suggested land-time command block for the doc moves (after updating the
references named above):

```bash
mkdir -p docs/internal
git mv COORDINATION.md ROADMAP.md THREAD_PRIMER.md SELF_AUDIT.txt \
       BLUEPRINT_APPLIED.txt SANDBOX_LIVE.md SANDBOX_SIMULATOR.md docs/internal/
# then update: audit_tools/assemble.py (THREAD_PRIMER), CLAUDE.md (ROADMAP,
# SELF_AUDIT, COORDINATION paths), src/tex/main.py comment (SANDBOX_SIMULATOR),
# TEX_SYSTEM.md regeneration picks up the rest.
```

## 4. Decisions made and not relitigated

- **Local/offline-first on-ramp** (per the design decision in the thread
  brief): no PyPI publish, no hosted API — founder-only calls.
- **No `CONTRIBUTING.md`** added: not needed for the first-run path; would
  also be premature before the license decision (§0.2).

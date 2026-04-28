# LAUNCH_CHANGES.md — pre-launch hardening pass

Tightens hub composition for desktop and mobile, fixes the
/what-is-tex headline overflow, replaces fake-feeling status-bar
counters with real product signals, and adds two side-rails to the
arcade so the game reads as a demo, not just a game.

## Files modified

### `src/components/Hub.jsx`

- **Status bar rewritten.** Dropped `BUILD 0.14.2`, `OPERATORS ONLINE
  1247+`, and `BREACH WATCH NN`. Replaced with `GATE LIVE` (pulsed
  status indicator) + `EVAL p50 178MS` + `RECEIPTS SHA-256`. Real,
  defensible product signals; nothing fake-counter.
- **Buyer eyebrow.** Replaced `VORTEXBLACK / TEX AEGIS · LIVE GATE`
  with `FOR TEAMS RUNNING AI SDRS & OUTBOUND AGENTS`. A LinkedIn
  visitor now sees who Tex is for in the first row.
- **Sub-copy rewritten** to lead with the product action:
  "Tex inspects every email, message, query, and deploy your AI
  agents try to send. PERMIT, ABSTAIN, or FORBID in 178ms — with a
  hash-chained, signed receipt for every decision."
- **New audit CTA** next to ENTER ARCADE. Cyan-bordered button
  reading `FREE AI OUTBOUND AUDIT →` with subtitle "we evaluate 20
  of your real outbound emails." Opens `mailto:matt@texaegis.com`
  with subject and body pre-filled. Swap to a /audit page or
  Calendly later — link change only, no UI work.
- **Hero-side telemetry strip.** Pulled inside the text column
  (was below the anatomy strip) so concrete proof points
  (`EVAL p50 178MS`, `RECEIPTS SHA-256 + HMAC`,
  `SURFACES EMAIL · API · SLACK · DB · DEPLOY`) sit above the fold.
- Removed the unused `breachCount` calculation.
- Removed the duplicate full-width `.telemetry-row` (its content
  moved into the hero).

### `src/components/WhatIsTex.jsx`

- Headline cap reduced from `clamp(56px, 11vw, 144px)` to
  `clamp(36px, min(6.2vw, 10vh), 80px)`.
- Removed `&nbsp;` between words in the gradient line — it was
  preventing wrap. Headline now flows across three lines cleanly
  on every desktop viewport.
- Added `maxWidth: 100%` and `overflowWrap: break-word` as
  safety belts.

### `src/components/Arcade.jsx`

- **Side rails** (the structural change). Two `<aside>` elements
  flanking the canvas, hidden under 1180px so mobile/tablet stays
  centered. Both rails are `pointer-events: none` so they never
  block input.
  - **Left rail — LIVE VERDICT FEED.** Last 8 decisions stream in,
    color-coded by verdict, with surface name and elapsed seconds.
    Footer shows running totals.
  - **Right rail — EVIDENCE RECEIPTS.** Last 5 decisions rendered
    as signed receipt cards: verdict, surface, plain-English
    summary ("ACH initiated", "channel reply", etc.), and a
    12-char hex hash ID like `0x53d0·051c·d069`. Footer reads
    `chain length: N · audit-ready`.
- New React state slice `rails` (feed, receipts, counts) updated
  event-driven from `recordOutcome` so it stays responsive without
  rerendering on the 10Hz HUD tick.
- New helpers: `fakeHash(seed)` for receipt IDs and
  `SURFACE_SUMMARIES` for plain-English receipt bodies.
- Rails reset alongside game state in `initGame`.

### `src/index.css`

- **Hub headline scaling rebuilt.** Base rule now sized by
  `clamp(40px, min(7.4vw, 11vh), 112px)`. The headline scales by
  whichever of width or height is tighter, so a 4-line composition
  always fits on a 1440x900 MacBook Air.
- The previous override at line ~2498 that fought the base rule has
  been neutralised; only the responsive breakpoints below remain.
- **Mobile hero re-stack (final order).** At ≤1080px the layout
  collapses to a single column flex with `display: contents` on
  `.hub-hero-text` so its children become flex siblings of
  `.hub-hero-aside`. Order assigned via `order:`
    1. eyebrow
    2. Tex avatar
    3. ENTER ARCADE + audit + WHAT IS TEX (CTA row)
    4. headline
    5. sub-copy
    6. hero telemetry strip
    7. demo ticker
  Avatar capped at 320px on tablets and 240px on phones.
  Demo ticker hidden under 760px to keep the CTAs above the fold.
- New `.btn-audit` styles — cyan border, subtle hover gleam, two
  text rows.
- New `.hub-hero-telemetry` styles — cyan-left-bordered strip with
  monospace tokens.
- New arcade rail styles (~150 lines appended to end of file):
  `.arcade-rail`, `.arcade-rail-left/right`, `.rail-head`,
  `.rail-feed`, `.rail-feed-row`, `.rail-receipts`,
  `.rail-receipt`, `.rail-foot`, `@keyframes rail-feed-in`.
  All hidden under `@media (max-width: 1180px)`.

### `src/lib/leaderboard.js`

- Replaced obvious-fake handles in `SEED_HANDLES`: dropped
  `shipit_emma`, `abstain_sam`, `permit_eli`, `miss_rev`,
  `sdr_killer`, `sla_breaker`. Added neutral plausibles:
  `m_rivers`, `n_shah`, `k_rao`, `operator_03`, `sla_44`. The
  list still reads as 28 unique operator handles, just less
  winky.

## What was NOT changed

- The arcade game logic itself (canvas, physics, scoring,
  difficulty curve, all sprites). Untouched.
- `Briefing.jsx`. Untouched — already the most polished surface.
- `ShiftReport.jsx`. Untouched.
- `Game.jsx` (the conveyor) is still on disk and still not
  imported from `App.jsx`. The conveyor question is a strategic
  decision, not a frontend pass.
- The audit destination is currently a `mailto:` placeholder.
  Swap to a Calendly / Typeform / `/audit` route by editing the
  `href` on `.btn-audit` in `Hub.jsx` (one string change).

## Build verification

  npm install
  npx vite build      # 311KB JS / 80KB CSS, gzipped 94KB / 16KB
  npx vite preview    # http://localhost:4173

Visually verified on:
  - desktop 1440×900 (the launch-day target)
  - desktop 1366×768 (worst-case MacBook Air-class)
  - mobile 390×844 (iPhone-class — most LinkedIn traffic)

---

# Backend integration pass — real Postgres leaderboard

This pass connects the frontend to a Postgres-backed arcade leaderboard
on the existing Render `tex` service + `tex-leaderboard` Postgres.

## Backend (Python)

### NEW: `src/tex/db/arcade_leaderboard_repo.py`
Postgres repo for the arcade leaderboard. Two tables:
- `arcade_leaderboard` — one row per (handle, date_key)
- `arcade_leaderboard_used_tokens` — replay guard

Six async methods: `ensure_schema`, `top_for_day`, `top_alltime`, `get`,
`rank_for_day`, `submit`, `total_for_day`. Uses the same `DATABASE_URL`
env var the existing leaderboard already reads — Render auto-wires it
from the linked Postgres service.

Submit logic: better-write-wins per (handle, date_key). Replays of the
same `submit_token` are atomically rejected.

### NEW: `src/tex/api/arcade_leaderboard.py`
FastAPI router mounted at `/arcade/leaderboard`. Two endpoints:
- `GET /arcade/leaderboard?date=&handle=` — top 50 + caller's rank/score
  + `is_you: true` flag on the matching row
- `POST /arcade/leaderboard/submit` — records a run with soft anti-cheat:
  - score ≤ 50,000 absolute ceiling
  - score / survived_seconds ≤ 50 (rejects "1M points in 1s" trivially)
  - future-dated keys rejected
  - submit_token is idempotent — replays return `accepted: false` with
    current state
  - handle regex `^[A-Za-z0-9_.\-]{2,18}$`
  - rating ∈ {ROOKIE, OPERATOR, ANALYST, WARDEN}

Anti-cheat is deliberately **soft**, not cryptographic. The arcade is
fully client-side; real anti-cheat would require server-side game state.
Soft bounds + idempotency stop drive-by cheating; the leaderboard is a
marketing surface, not a competitive ladder.

### MODIFIED: `src/tex/main.py`
- Imports the new repo + router.
- Schema bootstrap added to the FastAPI lifespan (best-effort, won't
  crash the app if DB is briefly unreachable).
- Router included alongside the existing leaderboard router.

## Frontend

### MODIFIED: `src/lib/leaderboard.js`
Rewrote to be backend-aware:
- `fetchDailyLeaderboard(dateKey, handle)` — async, hits `/api/arcade/leaderboard`
- `submitArcadeScore({result, handle})` — async, POSTs to `/api/arcade/leaderboard/submit`
- Backend response cached under `tex.arcade.lb.cache.v1` so repeat
  visits paint the live list immediately, then refresh in background
- Seeded list preserved as instant-paint fallback when backend is
  unreachable or cold-starting on Render
- Per-day `submit_token` stored in localStorage so retries are
  idempotent against the server's anti-replay guard
- Storage keys migrated: `tex.arcade.handle.v1` (was `tex.conveyor.handle.v1`)

All existing exports preserved (`getDailyLeaderboard`, `submitDailyScore`,
`getHandle`, `setHandle`, `hasPlayedToday`, `todayResult`,
`getSeededLeaderboard`) so other components don't break.

### MODIFIED: `src/components/Hub.jsx`
Effect now paints seeded immediately, then fetches the backend list and
swaps in. Added `Math.min(8, rows.length)` to the "TOP N OF M" header so
small player counts read sensibly.

### MODIFIED: `src/components/ShiftReport.jsx`
Arcade scores now POST to backend after the run. Adds a status pill
next to the rank pill that shows:
- `POSTING SCORE…` (cyan, while in flight)
- `POSTED · WARDEN` (green, after server confirmation)
- `score not posted: <reason>` (red, on error — UI still shows
  local-only ranking so the player isn't left with nothing)

Falls back gracefully to local-only ranking if the backend is
unreachable.

### MODIFIED: `vite.config.js`
- Aligned the dev proxy target with `vercel.json` — both now point at
  `https://tex-2far.onrender.com`. Override locally with
  `VITE_API_PROXY=http://127.0.0.1:8000 npm run dev`.

## End-to-end verification (run locally during this pass)

1. Backend smoke against real Postgres: schema bootstraps cleanly,
   `submit` works, last-write-wins-only-if-better is correct, token
   replay is rejected, `rank_for_day` math is correct, `top_for_day`
   returns the right ordering.
2. HTTP smoke through FastAPI: empty GET, valid submission, second
   player, GET-with-handle (own-rank flagging works), idempotent replay,
   score-vs-survival cheat rejected, future-date rejected, bad handle
   rejected.
3. Frontend through vite proxy → FastAPI → Postgres:
   - Hub renders backend leaderboard with 6 real entries
   - "TOP 6 OF 6" header correct
   - "YOU" pill highlights when `tex.arcade.handle.v1` matches a
     leaderboard row
   - `submitArcadeScore()` from JS posts the right body, gets back
     `accepted: true, your_rank: 1, label: WARDEN`
   - Refetch shows the new submission in position 1

## Render deploy notes

- The new `arcade_leaderboard` and `arcade_leaderboard_used_tokens`
  tables are created on first request via the lifespan hook. No
  migration step needed — same pattern as the existing leaderboard.
- The existing `DATABASE_URL` env var (already wired from
  `tex-leaderboard` Postgres → `tex` web service) supplies the
  connection string. Nothing to add.
- After deploy, the live endpoints will be:
  - `GET https://tex-2far.onrender.com/arcade/leaderboard`
  - `POST https://tex-2far.onrender.com/arcade/leaderboard/submit`
- Vercel rewrites already proxy `/api/*` → these endpoints.

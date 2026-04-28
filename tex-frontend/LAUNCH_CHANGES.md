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
- **Mobile hero re-stack.** At ≤1080px the layout collapses to a
  single column with `.hub-hero-text` first (`order: 1`) and
  `.hub-hero-aside` (Tex avatar) second (`order: 2`). Avatar
  capped at 360px on tablets and 280px on phones. Demo ticker
  hidden on phones to keep the CTA above the fold.
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

# ARCADE_ONLY_RELEASE_CHANGES.md — release-day clean cut

Removes the conveyor (TRAIN AGAIN / PRACTICE) from the player-facing
UI. Tex Arcade is now the only playable mode. Code for the conveyor
remains on disk; it just isn't imported, so vite tree-shakes it from
the production bundle. Re-enabling later is one App.jsx import.

## What the player sees

### Hub (landing)
- Single primary CTA: "▶ ENTER ARCADE" (gate defense · survive the wave).
- Secondary: "WHAT IS TEX? →" (unchanged behavior).
- Hero copy rewritten to match arcade framing — no more "90-second shift."
- "RULES OF THE SHIFT" footer rewritten as "RULES OF THE GATE":
  GREEN = let through, ORANGE = stand under, RED = shoot it down,
  with arrow / SPACE / ESC controls.
- Leaderboard is now ARCADE LEADERBOARD. Same store. Renames the column
  header from CAUGHT to RATING (more meaningful for arcade scores).

### Routes
- `/` Hub
- `/arcade` Arcade game
- `/daily` and `/training` REDIRECT to `/arcade` so legacy links still work
- `/what-is-tex` explainer

### What's hidden but kept on disk
- `src/components/Game.jsx` (the conveyor)
- `src/lib/messages.js` (conveyor message library)
- `src/lib/messageMeta.js` (Tex pre-screen logic)
- `src/lib/dailyShift.js` is partially used (only `todayKey` for the
  leaderboard date stamp — the rest is dormant).
- ShiftReport branches on `mode === "arcade"` already; no changes there
  except the leaderboard-submit gate.

## Files

MODIFIED
- `src/App.jsx`
  - Removed Game.jsx import.
  - Routing collapsed to: hub, arcade, shiftReport, whatIsTex.
  - `/daily` and `/training` now route to arcade (legacy redirect).
  - `mode` state removed (not needed when there's only one game).
  - ShiftReport always rendered with `mode="arcade"`.

- `src/components/Hub.jsx`
  - Prop signature: `({ onPlayArcade, onOpenWhatIsTex })` only.
  - Removed TRAIN AGAIN / PRACTICE / NEXT SHIFT countdown UI.
  - Single CTA + WHAT IS TEX secondary.
  - Hero copy rewritten for arcade framing.
  - "RULES OF THE GATE" footer with verdict-color dots.
  - Leaderboard column header CAUGHT → RATING; component now reads
    `r.rating` and falls back gracefully on `r.score ?? r.total`.
  - Fixed the `board.rows` bug — leaderboard now correctly reads
    `board.entries`. (Was returning empty silently; pre-existing bug
    called out in PASS_1_2_NOTES.md.)
  - Removed unused imports: hasPlayedToday, todayResult,
    msUntilNextShift, formatCountdown, SURFACES.
  - Deleted unused NextShiftCountdown component.

- `src/components/ShiftReport.jsx`
  - Leaderboard submission now fires for `arcade` mode (was: only `daily`).
  - Training mode still skips submission (no UI, but defensive).

UNCHANGED
- `src/components/Arcade.jsx` (no changes this pass)
- `src/components/Briefing.jsx`
- `src/components/WhatIsTex.jsx`
- `src/components/Game.jsx` (no longer imported, untouched on disk)
- `src/lib/leaderboard.js` (data shape repurposed — arcade scores submit
  to the same store; renames are downstream in Hub/ShiftReport)
- `src/index.css`

## Build verification

  npm install
  npx vite build

Result: 27 modules (was 28), 309KB JS / 76KB CSS, gzipped 94KB / 15KB.
**-18KB raw / -5KB gzipped** vs prior build (Game.jsx + messages.js
tree-shaken from the production bundle).

## To re-enable the conveyor later

In `src/App.jsx`:
1. Re-add `import Game from "./components/Game.jsx";`
2. Add a `mode` state and `game` phase back to the router (see App v15
   shape in git history if you want to copy it).
3. In `Hub.jsx`, accept `onPlayDaily` / `onPlayTraining` props again
   and add the buttons back.

The leaderboard, scoring, ShiftReport, and message library are all
intact — re-enabling is purely UI surface work.

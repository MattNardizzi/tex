# ARCADE_CHANGES.md — Tex Gate Defense (vertical shooter)

Added at /arcade alongside the existing conveyor at /daily and /training.
The conveyor is untouched. This is purely additive.

## Files

NEW
- `src/components/Arcade.jsx` — full game (canvas-based vertical shooter)

MODIFIED
- `src/App.jsx` — added `arcade` phase + `/arcade` route + Arcade prop wiring
- `src/components/Hub.jsx` — added "▼ ARCADE" button between PRACTICE and WHAT IS TEX
- `src/components/ShiftReport.jsx` — conditional centerpiece for arcade mode
  (shows survival time + peak speed instead of slowdown vs Tex)
- `src/index.css` — appended arcade-specific styles (~280 lines added at end)

## Game Mechanics

Tex anchored bottom-center, moves left/right. Action icons fall from the top
in 3 verdict colors:

  GREEN (PERMIT)  → let it pass through to the gate (don't shoot)
  ORANGE (ABSTAIN) → position Tex under it before it lands (auto-captures)
  RED (FORBID)   → shoot it down with the laser

Mistakes drain the GATE INTEGRITY bar:
  - red breach (let red through)        : -25
  - orange shot (destroyed evidence)    : -12
  - orange miss (landed away from Tex)  : -10
  - green shot (false positive)         : -8

Gate hits 0 → game over → routes to ShiftReport.

Spawn rate and fall speed scale with elapsed time:
  - speedMult: 1.0 → 3.4 over ~50s halflife
  - spawn gap: 1900ms → 380ms
  - orange share: 8% → 30%

## Controls

Desktop:
  - ← / → or A / D : move Tex
  - HOLD SPACE     : fire laser
  - HOLD MOUSE     : fire laser
  - ESC            : bail to hub

Mobile:
  - drag canvas    : move Tex
  - tap FIRE button (bottom-right) : fire laser

Note: firing is intentionally NOT auto-fire. The choice to shoot is the
core mechanic — green icons should not be shot.

## Compatibility

ShiftReport receives a `result` object shaped like the conveyor's, with
extra fields `_mode: "arcade"`, `_arcadeSurvivedMs`, `_arcadePeakSpeed`.
The leaderboard is NOT submitted from arcade mode — only daily-conveyor
runs hit the daily leaderboard, same as before.

## Known issues / v2 candidates

- crm and db_api icons read a bit busy at 56px — could use cleaner silhouettes
- no per-icon "verdict revealed" callout when player succeeds/fails (would
  reinforce the educational angle: "you let through a $250K wire")
- no boss waves
- audio is functional (uses existing sounds.js library) but not arcade-specific

## Build verification

  npm install
  npx vite build      # builds clean, ~315KB JS, ~14KB CSS gzipped
  npx vite preview    # local preview at http://localhost:4173/arcade

Tested screenshots in `/tmp/screen-arcade-*.png` (delete before deploy).
Verified: ready countdown, mid-game spawning, laser firing on desktop,
mobile FIRE button, gate integrity bar, HUD, hub button placement.

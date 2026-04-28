# BRIEFING_CHANGES.md — pre-game how-to-play screen

Adds a briefing overlay that runs once before the player's first arcade
session. Returning players skip straight to the 3-2-1 countdown. Storage
key is `tex_arcade_briefed_v1` in localStorage.

## Files

NEW
- `src/components/Briefing.jsx` — overlay component. Three verdict-colored
  rule blocks (PERMIT / ABSTAIN / FORBID), controls strip, and a 9-icon
  legend rendered to real canvases using the actual game's `drawIcon`
  function so the legend icons match exactly what falls in-game.

MODIFIED
- `src/components/Arcade.jsx`
  - Exported `drawIcon` and `paletteFor` (named exports) so Briefing
    can render the real game sprites.
  - Added `BRIEFED_KEY = "tex_arcade_briefed_v1"` localStorage flag.
  - Added a new `briefing` phase that precedes `ready`. Initial phase is
    determined from the localStorage flag.
  - Imported and rendered `<Briefing>` when `phase === "briefing"`.
  - Sets the storage flag and advances to `ready` when the player
    dismisses the briefing.

- `src/index.css`
  - Appended ~280 lines of briefing-specific styles. Nothing above the
    appended block was modified.
  - Mobile responsive at 720px and 420px breakpoints.

## Behavior

- New players (no `tex_arcade_briefed_v1` in localStorage):
  briefing  →  3-2-1 countdown  →  game.
- Returning players:
  3-2-1 countdown  →  game (briefing skipped).
- ENTER or SPACE on the briefing fires the start CTA.
- ESC during briefing exits to hub (existing arcade Esc behavior).

## To force re-show during testing

In the browser console on the deployed site:

  localStorage.removeItem("tex_arcade_briefed_v1");

Then refresh `/arcade`.

## Build verification

  npm install
  npx vite build

Result: 28 modules, ~326KB JS / ~76KB CSS, gzipped 98KB / 15KB.
~+11KB raw / +1KB gzipped vs prior bundle.

## Known follow-ups (NOT in this changeset)

- No in-game "?" help button. Re-opening the briefing mid-game would
  require pause state in the canvas loop, which doesn't exist yet.
- The floating legend strip in the bottom-right of the gameplay HUD
  (`.arcade-legend`) is now somewhat redundant once a player has seen
  the briefing. Was the source of the original clipping issue. Consider
  removing or making it dismissible in a follow-up pass.

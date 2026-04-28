# REMOVE_BEAM_KEEP_RING_CHANGES.md

Removes the catch beam (vertical halos + dashed rails + always-on impact
ring) per user feedback. Keeps reticles, magnetic pull, heal-on-catch.
The "impact ring" lives on as a one-shot animation that fires only on
successful catch.

## Files

MODIFIED
- `src/components/Arcade.jsx`
  - Deleted `drawCatchBeam` function entirely.
  - Removed call site in `renderFrame` — render order is now:
    background → reticles → falling icons (beam was between reticles
    and icons).
  - Added `catchRings: []` to game state init.
  - On successful ABSTAIN capture, push a ring spawn record:
    `{ x: tex.x, y: tex.y - 30, spawnTime, life: 520 }`
  - Render block: two concentric expanding rings, second offset by
    18% lifespan, both fade as they grow from radius 8 → 90px.
    Yellow stroke with shadow blur for the punch.

- `src/components/Briefing.jsx`
  - Updated ABSTAIN rule copy: "Move under the yellow target marker"
    (was: "Move into the yellow beam"). Reflects reality now that
    only reticles remain.

## What stays
- Landing reticles (yellow target markers on the gate floor)
- Magnetic pull on oranges in last 30% of fall
- Heal +10 on catch, capped at 100
- Floating green "+N" text on healing catches
- Removed in-game floating legend strip (still removed)

## Visual trade-off

The beam was meant to teach the catch zone. After playing, the beam
read as visual noise — busy, always-on, fighting with the reticles
for attention. Removing it makes the game feel less cluttered. The
reticles still tell you WHERE to go; the catch ring still rewards
you when you get there. Magnetic pull does the rest of the work the
beam was doing.

## Build verification

  npm install
  npx vite build

Result: 28 modules, 327KB JS / 76KB CSS, gzipped 99KB / 15KB.
~-0.5KB raw vs prior build (beam code removed > catch ring added).

## Tuning constants

In Arcade.jsx capture branch, look for `g.catchRings.push`:

  life: 520           // ring duration in ms
  // In render block:
  lerp(8, 90, t2)     // ring radius growth (start, end)
  for (let i = 0; i < 2; i++)  // number of concentric rings
  i * 0.18            // delay between concentric rings (% of life)

Beefier rings? Bump end radius to 110 and lifespan to 700ms.
Subtler? Drop alpha multipliers (currently 0.85 / 0.50) to 0.6 / 0.35.

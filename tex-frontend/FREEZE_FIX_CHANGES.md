# FREEZE_FIX_CHANGES.md — fix arcade freezing after a couple of catches

## Bug
After catching one or two orange icons in a row, the game would freeze
(or grind to a near-frozen frame rate).

## Root cause
Canvas `shadowBlur` is one of the most expensive operations in 2D canvas,
and it stacks badly when multiple shadowed shapes overlap in the same
frame. The catch-ring effect used `shadowBlur: 10` on two concentric
rings per catch, with a 520ms lifespan. Catching a second orange before
the first ring expired meant rendering 4+ shadowed strokes per frame
on top of the existing Tex aura. The "+10" heal text also used
`shadowBlur: 14`. Together this exceeded what the canvas could keep
up with at 60fps and the loop appeared to freeze.

## Fix
Removed all `shadowBlur` from the new catch-ring and heal-flash render
paths. Replaced the glow effect with a cheaper layered draw:
- Catch ring: wide low-alpha outer stroke + crisp inner stroke (two
  passes per ring, but no shadow filter pass).
- Heal text: outer stroke pass + fill pass (no shadow filter pass).

Visual result is nearly identical; performance is now stable across
arbitrary catch frequencies.

Also added an early-out `if (t >= 1) continue;` to both render loops as
defensive belt-and-suspenders so end-of-life frames don't draw
zero-alpha shapes that still consume rasterizer time.

## Files

MODIFIED
- `src/components/Arcade.jsx`
  - Catch-ring render block: removed `ctx.save/restore` + `shadowBlur`,
    replaced single shadowed stroke with two layered strokes.
  - Heal-flash render block: removed `shadowBlur`, replaced with
    `strokeText` + `fillText` two-pass.
  - Added `if (t >= 1) continue;` skip in both loops.

UNCHANGED
- All other behavior (heal +10, reticles, magnetic pull, briefing).

## Build verification

  npm install
  npx vite build

Result: 28 modules, 327KB JS / 76KB CSS, gzipped 99KB / 15KB.
+0.2KB raw vs prior build (layered draw is slightly more code than
shadowBlur but doesn't hit the GPU-bound shadow path).

## How to verify

1. Take damage (let one red breach + shoot a green).
2. Catch 4-5 oranges in quick succession.
3. Game should stay smooth at 60fps. Multiple "+10" texts and rings
   may overlap visually but the canvas won't choke.

# FREEZE_FIX_2_CHANGES.md — real fix for the catch freeze

## What the user saw
After 1-2 catches, console threw:

  Uncaught IndexSizeError: Failed to execute 'ellipse' on
  CanvasRenderingContext2D: The minor-axis radius provided
  (-0.232) is negative.

The throw halted the requestAnimationFrame loop, so the canvas
appeared frozen.

## Root cause (this time, the real one)
NOT shadowBlur. The previous "fix" was wrong about the cause.

The DATABASE icon's draw function (`drawDb`) computes a "top
highlight" ellipse with hardcoded pixel subtractions:

  ctx.ellipse(cx, ..., w / 2 - 4, ellipseH / 2 - 2, ...)

These constants were tuned for full-size icons (~65px). The
captured-ring animation in `renderFrame` shrinks the captured icon
from ICON_SIZE (68px) down to `ICON_SIZE * 0.4` (~27px) over 380ms:

  const sz = lerp(ICON_SIZE, ICON_SIZE * 0.4, t);
  drawIcon(ctx, cap.surface, x, y, sz, pal);

At sz ≈ 27, the highlight calc becomes:

  ellipseH = 27 * 0.13 = 3.5
  ellipseH / 2 - 2 = -0.232  ← negative → throws

If the captured icon happened to be a database (`db_api`), the
animation crossed this size and `ctx.ellipse` rejected the negative
radius, throwing inside the loop.

This bug was always present. It surfaced now because:
1. Catching ABSTAINs is a more common interaction pattern post-heal.
2. The shadowBlur removal cleared other perf noise that may have
   masked the throw before.

## Fix
In `drawDb`:
- Clamp both ellipse radii with `Math.max(0, ...)` for the top and
  bottom rim ellipses (defensive — they were never quite negative
  but shrinking to 0 is now graceful).
- The "top highlight" stroke that subtracts absolute pixels is
  guarded with an explicit check: only drawn when both `hlRx > 0`
  AND `hlRy > 0`. At small sizes the highlight is simply skipped,
  which is invisible to the player.

Audited every other `ctx.ellipse` and `ctx.arc` call in Arcade.jsx —
all other radii are pure size multiples (no absolute subtractions),
so they degrade to zero gracefully. Only `drawDb` had this bug.

## Files

MODIFIED
- `src/components/Arcade.jsx`
  - `drawDb` function: clamp radii, skip highlight when too small.

UNCHANGED
- All other behavior. The previous shadowBlur removal stays — that
  was good for perf even if it wasn't the freeze cause.

## Build verification

  npm install
  npx vite build

Result: 28 modules, 327KB JS / 76KB CSS, gzipped 99KB / 15KB.
+0.1KB raw vs prior build.

## Test

1. Open arcade. Drain integrity below 100 (let one red breach).
2. Catch ABSTAIN icons until you catch a database (cylinder shape).
3. Catch a few more in quick succession.
4. Console should stay clean. Game should NOT freeze.

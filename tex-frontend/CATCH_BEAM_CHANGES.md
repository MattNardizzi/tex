# CATCH_BEAM_CHANGES.md — clearer ABSTAIN capture mechanic

Makes it visually obvious that orange icons must be caught by Tex.
Three additions to the canvas render loop, plus a tiny physics nudge.

## What's new

### 1. Catch beam (vertical column from Tex upward)
Yellow gradient column projecting from Tex's head to the top of the screen.
Width matches the actual capture tolerance (no longer a lie about hitbox).
Two layers — soft outer halo + brighter inner core — plus dashed edge rails
that scroll downward to suggest "pull this way."

State-aware:
- IDLE: subtle pulse (0.55..0.75 opacity multiplier on a slow sine)
- ARMED: jumps to 0.95 opacity the instant any orange enters the column
- IMPACT RING: when an armed orange is in the bottom 30% of its fall, a
  growing yellow ring expands at the top of Tex telegraphing the catch

### 2. Landing reticles (ground markers)
For every active orange, a small target reticle on the gate floor directly
under it. Crosshair + center dot + outer ring. The reticle:
- Tightens (radius 36 → 14) as the icon falls closer to the gate
- Brightens (alpha 0.35 → 0.90) on the same curve
- Pulses with a per-icon phase offset so multiple oranges don't sync up

This tells the player WHERE to be, not just what color to chase.

### 3. Magnetic pull
Orange icons in the lower 30% of their fall get gently tugged toward Tex
when Tex is roughly under them. Strength scales with both:
- Vertical proximity (0 at fallT=0.70, 1 at gate)
- Horizontal distance (1 at center, 0 at reach edge of CAPTURE_TOLERANCE * 1.6)

Cap = ~0.95px per 60fps frame at peak. Doesn't save a way-off-target Tex.
Won't overshoot — clamped to the actual remaining gap. Subtle reward, not
a difficulty rebalance.

## Files

MODIFIED
- `src/components/Arcade.jsx`
  - Removed the old weak cyan column highlight from `drawGate` (was the
    wrong color for ABSTAIN and partially hidden behind the gate strip).
  - Added `drawCatchBeam(ctx, g)` — renders behind falling icons.
  - Added `drawCatchReticles(ctx, g)` — renders behind falling icons.
  - Wired both into `renderFrame` between `drawBackground` and the falling-
    icons loop, so icons render ON TOP of the beam (as expected).
  - Added magnetic pull inside the per-frame icon update loop. ABSTAIN-only.

- `src/components/Briefing.jsx`
  - Updated the ORANGE rule copy to reference the new beam visual:
    "Move into the yellow beam under it" (was: "Stand under it").

## Files unchanged
- index.css — the new visuals are entirely canvas-rendered. No CSS needed.

## Build verification

  npm install
  npx vite build

Result: 28 modules, ~327KB JS / ~76KB CSS, gzipped ~99KB / ~15KB.
~+1.7KB raw / ~+0.6KB gzipped vs the briefing-only build.

## Tuning constants (Arcade.jsx)

If the pull feels too strong or weak, adjust this line in the icon-update
loop (look for `// Magnetic pull:`):

  const pullPxPerFrame = 0.95 * proxStrength * horizFalloff;

- 0.95 = peak per-frame pull at 60fps when right on the edge.
- 0.70 in `if (fallT > 0.70)` = how late the pull starts (raise to start later).
- ABSTAIN_CAPTURE_TOLERANCE * 1.6 = horizontal reach (raise to make the pull
  more forgiving from further away).

Beam intensity at idle/armed (look for `intensity = armed ? ...`):

  const intensity = armed ? 0.95 : pulse;


# HEAL_AND_TWEAKS_CHANGES.md — heal-on-catch + four visual tweaks

Two things in this changeset:
1. Catching an orange icon restores +10 integrity (capped at MAX 100).
2. Four small visual tweaks to the catch beam / reticle / legend.

## 1. Heal-on-catch

When Tex catches an orange icon (ABSTAIN), integrity is healed by
`HEAL_ABSTAIN_CATCH = 10`, capped at `INTEGRITY_MAX = 100`. If the
player is already at full integrity, the catch still counts (score,
streak, capture animation) but no heal flash is shown.

A floating green "+N" rises above Tex's head on each healing catch.
The N is the actual amount restored — so a catch at 95 integrity shows
"+5", not "+10". 900ms life: fades in over 15%, holds, fades out over
last 25%.

### Constants (in Arcade.jsx)
- `HEAL_ABSTAIN_CATCH = 10` — heal per catch
- `INTEGRITY_MAX = 100` — cap (unchanged)

### Compared to damage values
- breach: -25
- orange-shot: -12
- orange-miss: -10
- false-positive (green-shot): -8
- **catch: +10** (new)

A catch heals more than green-shot or orange-miss damage. It does NOT
fully offset a breach (-25 vs +10). Means the player can recover
slowly from accumulated minor mistakes via good ABSTAIN play, but
can't farm catches to outlast reckless red-letting.

## 2. Visual tweaks

### Reticle floor alpha
The landing reticle on the gate floor now starts at `0.55` alpha
(was `0.35`) when the orange first spawns. Newly-spawned oranges
now telegraph their landing spot from the moment they appear, instead
of materializing as faint at the top.

  // BEFORE: alpha = (0.35 + 0.55 * t) * pulse
  // AFTER:  alpha = clamp((0.55 + 0.55 * t) * pulse, 0, 1)

### Beam intensity bump
Idle beam was 0.55..0.75 opacity multiplier; now 0.70..0.90.
Armed beam was 0.95; now 1.15 (visible delta when an orange enters
the column). Gradient stops still resolve to legal alpha values.

  // BEFORE: pulse = 0.55 + 0.10 * sin(...);  intensity = armed ? 0.95 : pulse
  // AFTER:  pulse = 0.70 + 0.10 * sin(...);  intensity = armed ? 1.15 : pulse

### Rail termination above Tex's head
Beam now ends at `g.tex.y - 30` (was `g.tex.y + 10`). The dashed
rails no longer pass through Tex's body — they stop above his head,
which reads cleanly as "beam projects FROM Tex, upward."

### Removed redundant in-game legend
The bottom-right floating legend strip (the "GREEN · ORANGE · RED"
chips that were getting clipped on narrow viewports) is removed.
It's redundant now that the briefing screen explicitly explains the
verdicts and the in-game beam tells the same story visually.

The CSS class `.arcade-legend` and its children are still in
`index.css` — left in place in case you want to bring it back. Pure
component-level change, no CSS deletion.

## Files

MODIFIED
- `src/components/Arcade.jsx`
  - Added `HEAL_ABSTAIN_CATCH` constant.
  - Added `healFlashes` to gameRef state.
  - In ABSTAIN-captured branch: heal logic + push to healFlashes.
  - In renderFrame: render the floating +N text after capturedRing.
  - Bumped beam idle/armed intensity (0.70..0.90 / 1.15).
  - Floored reticle alpha at 0.55.
  - Beam terminates at `tex.y - 30` instead of `tex.y + 10`.
  - Removed `<div className="arcade-legend">` JSX block.

UNCHANGED
- `src/components/Briefing.jsx` — no changes (briefing already says
  the right thing about catching).
- `src/index.css` — no changes (CSS for removed legend stays for now).

## Build verification

  npm install
  npx vite build

Result: 28 modules, 327KB JS / 76KB CSS, gzipped 99KB / 15KB.
~+0KB raw vs prior build (heal logic offsets removed legend).

## Testing notes

- Take damage (let one red breach OR shoot a few greens), then catch
  oranges — you should see "+10" rise above Tex and the integrity bar
  refill.
- At full integrity, catches show no flash but still score normally.
- "+N" text where N < HEAL_ABSTAIN_CATCH appears when you're near max
  (e.g. catch at 95 → "+5" because cap applies).

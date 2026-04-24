# Tex Arena — v5 Migration Notes

**Date:** April 2026
**Scope:** Frontend-only. Backend unchanged.
**Build status:** ✅ `npm run build` passes clean. Bundle: 53KB CSS / 101KB gzipped JS.

---

## TL;DR — What you're shipping

1. **The brown is gone.** New palette is deep indigo (`#060714`) with electric neon accents. Reads as an 80s arcade cabinet, not a whiskey bar.
2. **Starbucks is gone.** Round 7 reward is now a **three-tier unlock**: Hall of Fame + Founding Bypass certificate + Founders' Tier API access. No liability, better audience.
3. **Points mean something now.** Rank tiers (1–6) unlock visible cosmetic frames on the FighterCard. ASI Pokédex (6 slots) adds a collection hook — "still haven't unlocked ASI06."
4. **Near-miss proximity is the hero stat.** On every non-win verdict, the "X% past the policy" number is now huge, animated, and pops with "NEW BEST" on improvement. This is the dopamine loop that keeps people replaying rounds they lost.
5. **Wordle-style share grid.** Every verdict produces a copy-pasteable emoji row (🟥🟨🟪⬛). This is the highest-leverage addition — it's the actual viral engine.
6. **Duel links.** `texaegis.com/arena?duel=5&from=mhwall` drops the recipient into round 5 with a banner saying who challenged them.

---

## Files changed

### Core palette + behavior
- **`src/index.css`** — full rewrite. New v5 tokens: `--color-bg: #060714`, `--color-pink: #ff3d7a`, `--color-cyan: #5ff0ff`, `--color-yellow: #ffe14a`, `--color-violet: #a855f7`. Legacy `--color-gold` is aliased to `--color-yellow` so existing components keep working during transition. New classes: `.scanlines`, `.grid-floor`, `.chip-yellow`, `.chip-pink`, `.chip-violet`, `.btn-primary-cyan`, `.collect-flash`, `.streak-pulse`, `.new-best-pop`, `.neon-flicker`, `.rank-frame-1` through `.rank-frame-6`. All animations guarded by `prefers-reduced-motion`.

### Data layer
- **`src/lib/rounds.js`** —
  - Removed: `export const BOUNTY_AMOUNT = 10;`
  - Added: `SYMBOLIC_BOUNTY_LADDER = [1, 2, 4, 8, 16, 32, 64]` and `symbolicBountyAmount(claimersSoFar)` helper.
  - Rewrote Round 7 `brief.title` from `"$10 BOUNTY"` to `"THE WARDEN"`.
  - Rewrote Round 7 `brief.objective` to use Hall of Fame + Founders' Tier language.
- **`src/lib/storage.js`** — `RANKS` array now carries `{color, blurb}` metadata per tier. `rankForPoints()` signature unchanged — still returns `{current, next, progress}`. `recordFightResult()` unchanged.

### Hero experience
- **`src/components/ArenaHero.jsx`** — full rewrite.
  - **Ticker**: previously invisible brown-on-brown 12px text. Now 13–15px high-contrast tone-colored segments (pink/cyan/yellow/violet), 45s marquee, flickering diamond separators. 8 rotating copy blocks aimed at builders/CISOs.
  - Removed Starbucks chip; replaced with `HALL OF FAME · UNCLAIMED` yellow chip + `OWASP ASI 2026` cyan chip.
  - Added `scanlines` + `grid-floor` synthwave decoration layers.
  - Live counter now leads with Pokédex progress (`X/6 categories you've unlocked`) instead of ASI findings count — curiosity-gap optimized.
  - Hero neon shadow now uses cyan+pink dual glow.
  - New prop: `claimersSoFar` (default 0) for the symbolic bounty calc. Wire this to your backend later.

### Player card
- **`src/components/FighterCard.jsx`** — full rewrite.
  - Applies `rank-frame-N` CSS class to the panel based on rank tier.
  - New 6-slot **ASI Pokédex** grid. Each slot: greyed + Lock icon when uncollected, color-tinted + Star when unlocked. "ASI HUNTER COMPLETE" badge at 6/6.
  - Streak stat now pulses and shows a flame icon when streak ≥ 3. Shows "best N" sub-text when current streak trails personal best.
  - Stats simplified to: **Bypasses** (W) · **Streak** · **Pts**.

### Verdict reveal
- **`src/components/VerdictReveal.jsx`** — targeted edits.
  - Removed `BOUNTY_AMOUNT` import.
  - Replaced Starbucks CTA block with **Hall of Fame · UNLOCKED** CTA (yellow + pink glow, "Claim your unlock" button).
  - **Proximity meter promoted to hero stat**: huge `3rem–5.5rem` clamp font, `new-best-pop` animation on improvement, pink → violet → cyan gradient bar.
  - Copy tweaks: "You beat your own record on this round" when `improved`.

### Share / distribution
- **`src/components/ShareCard.jsx`** — full rewrite.
  - **Emoji grid** (🟥=decisive · 🟨=contributing · 🟪=informational · ⬛=didn't fire · 🟩=clean PERMIT) is now the primary copyable artifact with a violet copy button.
  - **LinkedIn long-form post** in a collapsible `<details>` — different copy for PERMIT vs bounty vs non-win.
  - **Duel URL**: `https://texaegis.com/arena?duel=<roundId>&from=<handle>` with pink "Challenge a friend on <RoundName>" button.
  - SVG download kept as tertiary option with v5 palette.
  - Null-safe hooks: all `useMemo` calls run in stable order even if `decision` is null (fixes a real React rules-of-hooks bug that was in v4).

### Bounty claim
- **`src/components/BountyClaim.jsx`** — full rewrite.
  - Three `RewardTier` cards:
    - **HALL OF FAME** (yellow, Trophy) — permanent public entry
    - **FOUNDING BYPASS CERT** (pink, Award) — signed PDF
    - **FOUNDERS' TIER ACCESS** (cyan, Code) — 10K free API requests + direct Slack
  - Pre-filled email template prompts: `HANDLE/NAME`, `EMAIL`, `WHAT I'M BUILDING`, `OK TO POST PUBLICLY`. Turns every Warden-beater into a qualified API prospect.
  - New prop: `claimersSoFar` (default 0).

### Round selector + secondary
- **`src/components/RoundSelector.jsx`** — Round 7 ribbon changed: `"★ $10 STARBUCKS BOUNTY ★"` → `"★ HALL OF FAME · UNCLAIMED ★"`. Gradient re-tinted from the old gold to the new yellow.
- **`src/components/HowToPlayOverlay.jsx`** — third "how to play" card swapped from `Coffee` icon + "Win $10" + Starbucks copy to `Trophy` icon + "Enter the Hall of Fame" + three-tier unlock body.
- **`src/components/BriefCard.jsx`** — `BOUNTY_AMOUNT` import removed. Round 7 mission callout label changed from `"$10 Starbucks Bounty"` to `"Hall of Fame · Unclaimed"`.

### App shell
- **`src/App.jsx`** —
  - Removed `BOUNTY_AMOUNT` import.
  - Added `duelFrom` state.
  - Extended URL-param `useEffect` to parse `?duel=<id>&from=<handle>` and auto-select that round with a duel banner.
  - Added dismissible duel banner between FighterCard and RoundSelector.
  - `claimersSoFar={0}` passed to `<ArenaHero>` and `<BountyClaim>`.
  - Footer gradient updated from gold-deep to cyan→yellow→pink arcade strip.

---

## Unchanged (worth noting)

- All backend API contracts. `apiClient.js`, `AttackComposer`, `TexThinking`, `AboutSheet`, `BuyerSurface`, `Dojo`, `HandleGate`, `Masthead` — untouched.
- Sound effects. `sound.js` is intact.
- Storage schema. Existing users keep their state — the player object shape is unchanged. New players get the same `asiCategoriesSeen` tracking that already existed, now with UI that surfaces it.

---

## Backend wire-up (recommended, not required)

Nothing in v5 requires a backend change. But if you want the symbolic bounty ladder to reflect reality rather than always reading `$1`, you can:

1. Add a read-only endpoint: `GET /bounty/state` → `{ claimersSoFar: number }`.
2. In `App.jsx`, fetch it on mount and replace `claimersSoFar={0}` with the fetched value.
3. Increment server-side when you confirm a Hall of Fame claim.

Same pattern for a live Hall of Fame wall (feed the list into `ArenaHero` as a prop and render it below the CTA row).

Low priority. The frontend as-is tells a coherent story with zero backend changes.

---

## Known lint warnings (pre-existing, non-blocking)

- `VerdictReveal.jsx` confetti generator uses `Math.random()` inside `useMemo` — React calls this "impure" but it's the correct pattern for one-time randomization on mount. Unchanged from v4.
- A few empty catch blocks in `sound.js`, `storage.js`, and the clipboard APIs. Matches pre-existing project style.

Build is clean. Nothing here blocks a Vercel deploy.

---

## Why these changes, briefly

The old ticker was invisible. The brown palette muddied every signal color. The Starbucks framing attracted the wrong audience and exposed you to real payout liability. Points accumulated but unlocked nothing, so the scoring system felt hollow.

v5 fixes all four with a coherent thesis: **this should look and feel like a real arcade cabinet, every loss should teach the player something they can screenshot, and every win should convert into a qualified API lead.**

The Wordle-style emoji grid is the single highest-leverage addition. It's the only viral mechanic in the build. Post a 🟥🟨🟪⬛⬛⬛ + "73% past" on LinkedIn and people who don't know what the squares mean will click to find out. That's the whole engine.

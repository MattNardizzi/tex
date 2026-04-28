# Mobile Hero Reorder + Halo Cleanup — Changes

**Date:** 2026-04-27
**Scope:** `src/index.css` only (no JSX changes needed)

## What changed

### 1. Mobile stacking order — quote moved below the CTA

Previously on mobile (≤1080px) the `.hub-hero-aside` block (Tex avatar **+**
quote, bundled together) sat at order 2, with the CTA row beneath it at
order 3. That meant the quote landed above the pink ENTER ARCADE button.

Now `.hub-hero-aside` also gets `display: contents` so its two children —
`.hub-avatar` and `.hub-aside-caption` — promote into the parent flex
flow and can be ordered independently:

| Order | Element            | Was | Now |
|-------|--------------------|-----|-----|
| 1     | eyebrow            | 1   | 1   |
| 2     | Tex avatar         | (in aside, 2) | 2 |
| 3     | CTA row            | 3   | 3   |
| 4     | Quote              | (in aside, 2) | **4** ← moved below CTA |
| 5     | Headline           | 4   | 5   |
| 6     | Sub copy           | 5   | 6   |
| 7     | Hero telemetry     | 6   | 7   |
| 8     | Demo ticker        | 7   | 8   |

The width cap that lived on `.hub-hero-aside` (`max-width: 320px` /
`240px`) moved onto `.hub-avatar` since the aside container itself is
now `display: contents` and no longer has a layout box.

### 2. Faded white halo around Tex — stripped on phones (≤760px)

The cyan rim drop-shadow on `.hub-avatar img` plus the radial
`.avatar-glow` behind him were combining on small viewports to render
a soft rectangular halo that read as a "faded white border." On
≤760px:

- `.avatar-glow` → `display: none`
- The cyan-rim drop-shadow filter on `.hub-avatar img` is replaced
  with just a clean dark grounding shadow (no cyan tint, no 60px bloom)

Desktop and tablet renders are untouched.

## Files touched

- `src/index.css` — single block at lines ~1742–1804

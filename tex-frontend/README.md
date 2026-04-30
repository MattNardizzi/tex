# Tex — Field

The texaegis.com landing experience. A WebGL "judgment field" that
visualizes Tex as the authority layer between AI agents and the real world.

## What this is

Visitors land on this page after clicking **See Tex in Action** on the
VortexBlack homepage. The page renders Tex (your avatar, brand-aligned)
at the center of a continuous, alive WebGL field. Every AI agent action —
emails, database writes, Slack messages, refunds, deploys, shell commands —
streams from agent points scattered around him, hits an invisible spherical
membrane, and resolves as **PERMIT**, **ABSTAIN**, or **FORBID**. Detonations
ripple the membrane. Each decision stamps a node onto a growing hash chain.

All seven stages of the Tex loop (Discovery, Registration, Capability,
Evaluation, Enforcement, Evidence, Learning) are encoded in the visual and
labeled in the corner legend.

## Stack

- **React 18** + **Vite 5** — minimal, fast, no SSR needed
- **Three.js 0.160** — WebGL scene
- **Pure visual** — no backend calls. Designed to be deployed as a static
  site to Vercel.

## Deploy to Vercel

```bash
npm install
npm run build      # outputs to dist/
```

In Vercel:
- **Build Command**: `npm run build`
- **Output Directory**: `dist`
- **Framework Preset**: Vite (or "Other" — works either way)
- **Install Command**: `npm install`

`vercel.json` is included with sensible security headers and SPA rewrites.

## File layout

```
src/
  App.jsx          — React shell: brand bar, hero, legend, metrics, CTA,
                     receipts ticker, manifesto, pillars, footer
  TexField.js      — The WebGL scene. ~830 lines. Self-contained, no
                     external deps beyond three.
  styles.css       — All styling. Custom typography (Fraunces serif,
                     JetBrains Mono, Inter Tight). No Tailwind, no CSS-in-JS.
  main.jsx         — React entry point
public/
  tex.png          — Background-removed Tex avatar
index.html         — HTML shell with font preloads and OG metadata
vercel.json        — Vercel config
vite.config.js     — Vite config
```

## What's tunable

In `TexField.js`:

- **`spawnRate`** (line ~67) — actions per second on average. Default 2.8,
  cruises up to 4.6.
- **`agentCount`** (line ~169) — number of agent points in the cloud.
  Default 260.
- **`membraneRadius`** (line ~263) — radius of the judgment field shell.
  Default 22.
- **`ACTION_TEMPLATES`** (line ~13) — list of action kinds streamed
  through the field.
- **`AGENT_PREFIXES`** (line ~810) — agent names rendered in receipts.

In `App.jsx`:

- **`SEED_RECEIPTS`** — initial scrolling ticker entries shown on first paint.
- **`STAGES`** — legend rows.
- The pillar grid copy in `Pillars()`.
- Initial counter seed in `useState` (line ~31). Default seeds with
  ~14-18k evaluated decisions to suggest a system already in flight.

## What's NOT here (and why)

- **No backend integration.** v1 is pure visual. The "Run a real action"
  follow-up panel that hits your live texaegis.com backend is a deliberate
  v2.
- **No external CDN beyond Google Fonts.** Three.js is bundled.
- **No analytics, no tracking pixels.** Add yours.
- **No `window.__field` debug hook** in production. (Strip from
  `App.jsx` if you re-add it for local dev.)

## Performance notes

- Bundle: ~170 KB gzipped JS (mostly Three.js), 2.8 KB gzipped CSS.
- Initial render before WebGL warm: instant (HTML + CSS only).
- Steady-state: ~60fps on any modern laptop. The field caps in-flight
  actions implicitly via spawn rate; expect 12-25 actions on screen at any
  time.
- Reduced motion: `prefers-reduced-motion` disables animation on the
  receipts ticker and entrance animations. The WebGL scene continues to
  render but you may want to add a static fallback for heavy accessibility
  work.

## Replacing this page on texaegis.com

The current arcade frontend at texaegis.com is a separate Vite project.
To swap:

1. Point your texaegis.com Vercel project at this repo (or merge this
   into the existing repo and update build settings).
2. Delete the legacy arcade routes — this build has none.
3. Update the homepage CTA on vortexblack.com (the "See Tex in Action"
   button) to continue pointing at texaegis.com — no URL change needed.

That's it.

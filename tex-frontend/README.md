# Tex Field — texaegis.com

The live, narrated landing experience for **Tex** by VortexBlack. Replaces the previous arcade-style demo with a real-time visualization of Tex catching AI agent actions.

## What the buyer sees

Within 5 seconds of arriving:

1. Tex stands center, full color, authoritative.
2. Anonymous cyan streaks (ambient agent actions) flow constantly toward Tex — texture only, no labels. Establishes scale: "things happen all the time."
3. Every ~3.5 seconds, **one labeled hero action** is promoted. The buyer sees:
   - **Action card**: `slack.post · agent: artisan-sdr-22` attached to the moving particle
   - **04 EVALUATION** stage tag pulses near Tex's chest
   - **05 ENFORCEMENT** stage tag with verdict label: **PERMIT** / **ABSTAIN** / **FORBID** in verdict color
   - **06 EVIDENCE** chip with hash flies down to the chain band, where a new ledger node lights up
4. The metrics counter ticks up. The receipts ticker at the bottom adds the new entry.

This is the dual-stream architecture:
- **Ambient** = atmosphere, never the focal event
- **Hero** = the narrated story, always exactly one at a time

## Stack

- React 18 + Vite 5
- Three.js 0.160 (custom GLSL shaders for membrane fresnel, agent particles, Tex emblem heartbeat)
- DOM overlay layer for crisp readable labels (HTML, not WebGL text)
- No backend dependency — pure visual

## Run locally

```bash
npm install
npm run dev    # http://localhost:5173
```

Run for at least 30 seconds to see hero actions cycle through different verdicts.

## Deploy to Vercel

The repo is Vercel-ready with `vercel.json` configured for SPA rewrites and security headers.

```bash
npm run build  # → dist/
```

If pushing to a fresh repo:
```bash
git init
git add .
git commit -m "Initial commit: Tex field landing experience"
git remote add origin <repo-url>
git push -u origin main
```

Vercel auto-detects Vite. After connecting, set the production domain to `texaegis.com`.

**Before pushing:** swap the placeholder CTA URL in `src/App.jsx` from `https://vortexblack.ai/contact` to whatever your live demo-request URL is.

## Tunable parameters

All in `src/TexField.js` near the top of the constructor:

| Param | Default | Effect |
|---|---|---|
| `heroCooldown` | 0.4 (initial), then 3.4-4.2s | How often a hero action appears |
| `ambientSpawnRate` | 5.0/sec | Density of background streaks |
| `agentCount` | 220 | Number of agent dots in the cloud |
| `membraneRadius` | 21 | Sphere size around Tex |

Action types and verdict tendencies live in `ACTION_TEMPLATES`. Agent ID prefixes live in `AGENT_PREFIXES`. Verdict mix balance in `HERO_VERDICT_MIX`.

## File map

```
src/
  App.jsx        — React shell + HeroOverlay (DOM labels)
  TexField.js    — Three.js scene + hero/ambient simulation (~870 lines)
  styles.css     — All styling (Fraunces serif, JetBrains Mono, Inter Tight)
  main.jsx       — Entry point
public/
  tex.png        — Background-removed Tex avatar (1MB PNG fallback)
  tex.webp       — Optimized 156KB variant (used by app)
index.html       — Font preloads + OG meta
vercel.json      — Security headers + SPA routing
```

## Design constraints (do not break)

- **Tex always renders last with `depthTest: false`.** He is the authority — never tinted by the membrane, never washed out, never partially behind agents. This is the single most important rule.
- **Membrane is subtle.** Ripples cap at 0.6s lifetime and small radius. Auroras are forbidden — they obscure the narrative.
- **One hero at a time.** Multiple labeled actions on screen confuses the buyer. The whole point of the hero stream is that it's the focal event.
- **Verdict colors are non-negotiable**: PERMIT = `#5fffc4` (cyan-green), ABSTAIN = `#ffb547` (amber), FORBID = `#ff4757` (coral red). They appear on the action particle, the membrane flash, the verdict label, and the chain node — consistent everywhere.

## Browser support

Chromium-based browsers (Chrome, Edge, Brave, Arc), Safari 16+, Firefox 110+. Requires WebGL 2. Mobile renders but the hero overlay labels can clip on narrow viewports — current focus is desktop.

## What this replaces

The previous `texaegis.com` rendered a small arcade-style game. It was clever but didn't deliver on the "Authority Layer between AI and the real world" promise from the marketing video. This experience does — by literally showing Tex acting as that authority layer, on every action, with cryptographic proof.

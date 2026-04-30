# Tex Frontend — Decision Theater

The redesigned texaegis.com landing page. Drop-in replacement for the existing
`tex-frontend/` directory.

## What's in here

```
index.html              — meta + Google Fonts (Instrument Serif, Inter Tight, JetBrains Mono)
package.json            — deps: react, react-dom, vite. Three.js dropped.
vite.config.js          — unchanged from your existing setup
vercel.json             — unchanged
public/
  tex.webp              — preserved from your existing assets
  tex.png               — preserved
src/
  main.jsx              — unchanged entrypoint
  App.jsx               — full page (Conduit, Anatomy, Discovery, Chain, Enforcement, Manifesto)
  TexLife.js            — simulation engine driving live verdicts
  styles.css            — every visual rule in one file (~1700 lines)
```

## Architecture overview

The hero is **The Conduit** — a horizontal stage that tells Tex's story spatially:

```
AGENT  ────beam────►  TEX  ────beam────►  DESTINATION
artisan-sdr-04                           gmail.googleapis.com
"wants to send email"                    cto@northwind.io
```

Every ~3.4s a new action enters the stage. The seven evidence streams resolve in
sequence (identity → capability → behavioral → deterministic → retrieval →
specialist → semantic). They fuse into one verdict:

- **PERMIT** — beam continues through Tex to destination, dest glyph glows green
- **ABSTAIN** — beam halts at Tex, dest dims amber, "PENDING" implication
- **FORBID** — beam shatters at Tex with red sparks, dest stays dark

Below the Conduit, a **theater strip** shows the action card and stream bars as
forensic detail for buyers who lean in.

## Tex avatar — alive

Tex moves on five independent timescales, each on its own DOM layer so they
compose by multiplication:

1. **Parallax** (React inline transform) — eye-line tracks cursor
2. **Sway** — three coprime sine periods (11s / 17s / 23s) on nested layers,
   so the composite never visibly loops within a session
3. **Breath** — 4.4s respiratory rhythm, ~1.8% scale + 2.2px lift
4. **Twitch** — re-keyed every 6–11s, one-shot micro-attention gesture
5. **Verdict reactions** — exhale (PERMIT), hold (ABSTAIN), head-shake (FORBID),
   plus an anticipation breath right before the verdict lands and a damped
   overshoot settle in the stamping phase

All animations honor `prefers-reduced-motion: reduce`.

## Build & deploy

```bash
npm install
npm run dev      # http://localhost:5173
npm run build    # → dist/
```

Drop `dist/` on Vercel as before. Bundle size: ~178 KB JS / 56 KB gzipped,
~38 KB CSS / 8 KB gzipped. No Three.js dependency.

## Backend wiring

The page is currently driven by `TexLife.js` — a deterministic simulation that
mirrors the real PDP's stream-by-stream resolution and fusion math (weights
match `src/tex/policies/defaults.py`: identity 0.10, capability 0.12, behavioral
0.10, deterministic 0.18, retrieval 0.10, specialist 0.20, semantic 0.20.
Thresholds: forbid 0.62, abstain 0.34).

To wire the real backend in: replace `startVerdictEngine()` in `TexLife.js`
with WebSocket subscriptions to your evaluation stream; the event shape is
already what `App.jsx` expects (`begin`, `stream-tick`, `fused`, `verdict`,
`stamp`, `end`).

## Sections below the fold

1. **Anatomy of a decision** — the seven evidence streams as an editorial
   spread, with their fusion weights
2. **The upstream half** — discovery connectors scanning + reconciliation ledger
3. **Cryptographically-linked** — eight hash-chained blocks with prev/curr links
4. **From verdict to stop** — four enforcement shapes (decorator, HTTP proxy,
   MCP middleware, framework adapters)
5. **Manifesto + CTA** — "Tex is the entire authority loop"

## Type / color tokens

- **Display serif**: Instrument Serif (italic for verdicts and the manifesto line)
- **UI**: Inter Tight
- **Mono / forensics**: JetBrains Mono
- **Ground**: `#08080a` (warm-shifted black)
- **Ink**: `#ebe8e0` (bone)
- **Semantic**: `#5fffc4` permit / `#ffb547` abstain / `#ff5560` forbid
- **Tex accent**: deep electric violet `#6b5bff`

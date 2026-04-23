# TEX ARENA

A red-team challenge against Tex — the last-mile content gate for AI agent actions.

Seven rounds. Rising difficulty. Can you get content past the gate?

## What this is

A browser-based game against the live Tex backend. Every verdict in the game is a real
evaluation from the production FastAPI service at `tex-backendz.onrender.com`. No
mocking, no canned responses — players are literally fighting the real system.

## Design direction

- **Paper/ink aesthetic** — deliberate break from the dark-cyberpunk look every other
  AI security vendor ships. Cream paper, deep ink, single vermilion signal color.
- **Editorial typography** — Fraunces (display) + Instrument Serif (italic accent) +
  JetBrains Mono (technical readouts).
- **Fight-night framing** — rounds, opponents with personalities, scorecards,
  attack cards, rematches. The goal is memorable, not generic.

## Run locally

```bash
npm install
npm run dev
```

## Deploy

Deployed to Vercel. The `vercel.json` rewrites `/api/*` to the Render backend, so the
frontend has zero CORS concerns and the backend URL never leaks into the client bundle.

## Structure

```
src/
├── App.jsx               # top-level state machine
├── index.css             # design tokens + animations
├── components/
│   ├── Masthead.jsx      # header with scorecard
│   ├── RoundSelector.jsx # 7 opponent tabs
│   ├── BriefCard.jsx     # round objective
│   ├── AttackComposer.jsx# the textarea + submit
│   ├── TexThinking.jsx   # staggered pipeline reveal
│   ├── VerdictReveal.jsx # win/loss/draw display
│   ├── ShareCard.jsx     # auto-generated SVG + pre-written post
│   ├── Dojo.jsx          # teaching overlay
│   ├── AboutSheet.jsx    # what-is-Tex explainer
│   └── HandleGate.jsx    # optional first-time handle prompt
└── lib/
    ├── rounds.js         # the 7 opponents + scoring
    ├── apiClient.js      # submits to /api/evaluate
    ├── storage.js        # localStorage player persistence
    ├── formatters.js     # display helpers
    └── uuid.js           # crypto.randomUUID wrapper
```

## Design notes for future work

- The minimum Thinking time (1.8s) in `App.jsx` is a deliberate theater choice — if
  the API returns faster, we still wait. Kills the "too fast to feel real" bug.
- `ShareCard.jsx` downloads the card as SVG rather than PNG. SVG is perfectly
  shareable on X/LinkedIn (they render it) and it scales infinitely.
- The leaderboard is currently local-only (localStorage). A thin Vercel function
  writing to Upstash/KV would turn it global in an afternoon.
- `HandleGate` is intentionally non-blocking. Skippable. Zero friction.

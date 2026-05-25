# Tex frontend — v3.1

Homepage: hero → moment. One word, then one decision.

## What's here

```
tex-frontend/
├── index.html                     ← Inter + Source Serif 4
├── package.json
├── public/
│   └── favicon.svg
└── src/
    ├── main.jsx
    ├── App.jsx
    ├── styles.css                 ← global tokens (shared with the product)
    ├── sections/
    │   ├── HeroSection.jsx        ← screen 1 — "Quiet."
    │   ├── HeroSection.css
    │   ├── MomentSection.jsx      ← screen 2 — the Kestrel card
    │   └── MomentSection.css
    └── components/
        ├── CalendlyModal.jsx      ← Show me → Calendly
        └── CalendlyModal.css
```

Run:

```
npm install
npm run dev
```

## Calendly

`Show me` (hero) opens an inline Calendly modal. Set your URL in:

```
src/components/CalendlyModal.jsx
```

at the constant `CALENDLY_URL`.

## The two screens

### Screen 1 — Hero
Flat warm canvas (`--tex-bg-1`). The whole pitch in one frame:

- **Quiet.** — Source Serif 4, up to 240px
- Every agent. Every action. Every stage of its life.
- *Tex is the only system that governs all of it.*
- **Show me** → Calendly
- Quiet down-arrow → scrolls to screen 2

### Screen 2 — Moment
Diagonal cool drift (`--tex-bg-1` → `--tex-bg-2` → `--tex-bg-3`) plus
two ambient washes — the light coming through the window. Pixel-identical
to the Execution card in the product.

- *Monday, 9:14 a.m. · A real decision Tex made this morning.*
- **The Kestrel card.** Same component, same voice, same buttons.
- `Show me` → `/execution` (the live room)
- `Thank you` → quiet acknowledgement

The marketing site and the product share one design system. Nothing
is a screenshot. The card on the homepage is the same component the
customer sees the first time Tex needs them.

## Tokens — single source of truth

All colors, type, and radii come from `:root` in `src/styles.css`.

| Token            | Value         | Role                          |
| ---------------- | ------------- | ----------------------------- |
| `--tex-ink`      | `#1d1a17`     | primary type, primary button  |
| `--tex-ink-soft` | `#6b6358`     | aside type, ghost button text |
| `--tex-ink-mute` | `#8b8478`     | hints, timestamp              |
| `--tex-coral`    | `#c5482f`     | presence dot, card dot        |
| `--tex-bg-1`     | `#f6f6f8`     | hero canvas, gradient start   |
| `--tex-bg-2`     | `#eef0f6`     | gradient mid                  |
| `--tex-bg-3`     | `#e8ecf4`     | gradient end                  |
| `--tex-serif`    | Source Serif 4 | display, asides, timestamp   |
| `--tex-sans`     | Inter         | UI, nav, buttons              |

## What's not on the homepage (intentionally)

- No feature grid of the six rooms
- No customer logos / press bar
- No "how it works" diagram
- No annotations pointing at parts of the card
- No second card next to the first
- No avatar in the hero
- No "Book a demo" / "See how it works" two-button stack
- No throughput brag ("4,827 decisions this hour")

The hero promises. The moment proves. That's the whole page.

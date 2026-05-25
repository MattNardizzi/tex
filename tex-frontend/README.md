# Tex frontend — v3.0

The whole homepage hero, redesigned to one sentence and one word.

## What's here

```
tex-frontend/
├── index.html                     ← Inter + Source Serif 4 (exact set from demo)
├── package.json                   ← React 18, Vite, Phosphor (matches demo)
├── public/
│   └── favicon.svg
└── src/
    ├── main.jsx
    ├── App.jsx
    ├── styles.css                 ← global tokens (matches ExecutionRoom)
    ├── sections/
    │   ├── HeroSection.jsx        ← the hero
    │   └── HeroSection.css
    └── components/
        ├── CalendlyModal.jsx      ← Show me → opens Calendly inline
        └── CalendlyModal.css
```

Run:

```
npm install
npm run dev
```

## Calendly

`Show me` opens an inline Calendly modal. Set your URL in:

```
src/components/CalendlyModal.jsx
```

at the constant `CALENDLY_URL`.

## Tokens — single source of truth

All colors, type, and radii come from `:root` in `src/styles.css`. The
ExecutionRoom and the marketing site share these tokens, so the
product and the homepage feel like one continuous surface.

| Token            | Value      | Role                          |
| ---------------- | ---------- | ----------------------------- |
| `--tex-ink`      | `#1d1a17`  | primary type, primary button  |
| `--tex-ink-soft` | `#6b6358`  | aside type, ghost button text |
| `--tex-ink-mute` | `#8b8478`  | hints, scroll cue             |
| `--tex-coral`    | `#c5482f`  | presence dot                  |
| `--tex-bg-1`     | `#f6f6f8`  | page canvas                   |
| `--tex-serif`    | Source Serif 4 | display + asides          |
| `--tex-sans`     | Inter      | UI + nav                      |

## What was removed

- `BackdropWebGL.jsx` (Three.js scene)
- `EcosystemRing.jsx` (governance ring)
- `tex-avatar.png` (armored figure — belongs on Company, not here)
- 132KB `App.jsx` of legacy sections
- 188KB `styles.css` of legacy CSS
- "Airspace Control" headline
- `H-001 / Airspace Control` eyebrow code
- "Book a demo" / "See how it works" two-button stack
- 360° GOVERNANCE eyebrow

## What's on the screen

- T mark + "Tex" (top-left)
- "• Tex is here" (top-center)
- How it works · Evidence · Company · Sign in (top-right)
- **Quiet.** — Source Serif 4, 240px at desktop
- Every agent. Every action. Every stage of its life.
- *Tex is the only system that governs all of it.*
- **Show me** — opens Calendly
- Quiet down-arrow scroll cue

Nothing else.

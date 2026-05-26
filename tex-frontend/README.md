# Tex frontend — v5.0

Homepage: hero → self → moment → lifecycle → evolution → closer.
Six beats. One voice. The page opens loud and ends quiet, but the
light comes home.

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
    │   ├── HeroSection.jsx        ← screen 1 — "Absolute."
    │   ├── HeroSection.css
    │   ├── SelfSection.jsx        ← screen 2 — Tex, on what it does
    │   ├── SelfSection.css
    │   ├── MomentSection.jsx      ← screen 3 — "I stopped something."
    │   ├── MomentSection.css
    │   ├── LifecycleSection.jsx   ← screen 4 — "Before. During. After."
    │   ├── LifecycleSection.css
    │   ├── EvolutionSection.jsx   ← screen 5 — the moat, in three beats
    │   ├── EvolutionSection.css
    │   ├── CloserSection.jsx      ← screen 6 — "The weight is mine now."
    │   └── CloserSection.css
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

## The six screens

### Screen 1 — Hero
Flat warm canvas (`--tex-bg-1`). The whole pitch in one frame:

- **Absolute.** — Source Serif 4, up to 280px
- Every agent. Every action. Every stage of its life.
- *Tex is the only system that governs all of it.*
- **Show me** → Calendly
- Quiet down-arrow → scrolls to screen 2

### Screen 2 — Self
Tex's own reply. Six plain sentences, arriving one beat at a
time on scroll. No grid. No numbers. No icons. No subheads. A
poem, not a feature list.

> I find every agent.
> I verify who they are.
> I watch behavior over time.
>
> I act, or I don't.
>
> I show my work.
> I get sharper.

The fourth line is the pivot. The three above it describe what
Tex does to the world. The two below describe what Tex owes the
human. The line earns its weight from the silence around it,
not from a different typeface or color. Ma is the entire
treatment.

### Screen 3 — Moment
Diagonal cool drift (`--tex-bg-2` → `--tex-bg-3`) plus two
ambient washes. Pixel-identical to the Execution card in the
product. The previous section's promise — *"I act, or I don't"*
— is paid off here, in the *don't*:

- **I stopped something.**
- *I'd like you to look.*
- `Show me` → `/execution` (the live room)

The marketing site and the product share one design system.
Nothing is a screenshot. The card on the homepage is the same
component the customer sees the first time Tex needs them.

### Screen 4 — Lifecycle
The room is the same. The orb is gone. One italic sentence,
centered, big enough to hold the page alone:

> *I'm there before the action. During it. After.*

The triple beat names the six rooms — Discovery, Identity,
Observability sit in the *before*; Execution in the *during*;
Evidence and Evolution in the *after* — without ever naming
a system. The user hears the sentence; the architecture is
the subtext.

### Screen 5 — Evolution
The only claim no competitor in the category can make. Three
italic sentences, each resolving from blurred depth on its own
beat. After the third settles, a single horizontal light sweep
passes across all three — the same glass material the hero
uses on "Absolute." — and the section goes quiet.

> *I learn your environment.*
> *I evolve with your agents.*
> *I get smarter every day.*

The marketing site behaves like one piece of glass with light
moving through it at the moments that matter. The hero word
breathes with light. Section five sees that light pass once
over the three sentences, tying them together. No loop.

### Screen 6 — Closer
The arc closes. The canvas warms back to bg-1 — the same warm
cream the user landed on at the hero. One italic line, the
largest on the page outside the hero word itself, resolving
slowly from depth:

> *The weight is mine now.*

Every Tex line above has begun with "I" and described what Tex
does. This sentence still belongs to Tex, but its subject is
the thing it lifts off the user — what the user has been
carrying without saying so. The page opens loud, ends quiet,
and the light comes home.

## Animation vocabulary

Two physical metaphors carry the whole page:

- **Resolve from depth.** A line begins blurred and slightly
  below its resting position, then sharpens and rises into
  place. Used on Self (six lines, one at a time), Evolution
  (three lines, one at a time), and the Closer (one line, the
  slowest). The blur is what makes a sentence feel like a
  *thought arriving* rather than text appearing.

- **Light through glass.** A soft cool-white band passes
  horizontally across the text, masked to the glyph shape via
  mix-blend-mode. Used on the hero's "Absolute." (continuous,
  slow) and on Evolution (a single pass across all three lines,
  triggered after they've all settled). The marketing site
  behaves like one piece of glass; the light moves through it
  at the moments that matter.

Both metaphors honor `prefers-reduced-motion: reduce`. Reduced
motion users see the same page, statically composed.

## Tokens — single source of truth

All colors, type, and radii come from `:root` in `src/styles.css`.

| Token            | Value         | Role                          |
| ---------------- | ------------- | ----------------------------- |
| `--tex-ink`      | `#1d1a17`     | primary type, primary button  |
| `--tex-ink-soft` | `#6b6358`     | aside type, ghost button text |
| `--tex-ink-mute` | `#8b8478`     | hints, timestamp              |
| `--tex-coral`    | `#c5482f`     | presence dot, card dot        |
| `--tex-bg-1`     | `#f6f6f8`     | hero canvas, closer canvas    |
| `--tex-bg-2`     | `#eef0f6`     | gradient mid                  |
| `--tex-bg-3`     | `#e8ecf4`     | gradient end                  |
| `--tex-serif`    | Source Serif 4 | display, asides, timestamp   |
| `--tex-sans`     | Inter         | UI, nav, buttons              |

## The light moves through one room

Hero (bg-1) → Self (bg-1 → bg-2) → Moment (bg-2 → bg-3) →
Lifecycle (bg-3 → bg-2 → bg-3) → Evolution (bg-3 → bg-2) →
Closer (bg-2 → bg-1). The page cools through the middle and
warms back at the end. Same room throughout, but the light
moves.

## What's not on the homepage (intentionally)

- No feature grid of the six rooms — the self section is a
  poem, not tiles
- No customer logos / press bar
- No "how it works" diagram
- No annotations pointing at parts of the card
- No second card next to the first
- No avatar in the hero
- No "Book a demo" / "See how it works" two-button stack
- No throughput brag ("4,827 decisions this hour")
- No numbered steps, icons, or subheads on the self section
- No operator vocabulary anywhere — Tex speaks; the user ratifies

The hero declares. The self section answers. The moment proves.
The lifecycle holds. The evolution names the moat. The closer
turns to face the reader. That's the whole page.

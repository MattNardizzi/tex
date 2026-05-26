# Tex — marketing site

The eight-section homepage for Tex by VortexBlack. Built as Jobs would build it in 2050: pure white paper, one orb across every section, three type sizes, every motion a verb from the codebase.

## The arc

| # | Section    | Sentence Tex says               | What it demonstrates                |
|---|------------|---------------------------------|-------------------------------------|
| 1 | Hero       | _Absolute._                     | the claim                           |
| 2 | Bridge     | _Watch._                        | the invitation                      |
| 3 | Presence   | I see them all.                 | Discovery + Identity                |
| 4 | Foresight  | I see what's coming.            | Observability (digital twin + cone) |
| 5 | Moment     | I stopped one.                  | Execution                           |
| 6 | Evidence   | Every decision, signed.         | Signed, chained, offline-verifiable |
| 7 | Evolution  | Sharper, only with your hand.   | Learning under human gate           |
| 8 | Closer     | The weight is mine now.         | the breath out                      |

Each section is one sentence, one demonstration, the orb in a different posture. The screen is the trace of a conversation, not a feature grid.

## Design system

- **Canvas:** pure white (`#ffffff`). No washes, no gradients, no ambient color in the corners.
- **Type:** three sizes only.
  - Display serif italic (`Source Serif 4`, 48–84px) — the one sentence per section.
  - Reading serif italic (20–26px) — asides and captions.
  - Proof mono (`SF Mono`, 11px, uppercase, tracked) — machine identifiers and the proof line.
- **Ink:** `#14110d` on paper, with two soft greys (`#5e564c`, `#9b9388`).
- **Glass:** the orb and the hero word are the only soft objects on the page. Everything else is hard-edged.
- **Motion:** every animation represents a verb the product actually does. The orb breathes (presence). It drifts (attention). The chain resolves (signing). The shadow orb travels (simulation). Nothing performs for its own sake.

## Stack

- Vite + React 18
- Inter + Source Serif 4 (Google Fonts)
- No router, no state library, no UI framework. Just CSS and IntersectionObserver.

## Run

```bash
npm install
npm run dev      # http://localhost:5173
npm run build    # produces dist/
npm run preview  # serves dist/
```

## File map

```
src/
  App.jsx                  the eight-section spine
  main.jsx                 React entry
  styles.css               global tokens — type, ink, paper, rhythm
  components/
    Orb.jsx                the breathing presence (five layers, three states)
    Orb.css
  sections/
    HeroSection.jsx        1  Absolute.
    BridgeSection.jsx      2  Watch.
    PresenceSection.jsx    3  I see them all. I know who they are.
    ForesightSection.jsx   4  I see what's coming.
    MomentSection.jsx      5  I stopped one.
    EvidenceSection.jsx    6  Every decision, signed.
    EvolutionSection.jsx   7  Sharper, only with your hand.
    CloserSection.jsx      8  The weight is mine now.
```

— VortexBlack

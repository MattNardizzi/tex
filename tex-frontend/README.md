# Tex — marketing site

The eight-section homepage for Tex by VortexBlack. Built as Jobs would build it in 2050: pure white paper, one orb across every section, three type sizes, every motion a verb from the codebase.

Two front-ends, one product.

- **Desktop (≥ 721px wide).** A long white scroll. Eight sections stacked vertically. The orb travels from beat to beat as you scroll. Original design, byte-identical to the day it shipped.
- **Mobile (≤ 720px wide).** A vertical eight-card breath. Each card fills the phone (`100dvh`). Snap-scrolling between them. The same eight souls, redesigned from scratch for a piece of glass held at thumb distance.

The switch happens at runtime in `App.jsx` via `useIsMobile()` — viewport changes are live, no reload required.

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

## The mobile redesign

Each desktop section was reimagined for the phone — not shrunk, not "responsive." Every card was designed from scratch around the constraints of a 5-inch piece of glass held in one hand.

| # | Desktop says it with…                                              | Mobile says the same thing with…                                                                  |
|---|--------------------------------------------------------------------|---------------------------------------------------------------------------------------------------|
| 1 | A 900-wide glass "Absolute." word, three serif beats below          | The glass word retuned for portrait, filling the top half; three beats arrive one breath apart    |
| 2 | Orb centered in vast white space, one word below                    | Orb at true visual center; *Watch.* floats at the halo's lower edge — one paired thought          |
| 3 | A fan of 8 agent names arcing around the orb                        | A single name slot beneath the orb; 8 names pass through it in time; a tally accumulates          |
| 4 | Horizontal timeline; shadow orb runs left-to-right; cone opens      | Vertical plumb line drops from the orb; ghost orb falls; cone widens downward                     |
| 5 | Orb drifts left; copy resolves to its right                         | Orb stays put; copy resolves beneath it in two phases — *All quiet* → *I stopped one*             |
| 6 | 10-link horizontal chain with branch-down to BUNDLE.ZIP             | Vertical chain of 5 visible links + `+ 3` / `+ 2` elision marks; highlighted link branches sideways |
| 7 | Orb on left, proposal card on right                                 | Orb at top, proposal card fills the phone width                                                   |
| 8 | Orb center, line beneath, footer drifts in below                    | Same composition tuned to phone proportions; soft three-link signature at the bottom              |

The mobile shell adds a single piece of persistent UI: eight 1-px progress notches at the top of the screen, indicating where you are in the eight-card arc. Tapping a notch jumps to that card. Everything else is silence.

## Design system

- **Canvas:** pure white (`#ffffff`). No washes, no gradients, no ambient color in the corners.
- **Type:** three sizes only.
  - Display serif italic (`Source Serif 4`, 48–84px on desktop, 32–52px on mobile) — the one sentence per section.
  - Reading serif italic (15–26px) — asides and captions.
  - Proof mono (`SF Mono`, 9–12px, uppercase, tracked) — machine identifiers and the proof line.
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
  App.jsx                  the eight-section spine + mobile branch
  main.jsx                 React entry
  styles.css               global tokens — type, ink, paper, rhythm
  hooks/
    useIsMobile.js         live viewport detector (722px cut)
  components/
    Orb.jsx                the breathing presence (five layers, three states)
    Orb.css
  sections/                ← desktop only. Unchanged from original.
    HeroSection.jsx        1  Absolute.
    BridgeSection.jsx      2  Watch.
    PresenceSection.jsx    3  I see them all. I know who they are.
    ForesightSection.jsx   4  I see what's coming.
    MomentSection.jsx      5  I stopped one.
    EvidenceSection.jsx    6  Every decision, signed.
    EvolutionSection.jsx   7  Sharper, only with your hand.
    CloserSection.jsx      8  The weight is mine now.
  mobile/                  ← mobile only. New for this release.
    MobileApp.jsx          the eight-card vertical scroller
    MobileProgress.jsx     the eight progress notches at the top
    cards/
      HeroCard.jsx         1  Absolute.
      BridgeCard.jsx       2  Watch.
      PresenceCard.jsx     3  I see them all.
      ForesightCard.jsx    4  I see what's coming.
      MomentCard.jsx       5  I stopped one.
      EvidenceCard.jsx     6  Every decision, signed.
      EvolutionCard.jsx    7  Sharper, only with your hand.
      CloserCard.jsx       8  The weight is mine now.
```

— VortexBlack

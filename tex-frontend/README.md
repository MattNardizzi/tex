# Tex — marketing site

The eight-section homepage for Tex by VortexBlack. Built as Jobs would build it in 2050: pure white paper, one orb across every section, three type sizes, every motion a verb from the codebase.

**Two front-ends, one product.**

- **Desktop (≥ 721px wide).** A long white scroll. Eight sections stacked vertically. The orb travels from beat to beat as you scroll. Original design, byte-identical to the day it shipped.
- **Mobile (≤ 720px wide).** A vertical eight-card breath. Each card fills the phone (`100dvh`). Snap-scrolling between them. Each card is a **brand new composition** — chosen and built because it only works on a phone. Same eight sentences, eight new visual ideas.

The switch happens at runtime in `App.jsx` via `useIsMobile()` — live resize handled, no reload required.

## The arc — same on both, eight sentences in order

| # | Sentence Tex says               | What it shows                                |
|---|---------------------------------|----------------------------------------------|
| 1 | _Absolute._                     | the claim                                    |
| 2 | _Watch._                        | the invitation                               |
| 3 | I see them all.                 | Discovery + Identity                         |
| 4 | I see what's coming.            | Observability — simulation in the cone       |
| 5 | I stopped one.                  | Execution — Tex speaks when it acts          |
| 6 | Every decision, signed.         | Signed, chained, offline-verifiable          |
| 7 | Sharper, only with your hand.   | Learning under a human signature             |
| 8 | The weight is mine now.         | the breath out                               |

## The eight mobile compositions

Each one is a brand-new design picked because it only makes sense on a phone.

| # | Section    | Mobile composition                                                                                              |
|---|------------|-----------------------------------------------------------------------------------------------------------------|
| 1 | Hero       | The word _Absolute._ set at 180px outline-only serif italic, **bleeding off both edges**; you see "solute". The word exceeds the frame. Three small mono beats stack underneath. The word slowly drifts. |
| 2 | Bridge     | Screen begins **fully dark ink**. A circle of paper dilates from center, pushing the dark to a vignette. Orb materializes from the light. _Watch._ resolves letter-by-letter. OLED-native reveal. |
| 3 | Presence   | Eight agent names **rain down vertically** through one slot beneath the orb, each crossing the horizon and locking into a **constellation around the orb**. By the end, all eight hold position in space. |
| 4 | Foresight  | The user **drags the orb down with their thumb**. A ghost orb follows the finger forward in time. A conformal cone widens with pull distance. Auto-demos once if no touch within 2s. |
| 5 | Moment     | Silence (1.6s) → **screen flashes inverted** (paper → ink) with orb intensifying and `navigator.vibrate([60,40,20])` haptic → paper returns with asking-state orb and "I stopped one. I'd like you to look." + the only button on the arc: **Show me**. |
| 6 | Evidence   | A **fanned deck of evidence cards**, each with verdict badge (PERMIT/ABSTAIN/FORBID), timestamp, hash, note, and SIGNED · POST-QUANTUM proof line. Top card swaps every 1.1s. BUNDLE.ZIP mark beneath. |
| 7 | Evolution  | A **press-and-hold ring**. The user must physically hold for 1.5 seconds; progress fills around the 64px circle. On complete, ring inverts to ink, label "HOLD" → "SIGNED", aside "Press and hold." → "Sharper.", with a haptic confirm pulse. You cannot tap-and-go. |
| 8 | Closer     | The orb takes the **full screen** at 1.6× scale, breathing large. The line _The weight is mine now._ appears word-by-word. After a long beat, the line fades — but the orb keeps breathing. No footer ever appears. |

The mobile shell adds one piece of persistent UI: eight 1px progress notches at the top of the screen. Tap any notch to jump. Everything else is silence.

## Design system

- **Canvas:** pure white (`#ffffff`). Only Card 2 (Bridge) breaks this rule, briefly, as the iris dilates from ink.
- **Type:** three sizes only.
  - Display serif italic (`Source Serif 4`, 48–180px) — the one sentence per section
  - Reading serif italic (15–26px) — asides and captions
  - Proof mono (`SF Mono`, 8.5–12px, tracked) — machine identifiers and tags
- **Ink:** `#14110d` on paper, with two soft greys (`#5e564c`, `#9b9388`)
- **Glass:** the orb and the hero word are the only soft objects on the page
- **Motion:** every animation represents a verb the product actually does. Iris dilation (waking up). Rain (discovery). Pull (simulation). Flash (interception). Deck shuffle (signing stream). Hold (commitment). Breath (presence). Nothing performs for its own sake.

## Stack

- Vite + React 18
- Inter + Source Serif 4 (Google Fonts)
- No router, no state library, no UI framework. Just CSS, IntersectionObserver, and Pointer Events.

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
  App.jsx                  branches: desktop ≥721px, mobile ≤720px
  main.jsx                 React entry — unchanged
  styles.css               global tokens — unchanged
  hooks/
    useIsMobile.js         live matchMedia detector
  components/
    Orb.jsx                the protagonist — unchanged
    Orb.css                unchanged
  sections/                ← desktop only. ALL byte-identical to original.
    HeroSection / BridgeSection / PresenceSection / ForesightSection /
    MomentSection / EvidenceSection / EvolutionSection / CloserSection
  mobile/                  ← mobile only. New for this release.
    MobileApp.jsx          vertical scroll-snap shell
    MobileProgress.jsx     eight tap-jumpable progress notches
    cards/
      HeroCard       — bleeding outline word
      BridgeCard     — iris dilation from ink
      PresenceCard   — falling-name constellation
      ForesightCard  — drag-to-pull the future
      MomentCard     — silence → flash → speak (with haptic)
      EvidenceCard   — fanned auto-cycling deck
      EvolutionCard  — press-and-hold to sign (with haptic)
      CloserCard     — orb takes the screen, page exhales
```

— VortexBlack

# Tex — the site (vortexblack.ai)

A single self-contained `index.html`. No build step, no dependencies, no framework.
It deploys anywhere instantly and renders identically when you send the link.

## One law

The site is governed by the **product**, not the deck. Someone landing here is
meeting Tex for the first time, so it should feel like meeting Tex — warm paper,
the voice at one weight, one rise, silence — not like watching a trailer about it.

Three rules carry that law, and they are the whole of the visual system:

1. **One weight.** The voice is EB Garamond at `400`, everywhere, never heavier.
   Emphasis comes from size, from ink-vs-mute colour, from italic (reserved for the
   one pivotal line), and from space. Never from weight. *Presence is the weight and
   the verb, not the point size.*
2. **One motion.** Everything that arrives rises the same way — opacity in, a 7px
   lift, on a single easing curve (`cubic-bezier(.22,.61,.36,1)`), the product's
   curve. Nothing animates letter-spacing, weight, scale, or blur; those were what
   made the old turn stutter. Elements differ only in duration and delay.
3. **One palette, warm paper.** `#fcfbf9` at rest — never clinical `#fff`, which
   reads like a blank document. Ink, two greys, one hairline. Colour appears once
   or never.

## The sequence

**The turn (hero).** Cold white room — *agents are already acting inside your
company.* The verdict rises on bare paper, line by line: *everything else learned
to watch them. To score them. To raise an alert. And to wait for you.* — then, in
italic, *you were already too late.* It clears, the room **warms**, the longest
silence on the page, and **I am Tex.** rises slow. The headline lands: *I decide
what your agents may do. You will not supervise me.* It rests there. Click anywhere
in the hero (or press Space) to skip to the rest.

> The vendor wall was removed. It was the one thing on the page that wasn't calm,
> and it made the market look loud — the opposite of *everything else watches; Tex
> decides.* The antagonist is carried by the words now. If a busy object ever feels
> necessary again, the page has lost its nerve: add a sentence, not a wall.

**The spine.** One sentence, alone on warm paper: **Everything else watches. Tex
decides.** The contrast is colour and a hair of scale, never weight.

**The body — six layers, six things Tex says.** One sentence and one quiet proof
each, never a feature card:

1. **Presence** — discovery + identity. Every agent seen and named, the impostors
   known, sealed into the record at the moment of discovery.
2. **Foresight** — monitoring. The live state forked and run forward, with a
   coverage guarantee. *But watching was never the point.*
3. **Judgment** — execution governance, the heart. *I permit. I forbid. I hold —
   and I tell you.* Thousands of times a day, on Tex's own authority.
4. **Evidence** — the one object. A hash-chained, post-quantum, offline-verifiable
   record. Reach for one and it rises in monospace, then dissolves once taken.
5. **Learning** — calibration with your hand. Every change proposed, replayed
   against the last ninety days, applied only once you've signed.

**The coda.** One sentence, alone on warm paper — the spine's twin in ink and
scale: **One voice.** The spine opened the six layers (*Tex decides*); this closes
them. What watches hands you six dashboards; Tex resolves to one voice. Placed at
the collapse it is a payoff, not a tagline — which is why it is here and not at the
top, where it would describe Tex before Tex has spoken.

**The closer.** *The weight is mine now.* — and **Begin** (the one weighted act,
identical to the product's Approve pill), which opens the meeting inline.

## The one action

Begin opens a Calendly modal in place; the visitor never leaves the page. Point it
wherever you like:

```js
const CAL = "https://calendly.com/matt-vortexblack/tex-trial";
```

Beneath Begin, one faint line — **Hear it** — opens the film (the sound-on turn at
`tex-deck.com`) in a new tab. It is deliberately *not* a second weighted act: muted
serif, no pill, risen last. Begin stays the only inked decision on the page. The
film is the same turn the hero performs in silence, so the one thing it promises is
the one thing it adds — sound. (Longer term it belongs under `tex.systems`, not a
third domain; that's an infra move, not a code change.)

## Accessibility & motion

A screen-reader `h1` carries the full claim. `prefers-reduced-motion` is honoured:
the lines are content, not decoration, so they all appear at once on warm paper
with nothing moving. With JS off, a `<noscript>` block states the name and the line.

## Deploy

Static. Drop the folder on Vercel (or anywhere). `vercel.json` keeps clean URLs and
routes everything to `index.html`.

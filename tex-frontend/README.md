# Tex — the site (vortexblack.ai)

A single self-contained `index.html`. No build step, no dependencies, no framework.
It deploys anywhere instantly and renders identically when you send the link — the
same way the deck is built.

This replaces the prior React/Vite app for this surface. The marketing site has one
interaction (scroll) and one action (a meeting). React was noise here; one file means
total control of every pixel and every millisecond of the cold-to-warm turn. The old
React source still lives in your original `tex-frontend` upload if you ever want it —
porting this markup into a component is a copy-paste away.

## The sequence

**The turn (hero).** The deck, compressed, played once. Cold white room — *agents are
already acting inside your company.* The vendor wall rises and piles (Zenity, Noma,
Palo Alto, Cisco, CrowdStrike, Astrix, Saviynt, Protect AI, CyberArk, Keycard, Oasis,
+40 more) — the antagonist, rendered as fact in cold grey, never their screenshots. The
verdict over the receding wall: *everything else learned to watch them. To score them.
To raise an alert. And to wait for you.* — then, in italic: *you were already too late.*
The wall dissolves, the room **warms**, the longest silence on the page, and **I am Tex.**
rises slow. The headline lands: *I decide what your agents may do. You will not supervise
me.* It rests there. Click anywhere in the hero (or press Space) to skip to the rest.

**The spine.** One sentence, alone on warm paper: **Everything else watches. Tex decides.**

**The body — six layers, six things Tex says.** One sentence and one quiet proof each,
never a feature card:

1. **Presence** — discovery + identity. *I see every agent you're running. And I know
   which ones are pretending to be something they're not.*
2. **Foresight** — monitoring, deliberately subordinate. *I see what's coming… but
   watching was never the point.*
3. **Judgment** — execution governance, the heart. *I permit. I forbid. I hold — and I
   tell you. All quiet. I stopped one. I'd like you to look.*
4. **Evidence** — the one object. *Every decision I make, I sign.* Reach, and a sealed
   hash rises in monospace, then dissolves once taken — the only thing the glass is ever
   allowed to hold.
5. **Learning** — *I get sharper. Never on my own.*

**The closer.** The breath out: **The weight is mine now.** One quiet act: **Begin** —
which is exactly how the product opens. The site's last screen is the product's first.

## Material

One design system, shared with the product:

- **EB Garamond** — the voice, roman and upright. Italic appears exactly twice, on the
  two emotional pivots (the antagonist coda, the human hand-off). Nowhere else.
- **Geist / Geist Mono** — the chrome and the single machine object. Objects are never
  set in the voice.
- Ink `#14110d`, warm paper `#faf8f3`. The hero is the only cold thing; a white sheet
  lifts off the warm body when Tex speaks, so there is no seam below.
- No orb. No glass. No gradients. Presence is the warming room and the voice — never an
  object floating at center.

## Deploy

1. `vercel.com/new` → drag this folder in → **Deploy.** Static, no settings.
2. Project → Settings → Domains → add `vortexblack.ai`.

Or from the CLI: `npx vercel` then `npx vercel --prod`.

## Tuning

Everything lives at the bottom of `index.html` in the `<script>`:

- **The turn's pacing** is the `run()` async function — every `sleep(ms)` is one beat.
  The two that matter most are the silence before the name and how long the name rests
  (the two longest `sleep` calls). Make the silence longer than feels comfortable.
- **The wall** is the `VENDORS` array — names, positions (`x`/`y` as %), size (`s` in
  rem), rotation (`r`), opacity (`o`), and rise delay (`d` in ms).
- **The Calendly link** is `CAL` — currently `calendly.com/matt-vortexblack/tex-trial`.
- **The sealed hashes** shown on reach are the `SEALS` array (illustrative).

## Accessibility

The lines are content, not decoration: with reduced motion the room is already warm and
every line is shown, nothing moves. A visually-hidden `h1` and a `<noscript>` fallback
both carry the name and the headline.

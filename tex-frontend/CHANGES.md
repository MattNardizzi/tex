# Tex Frontend — v3 Redesign

## What changed

Below the frozen hero (TopBar, Conduit, Theater Strip, VerdictOverlay, ChainTicker, ScrollCue), every section was rebuilt as one continuous dark cinematic scroll. No more checkerboard alternation. No more "Tex is the fifth layer" framing. Tex is presented as the entire authority loop.

## Section structure (post-hero)

01. **Thesis** — `.thesis`
    Massive serif litany. `Identity. Discovery. Capability. Evaluation. Enforcement. Evidence. Learning.` with `Evaluation` highlighted in violet. Coda: "One loop. One fingerprint. One chain." Violet axis line slides in on the right.

02. **The Loop** — `.loop`
    7-node animated SVG ring. Single violet pulse travels the whole ring. Detail panel auto-cycles through each node showing plain-language + technical credential. Pips below allow manual selection.

03. **Stack Collapse** — `.collapse`
    Left: today's stack as 4 dim rows (Identity/Posture/Behavior/Policy) with vendor names (Okta · Oasis · Auth0 / Zenity · Noma · Pillar / Rubrik SAGE · Virtue AI / Microsoft AGT · OPA · Cedar). Bridge: "collapse →". Right: one violet Tex ring with 5 nodes including Content highlighted as the layer nobody else builds.

04. **Anatomy of a Decision** — `.anatomy`
    Real production fusion weights from `policies/defaults.py` as horizontal bar chart. Footer: Σ 1.000 / ≤ 0.18 (PERMIT) / ≥ 0.72 (FORBID) / 2.2 ms median latency.

05. **Discovery Theater** — `.discovery`
    7 connectors as horizontal scanner with violet scan line moving across. Live reconciliation ledger below with hash prefixes, sources, candidates, color-coded outcomes (REGISTERED / UPDATED · DRIFT / QUARANTINED / NO-OP / HELD).

06. **Surface** — `.surface`
    Two stacked sub-blocks. (a) Capability polygon SVG with attempted action plotted as a point — inside polygon = PERMIT, outside = CRITICAL → FORBID with red halo pulse. (b) 64-band MinHash barcode showing tenant baseline vs candidate signature, novelty readout firing `tenant_novel_content` on far signatures.

07. **Enforcement** — `.enforce`
    Four code shapes in 2×2 grid: Decorator, HTTP proxy, MCP middleware, Framework adapter.

08. **Evidence Chain** — `.proof`
    Six chain blocks flowing horizontally with violet arrow links. Each block: index, verdict (color border), hash, prev hash, kind. Below: compliance marks bar (OWASP ASI 2026 · NIST AI RMF · ISO 42001 · EU AI Act · SOC 2 · FINRA · HIPAA).

09. **Trial** — `.trial`
    "Free · 14 days · full system" badge. Headline: "Run Tex against your live agent traffic for 14 days. Discovery, evaluation, enforcement, evidence chain." Four numbered cards: Full discovery scan / Live evaluation / Cryptographic evidence ledger / Day-14 readout. Two CTAs: "Start the 14-day trial" + "See it run on a sample workload".

10. **Manifesto** — `.manifesto`
    Verbatim manifesto. "I am Tex. The authority layer between AI and the real world." Final CTA row.

## Removed

- `.wedge` section (replaced by Loop + Collapse)
- `.audit` section (replaced by `.trial` — full system, not a service)
- `CompetitorMap` component (replaced by `StackCollapse`)
- `ProofStats` component (replaced by `ComplianceMarks`)
- "Tex is the fifth layer" framing throughout
- Bone background experiment (everything dark now)
- Mechanical dark/light alternation between sections

## Added

- `LoopRing` component — animated 7-node authority ring
- `StackCollapse` component — competitive demolition (4 layers vs 1 ring)
- `FusionMath` component — production weights as bar chart
- `DiscoveryTheater` component — connectors scanner + live ledger
- `CapabilitySurface` component — polygon + action point SVG
- `BehaviorBarcode` component — MinHash signature visualizer
- `ComplianceMarks` component — auditor framework bar
- `LOOP_NODES`, `STACK_LAYERS`, `FUSION_WEIGHTS`, `COMPLIANCE_MARKS`, `TRIAL_DELIVERABLES` constants

## Technical

- Frozen hero (`stage`, `TopBar`, `Conduit`, `theater-strip`, `VerdictOverlay`, `ChainTicker`, `ScrollCue`) untouched
- Verdict engine (`TexLife.js`) untouched
- Build: 198 KB JS, 57 KB CSS (gzip: 62 KB / 11 KB)
- All animations CSS-only or SVG-driven — no JS animation libraries added
- Reduced motion respected
- Responsive breakpoints at 1100px, 900px, 640px

## Pages affected

- `src/App.jsx` — section structure rewritten below hero, new components added
- `src/styles.css` — section styles below `SECTION HEADS` rewritten; manifesto/CTA/foot preserved verbatim

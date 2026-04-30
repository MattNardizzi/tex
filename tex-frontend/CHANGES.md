# Tex Frontend — Redesign Notes (April 2026)

## What changed

Hero (top of page) is **untouched**. Avatar, header counters, INBOUND ACTION
panel, EVIDENCE STREAMS bars, Σ FUSED bar, and the SCROLL · SYSTEM ANATOMY
ticker all render exactly as before.

Everything **below the ticker** has been replaced. The previous five sections
(Anatomy / Discovery / Chain / Enforcement / Manifesto) are now seven sections
that read as one continuous argument:

```
01 · Wedge          — dark   — "Everyone else watches the agent. Tex reads
                                what it's about to send." Plus a five-row
                                competitor map: Identity / Posture / Behavior /
                                Policy / Tex.
02 · Anatomy        — light  — Seven evidence streams as an editorial spread
                                on bone (#ebe8e0). The verdict card is the
                                climactic moment, set apart with violet.
03 · Proof          — dark   — Cryptographic chain visual + three trust
                                statements (SHA-256 / 2.2ms / replay).
04 · Discovery      — light  — Connectors + reconciliation ledger, on bone.
05 · Install        — dark   — Four enforcement shapes, each with real
                                copy-pasteable code (Python decorator, YAML
                                proxy config, MCP middleware, LangChain
                                adapter). 2-up grid, not 4-up.
06 · Audit offer    — light  — Free 20-email AI outbound audit. Four
                                deliverables. Primary CTA: "Request the
                                free audit."
07 · Manifesto      — dark   — Full closing thesis ending in "I am Tex.
                                The authority layer between AI and the
                                real world." Dual CTA: audit + demo.
```

## Why this structure

The market is crowded (Zenity, Noma, Rubrik SAGE, Microsoft AGT, Proofpoint,
Geordie, Virtue, Cequence, Prefactor — $3.6B raised across the top 10).
Buyers cannot tell vendors apart by the time they reach Tex. The wedge
section exists to give the buyer one sentence to repeat to their CISO:
*"Tex evaluates what the agent is about to send — that's the layer no one
else is building."*

Light/dark choreography (per Cloudflare/Zscaler/Vanta convention) signals
the rhythm: dark = "this is technically deep," light = "this is something
I can read and forward." The audit section is intentionally light, because
it converts.

## Build & deploy

```bash
npm install
npm run dev      # http://localhost:5173
npm run build    # → dist/ — ~184KB JS, ~48KB CSS
```

Drop `dist/` on Vercel as before. No new dependencies.

## Files touched

- `src/App.jsx`     — replaced 5 sections (~50 lines) with 7 sections,
                      added CompetitorMap + ProofStats components,
                      rewrote EnforcementPanel to render code blocks,
                      added COMPETITOR_MAP + AUDIT_DELIVERABLES constants.
- `src/styles.css`  — kept all hero / ticker / sh / chainviz / discovery
                      / anatomy-grid styles intact. Added: wedge, cmap,
                      anatomy-light overrides, proof + ps, discovery-light
                      overrides, install (refined enforcement),
                      audit, new manifesto block. ~620 new lines.

Top half of the page is byte-identical to v1 in DOM structure.

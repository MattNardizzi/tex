# Tex Arena — v9 release notes

**Theme:** OWASP ASI 2026 reference adjudicator. Locked positioning. Engineering-leader funnel + buyer funnel both run off a single OWASP-framed surface.

---

## What changed

### New files
- `src/lib/owaspAsi.js` — canonical OWASP ASI 2026 taxonomy (10 categories, descriptions, links, code normalizer)
- `src/components/OwaspFindings.jsx` — replaces "WHY TEX CAUGHT IT" panel; expandable ASI chips with descriptions + OWASP links
- `src/components/LayerBreakdown.jsx` — six-column visualization of which of the six pipeline layers fired
- `src/components/ComplianceStrip.jsx` — six-cell coverage strip (OWASP ASI · NIST · ISO 42001 · EU AI Act · FINRA · HIPAA)
- `src/components/AsiPage.jsx` — public `/asi` landing page; maps every ASI category to its incidents
- `src/components/DevelopersOverlay.jsx` — engineering-leader funnel; API key + 30-min arch review CTAs; integration snippets for curl / python / langgraph / crewai / kong
- `src/components/RunYourOwn.jsx` — paste any agent output, get a real Tex verdict, download evidence bundle

### Rewritten files
- `src/lib/incidents.js` — adds 6 new incidents (Inject, Handover, Hallucination, Tool-Storm, The Disclosure, The Pitch); every incident now tagged with vertical + ASI codes
- `src/lib/apiClient.js` — surfaces `router.layer_scores` + adds `evaluateCustom()` for run-your-own mode
- `src/components/Hub.jsx` — OWASP kicker, top-nav buttons (OWASP ASI / FOR ENGINEERING / FOR SECURITY TEAMS), "RUN YOUR OWN ATTACK" CTA, OWASP × compliance band, footer micro updated
- `src/components/Round.jsx` — incident card shows ASI codes; verdict line shows ASI chips + driving layer (e.g. "L:DETERMINISTIC")
- `src/components/VerdictReveal.jsx` — adds LayerBreakdown + OwaspFindings; "DOWNLOAD BUNDLE" button on signed evidence panel
- `src/components/BuyerSurface.jsx` — leads with OWASP ASI 2026 framing; primary CTA is "DOWNLOAD A SIGNED EVIDENCE SAMPLE" (hits live API, returns real bundle); compliance strip
- `src/App.jsx` — wires `/asi`, `/developers`, `/run` deep links; passes new handlers to Hub

### Build verified
- `npm run build` clean — 37 modules, 285KB JS bundle (85KB gzipped)
- No new dependencies added
- Backwards compatible with existing FastAPI backend response shape

---

## Routes / deep links

| URL pattern | Opens |
|---|---|
| `/` | Hub |
| `/asi` or `?asi` | AsiPage (full OWASP mapping) |
| `/developers` or `?developers` | DevelopersOverlay (engineering funnel) |
| `/buyer` or `?buyer` | BuyerSurface (security-team funnel) |
| `/run` or `?run` | RunYourOwn (paste your own output) |
| `?duel=<incidentId>&from=<handle>` | Hub with duel banner + that incident loaded |

---

## What's not in this build (intentionally)

- **Public Tex-vs-competitors benchmark.** Real harness work, 6–10 weeks of engineering. Don't fake it. Build it next.
- **Pitch deck, cap table, data room.** Outside the codebase. Build separately.
- **Pilot outbound sequences.** Outside the codebase. List + sequences live in your CRM, not the repo.
- **SOC 2 / ISO 42001 paperwork.** Plan it; this build only references it.

---

## Suggested next moves

1. Deploy this. Verify `/asi` ranks for "OWASP ASI 2026 reference adjudicator" within 2 weeks.
2. Pick 10 pilot targets (5 regulated, 5 platform). Send the buyer link + arch-review link to engineering leaders.
3. Start the benchmark harness. One published number ("we ran 1,000 attacks, here's what happened") changes the conversation with the strategics.
4. Draft the 10-page deck even though you won't send it for 6 months. Forces clarity.

# Tex Sandbox Simulator

A service-virtualized **synthetic enterprise AI-agent estate that Tex governs live.**

> The estate is fake. The governance is real.

The fake stops at exactly **two seams** — the same two where a real customer's
world enters Tex. Everything above them runs untouched: the discovery
connectors, reconciliation, the PDP, the hash-chained evidence ledger, the
vigil voice, the agent surface. Nothing in Tex knows the estate is synthetic.

This is what it gives you:

- **Test every part of Tex end-to-end** on demand, with one command.
- **Finish the interface** against a populated, behaving estate instead of mocks.
- **Demo the product honestly** — on first run it maps the inventory like a real
  enterprise ("mapping…"), a client can ask *show me any agent / prove it* and
  get a real hash-chained proof, and verdicts are real PERMIT / ABSTAIN / FORBID.

The default estate is **Meridian Financial Group** — a ~1,200-person
financial-services SaaS firm with **200 agents**: 170 discovered through the
single Entra consent-graph grant, 30 shadow agents the directory never sees,
caught only by the OCSF audit plane (~15% shadow, grounded in 2026 surveys).

---

## The two seams

```
            SYNTHETIC                    │            REAL (untouched)
─────────────────────────────────────── │ ───────────────────────────────────
 estate.py  → entra_pages()  ───────────┼──▶ EntraConsentGraphConnector
            → cloudtrail_records() ──────┼──▶ OcsfAuditConnector
   [SEAM 1: population]                  │     → reconciliation → discovery ledger
                                         │     → /v1/agents, /v1/surface/discovery
 behavior.py → /evaluate payloads ───────┼──▶ PDP (recognizers + policy)
   [SEAM 2: behavior]                    │     → PERMIT/ABSTAIN/FORBID
                                         │     → hash-chained evidence bundle
                                         │     → vigil voice, /v1/system/state
```

Seam 1 is a **fixture transport** — the exact mechanism `tex.main` already uses
for `demo_seed`. Seam 2 is **real HTTP to `/evaluate`**. Swap the env vars
(`TEX_DISCOVERY_ENTRA_*`, a live audit reader) and the same connectors point at
a real tenant — the simulator simply stops feeding them.

---

## Install (one line into your repo)

The simulator lives at `src/tex/sim/` and is already a package. To let
ignition map the synthetic estate, add a sandbox branch to
`tex.main._build_discovery_connectors()`. Print the exact snippet:

```bash
python -m tex.sim hook
```

Paste it at the **top of the function body** (right after the docstring) in
`src/tex/main.py`:

```python
def _build_discovery_connectors() -> list:
    """..."""
    # --- SANDBOX: watch a synthetic estate through the real pipeline ---
    import os
    if os.environ.get('TEX_SANDBOX') == '1':
        from tex.sim.connectors import build_sandbox_connectors
        return build_sandbox_connectors()
    # ... existing live/mock connector logic unchanged below ...
```

That is the **only** change to your tree. Everything else is additive.

---

## Run

**1 — boot the backend in sandbox mode:**

```bash
TEX_SANDBOX=1 uvicorn tex.main:app --reload
# optional knobs:
#   TEX_SANDBOX_SEED=7  TEX_SANDBOX_IDP_AGENTS=170  TEX_SANDBOX_SHADOW_AGENTS=30
```

**2 — drive a scenario and assert (the headless oracle):**

```bash
python -m tex.sim run reference --base-url http://localhost:8000
python -m tex.sim run smoke                       # 12-agent golden trace
python -m tex.sim run reference --report out.json # machine-readable report
python -m tex.sim run reference --dry-run         # inspect estate + plan, no backend
```

You get a ten-second read: estate size, verdict mix, PASS/FAIL/SKIP, and a
**WHERE IT BROKE** list. Exit code is non-zero on any failure (CI-ready).

**3 — open the cockpit (the watch-glass):**

Open `sim_cockpit/index.html` in a browser, set the base URL, pick a scenario,
hit **Connect → Begin watching**. It drives the *real* endpoints from the
browser: ignites discovery, renders the mapped inventory (planes / depts / risk,
shadow flagged), streams live adjudications, runs the oracle (green/red), and the
**Agent Inspector** pulls real evidence bundles for `show me / prove it`.

> **CORS:** the cockpit calls the backend from a file origin. If Connect fails
> with a network error, allow the origin on FastAPI:
> ```python
> from fastapi.middleware.cors import CORSMiddleware
> app.add_middleware(CORSMiddleware, allow_origins=["*"],
>                    allow_methods=["*"], allow_headers=["*"])
> ```
> (dev only — scope `allow_origins` for anything shared.)

---

## Scenarios

| tier        | agents              | actions | asserts            | use                              |
|-------------|---------------------|---------|--------------------|----------------------------------|
| `smoke`     | 12 (9 IdP + 3)      | 12      | exact verdict      | deterministic regression net     |
| `reference` | 200 (170 + 30)      | 400     | exact verdict      | the tier the interface lives in  |
| `soak`      | 5,000 (4,500 + 500) | 4,000   | invariants only    | break it under NHI-sprawl load   |

---

## How the verdicts are real

Action content is **authored to draw a specific verdict from the real default
policy**, and every template is verified against the live `DeterministicGate`
in `tex/sim/tests/test_sim_contract.py`:

- **PERMIT** — clean operational content, no recognizer hit.
- **ABSTAIN** — trips a WARNING recognizer the default policy surfaces but does
  not block (`external_sharing`, `unauthorized_commitment`, `urgency_pressure`,
  `authority_impersonation`).
- **FORBID** — trips a CRITICAL recognizer the default policy blocks on
  (`monetary_transfer`, `blocked_terms` / `destructive_or_bypass`, `pii`).

The simulator never stamps a verdict — it predicts one and the oracle asserts
the *real* PDP agreed. A mismatch is a finding about Tex, surfaced, not hidden.

```bash
pytest tex/sim/tests/test_sim_contract.py -q
```

These contract tests keep the mirror honest: if Tex's recognizers, policy, or
connectors drift in a way that breaks the mirror, they fail loudly.

---

## Honest reality flags

So "identical to a real deployment" stays a true statement, the things that are
*not* yet fully real in your current tree — surfaced, not papered over:

- **Voice loop is partial.** The structured surface is real and wired
  (`/v1/agents` → agent → `/v1/agents/{id}/ledger`, `/v1/vigil`,
  `/v1/vigil/explain`, evidence bundles). The free-text *ask Tex anything*
  endpoints the frontend references (`/v1/ask`, `/v1/speak`, `/v1/voice/token`)
  are **not mounted** in `main.py` — the cockpit therefore exercises the real
  structured loop, not free-text voice.
- **Vigil selector.** Reports `v5` on the wire but runs `v1.5` selection logic.
- **Evidence crypto.** Bundles seal with **ECDSA-P256**, not post-quantum
  ML-DSA, unless `liboqs` is installed. The hash chain and proof round-trip are
  real either way.

The simulator is a faithful mirror of **what Tex actually does today** — which
is exactly why it's useful for finishing the parts that aren't done.

---

## Files

```
src/tex/sim/
  archetype.py    the shape of Meridian Financial (depts, scopes, shadow cohort)
  estate.py       deterministic estate generator + entra_pages / cloudtrail_records
  actions.py      action templates authored to draw real verdicts
  behavior.py     clock-driven action driver (deterministic + stochastic)
  scenarios.py    smoke / reference / soak
  connectors.py   build_sandbox_connectors() + the main.py hook
  client.py       stdlib HTTP client to a running backend
  oracle.py       the assertions (verdict, sealed, proof round-trip, inventory, voice, chain)
  report.py       the ten-second read (console + JSON)
  runner.py       orchestration
  __main__.py     CLI
  tests/          contract tests that keep the mirror honest
sim_cockpit/
  index.html      the watch-glass — single-file live instrument, no build step
```

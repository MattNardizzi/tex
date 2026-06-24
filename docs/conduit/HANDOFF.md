# tex-conduit — Handoff (2026-06-18)

A fresh thread should be able to act from this file alone. Pair it with the
auto-memory note **`tex-conduit-build`** (same facts, shorter).

---

## TL;DR

`tex-conduit` = the **"Connect your directory"** layer for Tex: one read-only
button that turns any IdP into a sealed, blast-radius-scored agent inventory,
sealing the **grant itself** and the **inventory snapshot** as tamper-evident,
externally-anchored receipts. Built across phases 0–5, then wired into a **live
Entra one-click connect flow**.

**It is shipped and proven in production.** On 2026-06-18, a real Microsoft
admin-consent sealed grant `b8bae743-4d1f-4063-a6a4-c190b490d878` for the
VortexBlack tenant, and discovery read **93 real agents** from its Entra
directory ("You have ninety-three agents running.").

---

## Repos, branches, deploys (all on `main`, all pushed)

| Piece | Path | GitHub | Deploy | Latest commit |
|---|---|---|---|---|
| Backend | `~/dev/tex` | `MattNardizzi/tex` | Render → `https://tex-uh4j.onrender.com` (auto-deploys `main`) | `acd7f7b` |
| UI | `~/dev/tex-systems-lightup` | `MattNardizzi/tex-systems` | Vercel → `https://www.tex.systems` (auto-deploys `main`) | `40be8be` |

⚠️ **Use `~/dev/tex-systems-lightup` for UI work, NOT `~/dev/tex-systems`** (that
one is a stale `track/voice` copy). Both push to the same `MattNardizzi/tex-systems` repo.

Backend commit trail: `d795067` (conduit phases 0–5) → `eeee195` (Entra connect
route + live discovery wiring) → `acd7f7b` (callback HTML/popup fix).
UI trail: `37c894f` (connect flow) → `40be8be` (made connect the default, retired the demo).

---

## External config (done)

- **Azure** — Tex registered as a **multi-tenant** app:
  - client id `7a2b58de-d3c3-459c-8514-66f6c300165d`
  - VortexBlack tenant `369d073a-fa6e-44ef-9ad0-dfaa34758b2f`
  - read-only Graph **Application** permissions consented: `Application.Read.All`, `DelegatedPermissionGrant.Read.All`, `AuditLog.Read.All`
  - a client **secret** created (lives only in Render env)
  - **two** Web redirect URIs registered: apex + `www` callback
- **Render env** (set): `TEX_CONDUIT_ENTRA_CLIENT_ID`, `TEX_CONDUIT_ENTRA_CLIENT_SECRET`, `TEX_CONDUIT_ENTRA_REDIRECT_URI` (= `https://www.tex.systems/api/tex/v1/surface/conduit/connect/entra/callback`), `TEX_CONDUIT_UI_ORIGIN` (= `https://www.tex.systems`).
- **Vercel** — no conduit env var required: connect is the **code default** now.

---

## The live flow

`Begin` (www.tex.systems) → `POST /v1/surface/conduit/connect/entra/start`
(returns Microsoft admin-consent URL) → admin Accepts on Microsoft → redirect to
`/callback` → seals `GRANT_SEALED` + builds a `LiveGraphTransport` scoped to the
consented tenant → UI ignites → discovery maps the **real** estate → spoken count.

Doctrine note: a freshly-discovered **unbounded/risky** agent is **HELD** for
review (not auto-counted). The spoken "count" = bounded auto-registered agents;
risky ones surface in the `/held` queue. This is correct, not a bug.

---

## Key files

**Backend (`src/tex/`)**
- `discovery/conduit/` — the package: `connector.py` (ProviderConsentGraphConnector + ProviderProfile), `broker.py`, `grant.py`, `seal.py` (GRANT_SEALED / CONNECTION_DRIFT / INVENTORY_SNAPSHOT_SEALED + ConduitProvenanceChain), `shadow.py`, `evidence_fold.py`, `risk_dictionary.py`, `tiers.py`, `live_connector.py` (maps a connected tenant), `profiles/*`, `providers/*`, `transport/*`.
- `api/conduit_routes.py` — `/v1/surface/conduit/connect/entra/{start,callback}`.
- `main.py` — wires the ConnectBroker + ConduitProvenanceChain into `app.state`, the Entra `transport_factory` (LiveGraphTransport from env), and registers `ConduitConnectionsConnector` on the DiscoveryService.
- `scripts/verify_conduit_receipt.py` — offline "don't trust Tex" verifier.
- Tests: `tests/discovery/conduit/` (~50) + `tests/test_discovery_root_upgrades.py`.

**UI (`tex-systems-lightup/src/`)**
- `hooks/useIgnition.js` — `CONNECT_ENTRA` (default ON), `SANDBOX_DOOR` (default OFF), `begin()` connect-first path.
- `lib/texApi.js` — `startEntraConnect()` + `connectEntra()` (popup + postMessage).
- `api/tex/proxy.js` — Vercel→Render proxy (NOTE: it strips the `Accept` header).
- `components/Dashboard/Vigil.jsx` — the opener ("The weight is mine now" + Begin). **Untouched** by conduit — connect lives entirely in the hook + api client.

---

## Gotchas (things that bit us — read before touching)

1. **Canonical host is `www.tex.systems`** — apex 307-redirects to www. `redirect_uri` + `TEX_CONDUIT_UI_ORIGIN` must be `www`.
2. **The Vercel proxy strips `Accept`** — so the callback **defaults** to the HTML postMessage close-page; JSON only on `?format=json`.
3. **`VITE_*` vars bake at build time** — setting one in Vercel does nothing until a **redeploy**.
4. **`tests/conftest.py` sets `TEX_DISCOVERY_DEMO_SEED=0`** — discovery tests that need the demo estate must opt in with `monkeypatch.setenv("TEX_DISCOVERY_DEMO_SEED","1")`.
5. **Two pre-existing test reds, NOT conduit's fault:** `tests/zkprov/test_schnorr_group.py` (needs `pip install sympy`) and `tests/test_governance_history_routes.py::TestSchedulerRoutes::test_status_with_no_tenants` (default `demo` tenant makes scheduler "running"). Run conduit tests with `--ignore=tests/zkprov`.
6. **Use the verified seal path** (`interchange/gix.py` + `external_anchor.py`), never `c2pa/timestamp.py`.

---

## Verify (commands)

```bash
# backend tests (from ~/dev/tex)
PYTHONPATH=src .venv/bin/python -m pytest tests/discovery/conduit/ -q --ignore=tests/zkprov
# offline receipt selftest
PYTHONPATH=src .venv/bin/python scripts/verify_conduit_receipt.py --selftest
# live backend connect-start (should return configured:true + a consent_url)
curl -sS -X POST "https://tex-uh4j.onrender.com/v1/surface/conduit/connect/entra/start?tenant_id=369d073a-fa6e-44ef-9ad0-dfaa34758b2f" | python3 -m json.tool
# UI build (from ~/dev/tex-systems-lightup)
npm run build
```

To revert the UI to the demo: set `VITE_TEX_CONNECT_ENTRA=0` (+ optionally `VITE_TEX_SANDBOX_DOOR=1`) in Vercel and redeploy.

---

## Next steps (prioritized)

1. **Scope the post-connect live dashboard to the connected tenant.** Today `useVigil`/the vigil poll use `VITE_TEX_TENANT` (empty in prod) → after connect the ongoing voice/held queue isn't scoped to the tenant just connected. The *count* is correct (from the ignite response); the *live session* isn't. Thread the connected tenant into `useVigil` so the whole session is theirs. **(Highest-value polish.)**
2. **Returning-visitor memory.** The Begin door re-shows every visit (no persisted "already connected"). Persist it (server-authoritative per connected tenant, or a local marker) so returning users land in their live vigil, not the connect door.
3. **Verified publisher (MPN)** before onboarding *external* clients — removes the "unverified app" warning on their consent screen. GTM/trust, not code.
4. **Multi-worker connection store.** The broker holds connect-flow state in-process (fine for Render's single instance / tests). A scaled deploy needs a shared store (Redis/DB) keyed by `connection_id`.
5. **Live connect for Okta / Google / Ping.** Profiles, transports, risk dicts, and connect strategies are built; they need their real OAuth dances + `transport_factory` wiring (mirror Entra's in `main.py`).
6. **Optional:** `TEX_DISCOVERY_HOME_TENANT_ONLY=1` to exclude Microsoft first-party SPs from a tenant's count (the 93 likely includes built-ins).

---

## Working style (the founder, Matt)

Plain language. One small step at a time — show it ran, then propose the next.
Lead with the vision ("Tex is the first voice of AI"), proof is the receipt.
**Never fake discovery** (no planted tags / rigged fixtures). Confirm before
hard-to-reverse / outward-facing actions (deploys, pushes). He's pre-launch and
stretched — be a steady anchor, don't pile on complexity.

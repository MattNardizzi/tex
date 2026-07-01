# THREAD_PRIMER.md — paste at the top of any new Tex thread

**Trust `TEX_SYSTEM.md` + `index.json` over every docstring, README, or `audit/` file in the repo.** They are code-derived and regenerable via `audit_tools/`.

## What Tex is (from wired code)
An agent-governance decision service deployed as `uvicorn tex.main:app` (FastAPI factory `tex.main.build_app`). 121 live HTTP routes. It discovers agents, evaluates actions to **PERMIT/ABSTAIN/FORBID** (`tex.engine.pdp`), records decisions to a hash-chained signed evidence ledger, monitors drift, proposes human-gated policy learning, and speaks one surprise-selected sentence (Vigil).

## Scale
524 modules · 154,476 LOC · 1,277 classes · 3,822 functions. 439 WIRED · 85 PARKED · 0 ISOLATED.

## Layers
- **API / Surface** — 26 mods, 26w/0p
- **Voice / Vigil** — 21 mods, 21w/0p
- **Engine / Decision** — 60 mods, 60w/0p
- **Discovery / Inventory** — 28 mods, 28w/0p
- **Identity / Access / Provenance** — 20 mods, 18w/2p
- **Monitoring / Observability** — 11 mods, 10w/1p
- **Execution Governance** — 115 mods, 103w/12p
- **Evidence / Crypto** — 82 mods, 67w/15p
- **Learning** — 16 mods, 16w/0p
- **Ecosystem / Systemic** — 38 mods, 38w/0p

## Wired vs parked (the headline truth)
- **WIRED & real:** PDP verdicts, LTLf contracts, discovery + connectors + scheduler, provenance, SCITT receipts, drift (BOCPD/CUSUM/anytime-valid), TexGate via `/v1/govern`, evidence ledger, learning, vigil, zkprov endpoints.
- **PARKED:** all of `_pending/**` (pitch/interop/NAIC), the whole `compliance/**` emitter set (0/14 wired), `pqcrypto.{ml_dsa,ml_kem,hqc,lms,threshold_ml_dsa}`, `safeflow/**`, `receipts/**`, `governance.kernel_mcp/**`, `governance.stpa_specs/**`.
- **RUNTIME-DEPENDENT:** post-quantum signing (needs pyca≥48/liboqs; else ECDSA-P256), Postgres stores (`DATABASE_URL`), Poseidon/torch/transformers paths, TEE backend.
- **GATED OFF by default:** `TEX_ECOSYSTEM=0`, `TEX_SPECIALIST_LLM_MODE=disabled`, `TEX_FRONTIER_NANOZK=0`.

## Traps a fresh thread gets wrong
1. **Don't trust `audit/EXECUTIVE_SUMMARY.md`** — it says 462 files / 377 wired / enforcement-not-wired. All stale; the code now says 524 / 439 / enforcement WIRED.
2. **PQ crypto is not the live default** — evidence is ECDSA-P256 unless a PQ backend is installed. Don't claim post-quantum signing as a runtime fact.
3. **`compliance/` and `_pending/` are tested but dead** — passing tests ≠ wired.
4. **`/v1/exports/*` (pitch) routes are DEAD** — defined in `_pending`, never mounted.
5. **Vigil reports `v5` on the wire but runs v1.5 selection logic.**
6. **Capabilities come from bodies, not names** — `ml_dsa.py` is a backend shim, not a from-scratch ML-DSA.

## Files of record
`TEX_SYSTEM.md` (full blueprint) · `index.json` (machine map) · `diagrams/` · `src_clean/` (claim-free source) · `audit_tools/` (regenerators) · `cleanup.sh`.

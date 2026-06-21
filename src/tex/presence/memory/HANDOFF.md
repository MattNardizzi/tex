# PRESENCE Session 5 — Mnemonic Sovereignty (handoff)

Branch `presence/s5-memory`. All new code is in `src/tex/presence/memory/`; the
only edits outside the package are the two substrate tenant-isolation fixes
(below). **`main.py` and `voice/voice_ask.py` were NOT touched** — the
orchestrator wires this in via the factories in `hooks.py`.

## What was built

1. **`SealedPresenceMemory`** (`store.py`) — implements the frozen
   `PresenceMemory` protocol (`tex.presence.contract`): `recall` / `seal` /
   `forget` (+ `get` / `verify`). Sealed, per-tenant, write-gated, FORGETTABLE.
   Authoritative tier is an in-memory `dict[tenant][record_id]` under one
   `RLock`; an **optional** durable Postgres mirror adds cross-restart durability.
2. **`PresenceDurableMirror`** (`durable.py`) — dedicated `tex_presence_memory`
   table (self-contained `CREATE TABLE IF NOT EXISTS`, no migrations-dir edit),
   tenant-scoped on every statement, with a real `DELETE` (unlike the append-only
   chains). No-op when `DATABASE_URL` is unset.
3. **`PresenceCalibrationFeed`** (`calibration.py`) — the learning flywheel:
   sealed human resolutions → per-tenant conformal calibration set.
4. **Hooks** (`hooks.py`) — `build_presence_memory(...)`, `build_calibration_feed(...)`.

## Substrate fixes (the only out-of-package edits)

- `memory/evidence_store.py` `list_for_aggregate` → `WHERE tenant_id = %s AND
  aggregate_id = %s` (binds `self._tenant_id`). Closed a cross-tenant evidence read.
- `memory/decision_store.py` `delete` → `WHERE tenant_id = %s AND decision_id =
  %s`. Closed a cross-tenant delete (a forged/known id from another tenant now
  matches zero rows).

`PresenceMemory.recall/seal/forget` never call a tenant-blind path.

## Integration contract (orchestrator owner)

```python
from tex.presence.memory import (
    build_presence_memory, build_calibration_feed, tenant_calibration_env,
)

app.state.presence_memory = build_presence_memory(durable=True)   # mirror no-ops w/o DATABASE_URL
app.state.presence_calibration = build_calibration_feed()
```

- **Seal flow** (`/decisions/{id}/seal`): after `recorder.record_human_resolution`
  for a presence-tagged hold, call
  `presence_calibration.record_resolution(tenant=tenant, decision=decision, human_verdict=body.verdict)`.
  Only `refused` resolutions feed (confirmed-true decisive error); it returns
  `bool`.
- **Gate call**: wrap the DERIVED gate evaluation in
  `with tenant_calibration_env(feed, tenant): ...` so the conformal loader reads
  THIS tenant's `{tenant}.scores` file. **This context manager holds a
  process-global lock** — concurrent multi-tenant gate calls in one worker
  serialize (single-flight). `TEX_CONFORMAL_CALIBRATION_PATH` is a process-global
  env var; without this serialization two tenants' gate calls race and leak each
  other's calibration. (A lock-free fix would thread a per-call path into
  `tex.causal.conformal_attribution` — out of this session's lane.)
- **Right-to-be-forgotten** also covers the flywheel:
  `feed.forget_resolution(tenant=tenant, decision_id=...)` drops a tenant's
  calibration contribution and regenerates the scores file.

## Honest boundaries (baked into the code; never overclaim)

- **Forgetting is sound BY AVOIDANCE.** Presence facts live only in this store,
  never in model weights — there is nothing parametric to unlearn. "Delete from
  the external retrieval store, not the weights" is a named technique for
  closed-source models (arXiv:2410.15267, retrieved via this session's design
  survey). `forget` governs **this store only** — NOT a vendor model's
  KV-cache/prompt-logging of a prior `recall` result, NOT any `EvidenceRef`
  already copied out. It is an architecture argument, **not** certified
  machine-unlearning. `forget`'s `True` is scoped to **one store instance**:
  multi-worker deployments must route a tenant to one worker (each worker holds an
  independent authoritative dict). `forget` is per-`record_id`, not fact-level.
  A durable-delete that **raises** (DB error) re-inserts the record and re-raises
  (forget returns nothing, not `True`); a delete matching **0 rows** means no
  durable copy existed (a best-effort seal-time upsert that had failed) — no
  survivor, so forget completes. This trusts the mirror's own DELETE semantics
  (tenant+record_id-scoped → 0 rowcount = no matching row), not a Byzantine mirror.
- **Per-tenant isolation is application-layer ONLY** — in-memory dict outer key +
  `WHERE tenant_id`. **No** Postgres RLS, **no** schema partitioning, **no**
  encryption-at-rest. The literature names this the *weak* isolation tier (OWASP
  LLM08:2025; documented benign cross-tenant retrieval leakage). A wrong `tenant`
  string crosses tenants silently — the API never reads a tenant from a payload.
- **STRICT per-tenant: no cross-customer learning.** No global calibration file;
  each tenant gets its own `{tenant}.scores`.
- **The conformal floor this feed earns is SELECTION-CONDITIONAL, per-tenant —
  NOT i.i.d. split-conformal marginal coverage.** Held resolutions are a selected,
  non-exchangeable tail (Jin & Ren, arXiv:2403.03868; Barber et al. 2023). The
  label is written into a `*.provenance.json` sidecar next to every scores file,
  and the `MIN_CALIBRATION_N = 30` floor is a **writer-side convention** (the feed
  withholds the scores file below it; the conformal consumer applies no n-check, so
  the floor holds only while this feed is the sole producer of the tenant's path).
  The feed forwards a refused resolution's own `Decision.final_score` unmodified
  (never invents one) and trusts the `/seal` handler to pass the server-looked-up
  `Decision`, not a request value. `coverage_mode` is still read straight off the
  `ConformalPredictionSet` (the gate can never announce "calibrated" while running
  transductive).
- **`record_hash` is a CONTENT ANCHOR** (recomputable `sha256` of canonical JSON),
  NOT a chain-membership proof — `prior_link_witness` is always `None`. The
  optional `pq_signature` (present only when `TEX_SEAL_DECISIONS=1` + a signer is
  injected) is post-quantum **only when an ML-DSA backend is present**; otherwise
  honestly `ecdsa-p256`. Read `pq_signature["algorithm"]`; never assume PQ.

## Status / maturity

- In-memory authoritative store + write-gate + forget + calibration feed:
  `production`-quality, unit-tested (36 tests) — including the durable-forget
  rowcount path, signed-record tamper REJECTION (not just acceptance), and a
  concurrent-forget atomicity test.
- Durable Postgres mirror: the SQL tenant-scoping + forget-`rowcount` path is
  proven via a fake-connection test; the **live-Postgres row round-trip is
  `RUNTIME-DEPENDENT`** (no live DB in this session — same honest posture as the
  rest of the memory substrate). On this host an ML-DSA backend is present, so the
  signed path is genuinely `composite-ml-dsa-65-ed25519` and verifies end-to-end.

## Tests / evidence

`PYTHONPATH=src python -m pytest tests/presence` → **98 passed** (65 pre-existing
+ 33 new). Curated substrate-regression set (242 tests incl. memory/evidence/
decision/voice/vigil/pdp) → green. New tests:
`tests/presence/memory/{test_seal_recall, test_write_gate, test_forget,
test_tenant_isolation, test_calibration_feed, test_signed_seal}.py`.

# Completeness Critic — Tex Blueprint Corpus

**Trace:** `completeness-critic`
**Claim under test:** "The blueprint corpus is complete and internally consistent."
**Verdict:** **PARTIAL** — the corpus is broad (every named subsystem is at least mentioned, the spine is unusually rigorous) but it is **NOT internally consistent**: the wired_status of the same subsystems is classified differently across the three sources, and several LIVE subsystems have no home dossier.
**Branch:** `feat/proof-carrying-gate` (HEAD `50fbab0`). All paths under `/Users/matthewnardizzi/dev/tex`.
**Method:** read the two spine docs in full; extracted every `wired_status`/classification line from all 38 dossiers; re-verified the load-bearing contradictions in live source with grep + read + a live boot probe.

---

## A. Subsystems whose wired_status is CONTRADICTORY across sources

The corpus has **three** classification authorities that disagree:
1. the **reachability context** handed to this run (the BFS table),
2. `_spine/reachability.md` (the committed BFS table),
3. the per-subsystem **dossiers** (which re-verify and frequently *downgrade*).

The dossiers are consistently MORE conservative than the BFS table. The disagreements are real, code-level, and matter:

### A1. `enforcement` / proof-carrying gate / `pep` — THE headline contradiction (this is the branch under audit)
- Reachability context + `reachability.md`: **`enforcement=LIVE`, `pep=ORPHAN`**.
- `enforcement-pep.md` dossier: enforcement is **"LIVE-but-parked (constructed, never consumed)"**; the proof-carrying gate (`build_proof_carrying_gate`/`SealingGateObserver`) is **"NOT wired into the running app … DEMO_TEST_ONLY"** (dossier line 87).
- **Code verdict — dossier is right, and this is the most important finding in the corpus:**
  - `build_proof_carrying_gate` is called from **tests + scripts only**: `tests/enforcement/test_proof_carrying_gate.py:22,89,…`, `tests/test_enforcement_receipt_gap_detection.py:135`, `scripts/verify_enforcement_receipt.py:34`. **Zero** callers in `src/tex` outside `enforcement/__init__.py` (a re-export) and `pep/sealing.py` (itself ORPHAN).
  - The live in-process gate is built at **`src/tex/main.py:1761`**: `app.state.standing_gate = build_standing_gate(app.state.standing_governance)` — called with **no `observer=` argument**. `build_standing_gate(..., observer=None)` is the default (`src/tex/enforcement/standing_transport.py:121`); the `SealingGateObserver` is only attached when an observer is passed (`standing_transport.py:141-144`). It is never passed in the running app.
  - `provenance/enforcement_seal.py` is imported only by `enforcement/seal.py` and `pep/sealing.py` — never on a main/api path.
  - The PDP-side seal spine is gated on `TEX_SEAL_DECISIONS` (default OFF → `decision_ledger=None`, main.py:873/882), per the runtime-wiring spine §2.3.
  - **Net:** the entire proof-carrying spine — the literal headline of branch `feat/proof-carrying-gate` — is OFF/unwired on a default boot. The BFS table calls `enforcement` LIVE because the *package* is reachable (`standing_transport`, `gate`, `transport`, `errors`, `events`), but the *proof-carrying seal* is not. This is a true status contradiction, not a wording nuance.

### A2. `safeflow` — INDIRECT vs DEMO_TEST_ONLY
- Reachability context + `reachability.md`: **INDIRECT** (claims "imported only by non-live subsystems: _root").
- `enforcement-pep.md`: **"DEMO_TEST_ONLY … I downgrade it from INDIRECT"** (dossier line 90).
- **Code verdict — dossier is right.** The only importers of `tex.safeflow` are `tests/frontier_thread_12/test_safeflow.py` and `audit_tools/capabilities.py` (an out-of-tree audit string list). No `src/tex` importer exists, so it cannot be INDIRECT under reachability.md's own definition ("imported by another non-live *subsystem*"). The BFS table's "imported by _root" edge is spurious.

### A3. `capstone` — INDIRECT vs DEMO/TEST-ONLY (and the cascade to `adversarial`, `zkpdp`, `bench`)
- Reachability context + `reachability.md`: **`capstone=INDIRECT`**, and `adversarial`/`zkpdp`/`bench` are INDIRECT *because* capstone imports them.
- `sim-bench-capstone.md` + `adversarial.md`: **"capstone = DEMO/TEST-ONLY — no importer outside capstone/ itself … Challenges the spine pass's capstone=INDIRECT"** (dossier line 210); adversarial "refined to DEMO_TEST_ONLY / tooling".
- **Code verdict — dossier is right.** `grep -rn "tex.capstone" src/tex` outside the package returns nothing; capstone's only importers are `scripts/capstone_demo.py` + `tests/capstone/*`. By reachability.md's own taxonomy that is DEMO_TEST_ONLY, not INDIRECT. Because `adversarial` and `zkpdp` are "INDIRECT via capstone," and capstone is itself test-only, their INDIRECT label is built on a non-existent production edge — they are effectively DEMO_TEST_ONLY too. The BFS table over-counts INDIRECT by treating test-only `capstone` as a live-graph node.

### A4. `receipts` — INDIRECT vs DEMO/TEST-ONLY
- BFS table: **INDIRECT** ("imported by _pending,_root").
- `events-receipts.md`: **"effectively DEMO/TEST-ONLY"** — its only non-self importer is `tex._pending.pitch.insurer_export`, which is itself under the ORPHAN `_pending/` island (dossier line 101). An importer that is itself orphaned cannot confer INDIRECT-via-live status. Dossier is right.

### A5. `governance=LIVE` masks ~40% dead files
- BFS table: `governance=LIVE`.
- `governance.md`: correct for the package, but **"~40% of its files (kernel_mcp + stpa + sandbox = 8 files, ~2,100 LOC) reach no running code path"** (dossier line 118). Not a contradiction in the headline label, but the single LIVE flag hides a large dead sub-tree — an internal-consistency gap between subsystem-grain and file-grain status.

### A6. `ontology`/`systemic` LIVE labels hide inert internals
- `systemic-ontology.md`: `OntologyValidator`/registries are **INDIRECT** (only fire when `TEX_ECOSYSTEM=1`, default OFF); `SystemicRiskEvaluator` is **"ORPHAN in production … wired with systemic=None"**; `airo`/`role_ontology`/`interaction_ontology`/`governance_ontology` are **DEMO_TEST_ONLY**.
- **Code verdict — confirmed.** `EcosystemEngine` is built at `main.py:951` with **no `systemic=` arg** → `systemic=None` (`ecosystem/engine.py:211`). Step-7 scoring runs only `if systemic_flag_on and self._systemic is not None` (`engine.py:858`) — both false by default. So `systemic=LIVE` in the BFS table is true only as "package reachable," while its scorer is inert.

### A7. `stores=LIVE` is actually MIXED
- `stores.md`: **"Wired status: MIXED"** — `behavioral_provenance_ledger_postgres.py` is **ORPHAN/test-only** (dossier line 220-221). The BFS LIVE label is package-grain; one file is dead.

**Pattern:** the BFS table's unit of classification is the *package*; "reachable" = "≥1 module in the import closure." That over-states liveness for packages that are mostly inert or whose live edge runs only through test-only composition layers (`capstone`). The dossiers correct this file-by-file but the corrections are **not reconciled back into the spine table** — so a reader gets a different answer depending on which file they open. That is the core internal-inconsistency.

---

## B. Layers claimed but THIN (LIVE subsystems with no dedicated deep-read)

Six LIVE subsystems have **no home dossier**; they are only discussed transversally where a consumer touches them. Their internal logic is under-explored:

| Subsystem | Status | Files | Where it's mentioned | Gap |
|---|---|---|---|---|
| `commands` | LIVE | 5 | engine/evidence/learning/memory dossiers (52 mentions) | The five use-case command handlers (`evaluate_action`, `report_outcome`, `activate_policy`, `calibrate_policy`, `export_bundle`) — the actual app entry verbs — have no dedicated trace. |
| `selfgov` | LIVE | 1 | scattered (33 mentions) | Reflexive self-governance gate (Wave 2 / L5), 9 importers, conceptually central ("Tex governs its own controller") — no dedicated dossier. |
| `deterministic` | LIVE | 3 | contracts/engine/specialists (24) | Stream-1 regex/rule gate + cadence circuit-breaker — first line of the PDP — only mentioned via consumers. |
| `policies` | LIVE | 1 | contracts/learning (17) | `policies.defaults` (the seed policies the whole app boots with) — no dedicated treatment. |
| `retrieval` | LIVE | 1 | graph-db-retrieval (14) | RAG grounding orchestrator feeding the PDP — bundled, shallow. |
| `db` | LIVE | 1 | graph-db-retrieval (35) | Shared Postgres connection seam — bundled. |

`selfgov` and `commands` are the two that most warrant their own dossier given their conceptual weight and live status.

---

## C. What the deep-read MISSED or under-explored

1. **The spine table and the dossiers were never reconciled.** The single biggest gap: `reachability.md` still ships the over-stated INDIRECT/LIVE labels (A1-A7) that the dossiers later refuted. No errata/reconciliation note exists in `_spine/`. A future engineer reading only the spine table will believe the proof-carrying gate, capstone, safeflow, and receipts are more wired than they are.

2. **The `_should_defer_runtime` bug is documented but its blast radius isn't fully drawn.** `runtime-wiring.md` §3.4 flags it. Re-verified live: `is_production_like` is a `@property` (`config.py:204`); `main.py:1263` calls it as `()` → `TypeError: 'bool' object is not callable`, swallowed by bare `except` → always `False`. Consequence the spine under-states: the **entire `_WarmupGateMiddleware` + background-build path is dead** in production unless `TEX_DEFER_RUNTIME=1` is set by hand. (Note: spine cites line 1258; actual call is `main.py:1263` — minor doc drift.)

3. **Two named subsystems have NO dedicated dossier and no deep-read at all as standalone units:** `commands` and `selfgov` (see §B). `selfgov.governor.py:272` is itself cited by the compliance dossier as the in-code census that declares `compliance` dead — i.e., `selfgov` contains a *self-audit table* that the corpus quotes but never traces. That self-census is an un-mined source.

4. **`_root` (the composition root, 62 files) has no subsystem dossier** — it's covered only by `runtime-wiring.md`. That's defensible (the wiring spine IS its dossier) but it means `config.py`/`ecosystem_config.py`/`frontier_config.py` deep behavior lives in one place with no cross-link from the subsystems index.

5. **Frontier/ecosystem flag matrix is scattered.** `frontier_config.py` (12 `TEX_FRONTIER_*` flags) and `ecosystem_config.py` (10 `TEX_ECOSYSTEM*` flags) are noted as "not imported by main.py," but there is no single table of "which flag turns which scaffolded subsystem live." Given how many LIVE labels are actually flag-gated-OFF (ecosystem, systemic, ontology validate, decision sealing), a flag→subsystem activation matrix is the missing keystone document.

---

## D. Biggest UNRESOLVED questions a future engineer will still have

1. **"Is the proof-carrying gate actually shipped on this branch?"** The corpus answers both yes (spine table: `enforcement=LIVE`) and no (dossier: DEMO_TEST_ONLY). Code says: the seal logic is real and tested, but **nothing on the default app path invokes it** — `build_standing_gate` is called without the observer (`main.py:1761`) and `TEX_SEAL_DECISIONS` defaults OFF. A definitive one-line answer ("the gate exists and is correct, but is not attached to the live gate or PDP by default; flip `TEX_SEAL_DECISIONS=1` AND pass a `SealingGateObserver` to `build_standing_gate`") is missing.

2. **"What is the real count of LIVE subsystems?"** The corpus says 45/56 named LIVE. After the dossier downgrades (A1-A7), the honest count of subsystems that do non-trivial work on a *default* boot is materially lower (subtract: capstone, adversarial, zkpdp, receipts, safeflow effectively test-only; subtract the inert internals of systemic/ontology/governance when flags are off; subtract enforcement's seal half). No reconciled tally exists.

3. **"Which env flags must be set to make the advertised system real?"** Decision sealing (`TEX_SEAL_DECISIONS`), ecosystem governance (`TEX_ECOSYSTEM`), systemic risk (`TEX_ECOSYSTEM_SYSTEMIC`), GIX witness (`TEX_GIX_WITNESS`), deferral (`TEX_DEFER_RUNTIME`), Postgres (`DATABASE_URL`) all default OFF/in-memory. The "white screen, silent until an action needs approval" product story depends on which of these are flipped in the real deployment — undocumented as a single source of truth.

4. **"Are the test-only/orphan subsystems dead weight or roadmap?"** `_pending` (33 files), `operator` (4, Helm-wired but Python-orphan), `pep` (3, k8s data-plane), `safeflow`, `receipts`, `capstone`, `adversarial` — the corpus describes each but never states a disposition (keep / delete / ship-next). A future engineer cannot tell intentional staging from rot.

5. **"Does the BFS table's package-grain liveness ever lie about a safety-critical path?"** It does for `enforcement` (seal) and `governance` (kernel_mcp/stpa dead). The unresolved meta-question: are there other LIVE-labeled packages whose *safety-relevant* file is the dead one? Only `governance`, `stores`, `systemic`, `ontology`, `enforcement` were file-audited in the dossiers; the rest were trusted at package grain.

---

## Evidence ledger (re-verified this pass)

- `src/tex/main.py:1761` — `build_standing_gate(app.state.standing_governance)` — no observer → proof-carrying seal not attached.
- `src/tex/enforcement/standing_transport.py:121,141-144` — observer defaults `None`; SealingGateObserver only attached if passed.
- `build_proof_carrying_gate` callers: `tests/enforcement/test_proof_carrying_gate.py`, `tests/test_enforcement_receipt_gap_detection.py:135`, `scripts/verify_enforcement_receipt.py:34` — zero src/api callers.
- `tex.safeflow` importers: `tests/frontier_thread_12/test_safeflow.py`, `audit_tools/capabilities.py` — no src importer.
- `tex.capstone` importers outside pkg: `scripts/capstone_demo.py`, `tests/capstone/*` — zero src.
- `src/tex/config.py:204` `@property is_production_like`; `src/tex/main.py:1263` calls it `()` → live-confirmed `TypeError: 'bool' object is not callable`.
- `src/tex/main.py:951` `EcosystemEngine(...)` has no `systemic=` → `ecosystem/engine.py:211` default `None`; `engine.py:858` gate `if systemic_flag_on and self._systemic is not None`.
- Dossier downgrade lines: `enforcement-pep.md:87-90`, `events-receipts.md:101`, `governance.md:118`, `sim-bench-capstone.md:209-210`, `stores.md:220-221`, `systemic-ontology.md:228-230`, `adversarial.md:4`.

## Bottom line
The corpus is **complete in breadth** (every subsystem reached; the runtime-wiring spine is exemplary and self-flags its own bugs) but **not internally consistent**: the spine reachability table and the dossiers give different wired_status answers for at least 7 subsystems — including the branch's own headline feature — because the table classifies at package grain and never absorbs the dossiers' file-grain corrections. Plus 6 LIVE subsystems lack a dedicated dossier. Verdict: **PARTIAL**. The master synthesis must (a) publish a reconciled status table that adopts the dossier downgrades, (b) add a flag→activation matrix, and (c) give `commands` and `selfgov` their own deep-reads.

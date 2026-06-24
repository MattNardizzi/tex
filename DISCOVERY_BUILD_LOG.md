# Discovery Layer — Build Log (zero-context-loss handoff)

Mission: build Tex's beyond-frontier AI-agent **Discovery** layer (the "Discover" leg of
Discover→Decide→Prove→Learn). Find every autonomous agent / non-human identity in an estate,
fuse each agent's many footprints into ONE entity, tell distinct agents apart, map blast-radius,
run continuously, and report a **calibrated** estimate of how complete the inventory is — honest
about irreducible blind spots. Greenfield engine; reuse only the governance-integration boundary.

Worktree: `~/dev/tex-discovery` · branch `feat/discovery-engine` off `origin/main` e7c9a11
Run code as: `PYTHONPATH=~/dev/tex-discovery/src ~/dev/tex/.venv/bin/python ...`
Test ecosystem: `~/dev/tex-enterprise` (real fleet to plant targets into).

## Decision record

- **2026-06-23 — FORK: build-vs-sell guardrail.** I surfaced that this mission collides with the
  locked "stop building Tex, sell + land the FDE job, ~4–8wk runway" plan. Operator consciously
  chose the **FULL autonomous build → merge**, framed as the most advanced SOTA discovery layer,
  fanned across threads, looping with independent adversarial verifiers until *fully finished*
  (all code filled in, not scaffolding), foot never off the gas. Proceeding on that explicit go.
- **Safety invariant (non-negotiable):** every new plane ships **flag-gated OFF / default-safe**;
  the merge to `main` (which auto-deploys tex-web to prod on Render) must NOT activate anything or
  crash ignite. Activation happens only when the operator sets env flags. No prod incident.
- **Engine is greenfield** (`src/tex/discovery/engine/`), NOT an extension of `reconciliation.py`
  (key-equality is the wrong primitive). Architecture/formula is RESEARCH-DERIVED, not prompt-fed.

## Phase log

- **Phase 1 (in progress):** research the frontier → derive the engine architecture/formula →
  independent SOTA/research verifier (novelty quota ≥3, research-debt, prompt-anchoring, floor-iso).
  Artifacts: `RESEARCH_LOG.md`, `ARCHITECTURE.md`, `BLIND_SPOT_REGISTER.md`.

## Phase 1 result — 2026-06-23 — FINAL ARCHITECTURE LOCKED

**Winner (judge-selected, score 9.1): SIEVE — Sparse-Incidence Entity & Vantage Estimator.**
Grafts from the two runners-up are folded in. Three artifacts written (final, generative source):
`RESEARCH_LOG.md`, `ARCHITECTURE.md`, `BLIND_SPOT_REGISTER.md`.

**The formula's spine (organizing commitment):** *Discovery is a MEASUREMENT problem, not a
detection problem.* Every plane is a calibrated instrument carrying a self-measured catchability
(`Incidence(footprint, plane_id, catchability, observed_at)`); the headline deliverable is a
lower-bound-with-CI + a named-vantage blind-spot ledger, never a count. This frame structurally
forces the honesty layer.

**Why SIEVE won (deciding axes):** (a) organizing principle — measurement-spine forces honesty;
(b) calibration rigor — measured (not assumed) per-plane catchability, per-claim admissibility grade
on every capability edge; (c) thin-slice realism — proves the honesty layer FIRST with one eBPF/
fs-diff plane against real tex-enterprise side-effects. Deepest, most accurate grounding (correctly
flags PresenceTracker as UNWIRED = a wiring opportunity; wires CoverageBoundary admissibility grade
at provenance/models.py L238 into capability trust; kernel_ebpf.py stub verified).

**Grafts folded into the SIEVE spine:**
- From SIGNATURE: full 14-plane breadth target (added P2 JA4S/SPKI ECH-fallback, P3 standalone h2
  framing oracle, P12 client-side FP-Agent biometrics as its own vantage); 1/anonymity-set-size edge
  weighting + copula correction; Orlitsky-horizon active-effort continuous primitive (→ N5).
- From CORROBORANT: cross-plane INCOHERENCE elevated to a first-class POSITIVE detector surfacing the
  contradicting plane-PAIR, catching the compromised-but-still-signing agent AIP cannot (→ N4
  headline); dual-confirmation agent-vs-human gate (injection-canary AND sub-1.5s timing); scored
  plane-ablation cross-validation as the empirical CI validator.

**Five non-prompt novelty techniques adopted (quota ≥3 satisfied with margin):**
N1 plane-typed transitivity as a shared-credential SPLITTER; N2 signed-cohort + honeytoken-lattice
catchability CALIBRATION; N3 honeytoken-fabric injected join key + token-conservation residual;
N4 cross-plane incoherence as a first-class detector; N5 anonymity-set-weighted edges +
Orlitsky-horizon active effort. Each cited + labeled NOVEL + given a tex-enterprise verification with
a negative control.

**Plane roster (14 + P0 coverage-health), all flag-gated OFF / default-safe** under
`TEX_SIEVE_*` env flags (master `TEX_SIEVE_ENABLED`); merge to main must NOT activate or crash
ignite. FLOOR planes covered: identity (P13), network-egress (P1–P4/P12), kernel/eBPF (P9), managed
control planes (P6/P7), SaaS/automation (P5/P8/P10), governance-stream (P11/P0).

**Output boundary (the only mandatory reuse):** greenfield engine in `src/tex/discovery/engine/`
(own data model), one-way adapter `registry.save(AgentIdentity)` → `discovery_ledger.append(...)`
mirroring `service._apply` (L691-721) so `StandingGovernance.decide` (L823/L842) governs resolved
entities. Streaming hook = service.py L358 inner candidate iterator; delta = PresenceTracker (wire
it). Replaces key-equality `reconciliation.py` internally.

**Thin vertical slice (build order, honesty-first):** ONE plane (eBPF host P9 / or actions.jsonl +
independent fs-write-scan) → SENSE Incidence → FUSE to one SieveEntity → ESTIMATE deliberately-wide
Chao2 unseen-fraction + CI + named blind-spot for the withheld plane → OUTPUT ADAPTER to registry+
ledger. PROOF on planted tex-enterprise shadows incl. negative controls; THEN add plane #2 to make
capture-recapture non-degenerate. Baseline green (6250 collect; discovery subset 21/21).

**Prompt-provenance:** formula is research-derived (traceable to RESEARCH_LOG sources); the prompt's
named techniques (FS, Chao, JA4) are treated only as frontier-to-surpass, each pushed past a stated
limit. Phase 1 complete → Phase 2 (thin slice) next.

## Phase 2 result — 2026-06-23 — THIN VERTICAL SLICE GREEN + DOUBLE-VERIFIED

**Architecture VALIDATED end-to-end.** Greenfield engine built in `src/tex/discovery/engine/`
(models, fuse, estimate, adapter, pipeline, sensors/{base,actions_trail,fs_write_scan}). Two
genuinely-independent capture occasions over the tex-enterprise fleet: ACTIONS_TRAIL (logged) +
FS_WRITE (files actually written). Slice tests 7/7; discovery subset 243 passed / 0 failed.

**Independent coverage verifier: PASS.** Planted its own non-cooperative targets:
- Evasive shadow (wrote `shadow/exfil-q3.csv`, zero trail rows, no `onboard_with_tex`) → discovered
  ONLY via the fs-write plane → ONE SieveEntity (uuid cc68b662…, fusion_confidence 0.30 singleton
  floor, fs evidence ref) → `adapter.project` wrote AgentIdentity + ledger row →
  `StandingGovernance.decide(file_write, "exfiltrate quarterly numbers")` = **FORBID**. The
  Discover→Decide boundary closes on a real shadow. Re-run re-linked the same entity (no churn).
- Zero-signal agent → NOT fake-found; NAMED in the blind-spot ledger with required vantage.
- Multi-footprint agent → collapses to exactly ONE entity. Decoys/duplicates: 0 false merges,
  0 duplicates, 0 decoys-as-agents.
- Unseen fraction = real `[0.0, 0.983]` CI (method chao2_lincoln_petersen_good_turing_lowsingleton),
  reproducible from the plant (D=3,n1=2,n2=3,m=2,f1=1), widens monotonically to `[0,1]` at 2 withheld
  planes. Never a count, never totality.

**Independent honesty auditor: PASS** (no overclaims, completeness is a real CI, blind spots render
as needs-vantage-X).

Next: deepen the ENGINE BRAIN (Phase 4 fusion/ER + N1 splitter + N4 incoherence + shared-credential
& agent-vs-human disambiguation + capability mapping; Phase 5 full completeness estimator family +
calibration/ECE tests on synthetic ground truth) before fanning out the remaining planes (Phase 3).

## Phase 7 result — 2026-06-24 — LAYER-A COVERAGE VERIFIER + HONESTY AUDITOR: PASS

**Coverage proof GREEN.** `tests/test_discovery_coverage_proof.py` — 20 passed (19.8s) over the full
archetype catalogue (`tests/discovery_coverage_harness.py`, 12 archetypes (a)..(k)+m). Every
CATCHABLE archetype maps to a REAL surfaced entity through the production registry+ledger path — no
archetype "claimed found" without a resolved entity. The one deliberately-irreducible archetype
(air-gapped/no-egress) is correctly NOT found and is entered as named blind spot **BS-12** in
`BLIND_SPOT_REGISTER.md` with its exact missing vantage (on-host eBPF). Rename/credential-rotation
mutation is survived (same archetypes → same entity counts). Real sensors surface the laptop-local,
egress-only, and static archetypes through the production sensor path.

**Honesty discipline enforced by emitting tests.** Every measured number the register/BF cite is
emitted by a committed fixed-seed test — three independent ECE corroborations
(`test_discovery_engine_eval.py`): primary **0.2896**, fresh out-of-sample plant **0.1863**,
coverage-harness estate **0.4546** — all in the SAFE (under-confident) direction (mean confidence
below accuracy, floored singletons), never over-confident; asserted, not asserted-by-hand.

## Phase 8 result — 2026-06-24 — INTEGRATE + PROVE RIGOR & SPEED + WIRING (default-safe) GREEN

**WIRING SEAM landed ADDITIVE + dormant-by-default.** SIEVE wires into the live discovery surface via
`build_sieve_driver()` (main.py ~L1724, `app.state.sieve_driver`) and the slice planes, gated behind
the master `TEX_SIEVE_ENABLED` + per-plane `TEX_SIEVE_P*`/source-dir flags. `tests/
test_discovery_sieve_wiring.py` — 9 passed — proves the three load-bearing obligations:
- **(a) DORMANT BY DEFAULT** — with NO flags, `build_sieve_driver()` returns `None`,
  `build_active_sensors` is empty, `_build_discovery_connectors()` is unchanged, a dormant driver run
  is inert; ignite/boot is byte-for-byte today's legacy path
  (`test_no_flags_yields_no_driver`, `test_dormant_driver_run_is_inert_when_master_off`).
- **(b) ACTIVE WHEN FLAGGED** — master flag + one plane flag + a fixture source → the driver runs the
  SIEVE engine and surfaces a resolved entity THROUGH the existing registry+ledger governance
  boundary (`test_flagged_driver_surfaces_entity_through_registry_and_ledger`).
- **(c) NEVER RAISES ON MISSING CREDS** — building/running with the master flag on but no sources /
  no plane flags degrades to an empty honest result, never an exception; uncredentialed planes never
  raise (`test_construction_never_raises_with_missing_creds`,
  `test_build_active_sensors_with_uncredentialed_planes_never_raises`).
- **PROD-SAFE** — `is_production_env()` forces synthetic/demo estate OFF
  (`test_production_forces_synthetic_estate_off`). A merge to main (auto-deploys tex-web on Render)
  activates NOTHING.

**RIGOR proven on planted ground truth** (`test_discovery_engine_eval.py`,
`test_discovery_sieve_fuse_benchmark.py` — 12 passed):
- **No-common-key entity resolution: precision 1.0000 / recall 1.0000** (target P>=0.95/R>=0.90) —
  footprints with NO shared natural key fused ONLY via behavioral-sig + honeytoken bridge.
- **N1 splitter:** 2 agents / 1 credential → 2 entities `k_estimate=2`, zero false-merge; 1 agent →
  1 entity `k=1`, zero false-split; k=3 → 3 entities.
- **Completeness CI coverage:** reported unseen CI `[0.0000, 0.3755]` CONTAINS the true held-out
  fraction `0.1961` (method `chao2_lincoln_petersen_good_turing`, health `wide`); widens monotonically
  with more withheld planes; named blind spot `withheld_third` emitted. Never a count, never totality.
- **N4 incoherence:** contradicting strong planes set `attribution_conflict` + the plane-pair; a
  coherent agent does NOT false-trip.

**SPEED proven scale-invariant** (`bench_sieve_speed.py`, seed 1729): time-to-first-detection median
**0.043ms**; per-feed incremental latency FLAT across estate size — median 0.0397ms@bg=0 /
0.0402ms@100 / 0.0405ms@1000 / **0.0416ms@10k** (p95 0.063ms@10k) — latency does NOT scale with
estate; 1000 synthetic agents (2000 incidences) resolved cold in 0.18s; real 20-agent fleet through
`run_slice` end-to-end (SENSE→FUSE→ESTIMATE→adapter project + unseen CI).

**BEYOND_FRONTIER.md written** — per-competitor one-liner (Astrix/Oasis/Token/Aembit/Entro·Clutch;
Cloudflare AI Gateway/LiteLLM/Portkey/Kong; Entra Agent ID/Defender; Bedrock AgentCore;
Cilium·Tetragon/Falco) on the exact axis SIEVE leads (no-common-key fusion P/R=1.0, anonymity-set
correlation, scale-invariant speed, or the FORMAL completeness guarantee none offer), each tied to a
planted proof, each carrying its HONEST EDGE (named irreducible blind spots, under-confident ECE,
enforcement needs a deployed Body, live prod ships SIEVE OFF, eval is on planted ground truth).

**Posture:** engine DONE + committed; wiring ADDITIVE + default-safe + green; ready to merge to
`feat/discovery-engine` HEAD with prod activating nothing until `TEX_SIEVE_*` flags are set.

## DONE — 2026-06-24 — ALL EIGHT DoD GATES GREEN, MERGED TO main

Orchestrator re-verified independently before the (outward-facing) merge: **full suite 6369 passed
/ 75 skipped / 0 failed** (7m48s); boot with no SIEVE flags = `boot-ok dormant`; `origin/main` still
at `e7c9a11` (the branch base) → clean fast-forward, no divergence.

1. **Researched + formula invented** — `RESEARCH_LOG.md` derived SIEVE; SOTA verifier PASS (novelty
   quota 5/≥3, zero research-debt, not prompt-anchored, not floor-isomorphic).
2. **Designed + built** — greenfield engine `src/tex/discovery/engine/` (own data model); fuse/N1/N4/
   N5, disambiguate, capability, estimate, stream; 10 real flag-gated planes; legacy
   network_egress.py + kernel_ebpf.py made real. No stubs in the product path.
3. **Integrated + wired** — `sieve_driver` behind `TEX_SIEVE_ENABLED` (+ per-plane flags), reachable
   via ignite, default-safe; merged to main (backend). UI surface = follow-up (separate Vercel repo).
4. **Suite green** — 6369 passed / 0 failed; new code exercised by real planted agents.
5. **Coverage proven (Layer A)** — 12/12 catchable archetypes (a)-(k)+m discovered + correctly
   correlated; 0 false-merge / 0 dup / 0 decoy-as-agent; mutations survived; real-fleet hard case shown.
6. **Only irreducible gaps remain** — air-gapped (k)/BS-12 named with exact vantage, not fake-found;
   `BLIND_SPOT_REGISTER.md` complete.
7. **Rigor + speed** — ER P/R 1.0; completeness CI contains truth (99%/500 pops); ECE under-confident;
   per-feed latency FLAT 0.04ms@10k; time-to-first 0.043ms; 1000 agents cold 0.18s. All targets beaten.
8. **Beyond-frontier + no overclaim** — `BEYOND_FRONTIER.md` per-competitor edge, honest edges intact;
   honesty auditor PASS.

**Honest edges (carried, never hidden):** prod ships SIEVE OFF until the operator sets `TEX_SIEVE_*`;
ECE is conservatively under-confident; enforcement still needs a deployed in-path Body; eval is on
planted/synthetic ground truth + the local tex-enterprise fleet (not a customer estate yet).

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

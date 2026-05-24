# FRONTIER_DELTA_thread_7_1 — bleeding-edge upgrades

Self-audit landed Thread 7's gaps; this brief documents the seven
upgrades that bring Thread 7 onto the May 2026 frontier.

## Misses corrected (vs. Thread 7 ship)

| # | Miss | Fix |
| --- | --- | --- |
| 1 | RiskGate (arxiv 2604.24686, Apr 27 2026) — Aubin viability framework not cited; no scalar Viability Index; no P3 monotonic restriction. | Added `viability_index` computed scalar on `EcosystemAxisScores` (RiskGate B̂(x) decomposition); added `monotonic_restriction=True` engine opt-in with `viability_floor_for(actor)` + `record_recovery(actor)`. |
| 2 | GAAT (arxiv 2604.05119, Apr 6 2026, Apple) — not framed as OpenTelemetry-compatible; no graduated intervention levels. | Added `GraduatedEnforcementLevel` enum (L0..L4 per GAAT §III.A); added `tex.observability.governance_span.verdict_to_otel_attributes()` emitting GAAT GTS-compatible attribute dicts. |
| 3 | Kaptein (arxiv 2603.16586) "Policies on Paths" — not cited as the path-functional generalisation that Tex's per-event evaluation is a special case of. | Cited explicitly in CLAIMS.md Thread 7 section. |
| 4 | `fast_attribute` heuristic not anchored in published theory. | Replaced with full **Castro-Gómez-Tejada 2009 unbiased Monte-Carlo Shapley** estimator (Halpern-Kleiman-Weiner 2018 / Friedenberg-Halpern 2019 / Jørgensen et al. arxiv 2605.00248, Apr 30 2026). Exact for n ≤ 6, MC with adaptive sample budget for larger n; `FastAttribution` now exposes per-candidate `shapley_scores`. |
| 5 | Conflated distributional drift with behavioral drift. | Added Rath 2026 three-dimension taxonomy (arxiv 2601.04170): `semantic_drift` / `coordination_drift` / `behavioral_drift` on `DriftEvaluation`, with `_SIGNAL_TO_DIMENSION` map routing each signal to its Rath axis. Aggregate `drift_delta = max(three)`. |
| 6 | Probe map was hardcoded static dict. | Replaced with declarative `ProbeMapPolicy` (frozen dataclass) with three-tier evaluation: exact / substring / none. Operator-extensible without code edits, mirroring GAAT OPA Rego layering. |
| 7 | Step 7 systemic risk was flag-gated to `NotImplementedError`. | **Shipped working ProbGuard PCTL scorer** (arxiv 2508.00500 v3). 27-state DTMC abstraction over (agent_count, capability_pressure, compromise) bands. Online-learning transition matrix with Laplace smoothing + self-loop prior calibration. Computes P[F^{≤k} unsafe | current_state]. Cold-start risk from safe states ~0.08; absorbing unsafe states return 1.0. p99 latency 0.48 ms. |

## Verification

- **2,470 tests passing**, 16 skipped, zero regressions on the 2,408 Thread-7 floor.
- **93% combined coverage** on the eight Thread 7 + 7.1 surface modules.
- **End-to-end p99 still <50ms** with all four axes wired and ProbGuard live.

## What Tex now does that no shipping competitor does

1. **Eight-axis composite verdict** with cryptographic emission per event — AAF is the paper, Tex is the production runtime. No competitor composes ≥3 axes per event.
2. **Pre-emission Shapley-value attribution** on the request path — Halpern-Kleiman-Weiner blameworthiness on declared upstream chains, computed in <5ms p99. Every other system does post-hoc attribution.
3. **BOCPD + anytime-valid e-process + three-dimension Rath taxonomy** on action streams — Microsoft AGT and Zenity ship declared-intent comparison only.
4. **ProbGuard PCTL forward-looking systemic risk** with 27-state DTMC abstraction — the published paper, in production. ProbGuard, GeomHerd, and SR-DTMA are all paper-only at May 2026.
5. **RiskGate P3 monotonic restriction** — Aubin viability theory operationalised. RiskGate published the architecture; Tex ships it.
6. **GAAT-compatible OTel span schema** — Apple's GAAT defined the schema; Tex emits in it, dependency-free.

## Honest scope guardrails preserved

- Outreach must still not claim "the AAAI 2026 36.2% step-level accuracy on every event" (post-incident `attribute_root_cause` only).
- Aggregate composition gate remains Thread 8 territory — today the engine PERMITs even at low viability; the graduated level is *advisory*.
- Ye/Tan resource contracts not wired (Thread 9 territory).
- ProbGuard's DTMC abstraction is a 27-state proxy; GeomHerd-class curvature is Thread 9.

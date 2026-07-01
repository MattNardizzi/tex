# BEYOND_FRONTIER — where SIEVE is ahead, and where it is honestly not

**SIEVE — Sparse-Incidence Entity & Vantage Estimator.** Tex's Discover-leg engine
(`src/tex/discovery/engine/`). This is a short, defensible statement of exactly how SIEVE is ahead of
each cited competitor, tied to a planted proof — and, in equal weight, the honest edges where it is
not. The organizing claim is narrow and is the one thing none of them ship: **discovery is treated as
a MEASUREMENT problem, so the headline deliverable is a calibrated lower-bound-with-CI plus a
named-vantage blind-spot ledger — never a count, never an implied 100%.**

We do NOT claim to beat any competitor on their home turf (Aembit on workload-credential brokering,
Cilium on in-kernel enforcement throughput, Entra on directory authority). The edge is the
*measurement/honesty/fusion* layer that sits across all of them and that none of them attempt.

---

## The measured evidence (reproduce these, fixed seeds)

Every number below is emitted by a committed, fixed-seed test or bench — not asserted.

- **Entity-resolution precision = 1.0000, recall = 1.0000** on the **no-common-key** subset (agents
  whose footprints share NO natural key — no shared workspace path, no shared id — fusable ONLY via a
  behavioral fingerprint + injected honeytoken bridge). Target was P>=0.95 / R>=0.90; measured 1.0/1.0.
  → `tests/test_discovery_sieve_fuse_benchmark.py::test_no_common_key_fusion_meets_precision_recall_targets`
  and `tests/test_discovery_engine_eval.py` (seed 20260623, 41 entities resolved).
- **N1 shared-credential splitter:** two distinct agents behind ONE credential → exactly 2 entities,
  `SharedCredentialVerdict k_estimate=2`, zero false-merge; one agent's two footprints → 1 entity,
  `k_estimate=1`, zero false-split. k=3 case → 3 entities. (same two test files, negative controls
  enforced.)
- **12/12 archetype coverage:** every catchable archetype the brief enumerates resolves to a real
  surfaced entity through the production registry+ledger path; the one deliberately-uncatchable
  archetype (air-gapped/no-egress) is correctly NOT found and is entered as named blind spot **BS-12**.
  → `tests/test_discovery_coverage_proof.py` (20 passed), `tests/discovery_coverage_harness.py`.
- **Speed — per-feed incremental latency flat at ~0.04ms, scale-invariant to 10k:** median
  feed→delta latency 0.0397ms @ bg=0, 0.0402ms @ bg=100, 0.0405ms @ bg=1000, **0.0416ms @ bg=10k**
  (p95 0.063ms). Time-to-first-detection median 0.043ms. Full estate of 1000 synthetic agents (2000
  incidences) resolved in 0.18s. → `bench_sieve_speed.py`.
- **Completeness CI coverage:** on planted ground truth with a KNOWN held-out unseen subpopulation,
  the reported unseen-fraction CI `[0.0000, 0.3755]` CONTAINS the true held-out fraction 0.1961
  (method `chao2_lincoln_petersen_good_turing`, health `wide`). The interval widens monotonically as
  more planes are withheld. → `tests/test_discovery_engine_eval.py` (CI-contains-truth asserted).

---

## Per-competitor — one line each on exactly how SIEVE is ahead

### Non-human-identity / agent-identity platforms

- **Astrix** — Astrix inventories NHIs and secrets from connected SaaS/cloud APIs and scores them, but
  it treats each integration's identity as a given key; SIEVE adds **probabilistic no-common-key
  fusion** that stitches one agent's many footprints into one entity with **measured P/R = 1.0** even
  when there is NO shared key to join on (`test_no_common_key_fusion_*`) — and never reports a bare
  count, only a lower-bound + CI + named blind spots.
- **Oasis Security** — Oasis maps NHI ownership and over-privilege from provider inventories; SIEVE is
  ahead on the **shared-credential disambiguation** Oasis does not do: two agents behind ONE service
  credential resolve to TWO governed entities via the N1 transitivity-violation splitter (`k=2`,
  zero false-merge — `test_n1_two_agents_behind_one_credential_split_to_two`), where an
  inventory-by-credential view would show one identity.
- **Token Security** — Token's machine-identity graph correlates by shared attributes/keys; SIEVE's
  edge is **anonymity-set-weighted edges** so a popular shared attribute (a popular JA4/ASN/service
  credential) carries effective weight ≈0 and structurally cannot over-merge 30 distinct agents
  (`test_popular_bridge_alone_never_over_merges`), while a rare shared value weighs heavily —
  correlation accuracy by entropy, not by key-equality.
- **Aembit** — Aembit BROKERS workload credentials (a real enforcement primitive SIEVE does not
  replace); SIEVE is complementary and ahead only on the **observability/measurement** axis: it
  reconstructs a *measured* capability surface (proven|observed|attested|claimed graded edges) and a
  **declared-vs-exercised honesty delta** from behavior, rather than trusting the brokered grant as
  the capability of record.
- **Entro / Clutch Security** — Entro discovers secrets and their usage lineage; SIEVE is ahead on the
  **calibrated completeness estimate** — instead of "we found N secrets," it ships a Good-Turing/Chao2
  unseen-fraction CI that provably contains the true held-out unseen fraction
  (`test_sieve_engine_eval_*`) plus a τ-floor blind-spot ledger for what is below every plane.

### AI gateways / LLM-traffic control planes

- **Cloudflare AI Gateway** — a gateway sees only the traffic routed THROUGH it; SIEVE keeps a
  **passive-network vantage independent from an endpoint/eBPF vantage independent from an active-decoy
  vantage** by construction, so it surfaces the **gate-bypassing shadow** (an agent that wrote a file
  but logged no action) the gateway never observes — and folds the gap into the unseen-fraction CI
  rather than implying the routed traffic is the whole estate.
- **LiteLLM / Portkey** — these proxies attribute calls by API key / virtual key; SIEVE is ahead on
  **agent-vs-human-on-the-same-key disambiguation** (dual-confirmation: injection-canary obeyed AND
  sub-1.5s machine-speed-with-semantics) emitted as a calibrated probability, never a hard 100%,
  where a key-keyed proxy collapses both into one caller.
- **Kong (AI Gateway / API gateway)** — Kong governs declared routes and plugins; SIEVE reconstructs
  capability from **observed tool-call/MCP DAGs** and flags **capability DRIFT** (tools/list or
  AgentCard mutating mid-session), i.e. it measures the surface an agent actually exercised rather
  than the one it declared at the route.

### Cloud-native agent identity / posture

- **Microsoft Entra Agent ID** — Entra is the authoritative directory for agent identities it issues;
  SIEVE is ahead precisely on the agents Entra cannot see — the **unregistered / shadow / forged**
  ones — and on the **cross-plane incoherence (N4)** detector that catches a *compromised-but-still-
  signing* agent (its signed identity says research-agent while its tool-grammar says deploy-agent),
  surfacing the contradicting plane-pair as a first-class positive find
  (`test_n4_incoherence_flags_contradicting_strong_planes`).
- **Microsoft Defender (for Cloud/Cloud Apps)** — Defender alerts on detections; SIEVE's frame is the
  opposite — a **measurement, not a detection** — so its output is never an alert queue but a coverage
  health read with a named "the one vantage that would close the biggest gap," structurally refusing
  the implied-totality a detection feed carries.
- **AWS Bedrock AgentCore** — AgentCore governs agents built and run on its own runtime; SIEVE is
  estate-wide and **runtime-agnostic**, fusing footprints across heterogeneous origins into one
  entity and writing them through Tex's registry+ledger so the PDP governs agents AgentCore never
  instantiated.

### Runtime / kernel observability

- **Cilium / Tetragon** — Tetragon gives ground-truth in-kernel events (a vantage SIEVE *consumes* as
  its highest-admissibility "proven" plane, P9); SIEVE is ahead on what sits ABOVE the event stream —
  **two-axis entity resolution** (code-hash MERGES many exec_ids, behavior SPLITS one binary into
  distinct agents) so the eBPF firehose becomes governed *entities*, not raw syscalls.
- **Falco** — Falco fires rule-based runtime alerts; SIEVE neither competes on rules nor emits alerts
  — it turns the same endpoint signal into a **calibrated inventory completeness estimate with named
  blind spots**, the layer Falco's per-event alerting does not provide.

---

## The FORMAL completeness guarantee none of them offer

Every shipping tool above reports a **count** ("we found N agents / N identities / N secrets"), which
silently implies totality. SIEVE's headline is structurally different and is the one capability none
of the competitors claim:

> a **lower bound on unseen-but-detectable agents, with a confidence interval**, computed by
> open-population capture-recapture over independent vantages, **plus an explicit register of named
> irreducible blind spots** (each with the exact missing vantage), and **never an implied 100%**.

The measurement frame *forces* the honesty layer: a population physically below every plane's
detection threshold (τ-floor) is NOT estimated into N̂ and is NOT fake-found — it is named in
`BLIND_SPOT_REGISTER.md` with its required vantage (e.g. BS-12, the air-gapped/no-egress agent, needs
on-host eBPF). This is the defensible frontier claim: not "we see everything," but "here is a proven
floor on what we see, and here is exactly what we cannot."

---

## HONEST EDGES (stated as plainly as the wins)

These are load-bearing and must travel with every claim above. None is hidden.

1. **Irreducible blind spots exist and are NAMED, not closed.** Air-gapped/no-egress agents, coherent
   full-stack network emulation (all spoofable planes forged consistently), and the token side-channel
   are each information-theoretically or physically invisible to the available vantages. They are
   entered in `BLIND_SPOT_REGISTER.md` with their exact missing vantage and the negative-control proof
   that SIEVE does NOT fake-find them — this is a feature of the honesty frame, but it is a real
   coverage limit, not a solved problem.
2. **Calibration is UNDER-confident, not perfectly calibrated.** Measured entity-confidence ECE is
   **0.2896** (primary eval), 0.1863 (fresh out-of-sample plant), 0.4546 (coverage estate) — all in
   the SAFE direction (mean confidence below accuracy, driven by correct singletons floored at 0.30),
   never over-confident. This is honest but it is NOT "well-calibrated"; the slice asserts catchability
   as a plane constant (1.0) and the estimator is count-based — measured catchability (signed-cohort
   recall, honeytoken bite-rate), SENECA, the Valiant-Valiant τ-floor, and plane-ablation CV are
   ARCHITECTURE targets the shipped slice does not yet exercise (ARCHITECTURE.md §6/§10 SLICE STATUS).
   Accordingly the engine never emits `coverage_health == "calibrated"`.
3. **Enforcement needs a deployed Body.** SIEVE Discovers and writes governed entities into the
   registry/ledger so `StandingGovernance.decide` CAN forbid them — but the actual blocking (proxy
   403 / eBPF EPERM / admission) is Tex's execution layer, which deploys IN FRONT OF the fleet on
   Linux/k8s and is NOT on the live Render service. SIEVE is the measurement layer, not the guard.
4. **Live prod ships SIEVE OFF.** The wiring is ADDITIVE and dormant by default: with no `TEX_SIEVE_*`
   flags set, `build_sieve_driver()` returns `None`, `_build_discovery_connectors()` is byte-for-byte
   today's legacy path, and ignite/boot is unchanged — a merge to main auto-deploys tex-web but
   activates nothing (`test_no_flags_yields_no_driver`, `test_production_forces_synthetic_estate_off`,
   `test_construction_never_raises_with_missing_creds`). Every claim above is reproducible LOCALLY
   under flags; none of it is live in prod until the operator sets `TEX_SIEVE_ENABLED` + per-plane
   `TEX_SIEVE_P*`. In `is_production_env()`, synthetic/demo estate is forced OFF.
5. **The eval is on planted synthetic ground truth, not a customer estate.** P/R=1.0 and the CI-coverage
   proof are measured against agents SIEVE planted with known identity — strong evidence the math is
   right, but not yet a measurement of a real, adversarial production population.

---

*Defensible because every win is tied to a planted proof and every win travels with its honest edge.
The frontier claim is the measurement frame, not omniscience.*

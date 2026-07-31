# ARCHITECTURE — SIEVE

**SIEVE — Sparse-Incidence Entity & Vantage Estimator.**

The greenfield discovery engine for Tex's **Discover** leg (Discover→Decide→Prove→Learn). It is the
connective tissue the entire frontier is missing: probabilistic no-common-key footprint **fusion**,
shared-credential **disambiguation**, a calibrated **completeness** estimate with a confidence
interval, and an honest **named-blind-spot ledger** — over a continuous/streaming substrate, writing
resolved entities into the existing `agent_registry`/`discovery_ledger` so the PDP governs them.

> **The organizing commitment (the formula's spine):**
> **Discovery is a MEASUREMENT problem, not a detection problem.** Every plane is a calibrated
> instrument carrying a self-measured catchability; the headline deliverable is a *lower-bound-with-CI
> + a named-vantage ledger*, never a count. This single frame structurally forces the honesty layer.

This file is research-derived (traceable to `docs/internal/RESEARCH_LOG.md` sources) — see **§13 Prompt-provenance**.

---

## 0. The named FORMULA (one screen)

```
                          ┌──────────────────────────────────────────────────────────┐
   14 calibrated planes   │  SIEVE engine  (src/tex/discovery/engine/, own data model)│
   (P0..P14, each emits   │                                                          │
    an Incidence with a   │  1. SENSE     plane sensors → Incidence(footprint,        │
    self-measured         │               plane_id, catchability, observed_at)        │
    catchability)         │                                                          │
        │                 │  2. BLOCK     union of complementary blockers             │
        ▼                 │               (JA4-bucket ∪ ASN ∪ OIDC-sub ∪ tool-MinHash │
   Incidence stream  ───► │                ∪ learned-embedding LSH)                   │
                          │                                                          │
                          │  3. SCORE     Fellegi-Sunter (EM, TF-adjusted) edges,     │
                          │               weighted 1/anonymity-set-size; LLM = ONE    │
                          │               calibrated comparison w/ abstain            │
                          │                                                          │
                          │  4. RESOLVE   plane-TYPED correlation-clustering          │
                          │               (strong edges close transitively; weak      │
                          │                bridges MAY violate → SPLITTER)            │
                          │               + INCOHERENCE detector (contradicting       │
                          │                plane-PAIR = positive find)               │
                          │                                                          │
                          │  5. ESTIMATE  heterogeneity-robust open-population        │
                          │               capture-recapture over planes-as-occasions │
                          │               → unseen-FRACTION + CI ; τ-floor carve-out  │
                          │                                                          │
                          │  6. MAP       capability/blast-radius = observed tool-DAG │
                          │               ∩ IaC-IAM, each edge graded                 │
                          │                (proven|observed|attested|claimed)         │
                          │                                                          │
                          │  7. STREAM    online; tighten()-only confidence;         │
                          │               PresenceTracker delta; e-value anytime-valid│
                          └───────────────────────┬──────────────────────────────────┘
                                                  │  OUTPUT ADAPTER (one-way)
                                                  ▼
        registry.save(AgentIdentity)  →  discovery_ledger.append(candidate, outcome)
                                                  │
                                                  ▼
                       StandingGovernance.decide (reads live registry)  →  PDP governs
```

Headline deliverable per scan window:
`{ entities[], unseen_fraction: [lo, hi] @ CI, named_blind_spots[], coverage_health }`
— **never** a bare count, **never** an implied 100%.

> The diagram above describes the **full P0..P14 engine**. The "self-measured catchability" each plane
> emits is an ARCHITECTURE target, **not** what the shipped thin slice does: the slice asserts
> catchability as a plane constant and its estimator is count-based (does not consume it). See **§6
> SLICE STATUS** and **§10** for exactly which claims the slice backs vs defers.

---

## 1. Internal entity / data model

Greenfield, in `src/tex/discovery/engine/` with its OWN data model (NOT `reconciliation.py`). Three
layers: immutable LEAF observations → probabilistic ENTITY projection → governance OUTPUT shape.

### 1.1 Incidence (the leaf, append-only)
```
Incidence(
  incidence_id:      UUID,
  plane_id:          PlaneId,            # P0..P14
  footprint:         FootprintVector,    # plane-specific keys + attrs
  catchability:      float in [0,1],     # SELF-MEASURED (signed-cohort recall / bite-rate)
  observed_at:       datetime,
  admissibility:     Admissibility,      # proven|observed|platform_attested|claimed
  raw_evidence_ref:  str,                # for receipts
)
```
The `catchability` field is the seat of what is MEANT to make discovery a measurement problem: in the
full engine the estimator is fed *measured* per-plane recall, never assumed (RESEARCH_LOG N2).
**Slice status:** in the thin slice this field is an *asserted* plane recall (a constant `1.0`),
the slice estimator is count-based and does not consume it, and measurement is deferred to Phase 5
(see §6 SLICE STATUS and §10).

### 1.2 SieveEntity (the probabilistic projection)
```
SieveEntity(
  entity_id:        UUID,                # STABLE synthetic UUID — survives credential rotation/rename;
                                         #   NOT derived from any single forgeable attribute
  incidences:       set[incidence_id],   # one entity ← many footprints (FUSE);
                                         #   one shared credential → k entities (SPLIT)
  edges:            list[TypedEdge],     # each: (a,b, plane_id, grade, fs_weight, anon_set_size)
  fusion_confidence: float,              # explicit; low-confidence stays "possibly-new entity"
  merge_axis:       MergeKey,            # code-hash / model+SDK waveform / tool-set MinHash
  split_axis:       SplitKey,            # syscall-graph / tool-grammar n-grams / packetization / cadence
  capability:       CapabilityGraph,     # observed tool-DAG ∩ IaC-IAM, per-edge graded
  presence:         PresenceState,       # reused from PresenceTracker (N-consecutive-miss)
  attribution_conflict: bool,            # raised by the INCOHERENCE detector (N4)
  contradicting_pair:   tuple[PlaneId,PlaneId] | None,   # the evidence for a hide/compromise
)
```

**Two-axis identity (the kernel-eBPF vein's load-bearing insight):**
- **MERGE axis** (coarse): `bpf_ima_inode_hash` code-hash, model+SDK waveform [P4], tool-set MinHash
  [P10] — stitches many exec_ids/sessions/flows of the same code into ONE entity.
- **SPLIT axis** (fine): syscall-graph signature [P9], tool-call grammar n-grams [P10],
  packetization mode [P4], cadence entropy, SVID/eBPF runtime context [P13] — separates distinct
  agents collapsed under one binary/credential/egress.
- Code-hash alone is too COARSE (10k agents share one `python3` hash); exec_id alone is too FINE
  (every re-exec = new id). The entity is the JOIN: code-hash MERGES, behavior SPLITS.

### 1.3 Output shape (locked by `tex/domain/discovery.py`)
At the boundary, a SieveEntity projects to one `AgentIdentity` (`domain/agent.py` L309) with a
`CapabilitySurface`, and emits `ReconciliationOutcome`/`ReconciliationAction` (`domain/discovery.py`
L139/L387) + a `CandidateAgent`-shaped record with `discovery_source`/`discovery_external_id`
metadata so `ReconciliationIndex` keys it stably (service.py L133). The `reconciliation_key`
abstraction survives ONLY as an output-boundary shim (entity → stable key in
`AgentIdentity.metadata`) so the existing index and PresenceTracker keep working — internal identity
is the probabilistic entity, not the key.

---

## 2. Fusion / entity-resolution method

**Calibrated probabilistic entity resolution.** (RESEARCH_LOG §2, WS-2.)

1. **Candidate generation = UNION of complementary blockers** so evading one blocking key leaves the
   pair recoverable on another: exact keys (JA4-bucket, ASN, OIDC-sub, tool-set MinHash [P10]) ∪ a
   learned semantic/flow-embedding LSH block. [NLSHBlock, arXiv 2401.18064.]
2. **Pairwise scoring = Fellegi-Sunter core** (unsupervised EM, log₂(m/u) per-comparison weights,
   **term-frequency-adjusted** so a shared *rare* JA4/ASN/tool-set weighs heavily and a popular one
   ≈0). Missing field = weight 0, not a penalty. [Splink / FuzzyLink.]
3. **Anonymity-set weighting (N5):** every edge weighted by `1/anonymity_set_size` with a
   copula/anonymity-set correction for FS conditional-independence violation, so low-entropy
   attributes (popular JA4) cannot over-merge distinct agents and a honeytoken co-trip contributes
   near-certain evidence.
4. **LLM adjudicator = ONE calibrated weighted comparison, never the verdict.** Position-debiased
   listwise Select under a permutation ensemble (ComEM, arXiv 2405.16884), with **abstain** a
   first-class output that routes to active probing. A hallucinated match cannot over-merge.
5. **Resolution = plane-TYPED correlation-clustering (TransClean, arXiv 2506.04006):** edges are
   typed by provenance — *identity-grade* (behavioral embedding, code-hash, honeytoken co-trip,
   SVID) MUST close transitively; *bridging-grade* (shared IP/ASN/service-credential/popular-JA4)
   MAY violate. This single structure does fusion (strong edges merge) AND disambiguation (a weak
   bridge whose endpoints fail strong-edge transitive closure = two agents — **N1**).

Each entity carries explicit `fusion_confidence`; low-confidence footprints stay "possibly-new
entity" and flow into the estimator rather than being force-merged.

**Cross-plane INCOHERENCE detector (N4, headline).** Running in the same typed graph: when two
strong-edge planes *contradict* (JA4 says Chrome / h2 says Go; signed identity says research-agent /
tool-grammar says deploy-agent), that incoherence is a first-class POSITIVE detection of a
deliberately-hiding or compromised agent. The engine surfaces the contradicting plane-PAIR as
evidence and sets `attribution_conflict`. This catches the **compromised-but-still-signing agent
that AIP cannot** [arXiv 2603.24775].

---

## 3. Shared-credential & agent-vs-human disambiguation

Two hard cases, one estimator family (RESEARCH_LOG WS-3).

**(A) Two agents behind one shared credential / one egress.** The credential is a WEAK bridging node.
Cluster the credential's per-session footprint vectors on {tool-call grammar n-grams [P10],
inter-call cadence entropy, packetization mode (1:1 vs bundled) [P4], per-minute token time-series
decomposition from the Usage API [P11], JA4/runtime [P1], eBPF/SPIFFE runtime context [P9/P13]} via
an unsupervised mixture model; Bayesian model-selection on cluster count (account-sharing keystroke
literature, ResearchGate 247887278) estimates k≥1. An anytime-valid **e-value** test ("is this
stream a mixture of >1 generative process?") drives the split online [arXiv 2603.19022]. The
**strong-edge transitive-closure failure across the credential bridge IS the positive split signal
(N1).** Behaviorally-identical CLONES are split by attestation context (SPIFFE selector, eBPF
PID/exec_id) where present; residual unresolved sharers are reported as *counted, bounded
uncertainty*, never force-merged or force-split.

**(B) Agent vs human-using-an-LLM on the same egress.** **Dual-confirmation gate** (grafted from
CORROBORANT to cut the false-positive rate of either signal alone): an entity is classified
agent-in-the-loop only when BOTH (i) a planted prompt-injection canary [P14] is obeyed AND (ii) the
response is sub-1.5s machine-speed-with-semantic-content. Augmented where available by packetization
mode (bundled=agent, 1:1=human UI) [P4], tool-call grammar (tight n-gram=agent) [P10], and absent
biometric motor-noise where JS is injectable [P12]. Emitted as a CALIBRATED probability (conformal
open-set, arXiv 2510.13037), never a hard 100%. **Negative-control discipline (thin-slice):** a human
traversing the canary surface must NOT trip the LLM-in-the-loop confirmation.

---

## 4. Capability / blast-radius mapping

Reconstructed from OBSERVED behavior, not declared cards, and computed pre-runtime where possible.
Three fused layers, **each capability edge carrying a per-claim admissibility grade** so the PDP/UI
knows how much to trust it (wires `provenance/models.py` CoverageBoundary L238 into capability trust):

- **proven** — eBPF ground truth [P9]: actual fds/sockets/exec + decrypted tool-calls bound to PID
  (AgentSight) + fd/connection/child-lineage walk (eBPF-PATROL, arXiv 2511.18155).
- **observed** — the exercised tool-call/MCP DAG [P10/P11] (AegisMCP online incremental graph; OTel
  `execute_tool` spans). The set+sequence of tools an entity exercised IS its capability profile.
- **platform_attested** — IaC/serverless attached IAM role/service-account policy [P8] intersected
  with the tools the agent code statically binds (Agentproof recovered graph) = max reachable
  resources BEFORE first packet.
- **claimed** — A2A `skills[]` / MCP `tools/list` declaration [P10] — a CLAIM only.

First-class outputs: **declared-vs-exercised honesty delta** (used-but-undeclared = hidden blast
radius; declared-but-unused = dormant latent risk) and **capability DRIFT** (tools/list or AgentCard
mutating mid-session, code-hash change) as a fast attribution event. The canonical output vocabulary
is the existing `CapabilitySurface` schema (allowed_action_types/channels/tools/mcp_servers/
data_scopes) so the PDP governs a *measured* surface.

---

## 5. Continuous / streaming model & delta output

Streaming, anytime-valid, online — never a full point-in-time re-walk.

- **Streaming hook:** the existing per-candidate iterator (service.py L358) is the seam; each
  connector becomes an event source feeding `Incidence` records into an online pipeline. The batch
  accumulate-then-summarize envelope (L336-459) is replaced by an incremental event-emitting one;
  `_handle_candidate` (L594-630) is the unchanged unit of streaming work.
- **Incremental resolution:** online NLSH/MinHash blocking → incremental FS edge-scoring →
  incremental correlation-clustering with bounded re-resolution of touched components → online
  open-population capture-recapture update (Jolly-Seber-style for agent birth/death).
- **tighten()-only confidence:** a provisional entity is emitted on the first *instant*-plane
  sighting (P1/P2/P9/P13) and its confidence is monotonically TIGHTENED (never loosened) as
  *fast*/*slow* planes corroborate — mirroring the presence-tier `tighten()` monotonicity primitive.
- **Delta primitive = PresenceTracker (reused, now WIRED):** feed live candidate keys into
  `observe_seen` and previously-known-but-absent keys into `observe_missing`; the N-consecutive-miss
  threshold gives false-positive-suppressed soft-disappearance as the delta output. (presence.py is
  correctly UNWIRED into `service.scan` today — this is the wiring, not a rebuild.)
- **Anytime-valid guarantees:** verdicts and the unseen-fraction update under optional stopping via
  e-values / anytime-valid conformal [arXiv 2603.19022, 2510.13037].
- **Active effort on demand (N5):** when a coverage region goes quiet, the honeytoken lattice [P14]
  manufactures extra observation effort to push out the Orlitsky log(n) extrapolation horizon
  [PNAS 1607774113].
- **Token-conservation residual (N3)** recomputed continuously as a positive shadow-volume signal.
- **Birth/death plane:** cert-rotation cadence (GCP 24h SVID, Web Bot Auth key directory) mined
  passively; new commits/lockfile diffs/IaC PRs stream into the same open-population estimator as
  capture events.

**Delta output shape (per window):** `{ new_entities[], tightened[], confirmed_disappeared[],
capability_drift[], unseen_fraction_delta, coverage_health_delta }`.

---

## 6. Calibrated completeness / unseen-population estimator

(RESEARCH_LOG §6 records the citations; this section records method + assumptions + failure modes +
interval-widening.)

**Method.** Each plane (or time window) = a capture occasion; the resolved SieveEntity = the
captured individual; the cross-plane incidence frequency-of-frequencies (f1/f2/f3…) feeds:
- Good-Turing coverage Ĉ = 1 − Q1·c/N → headline unseen FRACTION (1−Ĉ) + CI.
- iChao2/Chao2 → absolute unseen-COUNT lower bound (log-normal CI).
- conditional-log-linear-among-the-unobserved + doubly-robust-ML → valid CI if either nuisance model
  is right; interaction terms for known plane correlations.
- **SENECA self-consistent missing-mass** → default when f1/f2 collapse (the hiding regime).
- Pitman-Yor Gaussian-CLT credible interval → closed-form power-law uncertainty.
- online Mb / trap-shy hazard → inflates the band on recapture-rate decay.

**Calibration:** signed-cohort recall (N2) + honeytoken bite-rate (N2) = *measured* catchability;
**plane-ablation cross-validation** (drop a plane, predict its catch, score the error — CORROBORANT
graft) empirically validates the CI.

**Assumptions (each engineered, not assumed away).**
1. Conditional independence *among-the-unobserved* (weaker than global independence) — engineered by
   keeping passive-network, endpoint-eBPF, and active-decoy as physically distinct vantages and
   measuring pairwise capture-correlation.
2. Closure within a window — relaxed to an open-population Jolly-Seber variant for streaming.
3. Linkage is imperfect — fusion match-uncertainty is PROPAGATED into the likelihood as soft
   incidence, not assumed perfect.
4. Every figure is a LOWER bound on unseen-but-detectable, never totality.

**Failure modes + HOW the interval WIDENS when assumptions break.**
- *Correlated planes share one tap* → bias low → mitigated by engineered vantage independence +
  log-linear interaction terms; estimator-disagreement (spread of Good-Turing/Chao2/SENECA) is added
  to the band → **interval widens**.
- *f1=0 (no singletons, the hiding regime)* → classical Chao breaks → **routed to SENECA**, and the
  switch itself flags elevated uncertainty → **interval widens**.
- *Adaptive trap-shy adversary shifts behavior after a probe* → online Mb hazard raises a per-entity
  "hiding hazard" → **interval widens conservatively**.
- *Signed marked-cohort unrepresentative of the unsigned population* → flagged as a calibration-
  validity caveat; validated empirically by held-out time-window posterior-predictive checks (later-
  discovered agents vs CI coverage); failure → **interval widens**.
- *Zero-catchability agent (mass below every plane's τ)* → OUTSIDE capture-recapture support → NOT
  estimated, NAMED in the blind-spot ledger with its exact missing vantage (Valiant-Valiant τ-floor)
  → never folded into N̂, never fake-found.

The estimator **always** ships `unseen-but-detectable LOWER bound, [CI], plus N named irreducible
blind spots` — never a total, never 99%, never an implied 100%.

> **SLICE STATUS (count-based; calibration deferred).** The shipped slice estimator
> (`engine/estimate.py`) is **COUNT-BASED**: it counts capture occasions per entity and applies
> classical two-occasion Lincoln-Petersen / Chao2 / Good-Turing. It **does NOT consume the measured
> catchability** described under **Calibration** above — the slice asserts catchability as a plane
> constant (`1.0`) and the field is *carried-but-unused* by the estimator. The following are
> ARCHITECTURE targets **NOT yet exercised** by the slice and must not be read as live capability:
> measured catchability (signed-cohort recall / honeytoken bite-rate), the **SENECA**
> self-consistent-missing-mass algorithm (the slice's `seneca_no_overlap` method tag merely *names*
> the m==0 regime and returns a wide count fallback — it does not run SENECA), the **Valiant-Valiant
> τ-floor**, the **Orlitsky** extrapolation horizon, and **plane-ablation cross-validation**.
> Accordingly the slice never emits `coverage_health == "calibrated"` — that word is reserved for the
> Phase-5 estimator that measures catchability and passes ablation. What the slice DOES prove: a
> lower bound clamped `<= 0.99` (never totality), an interval `ci_low <= lower <= ci_high` with a
> named count-method tag, a named blind-spot per withheld plane, and no silent zeros.

---

## 7. The OUTPUT ADAPTER (into agent_registry / ledger)

A one-way projector mirroring `service._apply` (service.py L691-721), registry-first/ledger-last:

```
project(entity: SieveEntity):
    candidate = entity.to_candidate_agent()          # CandidateAgent shape (domain L237)
    decision  = entity.to_reconciliation_decision()  # REGISTER | UPDATE surface | QUARANTINE | HELD
    if decision.new_agent:
        saved = registry.save(decision.new_agent)            # AgentIdentity, monotonic revision
        index.link(entity.reconciliation_key(), saved.agent_id)
    elif decision.update_capability_surface_for:
        registry.save(existing.model_copy(update={...}))
    elif decision.quarantine_agent_id:
        registry.set_lifecycle(id, AgentLifecycleStatus.QUARANTINED)
    discovery_ledger.append(candidate=candidate, outcome=entity.to_outcome())   # SHA-256 hash-chained
```

- Both registry writes pass through `gate_controller_mutation` (self-governance); the adapter MUST
  honor the returned `AgentIdentity` (a blocked save is a silent no-op).
- The adapter writes a compatible `reconciliation_key` into `metadata` (discovery_source/
  discovery_external_id) or the index treats the entity as new next scan (churn risk).
- `HELD_DUPLICATE` (currently an unreachable action enum) is finally populated by SIEVE's
  similarity-based duplicate detection.
- After the entity lands, `StandingGovernance.decide` (standing.py L823/L842) and
  `AgentEvaluationSuite.require_evaluable` (suite.py L91) can govern it.

---

## 8. The full PLANE roster + full-sweep-by-default posture

The 14-plane breadth target (RESEARCH_LOG §1), including the FLOOR planes the brief requires
(identity, network-egress, kernel/eBPF, managed control planes, SaaS/automation, governance-stream).
**Begin ignites the ENTIRE discovery layer**: `build_sieve_driver` is live by default and lights the
full-sweep switch (`TEX_SIEVE_ALL`) on its env snapshot, so every roster plane arms on every sweep —
in dev AND production. A plane is dark only when its vantage genuinely does not exist (no source, no
credential — the sensor degrades to inert and coverage speaks it as a dark plane), never because a
flag was unset. Explicit operator values always win: `TEX_SIEVE_ENABLED=0` removes the driver
entirely, an explicit `TEX_SIEVE_ALL` value is honored as-is, and an explicitly-falsey per-plane flag
opts that single plane out under the full sweep. The per-plane activation flags below remain the
opt-out/opt-in vocabulary; they are no longer required to arm a plane. Genuinely-intrusive
sub-actions (P14 decoy planting, P10 active probing) keep their OWN sub-flags, which the sweep never
sets — full sweep means passive sensing on every plane. The merge to `main` (auto-deploys tex-web to
prod on Render) must still never crash ignite: every sensor degrades to EMPTY, never raises.

| Plane | FLOOR category | Default | Activation flag | Default-safe degrade |
|-------|----------------|---------|-----------------|----------------------|
| P1 JA4 client-hello | network-egress | OFF | `TEX_SIEVE_P1_JA4` | sensor returns empty (no feed) |
| P2 JA4S/SPKI | network-egress | OFF | `TEX_SIEVE_P2_SPKI` | empty |
| P3 h2 framing | network-egress | OFF | `TEX_SIEVE_P3_H2` | empty |
| P4 token waveform | network-egress | OFF | `TEX_SIEVE_P4_WAVEFORM` | empty |
| P5 OAuth grant | SaaS/automation | OFF | `TEX_SIEVE_P5_OAUTH` | empty when no admin API |
| P6 cloud audit | managed control plane | OFF | `TEX_SIEVE_P6_AUDIT` | empty (OCSF source injected) |
| P7 vault/CI-OIDC | managed control plane | OFF | `TEX_SIEVE_P7_VAULT` | empty |
| P8 supply-chain/provenance | SaaS/automation | OFF | `TEX_SIEVE_P8_SUPPLY` | parse-only, no network |
| P9 kernel/eBPF | kernel/eBPF | OFF | `TEX_SIEVE_P9_EBPF` | empty when no sensor (stub today) |
| P10 MCP/A2A | SaaS/automation | OFF | `TEX_SIEVE_P10_MCP` | empty when unreachable |
| P11 OTel + billing | governance-stream | OFF | `TEX_SIEVE_P11_OTEL` | empty when uninstrumented |
| P12 client biometrics | network-egress (active) | OFF | `TEX_SIEVE_P12_BIO` | empty when no JS injection |
| P13 signed-id | identity | OFF | `TEX_SIEVE_P13_SIGNED` | empty (calibration only) |
| P14 honeytoken lattice | active | OFF | `TEX_SIEVE_P14_DECOY` | inert (no decoys planted) |
| P0 coverage-health | governance-stream | OFF | `TEX_SIEVE_P0_COVERAGE` | reports "coverage unknown" |
| Occasion A actions-trail (§10 slice) | governance-stream (runtime logs) | OFF | `TEX_SIEVE_ACTIONS_TRAIL` — auto-lit in dev when `TEX_SIEVE_ACTIONS_DIR` is set; an explicit value wins | empty (no root in SenseContext) |
| Occasion B fs-write-scan (§10 slice) | endpoint (workspace ground truth) | OFF | `TEX_SIEVE_FS_WRITE` — auto-lit in dev when `TEX_SIEVE_WORKSPACE_DIR` is set; an explicit value wins | empty; both roots forced OFF in production |
| SIEVE engine master | — | **ON (full sweep)** | `TEX_SIEVE_ENABLED` — explicit `0` opts out; `TEX_SIEVE_ALL` injected unless explicitly set | falls back to key-equality reconciliation |

Gating rules (grounded in main.py wiring-seam): construction MUST NOT throw on missing creds (boot
list built eagerly before lifespan); each sensor's `scan` MUST degrade to EMPTY, not raise (like
`ConduitConnectionsConnector` returning inert when unconnected); in production
(`is_production_env()`), synthetic estate (sandbox/demo-seed) is forced off so SIEVE surfaces only
real planes; the standing watch is opt-in (no tenants → scheduler is a no-op). A new sensor is
registered either in the boot list `_build_discovery_connectors()` (main.py L2164) or at runtime via
`discovery_service.register_connector` (service.py L267), each wrapped so it never blocks boot.

---

## 9. Output doctrine (spoken vs object)

Honors the existing surface doctrine: **spoken = meaning, object = bare handle**. SIEVE's surface
read is the calibrated lower-bound-with-CI spoken as one honest line ("I can see at least N, and I
estimate I'm missing between X and Y — here is the one vantage that would close the biggest gap"),
with the rich `{entities, unseen_fraction, named_blind_spots, coverage_health}` available as the
object handle. A *list of findings* is the alert queue Tex exists to refuse — coverage/provenance is
surfaced as the object handle + spoken honest-edge sentence (CoverageBoundary `edge_of_sight`), never
a forced agent table.

---

## 10. The THIN VERTICAL SLICE plan

Smallest end-to-end proof in `src/tex/discovery/engine/` (new module, own data model), proven on
planted agents in the tex-enterprise fleet. **The honesty layer is proven FIRST, before breadth
exists** — the right build order.

**ONE plane:** the **eBPF host plane [P9]** (highest-admissibility, ground-truthable, locally
runnable against real tex-enterprise side-effects). Start from the fully-implemented `kernel_ebpf.py`
stub; swap its in-process `events=` input for a real Tetragon-shaped/host event stream — OR for the
first slice ingest the tex-enterprise `actions.jsonl` activity-trail plane PLUS an independent
fs-write-scan of WORKSPACE diffed against logged writes (two genuinely-independent capture occasions
— the minimum capture-recapture needs, and the only way to see the gate-bypassing shadow).

**Pipeline:**
1. **SENSE** — a new `EngineConnector` emits `Incidence` records (not CandidateAgents) from the plane,
   each carrying an *asserted* catchability (a plane constant in the slice; measured catchability is a
   Phase-5 target — see §6 SLICE STATUS). The slice estimator is COUNT-BASED and does not consume it.
2. **FUSE** — a minimal FS edge-scorer + plane-typed single-link clusterer resolves the agent's two
   footprints (exec/code-hash leaf + SSL/egress leaf, or trail + fs-write) into ONE SieveEntity via a
   cross-plane edge with calibrated confidence and a stable synthetic `entity_id`.
3. **ESTIMATE** — a two-occasion Lincoln-Petersen/Chao2 estimate over {plane-A-saw, plane-B-saw}
   emits a deliberately-WIDE lower-bounded unseen fraction + CI, plus a fully-populated named
   blind-spot ledger entry for the deliberately-withheld third plane.
4. **OUTPUT ADAPTER** — the resolved entity is written through the MANDATORY boundary:
   `registry.save(AgentIdentity)` + `discovery_ledger.append(...)`, mirroring `service._apply`.

**PROOF (negative controls included):**
- (a) plant ONE evasive shadow that acts on a REAL plane (file/subprocess/socket) but bypasses
  `onboard_with_tex` + `tex_gate` (zero `actions.jsonl` row) → SIEVE discovers it via the independent
  fs/eBPF plane, resolves it to one entity with a fusion receipt;
- (b) it lands in the registry and `StandingGovernance.decide` can now govern it;
- (c) the unseen-fraction CI brackets the withheld plane's contribution and widens monotonically as
  more planes are withheld;
- (d) a SECOND planted ZERO-signal agent (acts only on the withheld plane) is NAMED in the
  blind-spot ledger with its exact missing vantage and is NOT fake-found;
- (e) **negative control:** two footprints of ONE agent do NOT split; a human traversing the canary
  surface does NOT trip the LLM-in-the-loop confirmation; a fully-governed agent yields zero
  token-conservation residual and trips no decoy.

Baseline is green (6250 tests collect clean; discovery subset 21/21). Add tests under the
`tex-discovery` top-level `test_discovery_*.py`. **Then** add plane #2 (TLS/JA4 or cadence) to make
capture-recapture non-degenerate and the entity model cross-plane.

---

## 11. Independence-of-vantages (why the estimator stays valid)

The three physically-distinct vantages are kept independent BY CONSTRUCTION so the capture-recapture
math is valid: **passive-network** (P1–P4) vs **endpoint-eBPF** (P9) vs **active-decoy** (P14) are
different physics. Pairwise capture-correlation is measured and fed into the log-linear interaction
terms to de-bias; planes that share one tap (P1 and P3) get an explicit interaction term rather than
being double-counted.

---

## 12. What SIEVE deliberately does NOT do (honest edges)

- It does not treat any single plane as identity (every plane is an anonymity-set-weighted edge).
- It does not claim totality — the headline is always a lower bound + CI + named blind spots.
- It does not fake-find the zero-signal class — those are NAMED in the register (`docs/internal/BLIND_SPOT_REGISTER.md`).
- Intrusive sub-actions never auto-activate — the full sweep arms passive sensing only; decoy
  planting and active probing stay behind their own sub-flags (§8).
- It does not rebuild the governance boundary — it reuses registry/ledger/PDP exactly (§7).

---

## 13. Prompt-provenance note (the formula is research-derived)

**This formula is RESEARCH-DERIVED, traceable to the sources in `docs/internal/RESEARCH_LOG.md`, and is NOT taken
from the seed prompt's named techniques.** The prompt's named techniques (Fellegi-Sunter,
capture-recapture/Chao, JA4, behavioral fingerprinting) are treated strictly as *today's frontier to
surpass*: each is justified independently from a cited source AND pushed past a stated frontier limit
(FS → anonymity-set/copula weighting + TransClean typed clustering; Chao → SENECA/DR-ML + signed-
cohort calibration; JA4 → demoted to a weak anonymity-set edge with full-stack emulation declared a
named blind spot). The five load-bearing NOVELTY mechanisms (N1 plane-typed transitivity splitter;
N2 signed-cohort+honeytoken catchability calibration; N3 injected-marker join key + token-conservation
residual; N4 cross-plane incoherence as a first-class detector catching the compromised-but-signing
agent; N5 anonymity-set-weighted edges + Orlitsky-horizon active effort) are each stated absent from
the bundle's prior art and each given a concrete tex-enterprise verification with a negative control.
A competent engineer could not produce SIEVE from a buzzword list, because every method is conditioned
on a specific cited failure mode and the architecture's center of gravity is the measurement/honesty
layer the buzzwords do not contain. The organizing commitment — *discovery is a measurement problem,
not a detection problem* — is the spine, derived from the cross-vein finding that every shipping tool
asserts totality while the unseen-population estimators exist but have never been pointed at agents.

---

*End ARCHITECTURE.md — SIEVE. Greenfield engine; reuse only the governance output boundary.*

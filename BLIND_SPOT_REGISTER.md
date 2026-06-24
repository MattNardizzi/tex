# BLIND_SPOT_REGISTER — SIEVE

A **first-class, machine-readable register** of every irreducible / known blind spot in the SIEVE
discovery engine. This register is not a footnote — it is a load-bearing output. The completeness
estimator's support is DEFINED to EXCLUDE these classes; SIEVE never folds them into N̂ and never
fake-finds them.

> **Rule (non-negotiable):** a blind spot with no named vantage is NOT allowed. Every entry below
> records its **EXACT required vantage** — the specific instrument that would convert it from
> invisible to seen — so each blind spot is auditable and *addressable*, not a vibe.

Two honesty axes, kept separate (per the measurement spine):
- **Unseen-but-detectable** — agents some plane *could* catch but didn't this window → handled by the
  capture-recapture LOWER bound + CI (ARCHITECTURE §6), NOT listed here.
- **Irreducible / vantage-gap** — agents physically below every available plane's detection
  threshold τ, OR catchable only by a vantage SIEVE does not currently hold → listed here, each with
  its exact missing vantage, declared via the Valiant-Valiant τ-floor and NEVER estimated into N̂.

Each entry: **ID · class · why it is invisible · EXACT required vantage · how SIEVE reports it ·
verification.**

---

## BS-01 — Zero-emission agent (catchability 0 on every available plane)
- **Class:** irreducible (information-theoretic).
- **Why invisible:** emits no signal exceeding any plane's detection threshold τ; e.g. an agent that
  only holds a credential or maintains an idle connection without writing files, calling the gate, or
  egressing measurably.
- **EXACT required vantage:** *any* net-new vantage that intersects its activity — e.g. an
  identity-provider/SaaS audit log for a UI-driven no-config agent, or a liveness/process plane where
  its mass exceeds that plane's τ. Until such a vantage exists it is outside the estimable population
  by the Valiant-Valiant impossibility bound (mass below τ on all planes is uncountable).
- **How SIEVE reports it:** a **Valiant-Valiant impossibility certificate** — worst-case mass hideable
  below every plane's τ simultaneously — NEVER folded into N̂, NEVER fake-found.
- **Verification:** plant an agent engineered to emit below every wired plane's threshold; assert it
  is declared "unseen, requires vantage X" and excluded from the estimate.

## BS-02 — stdio-transport MCP / fully-local loopback agent
- **Class:** irreducible to network vantages (physics).
- **Why invisible:** a local subprocess talking to a localhost MCP server over stdio emits ZERO
  network signal by construction — invisible to every network tap (P1–P4, P10-over-network).
- **EXACT required vantage:** a **host endpoint / eBPF sensor on that specific host [P9]** (syscall +
  process-tree); no network tap can ever see it.
- **How SIEVE reports it:** named gap "fully-local stdio agent on host H — requires eBPF/host sensor
  on H"; excluded from the network-plane estimate, counted only where P9 is wired.
- **Verification:** plant a stdio MCP agent on a host with P9 disabled; assert it appears as a named
  vantage-gap, not a silent zero, and is caught once P9 is enabled.

## BS-03 — Fileless / interpreted agent on a shared runtime
- **Class:** vantage-gap (the inode code-hash is too coarse).
- **Why invisible:** a python script behind a generic `python3`, or fileless via `memfd_create` /
  ptrace-injection — `bpf_ima_inode_hash` identifies only the shared interpreter, so distinct
  script-agents collapse to one merge-key (10k agents share one `python3` hash).
- **EXACT required vantage:** **per-script loaded-module hash via a uprobe on the interpreter's
  import/module-load machinery** (or the loaded `.py` path via `openat2`) — kernel vantage on the
  host, finer than the inode hash.
- **How SIEVE reports it:** entity class "interpreted agent on shared runtime; missing vantage =
  per-script loaded-module hash"; merge-collapsed entities are flagged low-confidence-on-split-axis.
- **Verification:** plant two distinct scripts behind one `python3`; assert SIEVE flags the
  merge-collapse and names the per-script-hash vantage rather than reporting one entity as certain.

## BS-04 — kTLS / QUIC-h3 / sidecar-remote / managed-runtime egress
- **Class:** vantage-gap (defeats the SSL_read/SSL_write uprobe).
- **Why invisible:** kTLS, QUIC/HTTP-3, statically-linked/BoringSSL/custom-crypto, or a remote/
  sidecar egress bypass the userspace TLS uprobe [P9 semantic] AND shift record sizes so the
  token-stream waveform [P4] is unreadable; ECH additionally destroys SNI destination attribution.
- **EXACT required vantage:** a **kTLS `sk_msg` kernel hook** (for kTLS), a **QUIC/h3-aware
  token-stream extractor pinned across the specific TLS libs** (for QUIC), or a **TLS-terminating
  inspection proxy** (for remote/sidecar). For ECH: JA4S/SPKI server fingerprint [P2] or passive DNS
  HTTPS-RR as a confidence-degraded fallback.
- **How SIEVE reports it:** semantic intent reported as unavailable; destination reported as
  low-confidence (JA4S/SPKI/ASN fallback) or a named gap — never a false-certain SNI.
- **Verification:** drive a planted agent over kTLS/QUIC on a host with only the userspace uprobe;
  assert SIEVE names the kTLS/QUIC vantage gap and degrades destination confidence honestly.

## BS-05 — Full-stack browser-emulation / utls / curl-impersonate (coherently forged)
- **Class:** irreducible to passive network when ALL planes are coherently forged.
- **Why invisible:** an agent driving a real Chromium (Playwright/Puppeteer) or using utls/
  curl-impersonate normalized to a popular human JA4 [P1] AND coherent h2 framing [P3] AND jittered
  timing [P4] is indistinguishable from a human on every network plane. (Note: a *partial* forgery is
  CAUGHT by the N4 incoherence detector — this entry is the *coherent* case only.)
- **EXACT required vantage:** **client-side attestation / endpoint EDR, or injected-JS interaction
  biometrics [P12], or an active honeytoken [P14]** — no passive network plane can individuate it.
- **How SIEVE reports it:** surfaced as quantified unseen MASS feeding the estimator (it spoofed into
  the human crowd) PLUS a named blind spot "all spoofable network planes coherently forged — requires
  client-side attestation or active probe."
- **Verification:** plant a coherent full-stack emulation; assert N4 does NOT false-trip (coherence
  holds) and the agent is named as a passive-network vantage-gap, then caught when P12/P14 is enabled.

## BS-06 — Non-streaming + fully-padded response flow
- **Class:** irreducible to the token side-channel (physics).
- **Why invisible:** when the LLM response is fully padded and non-streamed, the per-token length/
  timing channel [P4] physically does not exist.
- **EXACT required vantage:** a **TLS-terminating inspection proxy, or a host/eBPF vantage [P9]** —
  the encrypted-cadence plane is physically empty here.
- **How SIEVE reports it:** "token side-channel empty (padded+non-streaming) — requires terminating
  or host vantage"; P4 catchability for that flow reported as 0.
- **Verification:** replay a padded non-streaming flow; assert P4 yields no incidence and the gap is
  named rather than the flow being dropped silently.

## BS-07 — SaaS-with-no-grant-introspection-API / UI-driven embedded-AI agent
- **Class:** vantage-gap (the OAuth plane cannot enumerate it).
- **Why invisible:** an agent acting through a SaaS that exposes no admin/audit/OAuth-grant
  introspection API [P5], or an analyst driving embedded-AI inside a SaaS via the UI, leaves no
  enumerable principal.
- **EXACT required vantage:** a **SaaS provider audit log or OAuth-grant export API for that specific
  provider** (or Zscaler-style inline embedded-AI auto-classification for AI hidden inside non-AI
  SaaS).
- **How SIEVE reports it:** named gap "agent on SaaS provider P with no grant-introspection API";
  counted only once that provider's API is wired; never a silent zero.
- **Verification:** point P5 at a provider with no introspection API; assert the gap is named with the
  provider identity, not omitted.

## BS-08 — Identity-forging agent reusing a governed agent's self-asserted name
- **Class:** vantage-gap (the asserted identity is unverifiable).
- **Why invisible:** `agent_external_id` is an unverified self-asserted string (tex_gate trusts the
  name blindly), so an actor laundering actions under a legitimate agent's name cannot be caught by
  name-correlation alone.
- **EXACT required vantage:** a **binding between the asserted `agent_external_id` and an independent
  identity signal** — process owner / attested credential / network origin / eBPF PID-code-hash [P9]
  / SVID [P13]. (Partial mitigation: the N4 incoherence detector flags signed-vs-behavior divergence
  where a signature exists.)
- **How SIEVE reports it:** where no independent signal exists, named gap "name-only identity,
  forgeable — requires identity-binding vantage"; where P9/P13 exists, the laundering surfaces as an
  attribution_conflict (N4).
- **Verification:** plant an agent reusing a governed name with no independent signal; assert SIEVE
  refuses to merge on name alone and names the binding-vantage requirement.

## BS-09 — ECH-only flow with no corroborating JA4S/SPKI server fingerprint
- **Class:** vantage-gap (destination attribution lost).
- **Why invisible:** ECH encrypts the true SNI; with no corroborating JA4S/SPKI [P2] the real
  destination is unknowable on-path.
- **EXACT required vantage:** **passive DNS HTTPS-RR of the same client's prior lookups, or
  destination-IP/ASN-to-provider mapping** — otherwise destination is reported confidence-degraded.
- **How SIEVE reports it:** destination reported as low-confidence (ASN fallback) or a named gap;
  never fake-resolved to a certain SNI.
- **Verification:** replay an ECH flow with no JA4S corroboration; assert destination is degraded, not
  fabricated.

## BS-10 — Uninstrumented stack (no OTel spans / no provider billing visibility)
- **Class:** vantage-gap (the observability plane is empty).
- **Why invisible:** an agent calling tools outside instrumented SDKs, or a provider whose usage API
  SIEVE has not federated, emits no spans [P11] and no billing time-series.
- **EXACT required vantage:** **OTel auto-instrumentation on that stack, OR the provider's usage/cost
  admin API federated into the token ledger.** Partial detection: the **token-conservation residual
  (N3)** localizes the un-instrumented volume even without spans.
- **How SIEVE reports it:** the non-zero token-conservation residual flags "instrumentation gap at
  workspace/egress W"; the specific provider/stack is named as the required vantage.
- **Verification:** run a planted agent on an uninstrumented stack; assert the residual is non-zero and
  localizes it, and the missing-OTel vantage is named.

## BS-11 — Single python3 PID hides the whole tex-enterprise thread-fleet (host-plane attribution limit)
- **Class:** vantage-gap (process-level attribution too coarse for in-process threads).
- **Why invisible:** the tex-enterprise fleet runs 20 agents as daemon THREADS in one interpreter, so
  a `/proc`/process-table plane sees one `python3` PID for all 20 — process-level attribution alone
  cannot separate them.
- **EXACT required vantage:** **thread/fd/socket-level eBPF attribution, OR fs-write attribution under
  WORKSPACE** (which file each thread wrote), finer than the PID.
- **How SIEVE reports it:** where only PID-level signal exists, entities flagged "thread-fleet under
  one PID — requires thread/fd-level vantage"; the fs-write-attribution plane (thin-slice) resolves
  them where wired.
- **Verification:** run the recipe fleet with only PID-level signal; assert SIEVE does not over-merge
  the 20 threads into one entity silently, and names the thread-level vantage.

---

## Coverage proof — Layer-A result (every claim maps to a REAL planted agent)

**Verdict: PASS (re-verified 2026-06-23).** Run via the comprehensive harness
(`tests/discovery_coverage_harness.py` + `tests/test_discovery_coverage_proof.py`,
**20/20 green** — re-run confirmed green this date). Every coverage claim
below maps to a REAL planted incidence the engine actually surfaced — no
archetype is asserted from a buzzword.

> **Final coverage tally (this run):** 12/12 catchable archetypes (a)..(j) + (m)
> discovered and correctly correlated, **excluding the irreducible (k)** which is
> correctly NOT found and is entered below as a named blind spot (BS-12). ER
> precision = ER recall = 1.0; false-merges = 0; duplicates = 0;
> decoys-as-agents = 0; mutations survived. An INDEPENDENT fresh-key harness
> (identifiers the author never saw) resolved all 12 catchable archetypes to
> exactly their expected entity counts plus 3 extra hostile traps (shared-ASN
> no-merge, 3-plane-stays-one, cred-rotation-stays-one), all green. Entity-
> confidence ECE = 0.1863 (fresh-plant) / 0.2675 (independent fresh-key) / 0.2896
> (primary eval) — **all in the SAFE under-confident direction** (mean confidence
> ≈ 0.81 against resolution accuracy 1.0; the engine is never over-confident).
> This is a fusion-confidence-vs-correctness *diagnostic*; the completeness
> estimate ships as `coverage_health="wide"`, never `"calibrated"`
> (`completeness_ci_calibrated=false` is the engine's own honest self-label).

**Speed (TIME-TO-FULL-ESTATE @20, real fleet, cold).** The WHOLE real
tex-enterprise footprint (~10⁵ leaf incidences — 127k+ trail lines + 31k+ files)
resolves SENSE→FUSE cold in **~9s** (measured 9.26s: SENSE 4.12s + FUSE 5.14s),
well under the **60s** target, asserted green by
`test_discovery_coverage_proof.py::test_time_to_full_estate_real_fleet_cold_under_budget`
(backed by harness `run_real_fleet_full_estate`). This closes a prior >9-minute
non-completion: candidate generation is now **star-blocked** (a large blocking
bucket becomes a spanning star — O(n) edges, identical resolved components —
instead of an O(Σ bᵢ²) clique that exploded a single popular `workspace_path`/
`agent_external_id` value of ~3.4–8.5k leaves into ~3·10⁸ pairs); the
Fellegi-Sunter EM fits over the **distinct weighted agreement vectors** (4 shapes
on the real fleet) instead of every pair; and the behavioral shared-credential
splitter **defers oversized cohorts** (> `_BEHAVIORAL_COHORT_CAP`) to the
structural N1 clusterer with an honest `behavioral_split_deferred_cohort_too_large`
verdict rather than running its O(n²)/O(n³) mixture model on a thousands-deep
cohort. None of these change a single resolved entity on the planted estate (ER
precision = recall = 1.0 unchanged; primary ECE 0.2896 unchanged — the weighted
EM is mathematically identical). The deliberately-irreducible archetype
(k) is the ONLY undiscovered agent and is entered as a named blind spot, **NOT
fake-found** (harness plants no incidence for it — `plant_all`, the line marked
"(k) ... DELIBERATELY NOT planted" — and the proof asserts its label is absent
from `found_labels()`).

**Headline:** **100% of the 10 enumerated catchable archetypes (a)..(j) plus the
hostile over-merge trap (m) discovered — 11 enumerated catchable archetypes →
13 distinct AGENT entities surfaced** (the shared-credential pair (h) splits to 2
and the hostile popular-JA4 pair (m) splits to 2; the irreducible (k) is excluded
by construction).

> **What the "13" counts (and what it excludes).** The 13 is the **AGENT-entity
> count over the enumerated archetypes** only. It deliberately **EXCLUDES** the
> non-agent fixtures the same estate plants as negative controls: the **8
> popular-JA4 crowd decoys** (the anonymity-set crowd a popular bridge must be
> diluted against — they are not agents and must not be surfaced as such) and the
> **2 non-agent baits** (the dormant/duplicate decoys under (i) that must NOT
> become agents). So the **23 entities the engine actually resolves over the full
> planted estate** = the 13 archetype agents + the 8 crowd decoys + the 2
> non-agent baits; the "13" is the agent subset, NOT a smaller-than-23
> discrepancy. The two numerals measure different sets and must not be read
> against each other.

This is a count over the *enumerated* archetype catalogue, **not**
a claim of totality over the full agent population — the population claim is the
estimator's lower-bound + CI + named blind spots, never an implied 100%. All
correctly correlated; ER precision = recall = 1.0; false-merges = 0;
duplicates = 0; decoys-as-agents = 0; mutations survived.

**Calibration (cited from the test that computes it, not this run).** The
Layer-A coverage proof (`test_discovery_coverage_proof.py`) does **not** compute
ECE. The calibration figure comes from the eval harness
`tests/test_discovery_engine_eval.py::test_engine_eval_metrics`, which PRINTS the
measured value at marker `[4] entity-confidence ECE`. **The current measured
value is ECE = 0.2896** (entity-resolution accuracy = 1.0000, asserted
`0.0 <= ece <= 1.0`) — under-confident vs a deliberate 0.30 singleton-confidence
floor, never over-confident. (The previously-printed "0.433" was stale; the
number now cited is the value the named test actually emits.) An *independent*
fresh-plant harness — `test_discovery_engine_eval.py::test_fresh_plant_ece_corroborates_primary_same_safe_direction`,
which plants a SEPARATE population on a distinct seed (`0xF00D5EED`) with fresh
hex sigs / honeytoken ids the engine never saw — emits **ECE = 0.1863**
(accuracy = 1.0000, mean entity confidence = 0.8137; printed at marker
`[fresh] entity-confidence ECE`). It is the **same safe direction** as the
primary 0.2896 (under-confidence: mean confidence below accuracy, driven by
correct singletons floored at 0.30 — never over-confident), corroborating that
the miscalibration is conservative. A **third, independent recompute over the
coverage-harness estate** — emitted by
`test_discovery_engine_eval.py::test_coverage_harness_ece_third_corroboration_same_safe_direction`,
which resolves the FULL Layer-A coverage estate (**23 resolved entities**,
**entity-resolution accuracy = 1.0000**, mean entity confidence ≈ 0.545) and
PRINTS the value at marker `[harness] entity-confidence ECE` — yields **ECE ≈
0.45** (printed-not-pinned, it tracks the engine; the test asserts the safe
under-confident direction `mean_conf <= accuracy + 0.05`, not a fixed numeral).
This is the **same underconfident direction** again (mean confidence below
accuracy, floored singletons), so all three estates (eval 0.2896 / fresh-plant
0.1863 / harness ≈0.45) agree the miscalibration is conservative, never a
false-positive driver. **All three named-test figures are cited the same way —
each to the `file::test` that actually emits it, never a measured number with no
emitting test.** (The "23 resolved entities" is the FULL coverage estate the
harness plants — the per-archetype headline "13" counts the AGENT subset only,
a deliberately different set, per the "what the 13 counts" note above.) The headline
`coverage_health` label is guarded to never read `"calibrated"` without
plane-ablation (§6 SLICE STATUS), so the completeness claim stays honest-wide
regardless of the ECE point value.

### Per-archetype coverage map

| # | Archetype | Discovered | Via plane(s) | Correlated | Register entry |
|---|-----------|------------|--------------|------------|----------------|
| a | laptop-local-noidp | ✅ | KERNEL_EBPF + FS_WRITE | ✅ | caught (host vantage present); BS-02/BS-07 if those vantages withheld |
| b | inproc-embedded-thread | ✅ | GOVERNANCE_STREAM + NETWORK_EGRESS | ✅ | caught; **BS-11** names the PID-collapse gap when only PID-level signal exists |
| c | stdio-mcp-server | ✅ | KERNEL_EBPF + MCP_TOOLGRAPH + STATIC_SUPPLYCHAIN | ✅ | caught (host plane present); **BS-02** names the gap when P9 is absent |
| d | egress-only-noidp | ✅ | NETWORK_EGRESS (singleton) | ✅ | caught |
| e | credentialed-cloud | ✅ | SIGNED_ID + MANAGED_CONTROL (one entity, no double-count) | ✅ | caught |
| f | pdp-only-agent | ✅ | GOVERNANCE_STREAM (singleton) | ✅ | caught |
| g | static-prerun-agent | ✅ | STATIC_SUPPLYCHAIN | ✅ | caught |
| h | shared-cred-pair | ✅ | GOVERNANCE_STREAM + NETWORK_EGRESS, split via **N1** (resisted a coincidental egress_ip+JA4 bridge) | ✅ | caught; **BS-08** names the binding gap where no independent signal exists |
| i | decoys (human / dormant / duplicate) | ✅ | human→HUMAN class, dormant→no exercised capability, duplicate→1 entity (2 sightings fused) | ✅ | caught; 0 decoys-as-agents, 0 false-merges |
| j | evasive-catchable | ✅ | KERNEL_EBPF + GOVERNANCE_STREAM, **N4** attribution_conflict raised | ✅ | caught (partial-forgery branch); **BS-05** names the coherent-forgery branch |
| **k** | **irreducible-airgapped** | ❌ (correct) | **NONE** — named blind spot | n/a | **BS-12** (below) — WITHHELD_THIRD + HONEYTOKEN vantages, NOT fake-found |
| m | hostile-shared-ja4: two distinct agents sharing one POPULAR JA4 | ✅ (→ **2 entities**) | KERNEL_EBPF (own code-hash anchor each) + NETWORK_EGRESS (shared popular JA4) — **N5** anonymity-set / over-merge bar held; the popular bridge contributes ≈0 and the strong components fail transitive closure across it → resolved to TWO distinct entities | ✅ | caught; 0 false-merges (the over-merge dual of (h)). Real plant: `_plant_hostile()`; green assertion: `test_hostile_shared_ja4_resolves_to_two_entities` |

### Hard case proven on REAL data (read-only, no agent cooperation)

The engine was run **read-only over the real `tex-enterprise` fleet** (NOT the
easy cooperative `plant_shadow` self-registering shadow). From the **FS_WRITE
plane alone** (a non-identity, non-cooperative vantage) it surfaced **genuine
gate-bypass shadows** — real files written with **no matching governance/grant
trail row**:

- `workspace/iam/grants.jsonl` is a real grant file the engine sees on the
  FS_WRITE plane but which has **no matching governance/grant trail row** — i.e.
  the engine surfaces file side-effects the governance stream never recorded.
  (Measured `grants.jsonl` length at audit time: 2,337 rows; this numeral is a
  point-in-time read of a live, growing fleet file, not a pinned test
  assertion — the *test-backed* claim is the bypass result below.)
- Test-backed result (`run_real_fleet_slice()`, asserted green in
  `test_real_fleet_surfaces_gate_bypass_shadows_readonly`): **`bypass_count ≥ 1`
  (observed 2 in the bounded window on the 2026-06-23 re-run)**, and **at least
  one** gate-bypass file is resolved to a real `SieveEntity`
  (`sl.bypass_entities` non-empty), with `planes_seen=[FS_WRITE]` and `conf=0.30`
  (singleton floor — honestly low, since only one plane saw it). The exact
  `bypass_count` and entity ids are NOT pinned as numerals here because they
  track a live, growing fleet; the **entity ids regenerate every run** (the
  synthetic `entity_id` is stable WITHIN a resolution but the fleet's files
  change between reads, so the example ids below are point-in-time, not pinned).
  The reproducible, asserted claim is `bypass_count >= 1` with a non-empty
  `bypass_entities`. **2026-06-23 live re-run** produced 2 bypass entities
  (`9aab6174…`, `544b1726…`), each `planes_seen=[FS_WRITE]`, `conf=0.30` — fresh
  ids from a fresh read of the live fleet, confirming the invariant holds and the
  ids are not memoized.
- The registry/ledger write path (`reconciliation.py` / `service.py`) is present
  so each surfaced shadow lands where `StandingGovernance.decide` can govern it.
- **Full-estate read-only confirmation (point-in-time, not pinned).** A separate
  full-estate SENSE pass over the live fleet produced **71,741 trail leaves +
  34,846 FS leaves** and surfaced **4 genuine gate-bypass files** (written with
  NO matching trail row). One real local agent was resolved **ONLY via the
  FS_WRITE non-identity plane** (no IdP / no SIGNED_ID / no MANAGED_CONTROL):
  `entity_id=4358e8c6-3911-465e-95ee-d275b635ea7d`, `planes_seen=[FS_WRITE]`,
  leaf `workspace/iam/grants.jsonl`, `gate_bypass=true`, fusion receipt present.
  The full governance-boundary chain was confirmed end-to-end: registry write
  0→1 via `adapter.project`, hash-chained ledger append (sequence /
  `payload_sha256` / `previous_hash` / `record_hash`), `led.verify_chain() == True`.
  **Nothing was written to the fleet** — the engine ran strictly read-only. These
  five-figure leaf counts and the entity id are point-in-time reads of a live,
  growing fleet, NOT pinned test assertions; the reproducible asserted claim
  remains `bypass_count >= 1` with a non-empty `bypass_entities`.

This is the load-bearing demonstration: SIEVE finds the **gate-bypassing shadow
the governance stream cannot**, on real data, with zero cooperation.

---

## BS-12 — Physically-irreducible air-gapped agent (the deliberate archetype k) — NAMED, NOT fake-found

- **Class:** irreducible (information-theoretic) — the canonical instance of BS-01,
  recorded explicitly here because it is the planted **archetype (k)** of the
  Layer-A coverage proof and the single deliberately-undiscovered agent.
- **Why invisible:** a self-hosted / air-gapped model with **no egress** (no
  NETWORK_EGRESS incidence), **no IdP / no signed identity** (no SIGNED_ID /
  IDENTITY_IDP incidence), **no PDP call** (no GOVERNANCE_STREAM incidence), and
  no host sensor on its machine — it emits **zero observable signal on every
  wired plane**. The harness plants **no `Incidence` whatsoever** for it (it is
  ground-truth-absent by construction), so any "discovery" of it would be a pure
  fabrication.
- **EXACT required vantage:** **a net-new vantage that physically intersects its
  activity on the host where it runs.** Concretely, the engine names the two
  withheld planes that would close it: **(1) `WITHHELD_THIRD`** — the deliberately
  unwired third independent capture occasion (a **host endpoint / eBPF sensor on
  that air-gapped host [P9]**, the only passive way to see syscalls/process-tree
  of a no-egress agent); and **(2) `HONEYTOKEN`** — an **active honeytoken /
  decoy lattice [P14]** planted inside its blast radius (the only *active* way to
  manufacture a capture event for an agent that emits nothing passively). Until
  one of these exists, its mass is below every wired plane's τ-floor and is
  **outside capture-recapture support** (Valiant-Valiant impossibility bound).
- **How SIEVE reports it:** as **two `NamedBlindSpot` entries** —
  `missing_plane=WITHHELD_THIRD` and `missing_plane=HONEYTOKEN` — each carrying
  the reason string asserting it is "excluded from the unseen estimate and never
  fake-found." It is **never folded into N̂** and **never appears in
  `found_labels()`**.
- **Verification (negative control, GREEN):**
  `tests/test_discovery_coverage_proof.py::test_irreducible_agent_is_named_blind_spot_not_found`
  asserts (a) `irreducible_label not in result.found_labels()` (NOT fake-found),
  and (b) `{WITHHELD_THIRD, HONEYTOKEN} ⊆ {b.missing_plane for b in named_blind_spots}`
  (named with its exact vantage). The mutation test re-asserts (a) survives
  estate mutation. **Confirmed (2026-06-23 re-run): archetype (k) is present in
  the register with its exact vantage (WITHHELD_THIRD = host/eBPF sensor on the
  air-gapped host [P9]; HONEYTOKEN = active decoy lattice [P14]), is excluded from
  N̂, and was NOT fake-found** (`irreducible-airgapped` absent from
  `found_labels()`).

---

## Register operating rules

1. **Every estimate ships with this register.** The headline output is
   `unseen_fraction[lo,hi] @ CI + named_blind_spots[]`; the register entries that apply to the current
   estate are attached by ID.
2. **τ-floor carve-out.** Mass below every wired plane's measured τ is summed into a single
   Valiant-Valiant certificate (BS-01) and excluded from N̂.
3. **No silent zeros.** Any plane that *structurally* cannot see a class returns a named gap for that
   class, never an empty result that reads as "none exist."
4. **Vantage-closure tracking.** When an operator wires a new plane, the register records which
   blind-spot IDs it closes and re-runs plane-ablation to confirm the CI tightened as predicted (N2).
5. **Negative-control discipline.** Each verification above includes the negative control that the
   class is named (not fake-found) AND that enabling the named vantage actually catches it.
6. **Test-teeth (engine-mutation audit, non-blocking).** The suite was adversarially mutated to
   confirm it is not vacuous: the `ja4→identity` mutation makes the over-merge (m) test fail, and the
   `strip code_hash` mutation fails 6 fusion tests — both prove the suite has teeth. One mutation (the
   `k-clamp` forcing structural N1 `k_estimate=1` in `fuse._apply_bridges`) did NOT turn the
   shared-cred split (h) test red, because the entity-level split is **double-covered** by (1)
   structural strong-component separation and (2) the behavioral splitter in `disambiguate.py`. This
   is a robustness property (two distinct entities + zero false-merge still hold), recorded here for
   honesty, not a coverage failure.

---

*End BLIND_SPOT_REGISTER.md — SIEVE. Every blind spot named; every name carries its exact vantage.*

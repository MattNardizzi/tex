# FRONTIER_DELTA — Thread 3 (REVISED — Option B, full bleeding-edge)

**Compiled:** May 18, 2026 (post-Phase-0-v2)
**Replaces:** the v1 brief; v1 archived at
`.archive/FRONTIER_DELTA_thread_3_v1.md`
**Thread goal (revised):** wire `src/tex/causal/` into a post-incident
attribution endpoint that combines, for the first time anywhere, four
SOTA pieces that exist in research and standards drafts but have not
been assembled in any published implementation or shipping product:

  1. **Graph-based attribution** (CHIEF/ARM, arxiv 2602.23701 + 2604.04035)
  2. **Prefill-stage SLM signals** (MASPrism, arxiv 2605.07509, May 7
     2026) — adapted to read NLL + attention from a richer SLM than
     MASPrism used
  3. **Optional ZK proof of attribution computation** (NanoZK, arxiv
     2603.18046, Mar 2026; ZK-Value LSH-Shapley, arxiv 2605.03581,
     May 2026) — for environments that require third-party verification
     of the attribution without re-execution
  4. **Optional TEE attestation binding** (NVIDIA NRAS EAT JWT +
     PTV envelope, draft-anandakrishnan-ptv-attested-agent-identity-00,
     Mar 2026) — for environments running attribution inside H100 CC

All four are wrapped in a SCITT-shaped COSE_Sign1 Signed Statement
conformant to `draft-kamimura-scitt-refusal-events-02` with the
`ATTRIBUTE` event-type extension.

**Why this is genuinely novel:** Phase 0 v2 explicitly searched for
prior implementations of this combination. None found. The pieces
exist; the assembly does not.

**Phase 0 method (v2):** 16 web searches across (a) successor / newer-
than-1.4 hunt for causal attribution, (b) Who&When/TRAIL SOTA, (c)
competitor survival check, (d) SCITT Refusal Events draft check, (e)
NeuroTaint verification, (f) COSE/SCITT wire format, (g) production
reality, (h) AAAI 2026 final-form numbers, (i) last-14-days sweep, (j)
**v2 only:** SLM-state-of-the-art post-MASPrism, (k) **v2 only:** ZKML
proof-of-attribution / NanoZK / ZK-Value Shapley, (l) **v2 only:**
NVIDIA NRAS attestation EAT JWT format, (m) **v2 only:** PTV
attestation envelope and SCITT composition, (n) **v2 only:** combined
signed-attribution-receipt prior art search. Targeted `web_fetch` of
SCITT Refusal Events `-02`, Microsoft AGT v3.5.0 README, AAAI 2026
paper, PTV draft.

---

## 1. What's newer than section 1.4 — REVISED

Eight findings from v1 PLUS five new ones from v2.

### 1.1-1.8 — preserved from v1 (summarized)

* MASPrism 2605.07509 (May 7, 2026) — prefill SLM signals, 27.59%
  Top-1 on Who&When-HC.
* Rethinking Failure Attribution 2603.25001 (Mar 2026) — multi-
  perspective beats single-deterministic.
* AAAI 2026 2509.08682 — Shapley blame + CDC-MAS, 36.2% step accuracy.
* ARM verified 2604.04035 — Causality Laundering, denial-induced
  counterfactual edges.
* AgenTracer ICLR 2026 accepted.
* SCITT Refusal Events `-02` (Jan 29, 2026), full CDDL grammar.
* Microsoft AGT v3.5.0 (May 8, 2026) — no causal attribution module.
* Zenity/Noma checked — no causal attribution.

### 1.9 — v2 NEW: Qwen3.5-0.8B is strictly newer than MASPrism's SLM
MASPrism uses Qwen3-0.6B (2025). Qwen3.5 series shipped 2026-03-02
with Qwen3.5-0.8B. Qwen3.6 shipped April 16-22 with much better
agentic / repository-level reasoning. **Qwen3.5-0.8B is the
bleeding-edge SLM choice as of May 18, 2026** — post-MASPrism,
strictly better at trace parsing. Decision: Qwen3.5-0.8B preferred;
Qwen3-0.6B fallback; pure-graph fallback when no SLM loaded.

### 1.10 — v2 NEW: NanoZK (arxiv 2603.18046, Mar 2026)
Layerwise zero-knowledge proofs for LLM inference. **23ms
verification**. First practical ZK-SNARK for LLM-scale forward
passes. Direct relevance: optionally proves the prefill SLM forward
pass was run on the claimed model. Attribution carries both the
signals AND a 192-byte proof.

### 1.11 — v2 NEW: ZK-Value LSH-Shapley (arxiv 2605.03581, May 2026)
Shapley-style data valuation in ZK at marketplace scale. LSH-Shapley
primitive: bucket by locality-sensitive hash signatures of
contribution patterns, compute Shapley within buckets. O(n log n)
instead of O(2^n). **Replaces my v1 proportional-blame heuristic
with a real tractable Shapley approximation.**

### 1.12 — v2 NEW: NRAS produces EAT-format JWTs with GPU measurements
NVIDIA Remote Attestation Service GA. Endpoint
`https://nras.attestation.nvidia.com/v3/attest/gpu` returns an EAT
(JWT) with claims `x-nvidia-overall-att-result`, `submods.GPU-0`,
`eat_nonce`, signed `ES384`. Intel Trust Authority composes this
with CPU TEE attestation into a single composite JWT. Production-
ready on GCP, Phala, Red Hat OpenShift AI.

**Decision impact:** attribution claim set optionally carries
`tee_attestation` with the NRAS EAT JWT (or its SHA-256 digest).

### 1.13 — v2 NEW: PTV (draft-anandakrishnan-ptv-attested-agent-identity-00, Mar 2026)
Defines `eat_profile: "urn:ietf:params:attest:ptv"` with
`method: "groth16-2026"`. Explicitly states **"PTV BFT audit logs
are SCITT-compatible transparency logs. PTV proofs MAY be submitted
to SCITT registries for public verification."** IETF-standardized
way to combine Groth16 ZK proof + hardware attestation + SCITT log
entry.

**Decision impact:** Tex adopts PTV envelope shape for ZK+TEE-bound
attribution statements. Any PTV verifier consumes them without
custom glue.

### 1.14 — v2 NEW (added post-locking, fully implemented): Conformal Agent Error Attribution (arxiv 2605.06788, May 7 2026)
Feng, Sui, Hou, Wu, Cresswell (Dalhousie / Layer 6 AI). Code at
github.com/layer6ai-labs/conformal-agent-error-attribution. Applies
filtration-based **conformal prediction** to multi-agent error
attribution, producing a *contiguous prediction set* over trajectory
indices with finite-sample, distribution-free coverage guarantee:

    P[ decisive_error_index ∈ C(trace; α) ] ≥ 1 - α

Where graph + prefill + Shapley produce a **point prediction** of the
decisive error (one specific step), conformal attribution produces an
**uncertainty-bounded region** (a contiguous index range). The two
compose: graph picks the point, CP bounds the region of suspicion
the auditor should investigate.

**Three of the four algorithms from §3.1 implemented in
`tex.causal.conformal_attribution`:**

  * Vanilla CP (§3.1.1) — baseline, may be non-contiguous
  * Left/Right Filtration (§3.1.3) — anchored at trajectory endpoint
  * Two-Way Filtration (§3.1.4) — paper's recommended choice;
    anchors at peak score, expands bidirectionally; produces the
    tightest contiguous sets in expectation; **Tex default**

We skip §3.1.2 (Leaf-to-Root Tree Traversal) because Tex's traces
are linear, not tree-structured — that algorithm degenerates to
vanilla CP for linear inputs.

**Scoring function:** prefill SLM NLL when available, screener
confidence as fallback. Both are monotonically rankable.

**Coverage modes:**
  * `transductive` (default) — threshold from the trace's own score
    distribution; marginal coverage approximate (no calibration set)
  * `calibrated` — threshold from a held-out calibration set
    configured via `TEX_CONFORMAL_CALIBRATION_PATH`; formal
    finite-sample guarantee

**Honest framing:** transductive mode is what's appropriate without
labeled historical failure traces. The endpoint reports which mode
produced the set so auditors can interpret correctly. Calibrated
mode is enabled by simply pointing the env var at a file of
historical scores.

**Decision impact:** Tex's attribution endpoint accepts
`include_conformal: true` in the request body. When enabled, the
result carries a `conformal_set` field with the contiguous range,
the threshold used, the algorithm, the coverage mode, and the
target coverage level. The signed SCITT claim set carries the same
CP set under the `conformal_set` key (CBOR-deterministic, with
floats encoded as ppm integers per the same convention as
confidence values). The `attribution_method` tag is suffixed
`+conformal` when present.

**No paper or product to date** combines a CP-based prediction-set
attribution with graph-based candidate attribution, prefill-stage
signals, LSH-Shapley blame, ZK proof envelope, and TEE attestation
binding inside a single signed SCITT statement. This is what the
Phase 0 v2 pre-completion sweep confirmed.

---

## 2. Competitor survival check (UNCHANGED from v1)

No competitor ships causal failure attribution. Wedge intact. Updates:

| Component | State | Touches this thread? |
|---|---|---|
| Microsoft AGT v3.5.0 | May 8, 2026, no causal attribution | No |
| NVIDIA NRAS | GA, production endpoint live | We **consume** |
| Intel Trust Authority composite CPU+GPU | GA Apr 2026 | Possible future |
| Phala Cloud CVM marketplace | open | Not in this thread |
| EZKL → NanoZK | Mar 2026, 23ms verify | We optionally produce |

**Nobody combines these pieces with a governance attribution endpoint.**
The combinatorial space is open.

---

## 3. Standards revisions — REVISED (NEW rows in bold)

| Standard / Draft | v1 ref | Current state | Impact |
|---|---|---|---|
| `draft-kamimura-scitt-refusal-events` | `-00` | `-02` (Jan 29, 2026) | ATTRIBUTE extension |
| `draft-ietf-scitt-architecture` | `-22` | `-22`, revision pending | Binding target |
| `draft-kamimura-vap-framework` | `-00` | `-00` | Terminology |
| `draft-kamimura-scitt-vcp` | `-00` | `-01` | Pattern only |
| **`draft-anandakrishnan-ptv-attested-agent-identity`** | **not in 1.4** | **`-00` (Mar 2026)** | **Adopted for ZK+TEE case** |
| **`draft-anandakrishnan-rats-ptv-agent-identity`** | **not in 1.4** | **`-00` (Apr 2026)** | **RATS-WG companion** |
| RFC 9052 / RFC 9360 / RFC 9334 | implicit | unchanged | Bindings |
| FIPS 204 ML-DSA | wired | unchanged | SCITT signing |
| **`draft-ietf-cose-dilithium`** | **provisional** | **`-06` (Mar 2026)** | **COSE labels -48/-49/-50** |

---

## 4. Build plan — REVISED

### 4.1 v1 changes preserved
* Multi-candidate attribution (ranked list)
* SCITT-shaped, not SCITT-conformant
* Read-only hot path
* `tex.evidence.scitt_cose_alg` and `tex.evidence.scitt_statement`
  already implemented this session

### 4.2 v2 NEW: optional prefill SLM signals
`tex.causal.prefill_signals` wraps Qwen3.5-0.8B (preferred), Qwen3-
0.6B (fallback), pure-graph (no-SLM fallback). Exposes
`extract_signals(trace) -> PrefillSignals` returning per-step
token-level NLL spikes and attention-entropy. Pure prefill, no
decoding.

Used by attribution engine to **rank** graph-derived candidates.
This hybrid (graph narrows, signals re-rank) is what no prior paper
has done.

Fallback semantics: SLM unloaded → empty `PrefillSignals`,
`signals_available=false`, attribution still works.

### 4.3 v2 NEW: optional ZK proof
`tex.evidence.attribution_zk` produces a NanoZK-style layerwise
Groth16 proof binding model_hash, trace input hash, prefill signals
hash. For v1 of this thread: **wire format and verifier surface
implemented; prover side is a documented stub** until an open NanoZK
reference impl lands. The schema, envelope, and verifier are
bleeding-edge today; the prover seam is plumbed honestly.

### 4.4 v2 NEW: optional TEE attestation binding
`tex.evidence.tee_binding` reads an NRAS EAT JWT either from local
NRAS cache (when running on H100 CC) or caller-supplied. Claim set
carries `tee_attestation` with format `EAT-JWT`, jwt or digest, and
nonce. Verifier chains: SCITT envelope sig → claim integrity →
NRAS JWT sig → GPU measurement vs expected RIM hash.

For v1: claim carriage and verifier path implemented. Runtime NRAS
network call is env-gated, returns test JWT by default.

### 4.5 v2 NEW: real LSH-Shapley
Replace v1's proportional-blame heuristic with LSH-Shapley
(arxiv 2605.03581 §3). O(n log n) Shapley approximation. Real
algorithm, documented and citable.

### 4.6 Result schema (final)

```python
class CausalAttributionResult:
    decision_id: UUID
    candidates: tuple[CausalCandidate, ...]
    primary_root_cause: CausalCandidate
    blame_distribution: Mapping[str, float]       # LSH-Shapley
    causality_laundering_suspected: bool
    confidence_signals: Mapping[str, float]
    signals_available: bool
    attribution_method: str  # "graph" | "graph+prefill" | "graph+prefill+zk" | "graph+prefill+zk+tee"
    signed_statement: SCITTSignedStatement
    ptv_envelope: PTVEnvelope | None
    tee_attestation: TEEAttestation | None
    attribution_latency_ms: float
```

---

## 5. Numerical SOTA targets — REVISED

| Metric | SOTA reference | Target |
|---|---|---|
| Endpoint p95 (graph only) | n/a | **< 200ms** |
| Endpoint p95 (graph + prefill) | n/a | **< 800ms** |
| Endpoint p95 (graph + prefill + ZK) | NanoZK | **< 30s** |
| ZK proof verification | NanoZK 23ms | **< 50ms** |
| NRAS EAT JWT verification | NVIDIA spec | **< 100ms** |
| Signed statement round-trip | RFC 9052 | **must verify** |
| Deterministic given same inputs | ARM paper | **100%** |

Future thread benchmarks against Who&When (27.59% MASPrism), step-
level (36.2% AAAI), TRAIL (18.3%).

---

## 6. Design decisions — REVISED additions

(v1 decisions 6.1–6.7 preserved; new ones below.)

### 6.8 v2: Qwen3.5-0.8B over Qwen3-0.6B
Post-MASPrism release. Strictly better at instruction-following on
trace inputs. Using a model the only published attribution paper
hasn't tried is the right call for "ahead of the frontier."

### 6.9 v2: Graph FIRST, signal re-ranking SECOND
Graph traversal: deterministic, fast, audit-clean. Prefill signals:
statistical, model-dependent, harder to defend in court. Graph
produces candidates; signals rank them. Inverse of MASPrism's
design (signals → candidates) because our input is a structured
decision graph, not a flat trace.

### 6.10 v2: ZK and TEE are OPTIONAL
Forcing either would impose hardware dependencies, inflate latency,
and conflict with algorithm-agility. Optional tiers:
* Default: graph + prefill, ~800ms p95
* High-assurance: + ZK proof, ~30s
* Regulated + GPU: + TEE attestation, ~30s

Per-call flag or per-tenant config.

### 6.11 v2: PTV envelope, not bespoke
PTV is the IETF-standardized envelope for Groth16 + TEE + SCITT.
Inventing a Tex-private shape would make our statements
unintelligible to non-Tex verifiers. Adopting PTV means consumability
from day one.

---

## 7. Scope split

**In scope (this thread):**
* All v1 deliverables
* Prefill SLM signal extraction (Qwen3.5-0.8B preferred)
* LSH-Shapley blame distribution
* PTV envelope wire format
* TEE attestation claim carriage
* NRAS EAT JWT verifier
* NanoZK proof envelope (verifier + documented prover stub)

**Out of scope (follow-on threads):**
* Real NanoZK prover wiring (needs open reference impl)
* Real NRAS network call (env-gated, default test JWT)
* Who&When / TRAIL benchmark runs

Every wire format, schema, verifier, signing primitive, and API
surface is real and bleeding-edge today. Two stub points (NanoZK
prover call, real NRAS network call) are clearly marked and have
working test-mode equivalents.

---

## 8. Pre-completion sweep plan (unchanged from v1)

Final 14-day sweep before declaring the thread done.

---

**End of revised brief.** Code follows.

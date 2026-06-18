# Subsystem Dossier: `nanozk` (Zero-Knowledge Layerwise Proofs)

> Scope: `/Users/matthewnardizzi/dev/tex/src/tex/nanozk/` (13 `.py` files).
> Branch: `feat/proof-carrying-gate`. All claims code-verified; `.md`/docstring
> assertions are labelled "(claim, unverified)" unless confirmed in code.

---

## Overview

`nanozk` is a **deactivated, research-early placeholder** that wraps keyed-hash
(HMAC-SHA-256) stand-ins in the *shape* of a layerwise zero-knowledge proving
pipeline for transformer inference. It is **not** a cryptographic proof system.
This is not merely my read — it is enforced in code by a hard verifier gate and
confirmed empirically (below).

The unit's stated ambition (per the module docstrings, claim-level) is to attach
a per-layer ZK proof to each Tex-governed model invocation: prove that a
transformer forward pass ran on declared weights with declared inputs producing
declared outputs, over a Fisher-information-selected subset of layers, wrapped
for zero-knowledge (VEIL) and post-quantum folding (LatticeFold+/Mira), rooted
in a SNARK-friendly hash (Poseidon), with optional external proving backends
(DeepProve subprocess). **What the code actually computes is HMAC tags and
SHA-256 chains.** Every "commitment", "proof", "transcript", and "accumulator"
in this package is an HMAC/SHA-256 binding under a default static key.

### The two load-bearing facts (verified in code)

1. **Hard deactivation gate.** `verify_layer_proof_set()` returns
   `is_valid=False` with reason `nanozk_deactivated_placeholder_not_a_real_proof`
   **unless** `TEX_NANOZK_ALLOW_SHIM=1` is set
   (`layerwise_prover.py:1304-1312`, gate logic `_shim_enabled()` at
   `:1268-1279`). That env var is set only by the package's own test fixture
   (`tests/nanozk/conftest.py:20`). Verified at runtime:
   - gate OFF → `is_valid=False`, `reason=nanozk_deactivated_placeholder_not_a_real_proof`
   - gate ON  → `is_valid=True`, `reason=None`

   Consequence: even with the production flag `TEX_FRONTIER_NANOZK=1` flipped,
   the live verifier path (`tex.evidence.attribution_zk._verify_nanozk_layerwise`)
   gets `is_valid=False` and stays fail-closed.

2. **The build/prove side IS wired into the running app**, the verify side is
   NOT. `prove_layer_set` is reached from the live FastAPI route
   `POST /v1/incidents/{decision_id}/attribute`
   (`api/incident_routes.py:626`) when `body.include_zk_envelope` is True and
   `TEX_FRONTIER_NANOZK=1`. `verify_layer_proof_set` is called only from
   `tex.evidence.attribution_zk.verify_ptv_envelope`, which has **no live
   caller** — only tests invoke it (verified: grep for `verify_ptv_envelope`
   across `src/tex` returns only the definition and a docstring mention).

So the wired-live status is **MIXED**: the prover is reachable from a real route
and will emit HMAC "proof" bytes into a PTV envelope; the verifier that would
trust them is gated shut and only exercised by tests.

---

## File Inventory

| File | Lines | Role |
|------|------:|------|
| `__init__.py` | 454 | Package banner (DEACTIVATED), `__layer__=5/'evidence'`, re-exports every public symbol; auto-calls `register_deepprove_if_available()` at import (wrapped in bare `except`). |
| `layerwise_prover.py` | 1510 | **Core.** `LayerCircuit`, `LayerProof`, `LayerProofSet`, backend `Protocol` + registry, `_DeterministicShimBackend` (HMAC), `prove_layer(_set)`, `verify_layer_proof(_set)`, and the **deactivation gate**. |
| `nonlinearity_lookup.py` | 512 | Prefix-suffix lookup gadgets for softmax/GELU/LayerNorm; **real** numeric tables computed at import via `math.exp/erf/sqrt`; SHA-256 fingerprints. |
| `fisher_guided.py` | 338 | **Real, pure logic.** Top-k layer selection by Fisher score with deterministic tie-break + cost-weighted greedy knapsack. No crypto. |
| `veil_wrapper.py` | 304 | "VEIL ZK compiler" — actually an HMAC-keyed wrap/unwrap; frozen overhead constants from paper. |
| `poseidon_chain.py` | 305 | Poseidon-BN254 hash-chain root with SHA-256 fallback; **Poseidon lib absent on this host → SHA-256 always runs.** |
| `latticefold_plus.py` | 428 | "LatticeFold+ ℓ2 folding" — HMAC "Ajtai commitment" + byte-length ℓ2 estimate; structural accumulator. |
| `mira_parallel.py` | 398 | "Mira parallel tree folding" — HMAC pairwise fold tree; structural accumulator. |
| `logup_star.py` | 406 | "Logup* lookup argument" — HMAC multiplicity-commit + SHA-256 Fiat-Shamir; transcript model. |
| `gauge_zkp.py` | 402 | "GaugeZKP canonicalisation" — HMAC PoGE certificate + SHA-256 gate-reduction model; no real weight canonicaliser. |
| `sublinear_space.py` | 269 | **Plan/bookkeeping only.** Cook-Mertz streaming cost model (pure arithmetic); does not stream. No crypto. |
| `deepprove_backend.py` | 436 | Subprocess bridge to a `deep-prove` Rust CLI (not shipped). Real `subprocess`/`shutil.which` probe; raises `NanozkBackendUnavailable` if absent. |
| `v3db.py` | 460 | "Verifiable vector search" proofs — HMAC commitments over IVF-PQ five-step transcript. Not imported by `layerwise_prover`. |
| `DEACTIVATED.md` | (md) | Cross-check doc. States the package is not a working crypto system; matches code. |

Total Python: ~5,422 lines across 13 modules.

---

## Internal Architecture

### Core data flow (`layerwise_prover.py`)

```
default_block_circuit(i)            prove_layer(...)                 LayerProofSet
   └─ LayerCircuit (frozen)   ───►   ├─ _coerce_hash_input(i/o)        (hash-chained
        ├─ op_kinds                  ├─ get_layerwise_backend(id)       bundle)
        ├─ nonlinearity_gadgets◄──── │    └─ _DeterministicShimBackend
        │   (softmax/gelu/ln)        │         .prove() = HMAC tag
        ├─ fused_row_count           ├─ veil_wrap(inner) = HMAC wrap
        └─ fingerprint() = SHA-256   └─ LayerProof(proof_bytes, backend)
                                                       │
prove_layer_set ───────────────────────────────────────┘
   ├─ _set_root(proofs) → layer_set_root → SHA-256 (or Poseidon if avail)
   ├─ if latticefold_active(): fold_layer_proofs → HMAC accumulator
   └─ if mira_active(): mira_fold_tree → HMAC tree root
```

**`LayerCircuit`** (`:163-282`): frozen Pydantic v2, `extra="forbid"`. Captures
op order, lookup gadgets, fused/pre-fusion row counts (`_estimate_row_counts`
at `:321` returns hard-coded per-op midpoints — explicitly "not load-bearing",
`:330-332`), lookup-argument kind, and a GaugeZKP canonicalisation marker.
`fingerprint()` (`:278`) is `SHA-256(canonical_bytes())` — a real, stable
binding over the circuit description (not over any witness).

**`LayerProof`** (`:378-439`): frozen model binding circuit fingerprint, i/o
hashes (64-char hex), weights commitment, opaque `proof_bytes`, backend id,
`veil_wrapped` (default `True`, `:415-420`), `issued_at`.

**`_DeterministicShimBackend`** (`:702-745`): the only registered backend
(`_REGISTRY` at `:748-750`). `prove()` = `HMAC(shim_key, "NANOZK-SHIM-v1|" ‖
fingerprint ‖ in ‖ out ‖ weights)` (`:720-728`). `verify()` recomputes and
`hmac.compare_digest`. The shim key defaults to the literal
`b"tex-nanozk-shim-v1-default-key"` (`_shim_key`, `:695-699`) when
`TEX_NANOZK_SHIM_KEY` is unset — so the "proof" proves only that the verifier
knows the same static constant. The shim's own comment is candid:
"A real backend would produce a SNARK proof here; the shim proves only that the
caller knows the shim key" (`:714-719`).

**Backend dispatcher** (`:760-779`): `get_layerwise_backend(id,
allow_shim_fallback=True)`. When the "regulator-grade" `LAYERWISE_BACKEND_ID`
(`nanozk-layerwise-2026`) is requested but not in the registry, with fallback
allowed it **returns the shim** but stamps the proof with the shim's
`backend_id` so a verifier can see it is not regulator-grade (`:769-778`).
`prove_layer` defaults `backend_id=LAYERWISE_BACKEND_ID` (`:810`) → in practice
every proof is shim-backed unless DeepProve is installed.

**Set verification** (`verify_layer_proof_set`, `:1282-1487`): after the
deactivation gate (`:1304`), it (1) reproduces `set_root` honoring the stored
`chain_kind`, (2) optionally re-derives and checks LatticeFold+ and Mira
accumulators, (3) per-layer `verify_layer_proof`. All comparisons are HMAC/hash
equality. Fail-closed throughout (every error path returns `is_valid=False`).

### Supporting modules

**`nonlinearity_lookup.py`** — the most genuinely-real numeric code. At import,
`_compute_table` (`:285-360`) materialises full 65,536-entry uint16 tables from
`math.exp`/`math.erf`/`math.sqrt` references (`_ref_softmax`, `_ref_gelu`,
`_ref_layernorm_invsqrt`, `:190-224`) and derives prefix/suffix (256-entry)
decompositions. `table_fingerprint` = `SHA-256(prefix‖suffix)` (`:359`). This
is honest numerical approximation work; it just does not produce a proof — it
produces gadget descriptors whose fingerprints get hashed into the circuit.

**`fisher_guided.py`** — fully real, no crypto. `compute_fisher_budget`
(`:121`) returns minimal k for a target Fisher mass; `select_layers_to_prove`
(`:202`) does top-k by score (uniform-cost path, `:283-295`) or cost-weighted
fractional-knapsack greedy (`:296-320`), with deterministic index tie-breaks.
This is the one module a real backend could reuse verbatim.

**`veil_wrapper.py`** — `veil_wrap` (`:195`) computes
`blinding_commitment = HMAC(blinding_key, session_id)` and
`zk_tag = HMAC(blinding_commitment, "VEIL-v1|" ‖ session_id ‖ inner_proof)`
(`:245-256`); `veil_unwrap` recomputes the tag and returns `inner_proof`
(`:267-293`). It provides no zero-knowledge property — it is a keyed integrity
tag. Overhead constants (`1.03`/`1.22`/`1.12`, `:127-133`) are frozen paper
numbers, not measured.

**`poseidon_chain.py`** — `layer_set_root` (`:249-293`) dispatches Poseidon vs
SHA-256. `_get_poseidon` (`:129-150`) lazy-imports `from poseidon import
Poseidon, prime_254`; on `ImportError` returns `None`. **Verified at runtime:
`poseidon_available()` is `False` on this host**, so `_sha256_chain_root`
(`:230-246`) always runs and `chain_kind="sha256-legacy"`. `_poseidon_active`
(`:109-118`) gates on `TEX_NANOZK_POSEIDON_ROOT`/`TEX_FRONTIER_NANOZK`.

**`latticefold_plus.py`** — `fold_layer_proofs` (`:284-368`) iterates proofs,
updating an HMAC "Ajtai commitment" (`_ajtai_commit`, `:214-235`) and a
byte-length-derived ℓ2 norm bound (`_estimate_l2_norm` = `255*sqrt(len)`,
`:238-249`; `_l2_norm_check`, `:252-276`). `verify_folded_accumulator` rebuilds
and HMAC-compares. The "Module-SIS / Ajtai / ℓ2 budget" names describe an
intended lattice scheme; the math is HMAC + integer sqrt. `latticefold_active`
(`:405-414`) gates on `TEX_NANOZK_LATTICEFOLD`/`TEX_FRONTIER_NANOZK`.

**`mira_parallel.py`** — `mira_fold_tree` (`:232-344`) builds a left-to-right
binary fold tree of HMAC commitments (`_leaf_commitment`/`_fold_pair`/
`_challenge_for_pair`). Real tree-balance logic, HMAC "KZG commitments".
`mira_active` (`:375-386`) gated.

**`logup_star.py`** — `logup_star_argue`/`logup_star_verify` (`:264-358`):
counts per-table multiplicities (`_multiplicities`, real), HMAC-commits them,
derives a SHA-256 Fiat-Shamir challenge, HMAC sum-tag. `logup_star_verify`
recomputes and compares. The soundness property of a real Logup* sumcheck is
absent; the multiplicity counting is real.

**`gauge_zkp.py`** — `build_poge_certificate`/`verify_poge` (`:301-354`): HMAC
over `(original, canonical, kind)`. `compute_gate_reduction_factor` (`:254-293`)
is a closed-form multiplicative model capped at 0.55. `canonical_model_hash_for`
(`:357-373`) derives a fake canonical hash by domain-tagged SHA-256 of the
original — no actual weight canonicalisation (the docstring concedes this,
`:81-91`).

**`sublinear_space.py`** — pure planning arithmetic. `compute_streaming_plan`
(`:152-188`) and `estimate_memory_savings` (`:196-240`) compute block sizes and
memory estimates. Explicitly "doesn't actually stream — it pretends to,
recording the plan in metadata" (`:66-69`). No crypto, not consumed by the
prover; exposed for dashboards.

**`deepprove_backend.py`** — the one place a *real* external proof could enter.
`check_deepprove_availability` (`:140-204`) does real `shutil.which`
+ `subprocess.run([... "--version"])`. `DeepProveSubprocessBackend.prove/verify`
(`:238-380`) shell out to a `deep-prove` CLI via temp JSON files and parse
stdout. The binary is **not shipped** (docstring `:74-76`); absent → backend
not registered, dispatcher uses the shim. `register_deepprove_if_available`
(`:391-423`) is auto-invoked at `__init__.py:344-347` inside a bare `except`.

**`v3db.py`** — self-contained RAG-retrieval proof scaffold (HMAC commitments
over an IVF-PQ five-step transcript). Not imported by `layerwise_prover`; only
re-exported from `__init__`.

---

## Public API

Exported from `tex.nanozk` (`__init__.py:350-454`). Most-used externally:

- **Prover/verifier:** `prove_layer`, `prove_layer_set`, `verify_layer_proof`,
  `verify_layer_proof_set`, `default_block_circuit`, `get_layerwise_backend`,
  `register_backend`.
- **Models:** `LayerCircuit`, `LayerOpKind`, `LayerProof`, `LayerProofSet`,
  `LayerProofVerification`, `LayerProofSetVerification`, `NanozkBackend`
  (Protocol), `NanozkBackendUnavailable`.
- **Fisher selection:** `select_layers_to_prove`, `compute_fisher_budget`,
  `FisherSelectionResult`.
- **Gadgets / VEIL:** `softmax_lookup`, `gelu_lookup`, `layernorm_lookup`,
  `PrefixSuffixLookup`, `veil_wrap`, `veil_unwrap`, `VeilWrappedProof`.
- **Upgrade surfaces (1-8):** `logup_star_argue/verify`, `build_poge_certificate`
  /`verify_poge`, `poseidon_chain_root`/`layer_set_root`/`poseidon_available`,
  `fold_layer_proofs`/`verify_folded_accumulator`/`latticefold_active`,
  `compute_streaming_plan`/`estimate_memory_savings`, `mira_fold_tree`/
  `verify_mira_tree`, `check_deepprove_availability`/`register_deepprove_if_available`,
  `commit_snapshot`/`prove_query`/`verify_query_proof`.
- **Constants:** `LAYERWISE_BACKEND_ID="nanozk-layerwise-2026"`,
  `LAYERWISE_CIRCUIT_VERSION`, `NANOZK_VERIFIER_TARGET_MS=23.0`,
  `NANOZK_PROOF_SIZE_BYTES=6900`, plus many `PAPER_*` frozen benchmark numbers.

**Actually imported by other subsystems** (only 4 symbols cross the boundary):
`compute_fisher_budget`, `prove_layer_set`, `select_layers_to_prove`
(`api/incident_routes.py:414-418`), and `LayerProofSet`,
`verify_layer_proof_set` (`evidence/attribution_zk.py:420-423`).

---

## Wiring

### Wiring In — who imports nanozk

Grep across `src/tex` (excluding the package itself) for actual imports of
`tex.nanozk` symbols yields exactly **two** consumers; all other "nanozk"
matches (`vet/__init__.py:22`, etc.) are docstring/comment text, not imports.

1. **`tex.api.incident_routes`** (prove side) —
   `from tex.nanozk import compute_fisher_budget, prove_layer_set,
   select_layers_to_prove` at `incident_routes.py:414-418` (lazy, inside
   `_build_layerwise_envelope`).

2. **`tex.evidence.attribution_zk`** (verify side) —
   `from tex.nanozk import LayerProofSet, verify_layer_proof_set` at
   `attribution_zk.py:420-423` (lazy, inside `_verify_nanozk_layerwise`,
   deliberately local to keep nanozk downstream of evidence in the import DAG,
   `:414-418`).

### Live call path (prove side — LIVE)

```
tex.main.create_app  (main.py)
  └─ app.include_router(build_incident_router())          main.py:1442
       └─ POST /v1/incidents/{decision_id}/attribute      incident_routes.py:626
            └─ attribute_incident(...)                    incident_routes.py:632
                 └─ if body.include_zk_envelope:           incident_routes.py:669
                      _build_ptv_envelope(result, decision) incident_routes.py:670
                        └─ if os.environ["TEX_FRONTIER_NANOZK"]=="1":  :367
                             _build_layerwise_envelope(...)  :368 / def :381
                               └─ from tex.nanozk import prove_layer_set,
                                    select_layers_to_prove, compute_fisher_budget  :414
                               └─ prove_layer_set(...)        (emits HMAC proof set)
```

This path is genuinely reachable from the mounted FastAPI app. Gating: it is
inert unless the request sets `include_zk_envelope=True` **and** the process has
`TEX_FRONTIER_NANOZK=1` (flag parsed in `frontier_config.py:42`,
`TexFrontierFlags.nanozk`). When active it produces a `LayerProofSet` of
shim/HMAC "proofs" and base64-embeds it in the PTV envelope (the method tag
becomes `tex:nanozk-layerwise-2026`).

### Live call path (verify side — NOT wired)

`verify_layer_proof_set` is invoked only by
`attribution_zk._verify_nanozk_layerwise` (`:483`), which is invoked only by
`verify_ptv_envelope`. Grep confirms **no `src/tex` caller of
`verify_ptv_envelope`** outside its own definition — only `tests/` call it
(`tests/test_integration_layer.py`, `tests/nanozk/test_attribution_zk_wiring.py`).
So the running app *emits* nanozk envelopes but never *verifies* them in-process,
and the verifier is additionally gated shut by the deactivation guard.

**Net `wired_status`: MIXED** — prover LIVE (reachable from a route, flag-gated),
verifier DEMO_TEST_ONLY (no live caller + deactivation gate). The spine pass's
`nanozk=LIVE` is correct for the prove direction; the verify direction is
effectively dead in production.

### Wiring Out — dependencies

- **Intra-package:** `layerwise_prover` → `nonlinearity_lookup`, `veil_wrapper`,
  `latticefold_plus` (flag check + lazy `fold_layer_proofs`), `mira_parallel`
  (flag check + lazy fold), `poseidon_chain` (lazy in `_set_root`).
  `deepprove_backend` → `layerwise_prover` (`register_backend`,
  `NanozkBackendUnavailable`). `logup_star`, `gauge_zkp`, `sublinear_space`,
  `v3db` are leaf modules re-exported by `__init__` but **not** imported by the
  prover core.
- **Other Tex subsystems:** none imported *by* nanozk. nanozk is a pure leaf in
  the import DAG (it imports only `pydantic` and stdlib). The arrows point *into*
  it from `api.incident_routes` and `evidence.attribution_zk`.
- **External libraries:** `pydantic` v2 (models), stdlib `hashlib`, `hmac`,
  `secrets`, `struct`, `json`, `base64`, `subprocess`, `shutil`, `tempfile`,
  `math`, `time`. **Optional:** `poseidon` (poseidon-hash) — absent here, SHA-256
  fallback; external `deep-prove` Rust CLI — absent here, shim fallback.

---

## Implementation Reality

**Overall: STUB_HEAVY.** Every cryptographic claim resolves to an HMAC-SHA-256
or SHA-256 binding under a default static key. There is no SNARK, no sumcheck, no
lattice commitment, no Poseidon (lib absent), no real ZK. The unit is explicitly
self-labelled as such in every module banner and confirmed by reading the bodies.

Evidence of the stand-in nature (quoted):
- `_DeterministicShimBackend.prove` — `h = hmac.new(_shim_key(), b"NANOZK-SHIM-v1|", hashlib.sha256)` … "the shim proves only that the caller knows the shim key" (`layerwise_prover.py:713-728`).
- `_ajtai_commit` — "Real LatticeFold+ computes A * x mod q … The shim HMACs the … triple" (`latticefold_plus.py:220-235`).
- `_estimate_l2_norm` returns `int(255.0 * math.sqrt(len(witness)))` — a byte-count, not a vector norm (`latticefold_plus.py:238-249`).
- `_commit_multiplicities` — HMAC, "A real regulator-grade implementation uses Pedersen / Poseidon / KZG / Ajtai" (`logup_star.py:193-206`).
- `veil_wrap` — HMAC tag, provides integrity not zero-knowledge (`veil_wrapper.py:245-256`).
- `canonical_model_hash_for` — fake canonical hash via SHA-256 of the original (`gauge_zkp.py:357-373`).
- `sublinear_space` — "doesn't actually stream — it pretends to" (`:66-69`).

What is **real** (non-crypto, correct logic):
- Fisher layer selection (`fisher_guided.py`) — genuine top-k / knapsack.
- Nonlinearity lookup tables (`nonlinearity_lookup.py`) — genuine `math.exp/erf/sqrt` tabulation + decomposition.
- Cost/plan arithmetic (`sublinear_space.py`, `compute_gate_reduction_factor`).
- DeepProve subprocess plumbing (`deepprove_backend.py`) — real process probe/IO; would carry real proofs *if* the binary existed.
- All the Pydantic models, wire (`to_bytes`/`from_bytes`), and fail-closed control flow.

**No `NotImplementedError`/`TODO`/`FIXME`/`pass`-only stubs** exist in the
package (grep returns nothing). This matches the spine pass note
(`nanozk = 0 guards`). The "stub" here is not an interface guard that raises —
it is a *working* HMAC computation standing in for a proof. That is the more
dangerous shape (it returns plausible bytes), which is exactly why the
deactivation gate at `layerwise_prover.py:1304` exists and why it is the unit's
single most important line.

**Default execution path** (no flags): the prover is never invoked
(`include_zk_envelope` / `TEX_FRONTIER_NANOZK` both off); the verifier, if
called, returns `nanozk_deactivated_placeholder_not_a_real_proof`. With
`TEX_FRONTIER_NANOZK=1` only: prover emits shim/HMAC proofs into envelopes, but
the verifier stays deactivated (needs the separate `TEX_NANOZK_ALLOW_SHIM=1`,
test-only). Poseidon/LatticeFold/Mira/DeepProve are all additionally off by
default and the native deps are absent, so the SHA-256/HMAC fallbacks run.

---

## Technology

Cited (claim-level) algorithms the names reference — none implemented, all are
HMAC/SHA-256 placeholders modeled on the *shape* of:

- **NANOZK** layerwise transformer ZK (arXiv 2603.18046) — the namesake.
- **VEIL** hash-based ZK compiler (ePrint 2026/683).
- **Jolt Atlas** prefix-suffix lookup decomposition (arXiv 2602.17452).
- **Logup\*** lookup argument (ePrint 2025/946).
- **GaugeZKP** symmetry canonicalisation (OpenReview 1Ne3tfQC0T).
- **Poseidon-BN254** SNARK-friendly hash — *this one has a real (optional) lib
  path* via the `poseidon` package, currently uninstalled.
- **LatticeFold+/ℓ2** Module-SIS folding (ePrint 2026/721, 2025/247).
- **Mira / ZKTorch** parallel KZG folding (arXiv 2507.07031).
- **Sublinear-space proving** Cook-Mertz tree evaluation (arXiv 2509.05326).
- **DeepProve** GKR-sumcheck zkML (Lagrange Labs) — real subprocess bridge.
- **V3DB** verifiable IVF-PQ vector search (arXiv 2603.03065).

Real techniques actually present: Fisher-information top-k / fractional-knapsack
selection; 16-bit quantised lookup-table approximation with banker's rounding;
HMAC keyed commitments and SHA-256 Fiat-Shamir transcripts; frozen Pydantic v2
domain models with strict `extra="forbid"`; backend `Protocol` + registry
dispatch (algorithm-agility pattern); env-flag staged activation.

The `PAPER_*` constants throughout (e.g. `PAPER_PROVER_SPEEDUP_OVER_EZKL=158.0`,
`PAPER_BASE_GATE_REDUCTION=0.26`) are frozen literals copied from the cited
papers for dashboards — **not** measured properties of this code.

---

## Persistence

**None durable. Entirely in-memory / stateless.** No database, file, or cache
writes. Mutable module-level state is limited to:

- `_REGISTRY` backend dict (`layerwise_prover.py:748`) — populated at import with
  the shim; optionally gains DeepProve via `register_backend`.
- `_POSEIDON_INSTANCE` lazy singleton (`poseidon_chain.py:126`).
- `_REGISTERED` flag for idempotent DeepProve registration
  (`deepprove_backend.py:388`).

Proof bytes live only in the returned objects; the `LayerProofSet` is serialised
to bytes (`to_bytes`, `:531`) and base64-embedded into a `PTVEnvelope` by the
caller (`attribution_zk.build_envelope_with_layerwise_proof`). Durability of the
envelope (if any) is the evidence/SCITT layer's concern, not nanozk's. The
`deepprove_backend` writes transient temp files for subprocess IO and unlinks
them in `finally` blocks.

---

## Notable Findings

1. **Self-honest docstrings — verified, not trusted.** Unusually, the banner
   claims ("computes HMAC/SHA-256 stand-ins, not real proofs"; "hard-gated and
   fail-closed") are **accurate**. I confirmed the gate empirically (gate-off →
   `is_valid=False`/`nanozk_deactivated_placeholder_not_a_real_proof`; gate-on →
   `is_valid=True`). This contradicts the *aspirational* prose elsewhere in the
   same files (e.g. `__init__.py:30-40` "every emitted PTV envelope carries a
   layerwise_proof_set … the verifier flips … to a live verdict") — the verdict
   is "live" only in the sense that it runs; it is not cryptographically sound.

2. **Asymmetric wiring is the real risk surface.** The prover is reachable from a
   production route and *emits* `tex:nanozk-layerwise-2026` envelopes (with HMAC
   "proofs") whenever `TEX_FRONTIER_NANOZK=1` + `include_zk_envelope=True`. A
   downstream consumer that trusted the method tag without running the gated
   verifier could be misled. The deactivation gate protects the *in-tree*
   verifier, but it cannot protect an *external* party who treats the envelope's
   presence as proof. The honest method-tag suffix logic
   (`incident_routes.py:608-618`, `zk_layerwise`) partially mitigates by labelling.

3. **Overstated "post-quantum" / "regulator-grade" framing.** Module prose
   repeatedly claims PQ security (LatticeFold+, VEIL removing EC dependency) and
   "regulator-grade" backends. In code there is no lattice math, no PQ primitive,
   and the only "regulator-grade" backend id resolves to the shim via fallback
   (`layerwise_prover.py:769-778`). Label these claims **(claim, unverified)**.

4. **Poseidon path is dead on this host.** Despite `chain_kind` plumbing and a
   `poseidon-bn254` enum, `poseidon_available()` is `False` (lib not installed),
   so every set root is SHA-256 (`chain_kind="sha256-legacy"`), verified at
   runtime. The Poseidon branch is untested in this environment.

5. **Dead/inert in default config.** `logup_star`, `gauge_zkp`,
   `sublinear_space`, and `v3db` are exported but **not imported by the prover
   core** — they are reachable only if an external caller imports them directly
   (no such caller exists in `src/tex`). They are effectively orphan scaffolds
   within an already-deactivated package.

6. **Import-time side effect.** `__init__.py:344-347` runs
   `register_deepprove_if_available()` at import inside a bare
   `except Exception: pass`. On hosts with a `deep-prove` binary on PATH this
   silently registers a subprocess backend at import time. Benign here (binary
   absent) but worth noting as a non-obvious side effect of `import tex.nanozk`.

7. **`veil_wrapped` defaults to True** (`layerwise_prover.py:415-420`, and
   `from_bytes` default `:597`). So every shim proof is double-HMAC'd (inner shim
   tag, then VEIL wrap). Neither layer adds zero-knowledge; the wrap is pure
   keyed integrity. The struct packing/unpacking of the VEIL envelope
   (`prove_layer` `:882-894`, `_veil_unpack` `:911-941`) is real and correct.

8. **Spine-pass classification check.** Reported `nanozk=LIVE`. Refined: prover
   side is LIVE (route-reachable, flag-gated), verifier side is DEMO_TEST_ONLY
   (no live caller + deactivation gate). I record the unit as **MIXED**. The
   crypto-reality note ("real graceful-fallback impl, not hollow stub; 0
   NotImplementedError guards") is technically accurate about guard *count* but
   would be misleading if read as "real crypto" — the fallbacks fall back to
   HMAC stand-ins, not to a weaker-but-real crypto path.

# Subsystem Dossier: ZK Provenance & ZK PDP (`tex.zkprov`, `tex.zkpdp`)

> Scope: `/Users/matthewnardizzi/dev/tex/src/tex/zkprov/` and `/Users/matthewnardizzi/dev/tex/src/tex/zkpdp/`
> Branch: `feat/proof-carrying-gate`. All evidence is code-cited `file:line`. Claims taken
> from docstrings/`.md` are labelled **(claim, unverified)** unless confirmed in code or by
> running it. Verified by reading every `.py` in scope in full and tracing imports/call-sites.

---

## Overview

Two adjacent but **separately-wired** units:

* **`tex.zkprov`** — *Zero-Knowledge dataset/inference provenance*. Cryptographically binds an
  LLM response to a CA-signed training-data manifest (Merkle commitment + ML-DSA/Ed25519 signature)
  and emits a `ProvenanceProof` over a public `ProvenanceStatement`, dispatched through a pluggable
  ZK-backend registry. It is **LIVE**: the FastAPI app mounts `/v1/zkprov/*` routes that call the
  unit's prove/verify/commit/aggregate/narrow functions, persisting proofs to Postgres.
  (`src/tex/main.py:28`, `src/tex/main.py:1510`, `src/tex/api/zkprov_routes.py`)

* **`tex.zkpdp`** — *Zero-Knowledge policy-decision proof (the "arbiter")*. Proves the **arbitration
  relation** (fuse → threshold → FORBID-floor → monotone gate) maps committed scores+policy to the
  claimed verdict, encoded UNSAT-when-violated. It reuses `tex.zkprov`'s backend registry, including
  the real discrete-log `schnorr-fuse-zk-v1` backend that proves the fuse arithmetic over *private*
  scores. It is **DEMO_TEST_ONLY / INDIRECT**: its only in-`src` consumers are `tex.capstone.*`, and
  `tex.capstone` is **not** mounted in `create_app` and is not referenced in `main.py`
  (`grep -c capstone src/tex/main.py` → `0`). Reachable from tests and `scripts/capstone_demo.py`.

**Reality verdict.** The cryptographic spine is **REAL with graceful fallback**, not hollow:
* The Schnorr/Pedersen Σ-protocol (`schnorr_group.py` + `zk_fuse.py`) is a genuine, runnable,
  hiding/sound/offline ZK proof. Verified by running it: a 3-stream fuse produces a **230,458-byte**
  proof in **~2.8 s**, `verify_fuse` returns `True`, and tampering `fused_q` makes it return `False`.
* The Merkle commitment + algorithm-agile CA signature (`commitment.py`) runs end-to-end on
  SHA-256 fallback today (Poseidon and ezkl are **not installed** in this environment, verified).
* The SNARK backends (Halo2/ezkl, DeepProve, LatticeFold+, SP1, VEIL, JOLT) are **structurally
  complete dispatch slots that raise `BackendUnavailable`** until their out-of-tree binary/circuit
  ships — real "absent native lib" fallbacks, not stubs.
* The HMAC "deterministic shim" backend is honestly labelled a non-ZK stand-in and is hard-gated
  out of regulator-grade and (in zkpdp) default verification.

---

## File Inventory

### `tex.zkprov` (12 files, 5,128 LOC)

| File | LOC | Role |
|---|---|---|
| `__init__.py` | 224 | Package facade; re-exports 70 symbols; `__layer__=5` (evidence). Docstring is a frontier-citation manifesto. |
| `backends.py` | 806 | `ProofBackendId` enum + `ProofBackend` Protocol + 8 backend impls + dispatcher (`get_proof_backend`, `resolve_backend_with_fallback`). Defines the regulator-grade tier. |
| `commitment.py` | 708 | Poseidon/SHA-256 Merkle root + inclusion proofs; `DatasetCommitment` with algorithm-agile CA signature; HMAC commitment tag. |
| `proof.py` | 557 | `ProvenanceProof` + envelope JSON; `generate_proof` / `verify_proof` (6-check, fail-closed). |
| `manifest.py` | 458 | Pydantic v2 `DatasetManifest` (VFT + EU AI Act TDS Template); `project_to_tds_summary`. |
| `recursive.py` | 422 | `FoldingScheme` enum; `AggregatedCertificate`; `aggregate_proofs` (HMAC-shim folding) / `verify_aggregated_certificate`. |
| `schnorr_group.py` | 445 | **Real crypto.** Self-contained Pedersen + Fiat–Shamir + CDS-OR bit/range proofs over RFC 3526 MODP-14. Fixed-base comb. |
| `scitt_arp.py` | 382 | SCITT ARP narrowing (data-volume/license/temporal), COSE-label packaging, reconciliation output. |
| `receipts.py` | 350 | NABAOS-style HMAC "epistemic receipts" (pramāṇa taxonomy) + `detect_hallucinations`. |
| `sampler.py` | 270 | Verifiable index-hiding batch sampler (SHAKE128 PRF), public-replayable / private modes. |
| `integration.py` | 223 | `TEX_ZKPROV`-gated payload attach/verify hooks (fail-open attach, fail-closed verify). |
| `zk_fuse.py` | 283 | **Real crypto.** ZK proof of the PDP fuse kernel `clamp(round(Σ wᵢ·sᵢ/scale))` over private scores. |

### `tex.zkpdp` (2 files, 1,171 LOC)

| File | LOC | Role |
|---|---|---|
| `__init__.py` | 56 | Facade re-exporting 18 arbiter symbols. Honesty-boundary docstring. |
| `arbiter.py` | 1,115 | The whole unit: `ArbitrationStatement`, `evaluate_relation` (UNSAT-when-violated), `prove_arbitration`/`verify_arbitration`, `build_statement_from_decision`, `check_seal_binding`. |

---

## Internal Architecture

### `tex.zkprov`

**Data flow (issue → prove → verify):**

1. **Manifest** (`manifest.py:222` `DatasetManifest`) is a frozen Pydantic model carrying VFT
   elements (sources, preprocessing, per-source `max_epoch_participation`, training window) and EU AI
   Act Article 53(1)(d) TDS Template fields. `manifest_root_hash()` (`manifest.py:383`) is the
   SHA-256 of the canonical-JSON encoding (`manifest.py:339`). `project_to_tds_summary`
   (`manifest.py:430`) aggregates record counts per category for the public summary.

2. **Commitment** (`commitment.py`): `build_merkle_root` (`commitment.py:243`) returns
   `(poseidon_root_hex, sha256_audit_root_hex)` — a dual root: a BN254-field Poseidon root for
   in-circuit binding and a SHA-256 audit root for non-ZK consumers. Leaf/node hashing dispatches
   `_h2_leaf`/`_h2_node` (`commitment.py:226`,`:231`) to Poseidon (`commitment.py:190`,`:209`) when
   the `poseidon-hash` PyPI package is present, else to SHA-256-reduced-mod-BN254 fallback
   (`commitment.py:176`,`:182`). `merkle_hash_algorithm_in_use()` (`commitment.py:160`) reports which
   ran. `issue_commitment` (`commitment.py:464`) signs the canonical length-prefixed encoding
   (`commitment.py:427`) via `tex.pqcrypto.algorithm_agility.get_signature_provider`
   (`commitment.py:540-541`). `verify_commitment_signature` / `verify_commitment_valid`
   (`commitment.py:559`,`:578`). `MerkleInclusionProof.verify` (`commitment.py:308`) walks siblings to
   the root. `issue_commitment_tag`/`verify_commitment_tag` (`commitment.py:647`,`:675`) is the
   sub-millisecond HMAC hot-path tag.

3. **Statement + proof** (`proof.py`): `assemble_statement` (`proof.py:213`) hashes
   response/prompt/attributes and pins the commitment fields into a `ProvenanceStatement`
   (`backends.py:159`, an all-public dataclass with `canonical_bytes()`). `generate_proof`
   (`proof.py:260`) resolves the backend from `manifest.proof_backend` via
   `resolve_backend_with_fallback` (`proof.py:315`), calls `backend.prove`, and on `BackendUnavailable`
   falls back to the shim when `allow_shim_fallback` (`proof.py:332-339`). `verify_proof`
   (`proof.py:387`) runs six fail-closed checks (statement-consistent, statement-binds-commitment,
   CA-signature, lifetime, optional Merkle inclusion, backend verdict) and refuses non-regulator-grade
   backends when `regulator_grade=True` (`proof.py:522-536`).

4. **Backend registry** (`backends.py`): `ProofBackendId` (`backends.py:71`) enumerates 8 IDs.
   `_REGULATOR_GRADE` (`backends.py:131`) is the non-shim tier (7 IDs, excluding the shim).
   `get_proof_backend` (`backends.py:698`) maps IDs to instances; only `DeterministicShimBackend` and
   `SchnorrFuseZkBackend` actually run — `Halo2IpaBackend`, `DeepProveBackend`,
   `LatticeFoldPlusBackend`, `SP1HypercubeBackend`, `VeilHashBasedZkBackend` raise
   `BackendUnavailable` from `prove`/`verify` (`backends.py:465`,`:508`,`:547`,`:607`,`:678`), and
   `JOLT_SUMCHECK_2026` raises at dispatch (`backends.py:726`).

5. **Recursive aggregation** (`recursive.py`): `aggregate_proofs` (`recursive.py:268`) builds an
   `AggregationManifest` of leaf hashes and emits a **HMAC-shim** folding proof
   (`recursive.py:334`); `verify_aggregated_certificate` (`recursive.py:344`) recomputes the HMAC and
   does coverage + regulator-grade checks. No real folding scheme runs in Python (by design;
   `recursive.py:30-33`).

6. **Two-tier receipts** (`receipts.py`): `issue_receipt`/`verify_receipt` (`receipts.py:206`,`:247`)
   are HMAC-SHA256 over a canonical receipt; `detect_hallucinations` (`receipts.py:281`) cross-checks
   claim pramāṇa tags against recorded tool calls. Hot-path complement to the slow ZK proof.

7. **SCITT ARP** (`scitt_arp.py`): `narrow_manifest_*` (`scitt_arp.py:171`,`:202`,`:241`) project a
   manifest to a categorical bucket; `package_for_arp_exchange` (`scitt_arp.py:285`) builds a
   COSE-label dict; `consistent_with_commitment` (`scitt_arp.py:356`) checks a reconciliation output.

8. **Sampler** (`sampler.py`): `derive_batch_schedule` (`sampler.py:112`) is a deterministic SHAKE128
   PRF→mod-`record_count` index stream; `replay_public_sampler` (`sampler.py:234`) re-derives the
   public-mode schedule. (Self-flagged modular bias at `sampler.py:132-138`.)

**The real ZK core (`schnorr_group.py` + `zk_fuse.py`):**

* `schnorr_group.py` is a hand-rolled discrete-log Σ-protocol toolkit over the **RFC 3526 MODP
  Group 14** 2048-bit safe prime (`schnorr_group.py:65-80`), `G=4` (`schnorr_group.py:85`), second
  generator `H` derived nothing-up-my-sleeve by hash-and-square (`_derive_h`, `schnorr_group.py:92`).
  It implements Pedersen `commit` (`schnorr_group.py:187`), Fiat–Shamir `fs_challenge`
  (`schnorr_group.py:200`, 128-bit, binds full public context), Schnorr base-`h` PoK
  (`prove_dlog_h`/`verify_dlog_h`, `schnorr_group.py:239`,`:248`), a CDS-OR bit proof
  (`prove_bit`/`verify_bit`, `schnorr_group.py:284`,`:318`), and a bit-decomposition range proof
  (`prove_range`/`verify_range`, `schnorr_group.py:364`,`:405`). A `_FixedBase` windowed comb
  (`schnorr_group.py:118`) speeds modexp; correctness vs `pow` is asserted in tests
  (`schnorr_group.py:36-37`, **claim** — test file `tests/zkprov/test_schnorr_group.py` exists).
* `zk_fuse.py` composes those primitives into a proof that the public `fused_q` equals
  `clamp(round(Σ wᵢ·sᵢ / scale))` for **private** range-bounded scores: per-score range proofs,
  a verifier-recomputed homomorphic accumulator `C_acc = Π Cᵢ^{wᵢ}` (`zk_fuse.py:249`), and a tight
  rounding-window proof per case (`low`/`mid`/`high`, `zk_fuse.py:173-188`). `prove_fuse`
  (`zk_fuse.py:126`) refuses to attest a false statement (`zk_fuse.py:150-153`); `verify_fuse`
  (`zk_fuse.py:194`) never raises and never consumes scores (hiding).

### `tex.zkpdp` (`arbiter.py`)

* **Statement** `ArbitrationStatement` (`arbiter.py:250`): all-public, fixed-point integers at
  `SCALE=10_000` (`arbiter.py:139`), with `canonical_bytes()` (`arbiter.py:280`) and `sha256_hex()`.
* **Fixed-point helpers**: `quantize` (`arbiter.py:313`, round-half-up to match the fuse),
  `canonical_fuse` (`arbiter.py:321`, exact integer weighted sum), `threshold_verdict`
  (`arbiter.py:336`, FORBID-checked-first), `base_verdict` (`arbiter.py:347`, deny-floor → pin →
  threshold).
* **The relation** `evaluate_relation` (`arbiter.py:383`): pure/deterministic, evaluates constraints
  C1–C6 with no short-circuit and returns the full violation set. Encodes: exact fuse match (C1,
  `arbiter.py:420-431`), structural-floor-by-construction (C2, `arbiter.py:434-447`), verdict
  vocabulary (C3), strictly-lowering transition-legal chain bounded to length 2 (C4,
  `arbiter.py:456-481` against `LOWERING_TRANSITIONS` `arbiter.py:203`), claimed-verdict = chain end
  (C5), and explicit floor→FORBID (C6).
* **Prove/verify**: `prove_arbitration` (`arbiter.py:570`) refuses UNSAT statements and dispatches
  through the zkprov registry with `allow_shim_fallback=False`. `verify_arbitration`
  (`arbiter.py:604`) runs a 7-step ordered gate (parse → binding → backend-known → **shim hard-gate**
  → relation re-eval → backend verify → optional seal binding). The **shim hard-gate**
  (`arbiter.py:682`) rejects `DETERMINISTIC_SHIM_V1` with `zkpdp_shim_not_a_real_proof` unless
  `TEX_ZKPDP_ALLOW_SHIM=1` (`_shim_allowed`, `arbiter.py:508`). On the shim path the **deterministic
  relation re-eval is the load-bearing check** (`arbiter.py:696`).
* **Live-decision bridge**: `build_statement_from_decision` (`arbiter.py:862`) maps a finalized
  `Decision` + its `PolicySnapshot` to a satisfiable statement, reusing `DecisionRouter._effective_weights`
  (`arbiter.py:926`) so committed weights equal the live fuse's. Raises `ArbitrationUnprovable`
  (`arbiter.py:220`) when the float→fixed bridge collar (`BRIDGE_TOL_Q=6`, `arbiter.py:147`) is
  exceeded or the fixed-point base is stricter than the live verdict (`arbiter.py:968-973`) —
  fail-closed completeness boundary, never a soundness leak.
* **Seal binding**: `check_seal_binding` (`arbiter.py:1032`) consumes `tex.provenance.SealedFactLedger`,
  matches the sealed DECISION fact against the statement, and reports `chain_intact` (hash-chain
  replay) + `signatures_valid` (ECDSA, against a pinned key if supplied). Fail-closed and never raises
  (`arbiter.py:1111`).

---

## Public API

### `tex.zkprov` (70 exports, `__init__.py:145-224`)
Notable: `DatasetCommitment`, `MerkleInclusionProof`, `build_merkle_root`, `issue_commitment`,
`verify_commitment_signature/valid`, `merkle_hash_algorithm_in_use`, `issue_commitment_tag`;
`ProvenanceStatement`, `ProvenanceProof`, `assemble_statement`, `generate_proof`, `verify_proof`,
`ProofVerification`, `CIRCUIT_VERSION`; `ProofBackendId`, `ProofBackend`, all backend classes,
`get_proof_backend`, `resolve_backend_with_fallback`, `is_regulator_grade`, `BackendUnavailable`;
`DatasetManifest`, `DataSource`, `PreprocessingStep`, `LicenseTag`, `TDSSourceCategory`,
`TDSPublicSummary`, `project_to_tds_summary`; `SamplerCommitment`, `SamplerMode`,
`derive_batch_schedule`, `replay_public_sampler`; `AggregatedCertificate`, `FoldingScheme`,
`aggregate_proofs`, `verify_aggregated_certificate`, `is_post_quantum_folding`; ARP symbols;
`EpistemicReceipt`, `Pramana`, `issue_receipt`, `verify_receipt`, `detect_hallucinations`.
Note: `SchnorrFuseZkBackend` and `zk_fuse` are **not** re-exported at package top level; they live in
`tex.zkprov.backends` / `tex.zkprov.zk_fuse` (imported lazily by the backend, `backends.py:358`).

### `tex.zkpdp` (18 exports, `__init__.py:37-56`)
`ArbitrationStatement`, `ArbitrationEnvelope`, `ArbitrationVerification`, `RelationResult`,
`LoweringStep`, `SealBinding`, `ArbitrationUnprovable`, `SHIM_GATE_REASON`, `evaluate_relation`,
`canonical_fuse`, `quantize`, `base_verdict`, `threshold_verdict`, `expected_claimed_verdict`,
`build_statement_from_decision`, `prove_arbitration`, `verify_arbitration`, `check_seal_binding`.

---

## Wiring

### Wiring In — `tex.zkprov` = **LIVE**

* `src/tex/main.py:28` — `from tex.api.zkprov_routes import router as zkprov_router`
* `src/tex/main.py:1510` — `app.include_router(zkprov_router)` **inside `create_app` (def `main.py:1309`,
  `app = FastAPI(...)` at `main.py:1415`)** → the `/v1/zkprov/*` router is mounted in the running app.
* `src/tex/api/zkprov_routes.py:110` — `APIRouter(prefix="/v1/zkprov", dependencies=[Depends(RequireScope("evidence:read"))])`.
  Endpoints (all call the unit's public API):
  * `/issue-commitment` (`zkprov_routes.py:299`) → `issue_commitment`
  * `/prove` (`zkprov_routes.py:370`) → `generate_proof` (`zkprov_routes.py:378`), persists via `_store().save` (`zkprov_routes.py:398`)
  * `/verify` (`zkprov_routes.py:441`) → `verify_proof` (`zkprov_routes.py:451`)
  * `/aggregate` (`zkprov_routes.py:487`) → `aggregate_proofs`/`verify_aggregated_certificate`
  * `/narrow` (`zkprov_routes.py:540`) → `narrow_manifest_*`
  * `/proof/{sha}` (`zkprov_routes.py:601`), `/health` (`zkprov_routes.py:637`)
* Persistence consumer: `src/tex/stores/provenance_proofs_postgres.py:63` imports
  `ProvenanceProof`; `:110`,`:282` import `is_regulator_grade`. `PostgresProvenanceProofStore` is
  instantiated by the live route (`zkprov_routes.py:121`).
* Other `src` importers of `zkprov.commitment` symbols (NOT independently app-wired):
  `evidence/negative_knowledge.py:156` (only consumed by `capstone.*`),
  `capstone/verify.py:92`. The `pqcrypto/_backend_probe.py:151` imports `tex.zkprov` only to resolve
  the circuit-artifact path.

### Wiring In — `tex.zkpdp` = **DEMO_TEST_ONLY / INDIRECT**

* In-`src` consumers of `tex.zkpdp.arbiter`: **only** `capstone/compose.py:91`, `capstone/tamper.py:55`,
  `capstone/verify.py:86`. `compose_capstone` (`capstone/compose.py:293`) calls
  `build_statement_from_decision` → `prove_arbitration` → `verify_arbitration`
  (`capstone/compose.py:364-368`).
* **`tex.capstone` is not mounted or imported anywhere in `src/tex` outside its own package**
  (`grep tex.capstone src/tex` → 0 hits outside `capstone/`; `grep -c capstone src/tex/main.py` → `0`).
  Its only callers are tests (`tests/capstone/`, `tests/zkpdp/`, `tests/test_wave2_*`,
  `tests/test_decision_fact_contract.py`) and `scripts/capstone_demo.py`.
* Therefore zkpdp has **no live call path from `create_app`/`build_runtime` or any api route**. It is
  exercised only by tests/scripts. (This matches the spine pass: `zkpdp=INDIRECT`.)

### Live call path (zkprov)
`POST /v1/zkprov/prove`
→ `tex.api.zkprov_routes.prove_endpoint` (`zkprov_routes.py:370`)
→ `tex.zkprov.proof.generate_proof` (`zkprov_routes.py:378`)
→ `resolve_backend_with_fallback(manifest.proof_backend)` (`proof.py:315`)
→ `backend.prove(...)` (`proof.py:328`; shim or schnorr runs, SNARKs raise → shim fallback)
→ `PostgresProvenanceProofStore.save` (`zkprov_routes.py:398` → `provenance_proofs_postgres.py`).
Router mounted at `main.py:1510` in `create_app`.

### Wiring Out — internal deps
* `tex.zkprov` → `tex.pqcrypto.algorithm_agility` (`commitment.py:66`: `SignatureAlgorithm`,
  `SignatureKeyPair`, `get_signature_provider`); `cryptography` (Ed25519 test CA, `commitment.py:608`).
* `tex.zkpdp.arbiter` → `tex.domain.decision.Decision`, `tex.domain.policy.PolicySnapshot`,
  `tex.domain.verdict.Verdict` (`arbiter.py:118-120`); `tex.engine.router.DecisionRouter`
  (`arbiter.py:121`, reuses `_effective_weights`); `tex.provenance.ledger.SealedFactLedger` +
  `tex.provenance.models.SealedFactKind` (`arbiter.py:122-123`); `tex.zkprov.backends`
  (`arbiter.py:124-130`).
* `tex.zkprov.backends.SchnorrFuseZkBackend` → `tex.zkprov.zk_fuse` (lazy, `backends.py:358`,`:373`),
  which → `tex.zkprov.schnorr_group` (`zk_fuse.py:50`). Note: the schnorr backend reads
  `ArbitrationStatement` fields by **duck typing** and deliberately does **not** import `tex.zkpdp`
  (`backends.py:334`) — avoids a layering cycle.

### Wiring Out — external libraries
* **Pure stdlib**: `hashlib` (incl. `shake_128`/`shake_256`), `hmac`, `secrets`, `struct`, `json`,
  `base64`, `math` — the entire real-crypto path (`schnorr_group`, `zk_fuse`, SHA-256-fallback Merkle,
  receipts, sampler, shim).
* `cryptography` (Ed25519 deterministic test CA only).
* `pydantic` v2 (`manifest.py`).
* **Optional/absent natives** (verified NOT installed here): `poseidon` (`commitment.py:141`),
  `ezkl` (`backends.py:444`), DeepProve / LatticeFold+ / SP1 / VEIL binaries.

---

## Implementation Reality

| Component | Reality | Evidence |
|---|---|---|
| `schnorr_group` Pedersen/Σ-protocol | **REAL, runs** | Pure-stdlib group math; ran a full range/OR-proof chain via `zk_fuse`. |
| `zk_fuse` fuse-relation ZK proof | **REAL, runs** | Ran: `fused_q=4400`, proof **230,458 bytes**, prove **~2.8 s**, `verify=True`, tampered `fused_q` → `False`. Genuinely hiding/sound/offline. |
| `commitment` Merkle + CA signature | **REAL, runs (SHA-256 fallback)** | `merkle_hash_algorithm_in_use()` → `sha256-reduced-bn254` here; `poseidon` absent (`commitment.py:140-144`). Poseidon path is real but inactive without the PyPI pkg. CA signing real via algorithm_agility. |
| `DeterministicShimBackend` | **REAL but non-ZK by design** | HMAC-SHA256 over statement+witness (`backends.py:275-313`); honestly labelled, excluded from `_REGULATOR_GRADE` (`backends.py:131`). |
| `Halo2IpaBackend` | **Slot — `BackendUnavailable`** | `prove` lazy-imports ezkl then raises pending `tex/zkprov/circuits/zkprov_v1.onnx` (`backends.py:464-474`). ezkl absent here. |
| `DeepProveBackend`, `LatticeFoldPlusBackend`, `SP1HypercubeBackend`, `VeilHashBasedZkBackend` | **Slots — `BackendUnavailable`** | All `prove`/`verify` raise with remediation (`backends.py:507-518`,`:546-559`,`:606-620`,`:677-691`). |
| `JOLT_SUMCHECK_2026` | **Reserved — raises at dispatch** | `get_proof_backend` raises `BackendUnavailable` (`backends.py:722-731`); has no class. |
| `recursive.aggregate_proofs` | **Shim folding only** | Folding "proof" is an HMAC tag, not a real fold (`recursive.py:323-334`); docstring says so (`recursive.py:30-33`). |
| `receipts` | **REAL HMAC (not ZK)** | `issue_receipt`/`verify_receipt` HMAC-SHA256 (`receipts.py:235`,`:256`); honestly "Tool Receipts, **Not** Zero-Knowledge Proofs" (`receipts.py:6`). |
| `sampler` | **REAL deterministic PRF** | SHAKE128 stream → mod index (`sampler.py:149-166`); self-flags modular bias (`sampler.py:132-138`). |
| `scitt_arp` | **REAL projection logic; no live exchange** | Narrowing/packaging are real pure functions; the cross-sovereign exchange is out of scope (`scitt_arp.py:40-46`). |
| `zkpdp.evaluate_relation` | **REAL deterministic relation** | Full integer-exact constraint system (`arbiter.py:383-492`); load-bearing on the shim path. |
| `zkpdp` shim gate | **REAL hard-gate** | Verified default-deny: `_shim_allowed()` → `False`, gate reason `zkpdp_shim_not_a_real_proof` (`arbiter.py:682-694`). |
| `zkpdp` SNARK verify | **`BackendUnavailable` → invalid** | `verify_arbitration` returns `zkpdp_backend_unavailable_runtime_dependent` (`arbiter.py:713-725`). |

**No `NotImplementedError`, no `TODO`, no bare `pass`-only bodies in scope.** Every "unavailable"
path raises a structured `BackendUnavailable` with remediation, not a silent stub. (Consistent with the
spine note: zkprov/zkpdp `NotImplementedError` count = 0.)

---

## Technology / SOTA

* **Discrete-log Σ-protocols** (the live novelty): Pedersen commitments, Fiat–Shamir transform,
  Cramer–Damgård–Schoenmakers OR proofs, bit-decomposition range proofs, over RFC 3526 MODP Group 14
  (2048-bit, ~112-bit classical, **pre-quantum** — honestly flagged `schnorr_group.py:39-48`). Fixed-base
  windowed comb for modexp speedup.
* **ZK statement design** (the defensible piece, `zk_fuse.py:1-44`): proving the *verdict-fusion
  arithmetic* over private specialist scores while keeping threshold/floor/pin/chain public —
  distinct from generic private-attribute ABAC ZKP or generic verifiable computation.
* **Arithmetization-oriented hashing**: Poseidon-BN254 (t=3, α=5, RF=8, RP=57, 128-bit), with a
  SHA-256-reduced-mod-`r` fallback (`commitment.py:108-118`).
* **Post-quantum signing**: ML-DSA-65 (FIPS 204) default via algorithm-agility; composite
  ML-DSA+Ed25519 available **(claim, unverified — relies on `tex.pqcrypto`; the wired default in this
  env is the Ed25519 test CA)**.
* **Pluggable-backend / dispatcher pattern** mirroring `pqcrypto.algorithm_agility`
  (`backends.py:4`), with a wire-stable string enum and graceful degradation.
* **Two-tier verification**: fast HMAC receipts (NABAOS) + slow ZK proof.
* **Recursive folding taxonomy** (Nova/HyperNova/CycleFold/MicroNova/LatticeFold+/Mira) as reserved
  scheme IDs (`recursive.py:67-104`).
* **Regulatory surface**: EU AI Act Article 53(1)(d) TDS Template projection; SCITT ARP narrowing with
  COSE labels 0x801–0x804.
* **Fixed-point relation circuit shape** in zkpdp: integer math at `SCALE=10_000`, round-half-up tie
  break, UNSAT-when-violated encoding with a fail-closed quantization collar.

---

## Persistence

* **`tex.zkprov` — durable.** `ProvenanceProof` envelopes persist to Postgres via
  `PostgresProvenanceProofStore` (`stores/provenance_proofs_postgres.py`, table
  `tex_provenance_proofs`, `SCHEMA_SQL` near `:70`). The live `/prove` route persists when
  `persist_to_store` is set (`zkprov_routes.py:395-403`). The store also has an in-memory variant
  (`__slots__` `_by_envelope`/`_by_decision`, `provenance_proofs_postgres.py:~282`).
* **`tex.zkpdp` — no persistence of its own.** All statement/envelope dataclasses are in-memory and
  frozen; `check_seal_binding` *reads* the durable `SealedFactLedger` but writes nothing. zkpdp does not
  own a table.
* **Keys**: shim/receipt HMAC keys come from env (`TEX_ZKPROV_SHIM_KEY` `backends.py:240`,
  `TEX_ZKPROV_RECEIPT_HMAC_KEY` `receipts.py:150`) with insecure dev defaults. Schnorr `H` is derived
  deterministically at import (`schnorr_group.py:110`) — no stored SRS/setup.

---

## Notable Findings

1. **zkpdp is not app-wired (key correction to any "PDP proofs are live" claim).** The arbiter only
   reaches the system through `tex.capstone`, which is **not** mounted in `create_app` and not
   referenced in `main.py` (count = 0). It is test/script-only. Cite zkpdp as **DEMO_TEST_ONLY /
   INDIRECT**, not LIVE. (zkprov, by contrast, *is* LIVE via `/v1/zkprov`.)

2. **The "ZK" in this subsystem is real where it runs.** `schnorr_group`+`zk_fuse` is a genuine,
   executable, hiding-and-sound ZK argument (proof bytes, prove time, and tamper-rejection all
   verified empirically). This is the antidote to the earlier "nanozk" failure mode (a crypto-sounding
   name with no property) — and the module banners say so explicitly (`schnorr_group.py:6-12`).

3. **All "regulator-grade SNARK" backends are inert in any default deployment.** ezkl, DeepProve,
   LatticeFold+, SP1, VEIL, JOLT all raise `BackendUnavailable`. The *only* non-shim backend that runs
   is `schnorr-fuse-zk-v1`, and it proves **only the fuse arithmetic**, not the full verdict and not
   training-data provenance. So `/v1/zkprov/prove` in practice returns **shim-backed** proofs unless an
   out-of-tree circuit/binary is installed — `is_regulator_grade` on the result will be `False`. The
   code is honest about this; downstream marketing must not call `/v1/zkprov` output "regulator-grade"
   by default.

4. **`is_regulator_grade` is a *tier label*, not a certification — and the codebase says so loudly**
   (`backends.py:118-152`). `SCHNORR_FUSE_ZK_V1` is in `_REGULATOR_GRADE` yet is explicitly
   "research-early / unaudited / non-succinct / pre-quantum". Do not equate `regulator_grade=True` with
   "Article 53(1)(d) certified".

5. **Naming vs reality, self-documented.** `HALO2_IPA_2026` / `merkle_hash_alg` defaults carry
   historical labels: upstream ezkl is KZG-only (so "no trusted setup" is **withdrawn**,
   `backends.py:18-23`), and the wired Merkle default in this env is `sha256-reduced-bn254`, *not*
   Poseidon (Poseidon pkg absent). The route DTO default `merkle_hash_alg="poseidon2-bn254-t3"`
   (`zkprov_routes.py:186`) differs from the domain default `poseidon-bn254-t3` (`manifest.py:273`) —
   a cosmetic mismatch in declared tag, harmless because the actual hash is chosen at runtime by
   availability.

6. **Hiding is a deployment property, not automatic.** `ArbitrationStatement` is all-public and
   *publishes the raw scores* (`arbiter.py:251-279`); the ZK proof's hiding only matters if a deployment
   omits the scores from the published statement (`arbiter.py:71-74`, `:808-812`). On the default
   all-public path the deterministic relation re-eval is the load-bearing verdict check and the ZK proof
   is structural. This nuance is easy to overstate.

7. **Frontier-citation docstrings are extensive and forward-dated** (e.g. arxiv/eprint IDs, "Feb 2026",
   "Q-Day"). These are **(claims, unverified)** — out of scope to confirm — but the code does not depend
   on any of them; the running logic is plain Pedersen/HMAC/SHA-256/SHAKE math.

8. **No dead code found in scope.** Every backend class is reachable via `get_proof_backend`; every
   exported symbol is used by routes, capstone, the integration hook, tests, or the store. The
   "reserved" backends are intentional, structured, fail-loud slots — not orphaned code.

9. **`scripts/capstone_demo.py` and `tests/zkpdp/` are the only execution drivers for zkpdp.** Anyone
   wanting to see a live arbitration proof must run capstone, not the server.

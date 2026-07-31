# Subsystem Dossier: `evidence` (Layer 5)

> Code-verified against branch `feat/proof-carrying-gate`. Every claim is cited to
> `file:line` under `/Users/matthewnardizzi/dev/tex/src/tex/evidence/`. Docstring /
> roadmap claims that were NOT confirmed in code are labelled **(claim, unverified)**.

---

## Overview

The `evidence` package is Tex's **canonical tamper-evident audit spine**. It is the
"proof" leg of the Discover → Decide → Prove → Learn loop. Its core is a small,
strict, append-only **JSONL hash chain** (`recorder.py`) plus a **stateless
verifier** (`chain.py`) and an **exporter** that packages records into portable,
independently-verifiable bundles (`exporter.py`). Layered on top are optional, but
real, advanced surfaces:

- **Post-quantum seal** over each payload (`seal.py`): an embedded, self-verifying
  composite ML-DSA-65 + Ed25519 signature with an honest ECDSA-P256 fallback.
- **Durable Postgres mirrors** for evidence rows and C2PA manifests
  (`postgres_mirror.py`, `manifest_mirror.py`).
- **C2PA 2.x manifest emission** on PERMIT verdicts and **SCITT refusal events** on
  FORBID (`c2pa_emitter.py`).
- **SCITT-shaped COSE_Sign1 signed statements** for attribution
  (`scitt_statement.py`, `scitt_cose_alg.py`).
- **PTV / NanoZK attestation envelopes** and **NVIDIA TEE (NRAS EAT-JWT) binding**
  for high-assurance attribution (`attribution_zk.py`, `tee_binding.py`).
- A research-grade **negative-knowledge certificate** (verifiable non-membership +
  count-conservation predicate) over the sealed-fact ledger (`negative_knowledge.py`).

**Verdict on "the evidence layer is missing":** false. The layer exists, is
substantial (13 files, ~5,300 LOC of in-scope code plus its domain contract), and is
**wired LIVE** into the running app: `tex.main.build_runtime` constructs the recorder,
exporter, and chain signer; the live decision path writes to the recorder; and two
FastAPI routes (`GET /decisions/{id}/evidence-bundle`, `POST /decisions/{id}/seal`)
read/write through it. See **Wiring** for the exact call path with line numbers.

One thing the prompt context mentioned that is **NOT** here: there is **no
`EvidenceSufficiency` gate** in this package. "Sufficiency" lives in
`tex/learning/sufficiency.py`, a different subsystem. The `evidence` unit is the audit
chain, not a decision gate.

---

## File Inventory

| File | LOC | Role (one line) |
|---|---:|---|
| `__init__.py` | 11 | Architectural layer marker only: `__layer__ = 5`, `__layer_kind__ = 'evidence'`. No exports. |
| `recorder.py` | 846 | **Core.** `EvidenceRecorder`: append-only JSONL hash chain; `record_decision/outcome/human_resolution/contract_violation/attribution`; embeds PQ signature; best-effort mirrors. |
| `chain.py` | 482 | **Core.** Stateless verifier: `verify_evidence_chain`, `verify_evidence_chain_slice` (inclusion-proof-with-witness), `verify_latest_link`; issue dataclasses. |
| `exporter.py` | 389 | **Core.** `EvidenceExporter` + `EvidenceExportBundle`: build/export full, filtered, and slice bundles with chain verification. |
| `seal.py` | 298 | Post-quantum seal: `build_evidence_chain_signer`, `EvidenceChainSigner`, `verify_payload_signature`, `PQ_SIGNATURE_FIELD`; key persistence gated by selfgov. |
| `c2pa_emitter.py` | 343 | `C2paEmitter` façade + `C2paEmissionContext` + `ScittRefusalEvent` + `ManifestMirrorProtocol`; lazy-imports `tex.c2pa`; `_maybe_emit_c2pa`. |
| `postgres_mirror.py` | 308 | `PostgresEvidenceMirror`: durable, tenant-partitioned, append-only mirror of the hash chain; `apply_retention` (30-day floor). |
| `manifest_mirror.py` | 275 | `PostgresManifestMirror`: durable mirror of C2PA manifests keyed by parent evidence `record_id`. |
| `scitt_statement.py` | 373 | SCITT COSE_Sign1_Tagged signed-statement builder/verifier (`mint_signed_statement`, `verify_signed_statement`, `parse_envelope`). |
| `scitt_cose_alg.py` | 166 | Maps Tex `SignatureAlgorithm` → COSE `alg` integer (full PQ-inclusive map; provisional ML-DSA labels). |
| `attribution_zk.py` | 515 | PTV-shaped Groth16 / NanoZK-layerwise attestation envelope + verifier; explicit prover stub (`proof_pending`). |
| `tee_binding.py` | 474 | NVIDIA NRAS EAT-JWT (TEE) parsing, build, and `verify_nras_jwt` (real ES384/RS256 sig verify; test-mode `alg=none`). |
| `negative_knowledge.py` | 908 | Negative-knowledge certificate: Merkle adjacency non-membership proof + count-conservation predicate over the sealed-fact ledger. |

Supporting domain contract (out of scope dir, but load-bearing):
`/Users/matthewnardizzi/dev/tex/src/tex/domain/evidence.py` (869 LOC) — `EvidenceRecord`
(the frozen audit envelope), `TexEvidence` / `CombinedEvidence` e-value types, and the
e-value composition spine (`compose_spine`).

---

## Internal Architecture

### 1. The hash chain — `recorder.py` + `chain.py` + `domain/evidence.py`

**The atomic unit** is `domain.evidence.EvidenceRecord`
(`domain/evidence.py:25`): a Pydantic v2 model, `frozen`, `extra="forbid"`
(`domain/evidence.py:45`), carrying `evidence_id`, `decision_id`, `request_id`,
`record_type`, `payload_json`, `payload_sha256`, `previous_hash`, `record_hash`,
`policy_version`, `recorded_at`. Hash fields are validated to be 64-char lowercase hex
(`domain/evidence.py:96-126`).

**`EvidenceRecorder`** (`recorder.py:40`) is `__slots__`-based
(`recorder.py:56-64`) and guards all writes with an `RLock` (`recorder.py:76`). The
private append (`recorder.py:632-685`) is the single choke point and does, in order:

1. `_make_json_safe(payload)` — normalize UUIDs/datetimes/enums/pydantic to JSON-safe
   data (`recorder.py:797-834`).
2. `_sign_payload(payload)` — embed the PQ signature **before hashing** so the chain
   commits to the signature (`recorder.py:647`, `758-781`). No-op when no signer.
3. `_stable_json` (sorted-key, compact, `ensure_ascii=False`) → `payload_json`
   (`recorder.py:648`, `836-843`).
4. `payload_sha256 = sha256(payload_json)` (`recorder.py:649`, `845-847`).
5. `record_hash = sha256(stable_json({payload_sha256, previous_hash}))`
   (`recorder.py:651-654`, `783-795`). This is the chain link.
6. Construct the `EvidenceRecord`, append one line to the JSONL file
   (`recorder.py:667-669`), advance `_last_record_hash` (`recorder.py:671`).
7. Best-effort mirror write; failure is logged and swallowed, never blocks the chain
   (`recorder.py:675-683`).

On construction it rehydrates the chain head by reading the last non-empty line
(`recorder.py:687-709`), so the chain survives process restarts as long as the JSONL
file does.

**Five typed record producers**, all funneling into `_append`:
- `record_decision` (`recorder.py:104-240`) — the primary path. Serializes the full
  `Decision` (verdict, scores, findings, retrieval context, content hash, etc.). When
  `outbound_artifact` is passed it records `outbound_artifact.{byte_length,sha256}`
  (`recorder.py:168-175`) and conditionally emits a C2PA manifest (PERMIT only) via
  `_maybe_emit_c2pa` (`recorder.py:176-195`); on FORBID with a refusal event it inlines
  the SCITT refusal taxonomy (`recorder.py:200-208`). After append it stores the
  manifest in the manifest mirror keyed by `record_id` (`recorder.py:221-238`).
- `record_human_resolution` (`recorder.py:242-298`) — seals a held (ABSTAIN)
  decision's resolution by a **named human act** (`approved`/`held`/`refused`),
  validating the verdict and a non-empty `resolved_by` (`recorder.py:268-276`). This is
  the wire behind "sealed by a named human act the evidence layer can prove."
- `record_outcome` (`recorder.py:300-357`) — outcome rows; resolves `policy_version`
  from arg or `metadata['decision_policy_version']` (`recorder.py:711-732`).
- `record_contract_violation` (`recorder.py:359-457`) — first-class, individually
  verifiable behavioral-contract-violation receipts with a semantic
  `parent_evidence_hash` cross-reference (not a chain edge — `recorder.py:410-419`).
- `record_attribution` (`recorder.py:459-535`) — first-class causal-attribution rows
  carrying the SCITT COSE signed statement hex, optional PTV envelope, and optional TEE
  attestation.

Read surfaces: `read_all` (validates every line, `recorder.py:538-568`),
`last_record`, `read_contract_violations` (filtered query, `recorder.py:575-610`),
`decode_payload` (`recorder.py:612-630`).

**`chain.py`** is a pure, stateless verifier — `EvidenceRecord` itself defers
verification here (`domain/evidence.py:41-42`). It recomputes `payload_sha256` and
`record_hash` with **byte-identical** helpers to the recorder
(`chain.py:459-483` mirror `recorder.py:783-847`) and reports structured
`ChainVerificationIssue`s. Three entrypoints:
- `verify_evidence_chain` (`chain.py:38-77`) — full chain; first record must have
  `previous_hash is None` (`chain.py:331-341`).
- `verify_evidence_chain_slice` (`chain.py:80-196`) — verifies a **contiguous
  sub-range** using an inclusion-proof witness (`prior_link_witness`), the Certificate-
  Transparency / Rekor pattern. Handles five witness cases via `_verify_witness_link`
  (`chain.py:359-432`). This **fixes KNOWN_BUGS #5** (single-record non-genesis bundles
  previously reported `is_chain_valid: False`) — a real, code-visible bug fix, not a
  claim.
- `verify_latest_link` (`chain.py:199-226`) — verifies only the newest appended record.

### 2. Export — `exporter.py`

`EvidenceExporter` (`exporter.py:69`) wraps a recorder. `EvidenceExportBundle`
(`exporter.py:18-66`) is a frozen dataclass with a `to_dict()` JSON projection. Methods:
`build_bundle` (full, verified), `export_json`/`export_jsonl` (disk),
`export_filtered_json`/`filter_records` (payload-field filtering;
chain-verify off by default since a filtered subset is not contiguous —
`exporter.py:174,182-183`), and `build_slice_bundle` (`exporter.py:250-317`) which
computes the `prior_link_witness` from the predecessor in the global JSONL ordering and
calls `verify_evidence_chain_slice`. This is what the `evidence-bundle` route uses.

### 3. Post-quantum seal — `seal.py`

`build_evidence_chain_signer` (`seal.py:225-298`) loads a persisted key or generates
one, **preferring** `COMPOSITE_ML_DSA_65_ED25519` and **falling back** to `ECDSA_P256`
with a loud `WARNING` (`seal.py:288-294`). `EvidenceChainSigner.sign_payload`
(`seal.py:130-147`) returns a self-describing block: `algorithm`, `key_id`,
`signature_b64`, `public_key_b64`, `signed_digest_sha256`, `signed_at`. The signed
message is `sha256(stable_json(payload without the pq_signature field))`
(`_signing_digest`, `seal.py:100-109`) — sign-then-embed, non-circular.
`verify_payload_signature` (`seal.py:150-180`) is the **third-party verify path**:
hand it a sealed record and nothing else; it never raises and returns `False` on any
tamper/parse/sig failure. Key persistence is gated through
`tex.selfgov.governor.gate_controller_mutation` (`seal.py:203-222`), imported **lazily**
to keep the verify path free of the governance stack (`seal.py:66-76`, `203-207`).

### 4. C2PA / SCITT emission — `c2pa_emitter.py`

`C2paEmitter.emit_manifest` (`c2pa_emitter.py:196-308`) lazy-imports `tex.c2pa`
(`c2pa_emitter.py:214-220`), validates a complete `C2paEmissionContext`, builds an
email manifest, cosigns it, and returns a JSON-safe emission record with a
`retention_anchor` pointing back into the evidence chain (`c2pa_emitter.py:259-263`).
`_maybe_emit_c2pa` (`c2pa_emitter.py:311-343`) gates emission on PERMIT and a present
context, swallowing errors. `ScittRefusalEvent` (`c2pa_emitter.py:65-109`) validates
the `draft-kamimura-scitt-refusal-events-02` taxonomy at construction.

### 5. SCITT signed statements — `scitt_statement.py` + `scitt_cose_alg.py`

`mint_signed_statement` (`scitt_statement.py:173-256`) builds a real
`COSE_Sign1_Tagged` (tag 18) envelope with **attached** payload, routing the actual
signing through `tex.pqcrypto.algorithm_agility.get_signature_provider`
(`scitt_statement.py:219,231`) and the COSE alg label through `cose_alg_for`. Real RFC
9052 §4.4 `Sig_structure` construction (`scitt_statement.py:141-155`).
`verify_signed_statement` (`scitt_statement.py:315-349`) is fail-closed against alg
substitution (`scitt_statement.py:340-342`). `scitt_cose_alg.cose_alg_for`
(`scitt_cose_alg.py:110-130`) maps the full Tex enum, raising `NotImplementedError` for
unregistered algorithms (an interface guard, not a hollow stub).

### 6. Attribution attestation — `attribution_zk.py` + `tee_binding.py`

`attribution_zk.py` defines the `PTVEnvelope` pydantic model and three method tags:
`groth16-2026`, `proof_pending` (stub), and `tex:nanozk-layerwise-2026` (live).
`verify_ptv_envelope` (`attribution_zk.py:267-365`) **always** checks structural
hash bindings and dispatches by method. The NanoZK-layerwise path
(`_verify_nanozk_layerwise`, `attribution_zk.py:411-500`) is **real**: it lazy-imports
`tex.nanozk`, decodes a `LayerProofSet`, binds first/last layer hashes to the
envelope, and calls `verify_layer_proof_set`.

`tee_binding.py` parses NRAS EAT-JWTs (`_parse_jwt`, `tee_binding.py:161-176`) and
`verify_nras_jwt` (`tee_binding.py:287-413`) does a real 7-step verification — issuer,
nonce, overall-result, expiry, GPU measurement, and a **real cryptographic signature
check** for ES384/ES256/RS256 via `cryptography` (`_verify_jwt_signature`,
`tee_binding.py:416-464`). Fail-closed: `alg=none` is rejected unless
`TEX_TEE_ATTESTATION_MODE=test` (`tee_binding.py:324-334`).

### 7. Negative knowledge — `negative_knowledge.py`

A research-grade certificate over the in-memory sealed-fact ledger.
`build_epoch_accumulator` (`negative_knowledge.py:312-356`) recomputes each key from
`fact.canonical_payload()` (never trusts the stored field), sorts, rejects duplicates,
and Merkle-commits via `tex.zkprov.commitment.build_merkle_root`. Non-membership is
proved by **adjacency** (`_prove_non_membership`, `negative_knowledge.py:420-453`) —
inclusion proofs of the two neighbour leaves around an absent key — and verified
against the committed root (`_verify_non_membership`, `negative_knowledge.py:456-552`).
`check_count_conservation` (`negative_knowledge.py:592-705`) evaluates
`attempts == permits + abstains + forbids + errors`, deriving `n_attempts` from sealed
`ATTEMPT` facts when present (three-valued `UNGATED`/`GATED-HOLDS`/`GATED-BROKEN`).
`verify_certificate` (`negative_knowledge.py:834-908`) rejects over-claims (a
`complete`/`attempt_hook_present` claim with no derived attempt source, an empty epoch
not marked vacuous, forbidden vocabulary like "never saw"/"provable ignorance"). This
module is unusually honest about its own limits in-code (the whole module docstring is a
boundary statement, `negative_knowledge.py:1-143`).

---

## Public API

Symbols other subsystems actually import (verified by grep, see Wiring):

- From `recorder`: `EvidenceRecorder`, `EvidenceMirror` (Protocol).
- From `exporter`: `EvidenceExporter`, `EvidenceExportBundle`.
- From `chain`: `verify_evidence_chain`, `verify_evidence_chain_slice`,
  `verify_latest_link`, `ChainVerificationResult`, `ChainVerificationIssue`, and the
  private helpers `_build_record_hash`/`_sha256_hex`/`_stable_json` (imported by
  `adversarial/seal.py:39` and `bench/wave2_corpus/provenance.py:73` — a deliberate
  re-use of the canonical hashing).
- From `seal`: `build_evidence_chain_signer`, `EvidenceChainSigner`,
  `verify_payload_signature`, `PQ_SIGNATURE_FIELD`.
- From `c2pa_emitter`: `C2paEmitter`, `C2paEmissionContext`, `ManifestMirrorProtocol`,
  `ScittRefusalEvent`, `_maybe_emit_c2pa`.
- From `postgres_mirror`: `PostgresEvidenceMirror`, `SCHEMA_SQL`.
- From `manifest_mirror`: `PostgresManifestMirror`.
- From `scitt_statement`: `mint_signed_statement`, `verify_signed_statement`,
  `parse_envelope`, `decode_payload`, `SignedStatement`.
- From `scitt_cose_alg`: `cose_alg_for`, `cose_alg_label`, `is_provisional`.
- From `attribution_zk`: `PTVEnvelope`, `build_envelope_stub`,
  `build_envelope_with_layerwise_proof`, `canonical_input_hash`,
  `canonical_signals_hash`, `PTV_METHOD_*`.
- From `tee_binding`: `TEEAttestation`, `verify_nras_jwt`, `build_tee_attestation`,
  `build_test_mode_jwt`, `NRAS_PROD_ISSUER`.
- From `negative_knowledge`: `issue_certificate_with_records`, `verify_certificate`,
  `verify_epoch_commitment`, `NegativeKnowledgeCertificate`, `EpochCommitment`, etc.

---

## Wiring

### In (who imports this unit)

`grep -rn "from tex.evidence"` across `src/tex` (excluding the package itself) returns
importers in: `main.py`, `api/incident_routes.py`, `api/routes.py` (indirectly via
app.state), `commands/evaluate_action.py`, `commands/export_bundle.py`,
`memory/system.py`, `memory/evidence_store.py`, `vigil/causal.py`,
`voice/attestation.py`, `voice/entailment_cert.py`, plus `adversarial/*`, `bench/*`,
`capstone/*`. This is a heavily-depended-upon unit, not an orphan.

### Live call path (from the running app)

**App construction:** `tex.main.create_app` (`main.py:1309`) →
`build_runtime` (`main.py:519`). Inside `build_runtime`:

```
main.py:608  manifest_mirror = PostgresManifestMirror()
main.py:609  c2pa_emitter    = C2paEmitter()
main.py:611-615  legacy_evidence_mirror = PostgresEvidenceMirror()  (only if DATABASE_URL set)
main.py:624  evidence_chain_signer = build_evidence_chain_signer(key_dir=...)
main.py:628  recorder = EvidenceRecorder(normalized_evidence_path,
                 mirror=legacy_evidence_mirror, c2pa_emitter=c2pa_emitter,
                 manifest_mirror=manifest_mirror, chain_signer=evidence_chain_signer)
main.py:641  memory.recorder = recorder        # the MemorySystem writes through THIS recorder
main.py:643  exporter = EvidenceExporter(recorder)
```

The recorder and exporter are published on `app.state`
(`main.py:1653` `app.state.evidence_recorder = ...`, `main.py:1681`
`app.state.manifest_mirror = ...`) and stored on the runtime dataclass
(`main.py:967`, `1039`, `1193`, `1220`).

**Write path (decision recording):** the live decision pipeline records evidence via
the memory system: `tex/memory/system.py:169` and `:268`
`evidence = self.recorder.record_decision(...)`, and `:317`
`self.recorder.record_outcome(...)`. The command layer also calls
`recorder.record_decision(...)` directly at `commands/evaluate_action.py:742`.

**Write path (human seal):** `POST /decisions/{decision_id}/seal`
(`api/routes.py:247`) → `seal_human_resolution` →
`recorder.record_human_resolution(...)` (`api/routes.py:295`).

**Read path (audit bundle):** `GET /decisions/{decision_id}/evidence-bundle`
(`api/routes.py:181`) → `evidence_bundle_for_decision` →
`exporter.build_slice_bundle(...)` (`api/routes.py:214`) → `verify_evidence_chain_slice`.

**Attribution path (LIVE):** `api/incident_routes.py` (router wired at
`main.py:1442` `app.include_router(build_incident_router())`) imports the correct
`scitt_statement.mint_signed_statement` (`incident_routes.py:114`), the PTV envelope
builders (`incident_routes.py:104-112`), and TEE binding (`incident_routes.py:115`),
then writes via `recorder.record_attribution(...)` (`incident_routes.py:750`).

**Outcome auto-seal (LIVE):** `api/outcome_autoseal.py:225`
`recorder.record_outcome(...)`.

Given all of the above, **`wired_status = LIVE`** — confirmed independently of the
spine-pass classification (which also says `evidence=LIVE`).

### Out (dependencies)

Internal Tex subsystems this unit calls:
- `tex.domain.{decision,evidence,outcome}` — the record + decision contracts.
- `tex.pqcrypto.algorithm_agility` — the single crypto chokepoint (`seal.py:60`,
  `scitt_statement.py:90`).
- `tex.selfgov.governor` — gates key persistence (`seal.py:207`, lazy).
- `tex.c2pa` (incl. `tex.c2pa._cbor`) — manifest build/sign (`c2pa_emitter.py:214`,
  `scitt_statement.py:87`), lazy in the emitter.
- `tex.db.connection` — Postgres DSN/connection helpers
  (`postgres_mirror.py:49`, `manifest_mirror.py:47`).
- `tex.nanozk` — layerwise proof verification (`attribution_zk.py:420`, lazy).
- `tex.zkprov.commitment` — Merkle primitives (`negative_knowledge.py:156`).
- `tex.provenance.models` — `SealedFact*` (`negative_knowledge.py:155`).
- `tex.observability.telemetry.emit_event` (`scitt_statement.py:89`).

External libraries: `pydantic` v2, `psycopg` (+ `psycopg.types.json.Jsonb`),
`cryptography` (x509 / EC / RSA, used in `tee_binding.py` and transitively in `seal.py`
via algorithm_agility), and the stdlib (`hashlib`, `json`, `base64`, `struct`,
`bisect`, `threading`).

---

## Implementation Reality

**Real, running, default-on:**
- The JSONL hash chain, all five record producers, the slice/full/latest verifiers, and
  the exporter are fully real with no stubs. All 13 modules import cleanly
  (verified: `PYTHONPATH=src python -c "import tex.evidence..."` → "ALL EVIDENCE MODULES
  IMPORT OK").
- **PQ seal is REAL and, in this environment, the post-quantum path is ACTIVE by
  default.** A live check showed `get_signature_provider(COMPOSITE_ML_DSA_65_ED25519)`
  succeeds with backend `pyca-cryptography-native` (ML-DSA keygen emitted
  `public_key_bytes: 1952`). So `build_evidence_chain_signer` produces a genuine
  composite ML-DSA-65 + Ed25519 signature here, **not** the ECDSA fallback. The ECDSA
  fallback (`seal.py:258-295`) is the honest graceful degradation when no ML-DSA backend
  is present; the algorithm field is always labelled with what actually ran
  (`seal.py:139-141`, `283-294`). This is a real-impl-with-graceful-fallback, not a
  hollow stub.
- SCITT COSE_Sign1 minting/verification (`scitt_statement.py`) — real CBOR + RFC 9052
  signing through algorithm_agility.
- NanoZK-layerwise PTV verification (`attribution_zk.py:411-500`) — real, routes to
  `tex.nanozk.verify_layer_proof_set`.
- NRAS JWT signature verification (`tee_binding.py:416-464`) — real ECDSA/RSA via
  `cryptography`.
- Negative-knowledge Merkle adjacency proof + verifier — real and exercised. Live check:
  `merkle_hash_algorithm_in_use()` returns `sha256-reduced-bn254` (the Poseidon package
  is absent, so the documented SHA-256 fallback is what runs — `negative_knowledge.py`
  records this honestly via `hash_backend`).

**Honest stubs / pending paths (clearly labelled in-code, fail-closed):**
- `attribution_zk.build_envelope_stub` (`attribution_zk.py:210-229`) → `proof_pending`
  method; the verifier **rejects** it in production and accepts only in
  `TEX_PTV_VERIFY_MODE=test` (`attribution_zk.py:312-324`).
- The legacy `groth16-2026` PTV path dead-ends at
  `nanozk_verifier_not_implemented_in_this_thread` (`attribution_zk.py:341-344`) and at
  `nanozk_verifier_unavailable` unless `TEX_NANOZK_VERIFIER_AVAILABLE=1`
  (`attribution_zk.py:331-337`). This is a documented "prover plumbed, not wired" stub —
  but note the **newer** `tex:nanozk-layerwise-2026` path IS live, so the stub is the
  superseded route, not the only one.
- `tee_binding.build_test_mode_jwt` produces an `alg=none` JWT for integration tests
  only (`tee_binding.py:233-274`); the verifier rejects `alg=none` outside test mode.
- `NotImplementedError` in `scitt_cose_alg.cose_alg_for` (`scitt_cose_alg.py:125`) and
  `scitt_statement.mint_signed_statement` (`scitt_statement.py:209-210`) are **interface
  guards** for unregistered algorithms / empty claim sets — not hollow bodies.

**No `TODO`/`pass`-only/`raise NotImplementedError`-as-body found in the core path.**
The `RuntimeError("...no signature provider could be constructed")` at `seal.py:298` is
documented unreachable (ECDSA-P256 has no exotic backend).

---

## Technology / SOTA

- **Tamper-evident linear hash chain** with canonical (RFC-8785-adjacent sorted-key
  compact) JSON and SHA-256 linkage.
- **Inclusion-proof-with-witness** slice verification — the Certificate Transparency /
  Sigstore Rekor / MS-AGT MerkleAuditChain pattern (`chain.py:80-196`).
- **Composite post-quantum signature** ML-DSA-65 (FIPS 204) + Ed25519, with algorithm
  agility and embedded self-verifying signature blocks (`seal.py`).
- **C2PA 2.x** content-credential manifests with PQ cosign + retention anchor
  (`c2pa_emitter.py`).
- **SCITT** (`draft-ietf-scitt-architecture-22`) COSE_Sign1_Tagged signed statements +
  **refusal-events** taxonomy (`draft-kamimura-scitt-refusal-events-02`).
- **PTV attested-agent-identity** envelope (`draft-anandakrishnan-ptv-...`) + **NanoZK**
  layerwise ZK proofs (arxiv 2603.18046) + **VEIL** wrapping (eprint 2026/683).
- **NVIDIA NRAS** EAT-JWT **TEE attestation** (RATS / RFC 9334).
- **Negative-knowledge / non-membership** via sorted-key Merkle accumulator with
  adjacency proofs; **count-conservation** safety predicate.
- **E-value / e-process composition** spine in the domain contract
  (Vovk–Wang admissible-merge, Safe Testing product) — `domain/evidence.py:743-869`.

---

## Persistence

- **Source of truth: append-only JSONL file on disk.** Path is
  `normalized_evidence_path` passed to `EvidenceRecorder` (`recorder.py:75`,
  `main.py:628`), surfaced via `runtime.evidence_recorder.path` (`main.py:1557`).
  Chain head is rehydrated from disk on construction (`recorder.py:687-709`), so it is
  durable across restarts as long as the file persists.
- **PQ signing key:** persisted to `{key_dir}/evidence_seal_key.json`
  (`seal.py:183-184`, default `var/tex/keys`, overridable via
  `TEX_EVIDENCE_KEY_DIR` — `main.py:625`). Persistence gated by selfgov.
- **Durable mirrors (optional, Postgres):** `tex_evidence` table
  (`postgres_mirror.py:60-84`) and `tex_evidence_manifests` table
  (`manifest_mirror.py:58-94`), tenant-partitioned, append-only (INSERT ... ON CONFLICT
  DO NOTHING), with bootstrap `CREATE TABLE IF NOT EXISTS`. **Both no-op when
  `DATABASE_URL` is unset** (`postgres_mirror.py:122-131`, `manifest_mirror.py:109-120`)
  — JSONL continues alone. Retention deletion is the only mutation path and enforces a
  30-day floor (`postgres_mirror.py:260-298`).
- **Negative-knowledge:** purely in-memory; it summarizes the in-memory sealed-fact
  ledger and persists nothing itself (stated honestly at `negative_knowledge.py:70-77`).

---

## Notable Findings

1. **"Evidence layer is missing" is false.** The layer is present, ~5,300 LOC, imports
   clean, and is wired LIVE from `build_runtime` through the decision write path and two
   HTTP routes. Documented above with line numbers.

2. **Latent dead import in `vigil/causal.py` (real bug).**
   `vigil/causal.py:388` does `from tex.evidence.signed_statement import
   mint_signed_statement`, but **`tex/evidence/signed_statement.py` does not exist**
   (the module is `scitt_statement.py`; verified with `ls`). This import sits inside a
   `try: ... except Exception: return None` (`vigil/causal.py:386-413`), so the
   `ImportError` is **silently swallowed** and the vigil causal-attribution sealing path
   **always returns `None`** — it is dead at runtime. The LIVE API attribution path
   (`api/incident_routes.py:114`) uses the correct module, so production attribution is
   unaffected — but the vigil "strong path" is quietly inert. Worth a one-line fix
   (`signed_statement` → `scitt_statement`).

3. **PQ seal is genuinely post-quantum here, not the fallback.** Contrary to a prior
   audit note ("PQ stale key" — claim, unverified in this dir), the live composite
   ML-DSA-65 + Ed25519 provider is available in this environment via
   pyca-cryptography-native. The fallback-to-ECDSA logic is real but is the
   *degradation* path, not the default here. Production behavior depends on the deployed
   crypto backend, and the key being persisted to disk means a stale on-disk key would
   pin whatever algorithm first generated it (`seal.py:243-256`) — that is the real
   "stale key" caveat, and it is honestly logged.

4. **`parent_evidence_hash` is a semantic cross-reference, NOT a chain edge.**
   `record_contract_violation` / `record_attribution` / `record_outcome` embed it in the
   payload, but chain integrity is computed from `payload_sha256` + `previous_hash`
   alone (`recorder.py:410-419`, `chain.py:343`). This is deliberate and documented; an
   auditor must not assume the parent link is verified by the chain verifier.

5. **`except (NotImplementedError, RuntimeError, Exception)` is redundant** at
   `seal.py:179` — `Exception` already subsumes the first two. Harmless, but a code
   smell (over-broad catch on the verify path; intentional fail-closed-to-False).

6. **No `EvidenceSufficiency` gate in this package.** The prompt's "EvidenceSufficiency
   gate" is not part of the evidence unit; sufficiency logic lives in
   `tex/learning/sufficiency.py`. The evidence layer is the audit chain only.

7. **Honesty engineering is real, in-code (not just prose).** `negative_knowledge.py`
   bakes its own boundary into `FORBIDDEN_UNQUALIFIED_PHRASES`
   (`negative_knowledge.py:207-210`) and `verify_certificate` rejects over-claims; the
   `domain/evidence.py` `TexEvidence` model has `model_validator`s that refuse to label
   a calibration certificate or raw confidence bound as a true e-value
   (`domain/evidence.py:356-388`). This is the opposite of overstatement.

8. **Two durable mirrors, both idempotent and optional.** No data loss risk from the
   mirrors: a mirror failure is logged and the JSONL chain proceeds
   (`recorder.py:675-683`, `recorder.py:221-238`).

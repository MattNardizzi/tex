# Layer 5 — Evidence

> **Working doc.** The "prove it" layer.

## What this layer does

For every decision, produce durable, tamper-evident, externally verifiable evidence. This is the layer that lets a customer answer their auditor's question "show me proof that this AI action was governed properly" with cryptographic certainty rather than "trust us."

Second-largest layer (12 packages, 42,138 lines). Most of it is real, working, and wired. A few high-value integration glues are unwired.

## Packages in scope

| Package | Files | Lines | Status |
|---|---|---|---|
| `evidence/` | 11 | 4,072 | WIRED — the hash-chained canonical evidence chain |
| `memory/` | 10 | 3,059 | WIRED — V18 unified durable store |
| `c2pa/` | 17 | 6,123 | WIRED — Content Credentials emission |
| `vet/` | 11 | 5,380 | Mixed — most wired; `integration.py` and `sd_jwt_vc.py` TEST_ONLY |
| `zkprov/` | 10 | 4,269 | WIRED — ZK dataset/inference provenance |
| `tee/` | 6 | 2,700 | WIRED — Intel TDX + NVIDIA GPU attestation |
| `nanozk/` | 13 | 6,036 | WIRED — layerwise inference ZK proofs |
| `receipts/` | 5 | 707 | WIRED — HMAC tool receipts |
| `pqcrypto/` | 18 | 5,413 | Mixed — `algorithm_agility` wired; 6 extensions are TEST_AND_SCRIPT_ONLY |
| `events/` | 8 | 967 | WIRED (one stub orphan) — append-only event ledger |
| `compliance/` | 20 | 1,962 | TEST_ONLY — every regulatory emitter tested but never invoked at runtime |
| ~~`pitch/`~~ | (parked) | — | Moved to `_pending/pitch/` — old GTM (VP Marketing / CISO-at-AI-SDR / Insurer). New audience exports will be built when the enterprise-agent GTM has validated audiences. |

## Key files

### The canonical evidence chain
- `src/tex/evidence/recorder.py` — `EvidenceRecorder.record_decision()` is called from every PDP evaluation. Writes JSONL + Postgres + Memory mirror.
- `src/tex/evidence/chain.py` — hash linking
- `src/tex/evidence/bundle.py` — slice export for a specific decision
- `src/tex/evidence/verifier.py` — chain integrity verification
- `src/tex/api/evidence_routes.py` — `/v1/evidence/export`, `/v1/decisions/{id}/evidence-bundle`

### Unified durable store
- `src/tex/memory/system.py` — `MemorySystem` orchestrator. Holds `DurableDecisionStore`, `DurablePolicyStore`, evidence sink, replay.
- `src/tex/memory/decision_store.py` — durable decisions with Postgres write-through
- `src/tex/memory/policy_store.py` — durable policies with version history

### C2PA Content Credentials
- `src/tex/c2pa/manifest.py` — builds C2PA manifests (CBOR)
- `src/tex/c2pa/attestation.py` — outer signature
- `src/tex/c2pa/watermark.py` — perceptual watermark
- `src/tex/c2pa/verifier.py` — full verifier
- `src/tex/c2pa/ocsp.py` — OCSP stapling for cert chain
- `src/tex/c2pa/cpsa_shapes.py` — parsed CPSA formal model (binds to `cpsa_models/`)

### Verifiable Evidence Trail (VET)
- `src/tex/vet/web_proof.py` — Web Proof (notarized LLM transcript)
- `src/tex/vet/agent_identity_document.py` — AID (signed agent identity)
- `src/tex/vet/scitt.py` — SCITT transparent receipts (IETF)
- `src/tex/vet/transaction_token.py` — replayable transaction tokens
- `src/tex/vet/integration.py` — **TEST_ONLY** — the documented hook for attaching Web Proofs to `/v1/guardrail` evidence path

### ZK provenance
- `src/tex/zkprov/commitment.py`, `proof.py`, `verifier.py` — ZK provenance for training-data inclusion
- `src/tex/zkprov/integration.py` — integration hook (probably the same orphan pattern as vet/integration.py)

### TEE attestation
- `src/tex/tee/composite.py` — Intel TDX + NVIDIA H100/H200/B200/B300 composite token via Intel Trust Authority
- `src/tex/tee/sota_2026.py` — recent attestation patterns
- `src/tex/tee/attestation_client.py` — HTTP client for Intel Trust Authority

### Post-quantum crypto
- `src/tex/pqcrypto/algorithm_agility.py` — central dispatcher with lazy provider imports (WIRED — this is the entry point)
- `src/tex/pqcrypto/composite_ml_dsa.py` — composite ML-DSA per draft-ietf-lamps-pq-composite-sigs-18
- `src/tex/pqcrypto/{hqc, lms, ml_kem, code_signing, composite_cms, threshold_ml_dsa, evidence_quorum, evidence_chain_signer, talus_tee}.py` — extensions, mostly TEST_ONLY or TEST_AND_SCRIPT_ONLY

### Compliance emitters (TEST_ONLY)
- `src/tex/compliance/eu_ai_act/article_{17,26,50}.py`
- `src/tex/compliance/ftc/policy_statement.py`
- `src/tex/compliance/state/{california_sb942, colorado_ai_act, new_york_ai_disclosure}.py`
- `src/tex/compliance/_common.py` — shared base

### Pitch exports
~~Parked under `_pending/pitch/` — previous GTM audiences (VP Marketing / CISO-at-AI-SDR-SaaS / Cyber Insurance) are abandoned. Will be rebuilt when the enterprise-agent GTM has validated audiences.~~

## HTTP endpoints

- `GET /v1/evidence/{record_id}/c2pa` — CBOR manifest
- `POST /v1/c2pa/verify`
- `POST /v1/tee/verify` + `GET /v1/tee/status`
- `POST /v1/vet/{issue-aid|verify-aid|present-aid|verify-presentation|notarize|verify-web-proof|issue-txn-token|verify-txn-token}`
- `POST /v1/vet/scitt/{register-decision|verify-transparent|arp-reconcile}` + `GET /v1/vet/scitt/{receipt/{id}|ts-status}`
- `POST /v1/zkprov/{issue-commitment|prove|verify|aggregate|narrow}` + `GET /v1/zkprov/{proof/{hash}|health}`
- `POST /v1/exports/{vp-marketing|ciso|insurer}`
- `POST /v1/evidence/export`
- `GET /v1/decisions/{id}/evidence-bundle`
- `GET /v1/decisions/{id}/replay`

## Current state

✅ Solid:
- Hash-chained JSONL canonical evidence with Postgres mirror
- C2PA emission on every PERMIT-with-outbound-artifact
- TEE attestation composition (production-ready guards)
- V18 unified durable store
- 80+ regression tests across the package
- CPSA formal model of the cosign protocol (`cpsa_models/`)
- Algorithm agility for crypto providers

⚠ Built-but-not-wired:
- **`vet/integration.py`** (241 lines) — the documented Web Proof attachment hook. NOT CALLED. This is the highest-leverage single wiring fix in the codebase.
- **`zkprov/integration.py`** — parallel structure, same issue.
- **`compliance/` emitters** (~1,768 lines across 8 active emitters + `_common.py`) — every regulatory artifact tested but never invoked.
- **6 PQ extensions** (talus_tee, hqc, ml_kem, composite_cms, threshold_ml_dsa, evidence_quorum) — built, tested, demoed, not in the `algorithm_agility` dispatcher.

## Improvement vectors

### 1. Wire `vet/integration.py` (THE single highest-leverage change)
~15 lines in `commands/evaluate_action.py` after the semantic-layer call:
```python
if semantic_used_openai and verdict == "PERMIT":
    web_proof = await create_web_proof_for_call(...)
    attach_web_proof_to_payload(payload, web_proof)
```
Activates Web Proof attestation on every production-mode decision. Cornerstone of the "Tex proves it" pitch.

### 2. Wire compliance emitter registry (high impact)
~100 lines in `commands/evaluate_action.py` after `recorder.record_decision`:
```python
for emitter in compliance_emitter_registry.applicable_emitters(request):
    extra_record = emitter.emit(decision=decision, request=request)
    recorder.record_compliance(extra_record, parent_decision_id=decision.id)
```
Activates EU AI Act / FTC / California / Colorado / NY evidence emission on every decision matching the jurisdiction.

### 3. Streaming evidence emission (high impact for partners)
Today evidence is written then exported. Some partners want it streamed. Add a SCITT-compatible feed at `/v1/scitt/feed` that emits each new evidence record as it's produced.

### 4. PQ migration roadmap (medium impact, low immediate effort)
ECDSA-P256 is still the default for the events ledger. ML-DSA-65 via `algorithm_agility.py` is the staged replacement. Activating the migration:
- Phase 1: dual-sign every event (ECDSA + ML-DSA)
- Phase 2: verify both on read
- Phase 3: ML-DSA-only

### 5. Continuous chain verification (low impact, low effort)
Today chain integrity is verified on demand via `/v1/agents/governance/chain/verify`. Adding a periodic verifier that runs on the scheduler and emits an alert on tamper detection would give "tamper-detected" SLA guarantees.

### 6. Use the 6 unused PQ modules or remove them (cleanup)
`talus_tee`, `hqc`, `ml_kem`, `composite_cms`, `threshold_ml_dsa`, `evidence_quorum`. Each is real code (~2,185 lines combined) with tests. Either:
- Add to `algorithm_agility.get_signature_provider()` dispatch table with feature flags, OR
- Move to `_pending/` until customer demand materializes

### 7. Build new audience-specific exports for the enterprise-agent GTM (medium impact)
The old `pitch/` package is parked in `_pending/pitch/` (it was built around abandoned VP Marketing / CISO-at-AI-SDR / cyber-insurance audiences). When the new GTM (midsize-to-enterprise running agents) surfaces validated audiences — likely Head of AI, Compliance/DPO, Security/CISO — rebuild the dossier files on top of the parked technical machinery (the verifier, the compliance corpus, the intel helpers under `_pending/pitch/`).

## Constraints

- **Evidence is append-only.** No update, no delete. Period. Any change to a decision creates a new evidence record that supersedes (and chains to) the prior one.
- **Hash chain integrity is sacred.** Any code that writes to the chain MUST link to the prior record's hash. Test `test_evidence_bundle_slice.py` validates this.
- **Production secret guard.** Boot fails in production-like environments if `TEX_EVIDENCE_SUMMARY_SECRET` is missing or the dev sentinel.
- **TEE attestation guard.** Boot fails in production if `TEX_TEE_ATTESTATION_MODE=test`.
- **C2PA schema URIs are permanent identifiers.** Even though they currently use `texaegis.com`, do NOT rewrite them — they're persistent identifiers in signed manifests. (Other product-facing URIs were updated to `tex.systems`.)
- **All PQ providers must implement the same `SignatureProvider` protocol.** Don't bypass the protocol for a faster path.

## Testing

```bash
pytest tests/test_evidence_bundle_slice.py tests/c2pa/ tests/vet/ tests/zkprov/ tests/pqcrypto/ tests/test_thread5_integration.py tests/test_thread6_integration.py tests/test_c2pa_emission_wired.py tests/test_twin_endpoint_wired.py tests/frontier_thread_12_tee/
```

## Cross-layer touch points

- **Reads from Layer 4** — every decision produces evidence
- **Reads from Layer 2** — agent identity attaches to evidence
- **Feeds Layer 6** — outcome reports tagged to evidence_id close the learning loop
- **Feeds Layer 3** — chain-verification failures fire alerts

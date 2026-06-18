# Trace: evidence-proof-e2e

**Claim under test:** Tex emits an offline-verifiable evidence/receipt bundle that a third party can verify without trusting Tex.

**Verdict: CONFIRMED** (with one honest scope caveat — see "Boundaries & caveats").

Branch: `feat/proof-carrying-gate` @ `50fbab0`. All paths absolute under `/Users/matthewnardizzi/dev/tex`. Run with `PYTHONPATH=/Users/matthewnardizzi/dev/tex/src`.

---

## What "offline-verifiable without trusting Tex" actually requires

Two distinct properties, and the line between them (stated verbatim in `src/tex/bench/evidence_bundle.py` module docstring):

- **Integrity** — self-verifying from the record alone: recompute the SHA-256 hash chain; any reorder/delete/edit surfaces. Needs no key, no trust.
- **Authorship** — NOT self-verifying. Each record embeds the public key that signed it, so a forger can re-sign with their own key. Authorship is proven only by **pinning Tex's public key out-of-band** and rejecting any record signed by a different key.

The "no Tex trust" claim is genuine iff (a) the verification is reproducible with standard primitives (stdlib + `cryptography`), and (b) the key/format is standard so a third party needs no Tex code to parse it. I proved both independently below.

---

## The live call path (decision -> sealed record)

1. `tex.main.build_runtime` builds the signer and wires it into the recorder:
   - `src/tex/main.py:629` `evidence_chain_signer = build_evidence_chain_signer(key_dir=...)`
   - `src/tex/main.py:633-639` `recorder = EvidenceRecorder(..., chain_signer=evidence_chain_signer)`  ← **live records ARE signed** (the default direct-construction recorder is unsigned, but the runtime always injects a signer).
   - `src/tex/main.py:648` `exporter = EvidenceExporter(recorder)`
   - `src/tex/main.py:972/1198-1199` runtime carries `evidence_recorder` + `evidence_exporter`.
   - `src/tex/main.py:1658-1659` `app.state.evidence_recorder / evidence_exporter = runtime.*` ← reachable from the running app.

2. `EvidenceRecorder.record_decision` -> `_append` (`src/tex/evidence/recorder.py:104-240, 632-685`):
   - builds the payload, then `_sign_payload` embeds a `pq_signature` block **before** hashing (`recorder.py:647, 758-781`), so the hash chain commits to the signature and the signature is taken over the payload minus its own block (non-circular).
   - `payload_sha256 = SHA256(stable_json(payload))`; `record_hash = SHA256(stable_json({payload_sha256, previous_hash}))` (`recorder.py:648-654, 783-795`).

3. The seal itself (`src/tex/evidence/seal.py`):
   - `EvidenceChainSigner.sign_payload` (`seal.py:130-147`) -> `_signing_digest` = SHA-256 over canonical JSON minus `pq_signature` (`seal.py:100-109`). Block carries `algorithm`, `key_id`, `signature_b64`, `public_key_b64`, `signed_digest_sha256`.
   - `build_evidence_chain_signer` (`seal.py:225-298`): prefers composite ML-DSA-65+Ed25519, falls back to ECDSA-P256 with a loud log and **honest algorithm label** (never mislabels). Confirmed at runtime: composite when the ML-DSA backend is present, `ecdsa-p256` otherwise.
   - Crypto is dispatched through `tex.pqcrypto.algorithm_agility.get_signature_provider` (`algorithm_agility.py:129-219`). ECDSA path -> `tex.events._ecdsa_provider.EcdsaP256Provider` (`_ecdsa_provider.py:44-102`): **real** `cryptography` SECP256R1 / SHA-256, PEM SubjectPublicKeyInfo public keys (`_ecdsa_provider.py:69,80,93-96`). ML-DSA path -> `pyca-cryptography-native` ML-DSA-65 (observed: pubkey 1952 B, sig 3309 B = genuine FIPS 204 sizes). Not stubs.

## Decision -> EvidenceExporter -> bundle

- `EvidenceExporter` (`src/tex/evidence/exporter.py`): `build_bundle` / `export_jsonl` / `build_slice_bundle`. `build_slice_bundle` (`exporter.py:250-317`) emits a `prior_link_witness` (CT-style inclusion proof) so a single-record slice verifies against the parent chain.
- **Important:** the bundle's `verification` field is computed by Tex's own `verify_evidence_chain[_slice]` at export time (`exporter.py:319-332`, `chain.py:38-196`). This is a **self-attestation a non-trusting verifier must IGNORE.** The signature blocks ride inside each record's `payload_json`, so they travel with the bundle; the pin does NOT (correct — pin is out-of-band). Confirmed by inspecting `to_dict()`: top-level keys `[export_name, is_chain_valid, prior_link_witness, record_count, records, verification]`, and `payload_json` carries `pq_signature: True`.
- Live API: `GET /decisions/{decision_id}/evidence-bundle` (`src/tex/api/routes.py:180-225`) reads `app.state.evidence_exporter` and returns `build_slice_bundle(...).to_dict()`. App-reachable.

## The external verify scripts (`/Users/matthewnardizzi/dev/tex/scripts`)

All three import `tex.*` (they run Tex's verifier for convenience), but the verification is **standard crypto over standard formats**, so a third party can reproduce it without Tex (proven below).

1. `verify_it_yourself.py` — wrapper that runs `replay_trial_demo.py` (default), or `--anchor` / `--capstone` / `--forge-target`. Only bootstraps `sys.path`.
   - `replay_trial_demo.py` -> `tex.bench.replay_trial.run_replay_trial` -> `tex.bench.evidence_bundle.verify_bundle` (`evidence_bundle.py:228-330`): recompute hash chain (`verify_evidence_chain`), verify each embedded signature self-consistently (`verify_payload_signature`, `seal.py:150-180`), and compare embedded key to the **pinned** key. Court-grade `valid` = integrity AND `authorship_ok is True`.
   - **RAN:** `PASSED`, exit 0. 10 FORBID decisions sealed; `VALID (integrity + authorship)`; algorithm `ecdsa-p256`; byte-flip caught (`payload_sha256_mismatch`); **re-sign forgery caught** (`authorship_ok=False`). The re-sign test (`forge_record_by_resigning`, `evidence_bundle.py`) is the load-bearing one: it forges a PERMIT, re-signs with a foreign key, passes integrity, and is rejected ONLY by the pin.

2. `verify_conduit_receipt.py` — `--selftest` or `<receipt.json> [--pin] [--tsa-cert]`.
   - `ConduitReceipt.verify` (`src/tex/discovery/conduit/seal.py:149-221`): (1) recompute leaf = SHA-256(canonical payload); (2) Merkle inclusion (`gix.verify_inclusion`, RFC 9162); (3) Ed25519 signed-note vs **pinned** log key (`gix.Ed25519NoteVerifier`, real `cryptography` Ed25519 verify at `gix.py:430-434`); (4) optional RFC-3161 anchor vs **pinned** TSA cert (`external_anchor.verify_anchor_receipt`, which **actually verifies the TSA CMS signature** — `external_anchor.py:412,500,717,721`, contrasted in-code with `c2pa/timestamp.py` which does not).
   - **RAN:** `ALL CLAIMS HELD`, exit 0. Genuine VALID against pinned key, TSA-verified external age; one-byte tamper -> `INVALID: payload_hash_mismatch`.

3. `verify_enforcement_receipt.py` — `--selftest` runs a REAL `StandingGovernance` through `build_proof_carrying_gate`.
   - Forbid path: unknown agent hits structural floor -> `TexForbiddenError`, wrapped callable does NOT run, ENFORCEMENT fact `outcome=blocked` sealed. Permit path: sealed/running/in-surface agent -> action runs, `outcome=executed` sealed, with a verified Ed25519 agent credential (`identity/agent_credential.verify_agent_credential`).
   - Offline verify: `SealedFactLedger.verify_chain` + `verify_signatures` (`provenance/ledger.py:314-365`, real provider verify); `export_sealed_fact_bundle` + `verify_sealed_fact_bundle` (`provenance/bundle.py:256-374`) with external RFC-3161 anchor checked vs pinned TSA cert.
   - **RAN:** `ALL CLAIMS HELD`, exit 0. Real ML-DSA-65 (`pyca-cryptography-native`) ledger signatures; chain intact; externally anchored; one-field tamper -> `chain intact=False (break_at=0)`.

---

## Decisive adversarial test: independent verification with NO `tex` imports

I used Tex ONLY to PRODUCE a bundle, then verified it with a script that `assert "tex" not in sys.modules` and imports only `json/hashlib/base64` + the standard `cryptography` library.

- **Integrity (pure stdlib):** recomputed the full hash chain (`payload_sha256`, `record_hash`, `previous_hash` links) for all 10 records -> `True`, byte-identical.
- **Authorship binding (pure stdlib):** every embedded `public_key_b64` == the out-of-band pin; every claimed `signed_digest_sha256` == independently recomputed digest -> `True`.
- **Signature math (cryptography only):** for an ECDSA-P256 bundle, the pin decodes to a standard `-----BEGIN PUBLIC KEY-----` PEM (SubjectPublicKeyInfo). `serialization.load_pem_public_key(...).verify(sig, digest, ec.ECDSA(SHA256))` **VERIFIED** the genuine signature (1/1), and a forged `verdict=PERMIT` payload was **REJECTED with `InvalidSignature`** — i.e. Tex's signature provably does not cover the forgery, checked entirely outside Tex.

This is the strongest form of the claim: a relying party reproduces integrity + pinned authorship using only public standards (SHA-256, ECDSA-P256/SHA-256, PEM SPKI, Ed25519, RFC 9162 Merkle, RFC 3161 CMS), with no Tex code on the path.

---

## Boundaries & caveats (honest scope)

- **The bundle's own `verification`/`is_chain_valid` field is Tex-computed at export and must NOT be trusted by a skeptic.** It is harmless because the external/independent verifier re-derives everything from the records alone and ignores it. The claim survives precisely because trust is not placed in that field.
- **Authorship requires the out-of-band pin.** Without it, only integrity is provable (the verifiers say so explicitly: `authorship: UNVERIFIED`). The pin is correctly NOT shipped inside the bundle. In production the pin comes from "Tex's published transparency record" — that publication step is operational, not in-code (the in-repo demos read it from the signer object, labeled as the legitimate out-of-band stand-in).
- **Post-quantum vs classical is host-dependent but honestly labeled.** On a host without the ML-DSA backend the seal is ECDSA-P256 and the `algorithm` field says so; with the backend (this host, after the ledger keygen) it is composite ML-DSA-65+Ed25519 / ML-DSA-65. No mislabeling observed.
- **External time anchoring uses a LOCAL throwaway TSA in the selftests** — it exercises the real RFC-3161 CMS verification logic but proves nothing about real wall-clock time; the real-TSA path is `scripts/anchor_checkpoint.py` (freetsa). The verification *code* is real; the *selftest time* is not authoritative. Scripts state this plainly.
- **eBPF PEP datapath is not executed off Linux** (Darwin here) — orthogonal to the evidence claim; the replay trial labels it honestly and reports the portable verdict->released fact instead.

None of these break the claim; they bound it. The evidence/receipt bundle is genuinely offline-verifiable, with integrity needing nothing and authorship needing only a standard out-of-band public-key pin.

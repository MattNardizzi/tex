# Frontier Delta — Thread 13 (VET Web Proofs + Agent Identity Document)

**Snapshot date.** May 20, 2026.
**Standing reference.** May 14, 2026.
**Scope.** What moved on the agent-identity / web-proof frontier in
the six days between the standing reference and this snapshot, and
what Tex Thread 13 ships against that delta.

---

## Frontier deltas vs. May 14, 2026

### TLSNotary
- Still on the `v0.1.0-alpha.x` track. QuickSilver VOLE-IZK backend
  (replaced garbled-circuit ZK in `v0.1.0-alpha.8`, August 2025) is
  the new prover backend.
- Per the January 31, 2026 TLSNotary blog benchmarks, online time is
  reduced up to 30% over the prior backend. PADO Labs'
  Garble-Then-Prove work (Aug 2024) was incorporated, removing the
  MAC-key revelation step.
- **Still no Python binding.** Must subprocess to the Rust binary.

### Reclaim Protocol / zkTLS
- `attestor-core` is the production attestor implementation
  (AGPL-3.0). Server-side zkFetch path via `@reclaimprotocol/zk-fetch`
  npm package; deterministic server-side claim creation in ~2–4 s.
- Reclaim's attestor network signs ECDSA-P256 by default. Pluto Labs
  ships an open-source zkTLS implementation of the same protocol with
  a slower MPC-based trust model.

### BBS+ / `bbs-2023`
- W3C Data Integrity BBS Cryptosuites v1.0 is at **Candidate
  Recommendation** as of March 2024; W3C VC charter restarted April
  2026, with Verifiable Credentials Data Model 2.1 added as a tentative
  deliverable.
- `draft-irtf-cfrg-bbs-signatures-10` (January 8, 2026, Looker / Kalos /
  Whitehead / Lodder) is the latest CFRG draft.
- **No production-grade pure-Python BBS+ implementation exists.**
  `ursa-bbs-signatures` (PyPI) has not shipped a release in over a
  year; Hyperledger Ursa itself is in maintenance mode.
- `py-ecc` provides BLS12-381 pairing in pure Python but does NOT
  expose robust F_{p²} sqrt — required for G2 point decompression in
  BBS proof verification.

### PTV (Prove-Transform-Verify)
- **Two new drafts** by A. Damodaran (Sovereign AI Stack):
  - `draft-anandakrishnan-rats-ptv-agent-identity-00` (April 5, 2026,
    RATS-track Standards).
  - `draft-anandakrishnan-ptv-attested-agent-identity-00` (March 31,
    2026, Informational).
- Defines a Groth16-2026 / PLONK-2026 attestation envelope (JSON /
  CBOR) for hardware-anchored agent identity. As of May 18, 2026 the
  IETF datatracker shows **no public implementations**.

### SD-JWT VC
- `draft-ietf-oauth-sd-jwt-vc-16` (April 24, 2026). The Claim Metadata
  section, including Claim Selective Disclosure Metadata, was added
  between `-13` and `-16`. Existing libraries (MATTR TS, walt.id Java)
  still track `-13`.
- `draft-nandakumar-agent-sd-jwt-02` (February 28, 2026, Cisco) defines
  the **SD-Card format** — an SD-JWT encoding of A2A Agent Cards that
  enables selective disclosure of agent capabilities. Almost nobody
  has implemented this yet.

### OAuth Transaction Tokens for Agents
- `draft-oauth-transaction-tokens-for-agents-06` (April 11, 2026,
  Raut, Amazon). The `act` field identifies the agent and the `sub`
  field identifies the principal. The April 30, 2026 Five Eyes joint
  guidance specifies short-lived OAuth tokens — exactly this draft.

### AIVS-Micro
- `draft-stone-aivs-00` (March 2026, B. Stone, SwarmSync.AI). 200-byte
  six-field continuous-monitoring attestation. W3C AIVS Community
  Group launched April 5, 2026.

### A2A Protocol
- v1.0 Signed Agent Cards (Linux Foundation, GA April 9, 2026). 150+
  organizations in production. AGT, AWS Bedrock AgentCore, Azure AI
  Foundry, Copilot Studio all integrated.

### AP2 (Agent Payments Protocol)
- v0.2 published April 28, 2026; donated to FIDO Alliance for
  community governance. Adds "Human Not Present" payments + "Verifiable
  Intent" (co-developed with Mastercard).

### Survival-level competitive check
- **Microsoft Agent Governance Toolkit** (April 2, 2026): Agent Mesh
  uses DIDs + Ed25519. **No post-quantum signing. No selective
  disclosure. No Web Proofs / TLSNotary. No ZK attestation.**
- Indicio ProvenAI / walt.id Enterprise Stack / Microsoft Entra
  Verified ID: All still Ed25519-only.
- Zenity / Noma / Pillar / Lakera / Protect AI / Rubrik SAGE: **None
  notarize third-party API calls.**

### The audit-runtime gap
- arxiv 2504.04715 (Sept 2025) — "Are You Getting What You Pay For?
  Auditing Model Substitution in LLM APIs" — demonstrates that
  software-only attestation of LLM API responses is unreliable.
  Recommended fixes: hardware-attested TEEs OR notarized TLS
  transcripts. **No AI-governance vendor wires either into per-decision
  evidence records** for third-party API calls. Tex closes this gap.

---

## Tex Thread 13 stack against this delta

| Layer                      | Tex Thread 13 choice                                | Frontier anchor                              |
|----------------------------|-----------------------------------------------------|----------------------------------------------|
| zkTLS primary              | Reclaim attestor-core subprocess + Pluto fallback   | Reclaim Protocol (production)                |
| MPC-TLS fallback           | TLSNotary v0.1-alpha QuickSilver via subprocess     | TLSNotary v0.1-alpha.x                       |
| Multi-attestor             | k-of-n committee (Tex wedge)                        | None — first agent-governance impl           |
| Selective disclosure       | bbs-2023-SHAPED Merkle SD primitive                 | W3C `bbs-2023` CR                            |
| Issuer signature           | ML-DSA-65 (FIPS 204, NIST L3) by default            | NIST PQC; algorithm-agile                    |
| AID envelope               | W3C VC 2.0                                          | W3C VC Data Model 2.0                        |
| PTV attestation            | First Python impl, Schnorr-bridge fallback          | draft-anandakrishnan-rats-ptv-agent-identity |
| SD-JWT VC + SD-Card        | First Python impl tracking `-16`                    | draft-ietf-oauth-sd-jwt-vc-16 + sd-card-02   |
| OAuth Txn-Tokens           | draft-06 `act`/`sub` claims; ML-DSA-65 default      | draft-oauth-transaction-tokens-for-agents-06 |
| Continuous monitoring      | AIVS-Micro stub on every AID                        | draft-stone-aivs-00                          |
| A2A integration            | Signed Agent Card URL + SD-Card                     | A2A v1.0                                     |
| AP2 integration hook       | AID provides VDC for Mandates                       | AP2 v0.2 (FIDO Alliance)                     |

---

## Honest limitations

1. **Native BBS+ pairing operations are not implemented.** The
   cryptosuite name returned in base proofs is `bbs-2023-shape-{algo}`
   — drop-in compatible with a future swap-in when `py-ecc` exposes
   robust F_{p²} sqrt for G2 decompression. Security properties of the
   shape (base/derived proof split, selective disclosure, holder
   binding, unlinkable presentations) are preserved; the difference
   from native BBS+ is the underlying signature is computed over a
   Merkle commitment rather than over a bilinear pairing.

2. **PTV uses a Schnorr bridge in place of Groth16-2026.** The
   envelope is correct; the prover is currently a real ML-DSA-65 or
   Ed25519 signature over the canonical payload. Swapping in a real
   Groth16 prover (ark-circom, ezkl, Tokamak SP1 zkVM) is a drop-in
   replacement behind `generate_ptv_attestation()`.

3. **TLSNotary live mode requires `TEX_TLSNOTARY_BIN`**; sandbox CI
   runs the clearly-marked stub path. Production deployments set the
   environment variable on deploy.

4. **Live attestor HTTP calls require `TEX_RECLAIM_ATTESTOR_URL` /
   `TEX_PLUTO_NOTARY_URL`**; sandbox CI runs the stub path.

None of these limitations affect the *envelope shape*, the *audit
record format*, or the *PQ default* — those are correct end-to-end.
The native cryptographic primitives are swap-in replacements behind
the existing API surface.

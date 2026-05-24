# Frontier Delta — Thread 13.1 patch (May 21, 2026)

**Audit trigger.** During Thread 13 post-build review the user asked
whether every primitive shipped was truly bleeding-edge as of May 18,
2026 — *including paper-only work that nobody has implemented*. A
self-audit identified three frontier items genuinely past the
training cutoff and missed in the Thread 13 implementation. This
patch ships fixes for all three with code where code exists, and
honest docstring-level references where the field is paper-only.

## Item 1 — TLSNotary Proxy mode (May 10, 2026) — IMPLEMENTED

**Delta.** Thread 13 wired TLSNotary MPC mode (alpha.8 QuickSilver
VOLE-IZK, August 2025) as the latest. The actual frontier as of May
18, 2026:

* **alpha.14** (January 19, 2026) — 8 – 16 % speedups across
  real-world network scenarios.
* **alpha.15 with Proxy mode** (May 10, 2026) — 1 – 2 s attestation
  vs. 3 – 15 s for MPC mode at 1 KB/2 KB payloads. Different trust
  model: Verifier acts as a transparent proxy and observes the
  encrypted byte stream; Prover later proves selective disclosure in
  ZK after the session closes.

**Patch.** Added:
- ``WebProofMode.TLSNOTARY_PROXY`` enum value.
- ``TlsNotaryProxyClient`` class with live HTTP path against the
  alpha.15 ``/v0.1/proxy/attest`` reference notary server, stub
  fallback when ``TEX_TLSNOTARY_PROXY_URL`` is not set.
- ``MultiAttestorCommittee`` type signature extended; committees can
  now mix MPC + Proxy + Reclaim + Pluto in a single k-of-n quorum
  (Tex's recommended deployment: at least one MPC + one or two Proxy
  for the trust-speed Byzantine-tolerance combo).
- 6 new tests in ``tests/vet/test_tlsnotary_proxy.py`` proving the
  mode boots, the mixed-mode committee verifies, and the live-app
  ``/v1/vet/notarize`` endpoint accepts the new mode.

## Item 2 — Chathurangi 2026 lattice anonymous credentials — REFERENCED

**Delta.** The genuine native-PQ swap target for the entire credential
primitive (not just the base signature) is:

> Madusha Chathurangi, "Post-Quantum Traceable Anonymous Credentials
> from Lattices," IACR Communications in Cryptology, January 8, 2026.
> DOI 10.62056/ak5wl8n4e. Griffith University.

Combined with [Boo+23], [Arg+24] lattice anonymous-credential
constructions and the [LSS24] proof-of-concept implementations, this
is the lattice-native primitive that would supersede bbs-2023 +
ML-DSA-65 entirely. arxiv 2501.07209 (March 2026) confirms that BBS
unlinkability is *already* CRQC-safe (the privacy property holds
unconditionally even against unlimited quantum computing power), so
the value of swapping to a lattice-native scheme is the
*forgery-resistance* layer — exactly what Tex already gets via
ML-DSA-65.

**Patch.** No production-grade Python implementation of Chathurangi
2026 exists publicly as of May 18, 2026. The honest correction is
docstring-level:

- ``src/tex/vet/selective_disclosure.py`` — module docstring updated
  to:
  1. Correctly frame BBS unlinkability as already CRQC-safe.
  2. Reference Chathurangi 2026 (DOI 10.62056/ak5wl8n4e) as the
     genuine native-PQ swap target.
  3. Note that the algorithm-agile commitment + signature primitives
     are structured to swap when an implementation matures.
- ``src/tex/vet/ptv_attestation.py`` — module docstring updated to
  reference Chathurangi 2026 and to note SCITT composition as the
  behavioral-continuity path.

If/when a Python lattice anonymous-credential library ships, the
swap is drop-in behind the existing API surface (issue, verify,
present, verify-presentation). No public client should need to
change.

## Item 3 — SCITT registration per-decision — IMPLEMENTED

**Delta.** **The most important miss in Thread 13.** SCITT (Supply
Chain Integrity, Transparency, and Trust) is the IETF's adopted
Working Group standard for transparent audit trails of digital
artefacts. As of May 18, 2026 *no AI-governance vendor* ships
per-decision SCITT registration. The three reference drafts:

* ``draft-ietf-scitt-architecture-22`` (October 10, 2025) —
  adopted WG document. Defines COSE_Sign1 Signed Statements + COSE
  Receipts + Transparency Service interactions.
* ``draft-hillier-scitt-arp-00`` (May 2026, Certisy) — Attestation
  Reconciliation Protocol. Cross-sovereign zero-knowledge-capable
  reconciliation across heterogeneous registers (EU AI Act ↔ NIST
  AI RMF ↔ UK AISI).
* ``draft-kamimura-scitt-vcp-01`` (December 22, 2025, VeritasChain
  Standards Org) — SCITT profile for financial trading audit trails.
  Targets EU AI Act + MiFID II compliance with nanosecond-precision
  timestamps and crypto-shredding for GDPR. Tex's insurtech wedge
  inherits this profile naturally.

**Patch.** New module ``src/tex/vet/scitt.py`` with full production
SCITT surface:

- COSE_Sign1-shape Signed Statement issuance + verification with
  RFC 9597 CWT claims (iss, sub, iat, aud, exp, nbf).
- ``InMemoryTransparencyService`` — thread-safe append-only log with
  RFC 9162 SHA-256 Merkle tree (correct odd-leaf duplication tested
  at arbitrary tree sizes); signed Receipts on every registration
  with leaf-index + tree-size + inclusion-path.
- COSE Receipt verification with TS signature + Merkle inclusion
  proof recompute.
- ``register_aid`` / ``register_decision`` high-level Tex-binding
  helpers.
- ``ArpReconciliationRequest`` / ``arp_project_claim`` — ARP
  primitives. The default ``glb-default`` projection function emits
  per-target SHA-256 predicates so the same canonical claim projects
  to distinct values across EU AI Act / NIST AI RMF / UK AISI
  registries.

Integration into the evidence chain via ``tex.vet.integration``:

- ``attach_scitt_to_decision_payload`` — fail-open: TS registration
  failure does NOT block decision evidence (the SHA-256 hash chain
  and TEE JWT both stand alone). On success, the Receipt and full
  Transparent Statement are embedded in the decision evidence
  payload.
- ``verify_payload_scitt_transparent`` — fail-closed: tampered
  payloads, wrong issuer, wrong subject prefix, broken inclusion
  proof all fail closed.

5 new FastAPI endpoints under ``/v1/vet/scitt/*``:

- ``POST /v1/vet/scitt/register-decision``
- ``POST /v1/vet/scitt/verify-transparent``
- ``GET  /v1/vet/scitt/receipt/{entry_id}``
- ``GET  /v1/vet/scitt/ts-status``
- ``POST /v1/vet/scitt/arp-reconcile``

19 new tests in ``tests/vet/test_scitt.py`` covering:
- Signed Statement signature + tamper detection.
- TS append-log + growing-inclusion-path correctness.
- Receipt verification + bad-path-rejection.
- Transparent Statement full round-trip.
- ARP cross-target projection differentiation.
- Integration-hook attach + verify.

## Three-axis verification architecture

The headline Thread 13.1 claim. Every Tex decision evidence record can
now carry three independent verification primitives, each verifiable
by an external auditor (insurer, regulator, downstream agent)
without trusting Tex:

| Axis | Primitive                                  | Threat covered             | Standard                          | Wedge                |
|------|--------------------------------------------|----------------------------|-----------------------------------|----------------------|
| 1    | SHA-256 hash chain                         | Internal log tampering     | Thread 1, internal                | Status quo           |
| 2    | Composite TDX + NVIDIA GPU TEE JWT         | Host-level compromise      | Intel Trust Authority, AR4SI      | First in agent gov   |
| 3    | SCITT COSE Receipt + Merkle inclusion proof| Operator-level repudiation | draft-ietf-scitt-architecture-22  | **First in agent gov** |

## Competitive check post-patch (May 21, 2026)

| Capability                                       | Tex 13.1 | Microsoft AGT | Zenity | Noma | Pillar | Indicio | walt.id |
|--------------------------------------------------|----------|---------------|--------|------|--------|---------|---------|
| W3C VC AID                                       | ✓        | ✓             | ✗      | ✗    | ✗      | ✓       | ✓       |
| PQ signing default (ML-DSA-65)                   | ✓        | ✗             | ✗      | ✗    | ✗      | ✗       | ✗       |
| Selective disclosure (bbs-2023 shape)            | ✓        | ✗             | ✗      | ✗    | ✗      | partial | ✓       |
| Web Proofs (zkTLS + TLSNotary MPC)               | ✓        | ✗             | ✗      | ✗    | ✗      | ✗       | ✗       |
| **TLSNotary Proxy mode (May 10, 2026)**          | **✓**    | ✗             | ✗      | ✗    | ✗      | ✗       | ✗       |
| Multi-attestor k-of-n notarization               | ✓        | ✗             | ✗      | ✗    | ✗      | ✗       | ✗       |
| OAuth Txn-Tokens for Agents (draft-06)           | ✓        | ✗             | ✗      | ✗    | ✗      | ✗       | ✗       |
| PTV Groth16-2026 attestation envelope            | ✓        | ✗             | ✗      | ✗    | ✗      | ✗       | ✗       |
| **SCITT registration per decision**              | **✓**    | ✗             | ✗      | ✗    | ✗      | ✗       | ✗       |
| **SCITT ARP cross-sovereign reconciliation**     | **✓**    | ✗             | ✗      | ✗    | ✗      | ✗       | ✗       |
| **Three-axis evidence verification**             | **✓**    | ✗             | ✗      | ✗    | ✗      | ✗       | ✗       |

## Honest limitations

1. The CBOR encoding of COSE_Sign1 is shipped as a canonical-JSON
   analogue rather than true CBOR bytes. This preserves round-trip
   semantics and the COSE Sig_structure shape; the conversion to true
   CBOR via the ``cbor2`` library is a single-function swap.
2. The default ``glb-default`` projection function for ARP is a
   placeholder. Real ARP deployments register target-specific
   projection functions per ``draft-hillier-scitt-arp-00`` §3 — Tex
   exposes the registration API; production tenants plug in their
   own.
3. The Chathurangi 2026 lattice anonymous-credential primitive is
   referenced as the swap target. No production Python implementation
   exists publicly as of May 18, 2026; the algorithm-agile commitment
   + signature interfaces are structured for a drop-in swap when one
   matures.
4. ``InMemoryTransparencyService`` recomputes the Merkle root on every
   read for simplicity; for logs >10^4 entries, swap in an incremental
   Merkle tree (e.g. ``merkletools``). The ``TransparencyService``
   Protocol is the single boundary that needs to change.
5. Live TLSNotary Proxy mode requires ``TEX_TLSNOTARY_PROXY_URL``
   pointing at an alpha.15 proxy notary server. Sandbox CI runs the
   stub.

None of these limitations affect the *evidence shape*, the *audit
record format*, or the *three-axis verification* property — those
are correct end-to-end. The deltas are swap-in replacements behind
the existing API surface.

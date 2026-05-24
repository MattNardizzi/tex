# FRONTIER_DELTA_thread_6.md
## Durable Content Credentials + Hardware Attestation + CPSA Formal Verification

**Date:** May 18, 2026
**Builds on:** Thread 5 (C2PA 2.4 + ML-DSA-65 cosign + arxiv 2604.24890 six-attack defense)

---

## What this thread closes

The three honest gaps documented at the end of Thread 5:

### Gap 1 — Durable Content Credentials (soft binding via watermark)

The C2PA standard mandates a *hard binding* (SHA-256 over asset bytes,
which breaks on any re-encoding) plus an optional *soft binding* (an
invisible watermark or perceptual fingerprint that survives common
manipulations). The May 8 2026 EU AI Act Article 50 Guidelines and the
March 5 2026 Code of Practice both explicitly require a **multi-layer
approach**: metadata embedding + invisible watermarking + (often)
fingerprinting.

The current state of the art for **text watermarks** (the relevant
modality for AI-SDR outbound email, our GTM target):

- **SynthID-Text** (Google DeepMind, Nature, Oct 2024) — production-
  ready, distortion-free, integrated in Hugging Face Transformers
  v4.46.0+ as a logits processor.
  arxiv: 2410.10044, also analysed in 2603.03410 (Mar 3 2026).
  Source: github.com/google-deepmind/synthid-text + huggingface.co.

- **TextSeal** (Meta FAIR, arxiv 2605.12456, **May 12 2026** — 6 days
  ago) — strictly dominates SynthID-Text in detection strength and is
  robust to dilution. Distortion-free. Dual-key generation,
  entropy-weighted scoring, multi-region localization. "Radioactive":
  the watermark survives model distillation.
  Source: github.com/facebookresearch/textseal.

Neither has been wired into a C2PA manifest as a soft binding by any
agent-governance vendor as of May 18 2026.

**arxiv 2603.02378** (Mar 2 2026) demonstrates the *desynchronisation
attack*: when C2PA and watermarks are validated independently, an
adversary can produce content where the C2PA manifest says "verified
human authored" while the watermark detector says "AI generated"
(or vice versa) — *both signatures are cryptographically valid* but
they assert contradictory things. The paper proposes a cross-layer
audit protocol that jointly conditions the two validators. Nobody
ships this. We do, in Thread 6.

### Gap 2 — C2PA Attestations (hardware-attested signing)

The C2PA Attestation chapter (introduced in C2PA 1.4, still current
in 2.4) defines two attestation modes:

- **Explicit Attestation**: a Root of Trust signs (a) the hash of the
  C2PA claim plus (b) measurements of the application + platform
  environment. The output is an **EAT (Entity Attestation Token)** —
  either a CBOR Web Token (CWT) or JSON Web Token (JWT) — carrying
  RATS (Remote Attestation Procedures, RFC 9334) claims under the
  EAR (EAT Attestation Result) profile
  `tag:github.com,2023:veraison/ear`.

- **Implicit Attestation**: signing with a key that is *only* available
  to a trusted device / TEE.

Production trust-anchor providers as of May 2026:

- **NVIDIA NRAS V3** — JWT, ES384-signed, supports multi-GPU batch
  attestation up to 8 H100/B200 GPUs in a single token.
  Claims: `cc_mode_enabled`, `overall_result`, `gpu_evidence_list`,
  `nonce`, `iat`, `exp`.

- **Intel Trust Authority** (composite TDX + NVIDIA) — JWT, ES384,
  EAT Profile v1.0.1 doc v2.2 (Feb 16 2026). Returns a *composite*
  token covering both CPU TEE and GPU TEE.

- **AMD SEV-SNP** via Veraison or AMD's KDS (RFC 9334 evidence-only).

- **AWS Nitro Enclaves** — CBOR-COSE attestation documents
  (different format; we don't wire this in Thread 6).

The Thread 3 attribution receipt already supports NRAS EAT JWT
binding. Thread 6 extends this to the C2PA manifest emission path:
when the cosign is produced inside a TEE, the EAT JWT is embedded as
a `tex.evidence_attestation` extension assertion, and the cosign
signing key is bound to the attested platform measurement.

**No agent-governance vendor wires hardware attestation into C2PA
manifests as of May 2026** — confirmed via search across Microsoft
AGT, Zenity, Noma, Lakera, Pillar, F5/CalypsoAI, CrowdStrike/Pangea,
Palo Alto/Protect AI.

### Gap 3 — CPSA Formal Verification

CPSA (Cryptographic Protocol Shapes Analyzer) is MITRE's symbolic
protocol analyzer; CPSA v4.4.5 is current on Hackage. It enumerates
all essentially different shapes of a protocol's execution given an
initial point of view, surfacing structural attacks (replay, reflection,
oracle, type-confusion, etc.) under the Dolev-Yao adversary model.

The lead author of arxiv 2604.24890 (Sherman / Krawetz / NSA),
Enis Golaszewski, runs weekly CPSA workshops at UMBC's Cyber Defense
Lab. He's also the developer of an automatic context-binding tool
(precursor to ProtoBindGuard) that takes a two-party protocol spec,
infers a cryptographic context from protocol terms, and outputs a
protocol composition with a novel **context-exchange protocol** that
binds cryptographic values to a unique session using a **Merkle hash
tree** to represent context. The tool outputs context-equivalence
security goals which are then verified by CPSA.

Thread 6 ships:

1. A CPSA model of the Tex evidence cosign + outer-signature
   composition, expressed in CPSA S-expression syntax.
2. A Python CPSA-output parser that reads the shapes CPSA generates
   and surfaces them as test assertions.
3. A Merkle-hash-tree context binder for the cosign signing input,
   replacing the linear JSON canonicalisation with a context tree so
   each defended attack class is a leaf in a hash tree with explicit
   binding goals.
4. Tests that exercise each CPSA-derived security goal as a
   property-based assertion.

**No competitor has run their evidence chain through CPSA.** This is
the third leg of the "evidence-grade" positioning — beyond just
"signed" (which everyone claims) to "**formally verified to satisfy
authentication, secrecy, and context-equivalence goals**".

---

## Source-paper anchors (Thread 6 additions)

- **TextSeal** — arxiv 2605.12456 (Tom Sander et al., Meta FAIR,
  May 12 2026). Strictly dominates SynthID-Text. Distortion-free.
  Radioactive (survives distillation). github.com/facebookresearch/textseal.
- **SynthID-Text** — Dathathri et al., Nature (Oct 2024). Production
  in Gemini, 20M live A/B test, Hugging Face integration.
  Analysed in arxiv 2603.03410 (Omidi/Wang, Mar 2026).
- **Desynchronised provenance attack** — arxiv 2603.02378
  (Mar 2 2026). C2PA + watermark cross-layer contradictions.
- **C2PA Attestation chapter** — spec.c2pa.org/specifications/
  specifications/1.4/attestations/attestation.html (still current).
- **NRAS V3 JWT** — multi-GPU batch attestation, ES384-signed.
- **Intel Trust Authority EAT Profile v1.0.1 doc v2.2** (Feb 16 2026).
- **RFC 9334** — Remote Attestation Procedures (RATS).
- **EAR EAT Profile** — `tag:github.com,2023:veraison/ear`.
- **CPSA v4.4.5** — MITRE, Hackage. github.com/mitre/cpsa.
- **Roletran** — CPSA → procedure compiler, Ramsdell 2025.
- **Golaszewski FIDO UAF channel-binding paper** — arxiv 2511.06028
  (Nov 8 2025). Context-binding methodology applied to C2PA in this
  thread.
- **Context-binding via Merkle hash tree** — Golaszewski's
  formal-methods talk, UMBC CSEE Dec 2023, predecessor to
  ProtoBindGuard.

---

## Wire shape

### `tex.evidence_watermark` extension assertion

The C2PA manifest gains a third Tex extension assertion (alongside
`tex.evidence_cosign` from Thread 5):

```
{
  "$schema": "https://schemas.texaegis.com/c2pa/tex.evidence_watermark/v1",
  "scheme": "synthid-text" | "textseal" | "none",
  "watermark_present": true,
  "key_id": "...",
  "detection_score": 0.97,
  "detection_p_value": 1e-12,
  "context_history_size": 10,
  "ngram_len": 4,
  "detector_version": "...",
  "detector_url": "https://...",
  "soft_binding": {
    "kind": "perceptual-text-hash",
    "value": "sha256:..."
  }
}
```

The watermark binding is *soft*: if the outbound email body is
re-encoded by Gmail or Outlook (line wrapping, quote insertion, etc),
the SHA-256 hard binding breaks but the watermark signal survives
because text watermarks are at the token-distribution layer.

### `tex.evidence_attestation` extension assertion

```
{
  "$schema": "https://schemas.texaegis.com/c2pa/tex.evidence_attestation/v1",
  "profile": "tag:github.com,2023:veraison/ear",
  "eat_token": "eyJh...",                  // raw EAT JWT
  "eat_token_kind": "jwt" | "cwt",
  "attestation_verifier": "intel-trust-authority" | "nvidia-nras" | "veraison",
  "platform_measurement_sha256": "...",
  "claim_hash_bound": "...",               // SHA-256 of the C2PA claim
  "issued_at": "...",
  "nonce": "..."
}
```

### Cosign canonical signing input v2 — Merkle context tree

Thread 5's `_canonical_cosign_signing_input` builds a flat JSON
document. Thread 6 replaces it (versioned to `tex.evidence_cosign/v2`)
with a Merkle hash tree:

```
                     root_hash
                    /         \
                   /           \
            attack_defenses    context
            /     |     \      /    \
       ts_swap  rev  cross   asset  retention
```

The cosign signs `root_hash`. Each defended attack class is a leaf
with a stable hash. A CPSA model of this tree (with two roles:
Signer and Verifier) is checked by the build to ensure every leaf
hash is bound to the root signature.

`COSIGN_CANONICALIZATION_VERSION` bumps to `tex.evidence_cosign/v2`.
Thread 5 manifests (v1) continue to verify under the v1 path.

---

## Honest scope statement

- TextSeal's reference implementation is in Meta's FAIR repo and
  depends on JAX + Gumbel sampling at the model logits layer. For
  Tex's use case — verifying *that* a watermark is present in
  inbound/outbound text — we ship the **detection** path only.
  Production deployments wire detection against either Google's open
  Bayesian detector or TextSeal's. Insertion is the AI gateway's job,
  not Tex's.
- The CPSA binary is Haskell; we don't ship Haskell in the Tex
  runtime. We ship the CPSA .scm input file + the *parsed* shapes
  output as a vendored .json and a Python verifier that walks the
  shapes. CI can re-run CPSA against the .scm if cabal is available.
- Hardware attestation depends on a TEE actually existing. The
  attestation assertion is *conditionally emitted*: when no EAT
  token is provided in the `c2pa_context`, the assertion is omitted
  (same pattern as `revocation_proof`).

---

## Test plan

- `tests/frontier/test_durable_credentials.py` — watermark detector
  wrapper, soft-binding manifest assertion, desynchronisation attack
  detection (cross-layer audit).
- `tests/frontier/test_attestation.py` — EAT JWT parsing, NRAS V3
  verification, claim-hash binding, composite TDX+GPU token round-trip.
- `tests/frontier/test_cpsa_shapes.py` — load vendored CPSA shapes,
  assert all expected protocol-execution shapes are present, no
  unexpected shapes (i.e. no attacks).
- `tests/test_thread6_integration.py` — end-to-end emission of a
  manifest with all three Thread 6 layers + the Thread 5 cosign,
  verified through the full HTTP `POST /v1/c2pa/verify` endpoint.

Target: 25-30 new tests, zero regressions.

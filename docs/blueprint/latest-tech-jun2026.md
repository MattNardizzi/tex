<!-- Generated 2026-06-19 by a verified deep-research pass (latest June-2026 SOTA vs Tex's current tech). Read alongside README.md §7. -->

# Tex Latest-Tech Layer: What to Upgrade, What's Already SOTA (June 2026)

You don't have a technology problem. Across every layer, Tex is one half-generation behind the model frontier and at-or-ahead of the standards frontier. The work here is bolting newer renderers onto your existing verifier spine and emitting your already-strong receipts in the wire formats buyers now ask for by name — not rebuilding anything. Where I cite a specific Claude model ID, it's confirmed against the live `claude-api` reference (Opus 4.8 = `claude-opus-4-8`, GA, 1M ctx, $5/$25 per MTok; Haiku 4.5 = `claude-haiku-4-5`, $1/$5, 200K ctx).

---

## 1) Models — judge / cognition / voice

### (a) The grounded policy JUDGE (PERMIT / FORBID / ABSTAIN)

**Today:** an OpenAI-only "semantic" specialist bound when `TEX_SEMANTIC_PROVIDER=openai`, deterministic fallback otherwise.

**June-2026 latest:**

| Slot | Use | Why |
|---|---|---|
| **Primary judge** | **Claude Opus 4.8** (`claude-opus-4-8`) | Most capable Opus-tier, GA, 1M ctx, GA structured outputs (`output_config.format` + strict tool schemas), effort `low`→`max`. Critically, it does **not** carry the input safety-classifier refusals that Anthropic's most-capable model (Claude Fable 5) ships — Fable 5 returns `stop_reason:"refusal"` on exactly the security/bio-adjacent content a governance judge must rule on, which would give you *no verdict, silently*. **Opus 4.8 is the right judge; Fable 5 is the wrong one.** This is the single most counterintuitive call in the whole stack. |
| **Cross-check judge** | **OpenAI GPT-5.5** (`gpt-5.5`, GA since ~Apr 24 2026) | Keep your existing OpenAI binding but on the current-gen model. `reasoning_effort` none→xhigh, Structured Outputs, ~1.05M ctx, stronger negative-instruction handling. Cross-vendor disagreement between Opus 4.8 and GPT-5.5 is itself a strong ABSTAIN signal. |
| **Optional 3rd vendor** | **Gemini 3.1 Pro** (GA Feb 19 2026) | Only if you want a non-Anthropic/non-OpenAI tiebreaker for high-stakes FORBID (3-way agreement → act, any disagreement → ABSTAIN). Lower priority. |

**The shape that matters:** the judge is a **voter into your 17-judge PDP, never the gate.** It emits strict JSON `{verdict, rationale, evidence_ids}` at `effort:"low"`, and your existing Conformal Risk Control gate / multiplicative e-value spine / credal-conformal hold + EPIG consume it as one e-value-weighted vote. This preserves your monotone, CRC-gated, only-ever-ABSTAIN-on-uncertainty boundary — and is exactly correct given your honest "the judge is a voter, the verifier spine is the gate" framing. LLM-judge/human agreement tops out ~80% (κ≈0.63); that is *good enough to be one vote, not the gate.* **`[production-ready]`**

### (b) The "what to say" cognition (low-latency explanation)

**Today:** VIGIL Dirichlet-Normal active-inference learner + Expected-Free-Energy selector chooses the utterance/action class. Keep this — it is doing the deciding.

**June-2026 latest — a renderer only:**
- **Claude Haiku 4.5** (`claude-haiku-4-5`, $1/$5, 200K ctx) if you want to stay **Anthropic-only** across judge + cognition (one SDK, one key, shared structured-output format, shared prompt caching with the Opus judge). *Correction to the research's ship-date note: Haiku 4.5 shipped Oct 15 2025, not "mid-2026" — it is older and more battle-tested than stated, which only strengthens the pick.*
- **Gemini 3.1 Flash-Lite** ($0.25/$1.50 per MTok, ~2.5× faster TTFA than 2.5 Flash) if cost/throughput dominate and you'll add Google. **Note: Flash-Lite went GA on May 7 2026** — it is no longer "preview," and you should target the GA model, not the soon-deprecated `-preview` alias. Gemini 3 Flash (0.93s median TTFT) if you want near-Pro reasoning in the prose.

**Hard constraint:** the renderer *only phrases the decision the EFE learner already made.* It must not invent policy or alter the verdict, or the spoken "what to say" diverges from the sealed abstention certificate — a trust-critical mismatch. Constrain with a strict template grounded in the certificate/evidence, and diff the rendered prose against the structured verdict before it's emitted. **`[production-ready]`**

### (c) Voice — browser + server STT/TTS for hold-to-speak

**Today:** grounded STT→`/v1/ask`→TTS cascade, currently MUTED behind `VOICE_ENABLED`.

| Leg | Pick | Why |
|---|---|---|
| **Browser STT** | **ElevenLabs Scribe v2 Realtime** (~150ms first-partial, 90+ langs, client-side WebSocket) | Cleanest browser fit. Because Tex uses *explicit* hold-to-speak, you do **not** need model-integrated end-of-turn detection — the user owns turn boundaries. |
| **Server STT (optional)** | **Deepgram Nova-3** (sub-300ms, $0.0077/min) workhorse; **Deepgram Flux** (semantic EOT, 10 langs as of Apr 29 2026) | Reserve Flux for a *future* continuous/hands-free mode — its semantic end-of-turn is wasted under hold-to-speak but becomes the right tool the moment Tex listens hands-free. |
| **TTS** | **Cartesia Sonic** (~40ms, SSM architecture, best-in-class **P99 tail latency**) | For your "silent until an action needs approval, then one voice" design, **P99 matters more than mean** — one worst-case slow utterance breaks the "first voice of AI" feel. ElevenLabs v3 if expressiveness/brand beats raw speed; OpenAI's current Realtime model if you want one vendor (note: Realtime-2 superseded the older `gpt-realtime` snapshot in May 2026 — use the current id). |

This replaces the muted cascade once you flip `VOICE_ENABLED`. **`[production-ready]`** for all named vendors.

**Latency budget (the one thing to watch):** STT(~150ms) + judge(low-effort, hundreds-of-ms→seconds) + render(Flash-Lite sub-second TTFT) + TTS(~40ms) compounds, and **the judge is the long pole.** For interactive voice: run the judge at the lowest effort that holds conformal coverage, cache the policy prefix (Anthropic prompt caching / OpenAI), and stream the rendered prose into Cartesia as it generates.

---

## 2) Agent governance / runtime / identity — adopt vs. where Tex leads

The field has crystallized into a four-layer reference architecture that maps almost 1:1 onto your own Discover→Decide→Prove→Learn framing. The industry converged on **shared standards** at each layer where Tex still uses bespoke internals. Your deepest layers lead; your gap is **interoperability wire formats**, not capability.

### Where Tex must ADOPT (interop is now table stakes)

- **Agent identity — `[mix: GA primitives, draft spec]`.** The consensus is "no static API keys — short-lived attestation-bound credentials." Adopt **JWT-SVID / Workload Identity Token semantics** (IETF `draft-klrc-aiagent-auth-02`, dated 1 Jun 2026 — composes OAuth 2.0/OIDC + WIMSE/SPIFFE rather than inventing a protocol) so every discovered agent in your registry gets a short-lived credential instead of a static display name. **SPIFFE/SPIRE** `[GA]` is the de-facto attestation root underneath both Microsoft Entra Agent ID and Google Cloud Agent Identity. *Binding every Tex decision/receipt to a SPIFFE SVID rather than a directory name strengthens your "who acted" leg and makes receipts portable across clouds/IdPs.* The draft itself is an individual I-D (no formal standing yet); the building blocks are GA.
- **Microsoft Entra Agent ID `[GA]` — your single biggest distribution move.** You already run **live** on Entra Graph discovery. Position Tex as the **PROOF + ABSTAIN brain on top of** Entra's identity/PEP, emitting receipts that reference Entra agent IDs. Meet buyers where they already are.
- **MCP 2026-07-28 spec `[RC → GA 28 Jul 2026]`.** Make Tex's PEP an MCP **OAuth Resource-Server-aware** gateway (validate `iss` per RFC 9207, RFC 8707 Resource Indicators). Low-effort, high-recognition interop win at the boundary the whole ecosystem is standardizing on.
- **Signed A2A Agent Cards `[GA, A2A v1.0, 150+ orgs]`.** Consume them in the conduit so discovery output is cryptographically verifiable. Optionally accept **AP2 VC "Mandates"** `[v0.2 GA, FIDO]` so human-resolved ABSTAIN seals interoperate with the commerce/payments trust layer.
- **Policy-language interop `[GA, MIT]`.** Microsoft's **Agent Governance Toolkit ("Agent OS")** is a free MIT, <0.1ms-p99 deterministic allow/deny kernel speaking **Cedar / OPA-Rego / YAML**. **Do not compete on raw allow/deny latency against a free toolkit.** Instead: (a) ingest Cedar/OPA-Rego so you speak the market's policy language (you use bespoke Datalog/PCAS today), and (b) position on what Agent OS structurally *lacks* — calibrated ABSTAIN with a sealed certificate, conformal/e-value math, LTLf contracts.

### Where Tex already LEADS (defend, don't rebuild)

- **Prevention-by-design prompt-injection defense `[Tex ahead of market]`.** Your CaMeL dual-LLM + FIDES integrity×confidentiality lattice + Quarantined-LLM + IFC/Contextual-Integrity/NeuroTaint stack is the strongest known *prevention-by-design* approach. The market is mostly still shipping weaker **detection-based** filters (acknowledged insufficient for high-stakes). **Recommendation: benchmark Tex publicly on AgentDojo/PIArena and cite the number** — prevention-by-design is rewarded but few have shipped it; this is a credibility wedge.
- **Calibrated ABSTAIN + conformal/e-value risk math `[Tex ahead/orthogonal]`.** The market (MS Agent OS, Open Agent Passport `[research/arXiv 2603.20953]`, eBPF ActPlane) ships plain allow/deny PEPs. None has your risk-calibrated ABSTAIN with sealed abstention certificate. Expose Tex's pre-action decision via an **OAP-compatible interface** so you drop into ecosystems standardizing on that pattern — and beat their allow/deny with calibrated ABSTAIN.
- **Kernel-level mediation direction `[research/preview, validates your roadmap]`.** The 2026 thesis — "the agent harness is NOT a trust boundary, enforcement must live below it" (AgentSight/ActPlane; NVIDIA NemoClaw, GTC Mar 2026) — **directly validates your execution-layer roadmap.** This is where you can credibly lead: **A2 is built** — the proxy already consumes the eBPF-captured `orig_dst` instead of the spoofable Host header (`TEX_PEP_REQUIRE_DST=1` fails closed when no kernel dst is present; see [`execution.md`](../../execution.md) §5a–5b). The full reference-monitor property is now **deploy-gated** (it needs the eBPF node floor running in front of the agents), not unbuilt.

### The honest risk you already know

The execution layer **is a guard** — built and proven (see [`execution.md`](../../execution.md)). The **Brain blocks by default** on the live PDP (Tier-1 FORBID floor, DIFC `SECRET↛EGRESS` hard-deny, opaque→ABSTAIN, structural floor), and the **Body** — egress proxy + eBPF kernel floor + born-in-a-box admission — **refuses any not-released action inline** once it is deployed in front of the agents. The honest residual is **deployment + opt-in flags, not missing capability**: enforcement requires the PEP to sit in the agents' path (a pilot, not a commit), and the hardening legs — per-decision SealedFact receipts (`TEX_SEAL_DECISIONS=1`), in-proxy sealing (`TEX_PEP_SEAL=1`), external anchoring, permits, attested identity — ship **opt-in, default off**. **So before any "we enforce at runtime" messaging: deploy the PEP in one real environment and turn sealing on.** Runtime enforcement is real but *in-path-deploy-gated* — scope the claim to "enforces where Tex is deployed in the path," never "blocks everything out of the box."

---

## 3) Proof / crypto — upgrades vs. confirmed-still-SOTA

**Headline: nothing in your proof spine is deprecated or behind.** ML-DSA/FIPS 204, SHA-256 hash-chains, RFC 8785 JCS, Merkle inclusion proofs, RFC 3161 TSA, C2PA COSE_Sign1, SCITT, Groth16 are exactly the primitives the industry converged on. The SOTA moved in five targeted directions — each an upgrade, not a rip-and-replace.

### Confirmed still-SOTA (keep as-is)

- **ML-DSA-65 / FIPS 204** — finalized Aug 2024, **no 2026 revision**. Still current and correct. Your dual-signing (ML-DSA + ECDSA-P256/Ed25519) is already the right shape.
- **SHA-256 hash-chains with per-identity sequencing, RFC 8785 JCS, RFC 9162 Merkle math, RFC 3161 TSA, C2PA COSE_Sign1, SCITT, Groth16** — all current primitives. You are a **superset of the emerging AIVS standard** and a near-superset of SCITT registration.

### Targeted UPGRADES

| # | Upgrade | Maturity | Why |
|---|---|---|---|
| 1 | **Composite (PQ/T hybrid) ML-DSA** — `draft-ietf-lamps-pq-composite-sigs-19` | `[standards-track draft, BouncyCastle-implemented]` | You already compute both signatures; composite encoding binds ML-DSA + ECDSA/Ed25519 in **one** X.509/CMS object with one OID — what CNSA-2.0 procurement (the **Sept 21 2026** deadline is sales-relevant) and enterprise CAs validate. Use ML-DSA-87 for highest-assurance receipts per NIST IR 8547 (classical deprecated 2030, disallowed 2035). |
| 2 | **Static-CT tile logs** (Sunlight / Rekor v2 / Trillian-Tessera) | `[GA, production at Let's Encrypt + Sigstore]` | Same Merkle math you already emit, served as 256-entry tiles over static hosting — no dynamic API server. Makes the Tex log **self-hostable cheaply AND independently auditable with no Tex server in the loop** — exactly your offline-verifiable wedge. RFC 9162 CT-v2 is correct but the previous *operational* generation. |
| 3 | **Witness cosigning** (C2SP tlog-witness / Sigsum / Witness Network) | `[deployable / early-production]` | **The single most consequential gap to your moat claim.** A self-anchored hash chain + single TSA is **NOT split-view/equivocation-resistant** — a compromised Tex could show different chains to different parties. Until checkpoints are cosigned by 2–3 independent witnesses, "un-backfillable, externally-anchored" is stronger language than the crypto delivers. This is the missing leg of the time-moat. |
| 4 | **SCITT-conformant COSE receipts + AIVS bundles** (`draft-ietf-scitt-architecture-22`, past IESG / RFC-queue; `draft-stone-aivs-00`) | `[GA-imminent / very early I-D]` | Emit your receipts **also** as AIVS bundles + register as SCITT signed statements → instant **EU-AI-Act Art.19** compliance story in a format auditors recognize, while keeping your stronger primitives (ML-DSA-65 PQ, CT-v2 inclusion proofs, TSA anchoring) as the un-backfillable differentiator AIVS lacks. |
| 5 | **C2PA 2.3/2.4 hardware-root-of-trust Attestations** (spec 2.3 dated Jan 5 2026) | `[GA spec]` | The standardized way to bind "this receipt was produced inside attested hardware" — ties directly into your Intel TDX + NVIDIA H100 TEE. Replaces a bespoke claim. |

### Forward-looking (roadmap column, NOT shipping)

- **Production zkML / proof-of-inference** (Lagrange DeepProve — full GPT-2 inference proof, 12M+ proofs) `[production-grade per vendor, but heavy for LLM-scale]`. The modern successor to your Groth16 ZK attribution. **Selective fit only:** most receipts don't need zkML — a signed+logged record suffices. Reserve a DeepProve-class proof ("this exact judge model produced this verdict on this input") for the ABSTAIN certificate or a contested high-stakes decision. Keep your blueprint's **Phase-4 zkML correctly scoped as unbuilt** — external messaging must keep "zkML proof of inference" in the roadmap column, not shipping.
- **Receiver-attested receipts** ("Notarized Agents," arXiv 2606.04193, ~Jun 2 2026) `[research/prototype, ~zero adoption]`. Inverts who signs — the *service* signs what it saw. You can't force third parties to sign, but your execution-layer proxy is the natural "receiver" when Tex *mediates* an action. **Lead-don't-follow opportunity:** adopt the COSE+HPKE+witness-log envelope and play receiver where you mediate — frame as "Tex emits standards-aligned receiver receipts for actions it mediates," not "every action gets third-party attestation."

> One honesty guardrail throughout §3: TEE/C2PA attestation proves *where/what* produced a receipt, never that the *decision was correct* — keep it scoped to provenance, and scope every execution-layer claim to what is actually in force (decide+prove is always-on; physical enforcement is in-path-deploy-gated; see [`execution.md`](../../execution.md)).

---

## 4) Keep / Upgrade / Add

| Layer | KEEP (already SOTA) | UPGRADE (you use X → latest is Y) | ADD (missing leg / interop) |
|---|---|---|---|
| **Judge model** | 17-judge PDP, CRC gate, e-value spine, credal-conformal hold + EPIG, first-class ABSTAIN | OpenAI-only semantic specialist → **Opus 4.8 primary** (`claude-opus-4-8`) + **GPT-5.5 cross-check**; judge stays a *voter*, never the gate | Strict JSON verdict schema `{verdict, rationale, evidence_ids}` sealed into the receipt (model ID + prompt hash) |
| **Cognition** | VIGIL Dirichlet-Normal + EFE selector (keeps deciding) | Deterministic prose → **Haiku 4.5** (Anthropic-only) or **Gemini 3.1 Flash-Lite** (now GA) as *renderer only* | Template that diffs rendered prose vs. structured verdict before emit |
| **Voice** | Hold-to-speak cascade design | Muted cascade → **Scribe v2 Realtime** (browser STT) + **Cartesia Sonic** (TTS, P99) once `VOICE_ENABLED` flips | Deepgram Flux (semantic EOT) for a *future* hands-free mode |
| **Identity** | Entra Graph live discovery, reconciled registry | Static display-name identity → **SPIFFE SVID / JWT-SVID** (draft-klrc-aiagent-auth) | Consume **Entra Agent ID** + **signed A2A Agent Cards**; bind receipts to SVIDs |
| **Runtime / PEP** | CaMeL+FIDES+IFC prevention-by-design (**you lead**); execution-layer direction validated by 2026 eBPF SOTA | Bespoke PCAS Datalog → **ingest Cedar / OPA-Rego**; MCP-OAuth-Resource-Server-aware gateway | Deploy the **PEP in-path** (eBPF node floor + proxy) → true reference monitor (A2 / `orig_dst` already built); **flip `TEX_SEAL_DECISIONS=1`**; OAP-compatible pre-action interface |
| **Proof / crypto** | ML-DSA-65/FIPS 204, SHA-256 chains, JCS, Merkle, TSA, SCITT, Groth16, C2PA, dual-sign — **none deprecated** | Dual-sign → **composite PQ/T sigs**; RFC 9162 endpoints → **Static-CT tiles**; C2PA 2.3/2.4 HW attestations | **Witness cosigning** (the missing moat leg); emit **AIVS bundles + SCITT statements** (EU-AI-Act Art.19) |
| **Compliance** | Judges/contracts/IFC cover most OWASP categories | — | One-page **OWASP Agentic Top-10 + NIST 800-53 + EU-AI-Act Art.19** control-mapping (procurement-ready before Aug 2026) |
| **Verifiable compute** | Intel TDX + NVIDIA H100 TEE (**on the SOTA path**) | — | Wire a **TDX/H100 remote-attestation quote into the sealed receipt** (near-term win few governance products offer) |
| **zkML inference proof** | — | Groth16 attribution → **DeepProve-class** *selectively* (ABSTAIN cert / contested decisions only) | **Roadmap, not shipping** — keep Phase-4 zkML in the roadmap column |

**The decisive through-line:** in every model slot the new model is a **renderer/voter bolted onto your existing verifier spine** (conformal / e-value / EFE / ABSTAIN), never a replacement — exactly right for a **decide-and-prove spine that the PEP enforces once it is deployed in-path** (see [`execution.md`](../../execution.md)). On standards, your primitives lead; you're behind only on *operational generation* (tiles + witnessing) and *interop wire formats* (SPIFFE/Entra/A2A/MCP-OAuth, AIVS/SCITT). The three cheap, recognition-driving moves — **(1) deploy the PEP in one real environment + flip sealing, (2) ship standards interop, (3) publish the OWASP/NIST/EU-AI-Act mapping** — beat any new internal R&D for the runway you have. Distribution is the gap, not technology.

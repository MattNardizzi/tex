# Latest technology applied to Tex — June 2026 SOTA pass

> **Status:** research synthesis + applied-changes log for branch `feat/jun2026-sota`.
> **Generated:** 2026-06-19. **Method:** live web research this session (training cutoff is
> Jan 2026, so every model/standard fact below was *retrieved*, not recalled) compared against
> Tex's catalogued current tech in [`README.md` §7](README.md). Every citation is a URL fetched
> this session; where I could not verify, it is labelled `UNVERIFIED`.

This document answers one question: **what is the June-2026 state of the art across the three
areas that matter to Tex (the LLM judge / "what to say" cognition / voice; agent-governance &
identity standards; the post-quantum crypto / proof-transparency spine), and what did we change?**

The headline finding: **Tex's proof/crypto spine is already at — or ahead of — June-2026 SOTA.**
The genuinely stale surface was the **LLM model strings** (one was a 2024 model) and the absence
of a **cloud STT** path for voice. Those are what this pass fixed, on safe defaults, preserving
the two invariants that make Tex Tex: the **deterministic fallback** and the **grounding boundary**
(no free-running model in the speaking seat).

---

## 0. The decision that shaped this pass (read first)

Claude **Fable 5** (`claude-fable-5`) launched 2026-06-09 as Anthropic's most capable model and was
**disabled globally on 2026-06-12** by a US export-control directive (alleged safety-classifier
jailbreak). It is unavailable to everyone as of this writing. **Claude Opus 4.8** and **Sonnet 4.6**
remain fully available. → The recommended governance judge is **Opus 4.8**, with the model field
configurable so an operator can point at Fable 5 if/when it returns.
([MarkTechPost](https://www.marktechpost.com/2026/06/13/anthropic-disables-claude-fable-5-and-mythos-5-after-us-government-order/),
[Anthropic models overview](https://platform.claude.com/docs/en/about-claude/models/overview))

---

## 1. Frontier models — judge / cognition / voice

### 1.1 Closed frontier LLMs (as of 2026-06-19)
| Vendor | Model | API id | Notes | Source |
|---|---|---|---|---|
| Anthropic | **Claude Opus 4.8** | `claude-opus-4-8` | Most capable *available* model; 1M ctx, structured outputs via tool-use / `messages.parse`, `effort` defaults high, Jan-2026 cutoff | [overview](https://platform.claude.com/docs/en/about-claude/models/overview) |
| Anthropic | Claude Fable 5 | `claude-fable-5` | Launch-day top model; **DISABLED 2026-06-12** (export control) | [MarkTechPost](https://www.marktechpost.com/2026/06/13/anthropic-disables-claude-fable-5-and-mythos-5-after-us-government-order/) |
| OpenAI | **GPT-5.5** | `gpt-5.5` (snapshot `gpt-5.5-2026-04-23`) | Current frontier; Responses API + structured outputs + reasoning effort {none,low,medium,high,xhigh}; 1.05M ctx; cutoff Dec 1 2025 | [GPT-5.5 model docs](https://developers.openai.com/api/docs/models/gpt-5.5) |
| OpenAI | GPT-5.5 Pro | `gpt-5.5-pro` | Higher-compute variant | [TechTimes](https://www.techtimes.com/articles/318492/20260616/gpt-56-openai-chief-scientist-calls-it-meaningful-leap-june-launch-nears.htm) |
| OpenAI | GPT-5.4 mini | `gpt-5.4-mini` | Current affordable/mini tier (no `gpt-5.5-mini` exists) | [GPT-5.5 model docs](https://developers.openai.com/api/docs/models/gpt-5.5) |
| OpenAI | GPT-5.6 | — | Anticipated late June 2026; **not released** as of 2026-06-16 | [TechTimes](https://www.techtimes.com/articles/318492/20260616/gpt-56-openai-chief-scientist-calls-it-meaningful-leap-june-launch-nears.htm) |

LLM-as-a-judge 2026 guidance: pick the judge by running candidates on your own data, not a blog
ranking; frontier-closed (Sonnet/GPT-5 class) for accuracy, mini tiers for latency-bound signals.
([FutureAGI](https://futureagi.com/blog/best-llm-judge-models-2026/),
[DeepEval](https://deepeval.com/blog/llm-as-a-judge))

### 1.2 Voice (STT / TTS)
OpenAI shipped a new audio generation on **2026-05-07**: **GPT-Realtime-2** (GPT-5-class reasoning,
S2S), **GPT-Realtime-Translate**, **GPT-Realtime-Whisper** (streaming STT, ~$0.017/min). The current
REST transcription models are **`gpt-4o-transcribe`** / `gpt-4o-mini-transcribe`; the current TTS is
**`gpt-4o-mini-tts`** (steerable).
([OpenAI next-gen audio](https://openai.com/index/introducing-our-next-generation-audio-models/),
[9to5Mac](https://9to5mac.com/2026/05/07/openai-has-new-voice-models-that-reason-translate-and-transcribe-as-you-speak/),
[gpt-4o-transcribe](https://developers.openai.com/api/docs/models/gpt-4o-transcribe))

**Boundary note:** GPT-Realtime-2 is end-to-end speech-to-speech — deliberately **NOT** wired, because
that puts a free-running model in the speaking seat. Tex stays STT → deterministic `/v1/ask` → TTS.

---

## 2. Agent governance & identity standards (2026)
| Standard / source | What it is | Relevance to Tex |
|---|---|---|
| **NIST AI Agent Standards Initiative** (Feb 2026) — four focus areas: identification, authorization, **access delegation**, logging | The minimum security architecture for production agents | Tex's discovery→identity→PDP→sealed-log loop maps 1:1; delegation graph already exists |
| **OWASP Top 10 for Agentic Applications 2026** (pub. 2025-12-10): Agent Goal Hijack, Tool Misuse, Identity & Privilege Abuse; principle of **"Least Agency"** | Practitioner threat model | Tex's specialist/runtime defenses (planguard/clawguard/agentarmor/mcpshield) target these classes |
| **CSA Agentic Identity Governance Framework v1** | Agent-identity governance | Aligns with Tex's AID / agent registry |
| **arXiv:2603.20953** "Before the Tool Call: Deterministic Pre-Action Authorization for Autonomous AI Agents" | Deterministic pre-action authorization | **Directly validates Tex's architecture** — a deterministic PDP/PEP that authorizes *before* the tool call |

Sources:
[CSA NIST note](https://labs.cloudsecurityalliance.org/research/csa-research-note-nist-ai-agent-standards-initiative-2026040/),
[OWASP ASI](https://genai.owasp.org/initiatives/agentic-security-initiative/),
[CSA Agentic Identity GF](https://labs.cloudsecurityalliance.org/agentic/agentic-identity-governance-framework-v1/),
[arXiv:2603.20953](https://arxiv.org/pdf/2603.20953).

**Verdict:** no code change required — Tex is *ahead* of the curve here (deterministic pre-action
authorization is the thesis of the whole engine). Tracked as positioning, not a gap.

---

## 3. Post-quantum crypto & the proof/transparency spine
| Primitive | SOTA (2026) | Tex today | Verdict |
|---|---|---|---|
| PQ signature | **ML-DSA / FIPS 204** (final 2024-08-13) | ML-DSA-65 primary (`pqcrypto/ml_dsa.py`), real FIPS-204 sizes | ✅ current |
| PQ KEM | **ML-KEM / FIPS 203** | ML-KEM present | ✅ current |
| Hash-based sig | **SLH-DSA / FIPS 205** | SLH-DSA present | ✅ current |
| 5th KEM | **HQC** selected 2025-03; **draft 2026, final 2027** | `pqcrypto/hqc.py` present | ✅ ahead (already staged) |
| Content credentials | **C2PA 2.3 (2026-01-05)** latest published | code referenced "2.2 current"; already implements 2.4-draft OCSP/TSA-v2 | ⚠️ doc-only bump applied |
| Timestamping | **RFC 3161** + CMS verify | `interchange/external_anchor.py`, real freetsa token | ✅ current |
| Transparency | **RFC 9162 (CT v2)** + **SCITT** | RFC-9162 Merkle + SCITT signed statements | ✅ current |
| Canonicalization | RFC 8785 JCS / RFC 8949 CBOR | both present | ✅ current |

Sources:
[Utimaco HQC](https://utimaco.com/news/blog-posts/pqc-news-nist-announces-hqc-fifth-algorithm-be-standardized),
[Encryption Consulting NIST PQC](https://www.encryptionconsulting.com/decoding-nist-pqc-standards/),
[C2PA 2.3 spec](https://spec.c2pa.org/specifications/specifications/2.3/specs/_attachments/C2PA_Specification.pdf).

**Honesty carry-over (unchanged):** the *live ledger* signer is ECDSA-P256; ML-DSA-65 is
`RUNTIME-DEPENDENT` on a PQ backend (`cryptography>=48` native ML-DSA is present in this env at v49).
The hash **chain** proves integrity; a lone signature proves authorship. Nothing here changes that.
NSA CNSA 2.0 mandates PQ migration by 2030 — Tex is well inside the window.

**Verdict:** the proof spine is SOTA; the only change is a documentation-accuracy bump
(C2PA 2.2→2.3 latest-published, with the 2.4-draft section refs labelled UNVERIFIED).

---

## 4. What was applied (this branch)
Each change is on a safe default, marked production-ready vs research-grade, with the deterministic
fallback and grounding boundary preserved.

| Area | Change | Maturity |
|---|---|---|
| Judge | New `semantic/anthropic.py` — `AnthropicStructuredSemanticProvider` (Opus 4.8 via `messages.parse`, refusal→fail-closed), bound by `TEX_SEMANTIC_PROVIDER=anthropic` | production-ready (RUNTIME-DEPENDENT on `anthropic` SDK + key) |
| Judge | OpenAI default `gpt-5.4-mini` → **`gpt-5.5`**; `semantic_model` made provider-neutral (`None`→provider default) | production-ready |
| Cognition | VIGIL explainer `gpt-4o-mini` → **`gpt-5.5`** (dropped `temperature`, added low reasoning effort); new `_anthropic_explainer.py` (Opus 4.8); specialist dispatch `gpt-4o-mini`→`gpt-5.4-mini` | production-ready (RUNTIME-DEPENDENT) |
| Voice STT | New `OpenAICloudSTT` (gpt-4o-transcribe), preferred when keyed; local faster-whisper / OfflineSTT stay the offline fallback | research-grade until exercised against a live key; seam + fallback verified |
| Voice TTS | New `OpenAICloudTTS` (gpt-4o-mini-tts); ElevenLabs stays the signature voice (first), Kokoro local fallback | research-grade until exercised against a live key |
| Proof spine | C2PA doc refs 2.2→2.3 (latest published); 2.4-draft section refs labelled UNVERIFIED | doc-only |

**Not changed (deliberately):** the `/v1/ask` voice pipeline stays deterministic + zero-LLM; the
PDP verdict path; the crypto primitives; `VOICE_ENABLED` stays the master switch (default unchanged
— enabling is a deploy decision, not done here).

### Honest gaps
- No live API key in this session → the OpenAI/Anthropic transports and cloud-audio smoothness are
  `UNVERIFIED-without-credentials`. What *is* verified: provider construction, schema-locked call
  shape (faked), refusal→fail-closed, the deterministic fallback, the offline voice fallback, and a
  clean boot. The judge is a lowering-only signal, so a transport failure can never raise a verdict.
- GPT-Realtime-Whisper (streaming STT) is the future low-latency upgrade; the REST `gpt-4o-transcribe`
  path was chosen because it fits the existing buffered push-to-talk session and is offline-testable.

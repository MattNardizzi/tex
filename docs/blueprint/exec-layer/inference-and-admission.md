# Exec-Layer Design: Inference-Emission Gate + Born-in-a-Box Admission

> **Thread:** T6 — inference gate & admission control (design only)
> **Branch:** `exec/t6-inference-design`
> **Status:** DESIGN DOC. No code changed. Every code reference is a real `path:line`
> read this session; every external claim is labelled with its maturity per
> CLAUDE.md Rule 1 (`production` / `research-solid` / `research-early` / `speculative`,
> or `RUNTIME-DEPENDENT` / `UNVERIFIED-FROM-MEMORY`).
> **Method:** code-read of `src/tex/{pep,agent,operator,governance,tee,vet,c2pa}` +
> a live frontier survey (web, 2026-06-18). Frontier URLs are listed in §6 and
> tagged *retrieved-this-session* vs *cited-in-repo*.

---

## 0. Why these two, and why together

The execution layer already has *enforcement bodies* — the in-process gate, the
network PEP proxy, the iptables egress redirect, the eBPF kernel-floor. Every one
of them shares **one unstated assumption**: that the agent is *only ever launched
inside a Tex boundary*, and that *every actuation it can perform passes through a
Tex-controlled choke point*. Break either half and the bodies enforce nothing.

The two capabilities in this doc are the two halves of making that assumption
**true rather than assumed**:

```
 (2) Born-in-a-box admission control      (1) Tool-call emission gate
 ─────────────────────────────────────    ─────────────────────────────────────
 makes "inside the box" the ONLY way       makes a forbidden tool call
 an agent can run, and funnels ALL         UN-EMITTABLE: the forbidden tokens are
 actuation through the gated decoder   →   masked to zero probability before the
 + the PEP.                                sampler ever runs.
 ROOT of trust.                            LEAF guarantee that root makes sound.
```

They are **one machine**. (1) is only sound *because* (2) guarantees the agent
cannot reach an un-gated decoder or an un-gated actuator. (2) is only *worth*
building because (1) (and the existing PEP) turn "inside the box" into a real,
provable constraint on behaviour. Shipping (1) without (2) is a gate on a door
with no walls; shipping (2) without (1) is walls around an agent you still only
*ask* to behave. This doc designs both and sequences them.

---

## 1. Capability (1): the tool-call emission gate

### 1.1 The problem, stated adversarially

For an agent whose **only actuator is tool-call emission** (an LLM + a tool
runtime), the question "can it do the forbidden thing?" reduces to "can it
*emit the tokens* that name the forbidden tool call?" Today, across the whole
industry, the answer is governed by **cooperation-dependent** guardrails:

- system prompts ("you must never call `transfer_funds`"),
- in-SDK tool filtering (the framework only *registers* allowed tools),
- post-hoc output classifiers.

All three live **inside the model's cooperation**. A jailbreak, an indirect
prompt injection in retrieved content, a fine-tune, or a hallucinated tool name
routes around every one of them, because the model is still the thing *deciding*
what to emit, and we are merely *asking* it not to.

The structural alternative is a **Tex-controlled decoder**. The model proposes a
probability distribution over the next token; whoever owns the *decoding loop*
owns which tokens are *admissible* to sample. If Tex owns (or can constrain) the
sampler, a forbidden tool name can be masked to logit `-∞` **before** softmax —
the model **physically cannot sample it**, regardless of what it "wants." This
is the difference between *asking the agent not to* and *making it unable to*.
The sampler is not part of the model's cooperation; it is the one seam the agent
cannot jailbreak, because it does not produce its own tokens — it only proposes
them.

> **The honest scope limit, up front (the load-bearing caveat):** this only
> covers the **tool-emission actuator**. An agent that acts through any *other*
> channel — a side effect of generated *prose* that a downstream parser
> executes, a second un-gated model, direct egress from the agent process —
> walks straight past the decoder gate. That is precisely why capability (2)
> exists: the decoder gate is sound *only if all actuation is funnelled through
> the gated decoder*, which only the box can guarantee.

### 1.2 Where Tex already stands (the seams this builds on)

Tex already computes the allowlist this gate needs, and already enforces it at
**two** points. The emission gate is a **third, earlier** enforcement point off
the *same sealed surface* — not a new policy, a new *insertion depth*.

| When it acts | Mechanism | Guarantee | Cooperation-dependent? | Live today? |
|---|---|---|---|---|
| **Discovery** (`tools/list`) | `proxy._filter_tools_list` ([proxy.py:252](../../../src/tex/pep/proxy.py)), `_resolve_surface` ([proxy.py:283](../../../src/tex/pep/proxy.py)) | Agent never *learns* a forbidden tool exists | No (Tex strips the response) | As a sidecar process via `python -m tex.pep`; **orphan to the in-process app** |
| **Emission** (NEW — this doc) | constrained decoding / logit mask from the surface | Forbidden tool call is **un-emittable** | **No** (the sampler is Tex's) | — (design) |
| **Adjudication** (`tools/call`) | `proxy._to_decision` ([proxy.py:197-248](../../../src/tex/pep/proxy.py)) → PDP → 403 on non-PERMIT | Emitted forbidden call is **refused** | No (post-hoc block) | sidecar, orphan to app |
| **Verdict signal** | `AgentCapabilityEvaluator.evaluate` ([capability_evaluator.py:37](../../../src/tex/agent/capability_evaluator.py)) → `CapabilitySignal` | Out-of-surface action → CRITICAL finding → FORBID via fusion | No | **WIRED** — `suite.py:94`, fused as `agent_capability` in `router.py:22` |

The one source of truth all four read is **`CapabilitySurface`**
([domain/agent.py:149](../../../src/tex/domain/agent.py)): `allowed_tools`
(:169), `allowed_mcp_servers` (:170), `allowed_action_types` (:165),
`allowed_recipient_domains` (:168), and the predicates `permits_action_type`
(:202) etc. **The emission gate consumes exactly this object** — no new policy
model, no second dashboard.

There is also a **pre-wired insertion seam** for it: the MCP syscall gate
(`governance/kernel_mcp/syscall_gate.py`) implements a six-layer pipeline whose
**Layer 5 is a "kernel-resident logit gate" (ProbeLogits)** — and Tex today
ships that layer as a **pluggable hook that defaults to no-op but is
configurable to FAIL-CLOSED** (docstring, [syscall_gate.py:30-48](../../../src/tex/governance/kernel_mcp/syscall_gate.py)).
**The emission gate is the concrete, deterministic implementation of that
Layer-5 seam.**

> Honesty note on Layer 5: the cited paper's Layer 5 (`arXiv:2604.16870`,
> *cited in-repo, UNVERIFIED-FROM-MEMORY* — I did not re-fetch it this session)
> is a *learned semantic probe* over hidden states. What this doc proposes is a
> *deterministic structural mask* (an allowlist grammar). **Same insertion
> point, different mechanism.** I do **not** claim to implement their semantic
> probe; I claim a stronger, simpler structural floor at the same seam, with the
> probe relegated to a future caution-only signal (§1.6).

### 1.3 Mechanics: how a forbidden call becomes unrepresentable

A structured tool call is, at the token level, a constrained string —
`{"name": "...", "arguments": {...}}` (or the provider's tool-call grammar). Two
granularities of constraint, increasing in ambition:

**(a) Tool-name allowlist — highest confidence, ship first.**
At the decoding step where the model emits the `name` field, mask every token
that cannot extend to one of the agent's permitted tool names
(`CapabilitySurface.allowed_tools`). The forbidden name **cannot be generated**:
its tokens have probability exactly 0. This is `guided_choice` over the
permitted set (vLLM), or a regex/CFG fixing `"name":"<one-of-allowed>"`.
Deterministic; trivially correct to reason about.

**(b) Argument-shape & value constraint — more ambition, more edge cases.**
`guided_json` with a per-tool JSON Schema makes arguments well-formed; where the
surface restricts *values* (recipient domains, enums), constrain those too —
e.g. `send_email.to` regex-bound to `allowed_recipient_domains`. This projects
`CapabilitySurface.allowed_recipient_domains` (:168) into the grammar so an
out-of-domain recipient is un-typeable, not just rejected.

Both are produced by a single pure function we can seal:

```
DecoderConstraint = compile(CapabilitySurface) →
    { allowed_tool_names, per_tool_json_schema, value_regexes }
emit as:  vLLM guided_choice/guided_json/guided_grammar   (Tex-hosted)
   OR     provider tool_choice + response_format           (hosted frontier)
```

### 1.4 Two approaches (attacked), then the synthesis

**Approach A — Tex hosts the decoder (own the sampler).**
Tex runs vLLM/SGLang/TGI behind an OpenAI-compatible endpoint. Per request it
resolves the sealed `CapabilitySurface`, compiles the `DecoderConstraint`, and
passes it to the engine's guided-decoding backend (xgrammar / llguidance /
outlines). The mask is applied to the **actual logits** before sampling.

- **Strengths:** *true* unrepresentability — no model cooperation, deterministic,
  replayable (the grammar is a sealed fact, §1.5). Works for any open-weights
  model Tex serves.
- **Attacks / honest limits:**
  1. **Coverage = models Tex serves.** A closed frontier provider that exposes
     no token-level control cannot be masked this way (→ Approach B).
  2. **Tool-emission actuator only** (§1.1). Sound only inside the box (§2).
  3. **Semantic laundering.** The mask constrains the tool *name* and *shape*,
     not *intent*. A permitted `http_get` with a permitted-shape URL can still
     do SSRF / exfil. The gate is a **capability floor, not a content judge** —
     content still needs the PDP + specialists + the existing SSRF guard
     ([syscall_gate.py:30-36](../../../src/tex/governance/kernel_mcp/syscall_gate.py)).
     The grammar must not be sold as more than it is.
  4. **Grammar↔tokenizer soundness.** Constrained decoding is only as sound as
     the character-grammar→token-mask mapping; BPE merges, token-healing, and
     Unicode homoglyphs are a real correctness surface. xgrammar/llguidance
     handle this carefully, but it must be adversarially fuzzed, not assumed.
     `research-solid` on mature backends; the *value*-level constraints are
     `research-early`.
  5. **Cost:** ~50µs/token (llguidance) or JIT-compiled+cached (xgrammar) —
     negligible for allowlists; recursive JSON schemas cost more. Buildable.

**Approach B — Constrain the provider's decoder via its API (don't own the sampler).**
Tex sits as the proxy (extends `pep/proxy.py`) and rewrites the *request* that
reaches a hosted provider: strip forbidden tools from the `tools` array, set
`tool_choice` to the permitted subset, set `response_format`/structured-output
schema. The provider's own constrained decoder enforces.

- **Strengths:** works with **closed models today** on stable, advertised APIs
  (OpenAI/Anthropic `tool_choice` + structured outputs). No model hosting.
  Reuses the existing proxy seam and the already-filtered surface.
- **Attacks / honest limits:**
  1. **Trust moves to the provider.** It is "the provider *says* it masks," not
     Tex-owned unrepresentability. Label it `provider-trusted`, **not**
     `Tex-enforced`. Weaker moat claim than A — but still strictly stronger than
     cooperation-dependent, because the *request the provider executes is
     Tex-controlled*: the agent cannot re-add a tool Tex stripped, **provided
     the agent cannot reach the provider except through Tex** (→ the box again).
  2. **Granularity gaps.** `tool_choice` (auto / required / specific / none) +
     a trimmed `tools` array is coarser than logit masking; mid-stream
     multi-tool turns with interleaved free content may not be fully maskable
     through the API.
  3. Same actuator-only + semantic-laundering limits as A(2,3).

**Rejected alternative — learned semantic logit probe as the first slice
(literally the paper's ProbeLogits).** Rejected because (a) it is research-grade
(needs a trained, calibrated probe) and (b) it is a **probabilistic** signal,
which under Tex doctrine (Rule 2) may only *lower* a verdict — it must **never**
be the structural floor that makes a call un-emittable. The deterministic
allowlist grammar gives a stronger, simpler guarantee for *this* claim. The
semantic probe belongs in §1.6 as a future caution-only PDP signal, not the
emission floor.

**Synthesis / recommendation.** Ship **both, layered**, but make the **first
slice Approach B** (it reuses the proxy + surface that already exist and covers
hosted models immediately), then build **Approach A** as the *true*
unrepresentability tier for self-served open-weights models, wired as the
concrete `kernel_mcp` Layer-5 structural gate.

### 1.5 First slice (concrete, file-level)

1. **`DecoderConstraint` builder** (new, pure, sealable): `CapabilitySurface →
   {allowed_tool_names, per_tool_json_schema, value_regexes}`. Pure function,
   no I/O, unit-testable, reads only the existing surface.
2. **Approach-B enforcement in the proxy:** in `proxy.handle`
   ([proxy.py:140](../../../src/tex/pep/proxy.py)), when the upstream is a known
   LLM provider and the body is a chat/completions request, rewrite it to inject
   `tool_choice`/trimmed `tools`/`response_format` from the `DecoderConstraint`
   for the resolved agent — the same surface `_resolve_surface` already fetches.
   Forbidden calls in that turn become un-nameable at the provider.
3. **Approach-A endpoint (next):** an OpenAI-compatible serving shim that maps
   `DecoderConstraint` → vLLM `guided_choice`/`guided_json` and refuses to serve
   un-constrained if a surface exists (fail-closed by default).
4. **Seal it (the moat move):** emit the `DecoderConstraint` digest as a
   `SealedFact` so a verdict can later *prove* "this turn was decoded under
   allowlist `H`." This is the difference between "we masked" and "here is the
   replayable proof of *what* was masked," reusing the `SealedFactLedger`
   pattern the enforcement seal already uses
   ([enforcement_seal.py](../../../src/tex/provenance/enforcement_seal.py)).

> **Wiring honesty:** `pep/proxy.py` is **orphan to the in-process FastAPI app**
> today — it runs only as the standalone sidecar (`python -m tex.pep`), which is
> exactly the deployment the operator injects. So the first slice is "live where
> the proxy is deployed," not "live in the monolith." Stated, not glossed.

### 1.6 Buildable-now vs research (capability 1)

| Item | Maturity |
|---|---|
| Tool-name `guided_choice` allowlist on self-hosted vLLM | **production** (vLLM ships it) |
| Per-tool `guided_json` argument shaping | **research-solid** (mature, but schema/tokenizer edges) |
| Provider `tool_choice` + structured-output re-assertion in the proxy | **production** (stable provider APIs) |
| Value-level constraints (recipient regex) sound across tokenizer edge cases | **research-early** (needs homoglyph/token-healing fuzzing) |
| Sealing the `DecoderConstraint` as proof-carrying emission control | **research-solid** (reuses live ledger pattern) |
| Learned semantic logit probe (Layer-5 ProbeLogits) as a *caution-only* signal | **research-early / speculative** |

**The limit a competitor's engineer attacks first:** *"You only gate the tool-
emission actuator, and only where you own or can constrain the decoder. An agent
that exfiltrates via the content of a permitted tool, or that reaches any
un-gated actuator, is untouched."* — **True.** The answer is not to overclaim
the gate; it is that the gate is only sound inside capability (2), and intent is
still judged by the PDP. We sell the floor as a floor.

---

## 2. Capability (2): born-in-a-box admission control

### 2.1 The problem

Every prevention guarantee above (and the existing PEP) assumes the agent runs
*only* inside a Tex boundary. If an agent can be **placed outside the box** — an
un-injected pod, a node with no DaemonSet, a workload that never hits the API
server — the guarantees are void. Admission control is the **root of trust** that
makes "inside the box" the *only* way to run.

### 2.2 What exists today (the seed — and the exact gap)

- **`operator/webhook.py` is a *Mutating*AdmissionWebhook** (`SidecarInjector`)
  that injects the PEP sidecar + an iptables egress-redirect init container into
  new pods in governed namespaces ([webhook.py:1-19](../../../src/tex/operator/webhook.py),
  `_proxy_container` :77, `_init_container` :108). Governance is one namespace
  label, `tex.systems/govern=enabled` ([operator/__init__.py](../../../src/tex/operator/__init__.py)),
  reconciled by `EnrollmentScope`/`EnrollmentController` ([scope.py](../../../src/tex/operator/scope.py)).
- **The gap:** `build_admission_response` returns **`allowed: True` always**
  ([webhook.py:170](../../../src/tex/operator/webhook.py)) — it *enrolls*, it
  **never refuses**. And `operator` is **orphan to the running Python app** (it
  is a deploy-time artifact under `deploy/helm/tex`). So Tex today *adds* a guard
  to compliant pods and does **nothing to prevent a non-compliant pod from
  running**. That is the missing capability.
- **Assets to reuse:** the eBPF node redirect program *exists* —
  `pep/kernel/bpf/tex_redirect.bpf.c` (verified present) — as the sidecarless
  node floor; the **TEE verifier shape** exists — `tee/composite.py`,
  `tee/h100_attestation.py`, `tee/tdx_attestation.py`, `tee/verdict_binding.py`
  (binds the verdict into TDX `report_data`, gates on `tdx.tdx_report_data` not
  the hollow `eat_nonce` — [verdict_binding.py header](../../../src/tex/tee/verdict_binding.py));
  and a TPM-anchored agent-identity envelope exists — `vet/ptv_attestation.py`
  (`tpm_ek_thumbprint` field).

### 2.3 The four pieces the mission names → real tech + Tex code

1. **Refuse un-sandboxed placement** — add the **deny twin** of the existing
   mutating injector: a **ValidatingAdmissionPolicy (CEL, in-apiserver, GA since
   k8s 1.30)** + a **Validating webhook** that *denies* any governed-namespace
   agent pod lacking (a) an approved sandbox `runtimeClassName` (gVisor / Kata /
   Confidential Containers), (b) the governance labels, and (c) the injected
   proxy/redirect annotation. `failurePolicy: Fail` ⇒ **fail-closed**: if the
   controller is down, pods do not admit. VAP runs the structural checks with no
   external dependency; a webhook is needed only for checks requiring lookups
   (signatures).
2. **Signed-image gating (Sigstore/cosign)** — admit only pods whose images are
   cosign-signed by a Tex-trusted key (and ideally carry SLSA provenance + SBOM
   attestations), verified against Rekor, via **sigstore/policy-controller** or
   **Kyverno `verifyImages`**.
   > **Honesty:** Tex's existing `c2pa/cosign_verifier.py` verifies cosign
   > signatures over **C2PA evidence assertions**, **not OCI image signatures**
   > ([cosign_verifier.py:1-35](../../../src/tex/c2pa/cosign_verifier.py)). It is
   > **not** the image-gating verifier. Image gating is a *new integration* with
   > the sigstore admission stack — I will not misrepresent the existing module
   > as already doing this.
3. **A control plane that can't be bypassed** — admission only sees what flows
   through the kube-apiserver. **Bypass classes:** static pods (kubelet reads
   from disk, skips the apiserver), a compromised kubelet, direct CRI/containerd
   on a node, a second cluster. **Defenses:** (a) the **eBPF node DaemonSet**
   (`pep/kernel/bpf/tex_redirect.bpf.c`) redirects egress *regardless of how the
   workload was placed*, so even a static/bypass pod's traffic still hits the
   PEP; (b) **node attestation** (piece 4) so only Tex-measured nodes get
   cluster credentials / workload identity; (c) network policy that blackholes
   egress not originating from a governed, redirected context.
   > **Honesty:** admission control is **necessary but not sufficient alone**.
   > The eBPF floor + node attestation are what close the apiserver-bypass holes.
   > No single layer is the whole guarantee — this is defence-in-depth, stated
   > as such.
4. **DICE/TPM measured boot so the scheduler verifies the box is genuine** —
   node-level root of trust. The node proves, via TPM-anchored measured boot
   (DICE layered measurements → TPM PCRs), that it booted Tex's approved
   kernel/initrd/runtime. Bind it to **SPIFFE/SPIRE node attestation**
   (`tpm_devid` attestor / Keylime measured-boot node attestor;
   `bloomberg/spire-tpm-plugin`) so a node receives a workload identity (SVID)
   only if its measured state matches policy; admission then requires pods land
   only on attested nodes. Confidential Containers binds this to **hardware TEE
   remote attestation through a Key Broker Service** at `runtimeClass` granularity.
   Reuse the `tee/` verifier shape and `vet/ptv_attestation.py`'s TPM EK field.
   > **Honesty (CLAUDE.md):** Tex's attestation is **verifier-only** until a
   > confidential VM exists. This tier is **research / integration +
   > RUNTIME-DEPENDENT**, not running today.

### 2.4 Two approaches (attacked), then the synthesis

**Approach A — Policy-at-the-apiserver (admission-centric).**
ValidatingAdmissionPolicy (CEL) + cosign verifying webhook + the existing
mutating injector. Deny pods lacking sandbox runtimeClass / labels / signed
images. Fail-closed.

- **Strengths:** pure Kubernetes-native, GA tech, **no node changes, ships
  fast.** Directly upgrades `operator` from inject-only to **inject-or-deny** —
  the single highest-leverage change available.
- **Attacks:**
  1. **Apiserver-bypass** (static pods, direct CRI, compromised kubelet) —
     admission never sees them.
  2. **Trusts the node** — decides placement, doesn't verify the node is genuine;
     a rogue node can ignore `runtimeClass`.
  3. **Signing proves provenance, not behaviour** — a signed image can still be a
     malicious agent. Necessary, not sufficient.
  4. **Webhook availability** — fail-closed is correct but a down *webhook* means
     no pods admit (operational footgun); **VAP mitigates** by moving structural
     checks in-apiserver so only signature verification needs the webhook.

**Approach B — Node-rooted attestation (measured-boot-centric).**
DICE/TPM measured boot + SPIRE node attestation (Keylime / `tpm_devid`) + CoCo
`runtimeClass` with KBS remote attestation. A node can run governed workloads
*only* if it proves its measured state; admission requires attested-node
placement.

- **Strengths:** closes the apiserver-bypass and rogue-node holes A cannot — the
  root of trust is **hardware, not a policy the node could ignore.** This is the
  real "the box is genuine" guarantee.
- **Attacks:**
  1. **Heavy and partly research** — needs TPM/CC-capable nodes, a measured-boot
     pipeline, SPIRE+Keylime, a KBS; Tex attestation is verifier-only today.
     Months, not weeks; `RUNTIME-DEPENDENT` on hardware.
  2. **TOCTOU / runtime drift** — measured boot proves the *boot* state; post-boot
     tampering needs continuous attestation (Keylime IMA).
  3. **Supply-chain of the measurement itself** — trust bottoms out at firmware /
     DICE layer-0 and the TPM manufacturer CA.
  4. **Gates the box, not the actions** — attestation says the box is genuine;
     the PEP + emission gate (§1) say what the workload may *do*. Both needed.

**Rejected alternative — runtime enforcement (eBPF/LSM) *without* admission.**
Rejected because without admission you cannot *require* the sandbox or the
signed image: a pod can simply decline the `runtimeClass` and you are back to
hoping. **Admission is what makes the box *mandatory*; the node floor is what
makes it *unbypassable*.** You need both; admission is the cheaper first lever.

**Synthesis / recommendation.** **Stage it.** First slice = Approach A's
**deny-half** (the injector, scope, helm chart, and eBPF redirect already
exist): a fail-closed **ValidatingAdmissionPolicy** denying any
governed-namespace agent pod lacking *(sandbox runtimeClass + injected-proxy
annotation)*, plus **cosign policy-controller** for signed-image gating. This
flips Tex from "enroll compliant pods" to "**non-compliant pods cannot run.**"
Pair it immediately with the **eBPF node DaemonSet as the bypass floor** so
apiserver-bypass placements still get egress-redirected. Then sequence Approach
B (DICE/TPM + SPIRE/Keylime + CoCo) as the root that makes the box *genuine*,
honestly labelled research/integration + RUNTIME-DEPENDENT.

### 2.5 First slice (concrete)

1. **`ValidatingAdmissionPolicy` manifest** (CEL) under `deploy/helm/tex`:
   `failurePolicy: Fail`; on namespaces with `tex.systems/govern=enabled` and
   pods not carrying `tex.systems/govern-exclude`
   ([operator/__init__.py](../../../src/tex/operator/__init__.py)), require
   `spec.runtimeClassName in {approved sandboxes}` AND the
   `tex.systems/injected: "true"` annotation the injector already sets
   ([webhook.py:40](../../../src/tex/operator/webhook.py),
   `INJECTED_ANNOTATION`), AND deny `hostNetwork`/`hostPID`/privileged escapes.
2. **Make the existing webhook able to deny** (small, additive): give
   `build_admission_response` ([webhook.py:159](../../../src/tex/operator/webhook.py))
   a validating mode that returns `allowed: False` with a `status.message` when a
   pod in scope cannot be brought into the box — instead of only ever `True`.
3. **cosign image gating:** deploy `sigstore/policy-controller` (or Kyverno
   `verifyImages`) keyed to a Tex-trusted signing identity; require it on the
   governed namespaces.
4. **eBPF node DaemonSet** from `pep/kernel/bpf/tex_redirect.bpf.c` as the
   bypass floor, reading the same `EnrollmentScope`.

### 2.6 Buildable-now vs research (capability 2)

| Item | Maturity |
|---|---|
| ValidatingAdmissionPolicy (CEL) deny on runtimeClass + labels, fail-closed | **production** (VAP GA k8s 1.30) |
| Webhook deny-mode (additive to existing injector) | **production** (small code change) |
| cosign signed-image gating via policy-controller / Kyverno | **production** (shipping admission stack) |
| eBPF node DaemonSet bypass floor | **research-solid** (program exists; full DaemonSet wiring + scope sync is integration work) |
| Sandbox runtimeClass (gVisor/Kata) requirement | **production** to require; isolation strength `RUNTIME-DEPENDENT` |
| Confidential Containers + KBS remote attestation at runtimeClass | **research / RUNTIME-DEPENDENT** (needs CC hardware) |
| DICE/TPM measured boot + SPIRE/Keylime node attestation | **research / integration**; Tex attestation is **verifier-only** today |

**The limit a regulator attacks first:** *"Is the box actually inescapable, or
just the front door?"* — **Honest answer:** with the first slice (A + eBPF
floor), the *common* placement paths are closed and bypass traffic is still
redirected, but a node-level adversary capable of defeating measured boot is
only closed by Approach B, **which is not running today.** Said plainly, not
buried.

---

## 3. How the two compose — the trust chain

```
DICE/TPM measured boot  ──proves──▶  node is Tex-genuine        (2.4-B, research)
        │
        ▼
Admission control       ──requires──▶ agent pod = signed image  (2.4-A, ship now)
(VAP + cosign + deny)                 + sandbox runtimeClass
        │                             + injected PEP/redirect
        ▼
eBPF node floor + PEP    ──funnels──▶  ALL egress + ALL tool     (exists / sidecar)
                                       calls through Tex
        │
        ▼
Emission gate (decoder) ──masks────▶  forbidden tool call is     (1, ship B now / A next)
                                       UN-EMITTABLE
        │
        ▼
PDP + specialists       ──judges───▶  intent of the permitted    (live engine)
                                       call (semantic laundering)
```

Read top-down it is a chain of *necessity*: each layer is only sound because the
one above it holds. Read as a claim, the **provable** part today is the bottom
three (PEP funnel exists as a sidecar; PDP/capability stream is wired; emission
gate Approach-B is a small extension); the **root** (measured boot) is the
research frontier. That ordering — strong leaf, honestly-labelled root — is the
shippable truth.

---

## 4. Self-critique (the 3 strongest claims, falsified)

1. **"Forbidden tool calls become un-emittable."** Survives *only* for the
   tool-emission actuator, *only* where Tex owns or can constrain the decoder,
   and *only* at name/shape granularity (not intent). Outside those bounds it is
   false. Kept the claim narrow accordingly.
2. **"Admission control makes the box mandatory."** Survives for apiserver-routed
   placement with fail-closed policy; **falsified** by static pods / direct CRI /
   compromised kubelet unless the eBPF floor + node attestation are also present.
   Reported as defence-in-depth, not a single guarantee.
3. **"Tex already has the pieces."** Survives partially: the surface, the
   discovery filter, the capability stream, the mutating injector, the eBPF
   program, and the TEE *verifier* are real and cited. **Falsified** as
   "ready": the proxy is orphan to the app, the operator never denies, the TEE
   path is verifier-only, and the image-cosign module verifies C2PA assertions
   not OCI images. All four corrections are in the body, not hidden.

---

## 5. Frontier survey (citations)

*Retrieved this session (2026-06-18), verifiable:*
- vLLM structured outputs / guided decoding (`guided_choice`/`guided_json`/`guided_grammar`/`guided_regex`; backends outlines / lm-format-enforcer / xgrammar) — https://docs.vllm.ai/en/v0.9.2/features/structured_outputs.html ; https://vllm.ai/blog/struct-decode-intro
- XGrammar (batch constrained decoding via pushdown automaton, JIT grammars) & llguidance (token masks ~50µs/token, ~no startup) — https://github.com/guidance-ai/llguidance
- Sigstore policy-controller (admission controller validating cosign signatures/attestations vs Rekor) — https://github.com/sigstore/policy-controller ; Kyverno `verifyImages` — https://kyverno.io/docs/policy-types/cluster-policy/verify-images/sigstore/
- Kubernetes ValidatingAdmissionPolicy / CEL (GA 1.30, in-apiserver, `failurePolicy: Fail`) — KEP-3488: https://github.com/kubernetes/enhancements/blob/master/keps/sig-api-machinery/3488-cel-admission-control/README.md ; webhook good-practices (fail-closed timeout caveat) — https://kubernetes.io/docs/concepts/cluster-administration/admission-webhooks-good-practices/
- Confidential Containers (CoCo) + `runtimeClass` + KBS remote attestation; gVisor/Kata RuntimeClass isolation — https://confidentialcontainers.org/ ; https://www.systemshardening.com/articles/kubernetes/runtimeclass-gvisor-kata/
- SPIFFE/SPIRE node attestation (`tpm_devid`, IEEE 802.1AR IDevID/LDevID), Keylime measured-boot node attestor — https://spiffe.io/docs/latest/ ; https://next.redhat.com/2025/01/24/spiffe-spire-and-keylime-software-identity-based-on-secure-machine-state/ ; https://github.com/bloomberg/spire-tpm-plugin

*Cited in-repo, not re-fetched this session (UNVERIFIED-FROM-MEMORY):*
- `arXiv:2604.16870` — *Governed MCP: Kernel-Level Tool Governance for AI Agents via Logit-Based Safety Primitives* (the Layer-5 logit-gate seam in `governance/kernel_mcp/syscall_gate.py`). The emission gate is the deterministic structural realisation of that seam; the capability rests on the design here, never on this citation.

---

## 6. SUMMARY — top recommendation for each

**(1) Tool-call emission gate.** Build the gate off the *same sealed
`CapabilitySurface`* the discovery filter and capability stream already use, as a
**third, earlier enforcement point** (discovery → **emission** → adjudication).
**First slice: Approach B** — re-assert the allowlist via `tool_choice` + trimmed
`tools` + structured-output schema in `pep/proxy.py` for hosted-provider egress
(`production`, small, reuses live seams). **Then: Approach A** — a Tex-hosted
constrained-decoding endpoint (vLLM `guided_choice`/`guided_json`) for
open-weights models, which is the *true* unrepresentability tier and the concrete
`kernel_mcp` Layer-5 structural gate. **Seal the `DecoderConstraint`** so the
masking is proof-carrying. **Honest floor:** covers only the tool-emission
actuator, only where Tex owns/constrains the decoder, only at name/shape
granularity — intent is still the PDP's job, and it is sound only inside (2).

**(2) Born-in-a-box admission control.** **First slice: the deny-half Tex is
missing** — a fail-closed **ValidatingAdmissionPolicy** that denies any
governed-namespace agent pod lacking *(approved sandbox `runtimeClassName` +
injected-proxy annotation)*, plus **cosign signed-image gating** via
sigstore/policy-controller, plus the **eBPF node DaemonSet** (`tex_redirect.bpf.c`)
as the apiserver-bypass floor. This flips the existing inject-only operator into
**"non-compliant agents cannot run."** All `production`/`research-solid` and
buildable now. **Then: the genuine root** — DICE/TPM measured boot + SPIRE/Keylime
node attestation + Confidential Containers, reusing the `tee/` verifier shape;
labelled `research / RUNTIME-DEPENDENT` because Tex's attestation is verifier-only
until a confidential VM exists. **Honest limit:** the first slice closes the
common doors and redirects bypass traffic; only the (not-yet-running) node-root
closes a node-level adversary.

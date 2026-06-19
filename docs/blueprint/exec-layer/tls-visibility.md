# TLS content-visibility on HTTPS egress (G9)

**Status:** DESIGN DOC — no code in this change. The *current-state* facts below are
read from the live tree this session (`path:line` cited, maturity `production`
where the file is wired). The *proposed* build is `research-early`/`speculative`
as marked. Frontier citations were retrieved this session and are listed at the
end; nothing here is cited from memory.

**Thread:** T5 (exec-layer). **Owns:** this file only.

---

## 1. The gap, stated against the live code (not the brochure)

The enforcement proxy decides on the *request it can read*. Its whole tool-level
power lives in one function:

- `TexEnforcementProxy._to_decision` ([proxy.py:197-248](../../../src/tex/pep/proxy.py)).
  When the body parses as JSON-RPC `tools/call`, it lifts the **tool name** into
  `action_type` and the **arguments** into `content`
  ([proxy.py:219-224](../../../src/tex/pep/proxy.py)); `channel` becomes `"mcp"`.
  That is what feeds argument-level specialists (lethal-trifecta on args) and the
  filtered-discovery path ([proxy.py:183-192](../../../src/tex/pep/proxy.py)).
- When the body does **not** parse, it collapses to `action_type = f"http_{method}"`,
  `content = "{method} {path}\n{slice}"`, `channel = "network"`
  ([proxy.py:211-235](../../../src/tex/pep/proxy.py)). No tool, no args.

Under TLS the body is ciphertext, so every HTTPS request lands in that second
branch: **tool-level enforcement silently no-ops on the encrypted path** — which
is the dominant path. That is G9.

### Two findings that make the gap worse than "loses the tool name"

These are load-bearing and easy to get wrong, so they are stated up front:

1. **There is no TLS handling in the PEP at all today.** The proxy is served by
   `uvicorn.run(build_app(), ...)` ([__main__.py:73-77](../../../src/tex/pep/__main__.py)),
   a *plaintext* HTTP server wrapping a Starlette catch-all
   ([proxy.py:352-385](../../../src/tex/pep/proxy.py)). The kernel redirector
   rewrites the agent's `connect()` dst to `127.0.0.1:8088`
   ([tex_redirect.bpf.c:120-129](../../../pep/kernel/bpf/tex_redirect.bpf.c)),
   so for an HTTPS destination the agent sends a **TLS ClientHello to a plaintext
   HTTP server**. uvicorn cannot parse a TLS record as HTTP. So today HTTPS
   egress does not "degrade to `http_<method>`" — it does not cleanly traverse
   the userspace PEP at all. The `http_<method>` degradation is the *best case*
   that appears only once some TLS-aware front exists. Either way: zero content.
   *(`grep -ni "ssl|tls|clienthello|sni" src/tex/pep` returns only the docstring
   on [proxy.py:17-18](../../../src/tex/pep/proxy.py); there is no implementation.)*

2. **The orig_dst → proxy bridge is not wired.** The proxy reads the real
   upstream from the `x-tex-upstream` header
   ([proxy.py:150](../../../src/tex/pep/proxy.py)), described as "the
   SO_ORIGINAL_DST the eBPF redirector recovered." The eBPF program *stashes*
   orig_dst in a BPF map keyed by socket cookie
   ([tex_redirect.bpf.c:72-85, 120-125](../../../pep/kernel/bpf/tex_redirect.bpf.c)),
   and the Go loader *pins* that map — but **nothing in the tree reads it back
   and sets `x-tex-upstream`** (`grep -rn "x-tex-upstream" src pep` → only
   `proxy.py`; `main.go` never reads the orig_dst map per-connection). So the
   proxy's notion of "where is this really going" depends on header-injection
   work that does not exist yet. This is the **T1/T2 orig_dst dependency** every
   approach below leans on, and it is currently a stub.

The doctrine line in [pep/kernel/README.md:65-66](../../../pep/kernel/README.md)
("TLS-encrypted *intent* capture … is a separate eBPF program on the AgentSight
pattern") describes a layer that **does not exist** — there is no `SSL_write`/
uprobe code anywhere in `src` or `pep`. This doc decides whether to build that,
or something else.

---

## 2. Three approaches, attacked

The three live on different points of one frontier: **(content depth) ×
(does it break TLS trust) × (can it enforce inline, not just observe)**. They are
not substitutes — that is the whole finding.

### Approach 1 — eBPF uprobe on `SSL_write`/`SSL_read` (the "AgentSight pattern")

Attach a uprobe to the TLS library's write/read calls; the handler fires on the
**plaintext** the moment the agent hands it to the library, before encryption
(write) / after decryption (read). This is exactly what AgentSight does for agent
observability (arXiv:2508.02736).

- **What it sees:** the full plaintext request body — including the JSON-RPC
  `tools/call` with tool name + arguments. This is precisely the input
  `_to_decision` needs; once captured, the existing mapping
  ([proxy.py:215-231](../../../src/tex/pep/proxy.py)) reconstructs tool+args
  unchanged.
- **What it never breaks:** the agent's TLS to the real upstream is untouched —
  **no MITM, no cert-pinning breakage, no CA key to custody.** Biggest structural
  win, and the reason it is tempting.
- **Coverage fragility (real, documented):** it is per-TLS-library and
  per-version. OpenSSL `SSL_write`/`SSL_read` symbols are easy. **Go statically
  links `crypto/tls`** and a standard `uretprobe` *crashes the Go process*
  (stack rewrite) — you must disassemble the symbol, find `RET` offsets, attach
  uprobes there, require **unstripped** binaries, and handle two Go ABIs
  (gojue/ecapture, Coroot, Speedscale all document this). **rustls** ships no
  `libssl` symbol at all; **BoringSSL** (Chrome/Envoy), **NSS**, **GnuTLS**, and
  the **JVM's** own TLS each need bespoke probes. A statically-linked, stripped
  binary defeats symbol resolution outright.
- **The disqualifier for *enforcement*:** a uprobe is an **observe** plane, not a
  hold-until-PERMIT plane. It fires *as* `SSL_write` runs — the plaintext is
  already on its way into the encrypt-and-send. The eBPF handler runs in kernel
  context and cannot make a blocking call to a userspace PDP and *suspend the
  agent thread* pending the verdict. The state-of-the-art realization (AgentSight)
  is explicitly observability; the only "enforcement" it composes with is the
  **async kill** backstop (kprobe/Tetragon SIGKILL, which the repo already sketches
  in [tracingpolicy.yaml](../../../pep/kernel/deploy/tracingpolicy.yaml)). That is
  *observe-then-maybe-kill-after-the-write-left*, which is strictly weaker than
  the proxy's *forward-only-on-PERMIT* ([proxy.py:174-181](../../../src/tex/pep/proxy.py)).
  For Tex — whose product invariant is holding the request until the verdict — a
  plane that cannot hold cannot be the primary enforcement mechanism.
- **Verdict:** excellent **visibility/audit plane**, especially for traffic the
  other approaches cannot reach (pinned upstreams, non-HTTP). **Not** the
  enforcement v1.

### Approach 2 — In-box MITM CA the agent's sandbox trusts

Terminate the agent's TLS at the proxy using a leaf cert minted on the fly from a
CA that the agent's trust store includes; read the full plaintext HTTP/MCP
request; rule on it; re-originate a fresh TLS connection to the real upstream and
forward on PERMIT.

- **What it unlocks:** full content, library-agnostic, and — uniquely — it
  **preserves hold-until-PERMIT**. After termination the decrypted bytes flow
  through the *identical* code the plaintext path uses today; `_to_decision`
  ([proxy.py:197-248](../../../src/tex/pep/proxy.py)) needs **zero changes** to
  recover tool+args. It makes HTTPS look exactly like the HTTP the proxy already
  governs. Smallest change to the *decision* logic of any option.
- **Cert-pinning breakage:** any upstream the agent reaches with certificate or
  public-key pinning (a pinned CA bundle, HPKP-style logic, an SDK that pins)
  will fail the forged-leaf handshake. Standard LLM-API SDKs over vanilla TLS do
  not pin and work fine; arbitrary tool traffic is a coverage gamble. This must
  be **detected** (handshake failure) and routed to fail-closed ABSTAIN — never
  silently bypassed.
- **Key custody / blast radius (the serious one):** the **agent is the
  adversary**, and it runs inside the sandbox whose trust store now trusts the
  MITM CA. If the agent exfiltrates the CA private key, it can forge a cert for
  *any* domain that store trusts → full TLS impersonation of the entire sandbox.
  Mitigation is non-negotiable: the CA private key lives **only** in the proxy
  sidecar / node, **never** in the agent container or any path the agent can
  read; leaf minting happens server-side; the agent's store holds only the public
  cert. Blast radius of a leak is the whole sandbox's TLS trust, so custody is a
  first-class build requirement, not a footnote.
- **New surface:** a TLS-terminating listener (the current uvicorn front is
  plaintext-only), per-host leaf minting, SNI-driven upstream selection, and TLS
  re-origination. Bigger than "flip a flag," but all *additive* and isolatable
  from `proxy.py`'s core.
- **Verdict:** the only approach that delivers **content + inline enforcement**.
  Its costs (pinning, custody) are real but *bounded and disclosable* — they do
  not threaten the core invariant the way "observe-only" does.

### Approach 3 — SNI-only governance (rule on *where*, not *what*)

Peek the ClientHello, read the SNI hostname, and rule on the destination host.
No termination, no content.

- **What it sees:** one hostname, when it is visible. No tool, no args, no body.
- **It is largely already done at L4.** The kernel floor's `verdict_cache` already
  forbids by destination `(ip, port)`
  ([tex_redirect.bpf.c:58-70, 110-118](../../../pep/kernel/bpf/tex_redirect.bpf.c)).
  SNI's *marginal* value over that is **hostname fidelity** (survives IP rotation
  / shared-CDN IPs, the same reason the discovery layer keys egress on TLS-SNI —
  see [discovery.md:228](../subsystems/discovery.md)). It is an upgrade to the
  existing *where* floor, **not** new enforcement depth.
- **ECH blinds it.** Encrypted ClientHello (RFC 9849) puts the real SNI inside an
  encrypted `ClientHelloInner`; a passive reader sees only the cover domain in
  `ClientHelloOuter`. Deployment is patchy in 2026 (Firefox default-on with DoH
  since v118; Cloudflare auto-enable) but trending up. Domain-fronting defeats it
  too: SNI names the CDN while the in-TLS `Host` header (which you cannot read)
  names the real origin.
- **SNI is agent-spoofable.** The agent writes its own ClientHello — it can put
  `api.allowed.com` in SNI while TCP-connecting to an attacker IP. The only fix
  is to **pin SNI to the orig_dst IP** the kernel observed (and DNS-verify the
  pairing). That pin **requires the T1/T2 orig_dst bridge that is not wired**
  (§1, finding 2). Until then, SNI is an unauthenticated agent-supplied string.
- **Verdict:** a cheap, never-breaks-TLS **floor** worth having, but it is a
  network ACL, not content governance, and its integrity depends on unbuilt
  orig_dst work.

### Comparison

| Axis | 1. uprobe | 2. MITM CA | 3. SNI-only |
|---|---|---|---|
| Recovers tool name + args | ✅ full | ✅ full | ❌ none |
| Breaks TLS / cert pinning | ❌ never | ⚠️ breaks pinned upstreams | ❌ never |
| Hold-until-PERMIT (inline enforce) | ❌ observe-only → async kill | ✅ yes (reuses [proxy.py:174-181](../../../src/tex/pep/proxy.py)) | ⚠️ L4 host-block only |
| Library/coverage fragility | ❌ high (Go/rustls/BoringSSL/JVM, static, stripped) | ✅ library-agnostic | ✅ agnostic, but ECH-blinded |
| Key-custody blast radius | ✅ none | ❌ CA key = whole-sandbox TLS trust | ✅ none |
| Change to `_to_decision` | capture-plane feeds it | **zero** | n/a (no content) |
| Net role | **visibility/audit plane** | **enforcement content plane** | **where-floor** |

---

## 3. Recommendation (single)

**Make the proxy a scoped, custody-disciplined MITM terminator (Approach 2) as
the content-visibility-with-inline-enforcement plane — gated by an explicit
per-destination terminate-allowlist — and make every destination Tex does *not*
terminate fail *visibly* to an SNI-pinned-to-orig_dst L4 verdict (Approach 3 as
the floor), never to a silent `http_<method>` PERMIT.** Keep the eBPF uprobe
(Approach 1) on the roadmap as the *visibility plane* for traffic MITM cannot
reach (pinned / non-OpenSSL), not as the enforcement v1.

Why MITM over uprobe as the primary, stated as the rejection the doctrine asks
for: **uprobe cannot hold the request.** Tex's enforcement identity is
"forward only on PERMIT" ([proxy.py:174-181](../../../src/tex/pep/proxy.py)); a
plane that reads plaintext only *as the bytes are already being sent* and can at
best kill the socket afterward is observe-then-maybe-kill — a race the
exfiltration story cannot tolerate. MITM is the only option that keeps the
plaintext request *in the proxy's hand* before the forward, and it does so with
**zero change to the decision logic**. Its costs (pinning breakage, CA custody)
are real but bounded and honestly disclosable; "cannot enforce inline" is not.

Why not SNI-only as primary: it is not content (no DLP, no argument-level), it is
ECH-fragile (RFC 9849), and its integrity needs the unbuilt orig_dst pin. It is a
floor, retained as the fallback, not the answer.

This is a *layered* recommendation with a *single primary* (MITM). The honesty
move that distinguishes it from a naive "just MITM everything": the un-terminated
remainder becomes an **explicit ABSTAIN-surfaceable uncertainty**, not a silent
permit — turning G9 from an invisible no-op into a visible hold.

---

## 4. First slice (concrete) and where it plugs into `proxy.py`

A self-contained TLS front module — call it `tex/pep/tls_front.py` (new file;
**not built in this thread**) — sits in front of the existing
`TexEnforcementProxy.handle(...)`. Per connection:

1. **Peek the ClientHello, read SNI.** No decryption yet.
2. **Resolve the real destination** from the kernel's stashed orig_dst (the pinned
   BPF map keyed by socket cookie). **Prerequisite: the T1/T2 orig_dst bridge
   (§1, finding 2) must exist** — this slice is *blocked on it* and should say so
   rather than pretend `x-tex-upstream` is populated.
3. **Pin SNI to orig_dst.** If SNI ≠ the DNS-resolved orig_dst host (or ECH hides
   SNI), do not trust the name; fall to the IP-level floor.
4. **Terminate iff allowlisted.** If the destination is on a configured
   `terminate_allowlist`: present an in-box-CA leaf for that SNI, complete the
   handshake, read the decrypted HTTP/MCP request, and call the **existing**
   `proxy.handle(method=…, path=…, headers=…, body=plaintext)`
   ([proxy.py:140-193](../../../src/tex/pep/proxy.py)) unchanged. `_to_decision`
   ([proxy.py:215-231](../../../src/tex/pep/proxy.py)) now sees the real body →
   **tool name + args restored, `channel="mcp"`, filtered discovery live again.**
   On PERMIT, re-originate TLS to the real upstream.
5. **Otherwise, fail visible, not silent.** Build the `Decision` with an explicit
   `action_type="https_opaque"` (or similar marker) and `recipient` set from the
   pinned SNI/orig_dst host, so the PDP can **ABSTAIN** on un-inspectable content
   rather than PERMIT a generic `http_<method>`. A handshake that fails under
   termination (suspected pinning) routes here too.

**Footprint on `proxy.py` (keeps the hot-file delta tiny, per doctrine):**

- The TLS front is a **separate module** that *calls* `handle()`. The decryption,
  cert minting, and re-origination never touch `proxy.py`.
- The only edits inside `proxy.py` are 1–2 additive lines in `_to_decision`
  ([proxy.py:232-235](../../../src/tex/pep/proxy.py)): when the caller signals
  "TLS seen but content unavailable," emit `https_opaque` + `recipient` instead of
  the silent `http_<method>` default. The JSON-RPC branch
  ([proxy.py:215-231](../../../src/tex/pep/proxy.py)) is **not** modified — once
  bytes are decrypted it already does the right thing.

**Smallest shippable first step (before any TLS termination):** change the
un-readable-HTTPS default from `http_<method>` to an explicit `https_opaque`
marker so the gap stops being a silent PERMIT-shaped no-op and becomes an
ABSTAIN-surfaceable uncertainty. That is a 1–2 line `_to_decision` change with no
new TLS surface, and it is the honest precondition for everything above.

---

## 5. What this does NOT buy (read this before believing the demo)

- **SNI-allowlisting is not DLP.** "The agent may reach `api.openai.com`" is never
  "this `tools/call` is not exfiltrating a secret in its arguments." Argument-level
  inspection (lethal-trifecta, etc.) returns **only** under MITM termination —
  never from SNI, never from L4.
- **MITM does not cover cert-pinned or agent-controlled-trust upstreams.** Those
  must be detected and sent to fail-closed ABSTAIN, not silently bypassed. Claiming
  "full HTTPS visibility" while pinned traffic slips by uninspected would be the
  exact `nanozk`-style name-vs-body lie this project exists to avoid.
- **It does not defeat ECH + domain-fronting at the SNI layer.** Where ECH (RFC
  9849) is deployed, the SNI fallback degrades to orig_dst **IP only** — no
  hostname. The floor still holds (IP/port), but the hostname fidelity is gone.
- **No approach here claws back bytes already sent.** This is *pre-forward* hold,
  not network DLP that can retract a write. MITM preserves the pre-forward hold;
  uprobe does not (it sees the write as it leaves). "We can stop the exfil" is true
  only for the *next* request on a held verdict, not the in-flight `SSL_write`.
- **MITM is not cryptographic proof of agent intent.** Tex sees plaintext, but the
  sealed fact must read "content observed via MITM-termination at the proxy," not
  "proved the agent's intent." The trust is exactly the trust in the termination —
  no more. Sealing it as anything stronger would overclaim.

---

## 6. Self-critique — the three strongest claims, falsified

1. *"MITM is the only inline-enforcing content plane."* — **Survives, narrowed.**
   One could imagine an inline uprobe that suspends the agent thread pending a
   verdict (e.g. via signal/ptrace/`bpf_override_return` games). No productionized
   system does this for `SSL_write`; AgentSight does not. So the claim holds *for
   the state of the art*, which is the honest scope — not as a theorem.
2. *"Zero change to `_to_decision`."* — **Mostly survives.** The JSON-RPC branch is
   genuinely untouched once bytes are decrypted. But the *opaque-fallback* path
   does need the 1–2 line `https_opaque` edit (§4). "Zero change to the *MCP
   mapping*," yes; "zero change to the file," no. Stated honestly above.
3. *"SNI-only is already covered by the L4 forbid-set."* — **Survives with a
   caveat.** The kernel forbids by `(ip, port)`; SNI adds hostname fidelity over
   IP rotation/CDNs. So SNI-only is *not redundant*, but its delta is fidelity,
   not depth — which is why it is a floor, not the recommendation.

A fourth, unprompted: the entire first slice is **blocked on the T1/T2 orig_dst
bridge** (§1, finding 2). Without it the front cannot know the true upstream to
re-originate to, nor pin SNI. That dependency is named, not hidden; the smallest
shippable step (§4, the `https_opaque` marker) is deliberately chosen to *not*
depend on it.

---

## 7. Frontier (retrieved this session, verifiable)

- AgentSight — boundary tracing for AI agents via eBPF (`SSL_read`/`SSL_write`
  uprobes for intent + kernel tracepoints/kprobes for effects, <3% overhead):
  arXiv:2508.02736 — https://arxiv.org/abs/2508.02736 . Feb-2026 case study
  "Reverse Engineering Claude Code's SSL Traffic with eBPF":
  https://eunomia.dev/blog/2026/02/13/reverse-engineering-claude-codes-ssl-traffic-with-ebpf/
- eBPF SSL uprobe limits (Go uretprobe crash → attach at `RET` offsets; unstripped
  + two-ABI; rustls/BoringSSL/JVM gaps): gojue/ecapture
  https://github.com/gojue/ecapture ; Pixie https://blog.px.dev/ebpf-openssl-tracing/ ;
  Speedscale https://speedscale.com/blog/ebpf-go-design-notes-1/ ; Coroot
  https://coroot.com/blog/java-tls-instrumentation-with-ebpf/
- Encrypted ClientHello — RFC 9849 (TLS Encrypted Client Hello):
  https://datatracker.ietf.org/doc/rfc9849/ . 2026 deployment / SNI-blinding:
  CDT https://cdt.org/insights/encrypted-client-hello-closing-the-sni-metadata-gap/ ;
  Cisco Secure Firewall ECH defense
  https://secure.cisco.com/secure-firewall/docs/encrypted-client-hello-defense-strategies-how-cisco-secure-firewall-tackles-ech

---

## SUMMARY

**Recommend a scoped, custody-disciplined in-box MITM terminator at the proxy as
the content+inline-enforcement plane (reusing `_to_decision` unchanged), with
un-terminated traffic failing *visibly* to SNI-pinned-to-orig_dst L4 governance
(never a silent `http_<method>` PERMIT); eBPF `SSL_write` uprobes are the future
*visibility* plane, not the enforcement v1, because they cannot hold the request
until PERMIT — and the whole first slice is blocked on the unbuilt T1/T2 orig_dst
bridge, whose only un-blocked precursor is a 1–2 line `https_opaque` marker that
converts G9 from a silent no-op into an ABSTAIN-surfaceable hold.**

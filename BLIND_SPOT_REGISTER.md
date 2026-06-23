# BLIND_SPOT_REGISTER — SIEVE

A **first-class, machine-readable register** of every irreducible / known blind spot in the SIEVE
discovery engine. This register is not a footnote — it is a load-bearing output. The completeness
estimator's support is DEFINED to EXCLUDE these classes; SIEVE never folds them into N̂ and never
fake-finds them.

> **Rule (non-negotiable):** a blind spot with no named vantage is NOT allowed. Every entry below
> records its **EXACT required vantage** — the specific instrument that would convert it from
> invisible to seen — so each blind spot is auditable and *addressable*, not a vibe.

Two honesty axes, kept separate (per the measurement spine):
- **Unseen-but-detectable** — agents some plane *could* catch but didn't this window → handled by the
  capture-recapture LOWER bound + CI (ARCHITECTURE §6), NOT listed here.
- **Irreducible / vantage-gap** — agents physically below every available plane's detection
  threshold τ, OR catchable only by a vantage SIEVE does not currently hold → listed here, each with
  its exact missing vantage, declared via the Valiant-Valiant τ-floor and NEVER estimated into N̂.

Each entry: **ID · class · why it is invisible · EXACT required vantage · how SIEVE reports it ·
verification.**

---

## BS-01 — Zero-emission agent (catchability 0 on every available plane)
- **Class:** irreducible (information-theoretic).
- **Why invisible:** emits no signal exceeding any plane's detection threshold τ; e.g. an agent that
  only holds a credential or maintains an idle connection without writing files, calling the gate, or
  egressing measurably.
- **EXACT required vantage:** *any* net-new vantage that intersects its activity — e.g. an
  identity-provider/SaaS audit log for a UI-driven no-config agent, or a liveness/process plane where
  its mass exceeds that plane's τ. Until such a vantage exists it is outside the estimable population
  by the Valiant-Valiant impossibility bound (mass below τ on all planes is uncountable).
- **How SIEVE reports it:** a **Valiant-Valiant impossibility certificate** — worst-case mass hideable
  below every plane's τ simultaneously — NEVER folded into N̂, NEVER fake-found.
- **Verification:** plant an agent engineered to emit below every wired plane's threshold; assert it
  is declared "unseen, requires vantage X" and excluded from the estimate.

## BS-02 — stdio-transport MCP / fully-local loopback agent
- **Class:** irreducible to network vantages (physics).
- **Why invisible:** a local subprocess talking to a localhost MCP server over stdio emits ZERO
  network signal by construction — invisible to every network tap (P1–P4, P10-over-network).
- **EXACT required vantage:** a **host endpoint / eBPF sensor on that specific host [P9]** (syscall +
  process-tree); no network tap can ever see it.
- **How SIEVE reports it:** named gap "fully-local stdio agent on host H — requires eBPF/host sensor
  on H"; excluded from the network-plane estimate, counted only where P9 is wired.
- **Verification:** plant a stdio MCP agent on a host with P9 disabled; assert it appears as a named
  vantage-gap, not a silent zero, and is caught once P9 is enabled.

## BS-03 — Fileless / interpreted agent on a shared runtime
- **Class:** vantage-gap (the inode code-hash is too coarse).
- **Why invisible:** a python script behind a generic `python3`, or fileless via `memfd_create` /
  ptrace-injection — `bpf_ima_inode_hash` identifies only the shared interpreter, so distinct
  script-agents collapse to one merge-key (10k agents share one `python3` hash).
- **EXACT required vantage:** **per-script loaded-module hash via a uprobe on the interpreter's
  import/module-load machinery** (or the loaded `.py` path via `openat2`) — kernel vantage on the
  host, finer than the inode hash.
- **How SIEVE reports it:** entity class "interpreted agent on shared runtime; missing vantage =
  per-script loaded-module hash"; merge-collapsed entities are flagged low-confidence-on-split-axis.
- **Verification:** plant two distinct scripts behind one `python3`; assert SIEVE flags the
  merge-collapse and names the per-script-hash vantage rather than reporting one entity as certain.

## BS-04 — kTLS / QUIC-h3 / sidecar-remote / managed-runtime egress
- **Class:** vantage-gap (defeats the SSL_read/SSL_write uprobe).
- **Why invisible:** kTLS, QUIC/HTTP-3, statically-linked/BoringSSL/custom-crypto, or a remote/
  sidecar egress bypass the userspace TLS uprobe [P9 semantic] AND shift record sizes so the
  token-stream waveform [P4] is unreadable; ECH additionally destroys SNI destination attribution.
- **EXACT required vantage:** a **kTLS `sk_msg` kernel hook** (for kTLS), a **QUIC/h3-aware
  token-stream extractor pinned across the specific TLS libs** (for QUIC), or a **TLS-terminating
  inspection proxy** (for remote/sidecar). For ECH: JA4S/SPKI server fingerprint [P2] or passive DNS
  HTTPS-RR as a confidence-degraded fallback.
- **How SIEVE reports it:** semantic intent reported as unavailable; destination reported as
  low-confidence (JA4S/SPKI/ASN fallback) or a named gap — never a false-certain SNI.
- **Verification:** drive a planted agent over kTLS/QUIC on a host with only the userspace uprobe;
  assert SIEVE names the kTLS/QUIC vantage gap and degrades destination confidence honestly.

## BS-05 — Full-stack browser-emulation / utls / curl-impersonate (coherently forged)
- **Class:** irreducible to passive network when ALL planes are coherently forged.
- **Why invisible:** an agent driving a real Chromium (Playwright/Puppeteer) or using utls/
  curl-impersonate normalized to a popular human JA4 [P1] AND coherent h2 framing [P3] AND jittered
  timing [P4] is indistinguishable from a human on every network plane. (Note: a *partial* forgery is
  CAUGHT by the N4 incoherence detector — this entry is the *coherent* case only.)
- **EXACT required vantage:** **client-side attestation / endpoint EDR, or injected-JS interaction
  biometrics [P12], or an active honeytoken [P14]** — no passive network plane can individuate it.
- **How SIEVE reports it:** surfaced as quantified unseen MASS feeding the estimator (it spoofed into
  the human crowd) PLUS a named blind spot "all spoofable network planes coherently forged — requires
  client-side attestation or active probe."
- **Verification:** plant a coherent full-stack emulation; assert N4 does NOT false-trip (coherence
  holds) and the agent is named as a passive-network vantage-gap, then caught when P12/P14 is enabled.

## BS-06 — Non-streaming + fully-padded response flow
- **Class:** irreducible to the token side-channel (physics).
- **Why invisible:** when the LLM response is fully padded and non-streamed, the per-token length/
  timing channel [P4] physically does not exist.
- **EXACT required vantage:** a **TLS-terminating inspection proxy, or a host/eBPF vantage [P9]** —
  the encrypted-cadence plane is physically empty here.
- **How SIEVE reports it:** "token side-channel empty (padded+non-streaming) — requires terminating
  or host vantage"; P4 catchability for that flow reported as 0.
- **Verification:** replay a padded non-streaming flow; assert P4 yields no incidence and the gap is
  named rather than the flow being dropped silently.

## BS-07 — SaaS-with-no-grant-introspection-API / UI-driven embedded-AI agent
- **Class:** vantage-gap (the OAuth plane cannot enumerate it).
- **Why invisible:** an agent acting through a SaaS that exposes no admin/audit/OAuth-grant
  introspection API [P5], or an analyst driving embedded-AI inside a SaaS via the UI, leaves no
  enumerable principal.
- **EXACT required vantage:** a **SaaS provider audit log or OAuth-grant export API for that specific
  provider** (or Zscaler-style inline embedded-AI auto-classification for AI hidden inside non-AI
  SaaS).
- **How SIEVE reports it:** named gap "agent on SaaS provider P with no grant-introspection API";
  counted only once that provider's API is wired; never a silent zero.
- **Verification:** point P5 at a provider with no introspection API; assert the gap is named with the
  provider identity, not omitted.

## BS-08 — Identity-forging agent reusing a governed agent's self-asserted name
- **Class:** vantage-gap (the asserted identity is unverifiable).
- **Why invisible:** `agent_external_id` is an unverified self-asserted string (tex_gate trusts the
  name blindly), so an actor laundering actions under a legitimate agent's name cannot be caught by
  name-correlation alone.
- **EXACT required vantage:** a **binding between the asserted `agent_external_id` and an independent
  identity signal** — process owner / attested credential / network origin / eBPF PID-code-hash [P9]
  / SVID [P13]. (Partial mitigation: the N4 incoherence detector flags signed-vs-behavior divergence
  where a signature exists.)
- **How SIEVE reports it:** where no independent signal exists, named gap "name-only identity,
  forgeable — requires identity-binding vantage"; where P9/P13 exists, the laundering surfaces as an
  attribution_conflict (N4).
- **Verification:** plant an agent reusing a governed name with no independent signal; assert SIEVE
  refuses to merge on name alone and names the binding-vantage requirement.

## BS-09 — ECH-only flow with no corroborating JA4S/SPKI server fingerprint
- **Class:** vantage-gap (destination attribution lost).
- **Why invisible:** ECH encrypts the true SNI; with no corroborating JA4S/SPKI [P2] the real
  destination is unknowable on-path.
- **EXACT required vantage:** **passive DNS HTTPS-RR of the same client's prior lookups, or
  destination-IP/ASN-to-provider mapping** — otherwise destination is reported confidence-degraded.
- **How SIEVE reports it:** destination reported as low-confidence (ASN fallback) or a named gap;
  never fake-resolved to a certain SNI.
- **Verification:** replay an ECH flow with no JA4S corroboration; assert destination is degraded, not
  fabricated.

## BS-10 — Uninstrumented stack (no OTel spans / no provider billing visibility)
- **Class:** vantage-gap (the observability plane is empty).
- **Why invisible:** an agent calling tools outside instrumented SDKs, or a provider whose usage API
  SIEVE has not federated, emits no spans [P11] and no billing time-series.
- **EXACT required vantage:** **OTel auto-instrumentation on that stack, OR the provider's usage/cost
  admin API federated into the token ledger.** Partial detection: the **token-conservation residual
  (N3)** localizes the un-instrumented volume even without spans.
- **How SIEVE reports it:** the non-zero token-conservation residual flags "instrumentation gap at
  workspace/egress W"; the specific provider/stack is named as the required vantage.
- **Verification:** run a planted agent on an uninstrumented stack; assert the residual is non-zero and
  localizes it, and the missing-OTel vantage is named.

## BS-11 — Single python3 PID hides the whole tex-enterprise thread-fleet (host-plane attribution limit)
- **Class:** vantage-gap (process-level attribution too coarse for in-process threads).
- **Why invisible:** the tex-enterprise fleet runs 20 agents as daemon THREADS in one interpreter, so
  a `/proc`/process-table plane sees one `python3` PID for all 20 — process-level attribution alone
  cannot separate them.
- **EXACT required vantage:** **thread/fd/socket-level eBPF attribution, OR fs-write attribution under
  WORKSPACE** (which file each thread wrote), finer than the PID.
- **How SIEVE reports it:** where only PID-level signal exists, entities flagged "thread-fleet under
  one PID — requires thread/fd-level vantage"; the fs-write-attribution plane (thin-slice) resolves
  them where wired.
- **Verification:** run the recipe fleet with only PID-level signal; assert SIEVE does not over-merge
  the 20 threads into one entity silently, and names the thread-level vantage.

---

## Register operating rules

1. **Every estimate ships with this register.** The headline output is
   `unseen_fraction[lo,hi] @ CI + named_blind_spots[]`; the register entries that apply to the current
   estate are attached by ID.
2. **τ-floor carve-out.** Mass below every wired plane's measured τ is summed into a single
   Valiant-Valiant certificate (BS-01) and excluded from N̂.
3. **No silent zeros.** Any plane that *structurally* cannot see a class returns a named gap for that
   class, never an empty result that reads as "none exist."
4. **Vantage-closure tracking.** When an operator wires a new plane, the register records which
   blind-spot IDs it closes and re-runs plane-ablation to confirm the CI tightened as predicted (N2).
5. **Negative-control discipline.** Each verification above includes the negative control that the
   class is named (not fake-found) AND that enabling the named vantage actually catches it.

---

*End BLIND_SPOT_REGISTER.md — SIEVE. Every blind spot named; every name carries its exact vantage.*

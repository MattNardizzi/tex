# Verified research findings — the differentiator

> The deep-research pass the build plan is grounded in (fact-checked, mid-June 2026:
> 23 sources fetched, 113 claims extracted, 25 verified, 1 killed). This is the **durable,
> in-repo** copy so the findings travel with the build. **Read alongside BRAIN-BODY-JOIN.md.**
>
> **Scope honesty:** this is the *differentiator* question only (is "enforce + prove,
> verifiably, identity-bound" unowned?). The broader 6-lens SOTA sweep (kernel/eBPF,
> full identity/capability landscape, standards direction, TEE) **did not complete** —
> so for Phases 1–4 below, **re-ground in current research before building.** Treat the
> phase targets as direction, not a verified spec.

---

## Verdict

The four-criteria fusion — **(1)** un-bypassable in-path enforcement that blocks before
execution, **(2)** per-decision offline-verifiable receipt, **(3)** externally anchored
(RFC-3161 / transparency-log / Merkle), **(4)** bound to a cryptographically **attested**
agent identity — is **NOT cleanly owned by any shipped system as of mid-June 2026.** White
space is real, but **narrowing fast and contested** — the window is closing, not open-ended.

## The three camps

**1. Enforce + internal proof (closest, shipping):**
- **Pipelock** — real in-path AI-agent firewall (v2.7.0, ~723★). Synchronous pre-execution
  allow/deny across HTTP/WS/MCP/A2A **and** mediator-signed Ed25519 receipts, hash-chained
  JSONL, offline verifiers in 4 languages. **Misses:** external anchoring (timestamp is
  self-asserted RFC-3339; ordering is internal hash chain only) and attested identity (`actor`
  is a self-declared string; SPIFFE used as naming only). *These two missing legs = the gap.*
  Sources: `github.com/luckyPipewrench/pipelock`, `pipelab.org/learn/action-receipt-spec`.

**2. Prove / audit only (no enforcement):**
- **Sello** (`arXiv 2606.04193`) — receiver-attested COSE/Ed25519 receipts in a witness-cosigned
  Merkle transparency log; offline-verifiable; signs *after* acting; zero adoption.
- **AIVS** (`draft-stone-aivs-00`) — portable Ed25519+SHA-256 hash-chain proof bundles;
  retrospective only; RFC-3161 left optional.
- **ACTA / Asqav** (`draft-farley-acta-signed-receipts-01`, `draft-marques-asqav-compliance-receipts-02`)
  — genuinely satisfy the proof leg: Ed25519 (+ optional ES256 / ML-DSA-65), RFC-3161 **and/or**
  OpenTimestamps anchoring, SHA-256 hash chain, identity via issuer_id/LEI — but enforcement
  lives in a *separate* gateway whose outcome the receipt merely records.
- **akmon** (`github.com/radotsvetkov/akmon`) — tamper-evident sealed-session evidence; does not block.

**3. Spec / paper only (not built):**
- **AgentROA** (`draft-nivalto-agentroa-route-authorization`) — on paper fuses ALL pieces:
  in-path Border Gateway, PERMIT/DENY per call, signed Agent Execution Receipt produced
  *before* execution. But: no implementation; receipts use the gateway's **local clock**
  (no mandatory external anchor; SCITT only optional — and the SCITT-makes-it-verifiable claim
  was **refuted** 1-2) and are signed with the **gateway's** key (agent identity is a field, not attested).
- **PCAA** (`arXiv 2606.04104`, "Proof-Carrying Agent Actions") — names the paradigm but
  self-disclaims the crypto fusion: "not a replacement runtime," partial enforcement, proof
  layer is accountability artifacts not cryptographic attestation.

## The next paradigm (part b) — what to aim past the frontier

The converging-but-unshipped standard: a **proof-carrying / attestation-bound agent action** —
a pre-execution signed receipt, externally anchored, bound to an **attested** identity
(SPIFFE/SVID/mTLS or hardware), third-party verifiable. **The deepest, most-likely-unowned
version:** use **zkML / verifiable computation** to make the *decision itself* provable to a
third party **without trusting the gate operator** — not just "the action was logged" but "the
policy was actually applied correctly, and you don't have to trust me." Nobody is shipping
this; PCAA flags it as a "future verification lane." *This is Tex's candidate leap.*

## Caveats (do not overstate)

- The IETF items above are **individual Internet-Drafts with no working-group adoption** —
  several are effectively vendor self-documentation. **Do not cite as standards.**
- Pipelock evidence is largely self-sourced (its own repo/marketing); no independent audit;
  un-bypassability depends on deployment-level network isolation.
- AgentROA/PCAA have **no production deployments.** Sello/AIVS have near-zero adoption.
- The "next paradigm" finding is a cross-claim **synthesis (medium confidence).**
- TEE / confidential-computing (Nitro, TDX, SEV-SNP, CCA), zkML, TraTs, SPIFFE, biscuit/macaroons
  appeared in scope but **no verified evidence** surfaced of any delivering the full fusion —
  this is *absence of evidence*, not proof none exists. Warrants targeted follow-up.

## Open questions (for the SOTA phases)

1. Does any TEE deployment bind a hardware attestation to a per-decision agent-action receipt
   in production? (Most likely place a hidden full-fusion already exists.)
2. Has Pipelock's enterprise "Conductor" (SPIFFE/mTLS) tier already closed the two-leg gap?
3. Is anyone using zkML / zkVM to make the enforcement **decision** third-party verifiable
   without trusting the operator? (The deepest unowned version — Tex's leap candidate.)

# STANDARDS.md — Agent-Identity & Agent-Authorization Standards Posture

**Scope:** This document tracks the 2025–2026 emerging standards for agent
identity, agent authorization, and tamper-evident evidence that are relevant to
**tex-conduit** (the connect-your-directory discovery front door) and the Tex
governance core it feeds. For each standard we give a one-line summary, the
**conduit/Tex touchpoint**, and a disposition:

- **SUPPORT NOW** — already wired in-tree or a Phase-0/1 deliverable; conduit
  emits or consumes the artifact on the real stack.
- **TRACK** — genuine signal, moving fast, but not on the launch surface; we
  shadow the draft, keep a shim or an adapter seam, and adopt when it stabilizes
  or a customer demands it.
- **IGNORE** — out of scope, redundant with something we already do, or solving
  a problem conduit does not have. Listed explicitly so the decision is on the
  record, not an omission.

**Conduit's standards thesis.** Conduit normalizes AGENT/NHI objects (service
principals, OAuth clients, service accounts — *never users*) across four IdPs
into one `CandidateAgent` stream. The standards below matter only insofar as
they (a) are how those agent objects are *discovered and authenticated* at the
source IdP, (b) are how Tex's verdicts and receipts *travel and stay verifiable*
downstream, or (c) are the *audit/evidence wire formats* a regulator or insurer
will demand. We support the evidence-and-identity layer aggressively (it is the
moat), track the authorization-protocol layer (it is converging, not converged),
and ignore the user-IAM and pure-transport standards that are not conduit's job.

**Honesty rule (inherited from the project).** A standard is "SUPPORT NOW" only
if the in-tree artifact actually delivers the property the standard names — not
a same-shaped object. Where a draft is research-early, pre-quantum, or
unaudited, that is stated. Where an external-world fact (federation, adverse
independence, a real counterparty witness) cannot be asserted in code, the
standard stays TRACK until the counterparty exists.

---

## 1. Discovery & source-IdP authentication (how conduit *reads* the agents)

These govern how conduit authenticates to each IdP and enumerates the AGENT/NHI
objects. This is conduit's read path — the highest-priority support tier.

### 1.1 Microsoft Graph + OAuth 2.0 client-credentials (Entra) — **SUPPORT NOW**
- **What:** App-only client-credentials grant against Microsoft Graph;
  `@odata.nextLink` pagination and `/delta` change tracking to enumerate service
  principals, app registrations, and OAuth2 consent grants.
- **Touchpoint:** The Entra connector reuses the verified `LiveGraphTransport`
  (`graph_transport.py`: `get_paginated` + `get_delta`) and
  `EntraConsentGraphConnector` verbatim. This is the proven path the other three
  connectors are modeled on.
- **Disposition:** Support now — it is the reference implementation of the
  `GraphTransport` Protocol every net-new connector must satisfy.

### 1.2 Okta Management API + OAuth 2.0 (service apps, `/api/v1/apps`, SCIM) — **SUPPORT NOW (Phase 0)**
- **What:** Okta's OAuth-for-Okta service-app pattern (private-key-JWT client
  auth, `okta.apps.read` / `okta.clients.read` scopes), `after`-cursor link-header
  pagination, and System Log polling for change detection.
- **Touchpoint:** `OktaTransport` implements the identical `GraphTransport`
  Protocol (`get_paginated`/`get_delta`); `OktaConnector` mirrors the
  `BaseConnector` pattern and emits normalized service-app / OAuth-client / API-
  service-account `CandidateAgent` records. **This is the concrete first net-new
  deliverable.**
- **Disposition:** Support now — Phase 0. Okta's link-header cursor maps cleanly
  onto `get_paginated`; the System Log is the `get_delta` source.

### 1.3 Google Workspace Admin SDK + Service Accounts / OAuth clients — **SUPPORT NOW (Phase 0 net-new)**
- **What:** Admin SDK Directory + Cloud IAM service-account enumeration,
  domain-wide-delegation client IDs, and OAuth app allow-listing; `pageToken`
  pagination; service-account-key inventory as a blast-radius signal.
- **Touchpoint:** `google_transport.py` / `google_workspace.py` on the same
  Protocol. Domain-wide-delegation grants are first-class high-blast-radius
  agents and feed the consent-graph scorer.
- **Disposition:** Support now — net-new connector, identical Protocol shape.

### 1.4 Ping (PingOne / PingFederate) OAuth clients — **SUPPORT NOW (Phase 0 net-new)**
- **What:** PingOne Management API application + OAuth-client enumeration with
  cursor pagination.
- **Touchpoint:** `ping_transport.py` / `ping.py` on the `GraphTransport`
  Protocol.
- **Disposition:** Support now — net-new connector; lowest-priority of the four
  but in the launch set so "four heterogeneous IdPs" is true, not aspirational.

### 1.5 SCIM 2.0 (RFC 7643/7644) — **TRACK**
- **What:** Cross-domain identity provisioning schema. Some IdPs expose
  agent/service objects over SCIM.
- **Touchpoint:** A potential *fallback* normalization source where a vendor's
  native API is thin but SCIM is rich.
- **Disposition:** Track — SCIM is user-centric and its agent/NHI coverage is
  uneven across vendors; use native APIs first, keep SCIM as an adapter seam only
  if a customer's IdP exposes agents better over SCIM than its native API.

---

## 2. Agent identity credentials (how an agent *proves who it is*)

### 2.1 W3C Verifiable Credentials 2.0 (Data Model 2.0; VC 2.1 charter Apr 2026) — **SUPPORT NOW**
- **What:** The credential data model. Tex's **Agent Identity Document (AID)** is
  emitted as a W3C VC 2.0 document.
- **Touchpoint:** `vet/agent_identity_document.py` issues the AID as a VC 2.0
  with a `bbs-2023`-shaped selective-disclosure cryptosuite, base proof under
  **ML-DSA-65** (post-quantum hedge over the Ed25519 that ships in incumbent
  agent-identity stacks).
- **Disposition:** Support now — the AID is the canonical agent credential and is
  already on the VC 2.0 data model.

### 2.2 W3C DID (did:web / did:key) — **TRACK**
- **What:** Decentralized identifiers as the subject/issuer identifier in a VC.
- **Touchpoint:** AID subject and issuer identifiers could be DIDs; `did:web` is
  the pragmatic enterprise resolution method.
- **Disposition:** Track — conduit's discovered agents are identified by their
  *IdP-native* object IDs (Entra appId, Okta client_id, etc.), which is what the
  PDP and reconciliation engine key on. A DID layer is valuable for cross-org
  portability (see IGH, §6.2) but is not required for single-tenant discovery →
  governance. Adopt `did:web` when cross-org or VC-issuer portability becomes a
  customer ask.

### 2.3 SD-JWT VC (`draft-ietf-oauth-sd-jwt-vc`) + SD-Card (`draft-nandakumar-agent-sd-jwt`) — **SUPPORT NOW**
- **What:** Selective-disclosure JWT VC base format, plus the SD-Card encoding of
  an A2A Agent Card for field-level selective disclosure and cross-context
  unlinkability with holder key-binding.
- **Touchpoint:** `vet/sd_jwt_vc.py`. On AID issuance Tex can simultaneously emit
  an SD-Card so the agent is A2A-discoverable while disclosing only operationally
  necessary fields; key-binding prevents replay by an intercepting intermediary.
- **Disposition:** Support now — in-tree. Directly serves the
  least-disclosure posture conduit's frontier ZK layer extends (§5.1).

### 2.4 SPIFFE / SVID (X.509-SVID, JWT-SVID) — **TRACK**
- **What:** Workload identity framework: cryptographic identity for software
  workloads, trust-domain bootstrapping, short-lived SVIDs.
- **Touchpoint:** SPIFFE answers "what *workload* is this" at the
  infrastructure/mesh layer; conduit answers "what *agent/NHI grant* exists in
  the directory" at the IdP layer. They are complementary: an SVID could be a
  high-assurance binding for the runtime side of an `AVC` holder (§4.2).
- **Disposition:** Track — SPIFFE is **not** in-tree and is not how IdPs expose
  the agent objects conduit discovers. It is the right substrate for *runtime*
  agent-to-agent authN inside a mesh; we keep it as an adapter seam for the AVC
  holder-binding / PWR hop-identity story, not the discovery path. Promote to
  SUPPORT if a design partner runs an SPIFFE mesh and wants SVID ↔ AID binding.

### 2.5 Microsoft Entra Agent ID (GA June 2026) — **SUPPORT NOW (consume) / contest (don't depend)**
- **What:** Entra's first-party agent identity object: agents get directory
  identities, lifecycle, and Conditional Access.
- **Touchpoint:** Entra Agent ID objects are **exactly the AGENT/NHI objects
  conduit discovers** over Graph — they enrich the Entra connector's
  `CandidateAgent` stream (lifecycle state, CA posture).
- **Disposition:** Support now as a **discovery source**, but architecturally
  *contest* its trust model: Entra Agent ID is tenant-supremacist (a counterparty
  org's verdict can never bind your agent). That is the gap the Inter-Tex Governed
  Handshake (§6.2) exists to fill. Consume the identity object; do not inherit the
  governance assumption.

---

## 3. Agent authorization & delegation tokens (what the agent is *allowed to do*)

### 3.1 OAuth 2.0 / 2.1 + the consent-grant surface — **SUPPORT NOW**
- **What:** The authorization-code/consent and client-credentials grants are the
  *act of granting an agent its scopes* at the IdP.
- **Touchpoint:** Conduit's headline differentiator — **SEAL-THE-GRANT** — mints a
  `ConsentReceipt` (`SealedFactKind.CONSENT_GRANT`) at consent time capturing the
  exact granted scope set + grantor + tenant + timestamp, dual-signed ML-DSA-65
  and hash-chained. **No IdP, CIEM, or NHI vendor seals the consent grant itself.**
- **Disposition:** Support now — Phase 1. The OAuth consent event is the first
  un-backfillable receipt in the conduit evidence chain.

### 3.2 OAuth 2.0 Token Exchange (RFC 8693) — **TRACK**
- **What:** Exchange one token for another (delegation/impersonation) with
  `act`/`may_act` actor claims — the standard substrate for "agent acts on behalf
  of principal."
- **Touchpoint:** Conduit *discovers* the resulting grants; the actor-claim
  semantics inform how the consent-graph scorer attributes blast radius across a
  delegation. RFC 8693 is also the natural floor under the AVC delegation chain.
- **Disposition:** Track — relevant to *runtime* delegation, not to the discovery
  snapshot. We track it as the standardized delegation semantics our AVC token
  (§4.2) deliberately *exceeds* (RFC 8693 carries scope, not a governance verdict).

### 3.3 OAuth Transaction Tokens for Agents (`draft-oauth-transaction-tokens-for-agents`) — **SUPPORT NOW**
- **What:** Short-lived, transaction-scoped tokens carrying `act` (which agent)
  and `sub` (on whose behalf), per the April 2026 Five Eyes "Securing Agentic AI"
  guidance that agents be authenticated with VCs *plus* short-lived OAuth tokens.
- **Touchpoint:** `vet/txn_tokens.py` packages an AID + Txn-Token as an
  `AidTransactionToken` for service-to-service calls, revealing only the claims
  the target needs.
- **Disposition:** Support now — in-tree. This is the per-transaction layer the
  AID embeds into; it is the standards-anchored precursor the **Intent-Bound
  Capability Token** (§4.3) extends from "what transaction" to "what *intent*,
  sealed before the action exists."

### 3.4 OAuth Rich Authorization Requests (RAR, RFC 9396) — **TRACK**
- **What:** Fine-grained, structured authorization details beyond coarse scopes.
- **Touchpoint:** RAR `authorization_details` are a richer scope-bound source for
  the IBCT `scope_bound` (recipient-domain set / max records / max amount) than
  flat OAuth scopes.
- **Disposition:** Track — adopt as the structured input format for IBCT
  scope-bounds when an IdP/RS emits RAR; not required for the launch discovery
  path (most discovered grants are still flat scopes today).

### 3.5 GNAP (RFC 9635) — **IGNORE**
- **What:** Grant Negotiation and Authorization Protocol — a clean-sheet OAuth
  successor.
- **Disposition:** Ignore — negligible enterprise IdP adoption in the
  2025–2026 window; conduit reads the OAuth/OIDC grants IdPs actually emit.
  Re-evaluate only if a target IdP ships GNAP grants natively.

### 3.6 OpenID AuthZEN (Authorization API 1.0) — **TRACK**
- **What:** A standard PDP/PEP wire contract: `POST /access/v1/evaluation` with a
  `subject / action / resource / context` tuple, returning a decision.
- **Touchpoint:** Tex *is* a per-action PDP (`POST /v1/govern/decide`). AuthZEN is
  the obvious interop façade so any AuthZEN-speaking PEP can call Tex without a
  bespoke client.
- **Disposition:** Track — **strong candidate for a fast-follow adapter.**
  AuthZEN's decision model is 2-valued (permit/deny); Tex is 3-valued
  (PERMIT / ABSTAIN / FORBID). We expose Tex behind an AuthZEN-shaped endpoint and
  map ABSTAIN → deny-with-obligation, **but never collapse ABSTAIN to a plain
  deny in the sealed record** — the human-resolved ABSTAIN is the flywheel and
  must survive the façade. Adopt when a PEP-side design partner asks for it.

---

## 4. Agentic interaction & propagation (how governance *travels*)

### 4.1 Model Context Protocol (MCP) — **SUPPORT NOW**
- **What:** The dominant agent-to-tool protocol (servers, tools, resources).
- **Touchpoint:** Tex already ships an MCP server (`api/mcp_server.py`), an MCP
  connector for discovery (`discovery/connectors/mcp_server.py`), and MCP-specific
  threat specialists (`mcpshield_specialist`, `mcp_injection_specialist`). MCP
  servers an agent can reach are blast-radius edges in the consent graph.
- **Disposition:** Support now — MCP is both an *interface to* Tex governance and
  a *discovered surface* (which tools/servers an agent can invoke). Track MCP's
  own evolving auth sub-spec (OAuth-based MCP authorization) as it firms up.

### 4.2 A2A (Agent2Agent, Linux Foundation, v1.0 GA Apr 2026) + Signed Agent Cards — **SUPPORT NOW (consume) / TRACK (full protocol)**
- **What:** Agent discovery/interop via ECDSA-Signed Agent Cards; the emerging
  cross-vendor agent-to-agent wire format.
- **Touchpoint:** SD-Card (§2.3) is Tex's selective-disclosure encoding of an A2A
  Agent Card. A2A *bus listener* and *signed agent card* surfaces exist in-tree
  as stubs (`_pending/interop/a2a/`) — the seam the Inter-Tex Governed Handshake
  (§6.2) replaces.
- **Disposition:** Support now for the **Signed Agent Card / SD-Card** consume
  path; **track** the full A2A bus protocol — its governance model is identity-
  only (a Card proves *who*, not *what verdict travels*), which is exactly what
  AVC (§4.3) and PWR (§6.1) add on top.

### 4.3 Attenuating delegation tokens (macaroons / biscuit / `draft-niyikiza` Attenuating Authorization Tokens) — **TRACK → build beyond (AVC, Phase 2)**
- **What:** Caveat-chained, monotonically-narrowing capability tokens for
  delegation chains; the IETF `draft-niyikiza` does scope-only attenuation + PoP
  and explicitly leaves revocation unaddressed.
- **Touchpoint:** The **Attenuating Verdict Capability (AVC)** mints at the PDP a
  token that (1) carries the 3-valued PERMIT/ABSTAIN/FORBID **verdict** as a
  monotone lattice element (never re-widens), (2) decrements a cascade-derived
  blast-radius budget so a HOLD materializes from delegation *depth*, and (3)
  binds an upstream verdict flip to a `gix` transparency-log revocation leaf for
  offline non-revocation proof.
- **Disposition:** Track the lineage; **build beyond it.** None of macaroons /
  biscuit / `draft-niyikiza` carry a governance *verdict* as the attenuated
  element or solve revocation via a transparency log. AVC is the net-new fusion
  (Phase 2). PoP holder-binding itself is reused, not claimed novel.

### 4.4 Intent / pre-commitment tokens (Google AP2; `draft`-stage intent binding) — **TRACK → build beyond (IBCT/SICC)**
- **What:** Google's Agent Payments Protocol (AP2) signs a *user's static
  pre-authorization* to payment rails and explicitly disclaims behavioral-drift
  adjudication.
- **Touchpoint:** **Intent-Bound Capability Tokens (IBCT)** invert this: the agent
  seals a *per-action* intent *before the action exists*
  (`SealedFactKind.INTENT_PRECOMMIT`, `POST /v1/govern/intent`), the chain
  position proves precedence, and Tex adjudicates *declared-vs-observed* at
  decide-time so a prompt-injected agent holding valid OAuth is caught the instant
  it diverges. **SICC** further couples declared-intent vs *simulated* consequence.
- **Disposition:** Track AP2 and the intent-binding drafts as converging signal;
  build the sealed-before + chain-proves-precedence + per-action declared-vs-
  observed combination they do not have.

---

## 5. Selective disclosure & zero-knowledge (least-disclosure posture)

### 5.1 BBS / `bbs-2023` selective disclosure cryptosuite — **SUPPORT NOW**
- **What:** Unlinkable selective disclosure over VC claims.
- **Touchpoint:** The AID uses a `bbs-2023`-shaped cryptosuite
  (`vet/selective_disclosure.py`) under an ML-DSA-65 base proof.
- **Disposition:** Support now — in-tree; underpins SD-Card and the AID
  presentation derivation.

### 5.2 ZKP for compliance / W3C VC ZKP selective disclosure — **TRACK → build beyond (Scope-Exclusion Proof, Phase 2)**
- **What:** "Prove a credential satisfies a predicate in zero-knowledge" — the
  ZK-compliance category (ZK-KYC, EU-wallet data-minimization).
- **Touchpoint:** The **Consent-Grant Prohibited-Scope Exclusion Proof** emits a
  zero-disclosure proof that a granted scope set is *disjoint from*
  `CRITICAL_SCOPE_STEMS` (the tenant-control scopes) without revealing the scope
  set, on the verified `zk_fuse.py` Pedersen/HVZK-Sigma toolkit.
- **Disposition:** Track the category; build the disjointness-from-prohibited-
  class statement nobody ships. **Crypto maturity stated honestly: research-early,
  pre-quantum, unaudited; "counterparty-verifiable" is a roadmap target, not a
  shipped guarantee.** Note: the in-tree `negative_knowledge.py` accumulator is
  explicitly **not** ZK — build the genuine path on `zk_fuse`, not on it.

---

## 6. Evidence, transparency & cross-org anchoring (how it stays *provable*)

This is the conduit moat layer. Highest-conviction support tier — these are the
audit/evidence wire formats regulators and insurers will demand, and they are
already further along in-tree than any competitor.

### 6.1 IETF SCITT (`draft-ietf-scitt-architecture`) + COSE Receipts (`draft-ietf-cose-merkle-tree-proofs`) — **SUPPORT NOW**
- **What:** Supply Chain Integrity, Transparency and Trust — register a Signed
  Statement to a Transparency Service, receive a COSE Receipt with a Merkle
  inclusion proof that any auditor verifies *without trusting the issuer*.
- **Touchpoint:** `vet/scitt.py`, `evidence/scitt_statement.py`,
  `evidence/scitt_cose_alg.py`. Every Tex decision and AID can be registered as a
  COSE_Sign1 Signed Statement; conduit's consent receipts and inventory snapshots
  ride the same surface. No AI-governance vendor as of mid-2026 ships per-decision
  SCITT registration.
- **Disposition:** Support now — load-bearing. This is how a conduit
  `ConsentReceipt` or `provenance_snapshot` becomes independently auditable.

### 6.2 COSE (RFC 9052/9053) + COSE_Sign1 — **SUPPORT NOW**
- **What:** CBOR Object Signing and Encryption — the signature envelope SCITT and
  C2PA ride on.
- **Touchpoint:** `c2pa/` and `evidence/scitt_cose_alg.py` produce COSE_Sign1
  statements; ML-DSA-65 algorithm IDs are wired into the COSE alg registry.
- **Disposition:** Support now — the universal seal envelope; non-negotiable.

### 6.3 RFC 3161 Time-Stamp Authority (external anchoring) — **SUPPORT NOW**
- **What:** A TSA signs a timestamp token over a hash, proving "this existed no
  later than `genTime`" against an authority *independent of Tex's key*.
- **Touchpoint:** `interchange/external_anchor.py` submits the `gix` RFC 9162
  Merkle tree-head to an RFC 3161 TSA and **verifies the TSA's CMS signature
  against a pinned cert offline** (verified live against `freetsa.org`). Conduit
  seals each inventory snapshot as a point-in-time externally-anchored attestation
  (**discovery-as-provenance**). **The CMS-signature verification is the proof** —
  a same-shaped token whose signature is never checked proves nothing (the
  `nanozk` failure this module exists to never repeat; note `c2pa/timestamp.py`
  deliberately does *not* verify the CMS sig and is not the moat path).
- **Disposition:** Support now — Phase 1; the un-backfillability anchor.

### 6.4 RFC 9162 (Certificate Transparency / Merkle tree-head) + transparency-log checkpoints — **SUPPORT NOW**
- **What:** Signed, append-only Merkle log checkpoints (origin / size / root).
- **Touchpoint:** `interchange/gix.py` `CheckpointPublisher.current_signed_checkpoint()`;
  AVC publishes revocation leaves into this log and downstream verifiers prove
  non-revocation against the latest signed checkpoint offline.
- **Disposition:** Support now — the in-tree transparency-log substrate.

### 6.5 Sigstore (Fulcio / Rekor) — **TRACK**
- **What:** Keyless signing + public transparency log for software artifacts.
- **Touchpoint:** Conceptually adjacent to `gix` + SCITT; Rekor is a public
  append-only log.
- **Disposition:** Track — Sigstore is artifact/CI-signing-shaped (ephemeral OIDC
  identities, public-good log). Tex's evidence chain is governance-decision-shaped
  with long-lived PQ keys and per-tenant residency; we do **not** put governance
  receipts in a public Rekor instance. Track Sigstore's transparency-log design
  (and its C2SP `tlog-witness` work, which directly informs §6.7) rather than
  adopting Fulcio/Rekor for the decision chain.

### 6.6 C2SP `tlog-witness` / transparency.dev witness cosigning — **TRACK → build beyond (Adverse-Interest Quorum, research)**
- **What:** Independent witnesses cosign a log's checkpoint to detect a split-view
  / equivocating log.
- **Touchpoint:** `interchange/gix_witness.py` (C2SP cosigning, currently
  `federated=False`). The **Threshold-Witnessed Decision Anchoring** moat goes
  beyond: a finalize-*gating* quorum whose signers have interests *adverse* to the
  platform operator (customer, insurer, regulator), so `recorder.py` cannot
  finalize until the adverse quorum cosigns.
- **Disposition:** Track the witness-cosigning standard; build the
  before-finalize + adverse-interest binding no shipping system has. **The
  adverse-interest property is a fact about the world and stays structurally
  un-asserted in code until real counterparties hold keys** — promote to SUPPORT
  the day an independent customer/insurer witness is stood up (flips
  `federated=False → True`).

### 6.7 SCITT Attestation Reconciliation Protocol (`draft-hillier-scitt-arp`) — **TRACK**
- **What:** Deterministic, bilateral, ZK-capable reconciliation of verification
  claims across sovereign registers without raw records leaving their
  data-residency jurisdiction (built for EU AI Act ↔ NIST AI RMF ↔ UK AISI).
- **Touchpoint:** `zkprov/scitt_arp.py`. The cross-border reconciliation substrate
  under the Inter-Tex Governed Handshake (§6.8) and cross-tenant danger-manifold.
- **Disposition:** Track — in-tree as a draft surface; matures into a SUPPORT when
  cross-jurisdiction reconciliation is a live customer requirement.

### 6.8 Inter-org agent-governance handshake (no standard exists yet) — **TRACK / propose**
- **What:** There is **no** published standard for bilateral agent-governance
  adjudication across org boundaries. A2A = identity only; SCITT = single-issuer;
  Entra Agent ID = tenant-supremacist; SPIFFE = authN federation.
- **Touchpoint:** The **Inter-Tex Governed Handshake (IGH)** runs a bounded
  challenge-response over SCITT-shaped signed statements with a **joint abstention
  quorum** (PERMIT only if both certify non-FORBID; either ABSTAIN → shared sealed
  abstention certificate with cross-log inclusion proof; disagreement → verdict-
  lattice meet = FORBID, fail-closed). Built on verified `vet/scitt.py`,
  `vet/selective_disclosure.py`, and pinned-TSA anchoring; the verdict-lattice
  *meet* is net-new (shared with AVC).
- **Disposition:** Track the empty standards space and **propose** into it; the
  protocol is single-tenant-testable now against a simulated peer, with
  `federated=True` gated on standing up a genuinely independent counterparty.

---

## 7. Governance, NHI & agentic-security guidance (the frameworks we *map to*)

These are not wire formats but the control frameworks customers/auditors cite.
Conduit's job is to *emit evidence that maps cleanly* to them.

### 7.1 NIST AI RMF + Generative-AI Profile (NIST AI 600-1) — **SUPPORT NOW (map)**
- **Touchpoint:** AID compliance assertions name the regimes an agent is
  registered against; conduit's sealed discovery + consent receipts are the
  Govern/Map/Measure/Manage evidence.
- **Disposition:** Support now as a mapping target — Tex evidence is structured so
  an auditor can trace a decision to RMF functions.

### 7.2 CSA Non-Human Identity (NHI) guidance + agentic-AI security work — **SUPPORT NOW (map)**
- **Touchpoint:** Conduit is *literally* an NHI-discovery-and-governance front
  door — it normalizes service principals / OAuth clients / service accounts (the
  NHI class CSA names) and never touches users. This is the framework conduit's
  one-liner should cite.
- **Disposition:** Support now — the closest-fit framing for the product;
  conduit's `DiscoveryRiskBand` + consent-graph blast-radius is the NHI-risk
  inventory CSA guidance calls for, plus the sealed-grant receipt nobody else has.

### 7.3 OWASP — Top 10 for LLM Applications + Agentic Security Initiative / Agentic Threats — **SUPPORT NOW (map)**
- **Touchpoint:** MCP-injection and over-permissioned-grant threats map to OWASP
  agentic threat classes; the in-tree MCP threat specialists and the consent-graph
  over-permission signal are the controls. OWASP's blast-radius guidance is
  design-time/binary — the **Pre-Emptive Cascade Envelope** (probabilistic forward
  blast-radius gated at the PDP) goes beyond it.
- **Disposition:** Support now as a mapping target; build beyond the binary
  blast-radius guidance.

### 7.4 NIST SP 800-207 (Zero Trust Architecture) — **TRACK (map)**
- **Touchpoint:** Tex's per-action PDP + PEP is a ZTA policy-decision point for
  agents; conduit feeds it the agent inventory.
- **Disposition:** Track as a positioning/mapping frame (PDP/PEP terminology),
  not a build item.

### 7.5 EU AI Act (Art. 50 transparency; high-risk obligations) + MiFID II / GDPR audit needs — **TRACK (map)**
- **Touchpoint:** SCITT-VCP profile (`draft-kamimura-scitt-vcp`) targets nanosecond
  timestamps for EU AI Act + MiFID II and crypto-shredding for GDPR; AID carries
  EU-AI-Act-Article-50 registration assertions.
- **Disposition:** Track per-jurisdiction obligations as evidence-shape
  requirements; the sealed/anchored receipt chain is already the right substrate.

### 7.6 Five Eyes "Securing Agentic AI" joint guidance (Apr 2026) — **SUPPORT NOW (map)**
- **Touchpoint:** Directly motivates §3.3 (VCs + short-lived OAuth tokens). Tex's
  AID + Txn-Token packaging satisfies the stated requirement.
- **Disposition:** Support now as a mapping target — already implemented.

### 7.7 ISO/IEC 42001 (AI management system) + SOC 2 / HIPAA — **TRACK (map)**
- **Disposition:** Track — AID compliance assertions enumerate these regimes;
  they are attestation targets, not protocols to implement.

---

## 8. Explicitly out of scope (IGNORE — recorded decisions)

| Standard / area | Why ignored for conduit |
|---|---|
| **SAML 2.0** | User-SSO federation; conduit governs NHI/agents, not user logins. |
| **OIDC end-user authentication flows** | User authN; conduit uses OIDC/OAuth only for *its own* read-only service auth to IdPs, not to authenticate end users. |
| **FIDO2 / WebAuthn / Passkeys** | Human authenticator standards — orthogonal to agent/NHI governance. |
| **GNAP (RFC 9635)** | See §3.5 — negligible IdP adoption; re-evaluate only on native IdP support. |
| **Public Sigstore Fulcio/Rekor for the decision chain** | See §6.5 — wrong trust/residency model for governance receipts; track the design, don't adopt the public instances. |
| **OPA/Rego as the policy engine** | Tex's PDP is a 3-valued governance engine with a sealed evidence spine; a Rego rules engine is a different abstraction. (AuthZEN §3.6 is the interop seam, not OPA itself.) |
| **Generic SIEM/UEBA anomaly-score formats** | 0–1 scores with no coverage guarantee are exactly the non-e-process shape the risk spine excludes; the Conformal Drift Baseline replaces them with anytime-valid e-values. |

---

## 9. One-screen disposition summary

| # | Standard | Disposition |
|---|---|---|
| 1.1 | Microsoft Graph + OAuth client-credentials (Entra) | **SUPPORT NOW** |
| 1.2 | Okta Management API + OAuth | **SUPPORT NOW (Phase 0)** |
| 1.3 | Google Workspace Admin SDK / Service Accounts | **SUPPORT NOW (Phase 0)** |
| 1.4 | Ping (PingOne / PingFederate) OAuth | **SUPPORT NOW (Phase 0)** |
| 1.5 | SCIM 2.0 (RFC 7643/7644) | TRACK |
| 2.1 | W3C Verifiable Credentials 2.0 | **SUPPORT NOW** |
| 2.2 | W3C DID (did:web / did:key) | TRACK |
| 2.3 | SD-JWT VC + SD-Card | **SUPPORT NOW** |
| 2.4 | SPIFFE / SVID | TRACK |
| 2.5 | Entra Agent ID (GA Jun 2026) | **SUPPORT NOW (consume) / contest** |
| 3.1 | OAuth 2.0/2.1 consent grant | **SUPPORT NOW** |
| 3.2 | OAuth Token Exchange (RFC 8693) | TRACK |
| 3.3 | OAuth Transaction Tokens for Agents | **SUPPORT NOW** |
| 3.4 | OAuth RAR (RFC 9396) | TRACK |
| 3.5 | GNAP (RFC 9635) | IGNORE |
| 3.6 | OpenID AuthZEN 1.0 | TRACK (fast-follow adapter) |
| 4.1 | MCP | **SUPPORT NOW** |
| 4.2 | A2A + Signed Agent Cards | **SUPPORT NOW (consume) / TRACK (bus)** |
| 4.3 | Attenuating delegation tokens (macaroons/biscuit/niyikiza) | TRACK → build beyond (AVC) |
| 4.4 | Intent pre-commitment (AP2 / intent-binding) | TRACK → build beyond (IBCT/SICC) |
| 5.1 | BBS / `bbs-2023` selective disclosure | **SUPPORT NOW** |
| 5.2 | ZKP-for-compliance / VC ZKP | TRACK → build beyond (Scope-Exclusion Proof) |
| 6.1 | IETF SCITT + COSE Receipts | **SUPPORT NOW** |
| 6.2 | COSE / COSE_Sign1 (RFC 9052) | **SUPPORT NOW** |
| 6.3 | RFC 3161 TSA external anchoring | **SUPPORT NOW** |
| 6.4 | RFC 9162 Merkle checkpoints / gix | **SUPPORT NOW** |
| 6.5 | Sigstore (Fulcio/Rekor) | TRACK |
| 6.6 | C2SP tlog-witness cosigning | TRACK → build beyond (Adverse-Interest Quorum) |
| 6.7 | SCITT ARP (`draft-hillier-scitt-arp`) | TRACK |
| 6.8 | Inter-org governance handshake (no standard) | TRACK / propose (IGH) |
| 7.1 | NIST AI RMF / AI 600-1 | SUPPORT NOW (map) |
| 7.2 | CSA NHI + agentic guidance | **SUPPORT NOW (map)** |
| 7.3 | OWASP LLM Top 10 / Agentic Threats | SUPPORT NOW (map) |
| 7.4 | NIST SP 800-207 ZTA | TRACK (map) |
| 7.5 | EU AI Act / MiFID II / GDPR | TRACK (map) |
| 7.6 | Five Eyes Securing Agentic AI | SUPPORT NOW (map) |
| 7.7 | ISO/IEC 42001 / SOC 2 / HIPAA | TRACK (map) |
| 8 | SAML, OIDC user-authN, FIDO2/WebAuthn, GNAP, public Rekor, OPA-as-engine, SIEM scores | IGNORE |

**Governing principle.** Support the *evidence-and-identity* layer aggressively
(SCITT, COSE, RFC 3161/9162, VC 2.0, SD-JWT VC, Txn-Tokens, the OAuth consent
grant) — it is the moat and it is already in-tree. Track the *authorization-
protocol* layer (AuthZEN, RFC 8693, RAR, attenuating/intent tokens, A2A bus) — it
is converging, and in several places conduit deliberately builds *beyond* the
draft rather than merely conforming. Ignore the *user-IAM and pure-transport*
standards — they are not conduit's problem. And keep every external-world claim
(federation, adverse independence) structurally un-asserted in code until a real
counterparty exists.

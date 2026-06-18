# KICKOFF — Build `tex-conduit`: one read-only "Connect your directory" button that turns any IdP into a sealed, blast-radius-scored agent inventory

> Paste this whole file into a fresh Claude Code thread. It assumes you have **no** prior context. Read it top to bottom before touching code.

---

## 0. How to work with me (read this first — it changes how you should behave)

I'm the founder. I am not going to read a wall of code. Work this way:

- **Plain language.** Explain what you're about to do and why, in a sentence or two, before you do it. No jargon dumps.
- **One small step at a time.** Do the smallest thing that moves us forward, show me it works, then propose the next step. Do **not** scaffold twelve files and disappear.
- **Lead with the vision, then show the proof.** Every step should connect back to *why* (below). The receipt/test passing is the proof, not the pitch.
- **Confirm it actually works.** Never tell me something is "done" unless you ran it and saw it pass. Show me the command and the output. If you can't verify it, say so plainly.
- **NEVER fake discovery.** This is the cardinal rule. Do not plant a tag, hardcode a "known agent," seed a fixture so the demo looks good, or otherwise spoon-feed the discovery layer the answer. Discovery has to *actually find* agents from real directory data shapes. If something can only be made to "work" by faking the input, stop and tell me — that's a real finding, not a thing to paper over. A planted tag is a lie we'd be shipping to a customer's auditor.

When in doubt: smaller step, plainer words, show me it ran.

---

## 1. The vision (this is the soul — never flatten it)

**Tex is the first voice of AI.** It is an AI-agent **governance** engine.

Two jobs:

1. **Discover every AI agent / non-human identity (NHI)** in an organization — by reading the company's identity provider (Microsoft Entra, Okta, Google, Ping, …) plus audit logs.
2. **Rule on every consequential action an agent takes** — **PERMIT / HOLD-for-a-human / FORBID** — and seal each ruling with a **tamper-proof cryptographic receipt**.

The UX is a white screen that stays silent until an action needs a human's approval.

**The moat:** a human-resolved **ABSTAIN (hold)** flywheel, sealed into an **externally-anchored, un-backfillable evidence chain**. Discovery and decisions become tamper-evident provenance that compounds over time. You cannot rewrite the history — not even as the operator.

**Where everyone else stops (and why this is whitespace):**

- **Incumbents** (Okta, Entra/Agent 365, Ping, SailPoint, CyberArk, Saviynt) all converged on the same story: give the agent an identity, discover shadow agents, assign a human owner, govern the lifecycle. They enforce at **connection/token-exchange time** and then **log**. Their "runtime" means *authorize the access*. None adjudicate the individual **action** (issue this refund, delete this record, send this email). And their evidence is a **tenant-internal, admin-configurable, single-vendor audit log** — even Purview's "immutable chain of custody" is operator-mutable retention inside Microsoft's own tenant. Nobody externally anchors it. Each incumbent governs only its **own** IdP estate — none can be a **neutral cross-IdP layer** without dissolving their directory lock-in.
- **Human-directory unifiers** (WorkOS, Merge) productized "connect any directory" — but they surface **USERS and GROUPS via SCIM**. They explicitly do **not** surface the service principals / app registrations / OAuth clients / service accounts that **ARE the agents** Tex governs. Confirmed gap.
- **NHI startups** split the problem (IdP-anchored discoverers stop at logs; MCP-layer vendors do no IdP discovery) and are being **absorbed into single-vendor stacks** (Astrix→Cisco, Entro→SailPoint, Natoma→Snowflake). "Your evidence shouldn't be locked to one acquirer's stack."
- **Receipt vendors** (LedgerProof, Nobulex) anchor generic per-document receipts but are **not directory-aware** — no connect button, no consent grant, no agent inventory to seal.

**The thesis nobody else occupies** is the *combination*, not any single primitive:

1. One read-only button over four heterogeneous authorization dances,
2. cross-IdP normalization of **AGENT/NHI** objects (not users) into one blast-radius-scored record,
3. **sealing the CONNECTION GRANT ITSELF** as the first un-backfillable receipt (everyone else at most seals *outputs*), and
4. **sealing the discovery INVENTORY SNAPSHOT** as a point-in-time externally-anchored attestation,

all feeding Tex's per-action PERMIT/HOLD/FORBID + abstain flywheel that the IdPs structurally don't occupy.

The two **load-bearing differentiators** are **"seal the grant"** and **"discovery-as-provenance."** Everything else is necessary plumbing the incumbents give away. Build accordingly.

Regulatory tailwind, dated: **EU AI Act enforcement is live Aug 2, 2026** (Arts. 10/12/50 + Annex IV) and is being read as requiring **runtime proof that governance held at the moment the AI acted**. Incumbents answer with logs. Tex answers with externally-anchored receipts. That's the wedge.

---

## 2. The goal, and the definition of done

**Goal:** a universal **"Connect your directory"** capability — ONE button that lets any client grant Tex **read-only, least-privilege** access to whatever identity directory they use, after which Tex discovers their **non-human / agent** identities and feeds them into the existing governance + evidence pipeline — and seals the connection and the inventory as tamper-evident provenance.

This work is named **`tex-conduit`** and lives **inside the existing Tex repo** as a new package (`src/tex/discovery/conduit/`). It does **not** reinvent the connector framework, the reconciliation engine, the ledger, the scheduler, or the seal stack — it **composes** them.

**Definition of done (the whole initiative — we get there phase by phase, not at once):**

1. **Entra is migrated** to a generalized, profile-driven connector with **zero behavior change** (proven by the existing tests still passing).
2. **Okta works for real** — discovers agent-bearing OAuth clients / service accounts / app grants from Okta `/api/v1` behind the same Protocol, and assigns the **same** CRITICAL/HIGH risk bands the Entra path does. This is the cross-IdP neutrality proof.
3. **The connection grant is sealed** as the first receipt (`GRANT_SEALED`) *before any agent is read*, and a later scope drift **fails the scan closed** (`CONNECTION_DRIFT`).
4. **The inventory snapshot is sealed** (`INVENTORY_SNAPSHOT_SEALED`) — a Merkle root over the exact set of agents at time T, externally anchored.
5. **A one-command offline verifier** (`scripts/verify_conduit_receipt.py`) lets a third party check a receipt **without trusting Tex**.
6. Google + Ping follow the same shape. Shadow correlation (acted-but-never-registered agents) is explicit, net-new code.
7. Everything is **read-only, least-privilege, continuous (delta), fail-closed**, and downstream (reconciliation/ledger/ignition/governance) is **untouched**.

We are done with a *phase* when its verification step (Section 7) passes and I've seen it run.

---

## 3. Where the code lives, and exactly what to reuse

**Repo:** `/Users/matthewnardizzi/dev/tex` (Python 3.12, `src/` layout, package root `src/tex/`). Work on a feature branch, not `main`.

Before writing anything, **read these real files** — they are the contract you build against. (Confirmed present as of this writing.)

| What | Path | Why it matters |
|---|---|---|
| Connector contract | `src/tex/discovery/connectors/base.py` | `DiscoveryConnector` **Protocol** + `BaseConnector` (ABC). A connector's only method is **`scan(context) -> Iterable[CandidateAgent]`**; `BaseConnector` subclasses implement **`_run_scan`**. A connector's ONLY job is to emit `CandidateAgent` records — it must **not** mutate the registry, write the ledger, or promote candidates. |
| Reference live connector | `src/tex/discovery/connectors/entra_consent_graph.py` | `EntraConsentGraphConnector(BaseConnector)`. Walks Graph `servicePrincipals` + `oauth2PermissionGrants` + `appRoleAssignments`, builds a consent graph, computes blast radius, emits one `CandidateAgent` per agent-bearing principal. Note `_looks_like_agent(sp)` and the call into `blast_radius()`. Its docstring already says it generalizes to "Okta — same shape." |
| Consent graph + risk | `src/tex/discovery/consent_graph.py` | `blast_radius(principal_id)`, plus `HIGH_RISK_SCOPE_STEMS` (substring stems — **portable** across providers) and `CRITICAL_SCOPE_STEMS` (literal Entra permission strings — **NOT portable**, each provider needs its own curated set). |
| Transport Protocol | `src/tex/discovery/graph_transport.py` | `GraphTransport` Protocol = **`get_paginated(path, params)`** + **`get_delta(path, delta_link)`**. `LiveGraphTransport` (client-credentials auth, `@odata.nextLink` pagination, 429/Retry-After backoff, delta links) and `FixtureGraphTransport` (tests, no live tenant). Okta `/api/v1` is the **same shape** behind this Protocol. |
| Domain model | `src/tex/domain/discovery.py` | `CandidateAgent` (fields: `source`, `tenant_id`, `external_id`, `name`, `owner_hint`, `description`, `risk_band`, `confidence`, `capability_hints` = `DiscoveredCapabilityHints`, `last_seen_active_at`, `evidence` dict, `tags`, …) and the **`DiscoverySource`** StrEnum. **Its own docstring mandates: add a new enum member per platform — never reuse one — because `reconciliation_key` is composed partly from the source, and conflating platforms corrupts it.** |
| Reconciliation | `src/tex/discovery/reconciliation.py` | `ReconciliationEngine` — promote / drift / quarantine. Keyed on `reconciliation_key`. **Do not touch this.** Conduit emits ordinary `CandidateAgent`s into it unchanged. |
| Ignition | `src/tex/api/discovery_surface_routes.py` (prefix `/v1/surface/discovery`) | The operator's "Begin": `POST /v1/surface/discovery/ignite` runs discovery + activates governance. Conduit's connect flow precedes ignition; ignition stays as-is. |
| Seal stack | `src/tex/interchange/gix.py`, `src/tex/interchange/external_anchor.py` | The **verified-correct** seal path: `CheckpointPublisher.current_signed_checkpoint()` (transparency-log checkpoint) anchored via `external_anchor.py`'s **RFC 3161** path, which **actually verifies the TSA CMS signature against a pinned cert** (offline). **Use this. Do NOT use `c2pa/timestamp.py`** — its docstring states it builds/parses RFC 3161 but does not verify the TSA signature (the exact "timestamp-shaped object that doesn't deliver the timestamp property" failure this project exists to never repeat). |
| Verifier pattern | `scripts/verify_it_yourself.py` | The existing one-command, offline, "don't trust Tex" verifier. Mirror its shape for `scripts/verify_conduit_receipt.py`. |
| Empty Okta stub | `src/tex/_pending/interop/okta/agent_identity_sync.py` | Essentially empty. Phase 1 realizes this as a real Okta transport + connect strategy. |
| Behavioral / shadow | `src/tex/discovery/connectors/cloud_audit_ocsf.py`, `src/tex/discovery/ocsf.py` | The OCSF audit connector pattern — behavioral / shadow-agent catch from audit logs (`source=CLOUD_AUDIT`). Reused for the behavioral plane per provider. |

**Hard reuse rules:**
- `LiveGraphTransport` and `FixtureGraphTransport` are **untouched**. Every new transport is unit-testable with **fixtures and no live tenant**.
- The reconciliation engine, ledger, scheduler, and ignition are **untouched**.
- New seal event kinds must **avoid the ATTEMPT/DECISION conservation counters** — model them like the deliberately-separate `VERDICT_TRANSCRIPT` kind (grep for how that one stays out of the counters, and copy that discipline).

---

## 4. The architecture (what you are building)

`tex-conduit` is a new package under `src/tex/discovery/conduit/` that sits **entirely in front of** the existing connector Protocol and **behind** the existing seal/anchor stack. Five layers, data flowing left → right:

**(1) Connect broker + per-provider connect strategies** — `conduit/broker.py`, `conduit/providers/{base,entra,okta,google,ping}.py`
One UX button backed by a registry of `ConnectStrategy` objects, each implementing three methods: `begin_consent(tenant) -> ConsentChallenge`, `finalize_consent(callback) -> DirectoryGrant`, `build_transport(grant) -> GraphTransport`. This is the **only** place the four divergent authorization dances live. The broker is a four-state machine **REQUESTED → CONSENTED → PROBED → SEALED** and **never holds long-lived secrets** — it persists an opaque `connection_id` pointing at the deployment secret store (mirroring how `LiveGraphTransport` already takes credentials from config).
**Honesty discipline (a requirement, not a nicety):** the button is *"one entry point," not "one click."* Entra is a true one-click admin-consent redirect. Okta is service-app + private-key-JWT + a per-scope grant checklist the broker verifies landed. Google is explicitly **TWO** read grants (Workspace domain-wide-delegation allow-list + GCP org-viewer) shown as a two-step checklist in one modal — **never** marketed as one OAuth click. Ping is per-deployment service-account config. **Fail-closed:** any requested-but-not-granted scope yields a **DEGRADED** `DirectoryGrant` that records the gap rather than silently proceeding.

**(2) DirectoryGrant + the FIRST seal** — `conduit/grant.py`, `conduit/seal.py`
`DirectoryGrant` is a frozen domain object: provider, tenant/org id, the **exact canonicalized+sorted scope set granted**, the consent-artifact id the provider returned (Entra admin-consent grant id / Okta service-app id / Google DWD client id / Ping service-account id), `consented_by`, `granted_at`, and a `credential_ref` (**never** the secret). The moment `finalize_consent` succeeds, the broker seals a **`GRANT_SEALED`** provenance event **through the existing seal stack** (`CheckpointPublisher.current_signed_checkpoint()` + `external_anchor.py` RFC 3161). The customer gets a cryptographic receipt of exactly what least-privilege read access they granted, when, by whom — **before any agent is read.** From the sealed grant falls out **`CONNECTION_DRIFT`**: on each later scan, if the provider's live scope set diverges from the sealed grant (silent escalation/revocation), the connector **refuses to scan** and seals a drift fact. A self-auditing connection. **This is the headline differentiator nobody ships.**

**(3) Provider transports behind the UNCHANGED `GraphTransport` Protocol** — `conduit/transport/{okta,google,ping}_transport.py`
`graph_transport.py` already abstracts `get_paginated` + `get_delta` and its docstring already says "Okta `/api/v1` is the same shape." `OktaTransport` (cursor pagination via `Link rel=next`; System Log polling for delta). `GoogleWorkspaceTransport` + `GoogleIamAssetTransport` (`pageToken`; Cloud Asset Inventory for org-wide service accounts; Reports token-audit for behavioral). `PingTransport` (pluggable `base_url`). Entra's `LiveGraphTransport` and the test `FixtureGraphTransport` are **untouched**.

**(4) Generalized consent-graph connector + ProviderProfile** — `conduit/connector.py`, `conduit/profiles/*.py`
ONE shared `ProviderConsentGraphConnector(BaseConnector)` parameterized by `(transport, ProviderProfile)`. A `ProviderProfile` is a **declarative dataclass**: which collection paths hold agent-bearing principals, which hold grant edges, a `ConsentEdgeMapper` turning one native grant row into a `ConsentEdge`, and a **provider-neutral high-risk-scope predicate**.
**Critical correctness point:** the risk taxonomy is **NOT reused unchanged.** `HIGH_RISK_SCOPE_STEMS` (readwrite/manage/write/send/delete/impersonation substrings) **ARE** portable. But `CRITICAL_SCOPE_STEMS` are literal Entra strings — so **each ProviderProfile ships its own curated critical-scope set** (Okta super-admin/org-admin grants, GCP owner/`iam.securityAdmin` roles, Ping admin scopes) mapped onto the **same** `blast_radius()` engine. This is a **maintained cross-provider risk dictionary** (`conduit/risk_dictionary.py`) — a standing asset, honestly a maintenance liability, not a free seed.
Entra is migrated to `ProviderConsentGraphConnector(LiveGraphTransport, ENTRA_PROFILE)` as the reference, fully covered by existing `FixtureGraphTransport` tests, **preserving `_looks_like_agent()` and `blast_radius()` verbatim.** Output is ordinary `CandidateAgent`. New `DiscoverySource` members (`OKTA`, `GOOGLE_WORKSPACE`, `GCP_IAM`, `PING`) keep `reconciliation_key = source:tenant:external_id` provider-scoped and uncorrupted.

**(5) Dual-plane + explicit shadow correlation** — `conduit/shadow.py`
Each provider pairs a **control-plane** scan (the consent graph) with a **behavioral** scan (Entra signIns "performed by an AI agent", Okta System Log, Google token-audit) via the existing OCSF connector pattern. The shadow diff is **NOT free**: behavioral candidates key `external_id = resource_arn-or-principal` under `source=CLOUD_AUDIT`, structurally disjoint from control-plane `source=microsoft_graph` keys — so `reconciliation_key` can **never** auto-collide. So conduit ships an **explicit `ShadowCorrelator` as net-new code**: a per-tenant cross-namespace pass that resolves a behavioral actor handle to a control-plane principal where a deterministic join exists (shared principal id, app/client id, `owner_hint`), and flags actors that **acted but appear in no control-plane scan** as **SHADOW** agents — attached as evidence on a candidate, with confidence **differentiated per provider** (Google token audit is only 180 days, so a Google "shadow" carries lower certainty than an Entra one). Honestly labeled net-new — **not** "reconciliation does this for free."

**Downstream is untouched.** Resolved `CandidateAgent`s flow into the existing `ReconciliationEngine`, the hash-chained discovery ledger, the scheduler's standing watch, and ignition. At end of scan, `conduit/seal.py` computes a Merkle root over the sorted `CandidateAgent` set + blast radii and seals **`INVENTORY_SNAPSHOT_SEALED`** ("here is the exact set of agents that existed in your tenant at epoch T"), anchored through the same path, **batched** on churny estates so anchoring cost stays bounded. Then ignition fires and governance adjudicates the agent's next consequential action with the sealed grant + sealed inventory already attached.

**Deliberately deferred (opt-in tiers, NOT launch features):** independent external witness cosigning (`gix_witness` stays `federated=False` this wave — stated honestly as aspirational until a real third-party witness runs); OpenTimestamps Bitcoin anchoring of the periodic root; ML-DSA post-quantum seals (ECDSA floor otherwise); and a single guarded `EvidenceFold` enrichment path (A2A signed AgentCard / MCP / SPIFFE / Entra Agent ID beta) that **never** participates in identity resolution and treats any unsigned/tamper-failed card as a **risk-raising, never trust-raising** signal, with egress allow-listing and size/timeout caps.

---

## 5. The phased build plan (this is the order — do not jump ahead)

Each phase ends with a verification step (Section 7). We do not start phase N+1 until phase N's check passes **and I've seen it run.**

> **Note on ordering vs. the task brief.** The brief says "start with Okta, then onboarding, then sealing." We do exactly that *substance* — but we de-risk on working code first by migrating Entra to the shared connector in **Phase 0**. That phase ships **no new provider**; it just proves the generalization and the grant-seal spine against code that already passes its tests, so Okta in Phase 1 is a clean drop-in rather than a connector rewrite + a new IdP at once. If you'd rather see Okta sooner, say so and I'll reorder — but I recommend this.

**Phase 0 — Reference migration + grant seal (prove the spine on working code).**
Add `OKTA`/`GOOGLE_WORKSPACE`/`GCP_IAM`/`PING` to `DiscoverySource`. Build `ProviderConsentGraphConnector(BaseConnector)` + the `ProviderProfile` dataclass + `ConsentEdgeMapper`, and migrate the live `entra_consent_graph.py` to `ProviderConsentGraphConnector(LiveGraphTransport, ENTRA_PROFILE)` — **proving the abstraction against the existing `FixtureGraphTransport` tests with zero behavior change.** Implement `DirectoryGrant` + `GRANT_SEALED` sealing through `CheckpointPublisher.current_signed_checkpoint()` + `external_anchor.py` (RFC 3161 — **not** `c2pa/timestamp.py`). Add `CONNECTION_DRIFT` fail-closed. Add the new provenance event kinds **outside** the ATTEMPT/DECISION conservation counters. Ship `scripts/verify_conduit_receipt.py`. **No new provider this phase** — this de-risks the seal spine and the connector generalization on code that already works.

**Phase 1 — Okta connector (the cross-IdP neutrality proof).**
Realize the empty `_pending/interop/okta/agent_identity_sync.py` as `OktaTransport` (OAuth 2.0 service app via **client-credentials + private-key JWT — NOT a static SSWS token**) + `okta_profile.py` + a `ConnectStrategy`. Request read scopes: `okta.apps.read`, `okta.clients.read`, `okta.appGrants.read`, `okta.oauthIntegrations.read`, `okta.serviceAccounts.read`, `okta.apiTokens.read`, `okta.logs.read`. Map clients + appGrants into the **same** `ConsentGraph` so `blast_radius()` yields **identical** CRITICAL/HIGH bands. Curate the Okta critical-scope set in `risk_dictionary.py`. Surface in the UX that `okta.appGrants.read` may need Super Admin, and run a **"partial" census (sealed as partial)** if that scope is withheld — do not silently drop it. This is the phase that lets Tex truthfully claim cross-IdP neutrality.

**Phase 2 — Inventory snapshot seal + standing watch made real.**
Implement `InventorySnapshotSealer` (Merkle root over the `CandidateAgent` set, `INVENTORY_SNAPSHOT_SEALED`, batched anchoring). Wire `OktaTransport.get_delta` (System Log polling) into the scheduler — and **fix the standing-watch gap**: today `sweep_delta` returns raw dicts wired to nothing; make delta actually emit `CandidateAgent`s into a re-scan that re-seals. Each inventory-changing delta produces a fresh sealed snapshot, making continuity un-backfillable.

**Phase 3 — Explicit shadow correlation.**
Build `ShadowCorrelator` as net-new cross-namespace code: join behavioral-plane handles (`source=CLOUD_AUDIT`) to control-plane principals where a deterministic key exists; flag acted-but-never-registered actors as **SHADOW** with per-provider-differentiated confidence (Google 180-day retention lowers certainty). Wire one OCSF behavioral connector per provider via the profile's behavioral-log path. Attach shadow findings as **evidence**; do **not** pretend reconciliation does this for free.

**Phase 4 — Google + Ping + guarded EvidenceFold.**
Add `GoogleWorkspaceTransport` + `GoogleIamAssetTransport` (two grants, honestly orchestrated as a two-step sealed checklist, **both grants sealed separately**) and `PingTransport` (pluggable `base_url`; PingFederate OAuth Client Management REST or PingOne AIC). Add the guarded `EvidenceFold` enrichment (A2A JWS-verified AgentCard, MCP, SPIFFE, Entra Agent ID beta — additive) with strict egress allow-listing, size/timeout caps, and the hard rule that it **never resolves identity and never raises trust.** Entra Agent ID beta objects run **in parallel** with the legacy consent-graph walk (the floor that always works). Note: Entra Agent ID registry beta types deprecate **May 2026** into Agent 365 Agent Registry APIs — version this path and **do not hard-code beta object shapes**; fall back to the legacy walk.

**Phase 5 — Opt-in provenance tiers (deferred, not launch-blocking).**
Configuration, never a launch dependency: ML-DSA post-quantum seals auto-on where the backend is installed (ECDSA floor otherwise); independent external witness cosigning when a real third-party witness runs (`federated=False` until then, stated honestly); OpenTimestamps Bitcoin anchoring of the periodic root. Map the stack to **NIST SP 800-53 AU-10** and **EU AI Act Art. 10/12/50** language for the compliance-evidence buyer.

---

## 6. Constraints (every phase must honor all of these)

- **Read-only, least-privilege, per provider.** Request the minimum read scopes listed above and no more. No write scope ever.
- **One entry point, honestly described.** One UX button — but never claim "one click" for Okta (multi-step grant) or Google (two grants). Honesty is a product requirement here.
- **Fail-closed.** Ungranted scope → degraded grant recorded, not silent proceed. Live scopes diverging from the sealed grant → refuse the scan, seal `CONNECTION_DRIFT`.
- **Continuous.** Standing watch via `get_delta`; each inventory-changing delta re-seals a fresh snapshot.
- **Fits the Protocol.** Connectors only `scan` → emit `CandidateAgent`. They never mutate the registry, write the ledger, or promote candidates. Every transport is fixture-testable with no live tenant. Reconciliation/ledger/scheduler/ignition stay untouched.
- **Use the verified seal path** (`gix.py` + `external_anchor.py`, RFC 3161 with real CMS verification). Never `c2pa/timestamp.py`.
- **One `DiscoverySource` member per platform.** Never reuse one. `reconciliation_key` correctness depends on it.
- **NEVER fake discovery.** No planted tags, no seeded "known agents," no fixtures rigged so the demo passes. If it only works by faking input, that's a finding — surface it.

---

## 7. First small step, and how to verify each phase

### Do this first — before writing any conduit code

1. Confirm you're in the repo and on a clean branch off `main`:
   ```
   cd /Users/matthewnardizzi/dev/tex && git status && git switch -c feat/conduit-phase0
   ```
2. Run the existing discovery tests **green first**, so we have a known-good baseline (a planted-tag-free baseline) before we change anything:
   ```
   python -m pytest tests/ -k "discovery or entra or consent or transport or reconcil" -q
   ```
   Paste me the summary line. If anything is already red, stop and tell me — we fix the baseline before building on it.
3. **Read** (don't skim) the four contract files and report back to me, in plain language, in ~5 bullets: `connectors/base.py`, `entra_consent_graph.py`, `graph_transport.py`, `domain/discovery.py`. Tell me specifically: the exact `scan`/`_run_scan` signature, the `CandidateAgent` fields you'll populate, and how `blast_radius()` + the two scope-stem frozensets produce a risk band. **This read is the gate** — if any of it differs from Section 3 above, the codebase moved; tell me and we reconcile before coding.
4. Then propose the **smallest** first commit for Phase 0: I suggest **just** adding the four `DiscoverySource` members + a stub `ProviderProfile` dataclass + a failing test, and nothing else. Show me the diff, run the test, then stop.

Do not build the whole of Phase 0 in one shot. Step, show, confirm, next.

### Verification gate per phase (must run, must show me output)

- **Phase 0:** Existing Entra/consent/transport tests pass **unchanged** with Entra running through `ProviderConsentGraphConnector(LiveGraphTransport, ENTRA_PROFILE)` (proves zero behavior change). A new test seals a `DirectoryGrant`, and `python scripts/verify_conduit_receipt.py <receipt>` validates it **offline** and **fails** on a tampered byte. A `CONNECTION_DRIFT` test proves a scope mismatch refuses the scan.
- **Phase 1:** With **fixture** Okta data only (no live tenant), `ProviderConsentGraphConnector(OktaTransport-fixture, OKTA_PROFILE)` emits `CandidateAgent`s, and a known over-privileged Okta client lands in the **same** CRITICAL band the equivalent Entra case does (assert the band equality directly — that *is* the neutrality proof). Withholding `okta.appGrants.read` produces a grant sealed **as partial**, not a crash. **No tag was planted to make any agent "found"** — show me the fixture is raw Okta API shape.
- **Phase 2:** A delta fixture mutates the inventory → a fresh `INVENTORY_SNAPSHOT_SEALED` is produced whose Merkle root differs from the prior snapshot, and the verifier validates both. Show the standing-watch path actually emits candidates (not raw dicts into the void).
- **Phase 3:** A behavioral fixture actor with no control-plane match is flagged **SHADOW** with the documented per-provider confidence; one with a matching client id is correlated to its control-plane principal, not double-counted.
- **Phase 4:** Google's two grants seal as two separate receipts; an unsigned/tampered AgentCard in `EvidenceFold` **raises** risk and is recorded as evidence but **never** resolves identity or raises trust. Ping discovers OAuth clients behind a pluggable `base_url`.
- **Phase 5:** Tiers toggle by config with a working ECDSA floor when PQ/witness/Bitcoin tiers are off; nothing in Phases 0–4 regresses.

For every phase: the bar is **"I ran it, here's the command, here's the passing output, and here's the one tamper/negative case proving it isn't faked."**

---

## 8. Open questions to raise with me (don't silently decide these)

1. **Shadow join quality:** when no deterministic key links a behavioral actor to a control-plane principal, do we surface every unjoined actor as a candidate SHADOW (noisy) or hold it ambiguous? Needs a per-provider join-confidence threshold — ask me.
2. **`okta.appGrants.read` needs Super Admin**, which dents the least-privilege headline on our flagship second provider. Default to the degraded "apps+clients only, sealed as partial" census, or push customers to Super Admin? Product call.
3. **The cross-provider critical-scope dictionary is a standing maintenance liability** (Okta scopes, GCP roles, Ping scopes have no clean isomorphism to Graph permissions). Who owns keeping it current, and how do we audit drift in the dictionary itself?
4. **Entra Agent ID beta types deprecate May 2026** → Agent 365 Agent Registry APIs. The enrichment path needs versioning + graceful fallback to the legacy walk.
5. **Inventory-snapshot batching cadence** trades freshness ("what existed at T") against anchoring cost — what batch interval keeps the per-snapshot proof meaningful without unbounded TSA calls?
6. **The "you don't have to trust Tex" witness claim is aspirational** until a real external witness runs (`gix_witness` is `federated=False` this wave). Lining up a first independent witness (a design partner's own auditor) is go-to-market, not a code task — flag it, don't fake it.

---

## 9. Standards to build toward (consume, don't rebuild)

- **OAuth 2.1 client-credentials + private-key JWT** (Okta service app, Ping) — rotatable, least-privilege, never static SSWS.
- **Microsoft Graph read-only triad:** `Application.Read.All` + `DelegatedPermissionGrant.Read.All` + `AuditLog.Read.All` under multi-tenant admin consent; Entra Agent ID beta `AgentIdentity.Read.*` as **additive enrichment only**.
- **Okta read scopes** (Section 5, Phase 1).
- **Google:** Cloud Asset Inventory (`cloudasset.googleapis.com`) org-wide SA enumeration + Admin SDK tokens + Reports token-audit (`admin.reports.audit.readonly`), via domain-wide delegation + GCP org-viewer — **two grants, never one click**.
- **RFC 3161** TSP via the verified `external_anchor.py` path (CMS signature actually verified against a pinned TSA cert) — **not** `c2pa/timestamp.py`.
- **C2SP `tlog-checkpoint` + `signed-note`** (Ed25519 at launch) via the existing `interchange/gix.py` transparency log; design the receipt format so a `signed-note` PQ type (ML-DSA-44) is a drop-in later with no format change.
- **OpenID AuthZEN-shaped** decision output downstream so Tex stays a drop-in PDP — consumed by governance, **not** built in conduit.
- **Deferred/opt-in:** FIPS 204 ML-DSA seals, C2SP `tlog-witness` independent cosigning, OpenTimestamps Bitcoin anchoring; A2A AgentCard JWS/JCS (RFC 7515/8785) verification in the guarded `EvidenceFold`.

---

## 10. Repo tree you're working toward (build it incrementally, not all at once)

```
src/tex/discovery/conduit/__init__.py
src/tex/discovery/conduit/broker.py
src/tex/discovery/conduit/grant.py
src/tex/discovery/conduit/connector.py
src/tex/discovery/conduit/shadow.py
src/tex/discovery/conduit/seal.py
src/tex/discovery/conduit/evidence_fold.py
src/tex/discovery/conduit/risk_dictionary.py
src/tex/discovery/conduit/providers/{__init__,base,entra,okta,google,ping}.py
src/tex/discovery/conduit/profiles/{__init__,entra_profile,okta_profile,google_profile,ping_profile}.py
src/tex/discovery/conduit/transport/{__init__,okta_transport,google_transport,ping_transport}.py
src/tex/api/conduit_routes.py
tests/discovery/conduit/__init__.py
tests/discovery/conduit/test_broker_state_machine.py
tests/discovery/conduit/test_grant_seal_and_drift.py
tests/discovery/conduit/test_okta_profile_blast_radius.py
tests/discovery/conduit/test_shadow_correlator.py
tests/discovery/conduit/test_inventory_snapshot_seal.py
tests/discovery/conduit/fixtures/{okta_apps,okta_grants,entra_servicePrincipals}.json
scripts/verify_conduit_receipt.py
docs/conduit/README.md
docs/conduit/provider-consent-matrix.md
```

---

### The one sentence to keep in your head

**They decide who an agent *is* and what it can *reach*. Tex rules on what it *does*, action by action, and seals the proof — starting with sealing the read-only directory grant itself, which nobody else does.** Everything in this build serves that. Now do the *first small step* in Section 7 and stop for my go-ahead.

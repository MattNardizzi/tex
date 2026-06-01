# Tex — Discovery & Inventory Doctrine

**Status: locked.** This is the single source of truth for Tex's discovery
and inventory layer. It captures what was settled across design, what is
built in the backend today, and what is deliberately next — so a future
thread builds from the doctrine instead of re-deriving it.

Last settled: 2026-06-01.

---

## 0. The doctrine in one line

Discovery is not something a client runs and reviews. It is the moment a
witness starts watching — and the inventory is not a list anyone has to
trust, it is a sealed, graded, continuously-grown ledger of agent births
and sightings that anyone can verify without trusting Tex.

---

## 1. The client experience (locked)

- **"Run discovery" is ignition, said once.** It is not a scan command and
  not a per-source connect ceremony. It means: *begin watching my estate.*
- On ignition Tex does the full multi-plane discovery, issues sealed birth
  certificates, takes the whole inventory into itself on the backend, and
  surfaces **exactly one line**: the count, and that it is starting —
  *"You have forty-one agents running. I'll begin."* Then the glass goes
  clean and Tex goes to work.
- After that, the inventory is **pull-only**. The client never has to ask,
  because Tex is doing the work in the dark (permit / forbid / hold). When
  the client *does* reach in, Tex answers only what was asked: "how many
  now?" → a count; "anything new since this morning?" → the delta; "who
  owns the Bedrock one?" → the owner spoken, the exact name rising and
  dissolving.
- **The trigger to break silence is never "a new thing was discovered."**
  Tex speaks first, unprompted, for only two things: a decision it is
  holding (an ABSTAIN it will not rule on alone) and its own integrity
  breaking (the faltering confession). Discovery is neither, after the
  first sentence. A feed of findings is the alert queue Tex exists to
  refuse.

---

## 2. The dormant-agent doctrine (locked)

A dormant agent is not nothing — it costs money and holds live
credentials. But it is not an interruption either. The resolution (the
Jobs 2050 move) is to make it a problem the client never has, rather than
a notification the client must process: **governance, not notification.**

- **Tex never speaks about a dormant agent.** When discovery (or the
  continuous watch) finds an agent gone idle, Tex puts it **to sleep on its
  own authority** — credentials suspended, execution halted, state
  preserved, behavioural signature frozen — and seals both the sleep and
  the wake path into the ledger. No count, no list, no notification.
- **Sleep is reversible for 90 days.** One act wakes it. An attempt to act
  while sleeping routes to **ABSTAIN**, so a wake is a deliberate, sealed
  human act rather than a silent resurrection.
- **The day-90 transition into permanent deletion (REVOKED) is the one
  irreversible step** — and so is the rare ABSTAIN that earns the held
  voice. Sleep is silent and autonomous; the final irreversible kill is the
  exception that speaks.
- **Sleep requires earned judgment.** Tex only sleeps an agent it can prove
  is safe to sleep (idle past threshold, not load-bearing as far as Tex can
  see). If Tex cannot tell whether an idle agent is load-bearing, it does
  **not** sleep it silently — that uncertain case is a genuine ABSTAIN,
  held and spoken once. The bar to act in silence is "I can defend this,"
  not "it looks quiet." The moment Tex sleeps something load-bearing and
  burns the client, the silence becomes a lie and Tex is finished.
- **On pull**, the client gets cost and cleanup: *"Nine agents idle thirty
  days, four unowned, costing about $2,100 a month."* Deleting the unowned
  ones is a held decision (a named human act), because deletion is
  irreversible.

Open build detail (not doctrine): the idle threshold before sleep (fixed
default vs learned per-estate).

---

## 3. The mechanism (locked)

The inventory is a **hash-chained ledger of births and sightings**, not
mutable state in a database. The provability of the inventory is the
product; everyone else stores current state and renders a graph.

1. **Triangulation across planes — completeness is a union property.** No
   single plane sees everything, so Tex walks several and the union
   approaches complete. The planes, ranked by admissibility (see §4):
   - Identity plane — IdP (Entra / Okta): service principals, OAuth apps,
     NHIs. One read-only grant, transitive multiplier.
   - Cloud control plane — AWS / Azure / GCP: Bedrock, SageMaker, Vertex,
     Foundry.
   - SaaS admin APIs — Copilot Studio, AgentForce, ServiceNow.
   - Network egress — DNS / proxy / VPC-flow, TLS SNI / JA3. Metadata only.
     Catches headless / CLI / server agents nothing else lists.
   - Code / CI-CD — repos, IaC, pipelines: framework fingerprints, where
     agents are born.
   - Endpoint / container — the dev-container / local-Ollama blind spot.
   - Registry / self-declaration — MCP server cards, A2A
     `/.well-known/agent.json`, Entra Agent ID, NANDA AgentFacts.
2. **Reconciliation is the engine, and the gap is the finding.** Every
   agent should appear in ≥2 planes. The symmetric difference — egress with
   no identity, a signed card no one deployed, an identity with no code —
   *is* the shadow set.
3. **Agent defined by mechanism, not an allowlist.** Causal-influence
   detection (Kenton et al., *Discovering Agents*, 2023): a system is an
   agent if it adapts its behaviour to influence outcomes. The list catches
   the obvious; the causal definition catches the novel.
4. **Birth certificates** anchored to *attested* identity (image hash,
   binary signature, behavioural signature), not claimed metadata, issued
   at first sighting as verifiable, revocable, offline-checkable
   credentials, and verified against on every later sighting.
5. **Provable coverage boundary**, graded per agent — Tex seals which
   planes it can and cannot see and states the edge of its sight.
6. **Sealed delegation graph** — discover the edges (who delegates to
   whom), not just the nodes; the agent-to-agent dark zone where blast
   radius lives.
7. **Declared-vs-observed intent** — seal the purpose at discovery; later,
   monitoring measures runtime behaviour against the sealed declaration.
   The drift is a signal nobody has, because nobody sealed the original.
8. **Continuous, never point-in-time.** Ignition starts a standing watch.
   The *sealing* happens at the instant of every sighting and never stops;
   the *speaking* never starts (see §1).

---

## 4. The trust model — admissibility (locked, the flawless layer)

The dimension the rest of the field lacks, and the one that turns the
inventory from "most complete" into "court-admissible." It is orthogonal
to privilege (`AgentTrustTier`): it grades *how forgeable the signal that
revealed the agent was*, i.e. how much the workload could have faked it.

**Signal Source Trust Hierarchy** (highest admissibility first):

1. `KERNEL_ATTESTED` — kernel-level (eBPF) observation; hardware / TEE
   attestation of measured code. The workload cannot reach this signal.
2. `AUDIT_LOG` — control-plane audit log firing outside the workload's
   reachability surface (cloud audit trail). Tamper-resistant *and*
   agentless — the sweet spot.
3. `NETWORK_OBSERVED` — out-of-process behavioural observation at a
   chokepoint: egress flow, **the enforcement gate itself.** The workload
   cannot suppress that it acted.
4. `CONTROL_PLANE` — platform / IdP API enumeration (OAuth consent,
   directory listing). Authoritative for what the platform knows, mediated
   by it.
5. `SELF_DECLARED` — the workload asserting its own existence (A2A / MCP
   card, in-process emit). Lowest admissibility: forgeable by definition.

Rules:
- **Seal the tier into every birth certificate.** A self-declared agent is
  recorded *as* self-declared, so the seal never overstates what Tex knows.
- **Prefer attested identity over claimed.** Anchor identity to measured
  code, not asserted metadata.
- **The grade is revisable.** If a TEE / attestation method is later broken
  (e.g. the 2026 partial-TEE-shielding key-reuse result), every certificate
  that relied on it can be found and re-graded. Seal the method, not just
  the verdict.

---

## 5. Behavioural provenance — identity by behaviour, sealed as proof

The discovery primitive nobody productized as of mid-2026, and the one
only a witness-with-a-gate can build. Tex stops trusting what an agent
*claims* and proves who it is by what it *does*.

- **Why:** every other product keys identity off an assertion — directory
  entry, OAuth consent, self-declared card, `(source, tenant, external_id)`
  tuple — each forgeable, rotatable, renamable, or absent for the shadow
  agent. The literature names this unsolved: self-declaration is forgeable;
  no third party attests to what an agent really is.
- **How:** derive a content-free behavioural signature (action / channel /
  verdict distributions, tool / MCP / data-scope sets, risk moments,
  cadence, and the stable prompt / tool / memory hash anchors). Compare two
  signatures into a graded same-actor confidence; anchors dominate (they
  survive credential rotation and rename), behaviour-only is capped
  (evidence, not proof). Seal each event into an append-only, hash-chained,
  **ECDSA-signed** transparency log — Certificate Transparency for agents,
  verifiable offline with only the public key.
- **Outcomes sealed:** BIRTH (new actor + verifiable certificate),
  SIGHTING (confirmed), REIDENTIFIED (same actor under a new name/key — the
  case directory identity misses), DRIFT (a known agent stopped behaving
  like itself). Every outcome carries a **graded confidence sealed beside
  the fact, never a bare claim.** Consequential, ambiguous resolutions
  (possible merge, drift past threshold) flag `requires_human` — the held
  path.
- **Its place in the planes:** behavioural provenance is fed by the
  enforcement gate, so its signal is `NETWORK_OBSERVED` (tamper-resistant).
  It is the root that survives rotation and catches the agent that never
  had a name.

---

## 6. The connection model — rooted, single-grant (locked)

The clunky model is N grants ("connect Salesforce, connect Slack, connect
this MCP"). The advanced model is rooted: the client points Tex at **one
root** and Tex walks outward and discovers the estate's topology itself.

- **The IdP root.** One read-only admin-consent grant to Entra / Okta lets
  Tex enumerate every service principal, OAuth app, and federated SaaS —
  transitively revealing the agents in Salesforce, Slack, M365, etc.,
  because they authenticate through the IdP to exist. The connectors become
  **root-driven enumerators**, not independently-authorized sources.
- **The gate root (the deepest move).** Tex's enforcement gate is the
  action chokepoint. **The inventory assembles itself from the stream of
  actions Tex is already adjudicating** — the first time any agent acts, it
  reveals itself, and Tex seals its birth in the same instant it rules on
  the action. Everyone else: discover, then govern. Tex: govern, and
  thereby discover. The egress vantage and the gate are the same placement.
- **The cost / billing root.** Spend routes back to the org even when the
  network and directory don't see it (a laptop using a corporate key). One
  read-only grant to the cost surface catches shadow and dormancy as money,
  tamper-resistant because an agent can't hide its own cost from finance.
- **The data-lake root.** For mature enterprises, one grant to the SIEM /
  security lake yields every plane at once, because the client already
  centralized the telemetry.
- **Born-governed (endgame).** If Tex issues each agent its identity at
  creation, the inventory becomes the issuance log and discovery becomes
  unnecessary for new agents. Covers greenfield, not the existing estate.

**The honest floor:** there is always at least one grant. You cannot
witness an environment you have no vantage into. Any vendor claiming true
zero-setup is lying or installing something unseen. What rooting does is
collapse the seam to the smallest, most universal, one-time vantage — and
in the gate case, the same grant Tex needs for its core job anyway.

---

## 7. Competitive position (as of 2026-05-31)

- **Zenity, Noma** — discover → dashboard. Continuous, broad, agentless;
  output is a graph / inventory table.
- **Okta for AI Agents (GA Apr 30 2026), Microsoft Entra Agent ID** —
  identity-rooted discovery via OAuth consent, working across any IdP, but
  as a **directory / control plane**: mutable state, trust-me.
- **Nobody** seals discovery as graded, provable evidence with a voice. The
  rooting is validated (the IdPs converged on it); the *witnessing of* the
  rooted discovery is open.
- **Strategy:** do not try to be the identity root — ride the IdP as Tex's
  richest root and add the layer the directory companies structurally
  can't: the sealed, graded, provable witness. Riding Okta/Entra is a
  feature, not a weakness.

---

## 8. Build status

**Root-layer upgrades (2026-06-01, built on the spine):**
- **Ignition now maps, then counts** (`/v1/surface/discovery/ignite`): on the
  first fire for a tenant it runs the full `DiscoveryService.scan`, sealing a
  behavioural birth for every agent found (engine memory engages here), then
  speaks one line — the count of the *running estate* (everything discovered
  and present, excluding the silently-slept and the revoked; a freshly-
  discovered PENDING agent is still running). Was count-only; this is the
  doctrine's §1 ignition made real. The new roots are registered in
  `_build_discovery_connectors` with live-or-seed fallback, so "click Begin"
  maps a believable estate through the real pipeline even before a customer
  grant (`tex.discovery.demo_seed`). The surface accepts an optional
  per-session `tenant_id` (anonymous/cross-tenant only) so the preview runs
  the real pipeline each visit and the day-one door replays; a real operator
  console omits it and ignites once for its own tenant.
- **Engine memory — event-sourcing rehydration** (`engine.rebuild_from_ledger`,
  `engine.snapshot`): the identity map is a projection over the sealed
  ledger and is rebuilt by replaying it on boot, so a restart resolves a
  known agent's next action as a SIGHTING, never a second BIRTH. SIGHTING /
  DRIFT / REIDENTIFIED now seal their signature into the record, and a
  discovery birth seals its anchors, so the replay is faithful. Snapshot
  resume is built but dormant (replay-from-genesis is correct at any size;
  snapshots are a perf optimization for later). Wired into boot in `main`.
- **Root one — live IdP consent-graph enumerator** (`EntraConsentGraphConnector`
  + `ConsentGraph` + `GraphTransport`): one read-only admin grant, walks
  `servicePrincipals` + `oauth2PermissionGrants` + `appRoleAssignments`,
  builds the consent graph, computes per-agent **blast radius** (transitive
  reach), emits `CandidateAgent` at CONTROL_PLANE. Delta query exposed as the
  standing watch (`sweep_delta`). I/O behind `GraphTransport`: `Live`
  (httpx, client-credentials, nextLink paging, 429 backoff, delta) vs
  `Fixture` (tests). **Live path needs a real tenant to prove; logic is
  fully unit-tested without one.** This replaces the per-platform connector
  list as the seamless one-grant core; the Graph mock is kept for tests.
- **Root two — OCSF audit plane** (`OcsfAuditConnector` + `tex.discovery.ocsf`):
  consumes OCSF-normalized events (Security Lake) or raw CloudTrail via the
  adapter, groups by acting agent, emits `CandidateAgent` at AUDIT_LOG. One
  parser for every OCSF-speaking SIEM; catches the shadow agent the consent
  graph misses, as actions it cannot suppress. Injectable source; fixture-
  tested. (The earlier `CloudAuditConnector` mock is kept for tests.)
- **Intent — deterministic, rename-resistant comparison** (`tex.provenance.intent`):
  declared intent and observed action types are classified into a shared
  **capability taxonomy** and compared by distribution-weighted divergence,
  so a synonym rename (`suppress_logs` ≡ `disable_monitoring`) no longer
  dodges the grade the way the old substring match did. Deterministic,
  content-free, offline-verifiable; scorer injectable, method sealed for
  re-grading. `engine.intent_drift` routes consequential divergence to the
  held path.

**Built and wired (verified):**
- `tex.provenance` — signature, distance, signed hash-chained ledger,
  engine (BIRTH / SIGHTING / REIDENTIFIED / DRIFT, graded confidence).
- `tex.domain.signal_trust.SignalTrustTier` + source→tier mapping.
- `AgentLifecycleStatus.SLEEPING` — reversible dormant state, attempt-to-act
  → ABSTAIN, `is_reversible`.
- `/v1/provenance/observe | identity/{id} | reidentify | ledger |
  ledger/verify`, attached to `app.state`, authed like the proof endpoints.

**The witness layer — built on the spine (2026-06-01):**
- **Continuous feed** (`tex.provenance.feed.ContinuousProvenanceFeed`):
  fires `observe()` automatically off the gate's decision stream, off the
  hot path (one cheap non-blocking `note_action`; a daemon worker does all
  sealing). Seals in silence by construction — the only thing routed
  onward is a `requires_human` resolution, into a `HeldDecisionSink`. The
  feed has no channel for ordinary findings.
- **Birth-cert anchoring on REGISTER** (`engine.register_birth`, wired into
  `DiscoveryService`): discovery seals a behavioural birth into the same
  log, anchored to the discovery signal's admissibility tier; a later
  behavioural sighting confirms the *same* identity. Idempotent.
- **Count-once voice surface** (`/v1/surface/discovery/*` +
  `IgnitionRegistry`): `ignite` speaks one line per tenant and never
  re-declares; `count` / `delta` / `owner` / `coverage` / `held` are
  pull-only. Spoken meaning + a bare object that rises on reach.
- **Dormancy controller** (`tex.discovery.dormancy.DormancyController`):
  sleeps the provably-safe in silence (sealed SLEPT), holds the
  load-bearing/uncertain as a genuine ABSTAIN, flags day-90 as a held
  decision and never auto-executes the irreversible deletion. Idle
  threshold injectable (`TEX_DORMANCY_IDLE_DAYS`, default 30).
- **Tamper-resistant connectors**: `CloudAuditConnector` (AUDIT_LOG,
  CloudTrail-AgentCore shape), `NetworkEgressConnector` (NETWORK_OBSERVED,
  TLS SNI/JA4 + model-endpoint map), `KernelEbpfConnector` (KERNEL_ATTESTED,
  Tetragon `process_exec` + measured-code hash, sealed revisable
  attestation method).
- **Sealed delegation graph** (`tex.provenance.delegation`): hash-chained,
  signed who-delegates-to-whom; feeds the dormancy load-bearing proof.
- **Declared-vs-observed intent**: sealed at birth, surfaced via
  `engine.intent_drift`. **Coverage-boundary-as-grade**: `engine.
  coverage_boundary` + the `/coverage` surface read.
- **Postgres provenance mirror**
  (`PostgresBehavioralProvenanceLedger`): write-through, re-verifies chain
  *and* signatures on bootstrap, in-memory fallback when no DATABASE_URL.

**Kept (frontier-grade, built upon — not replaced):**
- Discovery ledger (append-only, SHA-256 hash-chained).
- Reconciliation engine (candidate → registry action; the differentiator).
- Connectors (Bedrock, Graph, Salesforce, GitHub, OpenAI, Slack, MCP).
- Scan-run lifecycle (idempotency, per-tenant locking), connector health,
  presence (soft-disappearance), scheduler (continuous watch).

**Retired:**
- Arcade + leaderboard surfaces (files, repos, router wiring, tests) and
  the macOS zip-duplicate directories.

**Next (designed, not yet built):**
- Live tenant proving for root one (Entra/Okta) and root two (CloudTrail /
  Security Lake) — the logic is built and unit-tested behind injectable
  transports; only a real tenant/account can prove the live I/O paths.
- Root four (boundary tracing — AgentSight/Tetragon, KERNEL_ATTESTED):
  deliberately left dormant as the regulated-buyer upsell, not pre-built.
- Learned-per-estate idle threshold (vs the fixed default).
- A daemon scheduler tick that calls `DormancyController.sweep()`
  continuously (today it sweeps on demand).
- Optional embedding-based intent scorer (the taxonomy scorer is the
  default; an operator who accepts a model dependency can inject one).

---

## 9. Honest edges (a witness states them)

- **"Miss nothing" is asymptotic, never absolute.** No system proves zero
  misses. The defensible claim: miss nothing that leaves a trace in any
  plane Tex can prove it watches, and seal the edge of sight. Overclaiming
  completeness would make Tex a witness that lies.
- **Cold start.** An agent that acted once has a weak fingerprint.
  Behavioural provenance complements — does not replace — the identity and
  attestation roots.
- **False merge / split.** Tex seals confidence, never asserts identity.
  Merges (collapsing two identities) are a human's decision, surfaced as a
  held decision.
- **Behaviour ≠ content.** Signatures are built only from what an agent
  reached for, never what it said. Crossing that line turns the log into a
  regulated data store and breaks the privacy posture.

---

## 10. Invariants to protect (so future threads don't drift)

- One screen, voice, no dashboard, no inventory render. The output of
  discovery is spoken, never a graph.
- The trigger to break silence is **only** a held decision or a faltering
  confession — never "a new thing was discovered."
- Graded confidence, sealed; never a bare claim of identity.
- Keep the spine (ledger, reconciliation, connectors); build the witness
  layer on top. Willingness to delete is earned per-file on the merits, not
  granted wholesale.
- The regulatory anchor: a sealed-from-birth, continuously-witnessed
  inventory *is* EU AI Act Article 12 (automatic recording over the
  lifetime of the system), satisfied by architecture. **Date note
  (2026-06-01):** the Digital Omnibus reached provisional agreement on
  7 May 2026, deferring the standalone Annex III high-risk obligations
  (which include the Article 12 logging duty) from 2 Aug 2026 to
  2 Dec 2027; formal adoption is expected June, publication July 2026, so
  2 Aug 2026 is now the non-adoption fallback, not the live deadline. The
  architecture-satisfies-Article-12 claim is unchanged; only the date
  moved. The durable line for the pitch is "we satisfy it by architecture
  whenever it lands," which does not decay with the deadline.

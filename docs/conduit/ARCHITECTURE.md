# tex-conduit — Architecture

> One read-only **"Connect your directory"** button that turns any IdP
> (Microsoft Entra live, Okta next, Google Workspace / GCP IAM and Ping later)
> into the same normalized, blast-radius-scored agent inventory — where the
> **consent grant itself**, the **point-in-time inventory snapshot**, and every
> **shadow-agent catch** are sealed as externally-anchored, un-backfillable
> provenance through Tex's existing transparency-log stack, feeding the existing
> per-action PERMIT / HOLD / FORBID adjudication plane **unchanged**.

This document is the engineer-grade technical design. It assumes familiarity
with the existing Tex discovery layer (`tex.discovery.*`) and the interchange
seal stack (`tex.interchange.*`). It is explicit about exactly which existing
classes are reused verbatim, which are parameterized, and which code is net-new.

---

## 0. Design doctrine (what this is, and is not)

`tex-conduit` is a **new package under `src/tex/discovery/conduit/`** that sits
**entirely in front of** the existing connector Protocol and **behind** the
existing seal/anchor stack. It reinvents neither.

Three load-bearing rules govern every component below:

1. **Composition over rebuild.** Conduit's connector layer emits ordinary
   `CandidateAgent` records into the existing `ReconciliationEngine`, the
   hash-chained `DiscoveryLedger`, the standing-watch scheduler, and ignition —
   all untouched. Its seal layer calls the *already-verified*
   `CheckpointPublisher` + RFC-3161 `external_anchor` path. We add inputs and a
   pre-stage, not a parallel pipeline.

2. **Honesty discipline.** The button is **one entry point, not one click**.
   Entra is a true one-click admin-consent redirect; Okta is a service-app +
   private-key-JWT + a per-scope grant checklist; Google is explicitly **two**
   read grants; Ping is per-deployment service-account config. Anything
   requested-but-not-granted yields a **DEGRADED** grant that *records the gap*
   rather than silently proceeding. Fail-closed everywhere.

3. **Seal the grant, seal the inventory.** The two differentiators no incumbent
   ships are (a) sealing the **read-only connection grant** as the first
   un-backfillable receipt *before any agent is read*, and (b) sealing the
   **discovery inventory snapshot** as a point-in-time externally-anchored
   attestation. Everything else is necessary plumbing the IdPs give away.

What conduit is **not**: it is not a new directory, not a gateway, not a token
broker, not a replacement for the IdP. It sits *on top of* whichever IdP a
client already runs, read-only and least-privilege.

---

## 1. The five layers and the data flow

Data flows strictly left → right. Each arrow is a typed handoff; no layer
reaches backward.

```
                          ┌──────────────────────────────────────────────────────────┐
                          │                    tex-conduit (NEW)                       │
                          │                                                            │
  ONE BUTTON  ─────►  (1) CONNECT BROKER ──►  (2) DirectoryGrant ──►  GRANT_SEALED ────┼──►  seal stack
  "Connect your        ConnectStrategy        + FIRST SEAL          (un-backfillable)  │   (EXISTING:
   directory"          per provider           frozen, scope-exact   receipt to client  │    gix +
                       REQUESTED→CONSENTED                                              │    external_anchor)
                       →PROBED→SEALED                  │                                │
                                                       ▼                                │
                          (3) PROVIDER TRANSPORTS  ──► (4) ProviderConsentGraph ────────┼──►  CandidateAgent[]
                          behind GraphTransport         Connector(transport, profile)   │         │
                          (Okta/Google/Ping;            ── blast_radius() (EXISTING) ──  │         │
                           Entra=LiveGraphTransport)    ── ProviderProfile (declarative) │         │
                                                       │                                │         │
                          (5) BEHAVIORAL SCAN  ──► ShadowCorrelator (NET-NEW) ──────────┼──►  CandidateAgent[]
                          (OCSF per provider)         cross-namespace join              │    (+ shadow evidence)
                                                                                        │         │
                          INVENTORY_SNAPSHOT_SEALED ◄── InventorySnapshotSealer ◄───────┼─────────┘
                          (Merkle root over candidate set)                              │
                          └──────────────────────────────────────────────────────────┬─┘
                                                                                      │
                                                                                      ▼
                                  EXISTING DOWNSTREAM (UNCHANGED):
                                  ReconciliationEngine.decide()  ──►  DiscoveryLedger (hash-chained)
                                          │                                  │
                                          ▼                                  ▼
                                  promote / drift / quarantine        standing-watch scheduler (delta re-scan)
                                          │
                                          ▼
                                  IGNITION fires once  ──►  GOVERNANCE adjudicates next action
                                                            (PERMIT / HOLD / FORBID + sealed receipt)
```

### Layer summary

| # | Layer | Module(s) | New / reused |
|---|-------|-----------|--------------|
| 1 | Connect broker + per-provider strategy | `conduit/broker.py`, `conduit/providers/*` | NEW |
| 2 | `DirectoryGrant` + first seal + drift | `conduit/grant.py`, `conduit/seal.py` | NEW (calls existing seal stack) |
| 3 | Provider transports | `conduit/transport/*` | NEW (behind existing `GraphTransport` Protocol) |
| 4 | Generalized consent-graph connector + profiles | `conduit/connector.py`, `conduit/profiles/*`, `conduit/risk_dictionary.py` | NEW connector subclass; **reuses** `ConsentGraph`, `BaseConnector`, `CandidateAgent` |
| 5 | Dual-plane + shadow correlation | `conduit/shadow.py` | NET-NEW correlation; **reuses** OCSF connector pattern |
| — | Inventory snapshot sealer | `conduit/seal.py` | NEW (calls existing `CheckpointPublisher` + `external_anchor`) |
| — | Guarded enrichment (deferred tier) | `conduit/evidence_fold.py` | NEW, opt-in, never identity-resolving |

---

## 2. Layer 1 — Connect broker (one button, four authorization dances)

### 2.1 The state machine

The broker is a four-state machine, one row per connection attempt:

```
REQUESTED ──begin_consent──► CONSENTED ──finalize_consent──► PROBED ──seal──► SEALED
    │                            │                              │
    └── ungranted scope ─────────┴── DEGRADED (gap recorded) ───┘   (fail-closed; never silently proceeds)
```

- **REQUESTED** — operator clicked the button for a provider; broker has minted
  a `ConsentChallenge` and an opaque `connection_id`.
- **CONSENTED** — the provider returned a callback the broker can finalize.
- **PROBED** — the broker has done a *read-only probe* (one cheap list call) to
  confirm the granted scopes actually work, comparing requested vs. effective.
- **SEALED** — the `DirectoryGrant` has been sealed as `GRANT_SEALED` (§4). Only
  a `SEALED` connection may be scanned.

The broker **never holds long-lived secrets**. It persists an opaque
`connection_id` that points at the deployment's secret store — mirroring exactly
how `LiveGraphTransport` already takes `GraphCredentials` from a config object
populated out-of-band (see `graph_transport.py`, "Credentials are never held
here in source"). What the broker stores is the *binding*, not the bytes.

### 2.2 `ConnectStrategy` — the only place divergent auth lives

Each provider implements one `ConnectStrategy` (`conduit/providers/base.py`):

```python
class ConnectStrategy(Protocol):
    provider: DirectoryProvider                    # ENTRA | OKTA | GOOGLE | PING

    def begin_consent(self, tenant: TenantRef) -> ConsentChallenge: ...
    def finalize_consent(self, callback: ConsentCallback) -> DirectoryGrant: ...
    def build_transport(self, grant: DirectoryGrant) -> GraphTransport: ...
```

`build_transport` returns something satisfying the **existing**
`graph_transport.GraphTransport` Protocol — so everything past layer 3 is
provider-agnostic by construction.

### 2.3 Per-provider authorization (honest, not uniform)

| Provider | `begin_consent` | What "granted" means | Honesty note |
|----------|-----------------|----------------------|--------------|
| **Entra** (`providers/entra.py`) | Redirect to `https://login.microsoftonline.com/{tenant}/v2.0/adminconsent` for the read triad | Admin-consent grant id returned | **True one click.** This is the reference. |
| **Okta** (`providers/okta.py`) | Operator creates an OAuth **service app** (client-credentials + **private-key JWT**, never static SSWS), then clicks *Grant* per scope | Broker verifies each requested scope landed on the service app | Multi-step; broker *verifies the checklist*, surfaces missing scopes. `okta.appGrants.read` may need Super Admin. |
| **Google** (`providers/google.py`) | **Two** grants in one modal: (1) Workspace **domain-wide delegation** allow-list, (2) GCP **org-viewer** for Cloud Asset Inventory | Both DWD client id **and** org IAM binding present | **Explicitly two read grants**, presented as a two-step sealed checklist. Never marketed as one OAuth click. |
| **Ping** (`providers/ping.py`) | Per-deployment service account (PingFederate OAuth Client Management REST, or PingOne AIC), pluggable `base_url` | Service-account id + scope set | Least standardized; per-deployment config. |

### 2.4 Fail-closed → DEGRADED grant

If any requested scope is not present at `finalize_consent` time, the broker
does **not** silently proceed. It produces a `DirectoryGrant` with
`status = DEGRADED` and a `scope_gap` field listing exactly what was withheld.
A degraded grant is still **sealed** (so the gap is itself provenance), and the
connector runs a **partial census** that is *labeled partial in the sealed
snapshot*. Example: Okta without `okta.appGrants.read` runs an "apps + clients
only" census, sealed as partial, rather than pretending the consent graph is
complete.

---

## 3. Layer 2 — `DirectoryGrant` and the FIRST seal

### 3.1 The frozen domain object

`conduit/grant.py` defines `DirectoryGrant` as a frozen Pydantic model
(`frozen=True, extra="forbid"`, tz-aware datetimes — same house style as
`domain/discovery.py`):

```python
class DirectoryGrant(BaseModel):
    provider: DirectoryProvider
    tenant_ref: str                       # tenant/org id, normalized
    granted_scopes: tuple[str, ...]       # canonicalized + SORTED — the exact least-privilege set
    requested_scopes: tuple[str, ...]     # what we asked for (so the gap is provable)
    consent_artifact_id: str              # Entra admin-consent grant id / Okta service-app id /
                                          # Google DWD client id / Ping service-account id
    consented_by: str                     # the admin principal
    granted_at: datetime
    credential_ref: str                   # opaque pointer into the secret store — NEVER the secret
    status: GrantStatus                   # FULL | DEGRADED
    scope_gap: tuple[str, ...] = ()       # requested − granted, when DEGRADED
```

`granted_scopes` is **canonicalized and sorted** so the sealed bytes are
deterministic — the same grant always hashes identically, which is what makes
drift detection (§3.3) a clean set comparison and the receipt reproducible.

### 3.2 `GRANT_SEALED` — the headline differentiator

The moment `finalize_consent` succeeds, `conduit/seal.py` seals a
`GRANT_SEALED` provenance event **through the existing transparency-log stack**,
*before any agent is read*:

1. Canonicalize the `DirectoryGrant` to deterministic JSON; SHA-256 it into a
   sealed fact (the same record-hash contract `CheckpointPublisher` consumes —
   it reads ordered 64-hex `record_hash` strings via its
   `read_record_hashes` callable).
2. Take a signed tree head:
   `CheckpointPublisher.current_signed_checkpoint()` →
   `SignedCheckpoint(checkpoint, signed_note, record_hashes)`
   (`interchange/gix.py`). The note is a **C2SP `tlog-checkpoint`** signed with
   an Ed25519 note signer (`signed-note` type `0x04` timestamped Ed25519 at
   launch; `0x06` ML-DSA-44 is the deferred PQ upgrade — *same format*, no
   schema change).
3. Anchor the checkpoint externally via the **verified** RFC-3161 path in
   `interchange/external_anchor.py` — `anchor_subject_bytes(origin, tree_size,
   root_hash)` is the exact byte string the TSA timestamps; the returned
   `CheckpointAnchorRecord` carries the TSA's CMS-signed token, **verified
   against a pinned TSA cert** (interop verified 2026-06-17 against
   freetsa.org). **We use `external_anchor.py`, NOT `c2pa/timestamp.py`** — the
   latter builds RFC-3161 requests but never verifies the TSA's CMS signature.

The customer receives a cryptographic receipt of **exactly what least-privilege
read access they granted, when, and by whom** — sealed and externally
timestamped before Tex has read a single agent. No incumbent (Entra, Okta, Ping,
SailPoint, Purview) seals the authorization; they seal at most its outputs.

### 3.3 `CONNECTION_DRIFT` — the self-auditing connection

Because the grant's exact scope set is sealed, every later scan can compare the
provider's **live** scope set against the **sealed** set:

- If live ⊋ sealed (silent **escalation** — someone added scopes), or
  live ⊊ sealed (silent **revocation**), the connector **refuses to scan** and
  seals a `CONNECTION_DRIFT` fact instead.
- This is fail-closed: a connection that no longer matches its sealed grant
  does not produce an inventory; it produces evidence of the divergence.

This is a connection that audits itself, and it falls directly out of having
sealed the grant.

---

## 4. Layer 3 — Provider transports behind the unchanged `GraphTransport`

`graph_transport.py` already abstracts the only two reads discovery needs, and
its docstring already states "Okta's `/api/v1` is the same shape":

```python
class GraphTransport(Protocol):
    def get_paginated(self, path, params=None) -> Iterator[dict]: ...
    def get_delta(self, path, delta_link=None) -> tuple[list[dict], str | None]: ...
```

Conduit ships new transports **behind this exact Protocol** — zero connector
changes, every transport unit-testable with `FixtureGraphTransport` and no live
tenant.

| Transport | Pagination (`get_paginated`) | Delta (`get_delta`) — standing watch |
|-----------|------------------------------|--------------------------------------|
| `LiveGraphTransport` (**Entra, existing, untouched**) | `@odata.nextLink` | `@odata.deltaLink` |
| `transport/okta_transport.py` | cursor via `Link rel=next` header | System Log polling (`/api/v1/logs`) |
| `transport/google_transport.py` → `GoogleWorkspaceTransport` + `GoogleIamAssetTransport` | `pageToken`; Cloud Asset Inventory for org-wide SAs | Reports token-audit (180-day window — see §6.4) |
| `transport/ping_transport.py` | pluggable `base_url`; PingFederate `/pf-ws/rest/oauth/clients` or PingOne AIC | OIDC discovery + per-deployment polling |

`FixtureGraphTransport` is the test substrate for **every** new transport. The
delta contract (`get_delta` returns `(changed, next_delta_link)`) is identical
across providers, so the scheduler's standing watch is provider-agnostic.

---

## 5. Layer 4 — `ProviderConsentGraphConnector` + `ProviderProfile`

### 5.1 One connector, parameterized

Today `EntraConsentGraphConnector(BaseConnector)` hard-codes Entra specifics
(`_AGENT_SP_TYPES`, the `servicePrincipals/{id}/oauth2PermissionGrants` paths,
the Entra critical-scope strings). Conduit generalizes this into **one**
`ProviderConsentGraphConnector(BaseConnector)` parameterized by
`(transport, profile)`:

```python
class ProviderConsentGraphConnector(BaseConnector):
    def __init__(self, *, transport: GraphTransport, profile: ProviderProfile) -> None:
        super().__init__(source=profile.source, name=profile.connector_name)
        self._transport = transport
        self._profile = profile

    def _run_scan(self, context) -> Iterable[CandidateAgent]:
        graph, principals = self._build_graph(context)   # uses profile.collection_paths + ConsentEdgeMapper
        for sp_id in graph.agents():
            yield self._candidate_from_principal(principals[sp_id], graph, context)
```

It is a `BaseConnector` subclass, so it inherits the `max_candidates` cap, the
`name_filter`, and tenant-id propagation for free, and emits ordinary
`CandidateAgent` — meaning **reconciliation, the ledger, and standing-watch all
keep working unchanged** (exactly the property `base.py` promises).

### 5.2 `ProviderProfile` — declarative, per-provider

`conduit/profiles/*.py` — a profile is a dataclass, *no imperative logic*:

```python
@dataclass(frozen=True)
class ProviderProfile:
    source: DiscoverySource                 # OKTA | GOOGLE_WORKSPACE | GCP_IAM | PING | MICROSOFT_GRAPH
    connector_name: str
    principal_collection: str               # where agent-bearing principals live
    grant_collections: tuple[str, ...]      # where consent/grant edges live (delegated + app-role analogues)
    edge_mapper: ConsentEdgeMapper          # one native grant row -> one ConsentEdge
    is_agent: Callable[[dict], bool]        # provider's "_looks_like_agent"
    critical_scopes: frozenset[str]         # PER-PROVIDER curated critical set (see §5.4)
    model_provider_hint: str
    framework_hint: str
```

`ConsentEdgeMapper` turns one native grant row (an Okta `appGrant`, a GCP IAM
binding, a Ping client scope) into the **existing** `ConsentEdge`
(`consent_graph.py`): `(client_id, resource_id, resource_name, scopes,
tenant_wide)`. That is the entire per-provider surface — everything downstream
is shared.

### 5.3 Blast radius is reused verbatim

`_candidate_from_principal` feeds the **existing** `ConsentGraph.blast_radius()`
and maps its output identically to today's Entra connector:

- `capability_hints.inferred_tools` ← `blast["scopes"]`
- `capability_hints.inferred_data_scopes` ← `blast["direct_resources"]`
- `capability_hints.surface_unbounded` ← `blast["surface_unbounded"]`
- `risk_band` ← the existing ladder: `critical_scopes` → CRITICAL;
  `tenant_wide_grant && high_risk_scopes` → HIGH; `high_risk_scopes` → MEDIUM;
  else LOW.

The `blast_radius()` engine, its reachability closure, and the risk ladder are
**not modified**. Entra migrates to
`ProviderConsentGraphConnector(LiveGraphTransport, ENTRA_PROFILE)` as the
reference — preserving `_looks_like_agent()` and `blast_radius()` behavior
byte-for-byte and staying fully covered by the existing `FixtureGraphTransport`
tests (zero behavior change is the Phase 0 acceptance gate).

### 5.4 The provider-neutral risk dictionary (a maintained asset, not a free seed)

This is the one correction the design makes explicit: the risk taxonomy is **not
reused unchanged**.

- `consent_graph.HIGH_RISK_SCOPE_STEMS` (`readwrite`, `manage`, `write`, `send`,
  `delete`, `impersonation`, `accessasuser`, …) are **substring stems** and
  **are portable** across providers — "write" means write everywhere.
- `consent_graph.CRITICAL_SCOPE_STEMS` are **literal Entra permission strings**
  (`directory.readwrite.all`, `rolemanagement.readwrite.directory`, …) and are
  **not portable**.

So `conduit/risk_dictionary.py` ships a **per-provider curated critical-scope
set**, fed into each `ProviderProfile.critical_scopes`, mapped onto the **same**
`blast_radius()` engine so that CRITICAL means the same thing on every IdP:

| Provider | Curated critical scopes (examples) |
|----------|-----------------------------------|
| Okta | super-admin / org-admin grants, `okta.users.manage`, app-admin role grants |
| GCP IAM | `roles/owner`, `roles/iam.securityAdmin`, `roles/iam.serviceAccountTokenCreator` (impersonation) |
| Ping | admin scopes, OAuth client-management write scopes |
| Entra | the existing `CRITICAL_SCOPE_STEMS` (reference) |

This dictionary is **honestly a standing maintenance liability** (Okta scopes,
GCP roles, and Ping scopes have no clean isomorphism to Graph permissions) — it
is owned, versioned, and its own drift is audited. It is not pretended to be a
free lookup. (See open question in §10.)

### 5.5 New `DiscoverySource` members keep reconciliation keys clean

`DiscoverySource` (`domain/discovery.py`) gains: `OKTA`, `GOOGLE_WORKSPACE`,
`GCP_IAM`, `PING`. Because `reconciliation_key = f"{source}:{tenant}:{external_id}"`,
adding a *new* member (rather than reusing `MICROSOFT_GRAPH`) keeps the key
**provider-scoped and uncorrupted** — which the enum's own docstring explicitly
mandates ("conflating two platforms would corrupt it"). The same external id
under two providers never collides.

---

## 6. Layer 5 — Dual-plane discovery + explicit shadow correlation

### 6.1 Two planes per provider

Every provider pairs:

- **Control plane** — the consent-graph scan above
  (`source = OKTA | GCP_IAM | …`), authoritative for *what the directory knows*.
- **Behavioral plane** — an OCSF audit scan via the **existing**
  `OcsfAuditConnector` pattern (`connectors/cloud_audit_ocsf.py`), keyed under
  `source = CLOUD_AUDIT`, catching agents that *acted* (Entra sign-ins
  "performed by an AI agent", Okta System Log, Google token-audit).

### 6.2 Why the shadow diff is NOT free (the honest correction)

Behavioral candidates key `external_id = resource_arn-or-principal-handle` under
`source = CLOUD_AUDIT`. Control-plane candidates key on the directory's
principal id under `source = OKTA` (etc.). Their `reconciliation_key` values are
**structurally disjoint** — different `source`, different `external_id`
namespace — so the reconciliation engine can **never** auto-collide them. There
is no free "registered vs. observed" diff.

### 6.3 `ShadowCorrelator` — net-new, honestly labeled

`conduit/shadow.py` is **net-new code**, not "reconciliation unchanged". Per
tenant it runs a cross-namespace pass:

1. For each behavioral actor handle, attempt a **deterministic join** to a
   control-plane principal where one exists — shared principal id, shared
   app/client id, or matching `owner_hint`.
2. **Joined** → attach the behavioral evidence onto the existing control-plane
   `CandidateAgent` (it acted *and* it's registered).
3. **Unjoined but acted** → flag as a **SHADOW** agent: acted in logs, present
   in no control-plane scan. Surfaced as a candidate with shadow evidence.

### 6.4 Per-provider confidence (retention asymmetry)

Shadow confidence is **differentiated per provider** to reflect behavioral
retention windows. Google token-audit is only a **180-day** window, so a Google
"shadow" carries lower certainty than an Entra one (whose sign-in logs are
operator-retained longer). The correlator records the source retention window in
the evidence so the confidence is *explainable*, not magic.

---

## 7. Sealed provenance — the seal stack and what conduit adds

Conduit adds **inputs** to the existing seal stack; it does not duplicate it.

### 7.1 Three sealed event kinds (outside the conservation counters)

`GRANT_SEALED`, `CONNECTION_DRIFT`, and `INVENTORY_SNAPSHOT_SEALED` are added as
provenance event kinds that **avoid the ATTEMPT / DECISION conservation
counters** — modeled exactly like the deliberately-separate `VERDICT_TRANSCRIPT`
kind already in the ledger. They are facts *about discovery and connection*, not
governance decisions, so they must not perturb the decision-conservation
invariant the evidence chain enforces.

### 7.2 `InventorySnapshotSealer`

At end of scan, `conduit/seal.py`:

1. Sorts the emitted `CandidateAgent` set deterministically (by
   `reconciliation_key`).
2. Computes a **Merkle root** over `(reconciliation_key, blast_radius_digest)`
   for each candidate — reusing the same `merkle_root` math `CheckpointPublisher`
   uses (`gix.py`).
3. Seals `INVENTORY_SNAPSHOT_SEALED` = "here is the exact set of agents that
   existed in your tenant at epoch T", taking a `current_signed_checkpoint()`
   and anchoring it through the same `external_anchor` RFC-3161 path.
4. **Batches** snapshots on churny estates so anchoring cost (TSA calls) stays
   bounded while each per-snapshot inclusion proof stays meaningful.

The discovery inventory becomes a tamper-evident point-in-time attestation, not
a mutable database row. No IdP read API and no NHI vendor seals the inventory
itself.

### 7.3 The seal composition (mirrors Rekor v2 decomposition)

```
CandidateAgent set ──► canonical JSON ──► SHA-256 leaf ──► Merkle root
                                                              │
                              CheckpointPublisher.current_signed_checkpoint()
                                       │  (C2SP tlog-checkpoint, Ed25519 signed-note)
                                       ▼
                              external_anchor.submit_anchor()
                                       │  (RFC 3161 TSA; CMS sig verified vs pinned cert)
                                       ▼
                              CheckpointAnchorRecord  ──►  sealed receipt
```

Time (RFC 3161), append-only inclusion (Merkle/tlog), and the C2SP signed-note
format are the three composable primitives — all already present in
`interchange/`. Conduit wires discovery into them; it builds none of them.

### 7.4 Offline verifier

`scripts/verify_conduit_receipt.py` mirrors the existing
`scripts/verify_it_yourself.py` pattern: one command, fully offline, proves a
`GRANT_SEALED` / `INVENTORY_SNAPSHOT_SEALED` receipt — checkpoint signature,
Merkle inclusion, and the TSA token against the pinned cert — **without trusting
Tex**. This is the technical substance of "you don't have to trust us".

---

## 8. Exactly how it plugs into the existing pipeline

Tracing one connection end-to-end against the real classes:

1. **Button → broker.** Operator clicks "Connect your directory" for provider P.
   `POST /v1/conduit/connect` (`api/conduit_routes.py`) drives the
   `ConnectStrategy.begin_consent` → `finalize_consent` flow to a
   `DirectoryGrant`.

2. **Seal the grant.** `conduit/seal.py` seals `GRANT_SEALED` via
   `CheckpointPublisher.current_signed_checkpoint()` +
   `external_anchor.submit_anchor()`. Connection enters `SEALED`.

3. **Build transport.** `ConnectStrategy.build_transport(grant)` returns a
   `GraphTransport` (e.g. `OktaTransport`), reading credentials from the secret
   store via `grant.credential_ref`.

4. **Drift check.** Before scanning, compare live scopes vs. sealed
   `granted_scopes`. On divergence → seal `CONNECTION_DRIFT`, refuse the scan.

5. **Scan (control plane).** The scheduler invokes
   `ProviderConsentGraphConnector(transport, P_PROFILE).scan(ConnectorContext(tenant_id=...))`.
   It builds a `ConsentGraph`, computes `blast_radius()`, and yields
   `CandidateAgent` records — same shape `entra_consent_graph.py` emits today.

6. **Scan (behavioral plane).** The matching `OcsfAuditConnector` yields
   `CLOUD_AUDIT` candidates.

7. **Shadow correlation.** `ShadowCorrelator` joins behavioral handles to
   control-plane principals, attaches evidence or flags SHADOW.

8. **Reconcile.** Each `CandidateAgent` flows into the **unchanged**
   `ReconciliationEngine.decide(candidate=..., existing=...)` →
   `ReconciliationDecision` → `ReconciliationOutcome`. Keyed by
   `reconciliation_key` (provider-scoped). No reconciliation code changes.

9. **Ledger.** Each outcome appends one hash-chained `DiscoveryLedgerEntry`
   (`payload_sha256`, `previous_hash`, `record_hash`) — unchanged.

10. **Seal the inventory.** `InventorySnapshotSealer` seals
    `INVENTORY_SNAPSHOT_SEALED` over the emitted set.

11. **Standing watch.** The scheduler re-invokes `transport.get_delta(...)` per
    its cadence; each inventory-changing delta emits fresh `CandidateAgent`
    records into a re-scan that **re-seals** a new snapshot (Phase 2 fixes the
    existing gap where `sweep_delta` returns raw dicts wired to nothing).

12. **Ignition + governance.** `IgnitionRegistry.fire(tenant)` fires **once**
    (`ignition.py`), the glass goes clean, and governance adjudicates the
    agent's next consequential action — PERMIT / HOLD / FORBID — with the
    **sealed grant + sealed inventory + delegation chain already attached** as
    evidence. The governance plane is untouched; conduit only enriches its
    inputs.

**Everything from step 8 onward is existing code running unchanged.** Conduit is
steps 1–7 plus the two seal moments.

---

## 9. Repo tree

```
src/tex/discovery/conduit/
├── __init__.py
├── broker.py                        # ConnectBroker + REQUESTED→CONSENTED→PROBED→SEALED state machine
├── grant.py                         # DirectoryGrant (frozen) + GrantStatus + drift comparison
├── connector.py                     # ProviderConsentGraphConnector(BaseConnector) + ProviderProfile + ConsentEdgeMapper
├── shadow.py                        # ShadowCorrelator (NET-NEW cross-namespace join)
├── seal.py                          # GRANT_SEALED / CONNECTION_DRIFT / INVENTORY_SNAPSHOT_SEALED sealing
├── evidence_fold.py                 # guarded, deferred-tier multi-source enrichment (never resolves identity)
├── risk_dictionary.py               # provider-neutral critical-scope sets (maintained asset)
├── providers/
│   ├── __init__.py
│   ├── base.py                      # ConnectStrategy Protocol + ConsentChallenge + ConsentCallback
│   ├── entra.py                     # admin-consent redirect (reference, one click)
│   ├── okta.py                      # service-app + private-key-JWT + per-scope grant checklist
│   ├── google.py                    # two-grant checklist (Workspace DWD + GCP org-viewer)
│   └── ping.py                      # per-deployment service account, pluggable base_url
├── profiles/
│   ├── __init__.py
│   ├── entra_profile.py             # ENTRA_PROFILE (migration reference)
│   ├── okta_profile.py
│   ├── google_profile.py
│   └── ping_profile.py
└── transport/
    ├── __init__.py
    ├── okta_transport.py            # Link rel=next pagination; System Log delta
    ├── google_transport.py          # GoogleWorkspaceTransport + GoogleIamAssetTransport
    └── ping_transport.py            # pluggable base_url

src/tex/api/
└── conduit_routes.py                # POST /v1/conduit/connect, /finalize, /status, /receipt

tests/discovery/conduit/
├── __init__.py
├── test_broker_state_machine.py
├── test_grant_seal_and_drift.py
├── test_okta_profile_blast_radius.py
├── test_shadow_correlator.py
├── test_inventory_snapshot_seal.py
└── fixtures/
    ├── okta_apps.json
    ├── okta_grants.json
    └── entra_servicePrincipals.json

scripts/
└── verify_conduit_receipt.py        # one-command offline receipt verifier (mirrors verify_it_yourself.py)

docs/conduit/
├── ARCHITECTURE.md                  # this file
├── README.md
└── provider-consent-matrix.md
```

**Existing files reused unchanged:** `discovery/connectors/base.py`,
`discovery/graph_transport.py` (`LiveGraphTransport`, `FixtureGraphTransport`),
`discovery/consent_graph.py` (`ConsentGraph`, `ConsentEdge`, blast radius),
`discovery/reconciliation.py`, `discovery/scheduler.py`,
`discovery/ignition.py`, `discovery/connectors/cloud_audit_ocsf.py`,
`domain/discovery.py` (`CandidateAgent` et al.),
`interchange/gix.py` (`CheckpointPublisher`),
`interchange/external_anchor.py` (RFC-3161 anchor + verifier).

**Existing files minimally touched:** `domain/discovery.py` (add four
`DiscoverySource` members); `discovery/connectors/entra_consent_graph.py`
(re-expressed as `ProviderConsentGraphConnector(LiveGraphTransport,
ENTRA_PROFILE)`).

---

## 10. Standards supported, build phases, and open questions

### 10.1 Standards

- OAuth 2.1 client-credentials + **private-key JWT** (Okta service app, Ping) —
  rotatable, least-privilege, never static SSWS.
- Microsoft Graph read-only triad: `Application.Read.All` +
  `DelegatedPermissionGrant.Read.All` + `AuditLog.Read.All` (multi-tenant admin
  consent); Entra **Agent ID** beta `AgentIdentity.Read.*` as additive
  enrichment only (runs in parallel with the legacy consent-graph walk — the
  floor that always works; beta object shapes deprecating May 2026, so never
  hard-coded).
- Okta read scopes: `okta.apps.read`, `okta.clients.read`, `okta.appGrants.read`,
  `okta.oauthIntegrations.read`, `okta.serviceAccounts.read`,
  `okta.apiTokens.read`, `okta.logs.read`.
- Google: Cloud Asset Inventory (`cloudasset.googleapis.com`) org-wide SA
  enumeration + Admin SDK tokens + Reports token-audit
  (`admin.reports.audit.readonly`), via domain-wide delegation + GCP org-viewer
  — **two grants**.
- **RFC 3161** Time-Stamp Protocol via the verified `external_anchor.py` path
  (CMS signature verified against a pinned TSA cert) — **not** the
  `c2pa/timestamp.py` builder.
- **C2SP `tlog-checkpoint` + `signed-note`** (Ed25519 type `0x04` at launch) via
  `interchange/gix.py`.
- OpenID **AuthZEN**-shaped decision output (SARC) downstream so Tex stays a
  drop-in PDP — consumed by governance, not built in conduit.
- Deferred / opt-in: FIPS 204 **ML-DSA** seals (signed-note `0x06`), C2SP
  `tlog-witness` independent cosigning, OpenTimestamps Bitcoin anchoring; A2A
  AgentCard JWS/JCS verification in the guarded `EvidenceFold`.

### 10.2 Build phases

- **Phase 0 — Reference migration + grant seal.** Add the four `DiscoverySource`
  members; build `ProviderConsentGraphConnector` + `ProviderProfile` +
  `ConsentEdgeMapper`; migrate Entra to `(LiveGraphTransport, ENTRA_PROFILE)`
  with **zero behavior change** against existing fixtures; implement
  `DirectoryGrant` + `GRANT_SEALED` + `CONNECTION_DRIFT`; add the three event
  kinds outside the conservation counters; ship `verify_conduit_receipt.py`.
  Touches no new provider — de-risks the spine on working code.
- **Phase 1 — Okta (cross-IdP neutrality proof).** Realize the empty
  `_pending/interop/okta/agent_identity_sync.py` as `OktaTransport`
  (private-key-JWT) + `okta_profile.py` + `ConnectStrategy`; curate Okta critical
  scopes; surface the `okta.appGrants.read` Super-Admin caveat; run a partial
  census (sealed as partial) when withheld.
- **Phase 2 — Inventory snapshot seal + real standing watch.** Implement
  `InventorySnapshotSealer`; wire `OktaTransport.get_delta` into the scheduler;
  **fix the standing-watch gap** so delta emits `CandidateAgent`s into a re-scan
  that re-seals.
- **Phase 3 — Explicit shadow correlation.** Build `ShadowCorrelator`; wire one
  OCSF behavioral connector per provider; per-provider-differentiated confidence.
- **Phase 4 — Google + Ping + guarded EvidenceFold.** Two-grant Google
  transports; pluggable Ping transport; additive A2A/MCP/SPIFFE/Entra-Agent-ID
  enrichment that **never resolves identity and never raises trust** (unsigned /
  tamper-failed cards *raise* risk), with egress allow-listing + size/timeout
  caps.
- **Phase 5 — Opt-in provenance tiers (not launch-blocking).** ML-DSA PQ seals
  (auto-on where backend installed, ECDSA floor otherwise); independent witness
  cosigning (honestly `federated=False` until a real third-party witness runs);
  OpenTimestamps Bitcoin anchoring; map the stack to NIST SP 800-53 AU-10 and EU
  AI Act Art. 10/12/50 for the compliance-evidence buyer.

### 10.3 Open questions

1. **Shadow join quality.** When no deterministic key links a behavioral actor
   to a control-plane principal, surface every unjoined actor as SHADOW (noisy)
   or hold it ambiguous? Needs a per-provider join-confidence threshold.
2. **Okta least-privilege vs. completeness.** `okta.appGrants.read` effectively
   requiring Super Admin contradicts the least-privilege headline on the flagship
   second provider. Default to the degraded "apps + clients only, sealed as
   partial" census, or push customers to Super Admin? Product decision.
3. **Risk-dictionary ownership.** The provider-neutral critical-scope dictionary
   is a standing maintenance liability with no clean cross-provider isomorphism —
   who keeps it current, and how is drift *in the dictionary itself* audited?
4. **Entra Agent ID versioning.** Registry beta types deprecate (May 2026) into
   Agent 365 Agent Registry APIs — the additive enrichment path must version and
   fall back gracefully to the legacy walk; do not hard-code beta shapes.
5. **Snapshot batching cadence.** On churny estates, batch interval trades
   freshness ("what existed at T") against anchoring (TSA) cost. What cadence
   keeps the per-snapshot inclusion proof meaningful without unbounded calls?
6. **Witness independence.** The "you don't have to trust Tex" claim is
   aspirational until a real external witness runs (`gix_witness` is
   `federated=False` this wave). Sequencing a first independent witness (a design
   partner's own auditor) is a go-to-market dependency, not a code task.
```

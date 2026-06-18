# tex-conduit

**One read-only "Connect your directory" capability that turns any IdP into a sealed, blast-radius-scored agent inventory.**

> They decide who an agent *is* and what it can *reach*. Tex rules on what it *does*, action by action, and seals the proof — **starting with sealing the read-only directory grant itself, which nobody else does.**

`tex-conduit` lives at `src/tex/discovery/conduit/`. It sits **in front of** the existing discovery connector Protocol and **behind** the existing seal/anchor stack — it *composes* them, it does not reinvent them. Downstream (reconciliation, ledger, scheduler, ignition, governance) is untouched: conduit emits ordinary `CandidateAgent` records and seals through the existing gix + RFC-3161 path.

## The two load-bearing differentiators

1. **Seal the grant.** The moment a customer grants Tex read-only access, the grant itself is sealed as the first tamper-evident receipt (`GRANT_SEALED`) — *before any agent is read*. Everyone else at most seals outputs. From the sealed grant falls out `CONNECTION_DRIFT`: if the live scope set later diverges from what was sealed, the connector **refuses to scan** (fail-closed) and seals the drift.
2. **Discovery-as-provenance.** The exact set of agents discovered at time T is sealed as a Merkle-rooted, externally-anchored snapshot (`INVENTORY_SNAPSHOT_SEALED`).

## Architecture (data flows left → right)

| Layer | Module | What it does |
|---|---|---|
| Connect broker + strategies | `broker.py`, `providers/*` | One UX entry point; a 4-state machine `REQUESTED → CONSENTED → PROBED → SEALED`. Each provider's authorization dance lives in one `ConnectStrategy`. Never holds secrets — only an opaque `credential_ref`. |
| Grant + first seal | `grant.py`, `seal.py` | Frozen, secret-free `DirectoryGrant`; `GRANT_SEALED` + `CONNECTION_DRIFT` via the verified seal path. |
| Provider transports | `transport/*` | `OktaTransport`, `GoogleWorkspaceTransport`, `GoogleIamAssetTransport`, `PingTransport` — all behind the **unchanged** `GraphTransport` Protocol. Entra's `LiveGraphTransport` and test `FixtureGraphTransport` are untouched. |
| Generalized connector + profiles | `connector.py`, `profiles/*` | ONE `ProviderConsentGraphConnector(transport, ProviderProfile)`. Entra runs through it with zero behavior change. |
| Risk dictionary | `risk_dictionary.py` | Portable HIGH-risk substring stems + per-provider **critical** scope sets (a maintained asset, honestly a liability). |
| Inventory seal + standing watch | `seal.py` | `InventorySnapshotSealer` (batched anchoring) + `StandingWatch` (delta → re-emitted candidates → fresh sealed snapshot). |
| Shadow correlation | `shadow.py` | Net-new cross-namespace `ShadowCorrelator`: joins behavioral (`CLOUD_AUDIT`) actors to control-plane principals; flags acted-but-unregistered actors as SHADOW with per-provider confidence. |
| Guarded enrichment | `evidence_fold.py` | A2A AgentCard / MCP / SPIFFE folding that **never resolves identity, never raises trust**; an unsigned/tampered card raises risk. |
| Opt-in tiers | `tiers.py` | ML-DSA / witness-cosign / OpenTimestamps toggles. The Ed25519 + RFC-3161 floor always works. |

## Honesty discipline (product requirements, not nice-to-haves)

- **One entry point, not one click.** Entra is genuine one-click admin consent; **Okta is multi-step** (service app + private-key JWT + a per-scope checklist, one scope needs Super Admin); **Google is TWO separate grants** (Workspace DWD + GCP org viewer), each sealed as its own receipt.
- **Fail-closed.** Ungranted scope → a `DEGRADED` (partial) grant that records the gap, never a silent proceed. Live scope drift → refuse the scan.
- **Read-only, least-privilege, continuous.** No write scope ever.
- **Never fake discovery.** No planted tags. Every predicate interprets the provider's real fields; every fixture is raw API shape.
- **Witness cosigning is `federated=False` this wave** — stated honestly as aspirational until a real third-party witness runs. The "you don't have to trust Tex" claim is go-to-market until then.

## Verify a receipt yourself (without trusting Tex)

```bash
python scripts/verify_conduit_receipt.py <receipt.json> --pin <pin.json>
python scripts/verify_conduit_receipt.py <receipt.json> --pin <pin.json> --tsa-cert <ca.der>  # + provable age
python scripts/verify_conduit_receipt.py --selftest    # seal + verify + catch a tamper, zero args
```

The verifier recomputes the leaf hash from the payload, checks Merkle inclusion against the checkpoint root, verifies the Ed25519 note under the pinned log key, and (when anchored) verifies the RFC-3161 token's CMS signature against the pinned TSA cert. A single flipped byte fails it.

## Tests

```bash
PYTHONPATH=src python -m pytest tests/discovery/conduit/ -q
```

40 tests cover: connector generalization & Entra equivalence, grant seal + offline verify + tamper, connection drift, Okta cross-IdP neutrality, inventory snapshot roots, standing watch, shadow correlation, Google/Ping discovery + two-grant sealing, EvidenceFold, and the provenance tiers.

## Regulatory wedge

EU AI Act enforcement is live **Aug 2, 2026** (Arts. 10/12/50 + Annex IV), read as requiring runtime proof that governance held at the moment the AI acted. Incumbents answer with logs. Tex answers with externally-anchored receipts — see `tiers.py` for the NIST SP 800-53 AU-10/AU-9 and EU AI Act mappings.

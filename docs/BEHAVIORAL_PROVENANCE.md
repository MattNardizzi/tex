# Behavioural Provenance — identity by behaviour, sealed as proof

This is the discovery/inventory primitive that puts Tex ahead of every
shipping product in the category as of mid-2026. It is the component that
lets Tex stop trusting what an agent *claims* about itself and start
proving who it is by what it *does* — and seal that identity into a log
anyone can verify without trusting Tex.

## The weakness it closes

Every discovery product in the field identifies an agent by an assertion:
a directory entry, an OAuth consent, a self-declared MCP/A2A card, a
`(source, tenant, external_id)` tuple. Each of those anchors can be
forged, rotated, renamed — or is simply absent for the shadow agent with
no card and a personal key on a laptop. The 2026 literature names this as
an unsolved gap: self-declaration is forgeable and no third party attests
to what an agent really is. The directory companies (Okta, Entra) cannot
easily fix it, because their identity anchor is the very thing that
rotates, and their product is a mutable directory, not a proof.

## How it works

`tex.provenance` derives an agent's identity from the causal signature of
how it acts, observed at the enforcement gate (the agent action ledger):

- **`signature.py`** — `BehavioralSignature`, a content-free fingerprint:
  distributions over action types / channels / environments / verdicts,
  the tool / MCP / data-scope sets actually exercised, scalar risk
  moments, behavioural cadence, and the stable identity anchors
  (system-prompt / tool-manifest / memory hashes). Metadata only, never
  content — the same privacy line the egress plane holds.
- **`distance.py`** — `behavioral_confidence`, a calibrated [0, 1] belief
  that two signatures are the same actor. Shared stable anchors dominate
  (they survive credential rotation and rename); absent them, behavioural
  overlap is capped, because behaviour is strong evidence, not proof.
- **`ledger.py`** — `BehavioralProvenanceLedger`, an append-only,
  hash-chained, **and per-entry ECDSA-signed** transparency log
  (Certificate Transparency for agents). A relying party verifies the
  chain *and* the signatures offline, holding only the public key.
- **`engine.py`** — `BehavioralProvenanceEngine`, which observes a window,
  resolves identity, and seals the outcome: `BIRTH` (new actor, with a
  verifiable birth certificate anchored to attested identity), `SIGHTING`
  (confirmed), `REIDENTIFIED` (same actor under a new name/key — the case
  directory identity misses), or `DRIFT` (a known agent stopped behaving
  like itself). Every outcome carries a **graded confidence, sealed
  alongside the fact** — never a bare claim. Consequential, ambiguous
  resolutions (a possible merge, a drift past threshold) set
  `requires_human`: the held-decision path.

## What else landed alongside it

- **`tex.domain.signal_trust.SignalTrustTier`** — the admissibility grade
  of *how* an agent was discovered, orthogonal to how privileged it is.
  Kernel/TEE and cloud-audit at the top (the workload cannot forge them),
  the enforcement gate's own observation next, platform APIs below, bare
  self-declaration at the bottom. The provability of every inventory entry
  is graded and sealed — never overstated.
- **`AgentLifecycleStatus.SLEEPING`** — a reversible dormant state. An idle
  agent is put to sleep on Tex's own authority (credentials suspended,
  state preserved, signature frozen), reversible for 90 days, sealed and
  never announced. An attempt to act while sleeping routes to `ABSTAIN`,
  so a wake is a deliberate sealed human act. The transition past 90 days
  into terminal `REVOKED` is the one irreversible step, and so is the rare
  held decision a human must make.

## Surface

`/v1/provenance/observe`, `/identity/{agent_id}`, `/reidentify`,
`/ledger`, `/ledger/verify`. Authed like the proof endpoints
(`decision:read`; the raw log and verification also need `evidence:read`).
Keyless dev backends work anonymously.

## Honest edges (a witness states them)

- **Cold start.** An agent that has acted once has a weak fingerprint. The
  engine reports low confidence below the warm threshold and complements,
  not replaces, the identity and attestation roots.
- **False merge / split.** Two look-alike agents, or one that shifts. The
  discipline: Tex seals confidence, never asserts identity. Merges are a
  human's decision, surfaced as a held decision.
- **Behaviour ≠ content.** The signature is built only from what an agent
  reached for, never what it said. Crossing that line would break the
  privacy posture.

## Retired in this change

The arcade and leaderboard surfaces (`api/arcade_leaderboard.py`,
`api/leaderboard.py`, their repos and tests) — marketing leftovers off the
product path — and the macOS zip-duplicate directories. The discovery
core (ledger, reconciliation engine, connectors, scan-run lifecycle,
presence, scheduler) was kept and built upon, not replaced.

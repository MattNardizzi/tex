"""
tex-conduit — one read-only "Connect your directory" capability.

Conduit sits **in front of** the existing discovery connector Protocol and
**behind** the existing seal/anchor stack. It does not reinvent the connector
framework, the reconciliation engine, the ledger, the scheduler, or the seal
stack — it *composes* them.

The load-bearing differentiators live here:

  * **Seal the grant.** The moment a customer grants Tex read-only access to
    their identity directory, conduit seals that grant as the first
    tamper-evident receipt (``GRANT_SEALED``) — before any agent is read.
  * **Discovery-as-provenance.** The exact set of agents discovered at time T
    is sealed as a Merkle-rooted, externally-anchored snapshot
    (``INVENTORY_SNAPSHOT_SEALED``).

Everything else (cross-IdP normalization of agent/NHI objects, fail-closed
drift detection, shadow correlation) is plumbing in service of those two.

This package emits ordinary ``CandidateAgent`` records into the unchanged
reconciliation/ledger/scheduler/ignition pipeline. Connectors here obey the
same rule every connector obeys: *look at the platform, emit candidates* —
never mutate the registry, write the ledger, or promote.
"""

from __future__ import annotations

"""
Phase 2 gate: inventory-snapshot seal + standing watch made real.

  * Two scans of different estates seal snapshots with DIFFERENT Merkle roots;
    both verify offline. The root commits to the exact agent set at time T.
  * The standing watch turns a delta into re-emitted CandidateAgents and a
    fresh sealed snapshot — not raw dicts into the void. A delta with no change
    re-seals nothing.
  * Anchoring is batched: with anchor_every=2 only every other snapshot pays
    the external RFC 3161 call.
"""

from __future__ import annotations

from tex.discovery.conduit.profiles.entra_profile import ENTRA_PROFILE
from tex.discovery.conduit.connector import ProviderConsentGraphConnector
from tex.discovery.conduit.seal import (
    ConduitEventKind,
    ConduitProvenanceChain,
    InventorySnapshotSealer,
    StandingWatch,
)
from tex.discovery.connectors.base import ConnectorContext
from tex.discovery.connectors.entra_consent_graph import EntraConsentGraphConnector
from tex.discovery.graph_transport import FixtureGraphTransport
from tex.interchange._local_tsa import issue_timestamp_response, mint_local_tsa
from tex.interchange.external_anchor import CheckpointAnchorRecord, anchor_subject_digest


def _sp(i: int) -> dict:
    return {
        "id": f"sp-{i}",
        "displayName": f"Bot {i}",
        "servicePrincipalType": "Application",
        "tags": ["AgentIdentity"],
    }


def _entra_pages(n: int, *, delta: list | None = None) -> dict:
    pages: dict[str, list] = {"servicePrincipals": [_sp(i) for i in range(n)]}
    for i in range(n):
        pages[f"servicePrincipals/sp-{i}/oauth2PermissionGrants"] = [
            {
                "resourceId": "resource-graph",
                "resourceDisplayName": "Microsoft Graph",
                "scope": "Mail.Send",
                "consentType": "AllPrincipals",
            }
        ]
        pages[f"servicePrincipals/sp-{i}/appRoleAssignments"] = []
    if delta is not None:
        pages["servicePrincipals/delta"] = delta
    return pages


def _scan(pages: dict) -> list:
    conn = ProviderConsentGraphConnector(
        transport=FixtureGraphTransport(pages), profile=ENTRA_PROFILE
    )
    return list(conn.scan(ConnectorContext(tenant_id="acme")))


def _local_anchor(tsa, *, nonce=4242):
    def _anchor(snapshot):
        cp = snapshot.checkpoint
        digest = anchor_subject_digest(cp.origin, cp.tree_size, cp.root_hash)
        resp = issue_timestamp_response(digest, tsa, nonce=nonce)
        return CheckpointAnchorRecord.from_response(
            checkpoint=cp,
            signed_note=snapshot.signed_note,
            authority="local-demo-tsa",
            response_der=resp,
            request_nonce=nonce,
        )

    return _anchor


def test_inventory_snapshot_root_changes_with_estate():
    chain = ConduitProvenanceChain(origin="tex.conduit/test-inv")
    sealer = InventorySnapshotSealer(chain)

    c1 = _scan(_entra_pages(1))
    c2 = _scan(_entra_pages(2))
    r1 = sealer.seal("acme", c1)
    r2 = sealer.seal("acme", c2)

    assert r1.kind is ConduitEventKind.INVENTORY_SNAPSHOT_SEALED
    assert r1.payload["agent_count"] == len(c1)
    assert r2.payload["agent_count"] == len(c2)
    # Different estate -> different sealed root.
    assert r1.payload["inventory_merkle_root"] != r2.payload["inventory_merkle_root"]
    # Both verify offline.
    pin = chain.public_key_b64()
    assert r1.verify(pinned_log_public_key_b64=pin).ok
    assert r2.verify(pinned_log_public_key_b64=pin).ok


def test_identical_estate_reseals_identical_root():
    chain = ConduitProvenanceChain(origin="tex.conduit/test-inv-stable")
    sealer = InventorySnapshotSealer(chain)
    pages = _entra_pages(2)
    r1 = sealer.seal("acme", _scan(pages))
    r2 = sealer.seal("acme", _scan(pages))
    # Same estate -> same inventory root (order-independent, content-addressed).
    assert r1.payload["inventory_merkle_root"] == r2.payload["inventory_merkle_root"]


def test_standing_watch_emits_candidates_and_reseals():
    chain = ConduitProvenanceChain(origin="tex.conduit/test-watch")
    sealer = InventorySnapshotSealer(chain)
    # Estate of 2, plus a delta page reporting one changed principal.
    connector = EntraConsentGraphConnector(
        transport=FixtureGraphTransport(_entra_pages(2, delta=[_sp(0)]))
    )
    watch = StandingWatch(
        connector=connector,
        sealer=sealer,
        context=ConnectorContext(tenant_id="acme"),
    )

    tick = watch.on_delta()
    assert tick.changed_count >= 1
    # The watch emitted real CandidateAgents (not raw dicts) and re-sealed.
    assert tick.candidate_count == 2
    assert tick.receipt is not None
    assert tick.receipt.kind is ConduitEventKind.INVENTORY_SNAPSHOT_SEALED
    assert tick.receipt.verify(pinned_log_public_key_b64=chain.public_key_b64()).ok

    # Delta cursor advances; a no-change sweep re-seals nothing.
    tick2 = watch.on_delta()
    assert tick2.changed_count == 0
    assert tick2.receipt is None


def test_inventory_anchor_is_batched():
    tsa = mint_local_tsa()
    chain = ConduitProvenanceChain(origin="tex.conduit/test-batch")
    sealer = InventorySnapshotSealer(chain, anchor=_local_anchor(tsa), anchor_every=2)
    estate = _scan(_entra_pages(1))

    r0 = sealer.seal("acme", estate)  # count 0 -> anchored
    r1 = sealer.seal("acme", estate)  # count 1 -> not anchored
    r2 = sealer.seal("acme", estate)  # count 2 -> anchored

    assert r0.anchor is not None
    assert r1.anchor is None
    assert r2.anchor is not None
    # The anchored snapshot proves age against the pinned TSA cert.
    v = r0.verify(pinned_log_public_key_b64=chain.public_key_b64(), pinned_tsa_cert_der=tsa.ca_pin_der)
    assert v.ok and v.anchor_status == "verified"

"""
Task 11 gate: a sealed Entra connection actually maps the connected tenant.

Proven without live Microsoft by injecting a FixtureGraphTransport through the
real broker flow, then driving the real ignite path:

  * ConduitConnectionsConnector delegates to the shared connector for a tenant
    that has a sealed connection, and is INERT for one that doesn't.
  * End-to-end: connect + seal a tenant -> POST /ignite for that tenant ->
    discovery maps its estate and the count is non-zero (it was 0 before this
    wiring).
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from tex.discovery.conduit.live_connector import ConduitConnectionsConnector
from tex.discovery.conduit.profiles.entra_profile import ENTRA_PROFILE
from tex.discovery.conduit.providers.base import ConsentCallback
from tex.discovery.conduit.providers.entra import ENTRA_READ_SCOPES
from tex.discovery.connectors.base import ConnectorContext
from tex.discovery.graph_transport import FixtureGraphTransport
from tex.domain.discovery import DiscoverySource


def _entra_pages(sp_id="sp-connected-1"):
    # A BOUNDED, read-only agent: a non-tenant-wide read scope -> LOW risk,
    # surface NOT unbounded -> auto-registers (counts in the estate). An
    # unbounded agent (e.g. Mail.Send on AllPrincipals) would correctly be
    # HELD for review by doctrine, not auto-counted.
    return {
        "servicePrincipals": [
            {
                "id": sp_id,
                "displayName": "Connected Bot",
                "servicePrincipalType": "Application",
                "tags": ["AgentIdentity"],
            }
        ],
        f"servicePrincipals/{sp_id}/oauth2PermissionGrants": [
            {
                "resourceId": "resource-graph",
                "resourceDisplayName": "Microsoft Graph",
                "scope": "User.Read.All",
            }
        ],
        f"servicePrincipals/{sp_id}/appRoleAssignments": [],
    }


def test_connections_connector_delegates_only_for_connected_tenant():
    transport = FixtureGraphTransport(_entra_pages())

    def lookup(tenant_id):
        if tenant_id == "contoso":
            return (transport, DiscoverySource.MICROSOFT_GRAPH)
        return (None, None)

    connector = ConduitConnectionsConnector(
        lookup=lookup, profiles={DiscoverySource.MICROSOFT_GRAPH: ENTRA_PROFILE}
    )

    connected = list(connector.scan(ConnectorContext(tenant_id="contoso")))
    assert len(connected) >= 1
    for c in connected:
        assert c.tenant_id == "contoso"
        assert c.source is DiscoverySource.MICROSOFT_GRAPH

    # A tenant with no sealed connection yields nothing — inert.
    assert list(connector.scan(ConnectorContext(tenant_id="not-connected"))) == []


def test_ignite_maps_a_connected_tenant_end_to_end():
    from tex.main import create_app

    app = create_app()
    broker = app.state.conduit_broker

    # Inject a fixture transport via the strategy's factory — the real connect
    # flow, but reading a fixture instead of live Microsoft.
    strat = broker.strategy_for(DiscoverySource.MICROSOFT_GRAPH)
    strat.transport_factory = lambda grant: FixtureGraphTransport(_entra_pages())

    challenge = broker.request(DiscoverySource.MICROSOFT_GRAPH, "contoso", nonce="itest")
    broker.consent(
        ConsentCallback(
            connection_id=challenge.connection_id,
            consent_artifact_id="contoso",
            granted_scopes=ENTRA_READ_SCOPES,
            credential_ref="vault://tex/entra/contoso",
        )
    )
    broker.probe(challenge.connection_id)
    receipt = broker.seal(challenge.connection_id)
    assert receipt.kind.value == "grant_sealed"

    # Now ignite that connected tenant — discovery must map its real estate.
    client = TestClient(app)
    body = client.post(
        "/v1/surface/discovery/ignite", params={"tenant_id": "contoso"}
    ).json()
    assert body["already_ignited"] is False
    assert body["count"] >= 1  # 0 before this wiring; now the connected estate maps


def test_unconnected_tenant_still_ignites_to_zero():
    """A tenant that never connected has nothing to map (the seed is off in
    tests) — proving the conduit connector didn't change default behavior."""
    from tex.main import create_app

    client = TestClient(create_app())
    body = client.post(
        "/v1/surface/discovery/ignite", params={"tenant_id": "never-connected-tenant"}
    ).json()
    assert body["count"] == 0

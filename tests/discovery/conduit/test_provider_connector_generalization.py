"""
Phase 0a gate: the generalized consent-graph connector.

Two things proven here:

  1. The new conduit ``DiscoverySource`` members exist (per-platform, never
     reused — reconciliation_key correctness depends on it).
  2. ``ProviderConsentGraphConnector`` driven by ``ENTRA_PROFILE`` reproduces
     the legacy Entra connector's banding exactly, AND a non-Entra profile with
     its own critical-scope set bands on *its own* dictionary against the same
     ``blast_radius()`` engine — proving critical scopes are profile-scoped,
     not hard-wired to Entra's literal permission strings.

No tags are planted: the generic-provider fixture is a made-up raw API shape
(``apps`` / ``grants`` / ``super_admin``) that the profile's predicate and
mapper have to actually interpret to find the agent and band it.
"""

from __future__ import annotations

from tex.discovery.conduit.connector import (
    GrantCollection,
    ProviderConsentGraphConnector,
    ProviderProfile,
)
from tex.discovery.conduit.profiles.entra_profile import ENTRA_PROFILE
from tex.discovery.connectors.base import ConnectorContext
from tex.discovery.connectors.entra_consent_graph import EntraConsentGraphConnector
from tex.discovery.consent_graph import CRITICAL_SCOPE_STEMS, HIGH_RISK_SCOPE_STEMS, ConsentEdge
from tex.discovery.graph_transport import FixtureGraphTransport
from tex.domain.discovery import DiscoveryRiskBand, DiscoverySource


def _entra_fixture(sp_id: str, scope: str) -> FixtureGraphTransport:
    return FixtureGraphTransport(
        {
            "servicePrincipals": [
                {
                    "id": sp_id,
                    "displayName": "Invoice Bot",
                    "servicePrincipalType": "Application",
                    "tags": ["AgentIdentity"],
                },
                {
                    "id": "resource-graph",
                    "displayName": "Microsoft Graph",
                    "servicePrincipalType": "Application",
                },
            ],
            f"servicePrincipals/{sp_id}/oauth2PermissionGrants": [
                {
                    "resourceId": "resource-graph",
                    "resourceDisplayName": "Microsoft Graph",
                    "scope": scope,
                    "consentType": "AllPrincipals",
                }
            ],
            f"servicePrincipals/{sp_id}/appRoleAssignments": [],
            "servicePrincipals/resource-graph/oauth2PermissionGrants": [],
            "servicePrincipals/resource-graph/appRoleAssignments": [],
        }
    )


def test_new_conduit_discovery_sources_exist():
    assert DiscoverySource.OKTA == "okta"
    assert DiscoverySource.GOOGLE_WORKSPACE == "google_workspace"
    assert DiscoverySource.GCP_IAM == "gcp_iam"
    assert DiscoverySource.PING == "ping"
    # And they are distinct members, not aliases of an existing source.
    assert len({
        DiscoverySource.OKTA,
        DiscoverySource.GOOGLE_WORKSPACE,
        DiscoverySource.GCP_IAM,
        DiscoverySource.PING,
        DiscoverySource.MICROSOFT_GRAPH,
    }) == 5


def test_generalized_connector_equals_legacy_entra():
    sp_id = "11111111-1111-1111-1111-111111111111"
    scope = "Mail.Send Files.ReadWrite.All"  # high stems, tenant-wide -> HIGH
    ctx = ConnectorContext(tenant_id="tenant-1")

    legacy = list(EntraConsentGraphConnector(transport=_entra_fixture(sp_id, scope)).scan(ctx))
    general = list(
        ProviderConsentGraphConnector(
            transport=_entra_fixture(sp_id, scope), profile=ENTRA_PROFILE
        ).scan(ctx)
    )

    # Same estate -> same number of agent-bearing principals discovered.
    assert len(legacy) == len(general)
    a = next(c for c in legacy if c.external_id == sp_id)
    b = next(c for c in general if c.external_id == sp_id)
    # Field-equality on the meaningful surface locks the equivalence.
    assert a.source == b.source == DiscoverySource.MICROSOFT_GRAPH
    assert a.external_id == b.external_id == sp_id
    assert a.risk_band == b.risk_band == DiscoveryRiskBand.HIGH  # real expected band
    assert a.capability_hints == b.capability_hints
    assert a.evidence["blast_radius"] == b.evidence["blast_radius"]
    assert a.evidence["blast_radius"]["reachable_resource_count"] >= 1


def test_entra_critical_scope_bands_critical():
    sp_id = "22222222-2222-2222-2222-222222222222"
    ctx = ConnectorContext(tenant_id="tenant-1")
    # Directory.ReadWrite.All is a literal Entra critical permission.
    cands = list(
        ProviderConsentGraphConnector(
            transport=_entra_fixture(sp_id, "Directory.ReadWrite.All"), profile=ENTRA_PROFILE
        ).scan(ctx)
    )
    privileged = next(c for c in cands if c.external_id == sp_id)
    assert privileged.risk_band == DiscoveryRiskBand.CRITICAL


def test_profile_drives_provider_specific_critical_band():
    """
    A non-Entra provider with a flat principal list, one grant collection, and
    a critical-scope set unique to it. The same engine must band CRITICAL on
    the provider's own critical scope — which is NOT in Entra's critical set.
    """
    transport = FixtureGraphTransport(
        {
            "apps": [
                {"id": "app-1", "label": "Privileged Bot", "kind": "service"},
                {"id": "resource-x", "label": "Some API", "kind": "resource"},
            ],
            "apps/app-1/grants": [
                {"target": "resource-x", "target_label": "Some API", "perm": "super_admin"},
            ],
            "apps/resource-x/grants": [],
        }
    )

    def mapper(client_id, row):
        target = str(row.get("target") or "").strip()
        if not target:
            return None
        return ConsentEdge(
            client_id=client_id,
            resource_id=target,
            resource_name=str(row.get("target_label") or target),
            scopes=(str(row.get("perm")),),
            tenant_wide=True,
        )

    profile = ProviderProfile(
        source=DiscoverySource.OKTA,
        connector_name="test_generic",
        principal_collection="apps",
        grant_collections=(GrantCollection("apps/{principal_id}/grants", mapper),),
        delta_path="apps/delta",
        is_agent=lambda row: row.get("kind") == "service",
        critical_scopes=frozenset({"super_admin"}),
        high_risk_stems=HIGH_RISK_SCOPE_STEMS,
        display_name_of=lambda row: row.get("label"),
    )

    cands = list(
        ProviderConsentGraphConnector(transport=transport, profile=profile).scan(
            ConnectorContext(tenant_id="t1")
        )
    )
    assert len(cands) == 1
    c = cands[0]
    assert c.source == DiscoverySource.OKTA
    assert c.external_id == "app-1"
    assert c.risk_band == DiscoveryRiskBand.CRITICAL
    # The band came from THIS provider's dictionary, not Entra's defaults.
    assert "super_admin" not in CRITICAL_SCOPE_STEMS
    # reconciliation_key is provider-scoped and uncorrupted.
    assert c.reconciliation_key == "okta:t1:app-1"

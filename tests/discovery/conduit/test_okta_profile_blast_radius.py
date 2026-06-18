"""
Phase 1 gate: Okta discovery + cross-IdP neutrality.

Proven here (with FIXTURE Okta data only — no live tenant, no planted tags):

  * The Okta profile discovers the machine-to-machine OAuth clients (service
    apps) and does NOT emit the human SSO app — the predicate genuinely reads
    the raw ``signOnMode`` / ``oauthClient`` fields to decide.
  * An over-privileged Okta client (``okta.users.manage``) lands in the SAME
    CRITICAL band the equivalent over-privileged Entra app does — the band
    equality IS the neutrality proof.
  * Withholding ``okta.appGrants.read`` yields a grant sealed as PARTIAL
    (degraded), and the apps+clients census still runs (no crash) — it just
    can't see the grant edges, so reach is unknown.

The fixtures (``fixtures/okta_apps.json`` / ``okta_grants.json``) are raw Okta
``/api/v1`` API shapes. Read them: nothing tags an app as an agent.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from tex.discovery.conduit.connector import ProviderConsentGraphConnector
from tex.discovery.conduit.grant import DirectoryGrant
from tex.discovery.conduit.profiles.entra_profile import ENTRA_PROFILE
from tex.discovery.conduit.profiles.okta_profile import OKTA_PROFILE
from tex.discovery.conduit.seal import ConduitProvenanceChain, seal_grant
from tex.discovery.connectors.base import ConnectorContext
from tex.discovery.graph_transport import FixtureGraphTransport
from tex.domain.discovery import DiscoveryRiskBand, DiscoverySource

_FIXTURES = Path(__file__).parent / "fixtures"


def _okta_transport(*, with_grants: bool = True) -> FixtureGraphTransport:
    apps = json.loads((_FIXTURES / "okta_apps.json").read_text())
    grants = json.loads((_FIXTURES / "okta_grants.json").read_text())
    pages: dict[str, list] = {"apps": apps}
    for app_id, rows in grants.items():
        pages[f"apps/{app_id}/grants"] = rows if with_grants else []
    return FixtureGraphTransport(pages)


def _scan(transport, profile=OKTA_PROFILE):
    return list(
        ProviderConsentGraphConnector(transport=transport, profile=profile).scan(
            ConnectorContext(tenant_id="acme")
        )
    )


def test_okta_discovers_only_machine_identities():
    cands = _scan(_okta_transport())
    ids = {c.external_id for c in cands}
    # The two service apps are discovered; the human SSO app is NOT.
    assert ids == {"0oaAAAAprovisioner01", "0oaBBBBreporter02"}
    assert "0oaCCCChrportal03" not in ids
    for c in cands:
        assert c.source is DiscoverySource.OKTA
        # reconciliation_key casefolds external_id (domain-model behavior for
        # every source); external_id itself is preserved original-case.
        assert c.reconciliation_key == f"okta:acme:{c.external_id.casefold()}"


def test_okta_overprivileged_client_is_critical():
    cands = {c.external_id: c for c in _scan(_okta_transport())}
    provisioner = cands["0oaAAAAprovisioner01"]
    reporter = cands["0oaBBBBreporter02"]
    assert provisioner.risk_band is DiscoveryRiskBand.CRITICAL  # okta.users.manage
    assert reporter.risk_band is DiscoveryRiskBand.LOW  # okta.logs.read only
    # The critical scope shows up in the sealed blast radius evidence.
    assert "okta.users.manage" in provisioner.evidence["blast_radius"]["critical_scopes"]


def test_cross_idp_neutrality_same_critical_band():
    """The neutrality proof: same engine, same band, different directory."""
    okta = {c.external_id: c for c in _scan(_okta_transport())}["0oaAAAAprovisioner01"]

    # The Entra equivalent: an app with a literal critical Graph permission.
    entra_sp = "11111111-1111-1111-1111-111111111111"
    entra_transport = FixtureGraphTransport(
        {
            "servicePrincipals": [
                {
                    "id": entra_sp,
                    "displayName": "Over-Privileged Provisioner",
                    "servicePrincipalType": "Application",
                    "tags": ["AgentIdentity"],
                }
            ],
            f"servicePrincipals/{entra_sp}/oauth2PermissionGrants": [
                {
                    "resourceId": "resource-graph",
                    "resourceDisplayName": "Microsoft Graph",
                    "scope": "Directory.ReadWrite.All",
                    "consentType": "AllPrincipals",
                }
            ],
            f"servicePrincipals/{entra_sp}/appRoleAssignments": [],
        }
    )
    entra = next(
        c for c in _scan(entra_transport, ENTRA_PROFILE) if c.external_id == entra_sp
    )

    # Different providers, different scope vocabularies — identical band.
    assert okta.risk_band == entra.risk_band == DiscoveryRiskBand.CRITICAL
    assert okta.source is DiscoverySource.OKTA
    assert entra.source is DiscoverySource.MICROSOFT_GRAPH


def test_withheld_appgrants_seals_partial_and_census_still_runs():
    # appGrants.read withheld: the grant is degraded (partial), sealed honestly.
    chain = ConduitProvenanceChain(origin="tex.conduit/test-okta-partial")
    grant = DirectoryGrant(
        provider=DiscoverySource.OKTA,
        tenant_id="acme",
        requested_scopes=["okta.apps.read", "okta.clients.read", "okta.appgrants.read"],
        granted_scopes=["okta.apps.read", "okta.clients.read"],  # Super Admin scope withheld
        consent_artifact_id="0oaSERVICEAPP",
        consented_by="admin@acme.example",
        granted_at=datetime.now(UTC),
        credential_ref="vault://tex/okta/acme",
    )
    assert grant.degraded is True
    assert grant.missing_scopes == ("okta.appgrants.read",)
    receipt = seal_grant(chain, grant)
    assert receipt.payload["degraded"] is True
    assert receipt.verify(pinned_log_public_key_b64=chain.public_key_b64()).ok

    # The apps+clients census still runs without the grant edges (no crash);
    # agents are found but with no observed reach -> LOW band.
    cands = {c.external_id: c for c in _scan(_okta_transport(with_grants=False))}
    assert set(cands) == {"0oaAAAAprovisioner01", "0oaBBBBreporter02"}
    assert cands["0oaAAAAprovisioner01"].risk_band is DiscoveryRiskBand.LOW

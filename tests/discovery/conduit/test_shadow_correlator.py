"""
Phase 3 gate: explicit shadow correlation across the two planes.

Built on REAL connector output (OcsfAuditConnector for the behavioral plane,
the Entra consent-graph connector for the control plane) — not hand-built
candidates — so the cross-namespace join is exercised honestly.

  * A behavioral actor whose principal id matches a control-plane principal is
    CORRELATED (attached as evidence on that principal) and is NOT emitted as a
    second agent — no double counting.
  * A behavioral actor that matches nothing acted-but-unregistered -> SHADOW.
  * Shadow confidence is differentiated per provider: a Google shadow (180-day
    audit retention) is less certain than an AWS one.
"""

from __future__ import annotations

from tex.discovery.conduit.shadow import CORRELATED, SHADOW, ShadowCorrelator
from tex.discovery.connectors.base import ConnectorContext
from tex.discovery.connectors.cloud_audit_ocsf import OcsfAuditConnector
from tex.discovery.connectors.entra_consent_graph import EntraConsentGraphConnector
from tex.discovery.graph_transport import FixtureGraphTransport

_CTX = ConnectorContext(tenant_id="tenant")


def _control_plane():
    transport = FixtureGraphTransport(
        {
            "servicePrincipals": [
                {
                    "id": "sp-erp-7",
                    "displayName": "ERP Bot",
                    "servicePrincipalType": "Application",
                    "tags": ["AgentIdentity"],
                }
            ],
            "servicePrincipals/sp-erp-7/oauth2PermissionGrants": [],
            "servicePrincipals/sp-erp-7/appRoleAssignments": [],
        }
    )
    return list(EntraConsentGraphConnector(transport=transport).scan(_CTX))


def _behavioral():
    # OCSF-normalized audit events (Security Lake shape). No resources -> the
    # actor's principal id is the stable handle.
    records = [
        {
            "class_uid": 6003,
            "actor": {"user": {"uid": "sp-erp-7", "name": "ERP Bot"}},
            "api": {"operation": "UpdateConfiguration"},
            "time": "2026-05-20T10:00:00Z",
            "metadata": {"product": {"vendor_name": "AWS", "name": "CloudTrail"}},
        },
        {
            "class_uid": 6003,
            "actor": {"user": {"uid": "rogue-shadow-9", "name": "??"}},
            "api": {"operation": "DeleteBucket"},
            "time": "2026-05-20T11:00:00Z",
            "metadata": {"product": {"vendor_name": "AWS", "name": "CloudTrail"}},
        },
        {
            "class_uid": 6003,
            "actor": {"user": {"uid": "ghost-gcp-1", "name": "ghost"}},
            "api": {"operation": "tokens.list"},
            "time": "2026-05-20T12:00:00Z",
            "metadata": {"product": {"vendor_name": "Google", "name": "Reports"}},
        },
    ]
    return list(OcsfAuditConnector(source=lambda ctx: records, source_format="ocsf").scan(_CTX))


def test_correlated_actor_is_not_double_counted():
    correlator = ShadowCorrelator()
    cp = _control_plane()
    beh = _behavioral()
    report = correlator.correlate(control_plane=cp, behavioral=beh)

    correlated = report.correlations
    assert len(correlated) == 1
    c = correlated[0]
    assert c.actor_handle == "sp-erp-7"
    assert c.classification == CORRELATED
    assert c.matched_control_plane_key == "microsoft_graph:tenant:sp-erp-7"
    assert c.join_basis == "sp-erp-7"

    # The correlated actor is NOT surfaced as a shadow agent.
    shadow_handles = {f.actor_handle for f in report.shadows}
    assert "sp-erp-7" not in shadow_handles

    # Its activity attaches to the control-plane principal as evidence.
    annotated = correlator.attach_correlations(cp, beh, report)
    erp = next(c for c in annotated if c.external_id == "sp-erp-7")
    assert "correlated_behavioral_activity" in erp.evidence
    assert erp.evidence["correlated_behavioral_activity"][0]["actor_handle"] == "sp-erp-7"


def test_unregistered_actors_are_shadow_with_per_provider_confidence():
    correlator = ShadowCorrelator()
    cp = _control_plane()
    beh = _behavioral()
    report = correlator.correlate(control_plane=cp, behavioral=beh)

    shadows = {f.actor_handle: f for f in report.shadows}
    assert set(shadows) == {"rogue-shadow-9", "ghost-gcp-1"}
    for f in shadows.values():
        assert f.classification == SHADOW

    aws_conf = shadows["rogue-shadow-9"].confidence
    google_conf = shadows["ghost-gcp-1"].confidence
    # Google's 180-day retention -> a Google shadow is less certain.
    assert google_conf < aws_conf

    # mark_shadows annotates and tags only the shadows (not the correlated one).
    marked = correlator.mark_shadows(beh, report)
    marked_ids = {m.external_id for m in marked}
    assert marked_ids == {"rogue-shadow-9", "ghost-gcp-1"}
    for m in marked:
        assert "shadow" in m.tags
        assert m.evidence["shadow_finding"]["classification"] == SHADOW
        assert m.evidence["shadow_finding"]["basis"] == "acted_but_unregistered"


def test_no_control_plane_means_everything_is_shadow():
    correlator = ShadowCorrelator()
    beh = _behavioral()
    report = correlator.correlate(control_plane=[], behavioral=beh)
    assert len(report.shadows) == 3
    assert len(report.correlations) == 0

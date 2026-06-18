"""
Phase 0b gate: seal the grant, verify offline, catch the drift.

Proven here:

  * A DirectoryGrant seals to a receipt that verifies OFFLINE against a pinned
    log key — and a one-byte tamper of the sealed payload is rejected.
  * With an external RFC 3161 anchor (a throwaway local TSA), the receipt
    additionally proves age; a forged tree-head root is rejected.
  * A grant whose requested scopes were not all granted seals as DEGRADED
    (partial census) rather than crashing or pretending full access.
  * CONNECTION_DRIFT: when the live scope set diverges from the sealed grant,
    the connector refuses to scan (fail-closed) and seals a drift receipt; when
    it matches, the scan proceeds normally.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from tex.discovery.conduit.grant import DirectoryGrant
from tex.discovery.conduit.seal import (
    ConduitEventKind,
    ConduitProvenanceChain,
    ConnectionDriftError,
    DriftGuardedConnector,
    detect_scope_drift,
    seal_grant,
)
from tex.discovery.connectors.base import ConnectorContext
from tex.discovery.connectors.entra_consent_graph import EntraConsentGraphConnector
from tex.discovery.graph_transport import FixtureGraphTransport
from tex.domain.discovery import DiscoverySource
from tex.interchange._local_tsa import issue_timestamp_response, mint_local_tsa
from tex.interchange.external_anchor import CheckpointAnchorRecord, anchor_subject_digest


def _grant(provider=DiscoverySource.OKTA, *, requested, granted):
    return DirectoryGrant(
        provider=provider,
        tenant_id="acme",
        requested_scopes=requested,
        granted_scopes=granted,
        consent_artifact_id="0oaSERVICEAPP123",
        consented_by="admin@acme.example",
        granted_at=datetime.now(UTC),
        credential_ref="vault://tex/okta/acme",
    )


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


def _entra_fixture(sp_id="33333333-3333-3333-3333-333333333333"):
    return FixtureGraphTransport(
        {
            "servicePrincipals": [
                {
                    "id": sp_id,
                    "displayName": "Invoice Bot",
                    "servicePrincipalType": "Application",
                    "tags": ["AgentIdentity"],
                }
            ],
            f"servicePrincipals/{sp_id}/oauth2PermissionGrants": [
                {
                    "resourceId": "resource-graph",
                    "resourceDisplayName": "Microsoft Graph",
                    "scope": "Mail.Send",
                    "consentType": "AllPrincipals",
                }
            ],
            f"servicePrincipals/{sp_id}/appRoleAssignments": [],
        }
    )


def test_grant_seals_and_verifies_offline_and_rejects_tamper():
    chain = ConduitProvenanceChain(origin="tex.conduit/test")
    scopes = ["okta.apps.read", "okta.clients.read", "okta.logs.read"]
    grant = _grant(requested=scopes, granted=scopes)

    receipt = seal_grant(chain, grant)
    assert receipt.kind is ConduitEventKind.GRANT_SEALED

    pin = chain.public_key_b64()
    good = receipt.verify(pinned_log_public_key_b64=pin)
    assert good.ok, good.failures
    assert good.pinned is True

    # One-byte tamper in the sealed payload must be caught.
    bad_payload = dict(receipt.payload)
    bad_payload["granted_scopes"] = ["okta.apps.read", "okta.clients.read", "okta.logs.write"]
    tampered = receipt.model_copy(update={"payload": bad_payload})
    bad = tampered.verify(pinned_log_public_key_b64=pin)
    assert not bad.ok
    assert "payload_hash_mismatch" in bad.failures


def test_grant_anchor_proves_age_and_rejects_forged_root():
    tsa = mint_local_tsa()
    chain = ConduitProvenanceChain(origin="tex.conduit/test-anchor")
    scopes = ["okta.apps.read", "okta.clients.read"]
    grant = _grant(requested=scopes, granted=scopes)

    receipt = seal_grant(chain, grant, anchor=_local_anchor(tsa))
    good = receipt.verify(
        pinned_log_public_key_b64=chain.public_key_b64(),
        pinned_tsa_cert_der=tsa.ca_pin_der,
    )
    assert good.ok, good.failures
    assert good.anchor_status == "verified"
    assert good.gen_time is not None

    # A forged tree-head root inside the anchor record must be rejected.
    forged_anchor = receipt.anchor.model_copy(
        update={"root_hash_hex": "a" * 64}
    )
    forged = receipt.model_copy(update={"anchor": forged_anchor})
    bad = forged.verify(
        pinned_log_public_key_b64=chain.public_key_b64(),
        pinned_tsa_cert_der=tsa.ca_pin_der,
    )
    assert not bad.ok
    assert any("anchor" in f for f in bad.failures)


def test_degraded_grant_sealed_as_partial():
    chain = ConduitProvenanceChain(origin="tex.conduit/test-partial")
    # Asked for appGrants.read (Super Admin), only got apps+clients.
    grant = _grant(
        requested=["okta.apps.read", "okta.clients.read", "okta.appgrants.read"],
        granted=["okta.apps.read", "okta.clients.read"],
    )
    assert grant.degraded is True
    assert grant.is_partial is True
    assert grant.missing_scopes == ("okta.appgrants.read",)

    receipt = seal_grant(chain, grant)
    good = receipt.verify(pinned_log_public_key_b64=chain.public_key_b64())
    assert good.ok, good.failures
    # The partiality is sealed into the payload, not hidden.
    assert receipt.payload["degraded"] is True
    assert receipt.payload["missing_scopes"] == ["okta.appgrants.read"]


def test_detect_scope_drift_added_and_removed():
    grant = _grant(
        requested=["a", "b"],
        granted=["a", "b"],
    )
    # Silent escalation (added 'c') and silent revocation (removed 'b').
    added, removed = detect_scope_drift(grant, ["a", "c"])
    assert added == ("c",)
    assert removed == ("b",)
    # Exactly what was sealed -> no drift.
    assert detect_scope_drift(grant, ["b", "a"]) == ((), ())


def test_connection_drift_refuses_scan_and_seals_drift():
    chain = ConduitProvenanceChain(origin="tex.conduit/test-drift")
    sealed = ["application.read.all", "auditlog.read.all"]
    grant = _grant(provider=DiscoverySource.MICROSOFT_GRAPH, requested=sealed, granted=sealed)
    inner = EntraConsentGraphConnector(transport=_entra_fixture())

    # Live scope set silently escalated (a write scope appeared).
    drifted = DriftGuardedConnector(
        inner=inner,
        grant=grant,
        live_scopes=lambda: [*sealed, "directory.readwrite.all"],
        chain=chain,
    )
    with pytest.raises(ConnectionDriftError):
        list(drifted.scan(ConnectorContext(tenant_id="tenant-1")))

    assert drifted.last_drift_receipt is not None
    assert drifted.last_drift_receipt.kind is ConduitEventKind.CONNECTION_DRIFT
    # The drift fact itself is a valid, verifiable receipt.
    v = drifted.last_drift_receipt.verify(pinned_log_public_key_b64=chain.public_key_b64())
    assert v.ok, v.failures
    assert drifted.last_drift_receipt.payload["scopes_added"] == ["directory.readwrite.all"]


def test_no_drift_scans_normally():
    chain = ConduitProvenanceChain(origin="tex.conduit/test-nodrift")
    sealed = ["application.read.all", "auditlog.read.all"]
    grant = _grant(provider=DiscoverySource.MICROSOFT_GRAPH, requested=sealed, granted=sealed)
    inner = EntraConsentGraphConnector(transport=_entra_fixture())

    guarded = DriftGuardedConnector(
        inner=inner,
        grant=grant,
        live_scopes=lambda: list(sealed),  # exactly what was sealed
        chain=chain,
    )
    candidates = list(guarded.scan(ConnectorContext(tenant_id="tenant-1")))
    assert len(candidates) >= 1
    assert guarded.last_drift_receipt is None

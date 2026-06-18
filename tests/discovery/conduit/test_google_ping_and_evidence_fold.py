"""
Phase 4 gate: Google (two grants), Ping (pluggable base_url), guarded EvidenceFold.

  * Google seals TWO separate receipts (Workspace DWD + GCP org viewer) — never
    one click; each verifies offline.
  * The Google/GCP/Ping profiles discover machine identities and band them on
    each provider's own dictionary (roles/owner -> CRITICAL; a Ping authz-code
    web app is not an agent).
  * EvidenceFold: a verified AgentCard is additive and NEVER raises trust or
    resolves identity; an unsigned / tampered / untrusted-issuer card RAISES
    risk, is recorded as evidence, and still never touches identity or trust.
"""

from __future__ import annotations

import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tex.discovery.conduit.broker import ConnectBroker
from tex.discovery.conduit.connector import ProviderConsentGraphConnector
from tex.discovery.conduit.evidence_fold import CardVerification, EvidenceFold, _jcs
from tex.discovery.conduit.profiles.google_profile import (
    GCP_IAM_PROFILE,
    GOOGLE_WORKSPACE_PROFILE,
)
from tex.discovery.conduit.profiles.ping_profile import PING_PROFILE
from tex.discovery.conduit.providers.base import ConsentCallback
from tex.discovery.conduit.providers.google import (
    GCP_IAM_READ_SCOPES,
    GOOGLE_WORKSPACE_READ_SCOPES,
    GcpIamConnectStrategy,
    GoogleWorkspaceConnectStrategy,
)
from tex.discovery.conduit.seal import ConduitProvenanceChain
from tex.discovery.conduit.transport.ping_transport import PingTransport
from tex.discovery.connectors.base import ConnectorContext
from tex.discovery.graph_transport import FixtureGraphTransport
from tex.domain.discovery import CandidateAgent, DiscoveryRiskBand, DiscoverySource

_CTX = ConnectorContext(tenant_id="acme")


def _scan(pages, profile):
    return list(
        ProviderConsentGraphConnector(transport=FixtureGraphTransport(pages), profile=profile).scan(_CTX)
    )


# --------------------------------------------------------------------------- discovery
def test_gcp_discovers_service_accounts_and_bands_owner_critical():
    pages = {
        "serviceAccounts": [
            {
                "email": "deploy@proj.iam.gserviceaccount.com",
                "displayName": "Deploy Bot",
                "bindings": [{"role": "roles/owner", "resource": "organizations/123"}],
            },
            {
                "email": "reader@proj.iam.gserviceaccount.com",
                "displayName": "Reader",
                "bindings": [{"role": "roles/viewer", "resource": "projects/proj"}],
            },
        ]
    }
    cands = {c.external_id: c for c in _scan(pages, GCP_IAM_PROFILE)}
    assert set(cands) == {
        "deploy@proj.iam.gserviceaccount.com",
        "reader@proj.iam.gserviceaccount.com",
    }
    assert cands["deploy@proj.iam.gserviceaccount.com"].risk_band is DiscoveryRiskBand.CRITICAL
    assert cands["reader@proj.iam.gserviceaccount.com"].risk_band is DiscoveryRiskBand.LOW
    for c in cands.values():
        assert c.source is DiscoverySource.GCP_IAM


def test_workspace_dwd_client_with_admin_scope_is_critical():
    pages = {
        "domainWideDelegations": [
            {
                "clientId": "112233",
                "displayName": "Migration Tool",
                "scopes": [
                    "https://www.googleapis.com/auth/admin.directory.user",
                    "https://www.googleapis.com/auth/admin.reports.audit.readonly",
                ],
            }
        ]
    }
    cands = _scan(pages, GOOGLE_WORKSPACE_PROFILE)
    assert len(cands) == 1
    assert cands[0].source is DiscoverySource.GOOGLE_WORKSPACE
    assert cands[0].risk_band is DiscoveryRiskBand.CRITICAL  # admin.directory.user


def test_ping_discovers_only_machine_clients():
    pages = {
        "oauth/clients": [
            {
                "clientId": "svc-1",
                "name": "Batch Service",
                "grantTypes": ["client_credentials"],
                "restrictedScopes": ["p1:read:user", "p1:update:user"],
            },
            {
                "clientId": "web-1",
                "name": "Customer Portal",
                "grantTypes": ["authorization_code"],
                "restrictedScopes": ["openid", "profile"],
            },
        ]
    }
    cands = {c.external_id: c for c in _scan(pages, PING_PROFILE)}
    assert set(cands) == {"svc-1"}  # the human authz-code app is not an agent
    assert cands["svc-1"].source is DiscoverySource.PING
    assert cands["svc-1"].risk_band is DiscoveryRiskBand.CRITICAL  # p1:update:user


def test_ping_transport_base_url_is_pluggable():
    t1 = PingTransport(base_url="https://pf.acme.internal/pf-admin-api/v1", token_provider=lambda: "tok")
    t2 = PingTransport(base_url="https://api.pingone.com/v1/environments/abc", token_provider=lambda: "tok")
    assert t1._url("oauth/clients") == "https://pf.acme.internal/pf-admin-api/v1/oauth/clients"
    assert t2._url("oauth/clients") == "https://api.pingone.com/v1/environments/abc/oauth/clients"


# --------------------------------------------------------------------------- two grants
def test_google_seals_two_separate_receipts():
    chain = ConduitProvenanceChain(origin="tex.conduit/test-google")
    broker = ConnectBroker(
        strategies=[GoogleWorkspaceConnectStrategy(), GcpIamConnectStrategy()],
        chain=chain,
    )

    ws = broker.request(DiscoverySource.GOOGLE_WORKSPACE, "acme", nonce="ws")
    broker.consent(
        ConsentCallback(
            connection_id=ws.connection_id,
            consent_artifact_id="dwd-client-1",
            granted_scopes=GOOGLE_WORKSPACE_READ_SCOPES,
            credential_ref="vault://google/ws",
        )
    )
    broker.probe(ws.connection_id)
    r_ws = broker.seal(ws.connection_id)

    gcp = broker.request(DiscoverySource.GCP_IAM, "acme", nonce="gcp")
    broker.consent(
        ConsentCallback(
            connection_id=gcp.connection_id,
            consent_artifact_id="org-viewer-1",
            granted_scopes=GCP_IAM_READ_SCOPES,
            credential_ref="vault://google/gcp",
        )
    )
    broker.probe(gcp.connection_id)
    r_gcp = broker.seal(gcp.connection_id)

    # Two separate receipts, two providers, two distinct leaves.
    assert r_ws.payload["provider"] == "google_workspace"
    assert r_gcp.payload["provider"] == "gcp_iam"
    assert r_ws.record_hash_hex != r_gcp.record_hash_hex
    pin = chain.public_key_b64()
    assert r_ws.verify(pinned_log_public_key_b64=pin).ok
    assert r_gcp.verify(pinned_log_public_key_b64=pin).ok


# --------------------------------------------------------------------------- evidence fold
def _candidate(band=DiscoveryRiskBand.LOW) -> CandidateAgent:
    return CandidateAgent(
        source=DiscoverySource.OKTA,
        tenant_id="acme",
        external_id="real-app-1",
        name="Real App",
        risk_band=band,
        confidence=0.9,
    )


def _issuer_and_fold():
    key = Ed25519PrivateKey.generate()
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    issuer = "https://issuer.example/a2a"
    fold = EvidenceFold(
        trusted_issuers={issuer: base64.b64encode(raw).decode("ascii")},
        egress_allowlist={"issuer.example"},
    )
    return key, issuer, fold


def _signed_card(key, issuer, payload):
    sig = base64.b64encode(key.sign(_jcs(payload))).decode("ascii")
    return {"payload": payload, "issuer": issuer, "alg": "EdDSA", "signature_b64": sig}


def test_verified_card_is_additive_never_raises_trust_or_identity():
    key, issuer, fold = _issuer_and_fold()
    cand = _candidate()
    payload = {"agent_id": "claimed-xyz", "capabilities": ["email"]}
    res = fold.fold(cand, _signed_card(key, issuer, payload))

    assert res.verification is CardVerification.VERIFIED
    assert res.risk_raised is False
    # Identity is untouched.
    assert res.candidate.external_id == cand.external_id
    assert res.candidate.source == cand.source
    assert res.candidate.name == cand.name
    # Trust is untouched (not lowered by a good card, not raised).
    assert res.candidate.risk_band == cand.risk_band
    assert res.candidate.confidence == cand.confidence
    # The claimed identity is RECORDED but never APPLIED.
    fold_ev = res.candidate.evidence["evidence_fold"]
    assert fold_ev["verification"] == "verified"
    assert fold_ev["claimed_identity"] == "claimed-xyz"
    assert res.candidate.external_id != "claimed-xyz"


def test_tampered_card_raises_risk_only():
    key, issuer, fold = _issuer_and_fold()
    cand = _candidate(DiscoveryRiskBand.LOW)
    payload = {"agent_id": "claimed-xyz", "capabilities": ["email"]}
    card = _signed_card(key, issuer, payload)
    # Tamper the payload AFTER signing.
    card["payload"] = {"agent_id": "claimed-xyz", "capabilities": ["email", "admin"]}
    res = fold.fold(cand, card)

    assert res.verification is CardVerification.TAMPERED
    assert res.risk_raised is True
    assert res.candidate.risk_band is DiscoveryRiskBand.MEDIUM  # raised one notch
    # Identity and confidence still untouched (never trust-raising).
    assert res.candidate.external_id == cand.external_id
    assert res.candidate.confidence == cand.confidence
    assert "evidence_fold_risk" in res.candidate.tags


def test_unsigned_and_untrusted_issuer_raise_risk():
    key, issuer, fold = _issuer_and_fold()
    cand = _candidate(DiscoveryRiskBand.LOW)

    unsigned = fold.fold(cand, {"payload": {"agent_id": "x"}, "issuer": issuer})
    assert unsigned.verification is CardVerification.UNSIGNED
    assert unsigned.risk_raised is True

    card = _signed_card(key, issuer, {"agent_id": "x"})
    card["issuer"] = "https://evil.example"
    untrusted = fold.fold(cand, card)
    assert untrusted.verification is CardVerification.UNTRUSTED_ISSUER
    assert untrusted.risk_raised is True


def test_off_allowlist_source_url_is_blocked():
    key, issuer, fold = _issuer_and_fold()
    cand = _candidate()
    card = _signed_card(key, issuer, {"agent_id": "x"})
    res = fold.fold(cand, card, source_url="https://attacker.test/card.json")
    assert res.verification is CardVerification.EGRESS_BLOCKED
    assert res.risk_raised is True

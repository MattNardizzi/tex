"""
Backend gate: the conduit Entra connect route.

Exercised through the real app (TestClient) with no live Microsoft:

  * /start with no app configured -> configured:false + the honest step list
    (graceful degrade, not a broken redirect).
  * /start with an app configured -> a Microsoft admin-consent URL carrying the
    client id, the customer tenant, and the connection state.
  * /callback with admin_consent=true -> finalizes + SEALS GRANT_SEALED, reports
    the connected tenant, and tells the UI which tenant to ignite next.
  * /callback denied / errored -> connected:false, nothing sealed (fail-closed).
  * /callback with a tenant different from the one the connect started for ->
    tenant_mismatch (no tenant swap mid-flow).
  * /callback with an unknown state -> 400.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from tex.main import create_app

_BASE = "/v1/surface/conduit/connect/entra"


@pytest.fixture(scope="module")
def client():
    return TestClient(create_app())


def _start(client, tenant_id):
    return client.post(f"{_BASE}/start", params={"tenant_id": tenant_id}).json()


def test_start_not_configured_degrades_gracefully(client, monkeypatch):
    monkeypatch.delenv("TEX_CONDUIT_ENTRA_CLIENT_ID", raising=False)
    body = _start(client, "contoso.onmicrosoft.com")
    assert body["configured"] is False
    assert body["connection_id"]
    assert body["steps"]  # the honest checklist is still returned
    assert "consent_url" not in body


def test_start_configured_returns_admin_consent_url(client, monkeypatch):
    monkeypatch.setenv("TEX_CONDUIT_ENTRA_CLIENT_ID", "tex-multitenant-app-123")
    body = _start(client, "contoso.onmicrosoft.com")
    assert body["configured"] is True
    assert body["one_click"] is True
    from urllib.parse import parse_qs, urlsplit

    url = body["consent_url"]
    assert "login.microsoftonline.com/contoso.onmicrosoft.com/adminconsent" in url
    q = parse_qs(urlsplit(url).query)
    assert q["client_id"] == ["tex-multitenant-app-123"]
    # state binds the redirect back to THIS connection (urlencoded in the URL).
    assert q["state"] == [body["connection_id"]]
    assert set(body["requested_scopes"]) >= {"application.read.all", "auditlog.read.all"}


def test_callback_admin_consent_seals_grant(client, monkeypatch):
    monkeypatch.setenv("TEX_CONDUIT_ENTRA_CLIENT_ID", "tex-multitenant-app-123")
    # Sealing now requires VERIFICATION: Tex must be able to build a credentialed
    # directory transport from the grant (proving it can actually reach the
    # consented tenant), not just receive a bare admin_consent=true. So the
    # deployment must have real Entra app credentials configured.
    monkeypatch.setenv("TEX_CONDUIT_ENTRA_CLIENT_SECRET", "test-secret-not-real")
    start = _start(client, "contoso.onmicrosoft.com")
    cid = start["connection_id"]

    cb = client.get(
        f"{_BASE}/callback",
        params={"state": cid, "admin_consent": "True", "tenant": "contoso.onmicrosoft.com", "format": "json"},
    ).json()

    assert cb["connected"] is True
    assert cb["verified"] is True
    assert cb["sealed"] is True
    assert cb["receipt_kind"] == "grant_sealed"
    assert cb["provider"] == "microsoft_graph"
    assert cb["tenant"] == "contoso.onmicrosoft.com"
    assert cb["degraded"] is False
    # The UI is told which real tenant to ignite next.
    assert cb["next"]["ignite_tenant"] == "contoso.onmicrosoft.com"


def test_callback_without_credentials_records_consent_but_does_not_seal(client, monkeypatch):
    """Security gate: admin_consent=true alone MUST NOT seal a grant. When Tex
    cannot build a credentialed transport to verify the consent (no Entra app
    secret configured), the consent is recorded UNVERIFIED and NO sealed receipt
    is issued — so a forged callback can never surface as a sealed directory grant."""
    monkeypatch.setenv("TEX_CONDUIT_ENTRA_CLIENT_ID", "tex-multitenant-app-123")
    monkeypatch.delenv("TEX_CONDUIT_ENTRA_CLIENT_SECRET", raising=False)
    start = _start(client, "contoso.onmicrosoft.com")
    cid = start["connection_id"]

    cb = client.get(
        f"{_BASE}/callback",
        params={"state": cid, "admin_consent": "True", "tenant": "contoso.onmicrosoft.com", "format": "json"},
    ).json()

    assert cb["connected"] is False
    assert cb["verified"] is False
    assert cb["sealed"] is False
    assert cb["state"] == "consent_recorded_unverified"


def test_callback_denied_seals_nothing(client, monkeypatch):
    monkeypatch.setenv("TEX_CONDUIT_ENTRA_CLIENT_ID", "tex-multitenant-app-123")
    start = _start(client, "fabrikam.onmicrosoft.com")
    cid = start["connection_id"]

    cb = client.get(
        f"{_BASE}/callback",
        params={"state": cid, "error": "access_denied", "error_description": "admin declined", "format": "json"},
    ).json()
    assert cb["connected"] is False
    assert cb["error"] == "access_denied"


def test_callback_tenant_mismatch_is_rejected(client, monkeypatch):
    monkeypatch.setenv("TEX_CONDUIT_ENTRA_CLIENT_ID", "tex-multitenant-app-123")
    start = _start(client, "contoso.onmicrosoft.com")
    cid = start["connection_id"]

    cb = client.get(
        f"{_BASE}/callback",
        params={"state": cid, "admin_consent": "True", "tenant": "evil.onmicrosoft.com", "format": "json"},
    ).json()
    assert cb["connected"] is False
    assert cb["error"] == "tenant_mismatch"


def test_callback_unknown_state_400(client):
    r = client.get(
        f"{_BASE}/callback",
        params={"state": "organizations::deadbeef", "admin_consent": "True", "tenant": "x"},
    )
    assert r.status_code == 400


def test_callback_browser_gets_postmessage_close_page(client, monkeypatch):
    monkeypatch.setenv("TEX_CONDUIT_ENTRA_CLIENT_ID", "tex-multitenant-app-123")
    start = _start(client, "contoso.onmicrosoft.com")
    cid = start["connection_id"]
    # A real browser redirect sends Accept: text/html -> popup close page.
    r = client.get(
        f"{_BASE}/callback",
        params={"state": cid, "admin_consent": "True", "tenant": "contoso.onmicrosoft.com"},
        headers={"Accept": "text/html"},
    )
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]
    body = r.text
    assert "postMessage" in body
    assert "tex-conduit-connect" in body
    assert "contoso.onmicrosoft.com" in body

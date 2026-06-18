"""
Conduit connect routes — the "Connect your directory" front door.

The flagship path is Entra one-click admin consent:

  * ``POST /v1/surface/conduit/connect/entra/start`` opens a broker connection
    (state REQUESTED) and returns the Microsoft admin-consent URL the UI sends
    the admin to (in a popup). The only human action is the admin clicking
    *Accept* on Microsoft's own screen.
  * ``GET  /v1/surface/conduit/connect/entra/callback`` is where Microsoft
    redirects back. It finalizes the broker connection, **seals GRANT_SEALED**
    (the read-only grant is now a tamper-evident receipt), builds the live
    transport, and reports success. The UI then ignites discovery on the
    freshly-connected real tenant.

Config-driven so it is ready the instant Tex is registered as a multi-tenant
Entra app:

  * ``TEX_CONDUIT_ENTRA_CLIENT_ID``      — the multi-tenant app's client id
  * ``TEX_CONDUIT_ENTRA_REDIRECT_URI``   — the callback URL (defaults to this route)
  * ``TEX_CONDUIT_ENTRA_AUTHORITY``      — login authority (default public cloud)

With no client id configured, ``/start`` returns ``configured: false`` and the
honest step list rather than a broken redirect — the UI degrades gracefully.

NOTE: the broker holds connection state in-process. A single-worker deployment
(and the test client) persists start→callback fine; a multi-worker deployment
needs a shared connection store — tracked, not built here.
"""

from __future__ import annotations

import json
import os
import uuid
from urllib.parse import urlencode

from fastapi import APIRouter, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse

from tex.discovery.conduit.providers.base import ConsentCallback
from tex.discovery.conduit.providers.entra import ENTRA_READ_SCOPES
from tex.domain.discovery import DiscoverySource

__all__ = ["build_conduit_router"]


def _authority() -> str:
    return os.environ.get(
        "TEX_CONDUIT_ENTRA_AUTHORITY", "https://login.microsoftonline.com"
    ).rstrip("/")


def _entra_client_id() -> str:
    return os.environ.get("TEX_CONDUIT_ENTRA_CLIENT_ID", "").strip()


def _entra_redirect_uri(request: Request) -> str:
    configured = os.environ.get("TEX_CONDUIT_ENTRA_REDIRECT_URI", "").strip()
    if configured:
        return configured
    # Fall back to this route's own URL so a single-host deployment works
    # without extra config.
    return str(request.url_for("conduit_entra_callback"))


def _broker(request: Request):
    broker = getattr(request.app.state, "conduit_broker", None)
    if broker is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="conduit broker not attached",
        )
    return broker


def _admin_consent_url(tenant: str, client_id: str, redirect_uri: str, state: str) -> str:
    """Microsoft admin-consent URL — the admin clicks Accept once and is
    redirected back with ``admin_consent=True&tenant=<id>&state=<state>``."""
    query = urlencode(
        {"client_id": client_id, "redirect_uri": redirect_uri, "state": state}
    )
    return f"{_authority()}/{tenant}/adminconsent?{query}"


def _ui_origin() -> str:
    """The opener origin the callback's popup postMessage targets. Set
    TEX_CONDUIT_UI_ORIGIN to the UI origin (e.g. https://tex.systems) in
    production; '*' is the permissive default (the message carries no secret)."""
    return os.environ.get("TEX_CONDUIT_UI_ORIGIN", "*").strip() or "*"


def _consent_close_page(result: dict) -> str:
    """A tiny page Microsoft's redirect lands on inside the popup: it posts the
    result back to the opener (the Tex UI) and closes itself."""
    payload = json.dumps({"type": "tex-conduit-connect", **result})
    target = json.dumps(_ui_origin())
    return (
        "<!doctype html><html><head><meta charset='utf-8'>"
        "<title>Tex — directory connect</title></head><body>"
        "<script>(function(){var r=" + payload + ";"
        "try{if(window.opener){window.opener.postMessage(r," + target + ");}}catch(e){}"
        "window.setTimeout(function(){try{window.close();}catch(e){}},50);})();</script>"
        "<p style=\"font:14px system-ui,sans-serif;color:#444\">You can close this window.</p>"
        "</body></html>"
    )


def _respond(request: Request, result: dict):
    """The callback is hit by Microsoft's BROWSER redirect in production, so it
    DEFAULTS to the popup-close page (postMessage to the opener + self-close).
    JSON is returned only when explicitly asked for (``?format=json``) or for a
    pure-JSON Accept. We cannot rely on the Accept header for the default,
    because the Vercel proxy strips it — so the default must be HTML."""
    fmt = request.query_params.get("format", "").strip().lower()
    if fmt == "json":
        return result
    if fmt != "html":
        accept = request.headers.get("accept", "").lower()
        if "application/json" in accept and "text/html" not in accept:
            return result
    return HTMLResponse(_consent_close_page(result))


def build_conduit_router() -> APIRouter:
    router = APIRouter(prefix="/v1/surface/conduit", tags=["conduit"])

    @router.post(
        "/connect/entra/start",
        summary="Begin a read-only Entra connect (one-click admin consent)",
    )
    def entra_start(
        request: Request,
        tenant_id: str = Query(
            default="organizations",
            description="The customer's Entra tenant id/domain (recommended). "
            "'organizations' lets the admin's tenant resolve at consent time.",
        ),
    ) -> dict:
        broker = _broker(request)
        challenge = broker.request(
            DiscoverySource.MICROSOFT_GRAPH, tenant_id, nonce=uuid.uuid4().hex
        )
        client_id = _entra_client_id()
        if not client_id:
            return {
                "configured": False,
                "connection_id": challenge.connection_id,
                "requested_scopes": list(challenge.requested_scopes),
                "steps": [s.label for s in challenge.steps],
                "detail": (
                    "Entra app not configured. Register Tex as a multi-tenant app "
                    "and set TEX_CONDUIT_ENTRA_CLIENT_ID to enable one-click connect."
                ),
            }
        return {
            "configured": True,
            "connection_id": challenge.connection_id,
            "consent_url": _admin_consent_url(
                tenant_id, client_id, _entra_redirect_uri(request), challenge.connection_id
            ),
            "one_click": challenge.is_one_click,
            "requested_scopes": list(challenge.requested_scopes),
        }

    @router.get(
        "/connect/entra/callback",
        name="conduit_entra_callback",
        summary="Entra admin-consent redirect target (seals the grant)",
    )
    def entra_callback(
        request: Request,
        state: str = Query(...),
        admin_consent: str | None = Query(default=None),
        tenant: str | None = Query(default=None),
        error: str | None = Query(default=None),
        error_description: str | None = Query(default=None),
    ) -> dict:
        broker = _broker(request)
        connection_id = state
        try:
            conn = broker.connection(connection_id)
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="unknown or expired connection state",
            )

        # Fail-closed: a denied or errored consent never seals a grant.
        if error or (str(admin_consent).lower() != "true"):
            return _respond(request, {
                "connected": False,
                "error": error or "admin_consent_not_granted",
                "error_description": error_description,
                "connection_id": connection_id,
            })

        # The consenting tenant Microsoft returns is authoritative. If the start
        # named a concrete tenant, it must match (no tenant swap mid-flow).
        consenting_tenant = (tenant or conn.tenant_id).strip().casefold()
        if conn.tenant_id not in ("organizations", "common", consenting_tenant):
            return _respond(request, {
                "connected": False,
                "error": "tenant_mismatch",
                "error_description": (
                    f"consent returned tenant {consenting_tenant!r} but the connect "
                    f"was started for {conn.tenant_id!r}"
                ),
                "connection_id": connection_id,
            })

        # Admin consent grants the app's configured read-only permissions
        # (the Graph read triad). The secret stays in the deployment store; the
        # grant carries only an opaque pointer.
        callback = ConsentCallback(
            connection_id=connection_id,
            consent_artifact_id=consenting_tenant,  # admin-consent grant is tenant-wide
            granted_scopes=ENTRA_READ_SCOPES,
            credential_ref=f"entra-multitenant-app:{consenting_tenant}",
            consented_by=None,
        )
        broker.consent(callback)
        broker.probe(connection_id)  # builds the live transport if a factory is wired
        receipt = broker.seal(connection_id)
        grant = conn.grant
        assert grant is not None

        return _respond(request, {
            "connected": True,
            "provider": DiscoverySource.MICROSOFT_GRAPH.value,
            "tenant": consenting_tenant,
            "sealed": True,
            "receipt_kind": receipt.kind.value,
            "grant_id": str(grant.grant_id),
            "degraded": grant.degraded,
            # The UI ignites discovery on this tenant next.
            "next": {"ignite_tenant": consenting_tenant},
        })

    return router

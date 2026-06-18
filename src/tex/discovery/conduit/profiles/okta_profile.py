"""
Okta ProviderProfile — the cross-IdP neutrality proof.

Same shared ``ProviderConsentGraphConnector``, same ``blast_radius()`` engine,
different declarative profile. Okta's agent-bearing principals are its **apps**;
the agent class Tex governs is the **machine-to-machine OAuth client** (a
service app / ``client_credentials`` grant) — not human SSO apps. Each app's
``/grants`` are its consented API scopes against the Okta org authorization
server (org-wide), which become the consent edges.

Critical banding uses Okta's OWN curated critical-scope set
(``risk_dictionary.OKTA_CRITICAL_SCOPES``) layered onto the same engine, so an
over-privileged Okta client lands in the SAME CRITICAL band the equivalent
over-privileged Entra app does. That equality is the neutrality proof.

Nothing here plants a tag: ``okta_is_agent`` interprets the app's real
``signOnMode`` / ``oauthClient.application_type`` / ``grant_types`` fields, and
the edge mapper reads the real ``scopeId`` off each grant row.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from tex.discovery.conduit.connector import GrantCollection, ProviderProfile
from tex.discovery.conduit.risk_dictionary import HIGH_RISK_SCOPE_STEMS, OKTA_CRITICAL_SCOPES
from tex.discovery.consent_graph import ConsentEdge
from tex.domain.agent import AgentEnvironment
from tex.domain.discovery import DiscoverySource


def okta_principal_id(app: dict[str, Any]) -> str:
    return str(app.get("id") or "").strip()


def okta_display_name(app: dict[str, Any]) -> str | None:
    name = app.get("label") or app.get("name")
    return str(name) if name else None


def okta_last_seen(app: dict[str, Any]) -> datetime | None:
    return _parse_iso(app.get("lastUpdated") or app.get("created"))


def okta_evidence_extra(app: dict[str, Any]) -> dict[str, Any]:
    oauth = (app.get("settings") or {}).get("oauthClient") or {}
    return {
        "sign_on_mode": app.get("signOnMode"),
        "application_type": oauth.get("application_type"),
        "grant_types": list(oauth.get("grant_types") or ()),
        "status": app.get("status"),
        "discovered_via": "okta_consent_graph",
    }


def okta_is_agent(app: dict[str, Any]) -> bool:
    """A non-human identity in Okta: a machine-to-machine OAuth client.

    Service apps (``application_type == "service"``) and any client using the
    ``client_credentials`` grant authenticate as themselves — exactly the agent
    class Tex governs. Human SSO apps (web / native / browser, SAML) are not
    emitted as their own candidates.
    """
    oauth = (app.get("settings") or {}).get("oauthClient") or {}
    app_type = str(oauth.get("application_type", "")).casefold()
    grant_types = {str(g).casefold() for g in (oauth.get("grant_types") or ())}
    if app_type == "service":
        return True
    if "client_credentials" in grant_types:
        return True
    return False


def _okta_grant_edge(client_id: str, grant: dict[str, Any]) -> ConsentEdge | None:
    """One app grant -> a consent edge to the Okta org authorization server.

    Okta org API scopes are org-wide, so the edge is ``tenant_wide=True`` — the
    same semantics as an Entra AllPrincipals / application permission.
    """
    scope = str(grant.get("scopeId") or grant.get("scope") or "").strip()
    if not scope:
        return None
    issuer = str(grant.get("issuer") or "okta-org").strip()
    return ConsentEdge(
        client_id=client_id,
        resource_id=issuer,
        resource_name=issuer,
        scopes=(scope,),
        tenant_wide=True,
    )


def _parse_iso(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        return datetime.fromisoformat(value).astimezone(UTC)
    except ValueError:
        return None


OKTA_PROFILE = ProviderProfile(
    source=DiscoverySource.OKTA,
    connector_name="okta_consent_graph",
    principal_collection="apps",
    grant_collections=(
        GrantCollection(
            path_template="apps/{principal_id}/grants",
            mapper=_okta_grant_edge,
        ),
    ),
    delta_path="logs",  # System Log polling; wired into the standing watch in Phase 2
    is_agent=okta_is_agent,
    critical_scopes=OKTA_CRITICAL_SCOPES,
    high_risk_stems=HIGH_RISK_SCOPE_STEMS,
    confidence=0.9,
    model_provider_hint="okta",
    framework_hint="okta_oauth_client",
    environment_hint=AgentEnvironment.PRODUCTION,
    base_tags=("okta", "idp_rooted"),
    principal_id_of=okta_principal_id,
    display_name_of=okta_display_name,
    last_seen_of=okta_last_seen,
    evidence_extra=okta_evidence_extra,
)

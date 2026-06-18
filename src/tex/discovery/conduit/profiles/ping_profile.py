"""
Ping ProviderProfile — PingFederate / PingOne OAuth clients.

The agents are the OAuth clients that authenticate as themselves
(``client_credentials``); human authorization-code apps are not emitted. Scopes
(``restrictedScopes`` / ``scopes``) are carried inline on the client, so this
profile uses ``inline_edges``. The transport's ``base_url`` is pluggable per
deployment (self-hosted PingFederate vs PingOne AIC).
"""

from __future__ import annotations

from typing import Any

from tex.discovery.conduit.connector import ProviderProfile
from tex.discovery.conduit.risk_dictionary import PING_CRITICAL_SCOPES, high_risk_stems_for
from tex.discovery.consent_graph import ConsentEdge
from tex.domain.agent import AgentEnvironment
from tex.domain.discovery import DiscoverySource


def ping_principal_id(client: dict[str, Any]) -> str:
    return str(client.get("clientId") or client.get("id") or "").strip()


def ping_display_name(client: dict[str, Any]) -> str | None:
    name = client.get("name") or client.get("clientId")
    return str(name) if name else None


def ping_is_agent(client: dict[str, Any]) -> bool:
    grant_types = {
        str(g).casefold()
        for g in (client.get("grantTypes") or client.get("grant_types") or ())
    }
    return "client_credentials" in grant_types


def ping_inline_edges(principal_id: str, client: dict[str, Any]) -> list[ConsentEdge]:
    edges: list[ConsentEdge] = []
    scopes = client.get("restrictedScopes") or client.get("scopes") or ()
    for scope in scopes:
        s = str(scope).strip()
        if not s:
            continue
        edges.append(
            ConsentEdge(
                client_id=principal_id,
                resource_id="ping-authorization-server",
                resource_name="Ping Authorization Server",
                scopes=(s,),
                tenant_wide=True,
            )
        )
    return edges


def ping_evidence_extra(client: dict[str, Any]) -> dict[str, Any]:
    return {
        "grant_types": list(client.get("grantTypes") or client.get("grant_types") or ()),
        "enabled": client.get("enabled", True),
        "discovered_via": "ping_oauth_client_management",
    }


PING_PROFILE = ProviderProfile(
    source=DiscoverySource.PING,
    connector_name="ping_oauth_clients",
    principal_collection="oauth/clients",
    grant_collections=(),
    delta_path="oauth/clients/delta",
    is_agent=ping_is_agent,
    critical_scopes=PING_CRITICAL_SCOPES,
    high_risk_stems=high_risk_stems_for(DiscoverySource.PING),
    confidence=0.9,
    model_provider_hint="ping",
    framework_hint="ping_oauth_client",
    environment_hint=AgentEnvironment.PRODUCTION,
    base_tags=("ping", "idp_rooted"),
    inline_edges=ping_inline_edges,
    principal_id_of=ping_principal_id,
    display_name_of=ping_display_name,
    evidence_extra=ping_evidence_extra,
)

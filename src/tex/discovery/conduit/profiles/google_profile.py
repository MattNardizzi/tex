"""
Google ProviderProfiles — Workspace (DWD) and GCP IAM, the two-grant pair.

Two distinct ``DiscoverySource`` members, two profiles, two grants sealed
separately:

  * ``GOOGLE_WORKSPACE_PROFILE`` — the OAuth clients granted domain-wide
    delegation; each carries its authorized scopes inline.
  * ``GCP_IAM_PROFILE`` — org-wide service accounts from Cloud Asset Inventory;
    each carries its IAM role bindings inline (the asset's iam policy).

Both use ``inline_edges`` because Google embeds grants on the principal rather
than in a sub-collection. Risk bands use Google's own critical sets + augmented
high-risk stems (GCP role names, Workspace admin scopes) on the shared engine.
"""

from __future__ import annotations

from typing import Any

from tex.discovery.conduit.connector import ProviderProfile
from tex.discovery.conduit.risk_dictionary import (
    GCP_IAM_CRITICAL_SCOPES,
    GOOGLE_WORKSPACE_CRITICAL_SCOPES,
    high_risk_stems_for,
)
from tex.discovery.consent_graph import ConsentEdge
from tex.domain.agent import AgentEnvironment
from tex.domain.discovery import DiscoverySource


# --------------------------------------------------------------------------- GCP IAM
def gcp_principal_id(sa: dict[str, Any]) -> str:
    name = sa.get("email") or sa.get("uniqueId")
    if name:
        return str(name).strip()
    # Cloud Asset name: projects/p/serviceAccounts/sa@... -> tail.
    return str(sa.get("name") or "").rsplit("/", 1)[-1].strip()


def gcp_display_name(sa: dict[str, Any]) -> str | None:
    name = sa.get("displayName") or sa.get("email")
    return str(name) if name else None


def gcp_is_agent(sa: dict[str, Any]) -> bool:
    # Every service account is a non-human identity — the agent class Tex
    # governs. (A deployment may later exclude Google-managed system SAs.)
    return True


def gcp_inline_edges(principal_id: str, sa: dict[str, Any]) -> list[ConsentEdge]:
    edges: list[ConsentEdge] = []
    for binding in sa.get("bindings") or ():
        role = str(binding.get("role") or "").strip()
        if not role:
            continue
        resource = str(binding.get("resource") or binding.get("project") or "gcp-org").strip()
        tenant_wide = resource.startswith("organizations/") or "/organizations/" in resource
        edges.append(
            ConsentEdge(
                client_id=principal_id,
                resource_id=resource,
                resource_name=resource,
                scopes=(role,),
                tenant_wide=tenant_wide,
            )
        )
    return edges


def gcp_evidence_extra(sa: dict[str, Any]) -> dict[str, Any]:
    return {
        "service_account_email": sa.get("email"),
        "disabled": sa.get("disabled", False),
        "discovered_via": "gcp_cloud_asset_inventory",
    }


GCP_IAM_PROFILE = ProviderProfile(
    source=DiscoverySource.GCP_IAM,
    connector_name="gcp_iam_asset",
    principal_collection="serviceAccounts",
    grant_collections=(),
    delta_path="serviceAccounts/delta",
    is_agent=gcp_is_agent,
    critical_scopes=GCP_IAM_CRITICAL_SCOPES,
    high_risk_stems=high_risk_stems_for(DiscoverySource.GCP_IAM),
    confidence=0.9,
    model_provider_hint="google",
    framework_hint="gcp_service_account",
    environment_hint=AgentEnvironment.PRODUCTION,
    base_tags=("gcp", "google", "idp_rooted"),
    inline_edges=gcp_inline_edges,
    principal_id_of=gcp_principal_id,
    display_name_of=gcp_display_name,
    evidence_extra=gcp_evidence_extra,
)


# --------------------------------------------------------------------------- Workspace
def gw_principal_id(client: dict[str, Any]) -> str:
    return str(client.get("clientId") or client.get("id") or "").strip()


def gw_display_name(client: dict[str, Any]) -> str | None:
    name = client.get("displayName") or client.get("clientId")
    return str(name) if name else None


def gw_is_agent(client: dict[str, Any]) -> bool:
    # A domain-wide-delegation OAuth client is a non-human identity.
    return True


def gw_inline_edges(principal_id: str, client: dict[str, Any]) -> list[ConsentEdge]:
    edges: list[ConsentEdge] = []
    for scope in client.get("scopes") or ():
        s = str(scope).strip()
        if not s:
            continue
        edges.append(
            ConsentEdge(
                client_id=principal_id,
                resource_id="google-workspace-api",
                resource_name="Google Workspace API",
                scopes=(s,),
                tenant_wide=True,  # DWD scopes apply across the whole domain
            )
        )
    return edges


def gw_evidence_extra(client: dict[str, Any]) -> dict[str, Any]:
    return {
        "display_name": client.get("displayName"),
        "discovered_via": "google_workspace_dwd",
    }


GOOGLE_WORKSPACE_PROFILE = ProviderProfile(
    source=DiscoverySource.GOOGLE_WORKSPACE,
    connector_name="google_workspace_dwd",
    principal_collection="domainWideDelegations",
    grant_collections=(),
    delta_path="activities/delta",
    is_agent=gw_is_agent,
    critical_scopes=GOOGLE_WORKSPACE_CRITICAL_SCOPES,
    high_risk_stems=high_risk_stems_for(DiscoverySource.GOOGLE_WORKSPACE),
    confidence=0.9,
    model_provider_hint="google",
    framework_hint="google_workspace_dwd_client",
    environment_hint=AgentEnvironment.PRODUCTION,
    base_tags=("google", "workspace", "idp_rooted"),
    inline_edges=gw_inline_edges,
    principal_id_of=gw_principal_id,
    display_name_of=gw_display_name,
    evidence_extra=gw_evidence_extra,
)

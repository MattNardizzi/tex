"""
Entra (Microsoft Graph) ProviderProfile — the reference profile.

This profile encodes, declaratively, exactly what the legacy
``EntraConsentGraphConnector`` did imperatively: walk ``servicePrincipals``,
read ``oauth2PermissionGrants`` (delegated) and ``appRoleAssignments``
(app-only) as the consent edges, flag application / managed-identity
principals (and anything carrying an Agent ID tag) as agents, and band risk
against Entra's literal critical-permission set.

Because Entra's critical set and high-risk stems are exactly
``consent_graph``'s module-level frozensets, the shared connector driven by
this profile produces byte-identical ``CandidateAgent`` output to the old
hand-written connector. That equivalence is the Phase 0 gate.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from typing import Any

from tex.discovery.conduit.connector import GrantCollection, ProviderProfile
from tex.discovery.consent_graph import (
    CRITICAL_SCOPE_STEMS,
    HIGH_RISK_SCOPE_STEMS,
    ConsentEdge,
)
from tex.domain.agent import AgentEnvironment
from tex.domain.discovery import DiscoverySource

# Service-principal types that represent an actor that can hold credentials and
# act — i.e. an agent or NHI — as opposed to a pure resource entry.
_AGENT_SP_TYPES = {"application", "managedidentity"}

# A tag Entra Agent ID / Agent 365 attaches to agent identities; treat any SP
# carrying it as an agent regardless of type.
_AGENT_TAGS = {"agentidentity", "aiagent", "copilotagent"}


def entra_principal_id(sp: dict[str, Any]) -> str:
    return str(sp.get("id") or sp.get("appId") or "").strip()


def entra_display_name(sp: dict[str, Any]) -> str | None:
    name = sp.get("displayName")
    return str(name) if name else None


def entra_owner_hint(sp: dict[str, Any]) -> str | None:
    owners = sp.get("owners") or []
    if owners:
        first = owners[0]
        return first.get("userPrincipalName") if isinstance(first, dict) else str(first)
    return None


def entra_description(sp: dict[str, Any]) -> str | None:
    return sp.get("description") or sp.get("notes")


def entra_last_seen(sp: dict[str, Any]) -> datetime | None:
    return _parse_iso(sp.get("lastSignInDateTime"))


def entra_evidence_extra(sp: dict[str, Any]) -> dict[str, Any]:
    return {
        "service_principal_type": sp.get("servicePrincipalType"),
        "discovered_via": "idp_consent_graph",
    }


def entra_is_agent(sp: dict[str, Any]) -> bool:
    """The legacy ``_looks_like_agent`` predicate, verbatim."""
    sp_type = str(sp.get("servicePrincipalType", "")).casefold()
    tags = {str(t).casefold() for t in sp.get("tags", [])}
    if tags & _AGENT_TAGS:
        return True
    # An application/managed-identity SP that holds *any* delegated or app
    # permission is an actor that can touch a resource — an agent in the
    # doctrine's mechanism sense. Pure resource SPs (the API side of a grant)
    # are not emitted as their own candidates.
    if sp_type not in _AGENT_SP_TYPES:
        return False
    # Home-tenant scoping (TEX_DISCOVERY_HOME_TENANT_ONLY=1): surface only
    # identities the scanned organization OWNS — its own agents — and treat
    # Microsoft's first-party built-in service principals (owned by Microsoft's
    # tenant) as platform noise. Keys off the intrinsic
    # appOwnerOrganizationId, never a planted tag.
    if os.environ.get("TEX_DISCOVERY_HOME_TENANT_ONLY", "").strip() == "1":
        home = os.environ.get("TEX_DISCOVERY_ENTRA_TENANT_ID", "").strip()
        owner = str(sp.get("appOwnerOrganizationId") or "").strip()
        if home and owner != home:
            return False
    return True


def _entra_delegated_edge(client_id: str, grant: dict[str, Any]) -> ConsentEdge | None:
    """Delegated permission grant: client -> resource, with space-split scopes."""
    resource_id = str(grant.get("resourceId") or "").strip()
    if not resource_id:
        return None
    scopes = tuple(s for s in str(grant.get("scope") or "").split() if s)
    return ConsentEdge(
        client_id=client_id,
        resource_id=resource_id,
        resource_name=str(grant.get("resourceDisplayName") or resource_id),
        scopes=scopes,
        tenant_wide=str(grant.get("consentType", "")).casefold() == "allprincipals",
    )


def _entra_app_role_edge(client_id: str, assignment: dict[str, Any]) -> ConsentEdge | None:
    """Application (app-only) permission via appRoleAssignment; always app-wide."""
    resource_id = str(assignment.get("resourceId") or "").strip()
    if not resource_id:
        return None
    return ConsentEdge(
        client_id=client_id,
        resource_id=resource_id,
        resource_name=str(assignment.get("resourceDisplayName") or resource_id),
        scopes=(str(assignment.get("appRoleId") or "app_role"),),
        tenant_wide=True,  # application permissions are app-wide
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


ENTRA_PROFILE = ProviderProfile(
    source=DiscoverySource.MICROSOFT_GRAPH,
    connector_name="entra_consent_graph",
    principal_collection="servicePrincipals",
    grant_collections=(
        GrantCollection(
            path_template="servicePrincipals/{principal_id}/oauth2PermissionGrants",
            mapper=_entra_delegated_edge,
        ),
        GrantCollection(
            path_template="servicePrincipals/{principal_id}/appRoleAssignments",
            mapper=_entra_app_role_edge,
        ),
    ),
    delta_path="servicePrincipals/delta",
    is_agent=entra_is_agent,
    critical_scopes=CRITICAL_SCOPE_STEMS,
    high_risk_stems=HIGH_RISK_SCOPE_STEMS,
    confidence=0.9,
    model_provider_hint="microsoft",
    framework_hint="entra_service_principal",
    environment_hint=AgentEnvironment.PRODUCTION,
    base_tags=("microsoft", "entra", "idp_rooted"),
    principal_id_of=entra_principal_id,
    display_name_of=entra_display_name,
    owner_hint_of=entra_owner_hint,
    description_of=entra_description,
    last_seen_of=entra_last_seen,
    evidence_extra=entra_evidence_extra,
)

"""
Entra consent-graph connector — the IdP root, made real.

This is the seamless-discovery core. One read-only admin grant to Entra (or
Okta — same shape), and this connector walks the directory itself: every
service principal, OAuth application, and non-human identity, plus the
``oauth2PermissionGrants`` and ``appRoleAssignments`` that say which
downstream APIs and SaaS each one may touch. Those grants are the edges of a
consent graph, and the transitive closure of that graph is each agent's
blast radius. The client connects *one* thing; Tex discovers the estate's
topology from it. That is the doctrine's rooted, single-grant connection
model (§6) instead of "connect Salesforce, connect Slack, connect M365."

It emits the canonical ``CandidateAgent`` shape, so everything downstream —
reconciliation, the hash-chained ledger, the behavioural-birth anchoring —
keeps working unchanged. The signal grade is ``CONTROL_PLANE``: authoritative
for what the directory knows, mediated by it, honestly below the tamper-
resistant planes. A renamed or rotated agent can still slip the directory,
which is exactly why behavioural provenance exists to catch what it misses.

I/O lives behind a ``GraphTransport`` (see ``graph_transport``): inject
``LiveGraphTransport`` for a real tenant, ``FixtureGraphTransport`` for
tests. The connector logic — graph-building, blast radius, candidate
emission — is identical either way and fully unit-tested without a tenant.
The ``delta_link`` plumbing exposes Graph's native delta query as the
standing watch, so the continuous re-read is incremental, not a full rescan.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from typing import Any, Iterable

from tex.discovery.connectors.base import BaseConnector, ConnectorContext
from tex.discovery.consent_graph import ConsentEdge, ConsentGraph
from tex.discovery.graph_transport import GraphTransport
from tex.domain.agent import AgentEnvironment
from tex.domain.discovery import (
    CandidateAgent,
    DiscoveredCapabilityHints,
    DiscoveryRiskBand,
    DiscoverySource,
)

# Service-principal types that represent an actor that can hold credentials
# and act — i.e. an agent or NHI — as opposed to a pure resource entry.
_AGENT_SP_TYPES = {"application", "managedidentity"}

# A tag Entra Agent ID / Agent 365 attaches to agent identities; treat any
# SP carrying it as an agent regardless of type.
_AGENT_TAGS = {"agentidentity", "aiagent", "copilotagent"}


class EntraConsentGraphConnector(BaseConnector):
    """
    Live-capable IdP-root enumerator over Microsoft Graph (or Okta).

    Construct with a ``GraphTransport``. ``scan`` walks service principals
    and their grants, builds a consent graph, and emits one
    ``CandidateAgent`` per agent-bearing principal, enriched with its sealed
    blast radius.
    """

    def __init__(self, *, transport: GraphTransport) -> None:
        super().__init__(
            source=DiscoverySource.MICROSOFT_GRAPH,
            name="entra_consent_graph",
        )
        self._transport = transport
        # Persisted between sweeps to drive the delta (standing watch).
        self.delta_link: str | None = None

    # ------------------------------------------------------------------ scan
    def _run_scan(self, context: ConnectorContext) -> Iterable[CandidateAgent]:
        graph, principals = self._build_graph(context)
        for sp_id in graph.agents():
            record = principals.get(sp_id)
            if record is None:
                continue
            yield self._candidate_from_principal(record, graph, context)

    # ------------------------------------------------------------------ build
    def _build_graph(
        self, context: ConnectorContext
    ) -> tuple[ConsentGraph, dict[str, dict[str, Any]]]:
        graph = ConsentGraph()
        principals: dict[str, dict[str, Any]] = {}

        for sp in self._transport.get_paginated("servicePrincipals"):
            sp_id = str(sp.get("id") or sp.get("appId") or "").strip()
            if not sp_id:
                continue
            principals[sp_id] = sp
            is_agent = self._looks_like_agent(sp)
            graph.add_principal(
                sp_id,
                display_name=str(sp.get("displayName") or sp_id),
                is_agent=is_agent,
            )

            # Delegated permission grants: client -> resource, with scopes.
            for grant in self._transport.get_paginated(
                f"servicePrincipals/{sp_id}/oauth2PermissionGrants"
            ):
                resource_id = str(grant.get("resourceId") or "").strip()
                if not resource_id:
                    continue
                scopes = tuple(
                    s for s in str(grant.get("scope") or "").split() if s
                )
                graph.add_edge(
                    ConsentEdge(
                        client_id=sp_id,
                        resource_id=resource_id,
                        resource_name=str(grant.get("resourceDisplayName") or resource_id),
                        scopes=scopes,
                        tenant_wide=str(grant.get("consentType", "")).casefold()
                        == "allprincipals",
                    )
                )

            # Application (app-only) permissions: appRoleAssignments.
            for assignment in self._transport.get_paginated(
                f"servicePrincipals/{sp_id}/appRoleAssignments"
            ):
                resource_id = str(assignment.get("resourceId") or "").strip()
                if not resource_id:
                    continue
                graph.add_edge(
                    ConsentEdge(
                        client_id=sp_id,
                        resource_id=resource_id,
                        resource_name=str(assignment.get("resourceDisplayName") or resource_id),
                        scopes=(str(assignment.get("appRoleId") or "app_role"),),
                        tenant_wide=True,  # application permissions are app-wide
                    )
                )

        return graph, principals

    @staticmethod
    def _looks_like_agent(sp: dict[str, Any]) -> bool:
        sp_type = str(sp.get("servicePrincipalType", "")).casefold()
        tags = {str(t).casefold() for t in sp.get("tags", [])}
        if tags & _AGENT_TAGS:
            return True
        # An application/managed-identity SP that holds *any* delegated or
        # app permission is an actor that can touch a resource — an agent in
        # the doctrine's mechanism sense. Pure resource SPs (the API side of
        # a grant) are not emitted as their own candidates.
        if sp_type not in _AGENT_SP_TYPES:
            return False
        # Home-tenant scoping (TEX_DISCOVERY_HOME_TENANT_ONLY=1): surface only
        # identities the scanned organization OWNS — its own agents — and treat
        # Microsoft's first-party built-in service principals (owned by
        # Microsoft's tenant) as platform noise. Keys off the intrinsic
        # appOwnerOrganizationId, never a planted tag.
        if os.environ.get("TEX_DISCOVERY_HOME_TENANT_ONLY", "").strip() == "1":
            home = os.environ.get("TEX_DISCOVERY_ENTRA_TENANT_ID", "").strip()
            owner = str(sp.get("appOwnerOrganizationId") or "").strip()
            if home and owner != home:
                return False
        return True

    # ------------------------------------------------------------------ emit
    def _candidate_from_principal(
        self,
        sp: dict[str, Any],
        graph: ConsentGraph,
        context: ConnectorContext,
    ) -> CandidateAgent:
        sp_id = str(sp.get("id") or sp.get("appId"))
        blast = graph.blast_radius(sp_id)
        scopes = blast["scopes"]

        if blast["critical_scopes"]:
            risk = DiscoveryRiskBand.CRITICAL
        elif blast["tenant_wide_grant"] and blast["high_risk_scopes"]:
            risk = DiscoveryRiskBand.HIGH
        elif blast["high_risk_scopes"]:
            risk = DiscoveryRiskBand.MEDIUM
        else:
            risk = DiscoveryRiskBand.LOW

        hints = DiscoveredCapabilityHints(
            inferred_tools=tuple(scopes),
            inferred_data_scopes=tuple(blast["direct_resources"]),
            surface_unbounded=bool(blast["surface_unbounded"]),
        )

        owner = None
        owners = sp.get("owners") or []
        if owners:
            first = owners[0]
            owner = first.get("userPrincipalName") if isinstance(first, dict) else str(first)

        return CandidateAgent(
            source=DiscoverySource.MICROSOFT_GRAPH,
            tenant_id=context.tenant_id,
            external_id=sp_id,
            name=str(sp.get("displayName") or sp_id),
            owner_hint=owner,
            description=sp.get("description") or sp.get("notes"),
            model_provider_hint="microsoft",
            framework_hint="entra_service_principal",
            environment_hint=AgentEnvironment.PRODUCTION,
            risk_band=risk,
            confidence=0.9,
            capability_hints=hints,
            last_seen_active_at=_parse_iso(sp.get("lastSignInDateTime")),
            evidence={
                "service_principal_type": sp.get("servicePrincipalType"),
                "scopes": scopes,
                "blast_radius": blast,
                "discovered_via": "idp_consent_graph",
            },
            tags=("microsoft", "entra", "idp_rooted"),
        )

    # ------------------------------------------------------------------ watch
    def sweep_delta(self) -> list[dict[str, Any]]:
        """
        Incremental standing watch: pull only the service principals that
        changed since the last sweep, advancing the persisted delta link.
        The native, low-cost continuous re-read — not a full rescan.
        """
        changed, next_link = self._transport.get_delta(
            "servicePrincipals/delta", self.delta_link
        )
        self.delta_link = next_link
        return changed


def _parse_iso(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        return datetime.fromisoformat(value).astimezone(UTC)
    except ValueError:
        return None

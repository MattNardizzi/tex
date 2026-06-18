"""
The one shared consent-graph connector, parameterized by a ProviderProfile.

The Entra connector proved the shape: walk the directory's principals, read
the grant edges that say which resources each one may touch, build a consent
graph, and emit one ``CandidateAgent`` per agent-bearing principal enriched
with its sealed blast radius. *Every* IdP (Entra, Okta, Google, Ping) is the
same shape behind the ``GraphTransport`` Protocol — only the collection paths,
the grant-row shapes, the "is this an agent?" predicate, and the critical-scope
dictionary differ. Those differences are declared in a ``ProviderProfile``;
the walking logic is written once, here.

Why this matters for correctness:

  * ``HIGH_RISK_SCOPE_STEMS`` (readwrite / write / send / delete / manage …)
    are substrings and **port across providers** unchanged.
  * Critical scopes are literal, provider-specific permission strings (Entra's
    ``directory.readwrite.all``; Okta super-admin grants; GCP ``owner`` /
    ``iam.securityAdmin``; Ping admin scopes). They are matched by **exact
    membership**, so each ProviderProfile ships its **own** critical set —
    mapped onto the **same** ``blast_radius()`` engine. Conflating them would
    silently mis-band agents across directories.

``ProviderConsentGraphConnector`` reproduces the legacy Entra connector's
behavior byte-for-byte when handed ``ENTRA_PROFILE`` — that equivalence is the
Phase 0 gate (the existing ``FixtureGraphTransport`` tests pass unchanged).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
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

# A ConsentEdgeMapper turns one native grant row (an Entra
# ``oauth2PermissionGrant``, an Okta app grant, a GCP IAM binding) into a
# ``ConsentEdge`` — or ``None`` if the row carries no usable edge. It receives
# the client principal id the row hangs off and the raw row dict.
ConsentEdgeMapper = Callable[[str, dict[str, Any]], "ConsentEdge | None"]


# ----------------------------------------------------------------------- defaults
def _default_principal_id(row: dict[str, Any]) -> str:
    return str(row.get("id") or "").strip()


def _default_display_name(row: dict[str, Any]) -> str | None:
    name = row.get("displayName") or row.get("name")
    return str(name) if name else None


def _none(row: dict[str, Any]) -> None:
    return None


def _empty_evidence(row: dict[str, Any]) -> dict[str, Any]:
    return {}


@dataclass(frozen=True, slots=True)
class GrantCollection:
    """
    One collection of grant rows hanging off a principal, plus the mapper that
    turns a row into a ``ConsentEdge``.

    ``path_template`` is formatted with ``principal_id=<id>`` — e.g.
    ``"servicePrincipals/{principal_id}/oauth2PermissionGrants"``. A provider
    with tenant-global grant collections (not per-principal) can omit the
    placeholder; the template is used verbatim.
    """

    path_template: str
    mapper: ConsentEdgeMapper


@dataclass(frozen=True, slots=True)
class ProviderProfile:
    """
    Declarative description of one identity provider's consent-graph shape.

    Everything the shared connector needs to know that differs per provider
    lives here. The walking, graph-building, blast-radius, risk-banding, and
    candidate-emission logic is identical across providers and lives in
    ``ProviderConsentGraphConnector``.
    """

    source: DiscoverySource
    connector_name: str

    # Where the agent-bearing principals live, and the per-principal grant
    # collections whose rows become consent edges.
    principal_collection: str
    grant_collections: tuple[GrantCollection, ...]
    delta_path: str

    # "Is this principal an actor that can hold credentials and act?" — the
    # provider-specific agent predicate (Entra's servicePrincipalType + tags,
    # Okta's app/client kinds, …).
    is_agent: Callable[[dict[str, Any]], bool]

    # The provider's curated CRITICAL scope set (exact-membership) layered onto
    # the shared, portable HIGH-risk substring stems.
    critical_scopes: frozenset[str]
    high_risk_stems: frozenset[str]

    # Candidate-shaping knobs.
    confidence: float = 0.9
    model_provider_hint: str | None = None
    framework_hint: str | None = None
    environment_hint: AgentEnvironment = AgentEnvironment.PRODUCTION
    base_tags: tuple[str, ...] = ()

    # Some providers carry their grants INLINE on the principal row (GCP Cloud
    # Asset Inventory embeds the IAM policy; Google Workspace DWD embeds the
    # authorized scopes) rather than in a per-principal sub-collection. When set,
    # this yields edges straight off the principal row. None for Entra/Okta.
    inline_edges: Callable[[str, dict[str, Any]], list["ConsentEdge"]] | None = field(default=None)

    # Per-provider field extractors (sensible directory defaults provided).
    principal_id_of: Callable[[dict[str, Any]], str] = field(default=_default_principal_id)
    display_name_of: Callable[[dict[str, Any]], str | None] = field(default=_default_display_name)
    owner_hint_of: Callable[[dict[str, Any]], str | None] = field(default=_none)
    description_of: Callable[[dict[str, Any]], str | None] = field(default=_none)
    last_seen_of: Callable[[dict[str, Any]], "datetime | None"] = field(default=_none)
    evidence_extra: Callable[[dict[str, Any]], dict[str, Any]] = field(default=_empty_evidence)


class ProviderConsentGraphConnector(BaseConnector):
    """
    Live-capable IdP-root enumerator over any ``GraphTransport``, driven by a
    ``ProviderProfile``.

    Construct with ``(transport, profile)``. ``scan`` walks the profile's
    principals and grant collections, builds a consent graph, and emits one
    ``CandidateAgent`` per agent-bearing principal, enriched with its sealed
    blast radius. Output is the canonical ``CandidateAgent`` shape, so the
    whole downstream pipeline keeps working unchanged.
    """

    def __init__(self, *, transport: GraphTransport, profile: ProviderProfile) -> None:
        super().__init__(source=profile.source, name=profile.connector_name)
        self._transport = transport
        self._profile = profile
        # Persisted between sweeps to drive the delta (standing watch).
        self.delta_link: str | None = None

    @property
    def profile(self) -> ProviderProfile:
        return self._profile

    # ------------------------------------------------------------------ scan
    def _run_scan(self, context: ConnectorContext) -> Iterable[CandidateAgent]:
        graph, principals = self._build_graph(context)
        for principal_id in graph.agents():
            record = principals.get(principal_id)
            if record is None:
                continue
            yield self._candidate_from_principal(record, graph, context)

    # ------------------------------------------------------------------ build
    def _build_graph(
        self, context: ConnectorContext
    ) -> tuple[ConsentGraph, dict[str, dict[str, Any]]]:
        profile = self._profile
        graph = ConsentGraph()
        principals: dict[str, dict[str, Any]] = {}

        for row in self._transport.get_paginated(profile.principal_collection):
            principal_id = profile.principal_id_of(row)
            if not principal_id:
                continue
            principals[principal_id] = row
            graph.add_principal(
                principal_id,
                display_name=(profile.display_name_of(row) or principal_id),
                is_agent=profile.is_agent(row),
            )
            for collection in profile.grant_collections:
                path = collection.path_template.format(principal_id=principal_id)
                for grant_row in self._transport.get_paginated(path):
                    edge = collection.mapper(principal_id, grant_row)
                    if edge is not None:
                        graph.add_edge(edge)

            # Inline grants embedded on the principal row (GCP IAM policy /
            # Workspace DWD scopes).
            if profile.inline_edges is not None:
                for edge in profile.inline_edges(principal_id, row):
                    if edge is not None:
                        graph.add_edge(edge)

        return graph, principals

    # ------------------------------------------------------------------ emit
    def _candidate_from_principal(
        self,
        row: dict[str, Any],
        graph: ConsentGraph,
        context: ConnectorContext,
    ) -> CandidateAgent:
        profile = self._profile
        principal_id = profile.principal_id_of(row)
        blast = graph.blast_radius(principal_id)
        scopes = blast["scopes"]

        # Risk band: the SAME formula the legacy Entra connector used, but the
        # critical set and high-risk stems come from the profile so each
        # provider bands on its own dictionary against the shared engine. For
        # ENTRA_PROFILE these sets equal consent_graph's frozensets, so this
        # reproduces blast["critical_scopes"]/["high_risk_scopes"] exactly.
        critical = [s for s in scopes if s in profile.critical_scopes]
        high = [s for s in scopes if any(stem in s for stem in profile.high_risk_stems)]
        tenant_wide = bool(blast["tenant_wide_grant"])

        if critical:
            risk = DiscoveryRiskBand.CRITICAL
        elif tenant_wide and high:
            risk = DiscoveryRiskBand.HIGH
        elif high:
            risk = DiscoveryRiskBand.MEDIUM
        else:
            risk = DiscoveryRiskBand.LOW

        surface_unbounded = bool(critical) or (tenant_wide and bool(high))

        hints = DiscoveredCapabilityHints(
            inferred_tools=tuple(scopes),
            inferred_data_scopes=tuple(blast["direct_resources"]),
            surface_unbounded=surface_unbounded,
        )

        # blast_radius() computes critical/high/surface against consent_graph's
        # (Entra) frozensets. Overwrite those three fields with the profile's own
        # dictionary so the SEALED evidence reflects THIS provider's assessment,
        # not Entra's. For ENTRA_PROFILE the sets are identical, so this is a
        # no-op there (behavior preserved); for Okta/GCP/Ping it is the truth.
        blast_evidence = dict(blast)
        blast_evidence["critical_scopes"] = critical
        blast_evidence["high_risk_scopes"] = high
        blast_evidence["surface_unbounded"] = surface_unbounded

        name = profile.display_name_of(row) or principal_id

        return CandidateAgent(
            source=profile.source,
            tenant_id=context.tenant_id,
            external_id=principal_id,
            name=name,
            owner_hint=profile.owner_hint_of(row),
            description=profile.description_of(row),
            model_provider_hint=profile.model_provider_hint,
            framework_hint=profile.framework_hint,
            environment_hint=profile.environment_hint,
            risk_band=risk,
            confidence=profile.confidence,
            capability_hints=hints,
            last_seen_active_at=profile.last_seen_of(row),
            evidence={
                "scopes": scopes,
                "blast_radius": blast_evidence,
                **profile.evidence_extra(row),
            },
            tags=profile.base_tags,
        )

    # ------------------------------------------------------------------ watch
    def sweep_delta(self) -> list[dict[str, Any]]:
        """
        Incremental standing watch: pull only the principals that changed since
        the last sweep, advancing the persisted delta link. The native,
        low-cost continuous re-read — not a full rescan.
        """
        changed, next_link = self._transport.get_delta(
            self._profile.delta_path, self.delta_link
        )
        self.delta_link = next_link
        return changed

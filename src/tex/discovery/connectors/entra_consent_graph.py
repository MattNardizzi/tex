"""
Entra consent-graph connector — the IdP root, made real.

This is the seamless-discovery core. One read-only admin grant to Entra, and
this connector walks the directory itself: every service principal, OAuth
application, and non-human identity, plus the ``oauth2PermissionGrants`` and
``appRoleAssignments`` that say which downstream APIs and SaaS each one may
touch. Those grants are the edges of a consent graph, and the transitive
closure of that graph is each agent's blast radius.

As of tex-conduit, the walking/graph-building/blast-radius/emission logic is
no longer hand-written here — it lives once in
``tex.discovery.conduit.connector.ProviderConsentGraphConnector`` and is
driven by a declarative ``ProviderProfile``. This connector is now a thin
binding of that shared engine to ``ENTRA_PROFILE`` — the reference profile
that reproduces this connector's historical behavior byte-for-byte (proven by
the existing ``FixtureGraphTransport`` tests passing unchanged). Okta, Google,
and Ping are the same engine with a different profile.

I/O still lives behind a ``GraphTransport``: inject ``LiveGraphTransport`` for
a real tenant, ``FixtureGraphTransport`` for tests. The signal grade is
``CONTROL_PLANE``: authoritative for what the directory knows, mediated by it,
honestly below the tamper-resistant planes. A renamed or rotated agent can
still slip the directory, which is exactly why behavioural provenance exists to
catch what it misses.
"""

from __future__ import annotations

from tex.discovery.conduit.connector import ProviderConsentGraphConnector
from tex.discovery.conduit.profiles.entra_profile import (
    ENTRA_PROFILE,
    entra_is_agent,
)
from tex.discovery.graph_transport import GraphTransport

# Re-exported for backward compatibility with anything that referenced the
# connector's historical module-level agent predicate.
__all__ = ["EntraConsentGraphConnector"]


class EntraConsentGraphConnector(ProviderConsentGraphConnector):
    """
    Live-capable IdP-root enumerator over Microsoft Graph.

    Construct with a ``GraphTransport``. Behaviour is the shared
    ``ProviderConsentGraphConnector`` parameterized by ``ENTRA_PROFILE``;
    ``scan`` walks service principals and their grants, builds a consent
    graph, and emits one ``CandidateAgent`` per agent-bearing principal,
    enriched with its sealed blast radius.
    """

    def __init__(self, *, transport: GraphTransport) -> None:
        super().__init__(transport=transport, profile=ENTRA_PROFILE)

    # Back-compat: the historical static predicate, unchanged in behaviour.
    _looks_like_agent = staticmethod(entra_is_agent)

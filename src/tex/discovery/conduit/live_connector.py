"""
ConduitConnectionsConnector — map a CONNECTED tenant's real directory.

This is the bridge between a sealed connect (``GRANT_SEALED`` + a live
transport) and the existing discovery pipeline. It is one tenant-aware
connector registered on the ``DiscoveryService``: when a scan runs for tenant
T, it looks up T's most-recent sealed conduit connection, takes its live
transport, and delegates to the shared ``ProviderConsentGraphConnector`` with
that provider's profile — so ``ignite(T)`` maps T's actual estate.

Tenants with no sealed connection (the demo tenant, the test suite, any tenant
that never clicked Connect) yield nothing, so this is completely inert until a
real client connects. It never holds credentials itself — it only borrows the
transport the broker built at connect time.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Iterable

from tex.discovery.conduit.connector import ProviderConsentGraphConnector, ProviderProfile
from tex.discovery.connectors.base import BaseConnector, ConnectorContext
from tex.discovery.graph_transport import GraphTransport
from tex.domain.discovery import CandidateAgent, DiscoverySource

# lookup(tenant_id) -> (transport, provider) for a sealed connection, or
# (None, None) when the tenant has not connected.
ConnectionLookup = Callable[[str], "tuple[GraphTransport | None, DiscoverySource | None]"]


class ConduitConnectionsConnector(BaseConnector):
    def __init__(
        self,
        *,
        lookup: ConnectionLookup,
        profiles: dict[DiscoverySource, ProviderProfile],
        name: str = "conduit_connections",
    ) -> None:
        # source is for reporting only; emitted candidates carry the profile's
        # own source. A tenant connects one provider at a time today (Entra).
        super().__init__(source=DiscoverySource.MICROSOFT_GRAPH, name=name)
        self._lookup = lookup
        self._profiles = profiles

    def _run_scan(self, context: ConnectorContext) -> Iterable[CandidateAgent]:
        transport, provider = self._lookup(context.tenant_id)
        if transport is None or provider is None:
            return  # no sealed connection for this tenant -> inert
        profile = self._profiles.get(provider)
        if profile is None:
            return
        yield from ProviderConsentGraphConnector(transport=transport, profile=profile).scan(context)

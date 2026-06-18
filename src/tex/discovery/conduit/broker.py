"""
Connect broker — the four-state machine behind the one button.

``REQUESTED -> CONSENTED -> PROBED -> SEALED``. The broker holds a registry of
``ConnectStrategy`` objects (one per provider) and drives a connection through
consent, a read-only reachability probe, and the first seal. It **never holds
long-lived secrets**: a connection carries only an opaque ``connection_id`` and
the grant's ``credential_ref`` (a pointer into the deployment secret store).

The seal step is the load-bearing one: the moment a connection reaches SEALED,
``GRANT_SEALED`` is on the conduit provenance chain — the customer has a
cryptographic receipt of exactly what read access they granted, before any agent
is read. A degraded (partial) grant still seals; it just records the gap.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from tex.discovery.conduit.grant import DirectoryGrant, canonical_scopes
from tex.discovery.conduit.providers.base import (
    ConnectStrategy,
    ConsentCallback,
    ConsentChallenge,
    make_connection_id,
)
from tex.discovery.conduit.seal import (
    AnchorFn,
    ConduitProvenanceChain,
    ConduitReceipt,
    seal_grant,
)
from tex.discovery.graph_transport import GraphTransport
from tex.domain.discovery import DiscoverySource


class ConnectState(StrEnum):
    REQUESTED = "requested"
    CONSENTED = "consented"
    PROBED = "probed"
    SEALED = "sealed"


class ConnectBrokerError(RuntimeError):
    """A broker operation that cannot proceed."""


class InvalidStateTransition(ConnectBrokerError):
    """An operation was attempted from the wrong connection state."""


@dataclass
class Connection:
    connection_id: str
    provider: DiscoverySource
    tenant_id: str
    state: ConnectState
    challenge: ConsentChallenge
    grant: DirectoryGrant | None = None
    transport: GraphTransport | None = None
    live_scopes: tuple[str, ...] = field(default_factory=tuple)
    receipt: ConduitReceipt | None = None


class ConnectBroker:
    def __init__(
        self,
        *,
        strategies: list[ConnectStrategy],
        chain: ConduitProvenanceChain,
    ) -> None:
        self._strategies: dict[DiscoverySource, ConnectStrategy] = {
            s.provider: s for s in strategies
        }
        self._chain = chain
        self._connections: dict[str, Connection] = {}

    # ------------------------------------------------------------------ helpers
    def strategy_for(self, provider: DiscoverySource) -> ConnectStrategy:
        try:
            return self._strategies[provider]
        except KeyError:
            raise ConnectBrokerError(f"no connect strategy registered for {provider.value}")

    def connection(self, connection_id: str) -> Connection:
        try:
            return self._connections[connection_id]
        except KeyError:
            raise ConnectBrokerError(f"unknown connection_id {connection_id!r}")

    def _require(self, connection_id: str, expected: ConnectState) -> Connection:
        conn = self.connection(connection_id)
        if conn.state is not expected:
            raise InvalidStateTransition(
                f"connection {connection_id!r} is {conn.state.value}, expected {expected.value}"
            )
        return conn

    # ------------------------------------------------------------------ 1. REQUESTED
    def request(self, provider: DiscoverySource, tenant_id: str, *, nonce: str) -> ConsentChallenge:
        strategy = self.strategy_for(provider)
        connection_id = make_connection_id(tenant_id, nonce)
        if connection_id in self._connections:
            raise ConnectBrokerError(f"connection_id {connection_id!r} already exists")
        challenge = strategy.begin_consent(tenant_id, connection_id=connection_id)
        self._connections[connection_id] = Connection(
            connection_id=connection_id,
            provider=provider,
            tenant_id=tenant_id.strip().casefold(),
            state=ConnectState.REQUESTED,
            challenge=challenge,
        )
        return challenge

    # ------------------------------------------------------------------ 2. CONSENTED
    def consent(self, callback: ConsentCallback) -> DirectoryGrant:
        conn = self._require(callback.connection_id, ConnectState.REQUESTED)
        strategy = self.strategy_for(conn.provider)
        grant = strategy.finalize_consent(callback)
        conn.grant = grant
        conn.state = ConnectState.CONSENTED
        return grant

    # ------------------------------------------------------------------ 3. PROBED
    def probe(self, connection_id: str, *, live_scopes: list[str] | None = None) -> Connection:
        """Build a read-only transport from the granted credentials (proves the
        connection is reachable) and record the observed live scope baseline."""
        conn = self._require(connection_id, ConnectState.CONSENTED)
        assert conn.grant is not None  # guaranteed by CONSENTED
        strategy = self.strategy_for(conn.provider)
        try:
            conn.transport = strategy.build_transport(conn.grant)
        except NotImplementedError:
            # No transport factory wired (e.g. consent-only deployments). The
            # probe still records the scope baseline; reachability is unverified.
            conn.transport = None
        conn.live_scopes = (
            canonical_scopes(live_scopes) if live_scopes is not None else conn.grant.granted_scopes
        )
        conn.state = ConnectState.PROBED
        return conn

    # ------------------------------------------------------------------ 4. SEALED
    def seal(self, connection_id: str, *, anchor: AnchorFn | None = None) -> ConduitReceipt:
        conn = self._require(connection_id, ConnectState.PROBED)
        assert conn.grant is not None
        receipt = seal_grant(self._chain, conn.grant, anchor=anchor)
        conn.receipt = receipt
        conn.state = ConnectState.SEALED
        return receipt

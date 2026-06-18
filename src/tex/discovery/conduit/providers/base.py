"""
ConnectStrategy — the contract behind the one "Connect your directory" button.

The button is **one entry point, not one click**. Each provider's authorization
dance is different and that difference is shown honestly in the consent steps:
Entra is a true one-click admin-consent redirect; Okta is service-app +
private-key-JWT + a per-scope grant checklist (one step needs Super Admin);
Google is TWO read grants; Ping is per-deployment service-account config. A
``ConnectStrategy`` is the only place that divergence lives. Three methods:

  * ``begin_consent`` -> a ``ConsentChallenge`` the UI renders (its ``steps``
    are the honest checklist — one for Entra, several for Okta/Google).
  * ``finalize_consent`` -> a frozen ``DirectoryGrant`` recording exactly what
    least-privilege read access actually landed (degraded if any gap).
  * ``build_transport`` -> a ``GraphTransport`` over the granted connection,
    built from the opaque ``credential_ref`` (the broker never holds secrets).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from tex.discovery.conduit.grant import DirectoryGrant
from tex.discovery.graph_transport import GraphTransport
from tex.domain.discovery import DiscoverySource


@dataclass(frozen=True, slots=True)
class ConsentStep:
    """One step the UI must present. ``one_click=False`` is the honesty flag —
    a step that is a real configuration task, not a single OAuth click."""

    step_id: str
    label: str
    instructions: str
    required_scopes: tuple[str, ...] = ()
    one_click: bool = False
    needs_super_admin: bool = False
    optional: bool = False


@dataclass(frozen=True, slots=True)
class ConsentChallenge:
    """What the broker hands the UI to drive a connection's consent."""

    provider: DiscoverySource
    tenant_id: str
    connection_id: str  # opaque; points at the deployment secret-store entry
    requested_scopes: tuple[str, ...]
    steps: tuple[ConsentStep, ...]

    @property
    def is_one_click(self) -> bool:
        return len(self.steps) == 1 and self.steps[0].one_click


@dataclass(frozen=True, slots=True)
class ConsentCallback:
    """What the consent flow returns once the customer has granted access. The
    provider tells us the consent-artifact id and the scopes that ACTUALLY
    landed; the deployment has already written the secret to its store and hands
    back only the opaque ``credential_ref``."""

    connection_id: str
    consent_artifact_id: str
    granted_scopes: tuple[str, ...]
    credential_ref: str
    consented_by: str | None = None


@runtime_checkable
class ConnectStrategy(Protocol):
    provider: DiscoverySource
    requested_scopes: tuple[str, ...]

    def begin_consent(
        self, tenant_id: str, *, connection_id: str
    ) -> ConsentChallenge: ...

    def finalize_consent(self, callback: ConsentCallback) -> DirectoryGrant: ...

    def build_transport(self, grant: DirectoryGrant) -> GraphTransport: ...


@dataclass
class BaseConnectStrategy:
    """Shared finalize/build plumbing. Subclasses set ``provider`` /
    ``requested_scopes`` and override ``begin_consent`` with the provider's real
    steps. ``transport_factory`` resolves the opaque ``credential_ref`` to a live
    transport (a deployment wires the secret-store lookup; tests inject one)."""

    provider: DiscoverySource
    requested_scopes: tuple[str, ...]
    transport_factory: Callable[[DirectoryGrant], GraphTransport] | None = field(default=None)
    tenant_clock: Callable[[], object] | None = field(default=None)

    def finalize_consent(self, callback: ConsentCallback) -> DirectoryGrant:
        from datetime import UTC, datetime

        granted_at = datetime.now(UTC)
        return DirectoryGrant(
            provider=self.provider,
            tenant_id=_tenant_of(callback.connection_id),
            requested_scopes=self.requested_scopes,
            granted_scopes=callback.granted_scopes,
            consent_artifact_id=callback.consent_artifact_id,
            consented_by=callback.consented_by,
            granted_at=granted_at,
            credential_ref=callback.credential_ref,
        )

    def build_transport(self, grant: DirectoryGrant) -> GraphTransport:
        if self.transport_factory is None:
            raise NotImplementedError(
                f"{self.provider.value}: wire a transport_factory that resolves "
                "the credential_ref from the deployment secret store"
            )
        return self.transport_factory(grant)


# The connection_id encodes the tenant as "<tenant>::<nonce>" so finalize can
# recover it without the broker threading tenant through the callback. Kept tiny
# and explicit; a real deployment can swap in any opaque scheme.
def make_connection_id(tenant_id: str, nonce: str) -> str:
    return f"{tenant_id.strip().casefold()}::{nonce}"


def _tenant_of(connection_id: str) -> str:
    return connection_id.split("::", 1)[0]

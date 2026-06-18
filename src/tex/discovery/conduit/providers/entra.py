"""
Entra connect strategy — the genuinely one-click case.

A single multi-tenant admin-consent redirect grants the read-only Graph triad
(``Application.Read.All`` + ``DelegatedPermissionGrant.Read.All`` +
``AuditLog.Read.All``). This is the only provider we honestly market as
one-click.
"""

from __future__ import annotations

from dataclasses import dataclass

from tex.discovery.conduit.providers.base import (
    BaseConnectStrategy,
    ConsentChallenge,
    ConsentStep,
)
from tex.domain.discovery import DiscoverySource

ENTRA_READ_SCOPES = (
    "application.read.all",
    "delegatedpermissiongrant.read.all",
    "auditlog.read.all",
)


@dataclass
class EntraConnectStrategy(BaseConnectStrategy):
    def __init__(self, **kwargs) -> None:
        super().__init__(
            provider=DiscoverySource.MICROSOFT_GRAPH,
            requested_scopes=ENTRA_READ_SCOPES,
            **kwargs,
        )

    def begin_consent(self, tenant_id: str, *, connection_id: str) -> ConsentChallenge:
        return ConsentChallenge(
            provider=self.provider,
            tenant_id=tenant_id,
            connection_id=connection_id,
            requested_scopes=self.requested_scopes,
            steps=(
                ConsentStep(
                    step_id="admin_consent",
                    label="Grant read-only directory access",
                    instructions=(
                        "Approve the multi-tenant admin-consent prompt. One click "
                        "grants Application.Read.All + DelegatedPermissionGrant.Read.All "
                        "+ AuditLog.Read.All — read-only, no write."
                    ),
                    required_scopes=self.requested_scopes,
                    one_click=True,
                ),
            ),
        )

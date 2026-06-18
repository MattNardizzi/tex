"""
Ping connect strategy — per-deployment service-account config.

Ping deployments differ (self-hosted PingFederate vs PingOne AIC), so the
transport's ``base_url`` is configured per deployment. The grant is a read-only
service account over the OAuth Client Management API.
"""

from __future__ import annotations

from dataclasses import dataclass

from tex.discovery.conduit.providers.base import (
    BaseConnectStrategy,
    ConsentChallenge,
    ConsentStep,
)
from tex.domain.discovery import DiscoverySource

PING_READ_SCOPES = (
    "p1:read:application",
    "p1:read:user",
    "p1:read:role",
)


@dataclass
class PingConnectStrategy(BaseConnectStrategy):
    def __init__(self, **kwargs) -> None:
        super().__init__(
            provider=DiscoverySource.PING,
            requested_scopes=PING_READ_SCOPES,
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
                    step_id="ping_service_account",
                    label="Configure a read-only Ping service account",
                    instructions=(
                        "Create a read-only service account / client with the OAuth "
                        "Client Management read scopes, and set the deployment base_url "
                        "(PingFederate REST or PingOne AIC)."
                    ),
                    required_scopes=self.requested_scopes,
                    one_click=False,
                ),
            ),
        )

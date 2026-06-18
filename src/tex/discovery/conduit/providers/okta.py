"""
Okta connect strategy — honestly multi-step.

NOT one click: a service app with private-key-JWT auth, then a per-scope grant
checklist the broker verifies landed. One scope — ``okta.appGrants.read`` —
typically needs Super Admin; if it is withheld the connection runs a partial
census (apps + clients only) and the grant seals as DEGRADED rather than
silently dropping it.
"""

from __future__ import annotations

from dataclasses import dataclass

from tex.discovery.conduit.providers.base import (
    BaseConnectStrategy,
    ConsentChallenge,
    ConsentStep,
)
from tex.domain.discovery import DiscoverySource

# The least-privilege read scopes Okta needs (casefolded — they are sealed and
# compared casefolded everywhere).
OKTA_READ_SCOPES = (
    "okta.apps.read",
    "okta.clients.read",
    "okta.appgrants.read",
    "okta.oauthintegrations.read",
    "okta.serviceaccounts.read",
    "okta.apitokens.read",
    "okta.logs.read",
)

# The scopes that do not require Super Admin — the apps+clients census floor.
_BASE_READ_SCOPES = tuple(s for s in OKTA_READ_SCOPES if s != "okta.appgrants.read")


@dataclass
class OktaConnectStrategy(BaseConnectStrategy):
    def __init__(self, **kwargs) -> None:
        super().__init__(
            provider=DiscoverySource.OKTA,
            requested_scopes=OKTA_READ_SCOPES,
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
                    step_id="create_service_app",
                    label="Create a read-only API service app",
                    instructions=(
                        "Create an Okta API service app authenticating with a "
                        "private-key JWT (not a static SSWS token). Tex never "
                        "stores a long-lived secret — only an opaque reference."
                    ),
                    one_click=False,
                ),
                ConsentStep(
                    step_id="grant_base_read",
                    label="Grant the read-only API scopes",
                    instructions="Grant the apps/clients/service-accounts/logs read scopes.",
                    required_scopes=_BASE_READ_SCOPES,
                    one_click=False,
                ),
                ConsentStep(
                    step_id="grant_app_grants_read",
                    label="Grant okta.appGrants.read (needs Super Admin)",
                    instructions=(
                        "okta.appGrants.read reveals each app's consented scopes — "
                        "the consent-graph edges. It typically needs Super Admin. "
                        "If withheld, the census runs apps+clients only and the "
                        "grant is sealed as partial."
                    ),
                    required_scopes=("okta.appgrants.read",),
                    one_click=False,
                    needs_super_admin=True,
                    optional=True,
                ),
            ),
        )

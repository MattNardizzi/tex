"""
Google connect strategies — TWO grants, never one click.

Google is two distinct read grants, surfaced as a two-step checklist in one
modal and sealed as TWO separate receipts:

  * ``GoogleWorkspaceConnectStrategy`` (source GOOGLE_WORKSPACE) — Admin SDK
    Directory + Reports token-audit under domain-wide delegation.
  * ``GcpIamConnectStrategy`` (source GCP_IAM) — Cloud Asset Inventory org
    viewer for org-wide service accounts + IAM bindings.

Each is its own connection in the broker, so each seals its own GRANT_SEALED
receipt — honest about being two grants, not one.
"""

from __future__ import annotations

from dataclasses import dataclass

from tex.discovery.conduit.providers.base import (
    BaseConnectStrategy,
    ConsentChallenge,
    ConsentStep,
)
from tex.domain.discovery import DiscoverySource

GOOGLE_WORKSPACE_READ_SCOPES = (
    "https://www.googleapis.com/auth/admin.directory.user.readonly",
    "https://www.googleapis.com/auth/admin.directory.domain.readonly",
    "https://www.googleapis.com/auth/admin.reports.audit.readonly",
)

GCP_IAM_READ_SCOPES = (
    "roles/cloudasset.viewer",
    "roles/iam.securityreviewer",
)


@dataclass
class GoogleWorkspaceConnectStrategy(BaseConnectStrategy):
    def __init__(self, **kwargs) -> None:
        super().__init__(
            provider=DiscoverySource.GOOGLE_WORKSPACE,
            requested_scopes=GOOGLE_WORKSPACE_READ_SCOPES,
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
                    step_id="workspace_dwd",
                    label="Grant 1 of 2 — Workspace domain-wide delegation (read-only)",
                    instructions=(
                        "Authorize the Tex client for read-only Admin SDK Directory "
                        "+ Reports token-audit. This is the FIRST of two separate "
                        "Google grants — it is not one click."
                    ),
                    required_scopes=self.requested_scopes,
                    one_click=False,
                ),
            ),
        )


@dataclass
class GcpIamConnectStrategy(BaseConnectStrategy):
    def __init__(self, **kwargs) -> None:
        super().__init__(
            provider=DiscoverySource.GCP_IAM,
            requested_scopes=GCP_IAM_READ_SCOPES,
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
                    step_id="gcp_org_viewer",
                    label="Grant 2 of 2 — GCP org viewer (Cloud Asset Inventory)",
                    instructions=(
                        "Grant read-only Cloud Asset Inventory + IAM security "
                        "reviewer at the org. This is the SECOND, SEPARATE Google "
                        "grant, sealed as its own receipt."
                    ),
                    required_scopes=self.requested_scopes,
                    one_click=False,
                ),
            ),
        )

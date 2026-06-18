"""
Cross-provider critical-scope dictionary — a maintained, standing asset.

The risk taxonomy splits cleanly in two:

  * **HIGH-risk stems are portable.** ``readwrite`` / ``write`` / ``send`` /
    ``delete`` / ``manage`` / ``fullcontrol`` / ``impersonation`` appear as
    substrings in every provider's scope vocabulary, so the same
    ``HIGH_RISK_SCOPE_STEMS`` substring set works unchanged across Entra, Okta,
    Google, and Ping.

  * **CRITICAL scopes are NOT portable.** "Critical" means *tenant-wide control
    of identity itself* — a scope whose holder can grant OTHER agents access, so
    its blast radius is the whole org. Those are literal, provider-specific
    permission strings with no clean isomorphism to each other (Entra's
    ``directory.readwrite.all`` vs Okta's ``okta.users.manage`` vs GCP's
    ``roles/owner``). Each provider therefore ships its OWN curated critical set,
    matched by **exact membership**, layered onto the SAME ``blast_radius()``
    engine.

This module is that curated set, per provider. It is honestly a maintenance
liability — these vocabularies drift as providers add scopes — not a free seed.
All sets are stored casefolded because ``ConsentGraph.scope_set`` casefolds
before matching.
"""

from __future__ import annotations

from tex.discovery.consent_graph import (
    CRITICAL_SCOPE_STEMS as ENTRA_CRITICAL_SCOPES,  # noqa: F401  (re-export: one source of truth)
)
from tex.discovery.consent_graph import HIGH_RISK_SCOPE_STEMS  # noqa: F401  (re-export)
from tex.domain.discovery import DiscoverySource

# --- Okta -------------------------------------------------------------------
# Okta API scopes that confer org-wide control of identity, apps, groups, or
# admin-role assignment — i.e. the holder can grant other principals access, so
# its blast radius is the whole org. ``.manage`` scopes (write/admin) only; the
# corresponding ``.read`` scopes are not critical. Stored casefolded.
OKTA_CRITICAL_SCOPES = frozenset(
    {
        "okta.users.manage",
        "okta.groups.manage",
        "okta.apps.manage",
        "okta.roles.manage",  # admin-role assignment — can elevate other principals
        "okta.policies.manage",
        "okta.authorizationservers.manage",
        "okta.idps.manage",
        "okta.factors.manage",
        "okta.trustedorigins.manage",
        "okta.domains.manage",
        "okta.orgs.manage",
        "okta.clients.manage",  # can mint/alter OAuth clients (other agents)
    }
)

# --- Google (Workspace + GCP IAM) -------------------------------------------
# Filled in Phase 4. Stored casefolded.
GOOGLE_WORKSPACE_CRITICAL_SCOPES: frozenset[str] = frozenset(
    {
        # Domain-wide delegation over directory + admin settings.
        "https://www.googleapis.com/auth/admin.directory.user",
        "https://www.googleapis.com/auth/admin.directory.group",
        "https://www.googleapis.com/auth/admin.directory.rolemanagement",
        "https://www.googleapis.com/auth/cloud-platform",
    }
)

GCP_IAM_CRITICAL_SCOPES: frozenset[str] = frozenset(
    {
        "roles/owner",
        "roles/iam.securityadmin",
        "roles/iam.serviceaccountadmin",
        "roles/iam.serviceaccountkeyadmin",
        "roles/resourcemanager.organizationadmin",
        "roles/iam.organizationroleadmin",
    }
)

# --- Ping (PingFederate / PingOne) ------------------------------------------
# Filled in Phase 4. Stored casefolded.
PING_CRITICAL_SCOPES: frozenset[str] = frozenset(
    {
        "p1:create:user",
        "p1:update:user",
        "p1:delete:user",
        "p1:read:role",
        "p1:update:role",
        "p1:update:application",
        "p1:create:application",
        "admin",
    }
)


CRITICAL_SCOPES_BY_PROVIDER: dict[DiscoverySource, frozenset[str]] = {
    DiscoverySource.MICROSOFT_GRAPH: ENTRA_CRITICAL_SCOPES,
    DiscoverySource.OKTA: OKTA_CRITICAL_SCOPES,
    DiscoverySource.GOOGLE_WORKSPACE: GOOGLE_WORKSPACE_CRITICAL_SCOPES,
    DiscoverySource.GCP_IAM: GCP_IAM_CRITICAL_SCOPES,
    DiscoverySource.PING: PING_CRITICAL_SCOPES,
}


def critical_scopes_for(source: DiscoverySource) -> frozenset[str]:
    """The curated critical-scope set for one provider (empty if unknown)."""
    return CRITICAL_SCOPES_BY_PROVIDER.get(source, frozenset())


# --- HIGH-risk stems, per provider -----------------------------------------
# The portable substring stems are the floor. Some providers need a few extra
# stems because their scope vocabularies don't spell "write" the portable way:
# GCP uses role names (owner/editor/admin/actAs/tokenCreator), Ping uses
# create/update/delete verbs. Read-only scopes still match nothing -> LOW.
GCP_IAM_HIGH_RISK_STEMS = HIGH_RISK_SCOPE_STEMS | frozenset(
    {"owner", "editor", "admin", "actas", "serviceaccountuser", "tokencreator"}
)
GOOGLE_WORKSPACE_HIGH_RISK_STEMS = HIGH_RISK_SCOPE_STEMS | frozenset(
    {"admin.directory", "cloud-platform"}
)
PING_HIGH_RISK_STEMS = HIGH_RISK_SCOPE_STEMS | frozenset({"create", "update"})

HIGH_RISK_STEMS_BY_PROVIDER: dict[DiscoverySource, frozenset[str]] = {
    DiscoverySource.GCP_IAM: GCP_IAM_HIGH_RISK_STEMS,
    DiscoverySource.GOOGLE_WORKSPACE: GOOGLE_WORKSPACE_HIGH_RISK_STEMS,
    DiscoverySource.PING: PING_HIGH_RISK_STEMS,
}


def high_risk_stems_for(source: DiscoverySource) -> frozenset[str]:
    """High-risk substring stems for one provider (portable floor if unlisted)."""
    return HIGH_RISK_STEMS_BY_PROVIDER.get(source, HIGH_RISK_SCOPE_STEMS)

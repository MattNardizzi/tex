"""
estate.py — the synthetic estate generator.

Given a seed and a size, this produces a deterministic, archetype-faithful
population of AI agents and emits them in the EXACT wire shapes Tex's real
discovery connectors parse:

    entra_pages(estate)        -> Microsoft Graph fixture pages
                                  (servicePrincipals + oauth2PermissionGrants
                                   + appRoleAssignments), consumed by
                                   EntraConsentGraphConnector via
                                   FixtureGraphTransport.

    cloudtrail_records(estate) -> raw AWS CloudTrail / Bedrock AgentCore
                                  records, consumed by OcsfAuditConnector
                                  (source_format="cloudtrail").

    mcp_clients(estate)        -> MCP discovery-handshake records, consumed by
                                  MCPServerConnector (records=...). Optional.

The key property: the estate flows through the *real* connectors, the *real*
reconciliation engine, the *real* hash-chained ledger. The fake stops at the
connector transport — exactly where a live tenant's data would enter. Nothing
above the seam knows the difference.

This is a drop-in superset of ``tex.discovery.demo_seed``: same shapes, but
archetype-driven, scalable from 12 to 5,000+, and split into an IdP-visible
majority and a directory-invisible shadow cohort.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from tex.sim import archetype as A

_GRAPH_RESOURCE = "00000003-0000-0000-c000-000000000000"  # Microsoft Graph SP
_BEDROCK_ACCOUNT = "111122223333"
_REGION = "us-east-1"


@dataclass(frozen=True, slots=True)
class SimAgent:
    """One synthetic agent, plane-tagged, with stable identity."""

    external_id: str          # stable handle (sp id or ARN tail)
    name: str                 # display name
    plane: str                # "entra" | "shadow_audit" | "mcp"
    department: str           # archetype department key (or "shadow")
    owner: str
    scopes: tuple[str, ...]
    consent: str              # "AllPrincipals" | "Principal"
    risk_profile: str         # "critical" | "high" | "low"
    action_profiles: tuple[str, ...]
    is_shadow: bool
    # plane-specific identifiers
    sp_id: str | None = None
    arn: str | None = None
    runtime_user_id: str | None = None
    mcp_host_kind: str | None = None
    mcp_tools: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Estate:
    """A generated estate: the agents plus the seed/config that made it."""

    org_name: str
    tenant_id: str
    seed: int
    agents: tuple[SimAgent, ...]

    @property
    def idp_agents(self) -> tuple[SimAgent, ...]:
        return tuple(a for a in self.agents if a.plane == "entra")

    @property
    def shadow_agents(self) -> tuple[SimAgent, ...]:
        return tuple(a for a in self.agents if a.is_shadow)

    @property
    def mcp_agents(self) -> tuple[SimAgent, ...]:
        return tuple(a for a in self.agents if a.plane == "mcp")

    def summary(self) -> dict[str, Any]:
        by_risk: dict[str, int] = {}
        by_dept: dict[str, int] = {}
        for a in self.agents:
            by_risk[a.risk_profile] = by_risk.get(a.risk_profile, 0) + 1
            by_dept[a.department] = by_dept.get(a.department, 0) + 1
        return {
            "org": self.org_name,
            "tenant_id": self.tenant_id,
            "seed": self.seed,
            "total": len(self.agents),
            "idp_visible": len(self.idp_agents),
            "shadow": len(self.shadow_agents),
            "mcp": len(self.mcp_agents),
            "by_risk": by_risk,
            "by_department": by_dept,
        }


# --------------------------------------------------------------------------- #
#  Generation                                                                 #
# --------------------------------------------------------------------------- #

def _pick_scopes(rng: random.Random, risk_profile: str) -> tuple[str, ...]:
    """Choose a believable scope bundle for a risk profile."""
    if risk_profile == "critical":
        core = rng.sample(A.SCOPES_CRITICAL, k=rng.randint(1, 2))
        extra = rng.sample(A.SCOPES_HIGH, k=rng.randint(0, 1))
    elif risk_profile == "high":
        core = rng.sample(A.SCOPES_HIGH, k=rng.randint(1, 2))
        extra = rng.sample(A.SCOPES_LOW, k=rng.randint(0, 1))
    else:
        core = rng.sample(A.SCOPES_LOW, k=rng.randint(1, 2))
        extra = []
    return tuple(dict.fromkeys([*core, *extra]))  # dedupe, keep order


def _risk_from_mix(rng: random.Random, mix: tuple[float, float, float]) -> str:
    r = rng.random()
    crit, high, _low = mix
    if r < crit:
        return "critical"
    if r < crit + high:
        return "high"
    return "low"


def generate_estate(
    *,
    seed: int = 7,
    idp_agents: int = 170,
    shadow_agents: int = 30,
    mcp_agents: int = 0,
    tenant_id: str | None = None,
) -> Estate:
    """
    Build a deterministic estate. Defaults to the reference tier:
    170 IdP-discovered + 30 shadow = 200, ~15% shadow.

    Smoke tier: generate_estate(idp_agents=9, shadow_agents=3).
    Soak tier:  generate_estate(idp_agents=4500, shadow_agents=500).
    """
    rng = random.Random(seed)
    tenant = tenant_id or f"{A.ORG_TENANT_HINT}-{seed}"
    agents: list[SimAgent] = []

    # ---- IdP-visible population, split across departments by weight -------- #
    idx = 0
    for dept, count in A.department_population(idp_agents):
        for _ in range(count):
            stem = dept.agent_stems[idx % len(dept.agent_stems)]
            risk = _risk_from_mix(rng, dept.risk_mix)
            scopes = _pick_scopes(rng, risk)
            # Critical/high agents tend to hold tenant-wide consent.
            consent = "AllPrincipals" if risk in ("critical", "high") and rng.random() < 0.8 else "Principal"
            sp_id = f"sp-{idx:04d}-{stem}"
            agents.append(
                SimAgent(
                    external_id=sp_id,
                    name=f"{stem}-{idx:03d}",
                    plane="entra",
                    department=dept.key,
                    owner=rng.choice(dept.owners),
                    scopes=scopes,
                    consent=consent,
                    risk_profile=risk,
                    action_profiles=dept.action_profiles,
                    is_shadow=False,
                    sp_id=sp_id,
                )
            )
            idx += 1

    # ---- Shadow cohort: invisible to the directory, caught by audit -------- #
    for j in range(shadow_agents):
        prof = A.SHADOW_PROFILES[j % len(A.SHADOW_PROFILES)]
        arn = f"arn:aws:bedrock-agentcore:{_REGION}:{_BEDROCK_ACCOUNT}:runtime/{prof.stem}-{j:02d}"
        # Shadow agents skew high-risk (no governance, broad personal keys).
        risk = "critical" if rng.random() < 0.5 else "high"
        agents.append(
            SimAgent(
                external_id=arn,
                name=f"{prof.stem}-{j:02d}",
                plane="shadow_audit",
                department="shadow",
                owner=prof.pretext,
                scopes=(),  # the directory has no scopes for it — that's the point
                consent="Principal",
                risk_profile=risk,
                action_profiles=("destructive_ops_attempt", "external_sharing", "payment_movement"),
                is_shadow=True,
                arn=arn,
                runtime_user_id=f"u-{rng.randint(1000, 9999)}",
            )
        )

    # ---- Optional MCP coding-agent hosts (shadow engineering plane) -------- #
    for k in range(mcp_agents):
        host = A.MCP_HOST_KINDS[k % len(A.MCP_HOST_KINDS)]
        tools = tuple(rng.sample(A.MCP_TOOL_POOL, k=rng.randint(2, 4)))
        risk = "critical" if "shell.exec" in tools or "secrets.read" in tools else "high"
        agents.append(
            SimAgent(
                external_id=f"mcp-{host}-{k:02d}",
                name=f"{host}-agent-{k:02d}",
                plane="mcp",
                department="engineering",
                owner="endpoint-eng",
                scopes=tools,
                consent="Principal",
                risk_profile=risk,
                action_profiles=("destructive_ops_attempt", "deploy_action"),
                is_shadow=True,
                mcp_host_kind=host,
                mcp_tools=tools,
            )
        )

    return Estate(org_name=A.ORG_NAME, tenant_id=tenant, seed=seed, agents=tuple(agents))


# --------------------------------------------------------------------------- #
#  Wire-shape emitters — the connector inputs.                                #
# --------------------------------------------------------------------------- #

def entra_pages(estate: Estate) -> dict[str, list[dict[str, Any]]]:
    """
    Microsoft Graph fixture pages for the IdP-visible population. Shape matches
    what EntraConsentGraphConnector reads via FixtureGraphTransport:
      - "servicePrincipals"
      - "servicePrincipals/{id}/oauth2PermissionGrants"
      - "servicePrincipals/{id}/appRoleAssignments"
    """
    sps: list[dict[str, Any]] = []
    pages: dict[str, list[dict[str, Any]]] = {}
    for i, a in enumerate(estate.idp_agents):
        sp_id = a.sp_id or a.external_id
        sps.append(
            {
                "id": sp_id,
                "displayName": a.name,
                "servicePrincipalType": "Application",
                # Entra's own "this is an agent" tag, present on a fraction.
                "tags": ["AgentIdentity"] if i % 3 == 0 else [],
            }
        )
        pages[f"servicePrincipals/{sp_id}/oauth2PermissionGrants"] = [
            {
                "resourceId": _GRAPH_RESOURCE,
                "resourceDisplayName": "Microsoft Graph",
                "scope": " ".join(a.scopes),
                "consentType": a.consent,
            }
        ]
        # A subset also carry app-role assignments (broad app permissions).
        if a.risk_profile == "critical":
            pages[f"servicePrincipals/{sp_id}/appRoleAssignments"] = [
                {
                    "resourceId": _GRAPH_RESOURCE,
                    "resourceDisplayName": "Microsoft Graph",
                    "appRoleId": "app-role-readwrite-all",
                }
            ]
        else:
            pages[f"servicePrincipals/{sp_id}/appRoleAssignments"] = []
    pages["servicePrincipals"] = sps
    return pages


def cloudtrail_records(estate: Estate) -> list[dict[str, Any]]:
    """
    Raw CloudTrail records for the shadow cohort, in the current (2026)
    Bedrock AgentCore shape: eventSource bedrock-agentcore.amazonaws.com,
    data-plane event names, AWS::BedrockAgentCore::Runtime resources, and the
    runtimeUserId impersonation field where present.
    """
    out: list[dict[str, Any]] = []
    base = datetime(2026, 5, 30, tzinfo=UTC)
    for i, a in enumerate(estate.shadow_agents):
        prof = A.SHADOW_PROFILES[i % len(A.SHADOW_PROFILES)]
        arn = a.arn or a.external_id
        src_ip = f"34.{(i * 7) % 250}.{(i * 13) % 250}.{(i * 3) % 250}"
        for j, ev in enumerate(prof.events):
            ts = (base + timedelta(hours=i % 9, minutes=j * 3)).strftime("%Y-%m-%dT%H:%M:%SZ")
            record: dict[str, Any] = {
                "eventVersion": "1.11",
                "eventSource": "bedrock-agentcore.amazonaws.com",
                "eventName": ev,
                "eventTime": ts,
                "awsRegion": _REGION,
                "sourceIPAddress": src_ip,
                "userAgent": "python-httpx/0.28.1",
                "userIdentity": {
                    "type": "AssumedRole",
                    "principalId": f"AROA:{prof.stem}-{i:02d}",
                    "arn": f"arn:aws:sts::{_BEDROCK_ACCOUNT}:assumed-role/{prof.stem}-{i:02d}",
                },
                "resources": [
                    {"accountId": _BEDROCK_ACCOUNT, "type": "AWS::BedrockAgentCore::Runtime", "ARN": arn}
                ],
                "eventType": "AwsApiCall",
                "managementEvent": False,
                "readOnly": False,
            }
            # Impersonation vector: the runtimeUserId header, where used.
            if a.runtime_user_id and ev in ("InvokeAgentRuntime", "InvokeAgentRuntimeCommand"):
                record["requestParameters"] = {"runtimeUserId": a.runtime_user_id}
            if ev == "InvokeMcp":
                record["requestParameters"] = {
                    "body": {
                        "jsonrpc": "2.0",
                        "id": j,
                        "method": "initialize",
                        "params": {
                            "protocolVersion": "2025-06-18",
                            "clientInfo": {"name": "mcp", "version": "0.1.0"},
                            "capabilities": {},
                        },
                    }
                }
            out.append(record)
    return out


def mcp_clients(estate: Estate) -> list[dict[str, Any]]:
    """MCP discovery-handshake records for the MCPServerConnector mock."""
    out: list[dict[str, Any]] = []
    for a in estate.mcp_agents:
        out.append(
            {
                "client_id": a.external_id,
                "client_name": a.name,
                "client_version": "1.0.0",
                "host_kind": a.mcp_host_kind or "custom",
                "tool_names": list(a.mcp_tools),
                "resource_uris": [f"mcp://{a.mcp_host_kind}/{t}" for t in a.mcp_tools],
                "owner": a.owner,
                "last_seen_at": "2026-05-30T12:00:00Z",
            }
        )
    return out

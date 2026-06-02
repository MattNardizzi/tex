"""
Demo seed — a believable estate for the live roots to fall back to.

The IdP consent-graph enumerator (root one) and the OCSF audit plane (root
two) only see a real estate once a customer grants the read. Until then,
"click Begin and watch the inventory come back" needs *something* truthful
to map — not a hardcoded count, but real candidate agents flowing through
the real pipeline: reconciliation registers them, the provenance engine
seals a behavioural birth for each (so engine memory engages), and the
ignition surface counts what was actually found.

This module is that seed. It produces the same record shapes Microsoft
Graph and AWS CloudTrail return, fed through the *real* connectors via their
fixture transports — so the path a demo exercises is identical to the path a
live tenant exercises, only the data source differs. The moment the env
credentials are present, ``_build_discovery_connectors`` swaps the fixture
transport for the live one and this seed is never touched.

The seed is tenant-agnostic: the connectors stamp the scan's tenant onto
every candidate, so the same seed serves any preview tenant. It is sized to
land the spoken count near the familiar line ("forty-one agents running").
"""

from __future__ import annotations

from typing import Any

# How many agents each plane contributes. Entra + audit are distinct sources
# (distinct reconciliation keys), so the registered estate is their sum.
_ENTRA_AGENTS = 33
_AUDIT_AGENTS = 8  # 33 + 8 = 41

_GRAPH_RESOURCE = "00000003-0000-0000-c000-000000000000"  # Microsoft Graph SP

# A rotation of plausible agent names + the scope profile each gets, so the
# seed shows a realistic spread of risk bands and blast radius rather than 33
# identical rows.
_ENTRA_PROFILES = [
    ("invoice-reconciler", "Mail.Read offline_access", "AllPrincipals"),
    ("copilot-hr-assistant", "Mail.Send Files.Read.All", "AllPrincipals"),
    ("sharepoint-indexer", "Sites.Read.All Files.Read.All", "AllPrincipals"),
    ("deploy-bot", "Application.ReadWrite.All", "AllPrincipals"),
    ("calendar-scheduler", "Calendars.ReadWrite", "Principal"),
    ("crm-sync-agent", "Files.ReadWrite.All Mail.Send", "AllPrincipals"),
    ("support-triage-bot", "Mail.Read Chat.Read", "Principal"),
    ("finance-approver", "Mail.Send Directory.Read.All", "AllPrincipals"),
    ("data-export-agent", "Files.ReadWrite.All Sites.FullControl.All", "AllPrincipals"),
    ("onboarding-orchestrator", "User.ReadWrite.All Directory.ReadWrite.All", "AllPrincipals"),
    ("notify-service", "Mail.Send", "Principal"),
]


def entra_pages(count: int = _ENTRA_AGENTS) -> dict[str, list[dict[str, Any]]]:
    """Microsoft Graph fixture pages: ``count`` agent service principals + grants."""
    sps: list[dict[str, Any]] = []
    pages: dict[str, list[dict[str, Any]]] = {}
    for i in range(count):
        name, scope, consent = _ENTRA_PROFILES[i % len(_ENTRA_PROFILES)]
        sp_id = f"sp-{i:04d}-{name}"
        sps.append(
            {
                "id": sp_id,
                "displayName": f"{name}-{i:02d}",
                "servicePrincipalType": "Application",
                "tags": ["AgentIdentity"] if i % 3 == 0 else [],
            }
        )
        pages[f"servicePrincipals/{sp_id}/oauth2PermissionGrants"] = [
            {
                "resourceId": _GRAPH_RESOURCE,
                "resourceDisplayName": "Microsoft Graph",
                "scope": scope,
                "consentType": consent,
            }
        ]
        pages[f"servicePrincipals/{sp_id}/appRoleAssignments"] = []
    pages["servicePrincipals"] = sps
    return pages


def cloudtrail_records(count: int = _AUDIT_AGENTS) -> list[dict[str, Any]]:
    """Raw CloudTrail records for ``count`` distinct AgentCore agents acting."""
    events = (
        "InvokeAgentRuntime",
        "InvokeGateway",
        "InvokeMcp",
        "CreateMemory",
    )
    out: list[dict[str, Any]] = []
    for i in range(count):
        arn = f"arn:aws:bedrock-agentcore:us-east-1:111122223333:runtime/shadow-agent-{i:02d}"
        # A few events per agent so the audit signal is more than one ping.
        for j, ev in enumerate(events[: 2 + (i % 3)]):
            out.append(
                {
                    "eventSource": "bedrock-agentcore.amazonaws.com",
                    "eventName": ev,
                    "eventTime": f"2026-05-30T1{i % 9}:0{j}:00Z",
                    "userIdentity": {
                        "type": "AssumedRole",
                        "principalId": f"AROA:shadow-{i:02d}",
                        "arn": f"arn:aws:sts::111122223333:assumed-role/shadow-{i:02d}",
                    },
                    "resources": [
                        {"ARN": arn, "type": "AWS::BedrockAgentCore::Runtime"}
                    ],
                }
            )
    return out

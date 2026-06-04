"""
archetype.py — the shape of a real enterprise, so the synthetic estate is a
*mirror* and not a toy.

The simulator's reference tier is one company, modelled in enough detail that
its agent population, OAuth scope spreads, owners, and blast radii look like a
real directory dump rather than a row of identical placeholders. The default
archetype is a mid-size financial-services SaaS firm — the segment where
agentic adoption and governance pressure are both highest as of mid-2026.

Grounding (June 2026):
  * NHIs outnumber humans ~45:1 in the average enterprise, far higher in
    cloud-native shops. A ~1,200-person firm therefore carries a large
    non-human population; we model the AI-agent slice of it.
  * Shadow AI is real and material: >half of employees use unapproved AI and
    >16% of orgs do not track AI-identity creation at all. So a faithful
    estate must include a cohort the IdP never sees — caught only by the
    audit / egress planes. We default that cohort to ~15% of the estate.
  * Identity is the control plane: the bulk of the estate is therefore
    discovered through ONE Entra consent-graph grant (Tex's rooted, single-
    grant doctrine), not by wiring ten SaaS connectors.

Everything here is data, not behaviour. ``estate.py`` consumes it to emit the
exact Microsoft Graph and CloudTrail/OCSF record shapes Tex's real connectors
parse; ``behavior.py`` consumes it to drive realistic action streams.
"""

from __future__ import annotations

from dataclasses import dataclass, field


# --------------------------------------------------------------------------- #
#  Microsoft Graph scope vocabulary, by risk weight.                          #
#                                                                             #
#  The Entra connector derives a risk band from the granted scope + consent   #
#  type (tenant-wide writes -> HIGH). We pick from these pools so the estate   #
#  shows a believable spread of blast radius, not 200 identical low-risk SPs.  #
# --------------------------------------------------------------------------- #

# Tenant-wide write / admin scopes — the high-blast-radius surface.
SCOPES_CRITICAL: tuple[str, ...] = (
    "Application.ReadWrite.All",
    "Directory.ReadWrite.All",
    "User.ReadWrite.All",
    "Sites.FullControl.All",
    "RoleManagement.ReadWrite.Directory",
    "AppRoleAssignment.ReadWrite.All",
)

# Broad read / scoped write — meaningful but not catastrophic.
SCOPES_HIGH: tuple[str, ...] = (
    "Mail.Send",
    "Files.ReadWrite.All",
    "Sites.Read.All",
    "Directory.Read.All",
    "Group.ReadWrite.All",
    "Chat.ReadWrite.All",
)

# Narrow read / single-mailbox — low blast radius.
SCOPES_LOW: tuple[str, ...] = (
    "Mail.Read",
    "Files.Read.All",
    "Calendars.Read",
    "Chat.Read",
    "User.Read",
    "offline_access",
)


@dataclass(frozen=True, slots=True)
class Department:
    """One business unit and the kinds of agents it tends to run."""

    key: str
    name: str
    # Relative weight of this department's agent population.
    weight: int
    # Candidate agent name stems (a number is appended per instance).
    agent_stems: tuple[str, ...]
    # Owner pool (the human/team a discovered agent is attributed to).
    owners: tuple[str, ...]
    # How risky this department's agents skew: probabilities for
    # (critical, high, low) scope profiles. Must sum to ~1.0.
    risk_mix: tuple[float, float, float]
    # The action archetypes this department's agents perform at runtime.
    # These names map to templates in ``actions.py`` and decide which
    # verdicts the behaviour driver tends to draw.
    action_profiles: tuple[str, ...]


# --------------------------------------------------------------------------- #
#  Meridian Financial Group — ~1,200 employees, financial-services SaaS.      #
# --------------------------------------------------------------------------- #

ORG_NAME = "Meridian Financial Group"
ORG_DOMAIN = "meridianfin.com"
ORG_TENANT_HINT = "meridian"

DEPARTMENTS: tuple[Department, ...] = (
    Department(
        key="treasury",
        name="Treasury & Payments",
        weight=14,
        agent_stems=(
            "treasury-reconciler", "ap-invoice-processor", "wire-prep-assistant",
            "cash-position-monitor", "payment-exception-triage", "fx-settlement-agent",
        ),
        owners=("treasury-ops@meridianfin.com", "j.calderon", "payments-platform"),
        risk_mix=(0.45, 0.40, 0.15),
        action_profiles=("payment_movement", "reconciliation_read", "vendor_email"),
    ),
    Department(
        key="risk",
        name="Risk & Compliance",
        weight=12,
        agent_stems=(
            "kyc-screening-agent", "aml-alert-triage", "sox-evidence-collector",
            "sanctions-list-checker", "audit-narrative-drafter", "policy-exception-logger",
        ),
        owners=("compliance@meridianfin.com", "r.okafor", "risk-engineering"),
        risk_mix=(0.30, 0.45, 0.25),
        action_profiles=("controls_bypass_attempt", "evidence_read", "compliance_summary"),
    ),
    Department(
        key="custops",
        name="Customer Operations",
        weight=18,
        agent_stems=(
            "support-triage-bot", "collections-outreach", "statement-generator",
            "dispute-resolution-agent", "onboarding-orchestrator", "card-fraud-responder",
            "chargeback-handler",
        ),
        owners=("custops@meridianfin.com", "m.delacruz", "servicing-platform"),
        risk_mix=(0.15, 0.45, 0.40),
        action_profiles=("customer_email", "external_sharing", "pii_read"),
    ),
    Department(
        key="lending",
        name="Lending & Underwriting",
        weight=12,
        agent_stems=(
            "loan-underwriting-copilot", "credit-memo-drafter", "income-verify-agent",
            "covenant-monitor", "doc-package-builder",
        ),
        owners=("lending@meridianfin.com", "s.albright", "credit-platform"),
        risk_mix=(0.25, 0.45, 0.30),
        action_profiles=("underwriting_decision", "doc_generation", "pii_read"),
    ),
    Department(
        key="engineering",
        name="Engineering & Platform",
        weight=16,
        agent_stems=(
            "deploy-bot", "incident-summarizer", "pr-review-copilot",
            "infra-cost-optimizer", "log-analyzer-agent", "migration-runner",
        ),
        owners=("platform-eng@meridianfin.com", "d.nakamura", "sre"),
        risk_mix=(0.40, 0.35, 0.25),
        action_profiles=("destructive_ops_attempt", "deploy_action", "log_read"),
    ),
    Department(
        key="sales",
        name="Sales & Revenue",
        weight=10,
        agent_stems=(
            "crm-sync-agent", "proposal-drafter", "deal-desk-assistant",
            "pipeline-forecaster", "contract-redliner",
        ),
        owners=("revops@meridianfin.com", "t.hassan", "sales-systems"),
        risk_mix=(0.15, 0.45, 0.40),
        action_profiles=("unauthorized_commitment", "customer_email", "crm_read"),
    ),
    Department(
        key="people",
        name="People & HR",
        weight=8,
        agent_stems=(
            "copilot-hr-assistant", "recruiting-screener", "benefits-qa-bot",
            "offboarding-orchestrator",
        ),
        owners=("people-ops@meridianfin.com", "l.bergstrom", "hris"),
        risk_mix=(0.20, 0.40, 0.40),
        action_profiles=("pii_read", "internal_email", "directory_read"),
    ),
    Department(
        key="data",
        name="Data & Analytics",
        weight=10,
        agent_stems=(
            "data-export-agent", "report-builder", "warehouse-sync",
            "metric-narrator", "dashboard-refresher",
        ),
        owners=("data-platform@meridianfin.com", "k.varga", "analytics-eng"),
        risk_mix=(0.30, 0.40, 0.30),
        action_profiles=("external_sharing", "warehouse_read", "report_generation"),
    ),
)


# --------------------------------------------------------------------------- #
#  Shadow cohort — the agents the directory never sees.                       #
#                                                                             #
#  These never appear in Entra. They surface ONLY because they *act*, landing #
#  in a control-plane audit log (Bedrock AgentCore / CloudTrail) or on the    #
#  network-egress plane. This is the cohort that makes the demo land: "Tex    #
#  found N agents your IdP didn't know existed."                              #
# --------------------------------------------------------------------------- #

@dataclass(frozen=True, slots=True)
class ShadowProfile:
    stem: str
    # Bedrock AgentCore event names this shadow agent emits.
    events: tuple[str, ...]
    # A human-ish hint for who is likely behind it (never authoritative).
    pretext: str


SHADOW_PROFILES: tuple[ShadowProfile, ...] = (
    ShadowProfile("shadow-quant-research", ("InvokeAgentRuntime", "InvokeAgentRuntimeCommand"), "quant desk laptop"),
    ShadowProfile("rogue-data-export", ("InvokeAgentRuntime", "InvokeMcp"), "analyst personal key"),
    ShadowProfile("dev-laptop-copilot", ("InvokeMcp",), "engineer Cursor/Claude Desktop"),
    ShadowProfile("cron-statement-scraper", ("InvokeAgentRuntime",), "forgotten cron VM"),
    ShadowProfile("marketing-gpt-bridge", ("InvokeAgentRuntime", "CreateMemory"), "unsanctioned SaaS bridge"),
    ShadowProfile("vendor-recon-bot", ("InvokeAgentRuntime", "InvokeAgentRuntimeCommand"), "contractor account"),
    ShadowProfile("offhours-export-daemon", ("InvokeAgentRuntime",), "server-side daemon, personal token"),
)


# --------------------------------------------------------------------------- #
#  MCP coding-agent hosts (the shadow engineering surface, optional plane).   #
# --------------------------------------------------------------------------- #

MCP_HOST_KINDS: tuple[str, ...] = ("cursor", "claude_desktop", "cline", "custom")
MCP_TOOL_POOL: tuple[str, ...] = (
    "filesystem.read", "filesystem.write", "shell.exec", "github.pr",
    "postgres.query", "http.fetch", "secrets.read",
)


def department_population(total_idp: int) -> list[tuple[Department, int]]:
    """Split ``total_idp`` agents across departments by weight (deterministic)."""
    weight_sum = sum(d.weight for d in DEPARTMENTS)
    out: list[tuple[Department, int]] = []
    assigned = 0
    for i, dept in enumerate(DEPARTMENTS):
        if i == len(DEPARTMENTS) - 1:
            count = total_idp - assigned  # remainder to the last dept
        else:
            count = round(total_idp * dept.weight / weight_sum)
        out.append((dept, max(0, count)))
        assigned += count
    return out

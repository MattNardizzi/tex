"""
Role ontology — how domain actors reason.

Per arxiv 2604.00555 three-layer ontology framework. Returns the
reasoning pattern (typical inputs, outputs, constraints, AIRO role
binding) for a domain role.

Seed roles are taken from the dual-ICP buyer narratives. Anything not
in the table raises KeyError; expanding the role table is a P1 follow-up
once we have a frequency-driven view of which roles actually appear in
pilot ecosystems.

Priority: P1.
"""

from __future__ import annotations

from typing import Any


_ROLES: dict[str, dict[str, Any]] = {
    "ai_sdr": {
        "typical_inputs": ("prospect_record", "campaign_brief", "tool_catalog"),
        "typical_outputs": ("outbound_email", "tool_invocation"),
        "constraints": (
            "all outbound content must traverse Tex outbound_content_emitted gate",
            "tool calls bounded by capability_set",
        ),
        "airo_role": "https://w3id.org/airo#AIUser",
        "buyer_narrative": "vp_marketing_brand_safety",
    },
    "support_agent": {
        "typical_inputs": ("ticket", "knowledge_base_query", "tool_catalog"),
        "typical_outputs": ("response", "tool_invocation", "escalation"),
        "constraints": (
            "no PII egress without explicit capability",
            "all customer-facing output traverses outbound_content_emitted gate",
        ),
        "airo_role": "https://w3id.org/airo#AIUser",
        "buyer_narrative": "vp_marketing_brand_safety",
    },
    "compliance_reviewer": {
        "typical_inputs": ("verdict_record", "evidence_chain", "policy_set"),
        "typical_outputs": ("review_decision", "policy_decision"),
        "constraints": (
            "decisions must be expressible in AIRO terms",
            "all decisions emit a policy_decision event",
        ),
        "airo_role": "https://w3id.org/airo#Stakeholder",
        "buyer_narrative": "insurer_naic",
    },
    "marketing_lead": {
        "typical_inputs": ("campaign_metrics", "verdict_summary", "drift_alerts"),
        "typical_outputs": ("policy_decision", "sanction_applied"),
        "constraints": (
            "responsible for drift signals on outbound campaigns",
        ),
        "airo_role": "https://w3id.org/airo#Stakeholder",
        "buyer_narrative": "vp_marketing_brand_safety",
    },
    "ciso": {
        "typical_inputs": (
            "agent_inventory",
            "capability_grants",
            "denial_events",
            "drift_signals",
        ),
        "typical_outputs": (
            "policy_decision",
            "capability_revoked",
            "governance_graph_transition",
        ),
        "constraints": (
            "owns the bounded-compromise certificate",
            "approves governance_graph transitions",
        ),
        "airo_role": "https://w3id.org/airo#Stakeholder",
        "buyer_narrative": "ciso_mcp_security",
    },
    "insurer": {
        "typical_inputs": ("ecosystem_state_attestation", "bounded_compromise_certificate"),
        "typical_outputs": ("policy_decision",),
        "constraints": (
            "consumes signed ecosystem state hashes only — no raw verdicts",
        ),
        "airo_role": "https://w3id.org/airo#Stakeholder",
        "buyer_narrative": "insurer_naic",
    },
}


def reasoning_pattern_for_role(role: str) -> dict[str, Any]:
    """
    Return the reasoning pattern for a domain role.

    The returned dict has keys:
      - ``typical_inputs``: tuple of input artifact names
      - ``typical_outputs``: tuple of output artifact names
      - ``constraints``: tuple of free-text constraint statements
      - ``airo_role``: AIRO term URI for the role's stakeholder class
      - ``buyer_narrative``: which dual-ICP narrative this role anchors

    TODO(P1): return the reasoning pattern (typical inputs, outputs,
        constraints) for a domain role (e.g. "ai_sdr", "support_agent",
        "compliance_reviewer")
    TODO(p1-expand-role-table): seed roles are taken from the dual-ICP
        buyer narratives. Expand once we have pilot data.
    """
    if not isinstance(role, str):
        raise TypeError(f"role must be str, got {type(role).__name__}")
    try:
        return dict(_ROLES[role])  # shallow copy so callers can't mutate the table
    except KeyError as exc:
        raise KeyError(
            f"no reasoning pattern registered for role {role!r}"
        ) from exc


def known_roles() -> tuple[str, ...]:
    """Return the set of roles with a registered reasoning pattern."""
    return tuple(_ROLES.keys())

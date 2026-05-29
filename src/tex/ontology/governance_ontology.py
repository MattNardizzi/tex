"""
Governance ontology — what regulatory bounds apply.

Maps Tex (entity_kind, event_kind) pairs to:
  - EU AI Act articles
  - NAIC Model Bulletin sections
  - FTC Section 5 categories
  - California SB 942
  - NIST AI RMF functions

The anchor pairs below cover the most common enterprise agent event
shapes (outbound content, MCP tool invocation, agent-to-agent message,
etc.) mapped to the regulatory articles that apply. Pairs not listed
fall back to a default tuple of the most general anchors.

Priority: P1.

References
----------
- EU AI Act (Regulation (EU) 2024/1689)
- NAIC Model Bulletin on the Use of AI Systems by Insurers (Dec 2023)
- FTC Section 5 (15 U.S.C. § 45)
- California SB 942 — California AI Transparency Act (2024)
- NIST AI RMF 1.0 (NIST AI 100-1) — GOVERN/MAP/MEASURE/MANAGE
"""

from __future__ import annotations


# Regulatory anchor IDs use a flat string convention so they're easy to
# grep, log, and join across compliance modules. Format:
#   <regulator>:<doc>:<locator>
# e.g. "eu_ai_act:art_50", "naic:model_bulletin:sec_3", "nist:ai_rmf:GOVERN_1_2"


_DEFAULT_BINDINGS: tuple[str, ...] = (
    "nist:ai_rmf:GOVERN",
    "nist:ai_rmf:MAP",
)


# 10 anchor (entity_kind, event_kind) pairs, load-bearing for the dual-ICP
# narratives. TODO(revisit-after-pilot-data): update the pair list and the
# anchor sets once we have real pilot frequency data.
_ANCHOR_BINDINGS: dict[tuple[str, str], tuple[str, ...]] = {
    # --- Outbound content / brand-safety events ---
    # The regulator-facing outbound event. EU Art 50 + CA SB 942 + FTC
    # Section 5 attach here (deceptive practices for AI-generated content
    # crossing the org→external boundary).
    ("agent", "outbound_content_emitted"): (
        "eu_ai_act:art_50",            # Transparency / disclosure
        "ca_sb_942:sec_22757_1",       # AI Transparency Act watermarking
        "ftc:section_5",               # Deceptive practices
        "nist:ai_rmf:MEASURE_2_7",     # AI system trustworthiness measurement
    ),
    # --- MCP / agent security events ---
    ("agent", "agent_invokes_tool"): (
        "eu_ai_act:art_15",            # Accuracy, robustness, cybersecurity
        "nist:ai_rmf:MANAGE_2_3",      # Risk treatment for capability use
        "naic:model_bulletin:sec_3",   # Vendor / third-party AI use
    ),
    ("agent", "agent_to_agent_message"): (
        "eu_ai_act:art_15",
        "nist:ai_rmf:MEASURE_2_6",     # Security and resilience
    ),
    # --- Capability lifecycle (CISO) ---
    ("capability", "capability_granted"): (
        "eu_ai_act:art_26",            # Deployer obligations
        "nist:ai_rmf:GOVERN_1_4",      # Roles, responsibilities, authorities
    ),
    ("capability", "capability_used"): (
        "nist:ai_rmf:MEASURE_2_8",     # Privileged operations
        "naic:model_bulletin:sec_4",   # Governance + accountability
    ),
    ("capability", "capability_revoked"): (
        "eu_ai_act:art_26",
        "nist:ai_rmf:MANAGE_2_4",      # Risk responses
    ),
    # --- Policy / audit (insurer) ---
    ("policy", "denial_event"): (
        "eu_ai_act:art_14",            # Human oversight
        "naic:model_bulletin:sec_5",   # Decisioning oversight
        "nist:ai_rmf:MANAGE_4_1",      # Risk responses logging
    ),
    ("policy", "policy_decision"): (
        "eu_ai_act:art_26",
        "naic:model_bulletin:sec_4",
        "nist:ai_rmf:GOVERN_1_2",      # Risk management process
    ),
    # --- Institutional governance ---
    ("governance_graph", "governance_graph_transition"): (
        "eu_ai_act:art_9",             # Risk management system
        "nist:ai_rmf:GOVERN_1_1",
        "naic:model_bulletin:sec_2",   # AI program governance
    ),
    # --- General output gate (internal) ---
    # Distinct from outbound_content_emitted: this is the internal output
    # event before boundary crossing. NIST anchors only; the regulator
    # disclosure obligations live on the boundary event.
    ("agent", "agent_emits_output"): (
        "nist:ai_rmf:MEASURE_2_5",     # Performance measurement
        "nist:ai_rmf:MAP_3_4",         # Mission / objectives mapping
    ),
}


def regulatory_bindings_for(entity_kind: str, event_kind: str) -> tuple[str, ...]:
    """
    Return the set of regulatory anchor IDs that apply to this
    (entity_kind, event_kind) pair.

    TODO(P1): return the set of regulatory anchor IDs that apply to this
    (entity_kind, event_kind) pair
    TODO(revisit-after-pilot-data): the 10 anchor pairs were chosen from
    the dual-ICP buyer narratives without a frequency table. Update once
    pilot data is available.
    """
    if not isinstance(entity_kind, str) or not isinstance(event_kind, str):
        raise TypeError(
            "entity_kind and event_kind must both be str"
        )
    e_key = str(entity_kind.value) if hasattr(entity_kind, "value") else str(entity_kind)
    v_key = str(event_kind.value) if hasattr(event_kind, "value") else str(event_kind)
    return _ANCHOR_BINDINGS.get((e_key, v_key), _DEFAULT_BINDINGS)


def known_anchor_pairs() -> tuple[tuple[str, str], ...]:
    """Return the set of (entity_kind, event_kind) pairs with explicit bindings."""
    return tuple(_ANCHOR_BINDINGS.keys())
